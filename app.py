import os
import zipfile
import smtplib
import threading
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
import pandas as pd
import re
import unicodedata

load_dotenv()  # Load .env from project root

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

send_status = {}


def get_smtp_config():
    """Read SMTP settings exclusively from .env file."""
    return {
        'host':       os.environ.get('SMTP_HOST', 'smtp.gmail.com'),
        'port':       int(os.environ.get('SMTP_PORT', 587)),
        'username':   os.environ.get('SMTP_USERNAME', ''),
        'password':   os.environ.get('SMTP_PASSWORD', ''),
        'from_email': os.environ.get('SMTP_FROM_EMAIL', os.environ.get('SMTP_USERNAME', '')),
        'tls':        os.environ.get('SMTP_TLS', 'true').lower() == 'true',
    }


def mask_email(email):
    if not email or '@' not in email:
        return '***'
    local, domain = email.split('@', 1)
    return local[:3] + '***@' + domain


def slugify_name(name):
    """
    Convert a name to a URL/filename-safe slug.
    Handles accented characters, French/Spanish diacritics, apostrophes,
    smart quotes, hyphens, and any other non-ASCII naming characters.

    Examples:
      'François'        -> 'francois'
      "O'Brien"         -> 'obrien'
      'Jean-Pierre'     -> 'jean-pierre'
      'Marie-Hélène'    -> 'marie-helene'
      'D\u2019Souza'    -> 'dsouza'
      'Müller'          -> 'muller'
    """
    # Decompose accented characters: é -> e + combining accent
    name = unicodedata.normalize('NFD', name)

    # Strip all combining/diacritic marks (accents, cedillas, tildes, etc.)
    name = ''.join(c for c in name if unicodedata.category(c) != 'Mn')

    # Collapse all apostrophe/quote variants to nothing
    name = re.sub(r"['''\u2018\u2019\u201a\u201b`\u0060]", '', name)

    # Convert hyphens and dashes to a space (preserves hyphenated names as two parts)
    name = re.sub(r'[-\u2010-\u2015\u2212\uFE63\uFF0D]', ' ', name)
    
    # Lowercase and strip any remaining non-alphanumeric, non-space characters
    name = re.sub(r'[^a-z0-9\s]', '', name.lower())
    
    # Collapse whitespace and replace with hyphens
    name = re.sub(r'\s+', '-', name.strip())
    return name


def match_certificate(student_name, pdf_files, fname=None, lname=None):
    # Build list of slugs to try: full name first, then fname+lname combo
    slugs = [slugify_name(student_name)]
    if fname and lname:
        slugs.append(slugify_name(f"{fname} {lname}"))

    # Exact match against all slugs
    for slug in slugs:
        for pdf in pdf_files:
            base = os.path.splitext(os.path.basename(pdf))[0].lower()
            if base == slug or base == f"{slug}_certificate":
                return pdf

    # Fuzzy: slug contained anywhere in filename
    for slug in slugs:
        for pdf in pdf_files:
            if slug in pdf.lower():
                return pdf

    return None

@app.route('/robots.txt')
def robots():
    return app.send_static_file('robots.txt')

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/smtp-status')
def smtp_status():
    cfg = get_smtp_config()
    configured = bool(cfg['username'] and cfg['password'])
    return jsonify({
        'configured': configured,
        'host': cfg['host'],
        'port': cfg['port'],
        'tls': cfg['tls'],
        'username_hint': mask_email(cfg['username']) if configured else '',
        'from_email': mask_email(cfg['from_email']) if configured else '',
    })


@app.route('/upload', methods=['POST'])
def upload():
    csv_file = request.files.get('csv_file')
    zip_file = request.files.get('zip_file')

    if not csv_file or not zip_file:
        return jsonify({'error': 'Both CSV and ZIP files are required.'}), 400

    csv_path = os.path.join(UPLOAD_FOLDER, 'students.csv')
    zip_path = os.path.join(UPLOAD_FOLDER, 'certificates.zip')
    csv_file.save(csv_path)
    zip_file.save(zip_path)

    cert_dir = os.path.join(UPLOAD_FOLDER, 'certificates')
    os.makedirs(cert_dir, exist_ok=True)
    with zipfile.ZipFile(zip_path, 'r') as z:
        z.extractall(cert_dir)

    pdf_files = []
    for root, dirs, files in os.walk(cert_dir):
        for f in files:
            if f.lower().endswith('.pdf'):
                pdf_files.append(os.path.relpath(os.path.join(root, f), cert_dir))

    try:
        df = pd.read_csv(csv_path)
        df.columns = [c.strip().lower() for c in df.columns]
    except Exception as e:
        return jsonify({'error': f'Failed to parse CSV: {str(e)}'}), 400

    fname_col = next((c for c in df.columns if 'first name' in c or 'first_name' in c or c in ('fname', 'firstname', 'first')), None)
    lname_col = next((c for c in df.columns if 'last name'  in c or 'last_name'  in c or c in ('lname', 'lastname',  'last', 'surname')), None)
    name_col  = next((c for c in df.columns if 'full name'  in c or 'full_name'  in c or c in ('name', 'fullname')), None)
    email_col = next((c for c in df.columns if 'email' in c or 'mail' in c), None)

    if not email_col:
        return jsonify({'error': 'CSV must have a column containing "email".'}), 400
    if not name_col and not (fname_col and lname_col):
        return jsonify({'error': 'CSV must have either a "name" column or both "fname"/"lname" columns.'}), 400

    students = []
    for _, row in df.iterrows():
        fname = str(row[fname_col]).strip() if fname_col and fname_col in row.index else None
        lname = str(row[lname_col]).strip() if lname_col and lname_col in row.index else None

        if name_col:
            name = str(row[name_col]).strip()
        else:
            name = f"{fname} {lname}"

        email = str(row[email_col]).strip()
        cert = match_certificate(name, pdf_files, fname=fname, lname=lname)
        students.append({
            'name': name,
            'email': email,
            'certificate': cert,
            'cert_path': os.path.join(cert_dir, cert) if cert else None,
            'status': 'ready' if cert else 'no_cert'
        })
  

    return jsonify({'students': students, 'pdf_count': len(pdf_files)})


@app.route('/send', methods=['POST'])
def send_emails():
    data = request.json
    students = data.get('students', [])
    subject = data.get('subject', 'Your Certificate')
    body = data.get('body', 'Dear {name},\n\nPlease find your certificate attached.\n\nBest regards.')

    smtp = get_smtp_config()

    if not smtp['username'] or not smtp['password']:
        return jsonify({
            'error': 'SMTP credentials not configured. Set SMTP_USERNAME and SMTP_PASSWORD in your .env file.'
        }), 500

    task_id = os.urandom(8).hex()
    send_status[task_id] = {'total': len(students), 'done': 0, 'errors': [], 'complete': False}

    def do_send():
        try:
            server = smtplib.SMTP(smtp['host'], smtp['port'])
            server.ehlo()
            if smtp['tls']:
                server.starttls()
            server.login(smtp['username'], smtp['password'])

            for student in students:
                try:
                    msg = MIMEMultipart()
                    msg['From'] = smtp['from_email'] or smtp['username']
                    msg['To'] = student['email']
                    msg['Subject'] = subject.replace('{name}', student['name'])
                    msg.attach(MIMEText(
                        body.replace('{name}', student['name'])
                            .replace('{email}', student['email']),
                        'plain'
                    ))

                    cert_path = student.get('cert_path')
                    if cert_path and os.path.exists(cert_path):
                        with open(cert_path, 'rb') as f:
                            part = MIMEBase('application', 'octet-stream')
                            part.set_payload(f.read())
                        encoders.encode_base64(part)
                        part.add_header('Content-Disposition',
                                        f'attachment; filename="{os.path.basename(cert_path)}"')
                        msg.attach(part)

                    server.sendmail(msg['From'], student['email'], msg.as_string())
                    send_status[task_id]['done'] += 1

                except Exception as e:
                    send_status[task_id]['errors'].append({'email': student['email'], 'error': str(e)})
                    send_status[task_id]['done'] += 1

            server.quit()

        except Exception as e:
            send_status[task_id]['errors'].append({'email': 'SMTP Connection', 'error': str(e)})
        finally:
            send_status[task_id]['complete'] = True

    threading.Thread(target=do_send, daemon=True).start()
    return jsonify({'task_id': task_id})


@app.route('/status/<task_id>')
def get_status(task_id):
    status = send_status.get(task_id)
    if not status:
        return jsonify({'error': 'Unknown task'}), 404
    return jsonify(status)


if __name__ == '__main__':
    app.run(debug=True, port=5000)
