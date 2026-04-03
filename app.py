import os, zipfile, smtplib, threading, re, unicodedata
import pandas as pd
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from flask import Flask, render_template, request, session, jsonify
from dotenv import load_dotenv

from models import (
    User, db, init_app,
    log_action, query_logs, list_users, log_summary,
    get_active_smtp, list_smtp_configs, save_smtp_config,
    activate_smtp, delete_smtp_config, get_smtp_by_id, set_user_active
)
from auth import login_required, init_routes, admin_required

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

send_status = {}

init_app(app)
init_routes(app)

def _client_ip() -> str:
    """Best-effort real IP (works behind common reverse proxies)."""
    return (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.remote_addr
        or "unknown"
    )

def _ua() -> str:
    return request.headers.get("User-Agent", "")[:512]

def _audit(action: str, detail: str | None = None, success: bool = True) -> None:
    log_action(
        action,
        google_id=session.get("google_id"),
        email=session.get("email"),
        detail=detail,
        ip_address=_client_ip(),
        user_agent=_ua(),
        success=success,
    )

def get_smtp_config() -> dict:
    """
    Return the active SMTP profile from the database.
    Falls back to environment variables if no active DB row exists
    (covers the period before the first login/setup).
    """
    row = get_active_smtp()
    if row:
        return {
            'host':       row['host'],
            'port':       row['port'],
            'username':   row['username'],
            'password':   row['password'],
            'from_email': row['from_email'] or row['username'],
            'tls':        bool(row['use_tls']),
        }
    # Env fallback
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

# Name / certificate helpers

def slugify_name(name):
    name = unicodedata.normalize('NFD', name)
    name = ''.join(c for c in name if unicodedata.category(c) != 'Mn')
    name = re.sub(r"['''\u2018\u2019\u201a\u201b`\u0060]", '', name)
    name = re.sub(r'[-\u2010-\u2015\u2212\uFE63\uFF0D]', ' ', name)
    name = re.sub(r'[^a-z0-9\s]', '', name.lower())
    name = re.sub(r'\s+', '-', name.strip())
    return name

def match_certificate(student_name, pdf_files, fname=None, lname=None):
    slugs = [slugify_name(student_name)]
    if fname and lname:
        slugs.append(slugify_name(f"{fname} {lname}"))

    for slug in slugs:
        for pdf in pdf_files:
            base = os.path.splitext(os.path.basename(pdf))[0].lower()
            if base == slug or base == f"{slug}_certificate":
                return pdf

    for slug in slugs:
        for pdf in pdf_files:
            if slug in pdf.lower():
                return pdf

    return None

# Application routes

@app.route('/robots.txt')
def robots():
    return app.send_static_file('robots.txt')

@app.route('/')
@login_required
def index():
    current_user = User.query.filter_by(google_id=session["google_id"]).first()
    _audit("VIEW_INDEX")
    return render_template('index.html', current_user=current_user)

@app.route('/smtp-status')
@login_required
def smtp_status():
    cfg = get_smtp_config()
    configured = bool(cfg['username'] and cfg['password'])
    if not configured:
        return render_template('404.html')
    _audit("VIEW_STATUS", detail="smtp-status")
    return jsonify({
        'configured': configured,
        'host': cfg['host'],
        'port': cfg['port'],
        'tls': cfg['tls'],
        'username_hint': mask_email(cfg['username']) if configured else '',
        'from_email': mask_email(cfg['from_email']) if configured else '',
    })

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    csv_file = request.files.get('csv_file')
    zip_file = request.files.get('zip_file')

    if not csv_file or not zip_file:
        _audit("UPLOAD", detail="Missing CSV or ZIP", success=False)
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
        _audit("UPLOAD", detail=f"CSV parse error: {e}", success=False)
        return jsonify({'error': f'Failed to parse CSV: {str(e)}'}), 400

    fname_col = next((c for c in df.columns if 'first name' in c or 'first_name' in c or c in ('fname', 'firstname', 'first')), None)
    lname_col = next((c for c in df.columns if 'last name'  in c or 'last_name'  in c or c in ('lname', 'lastname',  'last', 'surname')), None)
    name_col  = next((c for c in df.columns if 'full name'  in c or 'full_name'  in c or c in ('name', 'fullname')), None)
    email_col = next((c for c in df.columns if 'email' in c or 'mail' in c), None)

    if not email_col:
        _audit("UPLOAD", detail="CSV missing email column", success=False)
        return jsonify({'error': 'CSV must have a column containing "email".'}), 400
    if not name_col and not (fname_col and lname_col):
        _audit("UPLOAD", detail="CSV missing name column(s)", success=False)
        return jsonify({'error': 'CSV must have either a "name" column or both "fname"/"lname" columns.'}), 400

    students = []
    for _, row in df.iterrows():
        fname = str(row[fname_col]).strip() if fname_col and fname_col in row.index else None
        lname = str(row[lname_col]).strip() if lname_col and lname_col in row.index else None
        name  = str(row[name_col]).strip() if name_col else f"{fname} {lname}"
        email = str(row[email_col]).strip()
        cert  = match_certificate(name, pdf_files, fname=fname, lname=lname)
        students.append({
            'name': name,
            'email': email,
            'certificate': cert,
            'cert_path': os.path.join(cert_dir, cert) if cert else None,
            'status': 'ready' if cert else 'no_cert',
        })

    _audit(
        "UPLOAD",
        detail=f"students={len(students)} pdfs={len(pdf_files)} "
               f"matched={sum(1 for s in students if s['certificate'])}",
    )
    return jsonify({'students': students, 'pdf_count': len(pdf_files)})

@app.route('/send', methods=['POST'])
@login_required
def send_emails():
    data     = request.json
    students = data.get('students', [])
    subject  = data.get('subject', 'Your Certificate')
    body     = data.get('body', 'Dear {name},\n\nPlease find your certificate attached.\n\nBest regards.')

    smtp = get_smtp_config()

    if not smtp['username'] or not smtp['password']:
        _audit("SEND_EMAILS", detail="SMTP credentials missing", success=False)
        return jsonify({'error': 'SMTP credentials not configured.'}), 500

    task_id = os.urandom(8).hex()
    send_status[task_id] = {'total': len(students), 'done': 0, 'errors': [], 'complete': False}

    # Capture session info for the background thread (session not available there)
    actor_google_id = session.get("google_id")
    actor_email     = session.get("email")
    actor_ip        = _client_ip()
    actor_ua        = _ua()

    def do_send():
        errors = []
        try:
            server = smtplib.SMTP(smtp['host'], smtp['port'])
            server.ehlo()
            if smtp['tls']:
                server.starttls()
            server.login(smtp['username'], smtp['password'])

            for student in students:
                try:
                    msg = MIMEMultipart()
                    msg['From']    = smtp['from_email'] or smtp['username']
                    msg['To']      = student['email']
                    msg['Subject'] = subject.replace('{name}', student['name'])
                    msg.attach(MIMEText(
                        body.replace('{name}',  student['name'])
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
                    err = {'email': student['email'], 'error': str(e)}
                    send_status[task_id]['errors'].append(err)
                    errors.append(err)
                    send_status[task_id]['done'] += 1

            server.quit()

        except Exception as e:
            err = {'email': 'SMTP Connection', 'error': str(e)}
            send_status[task_id]['errors'].append(err)
            errors.append(err)
        finally:
            send_status[task_id]['complete'] = True

            # ── Audit the whole batch once it finishes ───────────────────────
            ok      = send_status[task_id]['done'] - len(errors)
            failed  = len(errors)
            log_action(
                "SEND_EMAILS",
                google_id=actor_google_id,
                email=actor_email,
                detail=f"task={task_id} total={len(students)} ok={ok} failed={failed}",
                ip_address=actor_ip,
                user_agent=actor_ua,
                success=(failed == 0),
            )

    # Audit the *initiation* immediately (so the user sees it even if tab closes)
    _audit("SEND_EMAILS_START", detail=f"task={task_id} recipients={len(students)}")

    threading.Thread(target=do_send, daemon=True).start()
    return jsonify({'task_id': task_id})

@app.route('/status/<task_id>')
@login_required
def get_status(task_id):
    status = send_status.get(task_id)
    if not status:
        return jsonify({'error': 'Unknown task'}), 404
    return jsonify(status)

@app.route('/storage-info')
@login_required
def storage_info():
    total_bytes = 0
    total_files = 0
    for root, dirs, files in os.walk(UPLOAD_FOLDER):
        for f in files:
            try:
                total_bytes += os.path.getsize(os.path.join(root, f))
                total_files += 1
            except OSError:
                pass
    _audit("VIEW_STATUS", detail="storage-info")
    return jsonify({'bytes': total_bytes, 'files': total_files})

@app.route('/cleanup', methods=['DELETE'])
@login_required
def cleanup():
    import shutil
    deleted = 0
    errors = []
    for item in os.listdir(UPLOAD_FOLDER):
        item_path = os.path.join(UPLOAD_FOLDER, item)
        try:
            if os.path.isdir(item_path):
                shutil.rmtree(item_path)
            else:
                os.remove(item_path)
            deleted += 1
        except Exception as e:
            errors.append(str(e))

    _audit("CLEANUP", detail=f"deleted={deleted} errors={len(errors)}", success=(len(errors) == 0))
    return jsonify({'deleted': deleted, 'errors': errors})

# ── Admin / audit API routes ──────────────────────────────────────────────────

@app.route('/admin/users')
@admin_required
def admin_users():
    """Return all registered users."""
    return jsonify(list_users())

@app.route('/admin/logs')
@admin_required
def admin_logs():
    _audit("VIEW_ADMIN_LOGS")
    logs = query_logs(
        google_id=request.args.get('google_id'),
        action=request.args.get('action'),
        since=request.args.get('since'),
        limit=int(request.args.get('limit', 200)),
        offset=int(request.args.get('offset', 0)),
    )
    return jsonify(logs)

@app.route('/admin/logs/summary')
@admin_required
def admin_logs_summary():
    _audit("VIEW_ADMIN_LOGS_SUMMARY")
    return jsonify(log_summary())

# ── Admin / SMTP config routes ────────────────────────────────────────────────
@app.route('/admin/smtp', methods=['GET'])
@admin_required
def admin_smtp_list():
    """List all SMTP profiles (passwords masked)."""
    _audit("VIEW_SMTP_CONFIGS")
    return jsonify(list_smtp_configs())

@app.route('/admin/smtp', methods=['POST'])
@admin_required
def admin_smtp_create():
    data = request.get_json(force=True) or {}
    required = ('host', 'username', 'password')
    missing = [k for k in required if not data.get(k)]
    if missing:
        return jsonify({'error': f"Missing fields: {', '.join(missing)}"}), 400

    try:
        new_id = save_smtp_config(
            label=data.get('label', 'default'),
            host=data['host'],
            port=int(data.get('port', 587)),
            username=data['username'],
            password=data['password'],
            from_email=data.get('from_email', ''),
            use_tls=bool(data.get('use_tls', True)),
            make_active=bool(data.get('make_active', False)),
            created_by=session.get('google_id'),
        )
    except Exception as e:
        _audit("SMTP_CREATE", detail=str(e), success=False)
        return jsonify({'error': str(e)}), 500

    _audit("SMTP_CREATE", detail=f"id={new_id} label={data.get('label')} host={data['host']}")
    return jsonify({'id': new_id}), 201

@app.route('/admin/smtp/<int:config_id>', methods=['PUT'])
@admin_required
def admin_smtp_update(config_id):
    existing = get_smtp_by_id(config_id)
    if not existing:
        return jsonify({'error': 'Not found'}), 404

    data = request.get_json(force=True) or {}

    try:
        save_smtp_config(
            config_id=config_id,
            label=data.get('label', existing['label']),
            host=data.get('host', existing['host']),
            port=int(data.get('port', existing['port'])),
            username=data.get('username', existing['username']),
            # Only update password if a non-empty value is supplied
            password=data['password'] if data.get('password') else existing['password'],
            from_email=data.get('from_email', existing['from_email']),
            use_tls=bool(data.get('use_tls', existing['use_tls'])),
            make_active=bool(data.get('make_active', False)),
            updated_by=session.get('google_id'),
        )
    except Exception as e:
        _audit("SMTP_UPDATE", detail=str(e), success=False)
        return jsonify({'error': str(e)}), 500

    _audit("SMTP_UPDATE", detail=f"id={config_id}")
    return jsonify({'ok': True})

@app.route('/admin/smtp/<int:config_id>/activate', methods=['POST'])
@admin_required
def admin_smtp_activate(config_id):
    ok = activate_smtp(config_id, updated_by=session.get('google_id'))
    if not ok:
        return jsonify({'error': 'Not found'}), 404
    _audit("SMTP_ACTIVATE", detail=f"id={config_id}")
    return jsonify({'ok': True})

@app.route('/admin/smtp/<int:config_id>', methods=['DELETE'])
@admin_required
def admin_smtp_delete(config_id):
    try:
        ok = delete_smtp_config(config_id)
    except ValueError as e:
        _audit("SMTP_DELETE", detail=str(e), success=False)
        return jsonify({'error': str(e)}), 400

    if not ok:
        return jsonify({'error': 'Not found'}), 404

    _audit("SMTP_DELETE", detail=f"id={config_id}")
    return jsonify({'ok': True})

# Admin panel page

@app.route('/admin')
@admin_required
def admin_panel():
    _audit("VIEW_ADMIN_PANEL")
    return render_template('admin.html')
 
@app.route('/admin/users/<google_id>/active', methods=['PATCH'])
@admin_required
def admin_user_toggle_active(google_id):
    data   = request.get_json(force=True) or {}
    active = bool(data.get('active', True))
    set_user_active(google_id, active)
    _audit(
        "USER_TOGGLE_ACTIVE",
        detail=f"google_id={google_id} active={active}",
    )
    return jsonify({'ok': True})

@app.route("/admin/users/<google_id>/toggle-role", methods=["POST"])
@admin_required
def toggle_user_role(google_id):
    user = User.query.filter_by(google_id=google_id).first_or_404()
    user.toggle_role()
    db.session.commit()
    return {"success": True, "role": user.role}

@app.route("/admin/users/<email>/togglestatus", methods=["POST"])
@admin_required
def toggle_user_status(email):
    user = User.query.filter_by(email=email).first_or_404()
    user.toggle_status()
    db.session.commit()
    return jsonify({"success": True, "status": user.status})

if __name__ == '__main__':
    app.run(debug=True, port=8080)
