from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from google.auth.exceptions import InvalidValue
from dotenv import load_dotenv

from flask import render_template, request, flash, session, abort, url_for, redirect

import os, time, pathlib, requests
from datetime import datetime
from functools import wraps
from models import upsert_user, User

load_dotenv()

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.endpoint in ("login_page", "account_status"):
            return f(*args, **kwargs)

        if "google_id" not in session:
            flash('Please log in first.', 'info')
            return redirect(url_for('login_page'))

        current_user = User.query.filter_by(google_id=session["google_id"]).first()

        if not current_user:
            flash("Something went wrong. Please log in again.", "warning")
            return redirect(url_for("login_page"))

        if current_user.status in ("pending", "suspended"):
            flash(f"Your account is {current_user.status}. Please contact support.", "warning")
            return redirect(url_for("account_status"))

        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.endpoint in ("login_page", "account_status"):
            return f(*args, **kwargs)
        
        google_id = session.get("google_id")
        if not google_id:
            flash("Please log in first.", "info")
            return redirect(url_for("login_page"))

        current_user = User.query.filter_by(google_id=google_id).first()
        if not current_user:
            flash("Something went wrong. Please log in again.", "warning")
            return redirect(url_for("login_page"))

        if current_user.role != "admin":
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for("index"))

        return f(*args, **kwargs)
    return wrapper

def init_routes(app):
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    
    GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
    client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

    flow = Flow.from_client_secrets_file(
        client_secrets_file=client_secrets_file,
        scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
        redirect_uri=os.getenv('GOOGLE_CALLBACK')
    )
        
    @app.context_processor
    def inject_user():
        return dict(user_email=session.get("email"))

    @app.template_filter('datetimeformat')
    def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
        if isinstance(value, int):
            return datetime.fromtimestamp(value / 1000).strftime(format)
        return value
    
    @app.route('/login-page')
    def login_page():
        if "google_id" in session:
            return redirect(url_for('index'))
        return render_template('login.html')

    @app.route('/login')
    def login():
        authorization_url, state = flow.authorization_url()
        session["state"] = state
        return redirect(authorization_url)

    @app.route('/callback')
    def callback():
        flow.fetch_token(authorization_response=request.url)

        if not session.get("state") == request.args.get("state"):
            abort(500)

        credentials = flow.credentials
        request_session = requests.session()
        cached_session = cachecontrol.CacheControl(request_session)
        token_request = google.auth.transport.requests.Request(session=cached_session)

        for attempt in range(3):
            try:
                id_info = id_token.verify_oauth2_token(
                    id_token=credentials._id_token,
                    request=token_request,
                    audience=GOOGLE_CLIENT_ID,
                    clock_skew_in_seconds=10
                )
                break
            except InvalidValue as e:
                if "Token used too early" in str(e) and attempt < 2:
                    time.sleep(2)
                else:
                    raise
        
        session.permanent = True

        google_id = id_info.get("sub", "")
        name = id_info.get("name", "")
        email = id_info.get("email", "").lower()

        # Store user in database if not exists
        upsert_user(google_id, email, name)

        session["google_id"] = google_id
        session["name"] = name
        session["email"] = email

        return redirect(url_for("index"))

    @app.route('/logout')
    @login_required
    def logout():
        session.clear()
        flash('You have been logged out.', 'info')
        return redirect(url_for('login_page'))

    @app.route('/unauthorized')
    def unauthorized():
        session.clear()
        return render_template("unauthorized.html")
    
    @app.route('/accountstatus')
    @login_required
    def account_status():
        current_user = User.query.filter_by(google_id=session["google_id"]).first()
        if current_user.status == "active":
            flash("Your account is active. You can access all features.", "success")
            return redirect(url_for("index"))
        return render_template("account_status.html", status=current_user.status)
