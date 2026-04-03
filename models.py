from __future__ import annotations

import os, uuid
from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import CheckConstraint, Index, func
from sqlalchemy.orm import validates

from flask_migrate import Migrate

from dotenv import load_dotenv

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.String(36), primary_key=True,default=lambda: str(uuid.uuid4()))
    google_id = db.Column(db.String, nullable=False, unique=True)
    email = db.Column(db.String, nullable=False)
    name = db.Column(db.String, nullable=False)
    status = db.Column(db.String, nullable=True, default="pending")
    role = db.Column(db.String, nullable=True, default="user")  # 'user' or 'admin'
    first_seen_at = db.Column(db.DateTime(timezone=True), nullable=False)
    last_login_at = db.Column(db.DateTime(timezone=True), nullable=False)
    login_count = db.Column(db.Integer,  nullable=False, default=1)
    is_active = db.Column(db.Boolean,  nullable=False, default=True)

    __table_args__ = (
        Index("idx_users_email", "email"),
        CheckConstraint("status IN ('pending', 'active', 'suspended')", name="check_status_valid")
    )

    def to_dict(self) -> dict:
        return {
            "id":            self.id,
            "google_id":     self.google_id,
            "email":         self.email,
            "name":          self.name,
            "status":        self.status,
            "role":          self.role,
            "first_seen_at": _fmt(self.first_seen_at),
            "last_login_at": _fmt(self.last_login_at),
            "login_count":   self.login_count,
            "is_active":     self.is_active,
        }

    def __repr__(self) -> str:
        return f"<User {self.email}>"
    
    @validates("status")
    def validate_status(self, key, value):
        if value not in ("pending", "active", "suspended"):
            raise ValueError(f"Invalid status: {value}")
        return value
    
    def toggle_status(self):
        order = ["pending", "active", "suspended"]
        current_index = order.index(self.status)
        self.status = order[(current_index + 1) % len(order)]
        return self.status
    
    def toggle_role(self):
        self.role = "admin" if self.role == "user" else "user"
        return self.role

class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id         = db.Column(db.String(36), primary_key=True,default=lambda: str(uuid.uuid4()))
    timestamp  = db.Column(db.DateTime(timezone=True), nullable=False)
    google_id  = db.Column(db.String,  nullable=True)
    email      = db.Column(db.String,  nullable=True)
    action     = db.Column(db.String,  nullable=False)
    detail     = db.Column(db.Text,    nullable=True)
    ip_address = db.Column(db.String,  nullable=True)
    user_agent = db.Column(db.String,  nullable=True)
    success    = db.Column(db.Boolean, nullable=False, default=True)

    __table_args__ = (
        Index("idx_audit_timestamp", "timestamp"),
        Index("idx_audit_google_id", "google_id"),
        Index("idx_audit_action",    "action"),
    )

    def to_dict(self) -> dict:
        return {
            "id":         self.id,
            "timestamp":  _fmt(self.timestamp),
            "google_id":  self.google_id,
            "email":      self.email,
            "action":     self.action,
            "detail":     self.detail,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "success":    self.success,
        }

    def __repr__(self) -> str:
        return f"<AuditLog {self.action} {self.email}>"

class SmtpConfig(db.Model):
    """
    Named SMTP profile.  Only one row may have is_active=True at a time.

    Security note: passwords are stored in plaintext in the SQLite file.
    Restrict OS-level read access to app.db in production
    (chmod 600, dedicated app user, or layer on SQLCipher).
    """

    __tablename__ = "smtp_configs"

    id         = db.Column(db.String(36), primary_key=True,default=lambda: str(uuid.uuid4()))
    label      = db.Column(db.String,  nullable=False, default="default")
    host       = db.Column(db.String,  nullable=False)
    port       = db.Column(db.Integer, nullable=False, default=587)
    username   = db.Column(db.String,  nullable=False)
    password   = db.Column(db.String,  nullable=False)
    from_email = db.Column(db.String,  nullable=False, default="")
    use_tls    = db.Column(db.Boolean, nullable=False, default=True)
    is_active  = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False)
    created_by = db.Column(db.String,  nullable=True)
    updated_by = db.Column(db.String,  nullable=True)

    __table_args__ = (
        Index("idx_smtp_active", "is_active"),
    )

    def to_dict(self, *, mask_password: bool = False) -> dict:
        return {
            "id":         self.id,
            "label":      self.label,
            "host":       self.host,
            "port":       self.port,
            "username":   self.username,
            "password":   _mask_password(self.password) if mask_password else self.password,
            "from_email": self.from_email,
            "use_tls":    self.use_tls,
            "is_active":  self.is_active,
            "created_at": _fmt(self.created_at),
            "updated_at": _fmt(self.updated_at),
            "created_by": self.created_by,
            "updated_by": self.updated_by,
        }

    def __repr__(self) -> str:
        state = "active" if self.is_active else "inactive"
        return f"<SmtpConfig {self.label!r} ({state})>"

def init_app(app) -> None:
    database_url = os.getenv("DATABASE_URL")
    debug = os.getenv("DEBUG", "false").lower() == "true"

    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)

    app.config["SQLALCHEMY_DATABASE_URI"] = database_url

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["DEBUG"] = debug

    db.init_app(app)
    Migrate(app, db)

# User Functions
def upsert_user(google_id: str, email: str, name: str) -> dict:
    now  = _utcnow()
    user = User.query.filter_by(google_id=google_id).first()

    if user is None:
        user = User(
            google_id     = google_id,
            email         = email.lower(),
            name          = name,
            first_seen_at = now,
            last_login_at = now,
            login_count   = 1,
            is_active     = True,
        )
        db.session.add(user)
    else:
        user.email         = email.lower()
        user.name          = name
        user.last_login_at = now
        user.login_count  += 1

    db.session.commit()
    return user.to_dict()

def get_user_by_email(email: str) -> dict | None:
    user = User.query.filter_by(email=email.lower()).first()
    return user.to_dict() if user else None

def list_users(active_only: bool = False) -> list[dict]:
    q = User.query
    if active_only:
        q = q.filter_by(is_active=True)
    return [u.to_dict() for u in q.order_by(User.last_login_at.desc()).all()]

def set_user_active(google_id: str, active: bool) -> None:
    """Enable or disable a user account without touching audit history."""
    user = User.query.filter_by(google_id=google_id).first()
    if user:
        user.is_active = active
        db.session.commit()

def log_action(
    action: str,
    *,
    google_id:  str | None = None,
    email:      str | None = None,
    detail:     str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    success:    bool       = True,
) -> int:
    """
    Common action strings:
        LOGIN, LOGOUT, UPLOAD, SEND_EMAILS, SEND_EMAILS_START, CLEANUP,
        ACCESS_DENIED, AUTH_FAILED, VIEW_STATUS, VIEW_INDEX,
        SMTP_CREATE, SMTP_UPDATE, SMTP_ACTIVATE, SMTP_DELETE,
        VIEW_ADMIN_LOGS, VIEW_ADMIN_LOGS_SUMMARY, VIEW_SMTP_CONFIGS
    """
    entry = AuditLog(
        timestamp  = _utcnow(),
        google_id  = google_id,
        email      = email.lower() if email else None,
        action     = action.upper(),
        detail     = detail,
        ip_address = ip_address,
        user_agent = user_agent,
        success    = success,
    )
    db.session.add(entry)
    db.session.commit()
    return entry.id

def query_logs(
    *,
    google_id: str | None = None,
    action:    str | None = None,
    since:     str | None = None,
    limit:     int        = 200,
    offset:    int        = 0,
) -> list[dict]:
    """Flexible audit log query; all filters are optional."""
    q = AuditLog.query
    if google_id:
        q = q.filter(AuditLog.google_id == google_id)
    if action:
        q = q.filter(AuditLog.action == action.upper())
    if since:
        since_dt = datetime.fromisoformat(since.rstrip("Z")).replace(tzinfo=timezone.utc)
        q = q.filter(AuditLog.timestamp >= since_dt)

    return [
        log.to_dict()
        for log in q.order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset).all()
    ]

def log_summary() -> list[dict]:
    """Return per-action counts and failure totals — useful for a dashboard."""
    rows = (
        db.session.query(
            AuditLog.action,
            func.count(AuditLog.id).label("count"),
            func.sum(
                db.case((AuditLog.success == False, 1), else_=0)  # noqa: E712
            ).label("failures"),
        )
        .group_by(AuditLog.action)
        .order_by(func.count(AuditLog.id).desc())
        .all()
    )
    return [
        {"action": r.action, "count": r.count, "failures": r.failures or 0}
        for r in rows
    ]

# SMTP Config Management
def get_active_smtp() -> dict | None:
    cfg = SmtpConfig.query.filter_by(is_active=True).first()
    return cfg.to_dict() if cfg else None

def get_smtp_by_id(config_id: int) -> dict | None:
    cfg = db.session.get(SmtpConfig, config_id)
    return cfg.to_dict() if cfg else None

def list_smtp_configs() -> list[dict]:
    """Return all SMTP profiles (passwords masked), active one first."""
    cfgs = (
        SmtpConfig.query
        .order_by(SmtpConfig.is_active.desc(), SmtpConfig.label)
        .all()
    )
    return [c.to_dict(mask_password=True) for c in cfgs]

def save_smtp_config(
    *,
    label:      str,
    host:       str,
    port:       int,
    username:   str,
    password:   str,
    from_email: str       = "",
    use_tls:    bool      = True,
    make_active: bool     = False,
    created_by: str | None = None,
    config_id:  int | None = None,   # None → INSERT, int → UPDATE
    updated_by: str | None = None,
) -> int:
    """
    Insert (config_id=None) or update an SMTP profile.
    If make_active=True, all other rows are deactivated atomically.
    Returns the row id.
    """
    now = _utcnow()

    if make_active:
        SmtpConfig.query.update({"is_active": False})

    if config_id is None:
        cfg = SmtpConfig(
            label      = label,
            host       = host,
            port       = port,
            username   = username,
            password   = password,
            from_email = from_email,
            use_tls    = use_tls,
            is_active  = make_active,
            created_at = now,
            updated_at = now,
            created_by = created_by,
            updated_by = updated_by,
        )
        db.session.add(cfg)
    else:
        cfg = db.session.get(SmtpConfig, config_id)
        if not cfg:
            raise ValueError(f"SmtpConfig id={config_id} not found")
        cfg.label      = label
        cfg.host       = host
        cfg.port       = port
        cfg.username   = username
        cfg.password   = password
        cfg.from_email = from_email
        cfg.use_tls    = use_tls
        cfg.is_active  = make_active
        cfg.updated_at = now
        cfg.updated_by = updated_by

    db.session.commit()
    return cfg.id

def activate_smtp(config_id: int, updated_by: str | None = None) -> bool:
    """Make one profile active; deactivate all others. Returns False if not found."""
    cfg = db.session.get(SmtpConfig, config_id)
    if not cfg:
        return False
    now = _utcnow()
    SmtpConfig.query.update({"is_active": False})
    cfg.is_active  = True
    cfg.updated_at = now
    cfg.updated_by = updated_by
    db.session.commit()
    return True

def delete_smtp_config(config_id: int) -> bool:
    cfg = db.session.get(SmtpConfig, config_id)
    if not cfg:
        return False
    if cfg.is_active:
        raise ValueError("Cannot delete the active SMTP config. Activate another profile first.")
    db.session.delete(cfg)
    db.session.commit()
    return True

# Helper Functions
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _fmt(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def _mask_password(pw: str) -> str:
    if not pw:
        return ""
    return pw[:2] + "***" + pw[-1] if len(pw) > 3 else "***"
