"""
auth.py — local user accounts, roles, sessions and permissions.

All local, offline. Passwords are hashed with werkzeug's PBKDF2 (ships with
Flask — no extra dependency). Sessions are signed with a secret key that is
generated once and stored on disk so logins survive restarts.

Roles:
  admin   — manage users + everything an editor can do
  editor  — the security team: edit findings, change status, import, scan
  viewer  — bosses, colleagues, asset owners: view everything and comment;
            may also change the status of a finding whose Asset Owner matches
            their account (owners self-report progress on their own assets)
"""
import functools
import os
import secrets
import sqlite3
from datetime import datetime

from flask import session, redirect, url_for, flash, g, request
from werkzeug.security import generate_password_hash, check_password_hash

ROLES = ["admin", "editor", "viewer"]
ROLE_LABELS = {
    "admin": "Admin",
    "editor": "Editor (security team)",
    "viewer": "Viewer / commenter",
}


# ---------------------------------------------------------------------------
# Secret key: generate once, persist, so sessions survive restarts.
# ---------------------------------------------------------------------------
def load_or_create_secret(app_dir):
    path = os.path.join(app_dir, ".secret_key")
    try:
        with open(path, "r") as f:
            k = f.read().strip()
            if k:
                return k
    except FileNotFoundError:
        pass
    k = secrets.token_hex(32)
    try:
        with open(path, "w") as f:
            f.write(k)
        os.chmod(path, 0o600)
    except OSError:
        pass
    return k


# ---------------------------------------------------------------------------
# Schema + first-run admin bootstrap
# ---------------------------------------------------------------------------
def init_auth_schema(db):
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            display_name TEXT,
            email TEXT,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            active INTEGER NOT NULL DEFAULT 1,
            must_change_pw INTEGER NOT NULL DEFAULT 0,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT,
            FOREIGN KEY(finding_id) REFERENCES findings(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            finding_id INTEGER,
            action TEXT,
            detail TEXT,
            created_at TEXT
        );
        """
    )
    db.commit()


def bootstrap_admin(db):
    """
    On first run (no users), create an 'admin' account with a random one-time
    password and return it so the launcher can print it. Returns None if users
    already exist.
    """
    n = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if n:
        return None
    pw = secrets.token_urlsafe(9)
    db.execute(
        "INSERT INTO users(username, display_name, email, password_hash, role, active, must_change_pw, created_at) "
        "VALUES (?,?,?,?,?,1,1,?)",
        ("admin", "Administrator", "", generate_password_hash(pw), "admin",
         datetime.now().isoformat(timespec="seconds")),
    )
    db.commit()
    return pw


# ---------------------------------------------------------------------------
# User helpers
# ---------------------------------------------------------------------------
def get_user_by_username(db, username):
    return db.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone()


def get_user(db, user_id):
    return db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()


def verify_login(db, username, password):
    u = get_user_by_username(db, username)
    if not u or not u["active"]:
        return None
    if check_password_hash(u["password_hash"], password):
        return u
    return None


def create_user(db, username, display_name, email, password, role):
    db.execute(
        "INSERT INTO users(username, display_name, email, password_hash, role, active, must_change_pw, created_at) "
        "VALUES (?,?,?,?,?,1,0,?)",
        (username, display_name, email, generate_password_hash(password), role,
         datetime.now().isoformat(timespec="seconds")),
    )
    db.commit()


def set_password(db, user_id, password, clear_must_change=True):
    db.execute(
        "UPDATE users SET password_hash=?, must_change_pw=? WHERE id=?",
        (generate_password_hash(password), 0 if clear_must_change else 1, user_id),
    )
    db.commit()


# ---------------------------------------------------------------------------
# Session / current user
# ---------------------------------------------------------------------------
def current_user(db):
    uid = session.get("uid")
    if not uid:
        return None
    u = get_user(db, uid)
    if u and u["active"]:
        return u
    return None


def login_user(user):
    session.clear()
    session["uid"] = user["id"]
    session.permanent = True


def logout_user():
    session.clear()


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------
def can_edit_finding(user, finding_row=None):
    """
    admin/editor can always edit. A viewer can change a finding only when they
    are its named Asset Owner (match on display_name or username, case-insens).
    """
    if not user:
        return False
    if user["role"] in ("admin", "editor"):
        return True
    if user["role"] == "viewer" and finding_row is not None:
        owner = (finding_row["asset_owner"] or "").strip().lower()
        if owner and owner in ((user["display_name"] or "").strip().lower(),
                               (user["username"] or "").strip().lower()):
            return True
    return False


def can_import_or_scan(user):
    return bool(user) and user["role"] in ("admin", "editor")


def is_admin(user):
    return bool(user) and user["role"] == "admin"


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------
def login_required(view):
    @functools.wraps(view)
    def wrapped(*a, **kw):
        if not session.get("uid"):
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapped


def role_required(*roles):
    def deco(view):
        @functools.wraps(view)
        def wrapped(*a, **kw):
            if not session.get("uid"):
                return redirect(url_for("login", next=request.path))
            u = get_user(get_db_proxy(), session["uid"])
            if not u or u["role"] not in roles:
                flash("You don't have permission to do that.")
                return redirect(url_for("index"))
            return view(*a, **kw)
        return wrapped
    return deco


# the app injects its get_db here so the decorator can use it
_get_db = None
def register_db_getter(fn):
    global _get_db
    _get_db = fn
def get_db_proxy():
    return _get_db()


# ---------------------------------------------------------------------------
# Activity log
# ---------------------------------------------------------------------------
def log_activity(db, user_id, finding_id, action, detail=""):
    db.execute(
        "INSERT INTO activity(user_id, finding_id, action, detail, created_at) VALUES (?,?,?,?,?)",
        (user_id, finding_id, action, detail, datetime.now().isoformat(timespec="seconds")),
    )
    db.commit()
