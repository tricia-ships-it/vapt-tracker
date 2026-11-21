"""
VAPT Assessment & Remediation Tracker — offline Flask application.

Runs entirely on the internal network. No internet calls, no AI, no telemetry.
Data lives in a local SQLite file (vapt.db) next to this script.

Usage:
    pip install flask openpyxl   # one-time, on a machine that can reach PyPI,
                                 # or install from an offline wheel cache
    python app.py                # serves on http://127.0.0.1:5000 by default

Bind to the internal interface for team access, e.g.:
    python app.py --host 10.0.0.5 --port 8080
"""
import argparse
import io
import os
import re
import sqlite3
from datetime import date, datetime

from flask import (
    Flask, g, render_template, request, redirect, url_for,
    jsonify, send_file, abort, flash, session,
)

import engine
from parsers import detect_and_parse
import scanner as scanner_mod
import auth
import compliance
import asset_classify
import threatintel
import phishing
import delivery
import sending
import csv as _csv
import json as _json
import threading
import uuid
from datetime import timedelta

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "vapt.db")

app = Flask(__name__)
app.secret_key = auth.load_or_create_secret(APP_DIR)
app.permanent_session_lifetime = timedelta(hours=12)
auth.register_db_getter(lambda: get_db())

# --- session cookie hardening -------------------------------------------------
# HttpOnly keeps the cookie out of JS; SameSite=Lax blocks it on cross-site POSTs
# (a strong CSRF mitigation on its own); Secure is enabled when serving over
# HTTPS — set VAPT_HTTPS=1 behind a TLS reverse proxy.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("VAPT_HTTPS", "") in ("1", "true", "yes"),
    MAX_CONTENT_LENGTH=64 * 1024 * 1024,  # cap uploads at 64 MB
)

import secrets as _secrets

# --- CSRF protection ----------------------------------------------------------
# Session-bound token, required on every state-changing (non-GET) request.
# SameSite=Lax already blocks cross-site form POSTs; this token defends the
# JSON/fetch endpoints and gives defence-in-depth against same-site attacks.
CSRF_EXEMPT = set()  # none currently


def csrf_token():
    tok = session.get("_csrf")
    if not tok:
        tok = _secrets.token_urlsafe(32)
        session["_csrf"] = tok
    return tok


@app.before_request
def _csrf_protect():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    if request.endpoint in CSRF_EXEMPT:
        return
    sent = (request.form.get("_csrf")
            or request.headers.get("X-CSRF-Token")
            or (request.get_json(silent=True) or {}).get("_csrf"))
    if not sent or sent != session.get("_csrf"):
        abort(400, description="Invalid or missing CSRF token. Reload the page and try again.")


@app.after_request
def _security_headers(resp):
    # The same headers the scanner flags when missing on a host — set them here.
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    # Self-only CSP: the UI uses only same-origin assets and inline scripts.
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    )
    return resp


@app.context_processor
def _inject_csrf():
    return {"csrf_token": csrf_token}

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
# Input columns are stored; derived columns (actual_risk, target_fix_date,
# time_to_fix, risk_tolerance_objective) are computed by engine.py on read,
# so the logic lives in exactly one place.
INPUT_COLUMNS = [
    "ip_hostname", "device", "asset_classification", "vulnerability",
    "synopsis", "definition", "cve", "risk_statement", "reported_risk",
    "exploit_available", "exploit_reference", "solution", "asset_owner",
    "detection_date", "remediation_status", "actual_fix_date",
    "exception_requested", "exception_approved_by", "revised_target_fix_date",
    "asset_owners_comment", "comment", "source_tool",
]
DATE_COLUMNS = {"detection_date", "actual_fix_date", "revised_target_fix_date"}


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            scan_date TEXT,
            source_tool TEXT,
            imported_at TEXT
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            ip_hostname TEXT, device TEXT, asset_classification TEXT,
            vulnerability TEXT, synopsis TEXT, definition TEXT, cve TEXT,
            risk_statement TEXT, reported_risk TEXT, exploit_available TEXT,
            exploit_reference TEXT, solution TEXT, asset_owner TEXT,
            detection_date TEXT, remediation_status TEXT DEFAULT 'Pending',
            actual_fix_date TEXT, exception_requested TEXT DEFAULT 'No',
            exception_approved_by TEXT, revised_target_fix_date TEXT,
            asset_owners_comment TEXT, comment TEXT, source_tool TEXT,
            created_at TEXT, updated_at TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS asset_owners (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE
        );
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER,
            filename TEXT, mime TEXT, size INTEGER,
            data BLOB, uploaded_by INTEGER, created_at TEXT,
            FOREIGN KEY(finding_id) REFERENCES findings(id)
        );
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT, hostname TEXT, description TEXT, owner TEXT,
            criticality TEXT, asset_type TEXT, scan_policy TEXT,
            scan_eligible INTEGER DEFAULT 1, classify_reason TEXT,
            authorized_by TEXT, authorized_at TEXT,
            source TEXT, created_at TEXT, updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY, value TEXT
        );
        CREATE TABLE IF NOT EXISTS threat_feed (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve TEXT, title TEXT, products TEXT, severity TEXT, source TEXT,
            kev INTEGER, date TEXT, summary TEXT, imported_at TEXT
        );
        CREATE TABLE IF NOT EXISTS phish_campaign (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT, template_key TEXT, sender TEXT, subject TEXT,
            body TEXT, landing_note TEXT,
            channel TEXT DEFAULT 'email',
            authorized INTEGER DEFAULT 0, authorized_by TEXT, authorized_at TEXT,
            status TEXT DEFAULT 'Draft',
            created_by INTEGER, created_at TEXT,
            launched_at TEXT, closed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS phish_recipient (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id INTEGER,
            name TEXT, email TEXT, department TEXT,
            phone TEXT, handle TEXT,
            token TEXT UNIQUE,
            clicked_at TEXT, reported_at TEXT, click_count INTEGER DEFAULT 0,
            sent_at TEXT, delivery_status TEXT, delivery_error TEXT,
            FOREIGN KEY(campaign_id) REFERENCES phish_campaign(id)
        );
        CREATE TABLE IF NOT EXISTS phish_event (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_id INTEGER, campaign_id INTEGER,
            kind TEXT, at TEXT, user_agent TEXT,
            FOREIGN KEY(recipient_id) REFERENCES phish_recipient(id)
        );
        CREATE TABLE IF NOT EXISTS phish_send_job (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id INTEGER, channel TEXT, status TEXT,
            total INTEGER, processed INTEGER DEFAULT 0,
            ok_count INTEGER DEFAULT 0, fail_count INTEGER DEFAULT 0,
            rate_per_min INTEGER DEFAULT 30, scheduled_at TEXT,
            include_sent INTEGER DEFAULT 0, base_url TEXT,
            created_by TEXT, created_at TEXT,
            started_at TEXT, finished_at TEXT, last_error TEXT,
            FOREIGN KEY(campaign_id) REFERENCES phish_campaign(id)
        );
        """
    )
    # WAL lets the background send worker write progress while web requests
    # read, without 'database is locked' contention.
    try:
        db.execute("PRAGMA journal_mode=WAL")
    except sqlite3.Error:
        pass
    # lightweight migrations: add columns that newer versions introduced to
    # tables that already exist in an older deployment's database.
    def _ensure_cols(table, cols):
        have = {r[1] for r in db.execute(f"PRAGMA table_info({table})")}
        for name, ddl in cols.items():
            if name not in have:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
    _ensure_cols("phish_campaign", {
        "channel": "channel TEXT DEFAULT 'email'",
        "authorized": "authorized INTEGER DEFAULT 0",
        "authorized_by": "authorized_by TEXT",
        "authorized_at": "authorized_at TEXT",
    })
    _ensure_cols("phish_recipient", {
        "phone": "phone TEXT", "handle": "handle TEXT",
        "sent_at": "sent_at TEXT", "delivery_status": "delivery_status TEXT",
        "delivery_error": "delivery_error TEXT",
    })
    # seed a few default owners if empty
    cur = db.execute("SELECT COUNT(*) FROM asset_owners")
    if cur.fetchone()[0] == 0:
        for n in ["Network Team", "Systems Team", "Security Team", "Unassigned"]:
            db.execute("INSERT OR IGNORE INTO asset_owners(name) VALUES (?)", (n,))
    db.commit()
    # auth tables + first-run admin
    auth.init_auth_schema(db)
    pw = auth.bootstrap_admin(db)
    db.close()
    return pw  # one-time admin password on first run, else None


@app.context_processor
def inject_user():
    """Make the current user and permission helpers available in every template."""
    try:
        u = auth.current_user(get_db())
    except Exception:
        u = None
    return {
        "current_user": u,
        "is_admin": auth.is_admin(u),
        "can_import_or_scan": auth.can_import_or_scan(u),
        "role_labels": auth.ROLE_LABELS,
    }


# ---------------------------------------------------------------------------
# Helpers: date parsing, row enrichment
# ---------------------------------------------------------------------------
def parse_date(s):
    if not s:
        return None
    if isinstance(s, (date, datetime)):
        return s.date() if isinstance(s, datetime) else s
    s = str(s).strip()
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%b %d, %Y", "%d-%b-%Y"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    return None


def iso(d):
    return d.isoformat() if d else None


def fmt_display(d):
    return d.strftime("%b %d, %Y") if d else ""


def enrich(row):
    """Row (sqlite Row) -> dict with derived fields computed by the engine."""
    r = dict(row)
    inp = {
        "asset_classification": r.get("asset_classification"),
        "reported_risk": r.get("reported_risk"),
        "exploit_available": r.get("exploit_available"),
        "detection_date": parse_date(r.get("detection_date")),
        "remediation_status": r.get("remediation_status"),
        "actual_fix_date": parse_date(r.get("actual_fix_date")),
        "revised_target_fix_date": parse_date(r.get("revised_target_fix_date")),
    }
    derived = engine.compute_row(inp)
    r["actual_risk_classification"] = derived["actual_risk_classification"] or ""
    r["target_fix_date"] = fmt_display(derived["target_fix_date"])
    r["target_fix_date_iso"] = iso(derived["target_fix_date"])
    r["time_to_fix_days"] = derived["time_to_fix_days"] if derived["time_to_fix_days"] is not None else ""
    r["risk_tolerance_objective"] = derived["risk_tolerance_objective"] or ""
    # display versions of stored dates
    r["detection_date_disp"] = fmt_display(parse_date(r.get("detection_date")))
    r["actual_fix_date_disp"] = fmt_display(parse_date(r.get("actual_fix_date")))
    r["revised_target_fix_date_disp"] = fmt_display(parse_date(r.get("revised_target_fix_date")))
    return r


def owner_list():
    db = get_db()
    return [row["name"] for row in db.execute("SELECT name FROM asset_owners ORDER BY name")]


# ---------------------------------------------------------------------------
# Routes: authentication
# ---------------------------------------------------------------------------
# Simple in-memory login throttle: lock an IP for a spell after repeated misses.
_LOGIN_FAILS = {}  # ip -> [count, first_ts]
_LOGIN_MAX = 8
_LOGIN_WINDOW = 300  # seconds


def _safe_next(target):
    """Allow only same-site relative paths, never absolute/scheme-relative URLs."""
    if not target:
        return None
    if target.startswith("//") or "://" in target or "\\" in target:
        return None
    if not target.startswith("/"):
        return None
    return target


@app.route("/login", methods=["GET", "POST"])
def login():
    db = get_db()
    if request.method == "POST":
        import time as _t
        ip = request.remote_addr or "?"
        rec = _LOGIN_FAILS.get(ip)
        if rec and rec[0] >= _LOGIN_MAX and (_t.time() - rec[1]) < _LOGIN_WINDOW:
            flash("Too many failed attempts. Wait a few minutes and try again.")
            return render_template("login.html", username="")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        u = auth.verify_login(db, username, password)
        if not u:
            r = _LOGIN_FAILS.get(ip)
            if not r or (_t.time() - r[1]) >= _LOGIN_WINDOW:
                _LOGIN_FAILS[ip] = [1, _t.time()]
            else:
                r[0] += 1
            flash("Incorrect username or password, or the account is inactive.")
            return render_template("login.html", username=username)
        _LOGIN_FAILS.pop(ip, None)
        auth.login_user(u)
        auth.log_activity(db, u["id"], None, "login", "")
        if u["must_change_pw"]:
            return redirect(url_for("change_password"))
        nxt = _safe_next(request.args.get("next")) or url_for("index")
        return redirect(nxt)
    if auth.current_user(db):
        return redirect(url_for("index"))
    return render_template("login.html", username="")


@app.route("/logout")
def logout():
    auth.logout_user()
    return redirect(url_for("login"))


@app.route("/account/password", methods=["GET", "POST"])
@auth.login_required
def change_password():
    db = get_db()
    u = auth.current_user(db)
    if request.method == "POST":
        cur = request.form.get("current", "")
        new = request.form.get("new", "")
        confirm = request.form.get("confirm", "")
        if not auth.verify_login(db, u["username"], cur):
            flash("Your current password is incorrect.")
        elif len(new) < 8:
            flash("New password must be at least 8 characters.")
        elif new != confirm:
            flash("New passwords don't match.")
        else:
            auth.set_password(db, u["id"], new)
            flash("Password updated.")
            return redirect(url_for("index"))
    return render_template("change_password.html", must_change=bool(u["must_change_pw"]))


# ---------------------------------------------------------------------------
# Routes: user management (admin only)
# ---------------------------------------------------------------------------
@app.route("/users")
@auth.role_required("admin")
def users():
    db = get_db()
    rows = db.execute("SELECT * FROM users ORDER BY role, username").fetchall()
    return render_template("users.html", users=rows, roles=auth.ROLES, role_labels=auth.ROLE_LABELS)


@app.route("/users/add", methods=["POST"])
@auth.role_required("admin")
def users_add():
    db = get_db()
    username = request.form.get("username", "").strip()
    display = request.form.get("display_name", "").strip()
    email = request.form.get("email", "").strip()
    role = request.form.get("role", "viewer")
    password = request.form.get("password", "")
    if not username or not password:
        flash("Username and an initial password are required.")
        return redirect(url_for("users"))
    if role not in auth.ROLES:
        role = "viewer"
    if auth.get_user_by_username(db, username):
        flash("That username already exists.")
        return redirect(url_for("users"))
    auth.create_user(db, username, display or username, email, password, role)
    flash(f"Account created for {username}. Share the initial password securely; they can change it after signing in.")
    return redirect(url_for("users"))


@app.route("/users/<int:uid>/role", methods=["POST"])
@auth.role_required("admin")
def users_role(uid):
    db = get_db()
    role = request.form.get("role", "viewer")
    if role in auth.ROLES:
        db.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
        db.commit()
    return redirect(url_for("users"))


@app.route("/users/<int:uid>/active", methods=["POST"])
@auth.role_required("admin")
def users_active(uid):
    db = get_db()
    me = auth.current_user(db)
    if me and me["id"] == uid:
        flash("You can't deactivate your own account.")
        return redirect(url_for("users"))
    cur = db.execute("SELECT active FROM users WHERE id=?", (uid,)).fetchone()
    if cur is not None:
        db.execute("UPDATE users SET active=? WHERE id=?", (0 if cur["active"] else 1, uid))
        db.commit()
    return redirect(url_for("users"))


@app.route("/users/<int:uid>/reset", methods=["POST"])
@auth.role_required("admin")
def users_reset(uid):
    db = get_db()
    newpw = request.form.get("password", "").strip()
    if len(newpw) < 8:
        flash("Reset password must be at least 8 characters.")
        return redirect(url_for("users"))
    auth.set_password(db, uid, newpw, clear_must_change=False)
    db.execute("UPDATE users SET must_change_pw=1 WHERE id=?", (uid,))
    db.commit()
    flash("Password reset. The user will be asked to set a new one at next sign-in.")
    return redirect(url_for("users"))


# ---------------------------------------------------------------------------
# Routes: dashboard & findings table
# ---------------------------------------------------------------------------
@app.route("/")
@auth.login_required
def index():
    db = get_db()
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    risk = request.args.get("risk", "").strip()
    breach = request.args.get("breach", "").strip()
    sql = "SELECT * FROM findings WHERE 1=1"
    params = []
    if q:
        sql += " AND (ip_hostname LIKE ? OR vulnerability LIKE ? OR cve LIKE ?)"
        params += [f"%{q}%", f"%{q}%", f"%{q}%"]
    if status:
        sql += " AND remediation_status = ?"
        params.append(status)
    sql += " ORDER BY id DESC"
    me = auth.current_user(db)
    raw_rows = db.execute(sql, params).fetchall()
    rows = []
    for raw in raw_rows:
        er = enrich(raw)
        er["can_edit"] = auth.can_edit_finding(me, raw)
        rows.append(er)
    if risk:
        rows = [r for r in rows if r["actual_risk_classification"] == risk]
    if breach:
        rows = [r for r in rows if r["risk_tolerance_objective"] == "Breached"]

    # stats
    all_rows = [enrich(r) for r in db.execute("SELECT * FROM findings")]
    stats = {
        "total": len(all_rows),
        "critical": sum(1 for r in all_rows if r["actual_risk_classification"] == "Critical"),
        "high": sum(1 for r in all_rows if r["actual_risk_classification"] == "High"),
        "medium": sum(1 for r in all_rows if r["actual_risk_classification"] == "Medium"),
        "low": sum(1 for r in all_rows if r["actual_risk_classification"] == "Low"),
        "information": sum(1 for r in all_rows if r["actual_risk_classification"] == "Information"),
        "open": sum(1 for r in all_rows if r["remediation_status"] not in ("Fixed", "Not Applicable")),
        "breached": sum(1 for r in all_rows if r["risk_tolerance_objective"] == "Breached"),
        "overdue": sum(1 for r in all_rows if _is_overdue(r)),
    }
    return render_template(
        "index.html", rows=rows, stats=stats, owners=owner_list(),
        statuses=engine.REMEDIATION_STATUSES, severities=engine.SEVERITIES,
        exploits=engine.EXPLOIT_OPTIONS, q=q, status=status, risk=risk, breach=breach,
        today_iso=date.today().isoformat(),
    )


def _is_overdue(r):
    if r["remediation_status"] in ("Fixed", "Not Applicable", "Risk Accepted", "Exception Approved"):
        return False
    tfd = r.get("revised_target_fix_date_iso") or r.get("target_fix_date_iso")
    if not tfd:
        return False
    return parse_date(tfd) < date.today()


# ---------------------------------------------------------------------------
# Routes: dashboard (charts & summary for presentation)
# ---------------------------------------------------------------------------
@app.route("/dashboard")
@auth.login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/dashboard/data")
@auth.login_required
def dashboard_data():
    """Aggregations for the dashboard charts, computed from live findings."""
    db = get_db()
    rows = [enrich(r) for r in db.execute("SELECT * FROM findings")]
    today = date.today()

    def counter(order):
        return {k: 0 for k in order}

    sev_order = ["Critical", "High", "Medium", "Low", "Information"]
    status_order = engine.REMEDIATION_STATUSES
    rto_order = ["Met", "Breached", "Not Applicable", "Open"]

    by_actual_risk = counter(sev_order)
    by_reported = counter(sev_order)
    by_status = counter(status_order)
    by_rto = counter(rto_order)
    by_exploit = {"Yes": 0, "No": 0, "Unknown": 0}
    owners = {}
    open_vs_closed = {"Open": 0, "Fixed": 0, "Not Applicable": 0}
    overdue = 0

    for r in rows:
        ar = r["actual_risk_classification"]
        if ar in by_actual_risk:
            by_actual_risk[ar] += 1
        rr = r["reported_risk"]
        if rr in by_reported:
            by_reported[rr] += 1
        st = r["remediation_status"]
        if st in by_status:
            by_status[st] += 1
        rto = r["risk_tolerance_objective"]
        if rto in ("Met", "Breached", "Not Applicable"):
            by_rto[rto] += 1
        else:
            by_rto["Open"] += 1
        ex = r["exploit_available"] or "Unknown"
        by_exploit[ex] = by_exploit.get(ex, 0) + 1
        owner = r["asset_owner"] or "Unassigned"
        owners[owner] = owners.get(owner, 0) + 1
        if st == "Fixed":
            open_vs_closed["Fixed"] += 1
        elif st == "Not Applicable":
            open_vs_closed["Not Applicable"] += 1
        else:
            open_vs_closed["Open"] += 1
        if _is_overdue(r):
            overdue += 1

    # top owners by finding count (max 8)
    top_owners = sorted(owners.items(), key=lambda kv: kv[1], reverse=True)[:8]

    total = len(rows)
    crit = by_actual_risk["Critical"]
    high = by_actual_risk["High"]
    open_count = open_vs_closed["Open"]
    fixed = open_vs_closed["Fixed"]
    breached = by_rto["Breached"]
    # remediation rate = resolved / total
    resolved = fixed + open_vs_closed["Not Applicable"]
    rem_rate = round(100 * resolved / total) if total else 0

    return jsonify({
        "totals": {
            "total": total, "critical": crit, "high": high,
            "open": open_count, "fixed": fixed, "breached": breached,
            "overdue": overdue, "remediation_rate": rem_rate,
        },
        "by_actual_risk": by_actual_risk,
        "by_reported": by_reported,
        "by_status": {k: v for k, v in by_status.items() if v > 0},
        "by_rto": by_rto,
        "by_exploit": by_exploit,
        "top_owners": top_owners,
        "open_vs_closed": open_vs_closed,
    })


@app.route("/finding/new", methods=["GET", "POST"])
@auth.role_required("admin", "editor")
def finding_new():
    db = get_db()
    me = auth.current_user(db)
    if request.method == "POST":
        rec = _form_to_dict(request.form)
        rec.setdefault("source_tool", "Manual")
        _insert_finding(rec, scan_id=None)
        fid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        auth.log_activity(db, me["id"], fid, "created",
                          request.form.get("vulnerability", "")[:120])
        flash("Finding added.")
        return redirect(url_for("index"))
    return render_template(
        "finding_form.html", finding={}, owners=owner_list(),
        statuses=engine.REMEDIATION_STATUSES, severities=engine.SEVERITIES,
        exploits=engine.EXPLOIT_OPTIONS, is_new=True, comments=[], can_edit=True,
    )


@app.route("/finding/<int:fid>/edit", methods=["GET", "POST"])
@auth.login_required
def finding_edit(fid):
    db = get_db()
    me = auth.current_user(db)
    row = db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    if not row:
        abort(404)
    editable = auth.can_edit_finding(me, row)
    if request.method == "POST":
        if not editable:
            flash("You can view and comment on this finding, but only the security team or the asset owner can edit it.")
            return redirect(url_for("finding_edit", fid=fid))
        prev_status = row["remediation_status"]
        form_data = _form_to_dict(request.form)
        # A non-editor asset owner may update remediation progress only — not the
        # finding's classification, ownership, or the vulnerability details.
        if me["role"] not in ("admin", "editor"):
            allowed = {"remediation_status", "actual_fix_date", "exception_requested",
                       "exception_approved_by", "revised_target_fix_date",
                       "asset_owners_comment", "comment"}
            form_data = {k: v for k, v in form_data.items() if k in allowed}
        _update_finding(fid, form_data)
        fresh = db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
        if fresh["remediation_status"] != prev_status:
            auth.log_activity(db, me["id"], fid, "status",
                              f'{prev_status} → {fresh["remediation_status"]} on {row["ip_hostname"]}')
        else:
            auth.log_activity(db, me["id"], fid, "edited", row["ip_hostname"])
        flash("Finding updated.")
        return redirect(url_for("index"))
    comments = db.execute(
        "SELECT c.*, u.display_name, u.username, u.role FROM comments c "
        "JOIN users u ON u.id=c.user_id WHERE c.finding_id=? ORDER BY c.created_at", (fid,)
    ).fetchall()
    return render_template(
        "finding_form.html", finding=enrich(row), owners=owner_list(),
        statuses=engine.REMEDIATION_STATUSES, severities=engine.SEVERITIES,
        exploits=engine.EXPLOIT_OPTIONS, is_new=False, comments=comments, can_edit=editable,
    )


@app.route("/finding/<int:fid>/delete", methods=["POST"])
@auth.role_required("admin", "editor")
def finding_delete(fid):
    db = get_db()
    me = auth.current_user(db)
    row = db.execute("SELECT ip_hostname, vulnerability FROM findings WHERE id=?", (fid,)).fetchone()
    db.execute("DELETE FROM findings WHERE id=?", (fid,))
    db.execute("DELETE FROM comments WHERE finding_id=?", (fid,))
    db.commit()
    if row:
        auth.log_activity(db, me["id"], None, "deleted", f'{row["ip_hostname"]}: {row["vulnerability"][:80]}')
    flash("Finding deleted.")
    return redirect(url_for("index"))


# Inline status update (AJAX) — auto-stamps actual_fix_date when closing.
@app.route("/finding/<int:fid>/status", methods=["POST"])
@auth.login_required
def finding_status(fid):
    db = get_db()
    me = auth.current_user(db)
    row = db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    if not row:
        abort(404)
    if not auth.can_edit_finding(me, row):
        return jsonify({"ok": False, "error": "no_permission"}), 403
    new_status = request.json.get("status")
    updates = {"remediation_status": new_status,
               "updated_at": datetime.now().isoformat(timespec="seconds")}
    # Auto-stamp Actual Fix Date the moment status becomes Fixed/Not Applicable,
    # but only if it isn't already set (stays editable afterward).
    if new_status in engine.CLOSING_STATUSES and not row["actual_fix_date"]:
        updates["actual_fix_date"] = date.today().isoformat()
    sets = ", ".join(f"{k}=?" for k in updates)
    db.execute(f"UPDATE findings SET {sets} WHERE id=?", (*updates.values(), fid))
    db.commit()
    auth.log_activity(db, me["id"], fid, "status",
                      f'{row["remediation_status"]} → {new_status} on {row["ip_hostname"]}')
    fresh = enrich(db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone())
    return jsonify({
        "ok": True,
        "actual_fix_date": fresh["actual_fix_date_disp"],
        "risk_tolerance_objective": fresh["risk_tolerance_objective"],
        "actual_risk_classification": fresh["actual_risk_classification"],
        "target_fix_date": fresh["target_fix_date"],
    })


# ---------------------------------------------------------------------------
# Routes: threaded comments + activity feed
# ---------------------------------------------------------------------------
@app.route("/finding/<int:fid>/comment", methods=["POST"])
@auth.login_required
def finding_comment(fid):
    db = get_db()
    me = auth.current_user(db)
    row = db.execute("SELECT ip_hostname FROM findings WHERE id=?", (fid,)).fetchone()
    if not row:
        abort(404)
    body = request.form.get("body", "").strip()
    if body:
        db.execute("INSERT INTO comments(finding_id, user_id, body, created_at) VALUES (?,?,?,?)",
                   (fid, me["id"], body, datetime.now().isoformat(timespec="seconds")))
        db.commit()
        auth.log_activity(db, me["id"], fid, "comment", f'on {row["ip_hostname"]}: {body[:80]}')
    return redirect(url_for("finding_edit", fid=fid) + "#discussion")


@app.route("/activity")
@auth.login_required
def activity_feed():
    db = get_db()
    rows = db.execute(
        "SELECT a.*, u.display_name, u.username, u.role, f.ip_hostname, f.vulnerability "
        "FROM activity a LEFT JOIN users u ON u.id=a.user_id "
        "LEFT JOIN findings f ON f.id=a.finding_id "
        "ORDER BY a.id DESC LIMIT 300"
    ).fetchall()
    return render_template("activity.html", rows=rows)


def _finding_key(row):
    """Stable identity for a finding across scans: host + CVE (or normalised vuln)."""
    vuln = (row["vulnerability"] or "").lower()
    vuln = re.sub(r"\s*\(\d+/tcp\)\s*$", "", vuln).strip()
    ip = (row["ip_hostname"] or "").lower().strip()
    cve = (row["cve"] or "").lower().strip()
    return (ip, cve or vuln)


@app.route("/finding/<int:fid>")
@auth.login_required
def finding_detail(fid):
    db = get_db()
    me = auth.current_user(db)
    row = db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    if not row:
        abort(404)
    f = enrich(row)
    f["can_edit"] = auth.can_edit_finding(me, row)
    comments = db.execute(
        "SELECT c.*, u.display_name, u.username, u.role FROM comments c "
        "JOIN users u ON u.id=c.user_id WHERE c.finding_id=? ORDER BY c.created_at", (fid,)
    ).fetchall()
    acts = db.execute(
        "SELECT a.*, u.display_name, u.username, u.role FROM activity a "
        "LEFT JOIN users u ON u.id=a.user_id WHERE a.finding_id=? ORDER BY a.id DESC", (fid,)
    ).fetchall()
    evidence = db.execute(
        "SELECT e.id, e.filename, e.mime, e.size, e.created_at, u.display_name, u.username "
        "FROM evidence e LEFT JOIN users u ON u.id=e.uploaded_by "
        "WHERE e.finding_id=? ORDER BY e.id DESC", (fid,)
    ).fetchall()
    controls = compliance.map_finding(f, _enabled_frameworks(db))
    return render_template("finding_detail.html", f=f, comments=comments, activity=acts,
                           evidence=evidence, controls=controls,
                           statuses=engine.REMEDIATION_STATUSES)


MAX_EVIDENCE = 5 * 1024 * 1024  # 5 MB per file


@app.route("/finding/<int:fid>/evidence", methods=["POST"])
@auth.login_required
def evidence_upload(fid):
    db = get_db()
    me = auth.current_user(db)
    row = db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    if not row:
        abort(404)
    if not auth.can_edit_finding(me, row):
        flash("Only the security team or the asset owner can add evidence to this finding.")
        return redirect(url_for("finding_detail", fid=fid))
    file = request.files.get("evidence")
    if not file or not file.filename:
        flash("No file selected.")
        return redirect(url_for("finding_detail", fid=fid) + "#evidence")
    data = file.read(MAX_EVIDENCE + 1)
    if len(data) > MAX_EVIDENCE:
        flash("File too large (max 5 MB).")
        return redirect(url_for("finding_detail", fid=fid) + "#evidence")
    fname = os.path.basename(file.filename)[:200]
    db.execute("INSERT INTO evidence(finding_id, filename, mime, size, data, uploaded_by, created_at)"
               " VALUES (?,?,?,?,?,?,?)",
               (fid, fname, file.mimetype or "application/octet-stream", len(data), data,
                me["id"], datetime.now().isoformat(timespec="seconds")))
    db.commit()
    auth.log_activity(db, me["id"], fid, "evidence", f'attached {fname} to {row["ip_hostname"]}')
    flash("Evidence attached.")
    return redirect(url_for("finding_detail", fid=fid) + "#evidence")


@app.route("/evidence/<int:eid>")
@auth.login_required
def evidence_download(eid):
    db = get_db()
    row = db.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
    if not row:
        abort(404)
    return send_file(io.BytesIO(row["data"]), mimetype=row["mime"] or "application/octet-stream",
                     as_attachment=True, download_name=row["filename"] or f"evidence-{eid}")


@app.route("/evidence/<int:eid>/delete", methods=["POST"])
@auth.login_required
def evidence_delete(eid):
    db = get_db()
    me = auth.current_user(db)
    row = db.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
    if not row:
        abort(404)
    finding = db.execute("SELECT * FROM findings WHERE id=?", (row["finding_id"],)).fetchone()
    if not (finding and auth.can_edit_finding(me, finding)):
        abort(403)
    db.execute("DELETE FROM evidence WHERE id=?", (eid,))
    db.commit()
    auth.log_activity(db, me["id"], row["finding_id"], "evidence", f'removed {row["filename"]}')
    flash("Evidence removed.")
    return redirect(url_for("finding_detail", fid=row["finding_id"]) + "#evidence")


# ---------------------------------------------------------------------------
# Scan-to-scan diff (New / Resolved / Recurring between two scans)
# ---------------------------------------------------------------------------
@app.route("/diff")
@auth.login_required
def scan_diff():
    db = get_db()
    scans_sorted = db.execute(
        "SELECT * FROM scans ORDER BY COALESCE(scan_date, imported_at) DESC, id DESC"
    ).fetchall()
    latest = scans_sorted[0] if scans_sorted else None
    prev = scans_sorted[1] if len(scans_sorted) > 1 else None
    a = request.args.get("base", type=int)
    b = request.args.get("target", type=int)
    if a and b:
        prev = db.execute("SELECT * FROM scans WHERE id=?", (a,)).fetchone()
        latest = db.execute("SELECT * FROM scans WHERE id=?", (b,)).fetchone()

    result = None
    if latest and prev and latest["id"] != prev["id"]:
        latest_rows = db.execute("SELECT * FROM findings WHERE scan_id=?", (latest["id"],)).fetchall()
        prev_rows = db.execute("SELECT * FROM findings WHERE scan_id=?", (prev["id"],)).fetchall()
        latest_map, prev_map = {}, {}
        for r in latest_rows:
            latest_map.setdefault(_finding_key(r), r)
        for r in prev_rows:
            prev_map.setdefault(_finding_key(r), r)
        new = [enrich(latest_map[k]) for k in latest_map if k not in prev_map]
        resolved = [enrich(prev_map[k]) for k in prev_map if k not in latest_map]
        recurring = [enrich(latest_map[k]) for k in latest_map if k in prev_map]
        sev_sort = lambda L: sorted(L, key=lambda r: -compliance.SEV_RANK.get(r["actual_risk_classification"], 0))
        result = {"new": sev_sort(new), "resolved": sev_sort(resolved),
                  "recurring": sev_sort(recurring)}
    return render_template("diff.html", scans=scans_sorted, latest=latest, prev=prev, result=result)


# ---------------------------------------------------------------------------
# Asset inventory (findings grouped by host)
# ---------------------------------------------------------------------------
@app.route("/assets")
@auth.login_required
def assets():
    db = get_db()
    rows = [enrich(r) for r in db.execute("SELECT * FROM findings")]
    rank = compliance.SEV_RANK
    hosts = {}
    for r in rows:
        key = r["ip_hostname"] or "—"
        h = hosts.setdefault(key, {
            "ip": key, "device": r.get("device") or "", "owners": set(),
            "total": 0, "open": 0, "exposed": 0, "breached": 0,
            "sev": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Information": 0},
            "max_sev": "", "max_rank": -1,
        })
        if r.get("device"):
            h["device"] = r["device"]
        if r.get("asset_owner"):
            h["owners"].add(r["asset_owner"])
        h["total"] += 1
        ar = r["actual_risk_classification"] or "Information"
        if ar in h["sev"]:
            h["sev"][ar] += 1
        if rank.get(ar, 0) > h["max_rank"]:
            h["max_rank"] = rank.get(ar, 0)
            h["max_sev"] = ar
        if r["remediation_status"] not in ("Fixed", "Not Applicable"):
            h["open"] += 1
        vl = (r["vulnerability"] or "").lower()
        if "exposed" in vl or "open service" in vl:
            h["exposed"] += 1
        if r["risk_tolerance_objective"] == "Breached":
            h["breached"] += 1
    host_list = sorted(hosts.values(), key=lambda h: (-h["max_rank"], -h["open"], h["ip"]))
    for h in host_list:
        h["owners"] = sorted(h["owners"])
    return render_template("assets.html", hosts=host_list, total_hosts=len(host_list))


# ---------------------------------------------------------------------------
# Compliance coverage (ISO 27001 / PCI DSS control areas touched by findings)
# ---------------------------------------------------------------------------
@app.route("/compliance")
@auth.login_required
def compliance_view():
    db = get_db()
    enabled = _enabled_frameworks(db)
    rows = [enrich(r) for r in db.execute("SELECT * FROM findings")]
    cov = compliance.coverage(rows, enabled)
    return render_template("compliance.html", coverage=cov, frameworks=list(cov.keys()),
                           total=len(rows))


# ===========================================================================
# Settings + threat intelligence (offline-first, fetch-only)
# ===========================================================================
def get_setting(db, key, default=None):
    r = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return r["value"] if r else default


def set_setting(db, key, value):
    db.execute("INSERT INTO settings(key, value) VALUES (?, ?) "
               "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))


def _enabled_sources(db):
    raw = get_setting(db, "ti_sources")
    if raw is None:
        return [s["id"] for s in threatintel.SOURCES]  # all checked by default
    try:
        return _json.loads(raw)
    except Exception:
        return []


def _enabled_frameworks(db):
    raw = get_setting(db, "comp_frameworks")
    if raw is None:
        return compliance.DEFAULT_ENABLED
    try:
        ids = _json.loads(raw)
        return [i for i in ids if i in compliance.FRAMEWORK_BY_ID]
    except Exception:
        return compliance.DEFAULT_ENABLED


@app.route("/settings")
@auth.login_required
@auth.role_required("admin")
def settings_page():
    db = get_db()
    enabled = set(_enabled_sources(db))
    sources = [{**s, "checked": s["id"] in enabled} for s in threatintel.SOURCES]
    enabled_fw = set(_enabled_frameworks(db))
    frameworks = [{**f, "checked": f["id"] in enabled_fw} for f in compliance.FRAMEWORKS]
    return render_template(
        "settings.html", sources=sources, frameworks=frameworks,
        ti_enabled=(get_setting(db, "ti_enabled", "0") == "1"),
        ti_proxy=get_setting(db, "ti_proxy", "") or "",
        last_update=get_setting(db, "ti_last_update", ""),
        feed_count=db.execute("SELECT COUNT(*) c FROM threat_feed").fetchone()["c"],
        delivery_status=delivery.provider_status(),
    )


@app.route("/settings/threatintel", methods=["POST"])
@auth.login_required
@auth.role_required("admin")
def settings_threatintel():
    db = get_db()
    me = auth.current_user(db)
    set_setting(db, "ti_enabled", "1" if request.form.get("ti_enabled") else "0")
    # only ids that actually exist in the hardcoded registry can be enabled
    chosen = [s["id"] for s in threatintel.SOURCES
              if request.form.get("src_" + s["id"])]
    set_setting(db, "ti_sources", _json.dumps(chosen))
    set_setting(db, "ti_proxy", request.form.get("ti_proxy", "").strip())
    db.commit()
    auth.log_activity(db, me["id"], None, "settings", "updated threat-feed settings")
    flash("Threat-feed settings saved.")
    return redirect(url_for("settings_page"))


@app.route("/settings/frameworks", methods=["POST"])
@auth.login_required
@auth.role_required("admin")
def settings_frameworks():
    db = get_db()
    me = auth.current_user(db)
    chosen = [f["id"] for f in compliance.FRAMEWORKS if request.form.get("fw_" + f["id"])]
    set_setting(db, "comp_frameworks", _json.dumps(chosen))
    db.commit()
    auth.log_activity(db, me["id"], None, "settings", "updated compliance frameworks")
    flash("Compliance frameworks updated.")
    return redirect(url_for("settings_page"))


@app.route("/threatintel/update", methods=["POST"])
@auth.login_required
@auth.role_required("editor", "admin")
def threatintel_update():
    db = get_db()
    me = auth.current_user(db)
    if get_setting(db, "ti_enabled", "0") != "1":
        flash("Online threat-feed updates are turned off. Enable them in Settings first, "
              "or import a feed file for air-gapped use.")
        return redirect(url_for("settings_page"))
    proxy = get_setting(db, "ti_proxy", "") or None
    enabled = _enabled_sources(db)
    records, errors = [], []
    for sid in enabled:
        try:
            records.extend(threatintel.fetch_source(sid, proxy=proxy))
        except Exception as e:
            errors.append(f"{sid}: {e}")
    if records:
        _store_feed(db, records)
        set_setting(db, "ti_last_update", datetime.now().isoformat(timespec="seconds"))
        db.commit()
        auth.log_activity(db, me["id"], None, "threatintel", f"updated feed ({len(records)} records)")
    msg = f"Fetched {len(records)} feed records from {len(enabled)} source(s)."
    if errors:
        msg += " Some sources could not be reached: " + "; ".join(errors)
    flash(msg)
    return redirect(url_for("threatintel_view"))


@app.route("/threatintel/import", methods=["POST"])
@auth.login_required
@auth.role_required("editor", "admin")
def threatintel_import():
    db = get_db()
    me = auth.current_user(db)
    file = request.files.get("file")
    if not file or not file.filename:
        flash("Choose a feed file (produced by feedsync.py) to import.")
        return redirect(url_for("settings_page"))
    MAX_FEED = 128 * 1024 * 1024  # 128 MB
    blob = file.read(MAX_FEED + 1)
    if len(blob) > MAX_FEED:
        flash("Feed file too large (max 128 MB).")
        return redirect(url_for("settings_page"))
    try:
        payload = _json.loads(blob.decode("utf-8", "ignore"))
        records = payload.get("records") if isinstance(payload, dict) else payload
        assert isinstance(records, list)
    except Exception as e:
        flash(f"Could not read that feed file: {e}")
        return redirect(url_for("settings_page"))
    _store_feed(db, records)
    set_setting(db, "ti_last_update", datetime.now().isoformat(timespec="seconds") + " (imported)")
    db.commit()
    auth.log_activity(db, me["id"], None, "threatintel", f"imported feed ({len(records)} records)")
    flash(f"Imported {len(records)} feed records.")
    return redirect(url_for("threatintel_view"))


def _store_feed(db, records):
    db.execute("DELETE FROM threat_feed")
    now = datetime.now().isoformat(timespec="seconds")
    for r in records:
        db.execute(
            "INSERT INTO threat_feed(cve, title, products, severity, source, kev, date, summary, imported_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            ((r.get("cve") or "").upper(), r.get("title") or "",
             _json.dumps(r.get("products") or []), r.get("severity") or "",
             r.get("source") or "", 1 if r.get("kev") else 0,
             r.get("date") or "", r.get("summary") or "", now))


@app.route("/threatintel")
@auth.login_required
def threatintel_view():
    db = get_db()
    feed = []
    for r in db.execute("SELECT * FROM threat_feed"):
        d = dict(r)
        try:
            d["products"] = _json.loads(d["products"] or "[]")
        except Exception:
            d["products"] = []
        d["kev"] = bool(d["kev"])
        feed.append(d)
    findings = [enrich(r) for r in db.execute("SELECT * FROM findings")]
    assets = [dict(r) for r in db.execute("SELECT * FROM assets")]
    alerts = threatintel.match(feed, findings, assets) if feed else []
    kev_count = sum(1 for a in alerts if a["kev"])
    return render_template("threat_alerts.html", alerts=alerts, feed_count=len(feed),
                           kev_count=kev_count, last_update=get_setting(db, "ti_last_update", ""),
                           enabled=(get_setting(db, "ti_enabled", "0") == "1"))


# ===========================================================================
# Phishing-awareness simulation (responsible scope)
#   * No credential capture anywhere — the link leads to a teachable page.
#   * Argus does not send mail; it mints per-recipient tracking links and the
#     team sends them through their own authorised relay.
#   * Tracking tokens are opaque; no PII is encoded in the URL.
# ===========================================================================
def _new_token():
    return _secrets.token_urlsafe(24)


def _csv_safe(v):
    """Neutralise spreadsheet formula-injection in exported cells."""
    s = "" if v is None else str(v)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s


_PHONE_RE = re.compile(r"^\+?[\d][\d\s()\-]{5,}$")


def _classify_recipient_fields(parts):
    """Sort free-form comma fields into name/email/phone/handle/dept.
    Accepts, in any order: an email (has @ and a dot), a phone (+ / digits),
    a social handle (@name), and plain words (first = name, next = dept)."""
    out = {"name": "", "email": "", "phone": "", "handle": "", "dept": ""}
    plain = []
    for p in parts:
        if not p:
            continue
        if p.startswith("@"):                       # social handle, e.g. @ama.b
            if not out["handle"]:
                out["handle"] = p
        elif "@" in p and "." in p.split("@", 1)[1]:
            if not out["email"]:
                out["email"] = p
        elif _PHONE_RE.match(p):
            if not out["phone"]:
                out["phone"] = p
        else:
            plain.append(p)
    if plain:
        out["name"] = plain[0]
    if len(plain) > 1:
        out["dept"] = plain[1]
    return out


def _delivery_providers():
    """Build the send providers from environment config. A seam tests can
    monkeypatch to inject fakes — real sending only happens on the operator's
    own deployment with their own credentials."""
    return {"email": delivery.EmailProvider(), "twilio": delivery.TwilioProvider()}


def _ensure_send_worker():
    """Start the background send worker on first use (idempotent)."""
    sending.start_worker(DB_PATH, _delivery_providers)


def _recipients_for(db, campaign_id):
    return db.execute(
        "SELECT * FROM phish_recipient WHERE campaign_id=? ORDER BY id",
        (campaign_id,)).fetchall()


def _campaign_stats(recips):
    n = len(recips)
    clicked = sum(1 for r in recips if r["clicked_at"])
    reported = sum(1 for r in recips if r["reported_at"])
    return {
        "recipients": n,
        "clicked": clicked,
        "reported": reported,
        "not_clicked": n - clicked,
        "click_rate": round(clicked / n * 100) if n else 0,
        "report_rate": round(reported / n * 100) if n else 0,
    }


@app.route("/phishing")
@auth.login_required
def phishing_view():
    db = get_db()
    campaigns = db.execute(
        "SELECT * FROM phish_campaign ORDER BY id DESC").fetchall()
    rbyc, enriched = {}, []
    for c in campaigns:
        rs = _recipients_for(db, c["id"])
        rbyc[c["id"]] = rs
        d = dict(c)
        d["stats"] = _campaign_stats(rs)
        enriched.append(d)
    prog = phishing.program_stats(campaigns, rbyc)
    return render_template("phishing.html", campaigns=enriched, prog=prog)


@app.route("/phishing/new", methods=["GET", "POST"])
@auth.role_required("admin", "editor")
def phishing_new():
    db = get_db()
    me = auth.current_user(db)
    if request.method == "POST":
        key = request.form.get("template_key", "")
        tpl = phishing.TEMPLATE_BY_KEY.get(key)
        if not tpl:
            flash("Pick a template to start from.")
            return redirect(url_for("phishing_new"))
        name = (request.form.get("name") or tpl["name"]).strip()[:160]
        sender = (request.form.get("sender") or tpl["sender"]).strip()[:200]
        subject = (request.form.get("subject") or tpl["subject"]).strip()[:200]
        body = (request.form.get("body") or tpl["body"])[:8000]
        landing = (request.form.get("landing_note") or "").strip()[:2000]
        channel = request.form.get("channel", "email")
        if channel not in (delivery.CHANNELS + delivery.MANUAL_CHANNELS):
            channel = "email"
        now = datetime.now().isoformat(timespec="seconds")
        cur = db.execute(
            "INSERT INTO phish_campaign(name, template_key, sender, subject, "
            "body, landing_note, channel, status, created_by, created_at) "
            "VALUES (?,?,?,?,?,?,?,'Draft',?,?)",
            (name, key, sender, subject, body, landing, channel, me["id"], now))
        db.commit()
        auth.log_activity(db, me["id"], None, "phishing",
                          f"created simulation campaign '{name}'")
        return redirect(url_for("phishing_campaign", cid=cur.lastrowid))
    return render_template("phishing_new.html", templates=phishing.TEMPLATES)


@app.route("/phishing/<int:cid>")
@auth.login_required
def phishing_campaign(cid):
    db = get_db()
    c = db.execute("SELECT * FROM phish_campaign WHERE id=?", (cid,)).fetchone()
    if not c:
        abort(404)
    recips = _recipients_for(db, cid)
    tpl = phishing.TEMPLATE_BY_KEY.get(c["template_key"], {})
    # a sample rendered email for the first recipient (or a placeholder)
    sample_link = url_for("phish_land", token="SAMPLE-TOKEN", _external=True)
    sample = phishing.render_body(c["body"],
                                  recips[0]["name"] if recips else "Alex Mensah",
                                  sample_link)
    pstatus = delivery.provider_status()
    channel = c["channel"] or "email"
    job = sending.active_job(db, cid)
    return render_template(
        "phishing_campaign.html", c=c, recips=recips,
        stats=_campaign_stats(recips), flags=tpl.get("flags", []),
        sample=sample, can_manage=auth.can_import_or_scan(auth.current_user(db)),
        channel=channel, provider_ready=pstatus.get(channel, False),
        is_manual=(channel in delivery.MANUAL_CHANNELS),
        job=job, pending=sending.pending_count(db, cid),
        ext_base=url_for("phish_land", token="", _external=True))


@app.route("/phishing/<int:cid>/recipients", methods=["POST"])
@auth.role_required("admin", "editor")
def phishing_recipients(cid):
    db = get_db()
    me = auth.current_user(db)
    c = db.execute("SELECT * FROM phish_campaign WHERE id=?", (cid,)).fetchone()
    if not c:
        abort(404)
    if c["status"] == "Closed":
        flash("This campaign is closed — reopen a new one to add recipients.")
        return redirect(url_for("phishing_campaign", cid=cid))
    raw = request.form.get("recipients", "")
    added, skipped = 0, 0
    existing = set()
    for r in _recipients_for(db, cid):
        for v in (r["email"], r["phone"], r["handle"]):
            if v:
                existing.add(v.lower())
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        rec = _classify_recipient_fields([p.strip() for p in line.split(",")])
        # a recipient needs at least one contactable address
        key = (rec["email"] or rec["phone"] or rec["handle"]).lower()
        if not key:
            skipped += 1
            continue
        if key in existing:
            skipped += 1
            continue
        existing.add(key)
        db.execute(
            "INSERT INTO phish_recipient(campaign_id, name, email, department, "
            "phone, handle, token, click_count) VALUES (?,?,?,?,?,?,?,0)",
            (cid, rec["name"][:120], rec["email"][:254], rec["dept"][:120],
             rec["phone"][:40], rec["handle"][:120], _new_token()))
        added += 1
    db.commit()
    auth.log_activity(db, me["id"], None, "phishing",
                      f"added {added} recipients to campaign #{cid}")
    flash(f"Added {added} recipient(s)." + (f" Skipped {skipped}." if skipped else ""))
    return redirect(url_for("phishing_campaign", cid=cid))


@app.route("/phishing/<int:cid>/launch", methods=["POST"])
@auth.role_required("admin", "editor")
def phishing_launch(cid):
    db = get_db()
    me = auth.current_user(db)
    c = db.execute("SELECT * FROM phish_campaign WHERE id=?", (cid,)).fetchone()
    if not c:
        abort(404)
    n = db.execute("SELECT COUNT(*) n FROM phish_recipient WHERE campaign_id=?",
                   (cid,)).fetchone()["n"]
    if not n:
        flash("Add at least one recipient before launching.")
        return redirect(url_for("phishing_campaign", cid=cid))
    db.execute("UPDATE phish_campaign SET status='Active', launched_at=? WHERE id=?",
               (datetime.now().isoformat(timespec="seconds"), cid))
    db.commit()
    auth.log_activity(db, me["id"], None, "phishing",
                      f"launched campaign #{cid} ({n} recipients)")
    flash("Campaign marked Active. Export the links and send them from your "
          "authorised mail relay.")
    return redirect(url_for("phishing_campaign", cid=cid))


@app.route("/phishing/<int:cid>/close", methods=["POST"])
@auth.role_required("admin", "editor")
def phishing_close(cid):
    db = get_db()
    me = auth.current_user(db)
    if not db.execute("SELECT 1 FROM phish_campaign WHERE id=?", (cid,)).fetchone():
        abort(404)
    db.execute("UPDATE phish_campaign SET status='Closed', closed_at=? WHERE id=?",
               (datetime.now().isoformat(timespec="seconds"), cid))
    db.commit()
    auth.log_activity(db, me["id"], None, "phishing", f"closed campaign #{cid}")
    flash("Campaign closed. Tracking links no longer record new clicks.")
    return redirect(url_for("phishing_campaign", cid=cid))


@app.route("/phishing/<int:cid>/delete", methods=["POST"])
@auth.role_required("admin", "editor")
def phishing_delete(cid):
    db = get_db()
    me = auth.current_user(db)
    if not db.execute("SELECT 1 FROM phish_campaign WHERE id=?", (cid,)).fetchone():
        abort(404)
    db.execute("DELETE FROM phish_event WHERE campaign_id=?", (cid,))
    db.execute("DELETE FROM phish_recipient WHERE campaign_id=?", (cid,))
    db.execute("DELETE FROM phish_campaign WHERE id=?", (cid,))
    db.commit()
    auth.log_activity(db, me["id"], None, "phishing", f"deleted campaign #{cid}")
    flash("Campaign deleted.")
    return redirect(url_for("phishing_view"))


@app.route("/phishing/<int:cid>/export")
@auth.role_required("admin", "editor")
def phishing_export(cid):
    db = get_db()
    c = db.execute("SELECT * FROM phish_campaign WHERE id=?", (cid,)).fetchone()
    if not c:
        abort(404)
    out = io.StringIO()
    w = _csv.writer(out)
    w.writerow(["name", "email", "department", "tracking_link"])
    for r in _recipients_for(db, cid):
        link = url_for("phish_land", token=r["token"], _external=True)
        w.writerow([_csv_safe(r["name"]), _csv_safe(r["email"]),
                    _csv_safe(r["department"]), link])
    data = out.getvalue().encode("utf-8")
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", c["name"] or f"campaign_{cid}")[:60]
    return send_file(io.BytesIO(data), mimetype="text/csv", as_attachment=True,
                     download_name=f"phish_{safe}_links.csv")


@app.route("/phishing/<int:cid>/authorize", methods=["POST"])
@auth.role_required("admin", "editor")
def phishing_authorize(cid):
    db = get_db()
    me = auth.current_user(db)
    c = db.execute("SELECT * FROM phish_campaign WHERE id=?", (cid,)).fetchone()
    if not c:
        abort(404)
    # the gate that keeps this an awareness tool: an explicit human attestation
    # that the recipients are people/systems the operator is allowed to test.
    if not request.form.get("confirm"):
        flash("Tick the authorisation box to confirm you may test these recipients.")
        return redirect(url_for("phishing_campaign", cid=cid))
    db.execute("UPDATE phish_campaign SET authorized=1, authorized_by=?, "
               "authorized_at=? WHERE id=?",
               (me["username"], datetime.now().isoformat(timespec="seconds"), cid))
    db.commit()
    auth.log_activity(db, me["id"], None, "phishing",
                      f"authorised sending for campaign #{cid}")
    flash("Authorisation recorded. You can now send to this campaign.")
    return redirect(url_for("phishing_campaign", cid=cid))


@app.route("/phishing/<int:cid>/testsend", methods=["POST"])
@auth.role_required("admin", "editor")
def phishing_testsend(cid):
    """Send a single message to an address the operator controls, so they can
    preview the real thing before any recipient is touched. Uses a SAMPLE link
    that records nothing."""
    db = get_db()
    me = auth.current_user(db)
    c = db.execute("SELECT * FROM phish_campaign WHERE id=?", (cid,)).fetchone()
    if not c:
        abort(404)
    channel = c["channel"] or "email"
    if channel in delivery.MANUAL_CHANNELS:
        flash("This channel is manual — use the copy buttons, there is nothing to test-send.")
        return redirect(url_for("phishing_campaign", cid=cid))
    target = (request.form.get("target") or "").strip()
    if not target:
        flash("Enter your own email or phone to send the test to.")
        return redirect(url_for("phishing_campaign", cid=cid))
    link = url_for("phish_land", token="SAMPLE-TOKEN", _external=True)
    recip = {"name": me["display_name"] or "",
             "email": target if channel == "email" else "",
             "phone": "" if channel == "email" else target}
    ok, err = delivery.dispatch(channel, recip, dict(c), link,
                                providers=_delivery_providers())
    if ok:
        flash(f"Test {channel} sent to {target}.")
    else:
        flash(f"Test send failed: {err}")
    auth.log_activity(db, me["id"], None, "phishing",
                      f"test-send ({channel}) for campaign #{cid}: {'ok' if ok else err}")
    return redirect(url_for("phishing_campaign", cid=cid))


@app.route("/phishing/<int:cid>/send", methods=["POST"])
@auth.role_required("admin", "editor")
def phishing_send(cid):
    """Queue a paced, background send for this campaign. Gated: the campaign
    must be Active, explicitly authorised, and the channel's provider ready.
    Only recipients attached to THIS campaign are ever contacted."""
    db = get_db()
    me = auth.current_user(db)
    c = db.execute("SELECT * FROM phish_campaign WHERE id=?", (cid,)).fetchone()
    if not c:
        abort(404)
    channel = c["channel"] or "email"
    if channel in delivery.MANUAL_CHANNELS:
        flash("This is a manual channel — copy each person's message and link by hand.")
        return redirect(url_for("phishing_campaign", cid=cid))
    if c["status"] != "Active":
        flash("Launch the campaign before sending.")
        return redirect(url_for("phishing_campaign", cid=cid))
    if not c["authorized"]:
        flash("Record your authorisation to test these recipients first.")
        return redirect(url_for("phishing_campaign", cid=cid))
    if not delivery.provider_status().get(channel):
        flash(f"The {channel} provider isn't configured on this server. "
              f"Set its credentials in the environment (see Settings) and retry.")
        return redirect(url_for("phishing_campaign", cid=cid))
    if sending.has_live_job(db, cid):
        flash("A send is already queued or running for this campaign.")
        return redirect(url_for("phishing_campaign", cid=cid))

    include_sent = request.form.get("resend") == "1"
    if not include_sent and sending.pending_count(db, cid) == 0:
        flash("Everyone has already been sent to. Tick 're-send' to send again.")
        return redirect(url_for("phishing_campaign", cid=cid))
    try:
        rate = int(request.form.get("rate") or 30)
    except ValueError:
        rate = 30
    scheduled_at = (request.form.get("scheduled_at") or "").strip() or None
    if scheduled_at:
        scheduled_at = scheduled_at.replace("T", " ")[:19]
    # Prefer a pinned base URL over the client-controlled Host header, so the
    # tracked links in sent messages can't be bent by a spoofed Host.
    base_url = os.environ.get("ARGUS_BASE_URL") or request.host_url
    jid = sending.create_job(db, cid, channel, base_url, me["username"],
                             rate_per_min=rate, scheduled_at=scheduled_at,
                             include_sent=include_sent)
    _ensure_send_worker()
    auth.log_activity(db, me["id"], None, "phishing",
                      f"queued send job #{jid} for campaign #{cid} via {channel}")
    flash("Send queued." if not scheduled_at else f"Send scheduled for {scheduled_at}.")
    return redirect(url_for("phishing_campaign", cid=cid))


@app.route("/phishing/<int:cid>/job")
@auth.login_required
def phishing_job(cid):
    """Live progress for the campaign's latest send job (polled by the UI)."""
    db = get_db()
    j = sending.active_job(db, cid)
    if not j:
        return jsonify({"exists": False})
    d = dict(j)
    d["exists"] = True
    d["pct"] = round(d["processed"] / d["total"] * 100) if d["total"] else 0
    return jsonify(d)


@app.route("/phishing/<int:cid>/job/cancel", methods=["POST"])
@auth.role_required("admin", "editor")
def phishing_job_cancel(cid):
    db = get_db()
    me = auth.current_user(db)
    j = sending.active_job(db, cid)
    if j and j["status"] in ("scheduled", "queued", "running"):
        sending.cancel_job(db, j["id"])
        auth.log_activity(db, me["id"], None, "phishing",
                          f"cancelled send job #{j['id']} for campaign #{cid}")
        flash("Send cancelled.")
    return redirect(url_for("phishing_campaign", cid=cid))


# --- PUBLIC tracking + teachable landing (no login, NO credential capture) ---
@app.route("/p/<token>")
def phish_land(token):
    """A simulated-phish click lands here. We record the click and teach.
    There is deliberately no form, no password field, nothing to submit."""
    db = get_db()
    r = db.execute("SELECT * FROM phish_recipient WHERE token=?",
                   (token,)).fetchone()
    campaign = None
    if r:
        campaign = db.execute("SELECT * FROM phish_campaign WHERE id=?",
                              (r["campaign_id"],)).fetchone()
        # only Active campaigns record clicks; SAMPLE-TOKEN never matches a row
        if campaign and campaign["status"] == "Active":
            ua = (request.headers.get("User-Agent", "") or "")[:300]
            now = datetime.now().isoformat(timespec="seconds")
            if not r["clicked_at"]:
                db.execute("UPDATE phish_recipient SET clicked_at=?, "
                           "click_count=click_count+1 WHERE id=?", (now, r["id"]))
            else:
                db.execute("UPDATE phish_recipient SET click_count=click_count+1 "
                           "WHERE id=?", (r["id"],))
            db.execute("INSERT INTO phish_event(recipient_id, campaign_id, kind, "
                       "at, user_agent) VALUES (?,?,'click',?,?)",
                       (r["id"], r["campaign_id"], now, ua))
            db.commit()
    tpl = phishing.TEMPLATE_BY_KEY.get(campaign["template_key"], {}) if campaign else {}
    note = campaign["landing_note"] if campaign else ""
    reported = bool(r["reported_at"]) if r else False
    return render_template("phishing_landing.html",
                           flags=tpl.get("flags", []), note=note,
                           token=token, known=bool(r), reported=reported,
                           active=bool(campaign and campaign["status"] == "Active"))


@app.route("/p/<token>/reported")
def phish_reported(token):
    """The teachable 'I would report this' acknowledgement. Idempotent,
    records no credentials — just that the person recognised the simulation."""
    db = get_db()
    r = db.execute("SELECT * FROM phish_recipient WHERE token=?",
                   (token,)).fetchone()
    if r and not r["reported_at"]:
        now = datetime.now().isoformat(timespec="seconds")
        db.execute("UPDATE phish_recipient SET reported_at=? WHERE id=?",
                   (now, r["id"]))
        db.execute("INSERT INTO phish_event(recipient_id, campaign_id, kind, at, "
                   "user_agent) VALUES (?,?,'report',?,?)",
                   (r["id"], r["campaign_id"], now,
                    (request.headers.get("User-Agent", "") or "")[:300]))
        db.commit()
    return redirect(url_for("phish_land", token=token))


# ===========================================================================
# Asset inventory register — import, classify, govern scanning
# ===========================================================================
def _read_asset_rows(file):
    """Return (headers, list-of-row-lists) from an uploaded .xlsx or .csv."""
    name = (file.filename or "").lower()
    MAX_IMPORT = 12 * 1024 * 1024  # 12 MB — asset sheets are small
    raw = file.read(MAX_IMPORT + 1)
    if len(raw) > MAX_IMPORT:
        raise ValueError("file too large (max 12 MB)")
    if name.endswith(".csv") or name.endswith(".tsv"):
        text = raw.decode("utf-8-sig", "ignore")
        delim = "\t" if name.endswith(".tsv") else ","
        reader = _csv.reader(io.StringIO(text), delimiter=delim)
        rows = [r for r in reader if any(str(c).strip() for c in r)]
        if not rows:
            return [], []
        return rows[0], rows[1:]
    # default: xlsx
    import openpyxl
    wb = openpyxl.load_workbook(io.BytesIO(raw), read_only=True, data_only=True)
    ws = wb.active
    data = [list(row) for row in ws.iter_rows(values_only=True)]
    data = [r for r in data if any(c is not None and str(c).strip() for c in r)]
    if not data:
        return [], []
    return data[0], data[1:]


def _assessed_keys(db):
    """IPs/hostnames that already appear in findings (proxy for 'assessed')."""
    keys = set()
    for r in db.execute("SELECT DISTINCT ip_hostname FROM findings"):
        v = (r["ip_hostname"] or "").strip().lower()
        if v:
            keys.add(v)
    return keys


@app.route("/inventory")
@auth.login_required
def inventory():
    db = get_db()
    rows = db.execute("SELECT * FROM assets ORDER BY "
                      "CASE criticality WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 "
                      "WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, hostname, ip").fetchall()
    assessed = _assessed_keys(db)
    assets = []
    counts = {"total": 0, "ot": 0, "do_not_scan": 0, "never_assessed": 0, "unclassified": 0}
    for r in rows:
        a = dict(r)
        ipk = (a.get("ip") or "").strip().lower()
        hnk = (a.get("hostname") or "").strip().lower()
        a["assessed"] = (ipk in assessed) or (hnk in assessed)
        assets.append(a)
        counts["total"] += 1
        if a["asset_type"] == "OT":
            counts["ot"] += 1
        if not a["scan_eligible"]:
            counts["do_not_scan"] += 1
        if not a["assessed"]:
            counts["never_assessed"] += 1
        if not a["criticality"] or a["asset_type"] == "Unknown":
            counts["unclassified"] += 1
    return render_template("inventory.html", assets=assets, counts=counts,
                           types=asset_classify.TYPES, crits=asset_classify.CRITICALITY,
                           policies=sorted(set(asset_classify.SCAN_POLICY.values())))


@app.route("/inventory/import", methods=["GET", "POST"])
@auth.login_required
@auth.role_required("editor", "admin")
def inventory_import():
    if request.method == "GET":
        return render_template("inventory_import.html")
    db = get_db()
    me = auth.current_user(db)
    file = request.files.get("file")
    if not file or not file.filename:
        flash("Choose an Excel (.xlsx) or CSV file to import.")
        return redirect(url_for("inventory_import"))
    try:
        headers, data_rows = _read_asset_rows(file)
    except Exception as e:
        flash(f"Could not read that file: {e}")
        return redirect(url_for("inventory_import"))
    if not headers:
        flash("That file appears to be empty.")
        return redirect(url_for("inventory_import"))
    mapping = asset_classify.map_headers(headers)
    if "ip" not in mapping and "hostname" not in mapping:
        flash("Couldn't find an IP or hostname column. Expected a header like "
              "'IP Address' or 'Hostname'. You can download the template for the layout.")
        return redirect(url_for("inventory_import"))
    now = datetime.now().isoformat(timespec="seconds")
    added = 0
    for raw in data_rows:
        rowdict = {}
        for canon, idx in mapping.items():
            if idx < len(raw):
                rowdict[canon] = raw[idx]
        if not (str(rowdict.get("ip") or "").strip() or str(rowdict.get("hostname") or "").strip()):
            continue
        a = asset_classify.classify(rowdict)
        db.execute(
            "INSERT INTO assets(ip, hostname, description, owner, criticality, asset_type,"
            " scan_policy, scan_eligible, classify_reason, source, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (a["ip"], a["hostname"], a["description"], a["owner"], a["criticality"],
             a["asset_type"], a["scan_policy"], a["scan_eligible"], a["classify_reason"],
             f"import:{os.path.basename(file.filename)[:80]}", now, now))
        added += 1
    db.commit()
    auth.log_activity(db, me["id"], None, "inventory", f"imported {added} assets")
    flash(f"Imported {added} assets. Review the classifications below — OT is marked do-not-scan.")
    return redirect(url_for("inventory"))


@app.route("/inventory/template")
@auth.login_required
def inventory_template():
    import openpyxl
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Assets"
    ws.append(["IP Address", "Hostname", "Description", "Criticality", "Type", "Owner"])
    ws.append(["10.20.4.11", "core-sw-01", "Core switch", "Critical", "Network", "Network Team"])
    ws.append(["10.20.8.23", "db-prod-02", "Production database", "Critical", "IT", "Database Team"])
    ws.append(["10.30.1.5", "plc-line3", "Siemens S7 PLC (do not scan)", "High", "OT", "Plant"])
    ws.append(["10.40.2.7", "jdoe-laptop", "Employee laptop", "Low", "BYOD", "IT"])
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                     as_attachment=True, download_name="asset_inventory_template.xlsx")


@app.route("/inventory/<int:aid>/edit", methods=["POST"])
@auth.login_required
@auth.role_required("editor", "admin")
def inventory_edit(aid):
    db = get_db()
    me = auth.current_user(db)
    row = db.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone()
    if not row:
        abort(404)
    crit = request.form.get("criticality", "").strip()
    atype = request.form.get("asset_type", "").strip() or row["asset_type"]
    policy = asset_classify.SCAN_POLICY.get(atype, "Review before scanning")
    scan_eligible = 0 if policy == "Do not actively scan" else 1
    authorized_by = request.form.get("authorized_by", "").strip()
    now = datetime.now().isoformat(timespec="seconds")
    authorized_at = row["authorized_at"]
    if authorized_by and not authorized_at:
        authorized_at = now
    if not authorized_by:
        authorized_at = None
    db.execute("UPDATE assets SET criticality=?, asset_type=?, scan_policy=?, scan_eligible=?,"
               " authorized_by=?, authorized_at=?, classify_reason=?, updated_at=? WHERE id=?",
               (crit, atype, policy, scan_eligible, authorized_by or None, authorized_at,
                "edited by " + (me["display_name"] or me["username"]), now, aid))
    db.commit()
    auth.log_activity(db, me["id"], None, "inventory", f'updated asset {row["hostname"] or row["ip"]}')
    flash("Asset updated.")
    return redirect(url_for("inventory"))


@app.route("/inventory/<int:aid>/delete", methods=["POST"])
@auth.login_required
@auth.role_required("editor", "admin")
def inventory_delete(aid):
    db = get_db()
    me = auth.current_user(db)
    db.execute("DELETE FROM assets WHERE id=?", (aid,))
    db.commit()
    auth.log_activity(db, me["id"], None, "inventory", "removed an asset")
    flash("Asset removed.")
    return redirect(url_for("inventory"))


def _form_to_dict(form):
    d = {}
    for col in INPUT_COLUMNS:
        if col == "source_tool":
            continue
        d[col] = form.get(col, "").strip()
    # normalise dates to ISO for storage
    for dc in DATE_COLUMNS:
        pd = parse_date(d.get(dc))
        d[dc] = iso(pd)
    # Only set source_tool when the form actually carries it (the edit form does
    # not), so editing a finding never clobbers its real origin (Nessus, etc.).
    if form.get("source_tool"):
        d["source_tool"] = form.get("source_tool")
    return d


def _insert_finding(d, scan_id=None):
    db = get_db()
    now = datetime.now().isoformat(timespec="seconds")
    cols = INPUT_COLUMNS + ["scan_id", "created_at", "updated_at"]
    vals = [d.get(c, "") for c in INPUT_COLUMNS] + [scan_id, now, now]
    placeholders = ", ".join("?" for _ in cols)
    db.execute(f"INSERT INTO findings ({', '.join(cols)}) VALUES ({placeholders})", vals)
    db.commit()


def _update_finding(fid, d):
    db = get_db()
    row = db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    # If status is being set to closing and no actual fix date provided, stamp today.
    if (d.get("remediation_status") in engine.CLOSING_STATUSES
            and not d.get("actual_fix_date") and not row["actual_fix_date"]):
        d["actual_fix_date"] = date.today().isoformat()
    d["updated_at"] = datetime.now().isoformat(timespec="seconds")
    sets = ", ".join(f"{k}=?" for k in d)
    db.execute(f"UPDATE findings SET {sets} WHERE id=?", (*d.values(), fid))
    db.commit()


# ---------------------------------------------------------------------------
# Routes: import scans
# ---------------------------------------------------------------------------
@app.route("/import", methods=["GET", "POST"])
@auth.role_required("admin", "editor")
def import_scan():
    if request.method == "POST":
        files = request.files.getlist("scanfile")
        detection = request.form.get("detection_date", "").strip()
        detection_iso = iso(parse_date(detection)) or date.today().isoformat()
        default_owner = request.form.get("default_owner", "").strip()
        default_class = request.form.get("default_classification", "").strip()
        total = 0
        errors = []
        for f in files:
            if not f or not f.filename:
                continue
            raw = f.read()
            try:
                label, findings = detect_and_parse(raw, f.filename)
            except ValueError as e:
                errors.append(f"{f.filename}: {e}")
                continue
            db = get_db()
            db.execute(
                "INSERT INTO scans(name, scan_date, source_tool, imported_at) VALUES (?,?,?,?)",
                (f.filename, detection_iso, label, datetime.now().isoformat(timespec="seconds")),
            )
            scan_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
            for fx in findings:
                rec = {c: "" for c in INPUT_COLUMNS}
                rec.update({
                    "ip_hostname": fx.get("ip_hostname", ""),
                    "device": fx.get("device", ""),
                    "asset_classification": default_class,  # analyst sets per-asset criticality
                    "vulnerability": fx.get("vulnerability", ""),
                    "synopsis": fx.get("synopsis", ""),
                    "definition": fx.get("definition", ""),
                    "cve": fx.get("cve", ""),
                    "reported_risk": fx.get("reported_risk", ""),
                    "exploit_available": fx.get("exploit_available", "Unknown"),
                    "exploit_reference": fx.get("exploit_reference", ""),
                    "solution": fx.get("solution", ""),
                    "asset_owner": default_owner,
                    "detection_date": detection_iso,
                    "remediation_status": "Pending",
                    "exception_requested": "No",
                    "source_tool": fx.get("source_tool", label),
                })
                _insert_finding(rec, scan_id=scan_id)
                total += 1
        if errors:
            flash("Some files could not be read: " + "; ".join(errors))
        me = auth.current_user(get_db())
        auth.log_activity(get_db(), me["id"], None, "import", f"Imported {total} findings")
        flash(f"Imported {total} findings.")
        return redirect(url_for("index"))
    return render_template(
        "import.html", owners=owner_list(), severities=engine.SEVERITIES,
        today=date.today().isoformat(),
    )


# ---------------------------------------------------------------------------
# Routes: built-in scanner
# ---------------------------------------------------------------------------
# In-memory registry of running scans. Keyed by job id. Each job holds progress
# lines, status, and (when done) the findings awaiting review.
SCAN_JOBS = {}


@app.route("/scan", methods=["GET"])
@auth.role_required("admin", "editor")
def scan_page():
    return render_template(
        "scan.html", owners=owner_list(), severities=engine.SEVERITIES,
        today=date.today().isoformat(),
        default_ports=",".join(str(p) for p in scanner_mod.DEFAULT_PORTS),
    )


@app.route("/scan/start", methods=["POST"])
@auth.role_required("admin", "editor")
def scan_start():
    targets = request.form.get("targets", "").strip()
    if not targets:
        flash("Enter at least one target IP, range or CIDR.")
        return redirect(url_for("scan_page"))
    ports_raw = request.form.get("ports", "").strip()
    ports = None
    if ports_raw:
        try:
            ports = [int(p) for p in ports_raw.replace(",", " ").split()]
        except ValueError:
            ports = None
    # Governance: assets the register marks do-not-actively-scan (OT/protected)
    db = get_db()
    blocklist = [r["ip"] for r in db.execute(
        "SELECT ip FROM assets WHERE scan_eligible=0 AND ip IS NOT NULL AND ip != ''")]
    job_id = uuid.uuid4().hex[:12]
    job = {
        "id": job_id,
        "status": "running",
        "progress": (["Scan queued…"] +
                     ([f"Governance: {len(blocklist)} protected (do-not-scan) asset(s) "
                       "will be skipped."] if blocklist else [])),
        "findings": [],
        "targets": targets,
        "detection_date": request.form.get("detection_date", "").strip() or date.today().isoformat(),
        "default_owner": request.form.get("default_owner", "").strip(),
        "default_classification": request.form.get("default_classification", "").strip(),
        "assume_up": request.form.get("assume_up") == "on",
        "do_tls": request.form.get("do_tls", "on") == "on",
        "do_http": request.form.get("do_http", "on") == "on",
        "ips": [],
        "committed": False,
    }
    SCAN_JOBS[job_id] = job

    def run():
        def progress(msg):
            job["progress"].append(msg)
            # keep last 200 lines
            if len(job["progress"]) > 200:
                job["progress"] = job["progress"][-200:]
        try:
            ips, findings = scanner_mod.scan_targets(
                targets, ports=ports, do_tls=job["do_tls"], do_http=job["do_http"],
                progress=progress, assume_up=job["assume_up"], blocklist=blocklist,
            )
            job["ips"] = ips
            job["findings"] = findings
            job["progress"].append(f"Done. {len(ips)} host(s) probed, {len(findings)} finding(s).")
            job["status"] = "done"
        except Exception as e:
            job["progress"].append(f"Scan error: {e}")
            job["status"] = "error"

    threading.Thread(target=run, daemon=True).start()
    return redirect(url_for("scan_progress", job_id=job_id))


@app.route("/scan/<job_id>")
@auth.role_required("admin", "editor")
def scan_progress(job_id):
    job = SCAN_JOBS.get(job_id)
    if not job:
        abort(404)
    return render_template("scan_progress.html", job=job)


@app.route("/scan/<job_id>/status")
@auth.role_required("admin", "editor")
def scan_status(job_id):
    job = SCAN_JOBS.get(job_id)
    if not job:
        return jsonify({"status": "missing"}), 404
    return jsonify({
        "status": job["status"],
        "progress": job["progress"][-40:],
        "finding_count": len(job["findings"]),
        "host_count": len(job["ips"]),
    })


@app.route("/scan/<job_id>/commit", methods=["POST"])
@auth.role_required("admin", "editor")
def scan_commit(job_id):
    job = SCAN_JOBS.get(job_id)
    if not job:
        abort(404)
    if job["committed"]:
        flash("These results were already added.")
        return redirect(url_for("index"))
    db = get_db()
    me = auth.current_user(db)
    db.execute(
        "INSERT INTO scans(name, scan_date, source_tool, imported_at) VALUES (?,?,?,?)",
        (f"Built-in scan: {job['targets'][:60]}", job["detection_date"],
         "Built-in scanner", datetime.now().isoformat(timespec="seconds")),
    )
    scan_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    for fx in job["findings"]:
        rec = {c: "" for c in INPUT_COLUMNS}
        rec.update({
            "ip_hostname": fx.get("ip_hostname", ""),
            "device": fx.get("device", ""),
            "asset_classification": job["default_classification"],
            "vulnerability": fx.get("vulnerability", ""),
            "synopsis": fx.get("synopsis", ""),
            "definition": fx.get("definition", ""),
            "cve": fx.get("cve", ""),
            "reported_risk": fx.get("reported_risk", ""),
            "exploit_available": fx.get("exploit_available", "Unknown"),
            "exploit_reference": fx.get("exploit_reference", ""),
            "solution": fx.get("solution", ""),
            "asset_owner": job["default_owner"],
            "detection_date": job["detection_date"],
            "remediation_status": "Pending",
            "exception_requested": "No",
            "source_tool": fx.get("source_tool", "Built-in scanner"),
        })
        _insert_finding(rec, scan_id=scan_id)
    job["committed"] = True
    auth.log_activity(db, me["id"], None, "scan",
                      f"Added {len(job['findings'])} findings from scan of {job['targets'][:60]}")
    flash(f"Added {len(job['findings'])} findings from the scan.")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Routes: asset owners management
# ---------------------------------------------------------------------------
@app.route("/owners", methods=["GET", "POST"])
@auth.role_required("admin", "editor")
def owners():
    db = get_db()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if name:
            db.execute("INSERT OR IGNORE INTO asset_owners(name) VALUES (?)", (name,))
            db.commit()
        return redirect(url_for("owners"))
    rows = db.execute("SELECT * FROM asset_owners ORDER BY name").fetchall()
    return render_template("owners.html", owners=rows)


@app.route("/owners/add_ajax", methods=["POST"])
@auth.role_required("admin", "editor")
def owners_add_ajax():
    db = get_db()
    name = request.json.get("name", "").strip()
    if name:
        db.execute("INSERT OR IGNORE INTO asset_owners(name) VALUES (?)", (name,))
        db.commit()
    return jsonify({"ok": True, "owners": owner_list()})


@app.route("/owners/<int:oid>/delete", methods=["POST"])
@auth.role_required("admin", "editor")
def owners_delete(oid):
    db = get_db()
    db.execute("DELETE FROM asset_owners WHERE id=?", (oid,))
    db.commit()
    return redirect(url_for("owners"))


# ---------------------------------------------------------------------------
# Routes: exports
# ---------------------------------------------------------------------------
@app.route("/export/excel")
@auth.login_required
def export_excel():
    from export_excel import build_excel
    db = get_db()
    rows = [enrich(r) for r in db.execute("SELECT * FROM findings ORDER BY id")]
    bio = build_excel(rows)
    fname = f"VAPT_Report_{date.today().isoformat()}.xlsx"
    return send_file(bio, as_attachment=True, download_name=fname,
                     mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@app.route("/export/pdf")
@auth.login_required
def export_pdf():
    from export_pdf import build_pdf
    db = get_db()
    rows = [enrich(r) for r in db.execute("SELECT * FROM findings ORDER BY id")]
    stats = {
        "total": len(rows),
        "critical": sum(1 for r in rows if r["actual_risk_classification"] == "Critical"),
        "high": sum(1 for r in rows if r["actual_risk_classification"] == "High"),
        "breached": sum(1 for r in rows if r["risk_tolerance_objective"] == "Breached"),
    }
    bio = build_pdf(rows, stats)
    fname = f"VAPT_Report_{date.today().isoformat()}.pdf"
    return send_file(bio, as_attachment=True, download_name=fname, mimetype="application/pdf")


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    admin_pw = init_db()
    _ensure_send_worker()   # resume scheduled / interrupted send jobs
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()
    if admin_pw:
        print("\n" + "=" * 64)
        print("  FIRST RUN — an administrator account has been created.")
        print("  Sign in, then create accounts for your team under 'Users'.")
        print(f"    Username: admin")
        print(f"    One-time password: {admin_pw}")
        print("  You'll be asked to set a new password at first sign-in.")
        print("=" * 64 + "\n")
    print(f"Argus running at http://{args.host}:{args.port}  (DB: {DB_PATH})")
    app.run(host=args.host, port=args.port, debug=args.debug)
