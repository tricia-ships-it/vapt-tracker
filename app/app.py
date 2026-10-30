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
        """
    )
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

    # stats
    all_rows = [enrich(r) for r in db.execute("SELECT * FROM findings")]
    stats = {
        "total": len(all_rows),
        "critical": sum(1 for r in all_rows if r["actual_risk_classification"] == "Critical"),
        "high": sum(1 for r in all_rows if r["actual_risk_classification"] == "High"),
        "open": sum(1 for r in all_rows if r["remediation_status"] not in ("Fixed", "Not Applicable")),
        "breached": sum(1 for r in all_rows if r["risk_tolerance_objective"] == "Breached"),
        "overdue": sum(1 for r in all_rows if _is_overdue(r)),
    }
    return render_template(
        "index.html", rows=rows, stats=stats, owners=owner_list(),
        statuses=engine.REMEDIATION_STATUSES, severities=engine.SEVERITIES,
        exploits=engine.EXPLOIT_OPTIONS, q=q, status=status, risk=risk,
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
    job_id = uuid.uuid4().hex[:12]
    job = {
        "id": job_id,
        "status": "running",
        "progress": ["Scan queued…"],
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
                progress=progress, assume_up=job["assume_up"],
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
    print(f"VAPT Tracker running at http://{args.host}:{args.port}  (DB: {DB_PATH})")
    app.run(host=args.host, port=args.port, debug=args.debug)
