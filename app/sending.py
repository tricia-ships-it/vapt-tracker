"""
Background send engine for phishing-awareness drills.

Why this exists: sending a drill to a real staff list must not happen inside a
web request. A synchronous loop over hundreds of recipients would time out the
request, give the operator no progress, lose its place on a crash, and hammer
the mail/SMS provider fast enough to get rate-limited or blacklisted.

So a send becomes a durable JOB (a row in phish_send_job) processed by a single
background worker thread that:
  * paces itself to rate_per_min (default 30/min) so the provider stays happy,
  * commits progress after every message, so the UI can show a live bar and a
    crash leaves an exactly-resumable job,
  * resumes rather than duplicates — a recipient with sent_at already set is
    skipped, so re-running a job never double-sends,
  * supports scheduling (send at a chosen time) and cancellation,
  * re-checks the campaign gates (Active + authorised) before it sends a thing.

Everything is transport- and clock-injectable so the engine is unit-tested with
fakes, no real network, SMTP, provider credentials or wall-clock sleeps.

Scope note: one in-process worker suits a self-hosted, single-process Argus
deployment. Running multiple web workers (e.g. gunicorn -w 4) would start one
worker each; for that, point them at an external queue instead. Documented in
docs/phishing-delivery.md.
"""

import sqlite3
import threading
import time
from datetime import datetime

import delivery

# job lifecycle:
#   scheduled -> queued -> running -> done
#                        \-> canceling -> canceled
#                         \-> failed
_worker_started = False
_worker_lock = threading.Lock()


def _now():
    return datetime.now().isoformat(timespec="seconds")


def _conn(db_path):
    c = sqlite3.connect(db_path, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA busy_timeout=8000")
    return c


# ---------------------------------------------------------------------------
# Job creation (called from a request, with a live DB handle)
# ---------------------------------------------------------------------------
def pending_count(db, campaign_id):
    return db.execute("SELECT COUNT(*) n FROM phish_recipient "
                      "WHERE campaign_id=? AND sent_at IS NULL",
                      (campaign_id,)).fetchone()["n"]


def active_job(db, campaign_id):
    """The most recent job for a campaign, if any (for the UI to poll)."""
    return db.execute("SELECT * FROM phish_send_job WHERE campaign_id=? "
                      "ORDER BY id DESC LIMIT 1", (campaign_id,)).fetchone()


def has_live_job(db, campaign_id):
    row = db.execute("SELECT 1 FROM phish_send_job WHERE campaign_id=? AND "
                     "status IN ('scheduled','queued','running','canceling') LIMIT 1",
                     (campaign_id,)).fetchone()
    return bool(row)


def create_job(db, campaign_id, channel, base_url, created_by,
               rate_per_min=30, scheduled_at=None, include_sent=False):
    if include_sent:
        total = db.execute("SELECT COUNT(*) n FROM phish_recipient WHERE campaign_id=?",
                           (campaign_id,)).fetchone()["n"]
    else:
        total = pending_count(db, campaign_id)
    status = "scheduled" if scheduled_at else "queued"
    rate = max(1, min(int(rate_per_min or 30), 600))
    cur = db.execute(
        "INSERT INTO phish_send_job(campaign_id, channel, status, total, "
        "processed, ok_count, fail_count, rate_per_min, scheduled_at, "
        "include_sent, base_url, created_by, created_at) "
        "VALUES (?,?,?,?,0,0,0,?,?,?,?,?,?)",
        (campaign_id, channel, status, total, rate, scheduled_at,
         1 if include_sent else 0, base_url, created_by, _now()))
    db.commit()
    return cur.lastrowid


def cancel_job(db, job_id):
    """Queued/scheduled jobs stop immediately; a running job is asked to stop
    at its next message boundary."""
    job = db.execute("SELECT status FROM phish_send_job WHERE id=?",
                     (job_id,)).fetchone()
    if not job:
        return
    if job["status"] in ("scheduled", "queued"):
        db.execute("UPDATE phish_send_job SET status='canceled', finished_at=? "
                   "WHERE id=?", (_now(), job_id))
    elif job["status"] == "running":
        db.execute("UPDATE phish_send_job SET status='canceling' WHERE id=?",
                   (job_id,))
    db.commit()


# ---------------------------------------------------------------------------
# Job processing (runs in the worker thread, own connection)
# ---------------------------------------------------------------------------
def recover(db_path):
    """Crash recovery: a job left 'running' or 'canceling' when the process
    died is requeued. Already-sent recipients are skipped, so this resumes
    rather than duplicates."""
    c = _conn(db_path)
    try:
        c.execute("UPDATE phish_send_job SET status='queued' "
                  "WHERE status IN ('running','canceling')")
        c.commit()
    finally:
        c.close()


def process_job(db_path, job_id, providers=None, sleep=time.sleep):
    c = _conn(db_path)
    try:
        job = c.execute("SELECT * FROM phish_send_job WHERE id=?",
                        (job_id,)).fetchone()
        if not job or job["status"] not in ("queued", "running"):
            return
        cam = c.execute("SELECT * FROM phish_campaign WHERE id=?",
                        (job["campaign_id"],)).fetchone()
        # re-check the gates at run time — never send for a campaign that was
        # closed or de-authorised after the job was queued.
        if not cam or cam["status"] != "Active" or not cam["authorized"]:
            c.execute("UPDATE phish_send_job SET status='failed', last_error=?, "
                      "finished_at=? WHERE id=?",
                      ("campaign is not Active and authorised", _now(), job_id))
            c.commit()
            return
        if job["channel"] in delivery.MANUAL_CHANNELS:
            c.execute("UPDATE phish_send_job SET status='failed', last_error=?, "
                      "finished_at=? WHERE id=?",
                      ("manual channel is not auto-sent", _now(), job_id))
            c.commit()
            return
        providers = providers if providers is not None else {
            "email": delivery.EmailProvider(), "twilio": delivery.TwilioProvider()}
        c.execute("UPDATE phish_send_job SET status='running', "
                  "started_at=COALESCE(started_at,?) WHERE id=?", (_now(), job_id))
        c.commit()

        delay = 60.0 / float(job["rate_per_min"] or 30)
        where = "campaign_id=?" + ("" if job["include_sent"] else " AND sent_at IS NULL")
        rows = c.execute(f"SELECT * FROM phish_recipient WHERE {where} ORDER BY id",
                         (job["campaign_id"],)).fetchall()
        base = (job["base_url"] or "").rstrip("/")
        last = len(rows) - 1
        for i, r in enumerate(rows):
            # cooperative cancel: checked every message
            st = c.execute("SELECT status FROM phish_send_job WHERE id=?",
                           (job_id,)).fetchone()["status"]
            if st == "canceling":
                c.execute("UPDATE phish_send_job SET status='canceled', "
                          "finished_at=? WHERE id=?", (_now(), job_id))
                c.commit()
                return
            link = f"{base}/p/{r['token']}"
            ok, err = delivery.dispatch(job["channel"], dict(r), dict(cam),
                                        link, providers)
            c.execute("UPDATE phish_recipient SET sent_at=?, delivery_status=?, "
                      "delivery_error=? WHERE id=?",
                      (_now(), "sent" if ok else "failed",
                       "" if ok else err[:300], r["id"]))
            c.execute("UPDATE phish_send_job SET processed=processed+1, "
                      "ok_count=ok_count+?, fail_count=fail_count+? WHERE id=?",
                      (1 if ok else 0, 0 if ok else 1, job_id))
            c.commit()
            if delay and i != last:
                sleep(delay)
        c.execute("UPDATE phish_send_job SET status='done', finished_at=? "
                  "WHERE id=?", (_now(), job_id))
        c.commit()
    except Exception as e:  # never let the worker die on one bad job
        try:
            c.execute("UPDATE phish_send_job SET status='failed', last_error=?, "
                      "finished_at=? WHERE id=?",
                      (f"{type(e).__name__}: {e}", _now(), job_id))
            c.commit()
        except Exception:
            pass
    finally:
        c.close()


def claim_next(db_path):
    """Promote due scheduled jobs, then return the id of the next queued job."""
    c = _conn(db_path)
    try:
        c.execute("UPDATE phish_send_job SET status='queued' WHERE status='scheduled' "
                  "AND scheduled_at IS NOT NULL AND scheduled_at<=?", (_now(),))
        c.commit()
        row = c.execute("SELECT id FROM phish_send_job WHERE status='queued' "
                        "ORDER BY id LIMIT 1").fetchone()
        return row["id"] if row else None
    finally:
        c.close()


def start_worker(db_path, providers_factory, poll=2.0):
    """Start the single background worker (idempotent)."""
    global _worker_started
    with _worker_lock:
        if _worker_started:
            return
        _worker_started = True

    def loop():
        recover(db_path)
        while True:
            try:
                jid = claim_next(db_path)
                if jid is not None:
                    process_job(db_path, jid, providers_factory())
                else:
                    time.sleep(poll)
            except Exception:
                time.sleep(poll + 1)

    threading.Thread(target=loop, name="argus-send-worker", daemon=True).start()


# ---------------------------------------------------------------------------
def _self_test():
    import os
    import tempfile
    d = tempfile.mkdtemp()
    p = os.path.join(d, "t.db")
    c = sqlite3.connect(p)
    c.executescript("""
      CREATE TABLE phish_campaign(id INTEGER PRIMARY KEY, name TEXT, channel TEXT,
        subject TEXT, body TEXT, status TEXT, authorized INT);
      CREATE TABLE phish_recipient(id INTEGER PRIMARY KEY, campaign_id INT, name TEXT,
        email TEXT, phone TEXT, handle TEXT, token TEXT, sent_at TEXT,
        delivery_status TEXT, delivery_error TEXT);
      CREATE TABLE phish_send_job(id INTEGER PRIMARY KEY AUTOINCREMENT, campaign_id INT,
        channel TEXT, status TEXT, total INT, processed INT, ok_count INT,
        fail_count INT, rate_per_min INT, scheduled_at TEXT, include_sent INT,
        base_url TEXT, created_by TEXT, created_at TEXT, started_at TEXT,
        finished_at TEXT, last_error TEXT);
    """)
    c.execute("INSERT INTO phish_campaign VALUES (1,'C','email','S','Hi {{name}} {{link}}','Active',1)")
    for i in range(5):
        c.execute("INSERT INTO phish_recipient(campaign_id,name,email,token) "
                  "VALUES (1,?,?,?)", (f"U{i}", f"u{i}@x.example", f"tok{i}"))
    c.commit()
    db = _conn(p)

    calls = []
    class FakeEmail:
        def send(self, to, s, b): calls.append(to); return True, ""
    prov = {"email": FakeEmail(), "twilio": None}

    jid = create_job(db, 1, "email", "http://a", "admin", rate_per_min=600)
    assert db.execute("SELECT total FROM phish_send_job WHERE id=?", (jid,)).fetchone()["total"] == 5
    process_job(p, jid, providers=prov, sleep=lambda _ : None)
    j = db.execute("SELECT * FROM phish_send_job WHERE id=?", (jid,)).fetchone()
    assert j["status"] == "done" and j["processed"] == 5 and j["ok_count"] == 5, dict(j)
    assert len(calls) == 5

    # idempotency: a second job sends nothing new
    jid2 = create_job(db, 1, "email", "http://a", "admin")
    assert db.execute("SELECT total FROM phish_send_job WHERE id=?", (jid2,)).fetchone()["total"] == 0
    process_job(p, jid2, providers=prov, sleep=lambda _ : None)
    assert len(calls) == 5, "re-send must not duplicate"

    # gate re-check: de-authorise, queue, process -> failed, no sends
    db.execute("UPDATE phish_recipient SET sent_at=NULL"); db.commit()
    db.execute("UPDATE phish_campaign SET authorized=0 WHERE id=1"); db.commit()
    jid3 = create_job(db, 1, "email", "http://a", "admin")
    process_job(p, jid3, providers=prov, sleep=lambda _ : None)
    assert db.execute("SELECT status FROM phish_send_job WHERE id=?", (jid3,)).fetchone()["status"] == "failed"
    assert len(calls) == 5

    # cancel mid-flight: cancel after 2 via a sleep hook that flips status
    db.execute("UPDATE phish_campaign SET authorized=1 WHERE id=1"); db.commit()
    jid4 = create_job(db, 1, "email", "http://a", "admin", rate_per_min=600)
    n = {"i": 0}
    def cancel_after_two(_):
        n["i"] += 1
        if n["i"] == 2:
            cc = _conn(p); cc.execute("UPDATE phish_send_job SET status='canceling' WHERE id=?", (jid4,)); cc.commit(); cc.close()
    process_job(p, jid4, providers=prov, sleep=cancel_after_two)
    j4 = db.execute("SELECT * FROM phish_send_job WHERE id=?", (jid4,)).fetchone()
    assert j4["status"] == "canceled" and j4["processed"] < 5, dict(j4)

    # crash recovery requeues a stuck 'running' job
    db.execute("UPDATE phish_send_job SET status='running' WHERE id=?", (jid4,)); db.commit()
    recover(p)
    assert db.execute("SELECT status FROM phish_send_job WHERE id=?", (jid4,)).fetchone()["status"] == "queued"
    print("sending self-tests passed")


if __name__ == "__main__":
    _self_test()
