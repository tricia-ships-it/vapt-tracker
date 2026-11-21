"""
Multi-channel delivery for phishing-awareness drills.

Architecture (deliberate — do not collapse):
  * Argus owns the recipient list, personalisation, the per-recipient tracked
    link and all click/report tracking. It does NOT own the transport. Each
    channel is delegated to a provider the organisation already controls and
    is accountable for — their own SMTP server, their own Twilio account.
    Argus formats {message + personal tracked link} and hands it off; it never
    becomes the sending engine itself.
  * Provider credentials are read from the environment / a local config file,
    never entered through the web UI and never stored in the database. A
    compromised admin web session therefore cannot read or exfiltrate mail or
    SMS credentials, and secrets never land in DB backups.
  * Sending is gated upstream (see app.py): a campaign must be explicitly
    authorised, and only recipients added to that campaign are ever contacted.
    There is no code path that sends to an arbitrary uploaded list.

Channels:
  * email     — SMTP (smtplib), the org's mail server.               [built]
  * sms       — Twilio-compatible Messages API.                      [built]
  * whatsapp  — same Twilio API with a whatsapp: sender. NOTE Twilio/Meta only
                deliver pre-approved templates, so lure content is usually
                rejected; wired for completeness, not relied upon.   [built]
  * voice     — vishing. Intentionally NOT automated here; higher risk and
                needs a per-campaign voice script. Left as a documented hook.
  * social    — automated DMs to social handles are intentionally unsupported:
                no platform offers a sanctioned API for unsolicited lure links,
                it breaks their terms, and personal social accounts fall
                outside an authorised staff directory. Argus prepares the
                message + link for manual sending only.

Everything here is transport-injectable so the pipeline is unit-tested without
any real network, SMTP server or provider credentials.
"""

import os
import re
import smtplib
import ssl
import urllib.parse
import urllib.request
from email.mime.text import MIMEText
from email.utils import formataddr

CHANNELS = ["email", "sms", "whatsapp"]          # channels Argus will send
MANUAL_CHANNELS = ["social"]                      # prepared, never auto-sent
DOCUMENTED_HOOKS = ["voice"]                       # extension point only


# ---------------------------------------------------------------------------
# Personalisation
# ---------------------------------------------------------------------------
def first_name(name, email):
    """Best-effort first name: explicit Name field wins, else derive from the
    email local-part (patricia.agyekum@x -> 'Patricia'). Falls back to 'there'
    so a message never reads 'Hi ,'."""
    if name and name.strip():
        tok = name.strip().split()[0]
        if tok.isalpha():
            return tok[:1].upper() + tok[1:]
        return tok
    if email and "@" in email:
        local = email.split("@", 1)[0]
        # split on separators and drop trailing digits
        parts = re.split(r"[._+\-]+", local)
        for p in parts:
            p = re.sub(r"\d+", "", p)
            # must look like a name: >=2 letters and contain a vowel, so bare
            # initials ("psk", "jkl") fall back rather than greeting "Hi Psk"
            if p.isalpha() and len(p) >= 2 and re.search(r"[aeiou]", p, re.I):
                return p[:1].upper() + p[1:].lower()
    return "there"


def render(channel, template_body, subject, name, email, link):
    """Return a dict describing the message to hand to the provider.
    Plain text only; the tracked link is the single actionable element."""
    fn = first_name(name, email)
    body = (template_body or "").replace("{{name}}", fn).replace("{{link}}", link)
    if channel == "email":
        return {"subject": subject or "", "body": body}
    # sms / whatsapp / social: short text; keep the link intact
    return {"subject": "", "body": body}


# ---------------------------------------------------------------------------
# Provider configuration (read from environment, never from the DB)
# ---------------------------------------------------------------------------
def _env(*keys):
    for k in keys:
        v = os.environ.get(k)
        if v:
            return v.strip()
    return ""


def smtp_config():
    return {
        "host": _env("ARGUS_SMTP_HOST"),
        "port": int(_env("ARGUS_SMTP_PORT") or "587"),
        "user": _env("ARGUS_SMTP_USER"),
        "password": _env("ARGUS_SMTP_PASS"),
        "from_addr": _env("ARGUS_SMTP_FROM", "ARGUS_SMTP_USER"),
        "from_name": _env("ARGUS_SMTP_FROM_NAME") or "IT Service Desk",
        "starttls": (_env("ARGUS_SMTP_STARTTLS") or "1") not in ("0", "false", "no"),
    }


def twilio_config():
    return {
        "sid": _env("ARGUS_TWILIO_SID"),
        "token": _env("ARGUS_TWILIO_TOKEN"),
        "sms_from": _env("ARGUS_TWILIO_FROM"),
        "wa_from": _env("ARGUS_TWILIO_WA_FROM"),
    }


def provider_status():
    """What the Settings page shows — configured or not, no secrets revealed."""
    s, t = smtp_config(), twilio_config()
    return {
        "email": bool(s["host"] and s["from_addr"]),
        "sms": bool(t["sid"] and t["token"] and t["sms_from"]),
        "whatsapp": bool(t["sid"] and t["token"] and t["wa_from"]),
    }


# ---------------------------------------------------------------------------
# Providers (transport-injectable)
# ---------------------------------------------------------------------------
class EmailProvider:
    def __init__(self, config=None, smtp_factory=None):
        self.cfg = config or smtp_config()
        # smtp_factory lets tests inject a fake; default is a real SMTP client
        self._factory = smtp_factory

    def ready(self):
        return bool(self.cfg["host"] and self.cfg["from_addr"])

    def send(self, to_addr, subject, body):
        if not self.ready():
            return False, "email provider not configured"
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = formataddr((self.cfg["from_name"], self.cfg["from_addr"]))
        msg["To"] = to_addr
        try:
            if self._factory is not None:
                client = self._factory()
            else:
                client = smtplib.SMTP(self.cfg["host"], self.cfg["port"], timeout=20)
            try:
                if self.cfg["starttls"] and self._factory is None:
                    client.starttls(context=ssl.create_default_context())
                if self.cfg["user"] and self._factory is None:
                    client.login(self.cfg["user"], self.cfg["password"])
                client.sendmail(self.cfg["from_addr"], [to_addr], msg.as_string())
            finally:
                try:
                    client.quit()
                except Exception:
                    pass
            return True, ""
        except Exception as e:
            return False, f"{type(e).__name__}: {e}"


class TwilioProvider:
    """SMS and WhatsApp via Twilio's Messages API. http_post is injectable so
    the dispatch is testable without network or credentials."""
    API = "https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"

    def __init__(self, config=None, http_post=None):
        self.cfg = config or twilio_config()
        self._post = http_post or self._real_post

    def ready(self, channel):
        base = self.cfg["sid"] and self.cfg["token"]
        return bool(base and (self.cfg["sms_from"] if channel == "sms"
                              else self.cfg["wa_from"]))

    def _real_post(self, url, data, auth):
        body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(url, data=body, method="POST")
        user, pw = auth
        token = urllib.request.base64.b64encode(f"{user}:{pw}".encode()).decode()
        req.add_header("Authorization", "Basic " + token)
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(req, timeout=20) as r:  # nosec - fixed host
            return r.status, r.read().decode("utf-8", "ignore")

    def send(self, channel, to, body):
        if channel not in ("sms", "whatsapp"):
            return False, f"unsupported channel {channel}"
        if not self.ready(channel):
            return False, f"{channel} provider not configured"
        if channel == "whatsapp":
            frm, to = "whatsapp:" + self.cfg["wa_from"], "whatsapp:" + to
        else:
            frm = self.cfg["sms_from"]
        url = self.API.format(sid=self.cfg["sid"])
        data = {"From": frm, "To": to, "Body": body}
        try:
            status, text = self._post(url, data, (self.cfg["sid"], self.cfg["token"]))
            if 200 <= status < 300:
                return True, ""
            return False, f"provider HTTP {status}: {text[:200]}"
        except Exception as e:
            return False, f"{type(e).__name__}: {e}"


# ---------------------------------------------------------------------------
# Dispatch — one recipient, one channel
# ---------------------------------------------------------------------------
def dispatch(channel, recipient, campaign, link, providers=None):
    """recipient: dict-like with name/email/phone. campaign: dict-like with
    subject/body. Returns (ok, error)."""
    providers = providers or {}
    msg = render(channel, campaign["body"], campaign["subject"],
                 recipient.get("name"), recipient.get("email"), link)
    if channel == "email":
        to = (recipient.get("email") or "").strip()
        if not to:
            return False, "no email address"
        prov = providers.get("email") or EmailProvider()
        return prov.send(to, msg["subject"], msg["body"])
    if channel in ("sms", "whatsapp"):
        to = (recipient.get("phone") or "").strip()
        if not to:
            return False, "no phone number"
        prov = providers.get("twilio") or TwilioProvider()
        return prov.send(channel, to, msg["body"])
    return False, f"channel {channel} is not auto-sent"


# ---------------------------------------------------------------------------
def _self_test():
    assert first_name("Patricia Agyekum", "x@y") == "Patricia"
    assert first_name("", "patricia.agyekum@paix.co") == "Patricia"
    assert first_name("", "psk@x") == "there"          # too cryptic -> fallback
    assert first_name("", "jordan2024@x") == "Jordan"
    r = render("email", "Hi {{name}}, {{link}}", "Subj", "", "amin.k@x", "L")
    assert r == {"subject": "Subj", "body": "Hi Amin, L"}, r

    # email via fake SMTP transport — proves the pipeline, no real network
    sent = {}
    class FakeSMTP:
        def starttls(self, *a, **k): pass
        def login(self, *a): pass
        def sendmail(self, frm, to, data): sent["to"] = to; sent["data"] = data
        def quit(self): pass
    cfg = {"host": "mail.x", "port": 587, "user": "", "password": "",
           "from_addr": "it@x", "from_name": "IT", "starttls": False}
    ep = EmailProvider(cfg, smtp_factory=FakeSMTP)
    ok, err = ep.send("a@b.example", "S", "Body")
    assert ok and sent["to"] == ["a@b.example"], (ok, err)

    # not-configured email fails cleanly
    ep2 = EmailProvider({"host": "", "from_addr": "", "port": 0, "user": "",
                         "password": "", "from_name": "", "starttls": False})
    assert ep2.send("a@b", "s", "b") == (False, "email provider not configured")

    # twilio SMS via fake http_post
    calls = []
    def fake_post(url, data, auth):
        calls.append((url, data, auth)); return 201, '{"sid":"SM1"}'
    tp = TwilioProvider({"sid": "AC1", "token": "tok", "sms_from": "+100",
                         "wa_from": "+200"}, http_post=fake_post)
    ok, err = tp.send("sms", "+15551234", "hello")
    assert ok, err
    assert calls[0][1]["From"] == "+100" and calls[0][1]["To"] == "+15551234"
    ok, err = tp.send("whatsapp", "+15551234", "hi")
    assert ok and calls[1][1]["To"] == "whatsapp:+15551234", calls[1]
    # provider HTTP error surfaces
    tp2 = TwilioProvider({"sid": "AC1", "token": "t", "sms_from": "+1", "wa_from": ""},
                         http_post=lambda *a: (401, "unauthorized"))
    ok, err = tp2.send("sms", "+1", "x")
    assert not ok and "401" in err, err

    # dispatch end-to-end with injected providers
    ok, err = dispatch("email", {"email": "kofi.mensah@x"},
                       {"subject": "S", "body": "Hi {{name}}"},
                       "http://a/p/t", providers={"email": EmailProvider(cfg, FakeSMTP)})
    assert ok, err
    ok, err = dispatch("sms", {"phone": ""}, {"subject": "", "body": "b"}, "L",
                       providers={"twilio": tp})
    assert not ok and "no phone" in err
    print("delivery self-tests passed")


if __name__ == "__main__":
    _self_test()
