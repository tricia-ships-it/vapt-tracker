"""
Phishing-awareness simulation — responsible-scope only.

Design constraints (deliberate, do not relax):
  * This module NEVER captures credentials. The link in a simulated email
    leads to a teachable landing page, not a fake login form. There is no
    password field anywhere in this feature.
  * Argus does not send the emails itself. It generates per-recipient
    tracking links; the security team dispatches them through their own
    authorised mail system. This keeps Argus from being usable as a
    spam/phishing sending engine.
  * Templates use generic role framing ("IT Service Desk", "HR") and never
    impersonate a specific real company, brand or person.
  * Only an opaque, unguessable token per recipient appears in the URL — no
    names, emails or IDs are encoded in it.

The point of the exercise is to measure click behaviour and turn a click
into a teachable moment, so staff learn to spot the next real one.
"""

# Each template is a safe, generic lure. {{name}} and {{link}} are the only
# placeholders. `flags` are the tell-tale signs shown on the landing page so
# the click becomes a lesson.
TEMPLATES = [
    {
        "key": "password_expiry",
        "name": "Password expiry notice",
        "category": "Credential lure",
        "sender": "IT Service Desk <no-reply@it-servicedesk.example>",
        "subject": "Action required: your password expires today",
        "body": (
            "Hi {{name}},\n\n"
            "Our records show your network password expires in the next few "
            "hours. To avoid being locked out of email and systems, please "
            "confirm your account now:\n\n"
            "{{link}}\n\n"
            "If you do not act today, access will be suspended until the help "
            "desk can reset it manually.\n\n"
            "Regards,\nIT Service Desk"
        ),
        "flags": [
            "Creates false urgency — a real password change is never a 'do it in the next few hours or lose access' emergency.",
            "The sender domain (it-servicedesk.example) is not your real IT domain.",
            "Asks you to 'confirm your account' through a link rather than through the tool you normally use.",
            "Generic threat of being 'locked out' to push you past your judgement.",
        ],
    },
    {
        "key": "shared_document",
        "name": "Shared document",
        "category": "Document lure",
        "sender": "Document Share <share@docs-delivery.example>",
        "subject": "A document has been shared with you",
        "body": (
            "Hi {{name}},\n\n"
            "A colleague has shared a document titled "
            "\"Q4 Compensation Review\" with you. It is available for a "
            "limited time:\n\n"
            "{{link}}\n\n"
            "You may be asked to sign in to view it.\n\n"
            "Document Delivery Service"
        ),
        "flags": [
            "A tempting subject ('Compensation Review') is bait to make you click before thinking.",
            "'You may be asked to sign in' is how credential-harvest pages get your password.",
            "No named colleague — a genuine share names the person who sent it.",
            "The link host is not the document system your organisation actually uses.",
        ],
    },
    {
        "key": "delivery_failed",
        "name": "Failed package delivery",
        "category": "Consumer lure",
        "sender": "Courier Notifications <tracking@parcel-notice.example>",
        "subject": "We missed you — reschedule your delivery",
        "body": (
            "Hello {{name}},\n\n"
            "We attempted to deliver a parcel addressed to you but no one was "
            "available. Please confirm your details to reschedule:\n\n"
            "{{link}}\n\n"
            "Undelivered items are returned to sender after 48 hours.\n\n"
            "Courier Notifications"
        ),
        "flags": [
            "You were not expecting this parcel, and the message gives no tracking number you recognise.",
            "A short deadline ('returned after 48 hours') to rush you.",
            "Delivery companies do not ask you to 'confirm your details' on a web form to redeliver.",
            "Sent to your work address for a personal parcel — a common mismatch in real phishing.",
        ],
    },
    {
        "key": "hr_policy",
        "name": "HR policy acknowledgement",
        "category": "Internal-process lure",
        "sender": "Human Resources <hr@company-updates.example>",
        "subject": "Please acknowledge the updated remote-work policy",
        "body": (
            "Dear {{name}},\n\n"
            "HR has published an updated remote-work policy that all staff "
            "must read and acknowledge by end of day. Acknowledge here:\n\n"
            "{{link}}\n\n"
            "Failure to acknowledge may affect your remote-work eligibility.\n\n"
            "Human Resources"
        ),
        "flags": [
            "Impersonates an internal team (HR) but comes from an outside domain (company-updates.example).",
            "Policy updates are normally posted on your intranet, not actioned through an email link.",
            "A consequence ('may affect your eligibility') is used to pressure a quick click.",
            "No specific policy reference number or document you can verify independently.",
        ],
    },
    {
        "key": "mfa_reset",
        "name": "MFA re-enrollment",
        "category": "Credential lure",
        "sender": "Security Team <security@account-verify.example>",
        "subject": "Re-enroll your multi-factor authentication",
        "body": (
            "Hi {{name}},\n\n"
            "As part of a security upgrade, all staff must re-enroll their "
            "multi-factor authentication within 24 hours. Begin re-enrollment:\n\n"
            "{{link}}\n\n"
            "Accounts not re-enrolled will be temporarily disabled.\n\n"
            "Security Team"
        ),
        "flags": [
            "Uses security language to sound legitimate — attackers often pose as the security team.",
            "MFA re-enrollment is driven from your identity provider, not a link in an email.",
            "24-hour deadline plus threat of a disabled account — classic pressure tactics.",
            "The domain (account-verify.example) is not an internal address.",
        ],
    },
]

TEMPLATE_BY_KEY = {t["key"]: t for t in TEMPLATES}


def render_body(body, name, link):
    """Fill the two allowed placeholders. Plain text only — no HTML, no exec."""
    safe_name = name or "there"
    return (body or "").replace("{{name}}", safe_name).replace("{{link}}", link)


def program_stats(campaigns, recipients_by_campaign):
    """Aggregate click metrics across campaigns for the program dashboard."""
    total_r = sum(len(r) for r in recipients_by_campaign.values())
    clicked = sum(1 for rs in recipients_by_campaign.values()
                  for r in rs if r["clicked_at"])
    reported = sum(1 for rs in recipients_by_campaign.values()
                   for r in rs if r["reported_at"])
    rate = round(clicked / total_r * 100) if total_r else 0
    return {
        "campaigns": len(campaigns),
        "recipients": total_r,
        "clicked": clicked,
        "reported": reported,
        "click_rate": rate,
    }


def _self_test():
    assert render_body("Hi {{name}}, {{link}}", "Ada", "http://x/p/t") == \
        "Hi Ada, http://x/p/t"
    # missing name falls back, link always substituted
    assert "there" in render_body("{{name}}", "", "L")
    # no template encodes a real brand domain
    for t in TEMPLATES:
        assert ".example" in t["sender"], t["key"]
        assert "{{link}}" in t["body"], t["key"]
        assert t["flags"], t["key"]
    print("phishing self-tests passed:", len(TEMPLATES), "templates")


if __name__ == "__main__":
    _self_test()
