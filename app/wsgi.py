"""
wsgi.py — entry point for running VAPT Tracker under a production WSGI server
(waitress on Windows, gunicorn/uWSGI on Linux).

It ensures the database and first-run admin account exist, prints the one-time
admin password on first run, then exposes `app` as the WSGI callable.

    Windows:  waitress-serve --listen=0.0.0.0:8080 wsgi:app
    Linux:    gunicorn --bind 0.0.0.0:8080 wsgi:app
"""
from app import app, init_db

# Idempotent: creates tables if missing and the admin account only on first run.
_admin_pw = init_db()
if _admin_pw:
    print("\n" + "=" * 64)
    print("  FIRST RUN — an administrator account has been created.")
    print("  Sign in, then create accounts for your team under 'Users'.")
    print("    Username: admin")
    print(f"    One-time password: {_admin_pw}")
    print("  You'll be asked to set a new password at first sign-in.")
    print("=" * 64 + "\n", flush=True)

# `app` is imported above and is the WSGI application object the server runs.

if __name__ == "__main__":
    # Allow `python wsgi.py` to serve with waitress directly, if installed.
    try:
        from waitress import serve
    except ImportError:
        raise SystemExit(
            "waitress is not installed. Install it with:  pip install waitress\n"
            "or run the development server instead:         python app.py"
        )
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    print(f"VAPT Tracker serving on http://{args.host}:{args.port}  (production server)")
    serve(app, host=args.host, port=args.port)
