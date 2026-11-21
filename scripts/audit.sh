#!/usr/bin/env bash
# Dependency security audit for VAPT Tracker.
# Checks the installed/declared dependencies against known-vulnerability
# databases (PyPI Advisory DB + OSV) using pip-audit. Run it before deploying
# and periodically afterwards.
#
# Usage:  ./scripts/audit.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Installing pip-audit (if needed)…"
python3 -m pip install --quiet --upgrade pip-audit

echo "==> Auditing declared dependencies (app/requirements.txt)…"
pip-audit -r app/requirements.txt || true

echo
echo "==> Auditing the current environment (catches transitive deps too)…"
pip-audit || true

echo
echo "Done. Review any findings above and upgrade the affected package."
echo "To produce a hash-verified lock for reproducible installs:"
echo "    python3 -m pip install pip-tools"
echo "    pip-compile --generate-hashes --output-file=app/requirements.lock app/requirements.txt"
echo "    pip install --require-hashes -r app/requirements.lock"
