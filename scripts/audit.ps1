# Dependency security audit for VAPT Tracker (Windows / PowerShell).
# Checks dependencies against known-vulnerability databases using pip-audit.
# Run before deploying and periodically afterwards:
#     powershell -ExecutionPolicy Bypass -File scripts\audit.ps1

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

Write-Host "==> Installing pip-audit (if needed)..."
python -m pip install --quiet --upgrade pip-audit

Write-Host "==> Auditing declared dependencies (app\requirements.txt)..."
pip-audit -r app\requirements.txt

Write-Host ""
Write-Host "==> Auditing the current environment (catches transitive deps too)..."
pip-audit

Write-Host ""
Write-Host "To produce a hash-verified lock for reproducible installs:"
Write-Host "    python -m pip install pip-tools"
Write-Host "    pip-compile --generate-hashes --output-file=app\requirements.lock app\requirements.txt"
Write-Host "    pip install --require-hashes -r app\requirements.lock"
