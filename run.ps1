# Local dev launcher for cxscan on Windows (PowerShell).
# Creates a venv on first run, installs deps, and starts the app with --reload.
#
#   .\run.ps1
#   $env:PORT=9000; .\run.ps1
#
# If PowerShell blocks the script (execution policy), run it as:
#   powershell -ExecutionPolicy Bypass -File .\run.ps1
# or use run.bat from cmd.exe instead.
#
# Optional auth / GitHub button (set before launching):
#   $env:CXSCAN_AUTH_USER="admin"; $env:CXSCAN_AUTH_PASSWORD="secret"
#   $env:GITHUB_OAUTH_CLIENT_ID="Iv1.xxxx"
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$Port = if ($env:PORT) { $env:PORT } else { "8080" }
$Venv = if ($env:VENV) { $env:VENV } else { ".venv" }

# Prefer the py launcher if present, else python on PATH.
$Py = if (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { "python" }

if (-not (Test-Path $Venv)) {
    Write-Host "==> creating venv at $Venv"
    & $Py -m venv $Venv
}
& "$Venv\Scripts\Activate.ps1"

Write-Host "==> installing dependencies"
pip install -q -r requirements.txt

Write-Host "==> starting cxscan on http://localhost:$Port"
python -m uvicorn app.app:app --reload --port $Port
