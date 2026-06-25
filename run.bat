@echo off
REM Local dev launcher for cxscan on Windows (cmd.exe).
REM Creates a venv on first run, installs deps, and starts the app with --reload.
REM
REM   run.bat
REM   set PORT=9000 && run.bat
REM
REM Optional auth / GitHub button (set before launching):
REM   set CXSCAN_AUTH_USER=admin && set CXSCAN_AUTH_PASSWORD=secret && run.bat
REM   set GITHUB_OAUTH_CLIENT_ID=Iv1.xxxx && run.bat
setlocal
cd /d "%~dp0"

if "%PORT%"=="" set PORT=8080
if "%VENV%"=="" set VENV=.venv

if not exist "%VENV%\" (
    echo ==^> creating venv at %VENV%
    python -m venv "%VENV%"
)
call "%VENV%\Scripts\activate.bat"

echo ==^> installing dependencies
pip install -q -r requirements.txt

echo ==^> starting cxscan on http://localhost:%PORT%
python -m uvicorn app.app:app --reload --port %PORT%
