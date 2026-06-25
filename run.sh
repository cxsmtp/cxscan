#!/usr/bin/env bash
# Local dev launcher for cxscan. Creates a venv on first run, installs deps, and
# starts the app with --reload. KICS + 2ms are fetched from the Setup tab the
# first time (or bake them via the podman image — see README).
#
#   ./run.sh                 # http://localhost:8080
#   PORT=9000 ./run.sh       # custom port
#
# Optional auth (recommended once anyone else can reach the port):
#   CXSCAN_AUTH_USER=admin CXSCAN_AUTH_PASSWORD=secret ./run.sh
set -euo pipefail
cd "$(dirname "$0")"

PORT="${PORT:-8080}"
VENV="${VENV:-.venv}"

if [ ! -d "$VENV" ]; then
  echo "==> creating venv at $VENV"
  python3 -m venv "$VENV"
fi
# shellcheck disable=SC1090
source "$VENV/bin/activate"

echo "==> installing dependencies"
pip install -q -r requirements.txt

echo "==> starting cxscan on http://localhost:${PORT}"
exec uvicorn app.app:app --reload --port "$PORT"
