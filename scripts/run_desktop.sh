#!/usr/bin/env bash
# Launch the full AetherOS desktop stack in development: the control-plane API
# (FastAPI) and the React UI (Vite). The UI proxies /api to the API on :8765.
#
# Usage:  ./scripts/run_desktop.sh
# Stop:   Ctrl-C (both processes are torn down).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

API_PORT="${AETHER_API_PORT:-8765}"

# Activate the Python 3.12 venv if present.
if [[ -f .venv/bin/activate ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

echo "▶ Starting AetherOS control-plane API on :${API_PORT}"
uvicorn aetheros_orchestrator.api:app --port "${API_PORT}" --log-level warning &
API_PID=$!

cleanup() {
  echo "\n▶ Shutting down…"
  kill "${API_PID}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Wait for the API to be ready.
for _ in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:${API_PORT}/health" >/dev/null 2>&1; then
    echo "▶ Control plane is up."
    break
  fi
  sleep 0.3
done

echo "▶ Starting UI (Vite). Open http://localhost:5173"
cd ui
if [[ ! -d node_modules ]]; then
  echo "▶ Installing UI dependencies…"
  npm install
fi
npm run dev
