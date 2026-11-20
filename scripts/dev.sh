#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "============================================================"
echo " THREATLENS AI — Starting Full-Stack SOC Platform"
echo "============================================================"

"$ROOT_DIR/scripts/setup-local-pg.sh"

if [ ! -f "$ROOT_DIR/backend/.env" ]; then
  cp "$ROOT_DIR/backend/.env.example" "$ROOT_DIR/backend/.env"
fi

if [ ! -f "$ROOT_DIR/analysis-engine/.env" ]; then
  cp "$ROOT_DIR/analysis-engine/.env.example" "$ROOT_DIR/analysis-engine/.env"
fi

mkdir -p "$ROOT_DIR/logs"

echo "[1/3] Starting Python FastAPI Analysis Engine on http://127.0.0.1:8088 ..."
(
  cd "$ROOT_DIR/analysis-engine"
  PYTHONPATH=. .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8088 > "$ROOT_DIR/logs/analysis-engine.log" 2>&1
) &
ENGINE_PID=$!

echo "[2/3] Starting Node.js Express + Prisma Backend on http://127.0.0.1:4000 ..."
(
  cd "$ROOT_DIR/backend"
  npx prisma db push >/dev/null
  npm run dev > "$ROOT_DIR/logs/backend.log" 2>&1
) &
BACKEND_PID=$!

echo "[3/3] Starting React + Vite SOC Frontend on http://localhost:5173 ..."
(
  cd "$ROOT_DIR/frontend"
  npm run dev > "$ROOT_DIR/logs/frontend.log" 2>&1
) &
FRONTEND_PID=$!

cleanup() {
  echo ""
  echo "[THREATLENS] Stopping services..."
  kill "$ENGINE_PID" "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo ""
echo "All services launched!"
echo "  -> SOC Web Console : http://localhost:5173"
echo "  -> Backend REST API: http://127.0.0.1:4000/api/health"
echo "  -> Python Engine   : http://127.0.0.1:8088/health"
echo "Press Ctrl+C to stop all services."

wait
