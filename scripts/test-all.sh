#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=== [1/4] Ensuring Local PostgreSQL Cluster ==="
"$ROOT_DIR/scripts/setup-local-pg.sh"

echo "=== [2/4] Running Python FastAPI Analysis Engine Pytest Suite ==="
(
  cd "$ROOT_DIR/analysis-engine"
  PYTHONPATH=. .venv/bin/pytest -v
)

echo "=== [3/4] Running Backend TypeScript Build & Vitest Integration Suite ==="
(
  cd "$ROOT_DIR/backend"
  npm run build
  npm run prisma:seed
  npm test
)

echo "=== [4/4] Running Frontend Production Build & Vitest Suite ==="
(
  cd "$ROOT_DIR/frontend"
  npm run build
  npm test
)

echo "=== ALL THREATLENS AI TESTS & BUILDS PASSED! ==="
