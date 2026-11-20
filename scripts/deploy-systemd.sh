#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYSTEMD_DIR="$HOME/.config/systemd/user"
mkdir -p "$SYSTEMD_DIR" "$ROOT_DIR/logs"

# Ensure local Postgres data cluster and database exist
"$ROOT_DIR/scripts/setup-local-pg.sh"

# Build latest Frontend SPA and Backend TypeScript
echo "[DEPLOY] Building frontend production bundle..."
npm --prefix "$ROOT_DIR/frontend" run build

echo "[DEPLOY] Building backend production server..."
npm --prefix "$ROOT_DIR/backend" run build

# Stop standalone pg_ctl daemon so systemd owns the foreground postgres process cleanly
PG_BIN=""
for ver in 18 17 16 15 14; do
  if [ -x "/usr/lib/postgresql/$ver/bin/postgres" ]; then
    PG_BIN="/usr/lib/postgresql/$ver/bin"
    break
  fi
done

if ! systemctl --user is-active --quiet threatlens-postgres.service; then
  "$PG_BIN/pg_ctl" -D "$ROOT_DIR/.local-pg/data" stop >/dev/null 2>&1 || true
fi

cat > "$SYSTEMD_DIR/threatlens-postgres.service" <<EOF
[Unit]
Description=THREATLENS AI Local PostgreSQL Database
After=network.target

[Service]
Type=simple
ExecStart=$PG_BIN/postgres -D $ROOT_DIR/.local-pg/data
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
EOF

cat > "$SYSTEMD_DIR/threatlens-engine.service" <<EOF
[Unit]
Description=THREATLENS AI Python FastAPI Analysis Engine
After=network.target

[Service]
Type=simple
WorkingDirectory=$ROOT_DIR/analysis-engine
EnvironmentFile=-$ROOT_DIR/analysis-engine/.env
Environment=PYTHONPATH=$ROOT_DIR/analysis-engine
ExecStart=$ROOT_DIR/analysis-engine/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8088
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
EOF

cat > "$SYSTEMD_DIR/threatlens-web.service" <<EOF
[Unit]
Description=THREATLENS AI Unified Web & API Server
After=network.target threatlens-postgres.service threatlens-engine.service
Requires=threatlens-postgres.service threatlens-engine.service

[Service]
Type=simple
WorkingDirectory=$ROOT_DIR/backend
EnvironmentFile=$ROOT_DIR/backend/.env
Environment=HOST=0.0.0.0
ExecStart=/usr/bin/env node $ROOT_DIR/backend/dist/server.js
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
EOF

CLOUDFLARED_BIN="/home/aashutosh/bin/cloudflared"
if [ ! -x "$CLOUDFLARED_BIN" ]; then
  CLOUDFLARED_BIN="$(command -v cloudflared || true)"
fi

if [ -n "$CLOUDFLARED_BIN" ] && [ -x "$CLOUDFLARED_BIN" ]; then
  cat > "$SYSTEMD_DIR/threatlens-tunnel.service" <<EOF
[Unit]
Description=THREATLENS AI Public HTTPS Cloudflare Tunnel
After=network-online.target threatlens-web.service
Wants=threatlens-web.service

[Service]
Type=simple
ExecStart=$CLOUDFLARED_BIN tunnel --no-autoupdate --protocol http2 --url http://127.0.0.1:4000 --logfile $ROOT_DIR/logs/cloudflared.log
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF
fi

systemctl --user daemon-reload
systemctl --user enable --now threatlens-postgres.service
sleep 2
systemctl --user enable threatlens-engine.service
systemctl --user restart threatlens-engine.service
systemctl --user enable threatlens-web.service
systemctl --user restart threatlens-web.service

if [ -f "$SYSTEMD_DIR/threatlens-tunnel.service" ]; then
  systemctl --user enable threatlens-tunnel.service
  if ! systemctl --user is-active --quiet threatlens-tunnel.service || ! grep -Eo 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$ROOT_DIR/logs/cloudflared.log" >/dev/null 2>&1; then
    rm -f "$ROOT_DIR/logs/cloudflared.log"
    systemctl --user restart threatlens-tunnel.service
  fi
fi

echo "[DEPLOY] Waiting for public HTTPS tunnel URL..."
for _ in {1..15}; do
  if grep -Eo 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$ROOT_DIR/logs/cloudflared.log" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

TUNNEL_URL="$(grep -Eo 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$ROOT_DIR/logs/cloudflared.log" | tail -n 1 || true)"
echo "============================================================"
echo " THREATLENS AI DEPLOYED (24/7 systemd user services)"
echo "  Local / VPS IP : http://148.72.141.50:4000"
if [ -n "$TUNNEL_URL" ]; then
  echo "  Public HTTPS   : $TUNNEL_URL"
fi
echo "============================================================"
