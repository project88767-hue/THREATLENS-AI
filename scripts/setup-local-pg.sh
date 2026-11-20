#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PG_DIR="$ROOT_DIR/.local-pg/data"
PG_RUN="$ROOT_DIR/.local-pg/run"
PG_LOG="$ROOT_DIR/.local-pg/postgres.log"
PG_PORT="${LOCAL_PG_PORT:-5433}"

PG_BIN=""
for ver in 18 17 16 15 14; do
  if [ -x "/usr/lib/postgresql/$ver/bin/initdb" ]; then
    PG_BIN="/usr/lib/postgresql/$ver/bin"
    break
  fi
done

if [ -z "$PG_BIN" ]; then
  if command -v initdb >/dev/null 2>&1; then
    PG_BIN="$(dirname "$(command -v initdb)")"
  else
    echo "PostgreSQL binaries (initdb/pg_ctl) not found. Please use Docker Compose or an external DATABASE_URL."
    exit 1
  fi
fi

mkdir -p "$PG_RUN"

if [ ! -f "$PG_DIR/PG_VERSION" ]; then
  echo "[THREATLENS] Initializing local user-space PostgreSQL cluster at $PG_DIR ..."
  "$PG_BIN/initdb" -D "$PG_DIR" -U threatlens -A trust --encoding=UTF8 --locale=C >/dev/null
  cat >> "$PG_DIR/postgresql.conf" <<EOF
listen_addresses = '127.0.0.1'
port = $PG_PORT
unix_socket_directories = '$PG_RUN'
EOF
fi

if ! "$PG_BIN/pg_isready" -h 127.0.0.1 -p "$PG_PORT" -U threatlens >/dev/null 2>&1; then
  echo "[THREATLENS] Starting local PostgreSQL on 127.0.0.1:$PG_PORT ..."
  "$PG_BIN/pg_ctl" -D "$PG_DIR" -l "$PG_LOG" start >/dev/null
fi

if ! psql -h 127.0.0.1 -p "$PG_PORT" -U threatlens -lqt | cut -d \| -f 1 | grep -qw threatlens; then
  echo "[THREATLENS] Creating database 'threatlens' ..."
  createdb -h 127.0.0.1 -p "$PG_PORT" -U threatlens threatlens
fi

echo "[THREATLENS] PostgreSQL ready at postgresql://threatlens@127.0.0.1:$PG_PORT/threatlens"
