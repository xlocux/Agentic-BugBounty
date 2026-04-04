#!/usr/bin/env bash
# start-interactsh.sh — start interactsh-client as a background daemon.
# Writes PID, host, and JSONL log to /tmp/agentic-bb-interactsh-*.
# Safe to call multiple times — no-ops if already running.

set -euo pipefail

PID_FILE="/tmp/agentic-bb-interactsh.pid"
HOST_FILE="/tmp/agentic-bb-interactsh-host.txt"
LOG_FILE="/tmp/agentic-bb-interactsh.jsonl"
ERR_FILE="/tmp/agentic-bb-interactsh.err"

# ── Already running? ──────────────────────────────────────────────────────────
if [ -f "$PID_FILE" ]; then
  PID=$(cat "$PID_FILE")
  if kill -0 "$PID" 2>/dev/null; then
    HOST=$(cat "$HOST_FILE" 2>/dev/null || echo "unknown")
    echo "[interactsh] already running (PID $PID) — host: $HOST"
    exit 0
  else
    echo "[interactsh] stale PID file found, cleaning up"
    rm -f "$PID_FILE" "$HOST_FILE"
  fi
fi

# ── Check binary ──────────────────────────────────────────────────────────────
INTERACTSH_BIN="${INTERACTSH_BIN:-$(which interactsh-client 2>/dev/null || echo "")}"
if [ -z "$INTERACTSH_BIN" ]; then
  echo "[interactsh] ERROR: interactsh-client not found in PATH"
  echo "  Install: go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
  echo "  Or:      apt install interactsh"
  exit 1
fi

# ── Launch ────────────────────────────────────────────────────────────────────
# -json          → structured JSONL output (one callback per line)
# -v             → verbose (includes DNS, HTTP, SMTP callbacks)
# -server        → use public interactsh server
# -output        → write callbacks to log file
echo "[interactsh] starting client..."
"$INTERACTSH_BIN" \
  -json \
  -v \
  -output "$LOG_FILE" \
  2>"$ERR_FILE" &

DAEMON_PID=$!
echo $DAEMON_PID > "$PID_FILE"

# ── Wait for host registration (max 15s) ─────────────────────────────────────
echo "[interactsh] waiting for host registration..."
for i in $(seq 1 30); do
  sleep 0.5

  # interactsh-client prints the host to stderr on startup
  HOST=$(grep -oP '[a-z0-9]+\.oast\.(fun|me|live|pro|site)|[a-z0-9]+\.interact\.sh' \
    "$ERR_FILE" 2>/dev/null | head -1 || true)

  if [ -z "$HOST" ]; then
    # Also check stdout log
    HOST=$(grep -oP '"interaction_domain"\s*:\s*"\K[^"]+' \
      "$LOG_FILE" 2>/dev/null | head -1 || true)
  fi

  if [ -n "$HOST" ]; then
    echo "$HOST" > "$HOST_FILE"
    echo "[interactsh] registered — host: $HOST"
    echo "[interactsh] PID: $DAEMON_PID"
    echo "[interactsh] log: $LOG_FILE"
    exit 0
  fi

  # Check process still alive
  if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo "[interactsh] ERROR: process died during startup"
    cat "$ERR_FILE" 2>/dev/null || true
    rm -f "$PID_FILE"
    exit 1
  fi
done

# Timeout — process is running but host not seen yet
# Write a placeholder so pipeline knows to wait
echo "pending" > "$HOST_FILE"
echo "[interactsh] WARNING: host not yet visible in output — still running (PID $DAEMON_PID)"
echo "  Check: cat $ERR_FILE"
echo "  Once host appears, run: cat $ERR_FILE | grep -oP '[a-z0-9]+\.oast\.(fun|me|live)'"
exit 0
