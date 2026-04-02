#!/usr/bin/env bash
# stop-interactsh.sh — gracefully stop the interactsh-client daemon.

PID_FILE="/tmp/agentic-bb-interactsh.pid"
HOST_FILE="/tmp/agentic-bb-interactsh-host.txt"

if [ ! -f "$PID_FILE" ]; then
  echo "[interactsh] not running (no PID file)"
  exit 0
fi

PID=$(cat "$PID_FILE")
if kill -0 "$PID" 2>/dev/null; then
  kill "$PID"
  echo "[interactsh] stopped (PID $PID)"
else
  echo "[interactsh] process $PID already dead"
fi

rm -f "$PID_FILE" "$HOST_FILE"
