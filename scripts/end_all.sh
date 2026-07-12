#!/usr/bin/env bash

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "Stopping dashboard..."
if [ -f "data/dashboard.pid" ]; then
    PID="$(cat data/dashboard.pid)"
    if kill -0 "$PID" 2>/dev/null; then
        kill "$PID"
        echo "  stopped dashboard (PID $PID)"
    else
        echo "  PID file present but process not running"
    fi
    rm -f data/dashboard.pid
else
    echo "  no dashboard PID file found, nothing to stop"
fi

echo "Checking for a detached collector process..."
COLLECTOR_PID="$(pgrep -f 'python3 -m src.main' || true)"
if [ -n "$COLLECTOR_PID" ]; then
    echo "  found PID $COLLECTOR_PID, sending clean shutdown signal"
    kill -INT "$COLLECTOR_PID"
    sleep 2
    echo "  done"
else
    echo "  none running (expected if you Ctrl+C'd it yourself)"
fi

echo ""
echo "mysql.service and suricata.service left running, they're system services, not per-session."
echo "Stop those separately if you actually want to: sudo systemctl stop suricata mysql"