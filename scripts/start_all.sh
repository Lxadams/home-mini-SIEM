#!/usr/bin/env bash
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
mkdir -p data logs

echo "Checking MySQL..."
if ! systemctl is-active --quiet mysql; then
    echo "  starting mysql.service"
    sudo systemctl start mysql
else
    echo "  already running"
fi

echo "Checking Suricata..."
if ! systemctl is-active --quiet suricata; then
    echo "  starting suricata.service"
    sudo systemctl start suricata
else
    echo "  already running"
fi

if [ ! -d "venv" ]; then
    echo "No venv found at $REPO_ROOT/venv. Run setup first."
    exit 1
fi

source venv/bin/activate

if [ -f "data/dashboard.pid" ] && kill -0 "$(cat data/dashboard.pid)" 2>/dev/null; then
    echo "Dashboard already running (PID $(cat data/dashboard.pid))"
else
    echo "Starting dashboard in background..."
    nohup python3 dashboard/app.py > logs/dashboard.log 2>&1 &
    echo $! > data/dashboard.pid
    echo "  dashboard PID $(cat data/dashboard.pid), logs at logs/dashboard.log"
fi

echo "Starting collectors + correlation (Ctrl+C to stop)..."
python3 -m src.main