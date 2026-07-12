#!/usr/bin/env bash
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

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

echo "Starting collectors (Ctrl+C to stop)..."
source venv/bin/activate
python3 -m src.main