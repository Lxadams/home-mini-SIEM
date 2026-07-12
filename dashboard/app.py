import sys
import time
import traceback
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
from src.config import load_config
from src.db.database import get_connection
from datetime import datetime

app = Flask(__name__)
socketio = SocketIO(app, async_mode="threading")

config = load_config()
FILTERABLE_COLUMNS = {"source", "event_type", "severity", "src_ip", "dest_ip"}

@app.route("/api/query")
def query_events():
    from flask import request
    conn = get_connection(config["database"])
    cursor = conn.cursor(dictionary=True)
    where_clauses = []
    params = []
    for column in FILTERABLE_COLUMNS:
        value = request.args.get(column)
        if value:
            where_clauses.append(f"{column} = %s")
            params.append(value)
    signature_search = request.args.get("signature_contains")
    if signature_search:
        where_clauses.append("signature LIKE %s")
        params.append(f"%{signature_search}%")
    start = request.args.get("start")
    if start:
        where_clauses.append("event_timestamp >= %s")
        params.append(start)
    end = request.args.get("end")
    if end:
        where_clauses.append("event_timestamp <= %s")
        params.append(end)
    where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
    limit = min(int(request.args.get("limit", 100)), 500)
    cursor.execute(
        f"SELECT id, event_timestamp, source, event_type, severity, "
        f"src_ip, dest_ip, signature FROM events "
        f"WHERE {where_sql} ORDER BY id DESC LIMIT %s",
        (*params, limit),
    )
    rows = cursor.fetchall()
    for row in rows:
        row["event_timestamp"] = str(row["event_timestamp"])
    cursor.close()
    conn.close()
    return jsonify(rows)

@app.route("/api/summary")
def summary():
    conn = get_connection(config["database"])
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT source, COUNT(*) AS count FROM events GROUP BY source"
    )
    by_source = cursor.fetchall()
    cursor.execute(
        "SELECT severity, COUNT(*) AS count FROM events "
        "WHERE severity IS NOT NULL GROUP BY severity ORDER BY severity"
    )
    by_severity = cursor.fetchall()
    cursor.execute(
        "SELECT src_ip, COUNT(*) AS count FROM events "
        "WHERE src_ip IS NOT NULL GROUP BY src_ip ORDER BY count DESC LIMIT 10"
    )
    top_ips = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify({
        "by_source": by_source,
        "by_severity": by_severity,
        "top_ips": top_ips,
    })

def poll_for_new_events():
    print("poll_for_new_events: starting up", flush=True)
    try:
        conn = get_connection(config["database"])
        conn.autocommit = True
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT MAX(id) AS max_id FROM events")
        last_seen_id = cursor.fetchone()["max_id"] or 0
        print(f"poll_for_new_events: connected, starting from id={last_seen_id}", flush=True)

        while True:
            cursor.execute(
                "SELECT id, event_timestamp, source, event_type, severity, "
                "src_ip, dest_ip, signature FROM events WHERE id > %s ORDER BY id ASC",
                (last_seen_id,),
            )
            new_rows = cursor.fetchall()
            print(f"poll tick, last_seen_id={last_seen_id}, found {len(new_rows)} new row(s)", flush=True)

            for row in new_rows:
                row["event_timestamp"] = str(row["event_timestamp"])
                socketio.emit("new_event", row)
                last_seen_id = row["id"]

            time.sleep(1)
    except Exception:
        print("poll_for_new_events: CRASHED", flush=True)
        traceback.print_exc()


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    socketio.start_background_task(poll_for_new_events)
    socketio.run(app, host="0.0.0.0", port=5000, debug=True, use_reloader=False)