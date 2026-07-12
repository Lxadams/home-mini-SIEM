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
    conn = get_connection(config["database"])
    conn.autocommit = True
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT MAX(id) AS max_id FROM events")
    last_event_id = cursor.fetchone()["max_id"] or 0

    cursor.execute("SELECT MAX(id) AS max_id FROM correlations")
    last_correlation_id = cursor.fetchone()["max_id"] or 0

    try:
        while True:
            cursor.execute(
                "SELECT id, event_timestamp, source, event_type, severity, "
                "src_ip, dest_ip, signature FROM events WHERE id > %s ORDER BY id ASC",
                (last_event_id,),
            )
            for row in cursor.fetchall():
                row["event_timestamp"] = str(row["event_timestamp"])
                socketio.emit("new_event", row)
                last_event_id = row["id"]

            cursor.execute(
                "SELECT id, created_at, rule_name, severity, src_ip, abuse_score, description "
                "FROM correlations WHERE id > %s ORDER BY id ASC",
                (last_correlation_id,),
            )
            for row in cursor.fetchall():
                row["created_at"] = str(row["created_at"])
                socketio.emit("new_correlation", row)
                last_correlation_id = row["id"]

            time.sleep(1)
    except Exception:
        import traceback
        print("poll_for_new_events crashed:")
        traceback.print_exc()

@app.route("/api/correlations")
def get_correlations():
    from flask import request

    conn = get_connection(config["database"])
    cursor = conn.cursor(dictionary=True)

    limit = min(int(request.args.get("limit", 50)), 200)

    cursor.execute(
        "SELECT id, created_at, rule_name, severity, src_ip, abuse_score, description "
        "FROM correlations ORDER BY id DESC LIMIT %s",
        (limit,),
    )
    rows = cursor.fetchall()
    for row in rows:
        row["created_at"] = str(row["created_at"])

    cursor.close()
    conn.close()
    return jsonify(rows)


@app.route("/api/correlations/<int:correlation_id>/events")
def get_correlation_events(correlation_id):
    conn = get_connection(config["database"])
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT e.id, e.event_timestamp, e.source, e.event_type, e.severity,
                e.src_ip, e.dest_ip, e.signature
        FROM events e
        JOIN correlation_events ce ON ce.event_id = e.id
        WHERE ce.correlation_id = %s
        ORDER BY e.event_timestamp ASC
        """,
        (correlation_id,),
    )
    rows = cursor.fetchall()
    for row in rows:
        row["event_timestamp"] = str(row["event_timestamp"])

    cursor.close()
    conn.close()
    return jsonify(rows)

@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    socketio.start_background_task(poll_for_new_events)
    socketio.run(app, host="0.0.0.0", port=5000, debug=True, use_reloader=False, allow_unsafe_werkzeug=True)