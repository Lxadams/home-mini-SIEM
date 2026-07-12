import mysql.connector
from datetime import datetime, timezone

def get_connection(db_config: dict):
    return mysql.connector.connect(
        host = db_config["host"],
        port = db_config["port"],
        database = db_config["name"],
        user = db_config["user"],
        password = db_config["password"]
    )

def init_db(db_config: dict, schema_path: str) -> None:
    with open(schema_path, "r") as f:
        schema_sql = f.read()
    statements = [s.strip() for s in schema_sql.split(";") if s.strip()]
    conn = get_connection(db_config)
    cursor = conn.cursor()
    try:
        for statement in statements:
            try:
                cursor.execute(statement)
            except mysql.connector.errors.ProgrammingError as e:
                if e.errno == 1061:  # Duplicate key name — index already exists
                    continue
                raise
        conn.commit()
    finally:
        cursor.close()
        conn.close()

INSERT_EVENT_SQL = """
INSERT INTO events (
    ingested_at, event_timestamp, source, event_type, severity,
    src_ip, src_port, dest_ip, dest_port, protocol, signature, raw_message
) VALUES (
    %(ingested_at)s, %(event_timestamp)s, %(source)s, %(event_type)s, %(severity)s,
    %(src_ip)s, %(src_port)s, %(dest_ip)s, %(dest_port)s, %(protocol)s, %(signature)s, %(raw_message)s
)
"""

EVENT_FIELDS = [
    "ingested_at", "event_timestamp", "source", "event_type", "severity",
    "src_ip", "src_port", "dest_ip", "dest_port", "protocol",
    "signature", "raw_message",
]

def insert_event(conn, event: dict) -> int:
    event = dict(event)
    event.setdefault("ingested_at", datetime.now(timezone.utc).replace(tzinfo=None))
    for field in EVENT_FIELDS:
        event.setdefault(field, None)
    cursor = conn.cursor()
    cursor.execute(INSERT_EVENT_SQL, event)
    conn.commit()
    row_id = cursor.lastrowid
    cursor.close()
    return row_id