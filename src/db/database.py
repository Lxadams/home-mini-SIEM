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
    src_ip, src_port, dest_ip, dest_port, protocol, signature, category, raw_message
) VALUES (
    %(ingested_at)s, %(event_timestamp)s, %(source)s, %(event_type)s, %(severity)s,
    %(src_ip)s, %(src_port)s, %(dest_ip)s, %(dest_port)s, %(protocol)s, %(signature)s, 
    %(category)s, %(raw_message)s
)
"""

EVENT_FIELDS = [
    "ingested_at", "event_timestamp", "source", "event_type", "severity",
    "src_ip", "src_port", "dest_ip", "dest_port", "protocol",
    "signature", "category", "raw_message",
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


def insert_correlation(conn, rule_name, severity, src_ip, abuse_score, description, event_ids):
    """
    Inserts a row into `correlations` and links it to the events that
    triggered it via `correlation_events`. Returns the new correlation id.
    """
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO correlations (created_at, rule_name, severity, src_ip, abuse_score, description)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (datetime.now(timezone.utc).replace(tzinfo=None), rule_name, severity, src_ip, abuse_score, description),
    )
    correlation_id = cursor.lastrowid
    if event_ids:
        cursor.executemany(
            "INSERT IGNORE INTO correlation_events (correlation_id, event_id) VALUES (%s, %s)",
            [(correlation_id, event_id) for event_id in event_ids],
        )
    conn.commit()
    cursor.close()
    return correlation_id


INSERT_NETWORK_EVENT_SQL = """
INSERT INTO network_events (
    ingested_at, event_timestamp, source, event_type,
    src_ip, src_port, dest_ip, dest_port, protocol, detail
) VALUES (
    %(ingested_at)s, %(event_timestamp)s, %(source)s, %(event_type)s,
    %(src_ip)s, %(src_port)s, %(dest_ip)s, %(dest_port)s, %(protocol)s, %(detail)s
)
"""

UPSERT_NETWORK_ACTIVITY_SQL = """
INSERT INTO network_activity_summary (
    source, event_type, src_ip, dest_ip, dest_port, protocol, detail,
    count, first_seen, last_seen
) VALUES (
    %(source)s, %(event_type)s, %(src_ip)s, %(dest_ip)s, %(dest_port)s, %(protocol)s, %(detail)s,
    1, %(event_timestamp)s, %(event_timestamp)s
) ON DUPLICATE KEY UPDATE
    count = count + 1,
    last_seen = GREATEST(last_seen, VALUES(last_seen))
"""

NETWORK_EVENT_FIELDS = [
    "ingested_at", "event_timestamp", "source", "event_type",
    "src_ip", "src_port", "dest_ip", "dest_port", "protocol", "detail",
]


def insert_network_event(conn, event: dict) -> int:
    event = dict(event)
    event.setdefault("ingested_at", datetime.now(timezone.utc).replace(tzinfo=None))
    event.setdefault("event_timestamp", event["ingested_at"])
    for field in NETWORK_EVENT_FIELDS:
        event.setdefault(field, None)

    cursor = conn.cursor()
    cursor.execute(INSERT_NETWORK_EVENT_SQL, event)

    summary_event = dict(event)
    for field in ("src_ip", "dest_ip", "protocol", "detail"):
        if summary_event.get(field) is None:
            summary_event[field] = ""
    if summary_event.get("dest_port") is None:
        summary_event["dest_port"] = -1

    cursor.execute(UPSERT_NETWORK_ACTIVITY_SQL, summary_event)

    conn.commit()
    row_id = cursor.lastrowid
    cursor.close()
    return row_id