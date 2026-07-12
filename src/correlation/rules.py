from datetime import datetime, timezone
from src.db.database import insert_correlation
from src.correlation.severity import compute_severity

def _already_correlated(conn, rule_name, event_ids):
    """
    True if any of these event_ids are already linked to an existing
    correlation of this rule_name, meaning this exact pattern has already
    been flagged, not just "an IP was flagged recently."
    """
    if not event_ids:
        return False
    placeholders = ",".join(["%s"] * len(event_ids))
    cursor = conn.cursor()
    cursor.execute(
        f"""
        SELECT 1 FROM correlation_events ce
        JOIN correlations c ON c.id = ce.correlation_id
        WHERE c.rule_name = %s AND ce.event_id IN ({placeholders})
        LIMIT 1
        """,
        (rule_name, *event_ids),
    )
    found = cursor.fetchone() is not None
    cursor.close()
    return found


def rule_repeated_alerts(conn, threshold=5, window_minutes=10):
    """
    Flags any src_ip with more than `threshold` events in the last
    `window_minutes`. Returns the list of correlation ids created.
    """
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT src_ip, COUNT(*) AS n, GROUP_CONCAT(id) AS event_ids
        FROM events
        WHERE src_ip IS NOT NULL
            AND source = 'suricata'
            AND event_timestamp >= UTC_TIMESTAMP() - INTERVAL %s MINUTE
        GROUP BY src_ip
        HAVING n > %s
        """,
        (window_minutes, threshold),
    )
    offenders = cursor.fetchall()
    cursor.close()
    created = []
    for src_ip, count, event_ids_str in offenders:
        event_ids = [int(x) for x in event_ids_str.split(",")]
        if _already_correlated(conn, "repeated_alerts", event_ids):
            continue
        severity, abuse_score = compute_severity(conn, "repeated_alerts", src_ip)
        correlation_id = insert_correlation(
            conn,
            rule_name="repeated_alerts",
            severity=severity,
            src_ip=src_ip,
            abuse_score=abuse_score,
            description=f"{count} events from {src_ip} in the last {window_minutes} minutes",
            event_ids=event_ids,
        )
        created.append(correlation_id)
    return created


def rule_failed_then_success_ssh(conn, min_failed_attempts=3, window_minutes=10):
    """
    Flags a successful SSH login preceded by at least `min_failed_attempts`
    failed logins from the same IP within `window_minutes`.
    """
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT s.id AS success_id, s.src_ip, COUNT(f.id) AS failed_count,
            GROUP_CONCAT(f.id) AS failed_ids
        FROM events s
        JOIN events f
            ON f.src_ip = s.src_ip
            AND f.event_type = 'ssh_failed_login'
            AND f.event_timestamp < s.event_timestamp
            AND f.event_timestamp >= s.event_timestamp - INTERVAL %s MINUTE
        WHERE s.event_type = 'ssh_accepted_login'
        GROUP BY s.id, s.src_ip
        HAVING failed_count >= %s
        """,
        (window_minutes, min_failed_attempts),
    )
    matches = cursor.fetchall()
    cursor.close()
    created = []
    for success_id, src_ip, failed_count, failed_ids_str in matches:
        event_ids = [success_id] + [int(x) for x in failed_ids_str.split(",")]
        if _already_correlated(conn, "failed_then_success_login", event_ids):
            continue
        severity, abuse_score = compute_severity(conn, "failed_then_success_login", src_ip)
        correlation_id = insert_correlation(
            conn,
            rule_name="failed_then_success_login",
            severity=severity,
            src_ip=src_ip,
            abuse_score=abuse_score,
            description=f"{failed_count} failed SSH login(s) from {src_ip} followed by a success within {window_minutes} min",
            event_ids=event_ids,
        )
        created.append(correlation_id)
    return created


def rule_port_scan(conn, distinct_ports_threshold=15, window_minutes=5):
    """
    Flags a src_ip touching at least `distinct_ports_threshold` distinct
    dest_ports within `window_minutes`, a port sweep pattern.
    """
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT src_ip, COUNT(DISTINCT dest_port) AS distinct_ports, GROUP_CONCAT(id) AS event_ids
        FROM events
        WHERE source = 'suricata' AND dest_port IS NOT NULL
            AND event_timestamp >= UTC_TIMESTAMP() - INTERVAL %s MINUTE
        GROUP BY src_ip
        HAVING distinct_ports >= %s
        """,
        (window_minutes, distinct_ports_threshold),
    )
    matches = cursor.fetchall()
    cursor.close()
    created = []
    for src_ip, distinct_ports, event_ids_str in matches:
        event_ids = [int(x) for x in event_ids_str.split(",")]
        if _already_correlated(conn, "port_scan", event_ids):
            continue
        severity, abuse_score = compute_severity(conn, "port_scan", src_ip)
        correlation_id = insert_correlation(
            conn,
            rule_name="port_scan",
            severity=severity,
            src_ip=src_ip,
            abuse_score=abuse_score,
            description=f"{src_ip} touched {distinct_ports} distinct ports in the last {window_minutes} minutes",
            event_ids=event_ids,
        )
        created.append(correlation_id)
    return created


def rule_ddos(conn, distinct_src_threshold=20, window_minutes=2):
    """
    Flags a dest_ip receiving traffic from at least `distinct_src_threshold`
    distinct source IPs within `window_minutes`.
    """
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT dest_ip, COUNT(DISTINCT src_ip) AS distinct_sources, GROUP_CONCAT(id) AS event_ids
        FROM events
        WHERE source = 'suricata' AND dest_ip IS NOT NULL
            AND event_timestamp >= UTC_TIMESTAMP() - INTERVAL %s MINUTE
        GROUP BY dest_ip
        HAVING distinct_sources >= %s
        """,
        (window_minutes, distinct_src_threshold),
    )
    matches = cursor.fetchall()
    cursor.close()
    created = []
    for dest_ip, distinct_sources, event_ids_str in matches:
        event_ids = [int(x) for x in event_ids_str.split(",")]
        # dest_ip is the meaningful IP here (the target)
        if _already_correlated(conn, "ddos", event_ids):
            continue
        severity, abuse_score = compute_severity(conn, "ddos", None)  # no single src_ip to check reputation on
        correlation_id = insert_correlation(
            conn,
            rule_name="ddos",
            severity=severity,
            src_ip=dest_ip,  # stored in src_ip column for schema consistency, the target
            abuse_score=abuse_score,
            description=f"{dest_ip} received traffic from {distinct_sources} distinct sources in {window_minutes} minutes",
            event_ids=event_ids,
        )
        created.append(correlation_id)
    return created