from datetime import datetime, timezone
from src.db.database import insert_event

def _already_escalated(conn, src_ip, event_type, window_minutes):
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT 1 FROM events
        WHERE source = 'correlation'
            AND src_ip = %s
            AND event_type = %s
            AND event_timestamp >= UTC_TIMESTAMP() - INTERVAL %s MINUTE
        LIMIT 1
        """,
        (src_ip, event_type, window_minutes),
    )
    found = cursor.fetchone() is not None
    cursor.close()
    return found

def rule_repeated_alerts(conn, threshold=5, window_minutes=10):
    """
    Flags any src_ip with more than `threshold` events in the last
    `window_minutes`. Returns the list of IPs it escalated.
    """
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT src_ip, COUNT(*) AS n
        FROM events
        WHERE src_ip IS NOT NULL
            AND source != 'correlation'
            AND event_timestamp >= UTC_TIMESTAMP() - INTERVAL %s MINUTE
        GROUP BY src_ip
        HAVING n > %s
        """,
        (window_minutes, threshold),
    )
    offenders = cursor.fetchall()
    cursor.close()
    escalated = []
    for src_ip, count in offenders:
        if _already_escalated(conn, src_ip, "repeated_alerts", window_minutes):
            continue
        insert_event(conn, {
            "event_timestamp": datetime.now(timezone.utc).replace(tzinfo=None),
            "source": "correlation",
            "event_type": "repeated_alerts",
            "severity": 1,
            "src_ip": src_ip,
            "signature": f"{count} events from {src_ip} in the last {window_minutes} minutes",
            "raw_message": f"Correlation rule 'repeated_alerts' fired for {src_ip}: {count} events in {window_minutes}m window",
        })
        escalated.append(src_ip)
    return escalated

def rule_failed_then_success_ssh(conn, window_minutes=10):
    """
    Flags any src_ip with a failed SSH login followed by a successful one
    from the same IP within the window. Returns the list of IPs escalated.
    """
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT DISTINCT f.src_ip
        FROM events f
        JOIN events s
            ON f.src_ip = s.src_ip
            AND s.event_type = 'ssh_accepted_login'
            AND s.event_timestamp > f.event_timestamp
            AND s.event_timestamp <= f.event_timestamp + INTERVAL %s MINUTE
        WHERE f.event_type = 'ssh_failed_login'
        """,
        (window_minutes,),
    )
    offenders = [row[0] for row in cursor.fetchall()]
    cursor.close()
    escalated = []
    for src_ip in offenders:
        if _already_escalated(conn, src_ip, "failed_then_success_login", window_minutes):
            continue
        insert_event(conn, {
            "event_timestamp": datetime.now(timezone.utc).replace(tzinfo=None),
            "source": "correlation",
            "event_type": "failed_then_success_login",
            "severity": 1,
            "src_ip": src_ip,
            "signature": f"Failed SSH login(s) from {src_ip} followed by a success within {window_minutes} min",
            "raw_message": f"Correlation rule 'failed_then_success_ssh' fired for {src_ip}",
        })
        escalated.append(src_ip)
    return escalated