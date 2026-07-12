RULE_BASE_SEVERITY = {
    "repeated_alerts": 3,
    "failed_then_success_login": 2,
    "port_scan": 3,
    "ddos": 1,
}

def compute_severity(conn, rule_name, ip):
    base = RULE_BASE_SEVERITY[rule_name]
    if not ip:
        return base
    cursor = conn.cursor()
    cursor.execute("SELECT is_known_bad, abuse_score FROM ip_reputation WHERE ip = %s", (ip,))
    row = cursor.fetchone()
    cursor.close()
    if row and row[0]:  # is_known_bad
        return max(1, base - 1), row[1]  # escalate one level, capped at 1
    return base, (row[1] if row else None)