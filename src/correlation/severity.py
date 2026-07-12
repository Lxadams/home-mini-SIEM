RULE_BASE_SEVERITY = {
    "repeated_alerts": 3,
    "failed_then_success_login": 2,
    "port_scan": 3,
    "ddos": 1,
}


def compute_severity(conn, rule_name, ip):
    """
    Returns (severity, abuse_score). abuse_score is None if no IP was
    given, or if the IP hasn't been checked against AbuseIPDB yet.
    """
    base = RULE_BASE_SEVERITY[rule_name]

    if not ip:
        return base, None

    cursor = conn.cursor()
    cursor.execute("SELECT is_known_bad, abuse_score FROM ip_reputation WHERE ip = %s", (ip,))
    row = cursor.fetchone()
    cursor.close()

    if not row:
        return base, None

    is_known_bad, abuse_score = row
    if is_known_bad:
        return max(1, base - 1), abuse_score
    return base, abuse_score