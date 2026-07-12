import json
from datetime import datetime, timedelta, timezone
import requests
import ipaddress

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

def is_public_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved)
    
def enrich_outbound_ips(conn, api_key, cache_days, limit=50):
    """
    Enriches distinct public dest_ip values from Suricata alerts,
    outbound connections from this host to an external address.
    """
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT DISTINCT dest_ip FROM events
        WHERE source = 'suricata' AND event_type = 'alert' AND dest_ip IS NOT NULL
        """
    )
    candidates = [row[0] for row in cursor.fetchall()]
    cursor.close()
    public_ips = [ip for ip in candidates if is_public_ip(ip)]
    results = {}
    for ip in public_ips[:limit]:
        score, known_bad = check_ip(conn, ip, api_key, cache_days)
        results[ip] = (score, known_bad)
    return results

def enrich_frequent_inbound_ips(conn, api_key, cache_days, threshold=5, window_minutes=10, limit=50):
    """
    Enriches distinct public src_ip values that triggered more than
    `threshold` Suricata alerts within `window_minutes`, external
    IPs scanning or hitting this host repeatedly.
    """
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT src_ip, COUNT(*) AS n
        FROM events
        WHERE source = 'suricata' AND event_type = 'alert' AND src_ip IS NOT NULL
            AND event_timestamp >= UTC_TIMESTAMP() - INTERVAL %s MINUTE
        GROUP BY src_ip
        HAVING n > %s
        """,
        (window_minutes, threshold),
    )
    candidates = [row[0] for row in cursor.fetchall()]
    cursor.close()
    public_ips = [ip for ip in candidates if is_public_ip(ip)]
    results = {}
    for ip in public_ips[:limit]:
        score, known_bad = check_ip(conn, ip, api_key, cache_days)
        results[ip] = (score, known_bad)
    return results

def _is_cached(conn, ip, cache_days):
    cursor = conn.cursor()
    cursor.execute("SELECT checked_at FROM ip_reputation WHERE ip = %s", (ip,))
    row = cursor.fetchone()
    cursor.close()
    if not row:
        return False
    checked_at = row[0]
    return datetime.now(timezone.utc).replace(tzinfo=None) - checked_at < timedelta(days=cache_days)

def check_ip(conn, ip, api_key, cache_days=7):
    """
    Returns (abuse_score, is_known_bad). Uses the local cache if fresh,
    otherwise calls AbuseIPDB and stores the result.
    """
    if _is_cached(conn, ip, cache_days):
        cursor = conn.cursor()
        cursor.execute("SELECT abuse_score, is_known_bad FROM ip_reputation WHERE ip = %s", (ip,))
        score, known_bad = cursor.fetchone()
        cursor.close()
        return score, bool(known_bad)
    response = requests.get(
        ABUSEIPDB_URL,
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=10,
    )
    response.raise_for_status()
    data = response.json()["data"]
    score = data["abuseConfidenceScore"]
    known_bad = score >= 25  # AbuseIPDB's "worth a look" threshold
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO ip_reputation (ip, abuse_score, is_known_bad, checked_at, raw_response)
        VALUES (%s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            abuse_score = VALUES(abuse_score),
            is_known_bad = VALUES(is_known_bad),
            checked_at = VALUES(checked_at),
            raw_response = VALUES(raw_response)
        """,
        (ip, score, known_bad, datetime.now(timezone.utc).replace(tzinfo=None), json.dumps(data)),
    )
    conn.commit()
    cursor.close()
    return score, known_bad