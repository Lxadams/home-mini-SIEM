from src.correlation.config import load_correlation_config
from src.correlation.rules import (
    rule_repeated_alerts,
    rule_failed_then_success_ssh,
    rule_port_scan,
    rule_ddos,
)
from src.correlation.enrichment import check_ip, enrich_outbound_ips, enrich_frequent_inbound_ips


def run_all_rules(conn, rules_cfg):
    created_ids = []
    cfg = rules_cfg.get("repeated_alerts", {})
    created_ids += rule_repeated_alerts(
        conn, threshold=cfg.get("threshold", 5), window_minutes=cfg.get("window_minutes", 10)
    )
    cfg = rules_cfg.get("failed_then_success_login", {})
    created_ids += rule_failed_then_success_ssh(
        conn, min_failed_attempts=cfg.get("min_failed_attempts", 3), window_minutes=cfg.get("window_minutes", 10)
    )
    cfg = rules_cfg.get("port_scan", {})
    created_ids += rule_port_scan(
        conn, distinct_ports_threshold=cfg.get("distinct_ports_threshold", 15), window_minutes=cfg.get("window_minutes", 5)
    )
    cfg = rules_cfg.get("ddos", {})
    created_ids += rule_ddos(
        conn, distinct_src_threshold=cfg.get("distinct_src_threshold", 20), window_minutes=cfg.get("window_minutes", 2)
    )
    return created_ids


def get_correlation_ips(conn, correlation_ids):
    if not correlation_ids:
        return set()
    placeholders = ",".join(["%s"] * len(correlation_ids))
    cursor = conn.cursor()
    cursor.execute(
        f"SELECT DISTINCT src_ip FROM correlations WHERE id IN ({placeholders}) AND src_ip IS NOT NULL",
        tuple(correlation_ids),
    )
    ips = {row[0] for row in cursor.fetchall()}
    cursor.close()
    return ips


def run_correlation_cycle(conn, config, log=print):
    """
    Runs all correlation rules once, then enriches whatever IPs are worth
    checking. `log` defaults to print, but main.py's background thread can
    pass something else in later if logging ever needs to go somewhere
    other than stdout.
    """
    correlation_cfg = load_correlation_config(config)
    created_ids = run_all_rules(conn, correlation_cfg["rules"])

    log(f"Correlation rules created {len(created_ids)} new correlation(s)")

    abuseipdb_cfg = config.get("abuseipdb", {})
    if not abuseipdb_cfg.get("enabled"):
        return
    api_key = abuseipdb_cfg["api_key"]
    cache_days = abuseipdb_cfg.get("cache_days", 7)
    for ip in get_correlation_ips(conn, created_ids):
        score, known_bad = check_ip(conn, ip, api_key, cache_days)
        flag = "KNOWN BAD" if known_bad else "clean"
        log(f"  {ip}: AbuseIPDB score {score} ({flag})")
    outbound_results = enrich_outbound_ips(conn, api_key, cache_days)
    for ip, (score, known_bad) in outbound_results.items():
        flag = "KNOWN BAD" if known_bad else "clean"
        log(f"  outbound {ip}: AbuseIPDB score {score} ({flag})")
    inbound_cfg = correlation_cfg["rules"].get("repeated_alerts", {})
    inbound_results = enrich_frequent_inbound_ips(
        conn, api_key, cache_days,
        threshold=inbound_cfg.get("threshold", 5),
        window_minutes=inbound_cfg.get("window_minutes", 10),
    )
    for ip, (score, known_bad) in inbound_results.items():
        flag = "KNOWN BAD" if known_bad else "clean"
        log(f"  inbound {ip}: AbuseIPDB score {score} ({flag})")