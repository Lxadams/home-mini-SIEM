import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.config import load_config
from src.db.database import get_connection
from src.correlation.rules import rule_repeated_alerts, rule_failed_then_success_ssh
from src.correlation.enrichment import check_ip, enrich_outbound_ips, enrich_frequent_inbound_ips

def main():
    config = load_config()
    conn = get_connection(config["database"])
    escalated_ips = set()
    escalated_ips.update(rule_repeated_alerts(conn))
    escalated_ips.update(rule_failed_then_success_ssh(conn))
    print(f"Correlation rules escalated {len(escalated_ips)} IP(s): {escalated_ips or 'none'}")
    abuseipdb_cfg = config.get("abuseipdb", {})
    if abuseipdb_cfg.get("enabled"):
        api_key = abuseipdb_cfg["api_key"]
        cache_days = abuseipdb_cfg.get("cache_days", 7)
        for ip in escalated_ips:
            score, known_bad = check_ip(conn, ip, api_key, cache_days)
            flag = "KNOWN BAD" if known_bad else "clean"
            print(f"  {ip}: AbuseIPDB score {score} ({flag})")
        outbound_results = enrich_outbound_ips(conn, api_key, cache_days)
        if outbound_results:
            print(f"\nEnriched {len(outbound_results)} outbound public IP(s):")
            for ip, (score, known_bad) in outbound_results.items():
                flag = "KNOWN BAD" if known_bad else "clean"
                print(f"  {ip}: AbuseIPDB score {score} ({flag})")
        inbound_results = enrich_frequent_inbound_ips(conn, api_key, cache_days)
        if inbound_results:
            print(f"\nEnriched {len(inbound_results)} frequent inbound public IP(s):")
            for ip, (score, known_bad) in inbound_results.items():
                flag = "KNOWN BAD" if known_bad else "clean"
                print(f"  {ip}: AbuseIPDB score {score} ({flag})")
    conn.close()

if __name__ == "__main__":
    main()