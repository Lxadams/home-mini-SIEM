import threading
from src.collectors.suricata_collector import SuricataCollector
from src.collectors.auth_log_collector import AuthLogCollector
from src.config import load_config, resolve
from src.db.database import init_db

def build_collectors(config):
    db_config = config["database"]
    state_file = resolve(config["state_file"])
    collectors = []
    suricata_cfg = config["collectors"].get("suricata", {})
    if suricata_cfg.get("enabled", False):
        collectors.append(SuricataCollector(
            log_path=resolve(suricata_cfg["eve_json_path"]),
            db_config=db_config,
            state_file=state_file,
            poll_interval_seconds=suricata_cfg.get("poll_interval_seconds", 1.0),
            from_start=suricata_cfg.get("from_start", False),
            event_types=suricata_cfg.get("event_types") or None,
        ))
    auth_log_cfg = config["collectors"].get("auth_log", {})
    if auth_log_cfg.get("enabled", False):
        collectors.append(AuthLogCollector(
            log_path=resolve(auth_log_cfg["path"]),
            db_config=db_config,
            state_file=state_file,
            poll_interval_seconds=auth_log_cfg.get("poll_interval_seconds", 1.0),
            from_start=auth_log_cfg.get("from_start", False),
        ))
    return collectors


def main():
    config = load_config()
    init_db(config["database"], str(resolve("src/db/schema.sql")))
    collectors = build_collectors(config)
    if not collectors:
        print("No collectors enabled in config.yaml.")
        return
    threads = []
    for collector in collectors:
        t = threading.Thread(target=collector.run, name=collector.source_name)
        t.start()
        threads.append(t)
        print(f"Started {collector.source_name} collector.")
    try:
        while any(t.is_alive() for t in threads):
            for t in threads:
                t.join(timeout=0.5)
    except KeyboardInterrupt:
        print("\nStopping all collectors...")
        for collector in collectors:
            collector.stop()
        for t in threads:
            t.join()
        print("All collectors stopped cleanly.")

if __name__ == "__main__":
    main()