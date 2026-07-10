from src.collectors.suricata_collector import SuricataCollector
from src.collectors.auth_log_collector import AuthLogCollector
from src.config import load_config, resolve
from src.db.database import init_db


def main():
    config = load_config()
    db_config = config["database"]
    state_file = resolve(config["state_file"])
    schema_path = resolve("src/db/schema.sql")
    init_db(db_config, str(schema_path))

    suricata_cfg = config["collectors"]["suricata"]
    if suricata_cfg.get("enabled", False):
        collector = SuricataCollector(
            log_path=resolve(suricata_cfg["eve_json_path"]),
            db_config=db_config,
            state_file=state_file,
            poll_interval_seconds=suricata_cfg.get("poll_interval_seconds", 1.0),
            from_start=suricata_cfg.get("from_start", False),
            event_types=suricata_cfg.get("event_types") or None,
        )
        collector.run()
        return

    auth_log_cfg = config["collectors"].get("auth_log", {})
    if auth_log_cfg.get("enabled", False):
        collector = AuthLogCollector(
            log_path=resolve(auth_log_cfg["path"]),
            db_config=db_config,
            state_file=state_file,
            poll_interval_seconds=auth_log_cfg.get("poll_interval_seconds", 1.0),
            from_start=auth_log_cfg.get("from_start", False),
        )
        collector.run()
        return

    print("No collectors enabled in config.yaml.")


if __name__ == "__main__":
    main()