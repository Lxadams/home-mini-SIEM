from src.config import load_config, resolve
from src.db.database import init_db
from src.collectors.suricata_collector import SuricataCollector

def main():
    config = load_config()
    db_config = config["database"]
    state_file = resolve(config["state_file"])
    schema_path = resolve("src/db/schema.sql")
    
    init_db(db_config, str(schema_path))
    
    suricata_cfg = config["collectors"]["suricata"]
    if not suricata_cfg.get("enabled", False):
        print("Suricata collector is disabled in config.yaml.")
        return
    
    collector = SuricataCollector(
        log_path = resolve(suricata_cfg["eve_json_path"]),
        db_config = db_config,
        state_file = state_file,
        poll_interval_seconds = suricata_cfg.get("poll_interval_seconds", 1.0),
        from_start = suricata_cfg.get("from_start", False),
        event_types = suricata_cfg.get("event_types") or None
    )
    collector.run()
    
if __name__ == "__main__":
    main()