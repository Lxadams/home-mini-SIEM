import threading
from src.collectors.suricata_collector import SuricataCollector
from src.collectors.auth_log_collector import AuthLogCollector
from src.config import load_config, resolve
from src.db.database import init_db, get_connection
import time
from src.correlation.runner import run_correlation_cycle


class CorrelationThread:
    def __init__(self, config, interval_seconds=60):
        self.config = config
        self.interval_seconds = interval_seconds
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def run(self):
        conn = get_connection(self.config["database"])
        conn.autocommit = True  # same fix the dashboard needed, avoid a stale snapshot
        try:
            while not self._stop_event.is_set():
                try:
                    run_correlation_cycle(conn, self.config)
                except Exception:
                    import traceback
                    print("correlation cycle failed:")
                    traceback.print_exc()
                self._stop_event.wait(self.interval_seconds)
        finally:
            conn.close()

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
    correlation_cfg = config.get("correlation", {})
    correlation_thread_obj = None
    if correlation_cfg.get("enabled", True):
        correlation_thread_obj = CorrelationThread(
            config, interval_seconds=correlation_cfg.get("interval_seconds", 60)
        )
    if not collectors and not correlation_thread_obj:
        print("Nothing enabled in config.yaml.")
        return
    threads = []
    for collector in collectors:
        t = threading.Thread(target=collector.run, name=collector.source_name)
        t.start()
        threads.append(t)
        print(f"Started {collector.source_name} collector.")
    if correlation_thread_obj:
        t = threading.Thread(target=correlation_thread_obj.run, name="correlation")
        t.start()
        threads.append(t)
        print(f"Started correlation thread (every {correlation_thread_obj.interval_seconds}s).")
    try:
        while any(t.is_alive() for t in threads):
            for t in threads:
                t.join(timeout=0.5)
    except KeyboardInterrupt:
        print("\nStopping all collectors...")
        for collector in collectors:
            collector.stop()
        if correlation_thread_obj:
            correlation_thread_obj.stop()
        for t in threads:
            t.join()
        print("All collectors stopped cleanly.")

if __name__ == "__main__":
    main()