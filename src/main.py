import threading
from src.collectors.suricata_collector import SuricataCollector
from src.collectors.auth_log_collector import AuthLogCollector
from src.config import load_config, resolve
from src.db.database import init_db, get_connection
import time
from src.correlation.runner import run_correlation_cycle
from src.network.cleanup import run_cleanup_cycle


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


class NetworkCleanupThread:
    def __init__(self, config, interval_seconds=3600, ttl_hours=24):
        self.config = config
        self.interval_seconds = interval_seconds
        self.ttl_hours = ttl_hours
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def run(self):
        # No autocommit=True here on purpose, unlike CorrelationThread -
        # that fix exists for a long-lived connection doing *repeated
        # reads* that need to see new commits from other connections.
        # This thread only ever runs a single DELETE per interval and
        # commits explicitly, so there's no stale-snapshot read to guard
        # against.
        conn = get_connection(self.config["database"])
        try:
            while not self._stop_event.is_set():
                try:
                    run_cleanup_cycle(conn, self.ttl_hours)
                except Exception:
                    import traceback
                    print("network cleanup cycle failed:")
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

    network_noise_cfg = config.get("network_noise", {})
    cleanup_thread_obj = None
    if network_noise_cfg.get("cleanup_enabled", True):
        cleanup_thread_obj = NetworkCleanupThread(
            config,
            interval_seconds=network_noise_cfg.get("cleanup_interval_seconds", 3600),
            ttl_hours=network_noise_cfg.get("ttl_hours", 24),
        )

    if not collectors and not correlation_thread_obj and not cleanup_thread_obj:
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
    if cleanup_thread_obj:
        t = threading.Thread(target=cleanup_thread_obj.run, name="network_cleanup")
        t.start()
        threads.append(t)
        print(
            f"Started network cleanup thread (every "
            f"{cleanup_thread_obj.interval_seconds}s, TTL {cleanup_thread_obj.ttl_hours}h)."
        )
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
        if cleanup_thread_obj:
            cleanup_thread_obj.stop()
        for t in threads:
            t.join()
        print("All collectors stopped cleanly.")

if __name__ == "__main__":
    main()