def load_correlation_config(config):
    return config.get("correlation", {
        "interval_seconds": 60,
        "rules": {
            "repeated_alerts": {"threshold": 5, "window_minutes": 10},
            "failed_then_success_login": {"min_failed_attempts": 3, "window_minutes": 10},
            "port_scan": {"distinct_ports_threshold": 15, "window_minutes": 5},
            "ddos": {"distinct_src_threshold": 20, "window_minutes": 2},
        },
    })