import json
from datetime import datetime, timezone
from src.collectors.base_collector import BaseCollector
from src.collectors.suricata_severity import map_suricata_severity


class SuricataCollector(BaseCollector):
    source_name = "suricata"
    def __init__(self, *args, event_types=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.event_types_filter = set(event_types) if event_types else None

    def parse_line(self, raw_line):
        try:
            return json.loads(raw_line)
        except json.JSONDecodeError:
            print(f"Skipping malformed JSON line: {raw_line[:100]}")
            return None

    def _parse_timestamp(self, ts_str):
        if not ts_str:
            return None
        try:
            dt = datetime.fromisoformat(ts_str)
            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        except ValueError:
            return None

    def normalize(self, parsed, raw_line):
        event_type = parsed.get("event_type")
        if self.event_types_filter is not None and event_type not in self.event_types_filter:
            return None
        alert = parsed.get("alert") or {}
        category = alert.get("category")
        signature = alert.get("signature")

        return {
            "event_timestamp": self._parse_timestamp(parsed.get("timestamp")),
            "event_type": event_type,
            "severity": map_suricata_severity(category, signature),
            "category": category,
            "src_ip": parsed.get("src_ip"),
            "src_port": parsed.get("src_port"),
            "dest_ip": parsed.get("dest_ip"),
            "dest_port": parsed.get("dest_port"),
            "protocol": parsed.get("proto"),
            "signature": signature,
            "raw_message": raw_line,
        }