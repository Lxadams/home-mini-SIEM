import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from src.db.database import get_connection, insert_event

def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)

class BaseCollector:
    source_name = "base"
    
    def __init__(self, log_path, db_config, state_file, poll_interval_seconds=1.0, from_start=False):
        self.log_path = Path(log_path)
        self.db_config = db_config
        self.state_file = Path(state_file)
        self.poll_interval_seconds = poll_interval_seconds
        self.from_start = from_start
        self._file = None
        self._inode = None

    def _load_state(self):
        if self.state_file.exists():
            return json.loads(self.state_file.read_text())
        return {}

    def _save_state(self, offset, inode):
        state = self._load_state()
        state[str(self.log_path)] = {"offset": offset, "inode": inode}
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps(state, indent=2))

    def _open_file(self):
        self._file = open(self.log_path, "r", encoding="utf-8", errors="replace")
        self._inode = os.fstat(self._file.fileno()).st_ino
        state = self._load_state().get(str(self.log_path))
        has_valid_state = state and state.get("inode") == self._inode
        if has_valid_state:
            self._file.seek(state["offset"])
        elif self.from_start:
            self._file.seek(0)
        else:
            self._file.seek(0, os.SEEK_END)

    def _rotated(self):
        try:
            current_inode = os.stat(self.log_path).st_ino
        except FileNotFoundError:
            return False
        return current_inode != self._inode

    def parse_line(self, raw_line):
        raise NotImplementedError

    def normalize(self, parsed, raw_line):
        raise NotImplementedError

    def run(self):
        self._open_file()
        conn = get_connection(self.db_config)
        try:
            while True:
                line = self._file.readline()
                if line:
                    self._handle_line(conn, line)
                    continue
                if self._rotated():
                    self._file.close()
                    self._open_file()
                    continue
                self._save_state(self._file.tell(), self._inode)
                time.sleep(self.poll_interval_seconds)
        except KeyboardInterrupt:
            print(f"Stopping {self.source_name} collector.")
        finally:
            self._save_state(self._file.tell(), self._inode)
            self._file.close()
            conn.close()

    def _handle_line(self, conn, raw_line):
        raw_line = raw_line.rstrip("\n")
        if not raw_line.strip():
            return
        parsed = self.parse_line(raw_line)
        if parsed is None:
            return
        event = self.normalize(parsed, raw_line)
        if event is None:
            return

        EVENT_FIELDS = [
            "ingested_at", "event_timestamp", "source", "event_type", "severity",
            "src_ip", "src_port", "dest_ip", "dest_port", "protocol",
            "signature", "raw_message",
        ]
        
        event.setdefault("ingested_at", utc_now())
        event.setdefault("source", self.source_name)
        for field in EVENT_FIELDS:
            event.setdefault(field, None)
        insert_event(conn, event)