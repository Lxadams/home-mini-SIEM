import re
from datetime import datetime, timezone
from src.collectors.base_collector import BaseCollector

SYSLOG_ISO_RE = re.compile(
    r'^(?P<iso_timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z))\s+'
    r'(?P<host>\S+)\s+(?P<process>\S+?)(?:\[\d+\])?:\s?(?P<message>.*)$'
)
SYSLOG_BSD_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<process>\S+?)(?:\[\d+\])?:\s?(?P<message>.*)$'
)
FAILED_LOGIN_RE = re.compile(
    r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)'
)
ACCEPTED_LOGIN_RE = re.compile(
    r'Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)'
)
SUDO_RE = re.compile(r'^(?P<user>\S+)\s*:.*COMMAND=(?P<command>.*)$')

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


class AuthLogCollector(BaseCollector):
    source_name = "auth_log"

    def parse_line(self, raw_line):
        match = SYSLOG_ISO_RE.match(raw_line)
        if match:
            return match.groupdict()
        match = SYSLOG_BSD_RE.match(raw_line)
        if match:
            return match.groupdict()
        return None

    def _parse_timestamp(self, parsed):
        if parsed.get("iso_timestamp"):
            dt = datetime.fromisoformat(parsed["iso_timestamp"])
            return dt.astimezone(timezone.utc).replace(tzinfo=None)
        month = MONTHS.get(parsed["month"])
        if month is None:
            return None
        day = int(parsed["day"])
        hour, minute, second = (int(x) for x in parsed["time"].split(":"))
        now = datetime.now(timezone.utc)
        year = now.year
        if month > now.month:
            year -= 1
        return datetime(year, month, day, hour, minute, second)

    def normalize(self, parsed, raw_line):
        process = parsed["process"]
        message = parsed["message"]
        event_timestamp = self._parse_timestamp(parsed)
        if process.startswith("sshd"):
            m = FAILED_LOGIN_RE.search(message)
            if m:
                return {
                    "event_timestamp": event_timestamp,
                    "event_type": "ssh_failed_login",
                    "severity": 2,
                    "src_ip": m.group("ip"),
                    "src_port": int(m.group("port")),
                    "signature": f"Failed SSH login for user '{m.group('user')}'",
                    "raw_message": raw_line,
                }
            m = ACCEPTED_LOGIN_RE.search(message)
            if m:
                return {
                    "event_timestamp": event_timestamp,
                    "event_type": "ssh_accepted_login",
                    "severity": 1,
                    "src_ip": m.group("ip"),
                    "src_port": int(m.group("port")),
                    "signature": f"Successful SSH login for user '{m.group('user')}'",
                    "raw_message": raw_line,
                }
            return None #other sshd chatter

        if process == "sudo":
            m = SUDO_RE.search(message)
            if m:
                return {
                    "event_timestamp": event_timestamp,
                    "event_type": "sudo_command",
                    "severity": 3,
                    "signature": f"sudo by '{m.group('user')}': {m.group('command')}",
                    "raw_message": raw_line,
                }
            return None
        return None