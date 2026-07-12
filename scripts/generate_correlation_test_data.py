import json
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

now = datetime.now(timezone.utc)


def iso(offset_seconds):
    ts = now + timedelta(seconds=offset_seconds)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.000000+00:00")


eve_lines = []

# repeated_alerts: 6 alerts from one IP, clears default threshold of 5
for i in range(6):
    eve_lines.append(json.dumps({
        "timestamp": iso(i * 5),
        "event_type": "alert",
        "src_ip": "198.51.100.201",
        "src_port": 40000 + i,
        "dest_ip": "192.168.20.8",
        "dest_port": 22,
        "proto": "TCP",
        "alert": {
            "action": "allowed", "gid": 1, "signature_id": 2010935,
            "signature": "ET SCAN NMAP OS Detection Probe",
            "category": "Attempted Information Leak", "severity": 2,
        },
    }))

# port_scan: one IP touching 16 distinct dest_ports, clears default threshold of 15
for i, port in enumerate(range(20, 36)):
    eve_lines.append(json.dumps({
        "timestamp": iso(30 + i * 2),
        "event_type": "alert",
        "src_ip": "198.51.100.202",
        "src_port": 41000 + i,
        "dest_ip": "192.168.20.8",
        "dest_port": port,
        "proto": "TCP",
        "alert": {
            "action": "allowed", "gid": 1, "signature_id": 2010936,
            "signature": "ET SCAN Suspicious Port Sweep",
            "category": "Attempted Information Leak", "severity": 2,
        },
    }))

# ddos: 22 distinct src_ips hitting one dest_ip, clears default threshold of 20
for i in range(22):
    eve_lines.append(json.dumps({
        "timestamp": iso(90 + i),
        "event_type": "alert",
        "src_ip": f"203.0.113.{i+1}",
        "src_port": 50000 + i,
        "dest_ip": "192.168.20.8",
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "action": "allowed", "gid": 1, "signature_id": 2010937,
            "signature": "ET DOS Possible SYN Flood",
            "category": "Attempted Denial of Service", "severity": 2,
        },
    }))

with open("tests/sample_eve_correlation_test.json", "w") as f:
    f.write("\n".join(eve_lines) + "\n")

print(f"wrote {len(eve_lines)} eve.json lines to tests/sample_eve_correlation_test.json")


# failed_then_success_login: 4 failures then a success, clears default min of 3
auth_lines = []
for i in range(4):
    ts = (now + timedelta(seconds=150 + i * 5)).strftime("%Y-%m-%dT%H:%M:%S.000000+00:00")
    auth_lines.append(
        f"{ts} logan-laptop sshd-session[99999]: Failed password for invalid user test from 198.51.100.203 port {45000+i} ssh2"
    )
ts = (now + timedelta(seconds=180)).strftime("%Y-%m-%dT%H:%M:%S.000000+00:00")
auth_lines.append(
    f"{ts} logan-laptop sshd-session[99999]: Accepted password for test from 198.51.100.203 port 45010 ssh2"
)

with open("tests/sample_auth_correlation_test.log", "w") as f:
    f.write("\n".join(auth_lines) + "\n")

print(f"wrote {len(auth_lines)} auth.log lines to tests/sample_auth_correlation_test.log")