import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.config import load_config
from src.db.database import get_connection

def main():
    config = load_config()
    db_config = config["database"]
    conn = get_connection(db_config)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM events")
    total = cursor.fetchone()[0]
    print(f"Total events: {total}\n")

    if total == 0:
        cursor.close()
        conn.close()
        return

    print("By source:")
    cursor.execute("SELECT source, COUNT(*) FROM events GROUP BY source ORDER BY COUNT(*) DESC")
    for source, count in cursor.fetchall():
        print(f"  {source:<12} {count}")

    print("\nBy severity:")
    cursor.execute(
        "SELECT severity, COUNT(*) FROM events "
        "WHERE severity IS NOT NULL GROUP BY severity ORDER BY severity"
    )
    for severity, count in cursor.fetchall():
        print(f"  severity {severity}: {count}")

    print("\nTop source IPs:")
    cursor.execute(
        "SELECT src_ip, COUNT(*) FROM events "
        "WHERE src_ip IS NOT NULL GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT 10"
    )
    for src_ip, count in cursor.fetchall():
        print(f"  {src_ip:<16} {count} event(s)")

    print("\nMost recent events:")
    cursor.execute(
        "SELECT event_timestamp, source, signature, src_ip, dest_ip, severity "
        "FROM events ORDER BY id DESC LIMIT 10"
    )
    for event_timestamp, source, signature, src_ip, dest_ip, severity in cursor.fetchall():
        label = signature or source
        print(f"  [{event_timestamp}] {src_ip} -> {dest_ip} (sev {severity}): {label}")


    cursor.close()
    conn.close()


if __name__ == "__main__":
    main()