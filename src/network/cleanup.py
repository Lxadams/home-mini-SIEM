from datetime import datetime, timezone


def run_cleanup_cycle(conn, ttl_hours, log=print):
    """
    Prunes network_events rows older than ttl_hours. Deliberately does
    NOT touch network_activity_summary - that table is the persistent
    aggregate and is meant to survive raw-row pruning, same reasoning as
    correlations surviving even though the events.severity/category on
    individual rows can churn. A device's total broadcast count
    shouldn't reset to zero just because the raw packets behind it aged
    out of the TTL window.
    """
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM network_events WHERE ingested_at < UTC_TIMESTAMP() - INTERVAL %s HOUR",
        (ttl_hours,),
    )
    deleted = cursor.rowcount
    conn.commit()
    cursor.close()
    if deleted:
        log(f"network_events cleanup: pruned {deleted} row(s) older than {ttl_hours}h")