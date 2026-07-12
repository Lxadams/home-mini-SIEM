import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.config import load_config
from src.db.database import get_connection
from src.correlation.runner import run_correlation_cycle


def main():
    config = load_config()
    conn = get_connection(config["database"])
    run_correlation_cycle(conn, config)
    conn.close()


if __name__ == "__main__":
    main()