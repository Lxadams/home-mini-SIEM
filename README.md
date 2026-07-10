# mini-siem

A lightweight home-network SIEM: collect logs from multiple sources,
normalize them into a common schema, centralize them in a database, apply
correlation/detection rules, and visualize alerts on a
dashboard.

Built by a final-year CompSci student (University of Waikato) as a portfolio
project alongside TryHackMe's SOC Level 1 path. Built by hand, from scratch, so every piece
is something I understand.

## Why this exists

Most student "SIEM" projects are a Grafana dashboard bolted onto someone
else's docker-compose file. This one is built bottom-up: a hand-written log
tailer and normalizer first, tested against real failure modes (restarts,
log rotation), before reaching for any heavier tooling.

## Current status: Phase 1 complete

Suricata `eve.json` → parsed → normalized → MySQL, with tested offset
persistence (restart-safe) and rotation handling (survives logrotate-style
file swaps). See `PROGRESS.md` for the detailed build log and `PLAN.md` for
what's next.

## Architecture

```
Suricata (eve.json) --> SuricataCollector (tail + parse + normalize) --> MySQL (events table)
```

Every collector: Suricata now, `auth.log` (in Phase 2) writes into the
**same** `events` table, distinguished by a `source` column. That design is what makes cross-source correlation possible later: "did
the IP that triggered a Suricata alert also fail an SSH login?" becomes one
SQL query instead of a join across differently shaped tables.

Each collector:
1. Tails a log file (detects rotation via inode comparison, resumes from a
   saved byte offset on restart)
2. Parses each line into its native format (JSON for eve.json)
3. Normalizes it into the shared schema (see `src/db/schema.sql`)
4. Inserts it into MySQL

## Repo layout

```
mini-siem/
├── README.md
├── PROGRESS.md               # build log / what's been done
├── PLAN.md                   # phase-by-phase roadmap
├── requirements.txt
├── .gitignore
├── config/
│   ├── config.yaml           # gitignored — real credentials live here
│   └── config.example.yaml   # committed — placeholder values, documents required shape
├── src/
│   ├── config.py             # loads config.yaml
│   ├── main.py                # entry point: wires config -> collector -> run loop
│   ├── db/
│   │   ├── schema.sql        # the `events` table + indexes
│   │   └── database.py       # connection, schema init, insert helpers
│   └── collectors/
│       ├── base_collector.py     # generic tail/rotation/offset logic, source-agnostic
│       └── suricata_collector.py # eve.json-specific parsing + normalization
├── scripts/
│   └── query_alerts.py       # (Phase 2) CLI report over the events table
├── tests/
│   └── sample_eve.json       # hand-crafted realistic eve.json lines, used for local testing
└── data/                      # gitignored — collector_state.json (offset tracking) lives here
```

## Setup

Requires Python 3 and a running MySQL server.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Copy the example config and fill in your real MySQL credentials:
```bash
cp config/config.example.yaml config/config.yaml
# edit config/config.yaml with your actual database password
```

Create the database and a dedicated (non-root) app user in MySQL:
```sql
CREATE DATABASE mini_siem;
CREATE USER 'siem_app'@'localhost' IDENTIFIED BY 'your_password_here';
GRANT ALL PRIVILEGES ON mini_siem.* TO 'siem_app'@'localhost';
FLUSH PRIVILEGES;
```

## Running

Always run as a module from the repo root, not as a direct file path (needed
for the `src.` package imports to resolve correctly):

```bash
python3 -m src.main
```

This initializes the schema if needed, then tails whatever `eve.json` path
is configured in `config.yaml` and inserts normalized alert events into
MySQL. `Ctrl+C` to stop — it saves its read position first, so restarting
picks up where it left off rather than replaying history.

By default (`tests/sample_eve.json`, `from_start: true` in the sample
config) it demos against bundled sample data with no live Suricata sensor
required. Point `eve.json_path` at a real sensor's log once one exists (see
`PLAN.md`, Phase 2).

## Design notes / things I'd say in an interview

- **Why MySQL over SQLite**: chose MySQL specifically to get hands-on with a
  real client-server database and its Python connector, rather than the
  zero-config `sqlite3` standard library module, closer to what a
  production SIEM's storage layer would actually look like, and forced me
  to deal with real concerns (connection config, credential management,
  version-specific SQL syntax) that SQLite hides.
- **Why one shared `events` table instead of one table per source**: it's
  what makes Phase 3's correlation queries a single `WHERE`/`GROUP BY`
  instead of a join across mismatched schemas.
- **Why timestamps are converted to naive UTC `datetime` objects before
  insert, not passed as raw ISO strings**: MySQL's `DATETIME` type doesn't
  understand ISO 8601's `T` separator or timezone offsets, and rejects them
  outright. Real bug I hit and fixed: see `PROGRESS.md`.
- **Why offset tracking uses a JSON state file rather than replaying the
  whole log on every restart**: this is how production log
  shippers like Filebeat/Promtail work. Built and tested it by hand so I
  actually understand the restart/rotation edge cases those tools handle
  for you.
- **Why parameterized queries (`%(field)s` placeholders) instead of
  string-built SQL**: SQL injection prevention isn't optional, even in a
  personal project. This is a direct, deliberate application of what I
  covered in COMPX317.
- **No ML yet, on purpose**: anomaly detection is explicitly gated behind
  finishing or progressing in COMPX310. I'd rather ship a correlation-rules SIEM I can defend than a README claiming ML skills I don't have yet.
