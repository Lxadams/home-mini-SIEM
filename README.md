# mini-siem

A lightweight home-network SIEM: collect logs from multiple sources,
normalize them into a common schema, centralize them in a database, apply
correlation/detection rules, and (eventually) visualize alerts on a
dashboard.

Built by a final-year CompSci student (University of Waikato) as a portfolio
project alongside TryHackMe's SOC Level 1 path.

## Current status: Phase 2 nearly complete

Two log sources, a live Suricata IDS sensor and this
host's own `/var/log/auth.log`, run concurrently in separate threads,
normalize into a shared schema, and land in the same MySQL table. Both are
verified against real data, not samples. See `PROGRESS.md` for the
detailed build log and `PLAN.md` for what's left.

## Architecture

```
Suricata (eve.json)  --> SuricataCollector --\
                                               +--> MySQL (events table)
/var/log/auth.log     --> AuthLogCollector  --/
```

Both collectors run as separate threads within one process (`src/main.py`),
each independently tailing its own file, but writing into the same
`events` table, distinguished by a `source` column. That design
makes cross-source correlation possible in Phase 3: "did
the IP that triggered a Suricata alert also fail an SSH login?" becomes one
SQL query instead of a join across differently shaped tables.

Each collector:
1. Tails a log file (detects rotation via inode comparison, resumes from a
   saved byte offset on restart, offsets for both collectors are persisted
   to one shared, lock-protected state file)
2. Parses each line into its native format (JSON for eve.json, regex for
   auth.log's plaintext syslog format)
3. Normalizes it into the shared schema (see `src/db/schema.sql`)
4. Inserts it into MySQL

The main process starts one thread per enabled collector and coordinates
clean shutdown. `Ctrl+C` signals every collector to stop via a shared
`threading.Event`, then waits for each thread to actually finish (flushing
its saved offset) before exiting. Verified to leave no orphaned background
processes.

## Repo layout

```
mini-siem/
├── README.md
├── PROGRESS.md                # build log / what's been done
├── PLAN.md                    # phase-by-phase roadmap
├── requirements.txt
├── .gitignore
├── config/
│   ├── config.yaml            # gitignored, real credentials live here
│   └── config.example.yaml    # committed, placeholder values, documents required shape
├── src/
│   ├── config.py              # loads config.yaml
│   ├── main.py                 # entry point: builds enabled collectors, runs them as threads
│   ├── db/
│   │   ├── schema.sql         # the `events` table + indexes
│   │   └── database.py        # connection, schema init, insert helpers
│   └── collectors/
│       ├── base_collector.py      # generic tail/rotation/offset/threading logic
│       ├── suricata_collector.py  # eve.json-specific parsing + normalization
│       └── auth_log_collector.py  # auth.log-specific parsing + normalization
├── scripts/
│   └── query_alerts.py        # CLI report over the combined events table
├── tests/
│   ├── sample_eve.json        # hand-crafted realistic eve.json lines
│   └── sample_auth.log        # hand-crafted realistic auth.log lines
└── data/                       # gitignored, collector_state.json (offset tracking) lives here
```

## Setup

Requires Python 3, a running MySQL server, Suricata, and (for real
`auth_log` data) OpenSSH server.

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

### Suricata

Installed via the OISF PPA:
```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update && sudo apt install suricata -y
```

Runs as a dedicated unprivileged `suricata` system user/group, not root,
configured via `run-as:` in `/etc/suricata/suricata.yaml`, with
`HOME_NET`/`af-packet` interface set to match the monitored NIC. Managed as
a systemd service (`sudo systemctl enable --now suricata`) so it survives
reboots.

Your own user needs to be in the `suricata` group to read `eve.json`
without `sudo`:
```bash
sudo usermod -aG suricata $USER
```
(log out/in, or `newgrp suricata`, for group membership to take effect)

### auth_log

Requires OpenSSH server for real SSH login events to appear:
```bash
sudo apt install openssh-server -y
```

`/var/log/auth.log` is owned by `syslog:adm`, so your user needs to be in
the `adm` group to read it without `sudo`:
```bash
sudo usermod -aG adm $USER
```

## Running

Always run as a module from the repo root, not as a direct file path
(needed for the `src.` package imports to resolve correctly):

```bash
python3 -m src.main
```

This initializes the schema if needed, then starts one thread per collector
enabled in `config.yaml`, each tailing its own log file and inserting
normalized events into MySQL. `Ctrl+C` stops all collectors cleanly, each
saves its read position first, so restarting resumes rather than replaying
history.

```bash
python3 scripts/query_alerts.py
```
gives a combined report across every source currently in the database:
totals by source, severity breakdown, top source IPs, and the most recent
events.

## Design notes

- **Why MySQL over SQLite**: chose MySQL specifically to get hands on with a
  real client-server database and its Python connector, rather than the
  no config `sqlite3` standard-library module.
- **Why one shared `events` table instead of one table per source**: it's
  what makes Phase 3's correlation queries a single `WHERE`/`GROUP BY`
  instead of a join across mismatched schemas. Proven out concretely once
  two differently formatted sources (JSON vs. plaintext syslog) both
  normalize into the same table and show up in one combined report.
- **Why timestamps are converted to naive UTC `datetime` objects before
  insert, not passed as raw strings**: MySQL's `DATETIME` type doesn't
  understand ISO 8601's `T`/timezone-offset format, and auth.log's syslog
  timestamps don't even include a year. Both had to be parsed and
  normalized explicitly demonstrating a "the data isn't clean, I made
  it clean" process.
- **Why offset tracking uses a JSON state file rather than replaying the
  whole log on every restart**: this is how production log
  shippers generally work. Built and tested by hand,
  including the concurrency of two collectors writing to the same
  state file at once (protected with lock).
- **Why collectors run as threads with a shared stop signal instead of each
  catching `KeyboardInterrupt` independently**: `Ctrl+C` only interrupts the
  main thread. A background thread relying on `KeyboardInterrupt` never
  actually stops, and silently leaks a process that keeps writing to the
  database indefinitely. Hit this exact bug once (a stale collector kept
  inserting duplicate Spotify P2P alerts every 5 minutes after I thought
  I'd stopped it) before fixing it with a proper `threading.Event` based
  stop signal that every collector checks on each loop iteration.
- **Why Suricata runs as a dedicated unprivileged system user**: running
  network facing software as root when it doesn't need to be is avoidable
  risk. Deliberately created a `suricata` system user/group, configured
  `run-as:`, and fixed the resulting permission chain (including a
  directory execute bit gotcha: group readable files inside a directory
  without execute permission for that group are still unreachable).
- **Why parameterized queries (`%(field)s` placeholders) instead of
  string-built SQL**: SQL injection prevention. Direct application of COMPX317 material.
- **No ML yet, on purpose**: anomaly detection is explicitly gated behind
  finishing and/or progressing COMPX310.