# mini-siem

A lightweight home-network SIEM: collect logs from multiple sources,
normalize them into a common schema, centralize them in a database, apply
correlation/detection rules, enrich flagged IPs against threat intel, and
(eventually) visualize alerts on a dashboard.

Built by a final-year CompSci student (University of Waikato) as a portfolio
project alongside TryHackMe's SOC Level 1 path.

## Current status

Two log sources, a live Suricata IDS sensor and this host's own
`/var/log/auth.log`, run concurrently in separate threads, normalize into a
shared schema, and land in the same MySQL table. Correlation rules run
against that table to catch patterns (repeated alerts from one IP, failed
SSH followed by success), and flagged IPs get checked against AbuseIPDB,
cached locally so repeat checks don't burn API quota. See `PROGRESS.md` for
the detailed build log and `PLAN.md` for what's left.

## Architecture

```
Suricata (eve.json)  --> SuricataCollector --\
                                               +--> MySQL (events table) --> correlation rules --> ip_reputation (AbuseIPDB cache)
/var/log/auth.log     --> AuthLogCollector  --/
```

Both collectors run as separate threads within one process (`src/main.py`),
each independently tailing its own file, but writing into the same
`events` table, distinguished by a `source` column. That design makes
cross-source correlation possible: "did the IP that triggered a Suricata
alert also fail an SSH login?" becomes one SQL query instead of a join
across differently shaped tables.

Correlation rules (`src/correlation/rules.py`) run separately, on demand
via `scripts/run_correlation.py`, querying the shared table for patterns
and writing escalations back into it as `source: 'correlation'` events.
Flagged IPs get checked against AbuseIPDB (`src/correlation/enrichment.py`),
with results cached in a separate `ip_reputation` table so the same IP
isn't re-checked within the cache window. Outbound alert destinations are
always checked (best signal for a compromised local device phoning home),
inbound sources only get checked once they clear a repetition threshold
(a single scan attempt doesn't justify an API call, a sustained one does).

Each collector:
1. Tails a log file (detects rotation via inode comparison, resumes from a
   saved byte offset on restart, offsets for both collectors are persisted
   to one shared, lock-protected state file)
2. Parses each line into its native format (JSON for eve.json, regex for
   auth.log's plaintext syslog format, both BSD and ISO 8601 timestamp
   styles)
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
│   │   ├── schema.sql         # events + ip_reputation tables, indexes
│   │   └── database.py        # connection, schema init, insert helpers
│   ├── collectors/
│   │   ├── base_collector.py      # generic tail/rotation/offset/threading logic
│   │   ├── suricata_collector.py  # eve.json-specific parsing + normalization
│   │   └── auth_log_collector.py  # auth.log-specific parsing + normalization
│   └── correlation/
│       ├── rules.py               # correlation queries over the events table
│       └── enrichment.py          # AbuseIPDB lookups + local caching
├── scripts/
│   ├── query_alerts.py        # CLI report over the combined events table
│   ├── run_correlation.py     # runs correlation rules + IP enrichment
│   └── start_all.sh           # starts mysql, suricata, and collectors
├── tests/
│   ├── sample_eve.json        # hand-crafted realistic eve.json lines
│   └── sample_auth.log        # hand-crafted realistic auth.log lines
└── data/                       # gitignored, collector_state.json (offset tracking) lives here
```

## Setup

Requires Python 3, a running MySQL server, Suricata, OpenSSH server (for
real `auth_log` data), and a free AbuseIPDB API key (for enrichment).

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Copy the example config and fill in real credentials:
```bash
cp config/config.example.yaml config/config.yaml
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
a systemd service (`sudo systemctl enable --now suricata`).

Your own user needs to be in the `suricata` group to read `eve.json`
without `sudo`:
```bash
sudo usermod -aG suricata $USER
```

### auth_log

```bash
sudo apt install openssh-server -y
```

`/var/log/auth.log` is owned by `syslog:adm`, so your user needs to be in
the `adm` group to read it without `sudo`:
```bash
sudo usermod -aG adm $USER
```

### AbuseIPDB

Free account at abuseipdb.com, 1000 checks/day. Add the key to
`config.yaml`:
```yaml
abuseipdb:
  enabled: true
  api_key: "your_key_here"
  cache_days: 7
```

## Running

```bash
./scripts/start_all.sh
```
Starts MySQL and Suricata if they're not already running, then starts the
collectors in the foreground. `Ctrl+C` stops everything cleanly.

Or manually:
```bash
python3 -m src.main
```

```bash
python3 scripts/query_alerts.py
```
gives a combined report across every source: totals by source, severity
breakdown, top source IPs, most recent events.

```bash
python3 scripts/run_correlation.py
```
runs correlation rules against the events table, escalates matches, and
enriches flagged/outbound IPs against AbuseIPDB.

## Design notes

- **Why MySQL over SQLite**: chose MySQL specifically to get hands on with a
  real client-server database and its Python connector, rather than the
  no config `sqlite3` standard-library module.
- **Why one shared `events` table instead of one table per source**: it's
  what makes correlation queries a single `WHERE`/`GROUP BY` instead of a
  join across mismatched schemas. Proven out concretely once two
  differently formatted sources (JSON vs. plaintext syslog) both normalize
  into the same table and show up in one combined report.
- **Why correlation writes back into the same `events` table** instead of
  a separate table: a correlation match is just another kind of event
  (`source: 'correlation'`), queryable the same way as everything else,
  with a `source != 'correlation'` filter in the rules themselves to avoid
  a feedback loop where escalations count toward their own trigger.
- **Why AbuseIPDB results are cached in their own table**: reputation
  lookups aren't events, they're a lookup result tied to an IP, not a point
  in time. `ip_reputation` has `ip` as the primary key, one row per IP,
  `checked_at` controls cache freshness so repeat checks within the window
  don't hit the API again.
- **Why outbound gets enriched unconditionally but inbound needs a
  threshold**: an inbound scan already has a Suricata signature vouching
  for it, the reputation check is just corroboration. An outbound
  connection to a bad destination is a much stronger compromise signal (a
  local device phoning home doesn't look suspicious on the wire the way a
  scan does), worth checking every time. Inbound only gets checked once it
  clears a repetition threshold, so a single stray alert doesn't burn an
  API call.
- **Why timestamps are converted to naive UTC `datetime` objects before
  insert, not passed as raw strings**: MySQL's `DATETIME` type doesn't
  understand ISO 8601's `T`/timezone-offset format. Hit this twice, once
  for eve.json, once for auth.log switching to ISO-format syslog on newer
  rsyslog, both fixed with the same parse-convert-strip approach.
- **Why `insert_event` fills in missing schema fields itself** rather than
  trusting every caller to: collectors, correlation rules, and anything
  added later all go through the same function, so schema completeness is
  guaranteed in one place instead of every caller having to remember it.
  Found this the hard way, first with `auth_log`'s collector missing fields
  Suricata's always had, then again when correlation rules hit the same gap
  from a different angle.
- **Why offset tracking uses a JSON state file rather than replaying the
  whole log on every restart**: this is how production log shippers
  generally work. Built and tested by hand, including the concurrency of
  two collectors writing to the same state file at once (protected with a
  lock).
- **Why collectors run as threads with a shared stop signal instead of each
  catching `KeyboardInterrupt` independently**: `Ctrl+C` only interrupts the
  main thread. A background thread relying on `KeyboardInterrupt` never
  actually stops, and silently leaks a process that keeps writing to the
  database indefinitely. Hit this exact bug once (a stale collector kept
  inserting duplicate alerts every 5 minutes after I thought I'd stopped
  it) before fixing it with a proper `threading.Event` based stop signal.
- **Why Suricata runs as a dedicated unprivileged system user**: running
  network facing software as root when it doesn't need to is avoidable
  risk. Deliberately created a `suricata` system user/group, configured
  `run-as:`, and fixed the resulting permission chain.
- **Why parameterized queries instead of string-built SQL**: SQL injection
  prevention. Direct application of COMPX317 material.
- **No auto-blocking yet**: AbuseIPDB "known bad" results are logged, not
  acted on. Automated firewall changes on a single interface home network
  carry risk of self lockout, and reputation scores aren't proof,
  tabled until there's a safer rollout plan (dry-run mode, explicit
  never-block list, auditable logging of every action).
- **No ML yet, on purpose**: anomaly detection is gated behind
  finishing or progressing COMPX310.