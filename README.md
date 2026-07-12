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
shared schema, and land in the same MySQL table. A background thread runs
four correlation rules automatically (repeated alerts, failed-then-success
SSH logins, port scans, distinct-source floods), writing results into
their own `correlations` table linked back to the specific events that
triggered them. Flagged IPs get checked against AbuseIPDB, cached locally.
A Flask + websocket dashboard shows correlations live, with raw events as
a drill-down/investigation view. See `PROGRESS.md` for the detailed build
log and `PLAN.md` for what's left.

## Architecture

```
Suricata (eve.json)  --> SuricataCollector --\
                                               +--> MySQL (events table)
/var/log/auth.log     --> AuthLogCollector  --/                |
                                                                 v
                                          correlation rules (background thread)
                                                                 |
                                                                 v
                                  correlations + correlation_events (linked to source events)
                                                                 |
                                                                 v
                                        ip_reputation (AbuseIPDB cache) <--
                                                                 |
                                                                 v
                                          Flask + websocket dashboard (correlations first, events as drill-down)
```

Both collectors run as separate threads within one process (`src/main.py`),
each independently tailing its own file, but writing into the same
`events` table, distinguished by a `source` column. That design makes
cross-source correlation possible: "did the IP that triggered a Suricata
alert also fail an SSH login?" becomes one SQL query instead of a join
across differently shaped tables.

Correlation rules (`src/correlation/rules.py`) run automatically on a
configurable interval via a background thread, or on demand via
`scripts/run_correlation.py`, both going through the same
`run_correlation_cycle()` (`src/correlation/runner.py`) so there's one
implementation, not two that could drift apart. Each match is a row in
`correlations`, linked to the specific `events` rows that triggered it via
`correlation_events`, a many to many join table, some correlations
(distinct-source floods) legitimately involve dozens of events. Severity
is computed per match (`src/correlation/severity.py`) against a defined
4-level scale (1 critical to 4 informational), escalated if the IP
involved has a cached bad reputation.

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

The main process starts one thread per enabled collector plus the
correlation thread, and coordinates clean shutdown. `Ctrl+C` signals all
of them to stop via a shared `threading.Event`, then waits for each thread
to actually finish (flushing offsets where relevant) before exiting.
Verified to leave no orphaned background processes.

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
│   ├── main.py                 # entry point: builds collectors + correlation thread, runs them
│   ├── db/
│   │   ├── schema.sql         # events, correlations, correlation_events, ip_reputation
│   │   └── database.py        # connection, schema init, insert helpers
│   ├── collectors/
│   │   ├── base_collector.py      # generic tail/rotation/offset/threading logic
│   │   ├── suricata_collector.py  # eve.json-specific parsing + normalization
│   │   └── auth_log_collector.py  # auth.log-specific parsing + normalization
│   └── correlation/
│       ├── config.py              # loads correlation.* config with sane defaults
│       ├── rules.py               # the four correlation rules
│       ├── severity.py            # base severity per rule + reputation-based escalation
│       ├── enrichment.py          # AbuseIPDB lookups + local caching
│       └── runner.py              # run_correlation_cycle(), shared by script + background thread
├── scripts/
│   ├── query_alerts.py                     # CLI report over the combined events table
│   ├── run_correlation.py                  # manual one-off correlation run
│   ├── generate_correlation_test_data.py   # fresh-timestamped test data for all four rules
│   ├── start_all.sh                        # starts mysql, suricata, dashboard, collectors
│   └── end_all.sh                          # stops dashboard + any leftover collector process
├── dashboard/
│   ├── app.py                  # Flask + Flask-SocketIO app, DB polling thread, API routes
│   ├── templates/index.html    # correlations (live) + charts + events (investigate)
│   └── static/                 # (currently inline in index.html, split out if it grows)
├── tests/
│   ├── sample_eve.json                        # hand-crafted realistic eve.json lines
│   ├── sample_auth.log                        # hand-crafted realistic auth.log lines
│   ├── sample_eve_correlation_test.json       # generated, fresh timestamps, see script above
│   └── sample_auth_correlation_test.log       # generated, fresh timestamps, see script above
└── data/                       # gitignored, collector_state.json + dashboard.pid live here
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
Starts MySQL and Suricata if not already running, then the dashboard
(backgrounded, PID saved to `data/dashboard.pid`), then collectors and the
correlation thread in the foreground. `Ctrl+C` stops the foreground
process cleanly.

```bash
./scripts/end_all.sh
```
Stops the backgrounded dashboard, and as a safety net, sends a clean
shutdown signal to any leftover collector process if `Ctrl+C` wasn't used
directly. Leaves `mysql`/`suricata` system services running.

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
runs all correlation rules once and enriches flagged/outbound IPs against
AbuseIPDB. Runs automatically on an interval too (`correlation.
interval_seconds` in config), this is for a manual one-off run.

```bash
python3 dashboard/app.py
```
starts the dashboard directly (normally started by `start_all.sh`
instead). Correlations shown live at the top, charts below, raw events
available as a filterable investigation view, click any correlation to
see exactly which events triggered it.

## Design notes

- **Why MySQL over SQLite**: chose MySQL specifically to get hands on with a
  real client-server database and its Python connector, rather than the
  no config `sqlite3` standard-library module.
- **Why one shared `events` table instead of one table per source**: it's
  what makes correlation queries a single `WHERE`/`GROUP BY` instead of a
  join across mismatched schemas. Proven out concretely once two
  differently formatted sources (JSON vs. plaintext syslog) both normalize
  into the same table and show up in one combined report.
- **Why correlations live in their own tables (`correlations` +
  `correlation_events`) instead of being written back into `events`**: a
  correlation isn't an event, it's a relationship between several events
  that already happened. The join table keeps the actual link, which
  specific rows triggered a given correlation, queryable and real, instead
  of implicit in whatever a rule's query happened to match at the time.
  Also removes a feedback-loop risk structurally rather than needing a
  filter to guard against it, there's nothing for a correlation to
  accidentally count toward once it's not in the same table it reads from.
- **Why severity is computed, not hardcoded per rule**: each rule has a
  base severity on a defined 4-level scale, escalated one level if the IP
  involved has a cached bad reputation. Severity reflects what's actually
  known at the time a correlation fires, not a static guess.
- **Why dedup checks exact event-id overlap instead of a time window**:
  precise rather than approximate, a correlation only counts as a repeat
  if it's tied to the literal same triggering rows, not just "same IP,
  roughly recently." Verified to survive a genuine mid-run script crash
  without creating duplicate correlations on retry.
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
  acted on. Automated firewall changes on a single-interface home network
  carry real risk of self-lockout, and reputation scores aren't proof,
  tabled until there's a safer rollout plan (dry-run mode, explicit
  never-block list, auditable logging of every action).
- **No ML yet, on purpose**: anomaly detection is explicitly gated behind
  finishing COMPX310.