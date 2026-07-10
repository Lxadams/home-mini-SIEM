# Progress Log

A running record of what's been built, in order, including the real bugs hit
and fixed along the way. Kept honest on purpose, the debugging is as much
the value as the finished code.

---

## Environment setup

- Installed MySQL Server on Ubuntu (`sudo apt install mysql-server`), ran
  `mysql_secure_installation`.
- Created a dedicated `mini_siem` database and a non-root app user
  (`siem_app`) scoped to that database only, not using root
  from application code.
- Set up a Python virtual environment (`venv`) to isolate project
  dependencies from system Python.
- Installed `mysql-connector-python` and `PyYAML` via `pip`, recorded in
  `requirements.txt`.
- Initialized git, set global `user.name`/`user.email`, set up `.gitignore`
  to exclude `venv/`, `__pycache__/`, `data/collector_state.json`, and
  `config.yaml` (the real one, with credentials — `config.example.yaml` is
  committed instead as a placeholder template).

## Repo skeleton

Built the directory structure separating concerns: `config/` (settings
only), `src/` (application code, further split into `db/` and
`collectors/`), `scripts/` (standalone utilities), `tests/` (sample data and
test files), `data/` (gitignored runtime state).

## `src/config.py`

Loader for `config.yaml`, using `yaml.safe_load()` (not `load()`, to avoid
executing arbitrary embedded Python objects. (security consideration in PyYAML). Includes a `resolve()` helper so paths in the
config are always relative to the repo root regardless of which directory a
script is actually run from.

**Verified**: manually loaded `config.yaml` and confirmed it printed back
correctly as a nested Python dict.

## `src/db/schema.sql`

Defined the shared `events` table — the single schema every log source
(Suricata now, `auth.log` later) normalizes into. Key design points:

- `ingested_at` vs `event_timestamp` kept as separate columns deliberately:
  they diverge if a collector is down and catches up on backlog, which is a
  useful thing to be able to show.
- `source` column is what allows one table to hold multiple log sources and
  still be queryable/correlatable as a whole.
- Most fields are nullable as not every source populates every column (a DNS
  event has no `severity`, an auth.log line may have no `dest_port`, etc).
- `raw_message` is the only field besides identifiers that's `NOT NULL` so
  the original line is always preserved, normalization bugs can be
  recoverable after the fact.
- Indexed `src_ip`, `dest_ip`, `event_timestamp`, `source`, `event_type`
  the columns known in advance to matter for filtering/grouping in
  correlation queries and reporting.

## `src/db/database.py`

Connection handling and insert logic, built around `mysql-connector-python`.

- `get_connection()` takes the `database:` block from config directly so no
  hardcoded credentials anywhere in code.
- `init_db()` reads `schema.sql` and executes each statement individually
  (MySQL's connector, unlike SQLite's `executescript()`, requires one
  statement at a time split on `;`).
- All inserts use parameterized queries (`%(field)s` style placeholders,
  values passed separately from SQL text) SQL-injection prevention, not an afterthought.

**Bug fixed**: initial `get_connection()` looked up `db_config["database"]`,
but `config.yaml`'s key is actually `name` : a plain dictionary key typo,
not an environment issue (briefly suspected the NTFS-mounted shared
partition as the cause; ruled that out once the actual `KeyError` was read
properly).

**Bug fixed**: `init_db()` originally had no protection against being run
twice: `CREATE TABLE IF NOT EXISTS` is idempotent, but the `CREATE INDEX`
statements weren't, and failed with "Duplicate key name" on a second run.
Attempted `CREATE INDEX IF NOT EXISTS` as a fix, but the installed MySQL
server version doesn't support that syntax (added in 8.0.29+), therefore reverted
schema.sql to plain `CREATE INDEX` and instead caught the specific MySQL
error code (1061, duplicate key name) in Python and ignored only that case,
re-raising anything else. More portable fix, doesn't depend on server
version.

## `src/collectors/base_collector.py`

Source agnostic file-tailing logic, designed as a base class so future
collectors (auth.log, etc.) reuse it entirely and only implement two
methods (`parse_line`, `normalize`).

Tracks: an open file handle, the file's inode (to detect rotation), the
last-read byte offset (persisted to `data/collector_state.json` so restarts
don't replay history).

**Bug fixed**: `_open_file()` originally checked `from_start` before
checking for valid saved state, meaning it reprocessed the entire file from
byte 0 on *every* run as long as `from_start: true` remained set in config,
not just the first run. Caught via a deliberate restart test (see Testing
section below) that showed row counts doubling on a second run. Fixed by
reordering the logic: valid saved state (matching inode) now always takes
priority and `from_start` only applies when there's no state to resume from.

**Bug fixed**: `utc_now_iso()` originally returned an ISO string with a
`+00:00` timezone suffix, which MySQL's `DATETIME` column type rejects
(same root cause as the eve.json timestamp bug below). Changed to return a
naive `datetime` object instead, matching the fix applied to event
timestamps.

## `src/collectors/suricata_collector.py`

Suricata-specific `parse_line` (JSON-lines parsing, one object per line,
malformed lines logged and skipped without crashing the collector) and
`normalize` (maps eve.json's native fields: `proto`, `timestamp`,
`alert.signature`, `alert.severity` onto the shared schema's column
names).

Supports filtering to specific `event_type` values via config
(`event_types: ["alert"]` by default, since eve.json emits dns/http/flow
events for everything, not just alerts).

**Verified**: ran `parse_line`/`normalize` directly against
`tests/sample_eve.json` (bypassing the DB and file-tailing loop) - 6 alert
lines correctly produced normalized dicts; 1 `dns` line correctly returned
`None` (filtered out).

**Bug fixed**: eve.json's ISO 8601 timestamps (e.g.
`2026-07-08T09:14:02.104112+1200`) were being passed straight through as
strings into a MySQL `DATETIME` column, which doesn't understand the `T`
separator or timezone offsets and rejected them outright
(`Incorrect datetime value`). Fixed by parsing with
`datetime.fromisoformat()`, converting to UTC, then stripping timezone info
(`.replace(tzinfo=None)`) before insert, since MySQL `DATETIME` is
timezone naive.

## `src/main.py`

Entry point wiring config → schema init → `SuricataCollector.run()`.
Respects a per-collector `enabled` flag from config. Must be run as
`python3 -m src.main` from the repo root (not `python3 src/main.py`
directly) thus running as a direct file path doesn't add the repo root to
Python's module search path, causing `ModuleNotFoundError: No module named
'src'`.

## Testing: offset persistence

Verified that restarting the collector does not replay already-ingested
lines:
1. Truncated the `events` table, cleared `collector_state.json`.
2. Ran the collector once against `sample_eve.json` : 6 rows inserted.
3. Ran it again without clearing state : **initially found 12 rows**
   (bug — see `from_start` ordering bug above).
4. After the fix: reran the same test, second run correctly inserted
   **zero** additional rows. Confirmed via `collector_state.json` containing
   a saved offset/inode matching the file.

## Testing: rotation handling

Verified the collector detects and correctly handles log rotation:
1. Started the collector in the background against a live-tailed file.
2. Renamed the original file (simulating logrotate) and wrote a new file
   with fresh content at the original path.
3. Confirmed the collector picked up the new file's content (the new
   alert row appeared in MySQL) rather than continuing to read the old,
   now-renamed file handle or erroring out.

---

## Bugs encountered and fixed (summary)

| # | Bug | Root cause | Fix |
| 1 | `KeyError: 'database'` | Config key was `name`, code looked up `database` | Corrected key name in `database.py` |
| 2 | VS Code "import could not be resolved" | Editor pointed at a different Python interpreter than the active venv | Set VS Code's interpreter to the venv explicitly |
| 3 | `Duplicate key name` on second `init_db()` run | `CREATE INDEX` isn't idempotent like `CREATE TABLE IF NOT EXISTS` | Catch MySQL error 1061 in Python, ignore only that case |
| 4 | `IF NOT EXISTS` on `CREATE INDEX` — syntax error | MySQL server version predates 8.0.29 | Reverted SQL, handled idempotency in Python instead |
| 5 | `ModuleNotFoundError: No module named 'src'` | Ran `main.py` as a file path instead of a module | Run via `python3 -m src.main` from repo root |
| 6 | Collector ran but inserted nothing | `from_start: false` + static sample file with no live appends meant it seeked to EOF and saw nothing | Understood as expected behavior; set `from_start: true` for static-file testing |
| 7 | `Incorrect datetime value` on insert | eve.json's ISO 8601 timestamps incompatible with MySQL `DATETIME` | Parse with `datetime.fromisoformat()`, convert to naive UTC before insert |
| 8 | Restart duplicated all 6 rows (12 total) | `from_start` was checked before saved state, so it always won | Reordered `_open_file()`: valid saved state takes priority over `from_start` |

## Current status

**Phase 1 complete.** Suricata `eve.json` → MySQL pipeline is built, tested
against restart and rotation scenarios, and committed to git. See `PLAN.md`
for what's next.
