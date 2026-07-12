# Progress Log

A running record of what's been built, in order, including the bugs hit
and fixed along the way.

---

## Environment setup

- Installed MySQL Server on Ubuntu, ran `mysql_secure_installation`, created
  a dedicated `mini_siem` database and a non-root app user (`siem_app`)
  scoped to that database only.
- Set up a Python virtual environment, `mysql-connector-python` and
  `PyYAML` recorded in `requirements.txt`.
- Initialized git, `.gitignore` excludes `venv/`, `__pycache__/`,
  `data/collector_state.json`, and the real `config.yaml` (credentials).
  `config.example.yaml` is committed instead as a placeholder template.

## Repo skeleton, `src/config.py`, `src/db/schema.sql`, `src/db/database.py`

Built the directory structure, config loader, shared `events` schema, and
MySQL connection/insert layer. See the bug table below for the issues hit
building these (key mismatch, index idempotency, MySQL version-specific
SQL syntax).

## `src/collectors/base_collector.py`, `src/collectors/suricata_collector.py`, `src/main.py`

Generic tail/rotation/offset-persistence base class, plus Suricata-specific
`parse_line`/`normalize`. Verified against `tests/sample_eve.json` in
isolation before wiring into the live pipeline.

**Bug fixed**: `KeyError: 'database'`. Config key was `name`, code looked
up `database`. Corrected in `database.py`.

**Bug fixed**: `CREATE INDEX` isn't idempotent like `CREATE TABLE IF NOT
EXISTS`, re-running `init_db()` failed with "Duplicate key name" on a
second run. Attempted `CREATE INDEX IF NOT EXISTS` but the installed MySQL
server predates 8.0.29 and doesn't support that syntax. Fixed by catching
MySQL error 1061 in Python and ignoring only that case.

**Bug fixed**: `ModuleNotFoundError: No module named 'src'`. Running
`python3 src/main.py` directly doesn't add the repo root to Python's module
search path. Fixed by always running as `python3 -m src.main`.

**Bug fixed**: eve.json's ISO 8601 timestamps
(`2026-07-08T09:14:02.104112+1200`) are incompatible with MySQL's
`DATETIME` type, which rejects the `T` separator and timezone offset
outright. Fixed by parsing with `datetime.fromisoformat()`, converting to
UTC, then stripping timezone info before insert (applied to both
`event_timestamp` and `ingested_at`).

**Bug fixed**: restarting the collector against the same file duplicated
all rows (6 became 12) instead of resuming. Root cause: `_open_file()`
checked `from_start` before checking for valid saved state, so every run
replayed from byte 0 as long as `from_start: true` stayed set in config.
Fixed by reordering the logic so valid saved state (matching inode) always
takes priority over `from_start`.

**Verified deliberately, not assumed**: restart-safety, a second run
inserts zero duplicate rows. Rotation handling, renamed the live file
mid-run (simulating logrotate), wrote a new file at the original path, and
confirmed the collector detected the inode change and picked up the new
file's content correctly.

## Suricata: real sensor deployment

Installed via the OISF PPA (`ppa:oisf/suricata-stable`) rather than
Ubuntu's default repo, for a more current, rule-syntax-compatible version
(landed on 8.0.3).

- Set `HOME_NET` to the actual local subnet and `af-packet.interface` to
  `wlp1s0` (the only real interface on this laptop, Wi-Fi, meaning the
  sensor watches this host's own traffic, matching the original
  single-host IDS scope).
- Ran `suricata-update` to pull the Emerging Threats Open ruleset
  (roughly 52,000 rules).
- Validated config with `suricata -T` before running for real: clean load,
  zero rule failures.
- Deployed as a systemd service (`systemctl enable --now suricata`) rather
  than foreground, so it persists across terminal sessions and reboots.

**Deliberate security decision**: created a dedicated unprivileged system
user/group (`suricata`), configured `run-as:` in `suricata.yaml` so the
service drops root after startup, and fixed the resulting log-directory
ownership so it runs correctly as that user instead of root.

**Bug fixed**: after setting file permissions to `640` on
`/var/log/suricata/` recursively (including the directory itself, not just
the files inside it), reads failed even for group members. Root cause:
directories need the execute bit to be traversed or entered, and `640` on
a directory removes that, independent of whether the files inside are
readable. Fixed by setting the directory itself to `750` (not recursive)
while leaving files at `640`.

**Verified**: read `eve.json` without `sudo` after the group/permission
fixes, confirmed real alerts land correctly in MySQL via the existing
collector, unmodified. For example, a real "ET INFO Spotify P2P Client"
alert from another device on the network, correctly parsed, normalized,
and queryable.

## `scripts/query_alerts.py`

CLI report script: total count, breakdown by source, severity breakdown,
top source IPs, most recent events. Needed a `sys.path` fix (same root
cause as the `python3 -m src.main` issue) since it lives outside the `src`
package.

**Verified** against real Suricata data, correct counts, correct
breakdown, matched what was actually in the database.

## `src/collectors/auth_log_collector.py`

Second collector, proving the "centralize multiple sources" design
actually works. auth.log is plaintext syslog, not JSON, so it needed regex
parsing instead of `json.loads()`.

- `parse_line`: a generic syslog envelope regex (timestamp, host, process,
  message) shared across all auth.log line types.
- `normalize`: process-specific regexes for `sshd` (failed/accepted login)
  and `sudo` (command execution), mapped onto the same shared schema
  Suricata uses.
- Syslog timestamps have no year, so the year is inferred: current year by
  default, rolling back one if the logged month is later than the current
  month (handles reading old December logs in January correctly).

**Verified**: tested `parse_line`/`normalize` directly against
`tests/sample_auth.log` (2 failed logins, 1 accepted login, 1 sudo
command, 1 line that should match neither pattern) before touching the
live pipeline. All 4 came out normalized correctly, and the 5th correctly
returned `None`.

**Bug fixed**: `KeyError: b'dest_ip'` on insert. `INSERT_EVENT_SQL`
requires every placeholder to exist as a dict key, but
`AuthLogCollector.normalize()` only populated fields relevant to SSH/sudo
events (no `dest_ip`/`dest_port`/`protocol`). Suricata's normalize
happened to always set every key since eve.json always has them available,
auth.log doesn't. Fixed at the right layer: `base_collector.py`'s
`_handle_line()` now fills in every schema column with `None` as a
default, via a shared `EVENT_FIELDS` list, before any insert. A source's
`normalize()` only needs to return what it actually knows, instead of
padding out the rest.

**Bug fixed**: `config.yaml`'s `auth_log:` block was indented at the same
level as keys inside `suricata:`, making it a nested key of `suricata`
instead of a sibling under `collectors:`. YAML structure is purely
indentation-driven, so the file looked plausible at a glance, but
`config["collectors"]["auth_log"]` genuinely didn't exist. Caught by
printing the parsed config structure directly instead of trusting a
visual read of the file.

**False lead investigated**: briefly suspected a leftover Suricata process
was still writing duplicate rows after a truncate. `ps aux` ruled that
out. Turned out to be the YAML indentation bug above (the auth_log
collector was never actually running), combined with stale data from an
earlier session's Suricata run that hadn't been re-truncated at that exact
point.

## Multi-collector threading

`main.py` originally only ran a single collector, blocking forever, with
no way to run Suricata and auth_log at the same time.

Redesigned around `threading`:
- Each `BaseCollector.run()` loop now checks a `threading.Event`
  (`self._stop_event`) instead of relying on `KeyboardInterrupt`, since
  `Ctrl+C` only interrupts the main thread. A background thread waiting on
  `KeyboardInterrupt` never actually receives it and would run forever.
- `main.py` builds one collector instance per enabled source, starts each
  in its own thread, and on `Ctrl+C` calls `.stop()` on every collector
  (setting each one's stop event) before joining all threads to confirm
  they've actually exited.
- The shared `collector_state.json` file needed a lock
  (`threading.Lock()`) around its read-modify-write, since two threads can
  now save offsets around the same time. Without it, one thread's write
  could race with and clobber another's.

**Bug fixed**: `base_collector.py` briefly had two `run()` methods defined
in the same class, the old `KeyboardInterrupt`-based version left in place
below the new `threading.Event`-based one. Python silently lets the second
definition overwrite the first with no error, so the new, correct loop was
dead code. The class was still actually running the old loop, meaning
`.stop()` had no effect and threads would never exit cleanly. Caught by
review before testing, not by a failure at runtime.

**Verified**: ran both collectors simultaneously against
`tests/sample_eve.json` and `tests/sample_auth.log`, confirmed both
"Started ... collector." lines printed, `Ctrl+C` produced "Stopping all
collectors..." followed by "All collectors stopped cleanly.", and `ps aux`
confirmed zero orphaned processes afterward. `query_alerts.py` showed 10
combined events (6 Suricata, 4 auth_log) in one report, the first proof
the shared-schema design works across genuinely different source formats
(JSON vs. plaintext syslog).

## auth_log: real data

Installed OpenSSH server (`openssh-server`), confirmed it starts correctly
via socket activation (`ssh.socket` triggers `ssh.service` on demand,
standard modern systemd behavior). Confirmed `/var/log/auth.log` is
written by traditional rsyslog, not journald-only, so no additional
logging pipeline changes were needed. Added own user to the `adm` group
(owner of the log file) to read it without `sudo`. Generated real
"Accepted password" and "Failed password" events via `ssh $USER@localhost`
to confirm real OpenSSH log line wording matches the regex patterns built
against hand-written sample data.

---

## Bugs encountered and fixed (full list)

| # | Bug | Root cause | Fix |
|---|---|---|---|
| 1 | `KeyError: 'database'` | Config key was `name`, code looked up `database` | Corrected key name |
| 2 | VS Code "import could not be resolved" | Editor's interpreter setting didn't match the active venv | Set VS Code interpreter to the venv explicitly |
| 3 | `Duplicate key name` on second `init_db()` run | `CREATE INDEX` isn't idempotent | Catch MySQL error 1061 in Python |
| 4 | `IF NOT EXISTS` on `CREATE INDEX`, syntax error | MySQL server predates 8.0.29 | Reverted SQL, handled idempotency in Python |
| 5 | `ModuleNotFoundError: No module named 'src'` | Ran `main.py` as a file path, not a module | Run via `python3 -m src.main` |
| 6 | Collector inserted nothing | `from_start: false` plus a static file with no new appends | Expected behavior, set `from_start: true` for static-file testing |
| 7 | `Incorrect datetime value` on insert | ISO 8601 timestamps incompatible with MySQL `DATETIME` | Parse and convert to naive UTC before insert |
| 8 | Restart duplicated all rows | `from_start` checked before saved state | Reordered `_open_file()` priority |
| 9 | Second `venv` accidentally created inside project dir | Ran `python3 -m venv venv` from project root without realizing an original venv already existed elsewhere | Consolidated to one project-local venv |
| 10 | `/var/log/suricata` unreadable despite `640` group permissions | Directory execute bit removed by recursive `chmod -R 640` | Set directory to `750` (not recursive), files stay `640` |
| 11 | `KeyError: b'dest_ip'` on auth_log insert | `normalize()` only populated fields relevant to that event type, insert SQL expects every column | `_handle_line()` now defaults every schema field via `EVENT_FIELDS` before insert |
| 12 | `auth_log` collector silently never ran | `config.yaml` indentation nested `auth_log:` inside `suricata:` instead of as a sibling | Fixed YAML indentation, verified by printing parsed config structure |
| 13 | Threaded collectors never stopped on `Ctrl+C` | Duplicate `run()` method definition silently shadowed the new `threading.Event`-based loop with the old `KeyboardInterrupt`-based one | Removed the stale duplicate method |

## Current status

Phase 1 complete. Phase 2 nearly complete: Suricata deployed live,
`auth_log` collector built and verified against real SSH/sudo events,
`query_alerts.py` working, both collectors running concurrently via
threading with verified clean shutdown. No remaining Phase 2 items. See
`PLAN.md` for Phase 3.