# UI/UX Overhaul Data Contracts

## Contract rules

These P1 contracts freeze the shapes P4–P6 will implement. Examples are JSON
documents, not runtime fixtures. Unknown or malformed source data is omitted or
falls back to the conservative behaviour stated by each verdict. The collector
paths are read-only and do not send data to an LLM or another machine.

## D1 — group_key

### JSON shape

```json
{
  "session_id": "cc-a1b2c3d4",
  "launch_id": "7f12c9a8-2c1d-4b98-a1f5-91c7d52c8e10",
  "group_key": "7f12c9a8-2c1d-4b98-a1f5-91c7d52c8e10",
  "dom_id": "cc-a1b2c3d4"
}
```

### Verdict

Set `group_key` to a non-empty `launch_id` when present; otherwise set it to
`session_id`. It is only a visual grouping key for shared batch identity.
`session_id` remains the DOM identity and API/session selection identity; a
group key must never replace it. `session_id` and the `spawns.launch_id` column
already exist, so P4 only needs to carry `launch_id` into office rows.

### Sources

`monitor.py` session row creation (`session_id`), `spawns` schema and launch
handling (`launch_id`), and `collect_office` row shaping.

## D2 — mini inheritance

### JSON shape

```json
{
  "session_id": "cc-a1b2c3d4/subagent-1",
  "parent_session_id": "cc-a1b2c3d4",
  "group_key": "7f12c9a8-2c1d-4b98-a1f5-91c7d52c8e10",
  "vendor": "cc",
  "mini": true
}
```

### Verdict

A local subagent mini row carries its parent's resolved `group_key`, which
gives it the same floor token, while retaining its own vendor emblem. Remote
relay rows expose no subagent mini rows by construction, so their count is zero
rather than guessed. The mini's DOM identity remains its `session_id`; parent
grouping does not collapse distinct DOM identities.

### Sources

`monitor.py` session/subagent discovery and the existing `.mini` rendering
convention in `ui/dashboard.html`.

## D3 — work_kind

### JSON shape

```json
{
  "session_id": "cc-a1b2c3d4",
  "work_kind": "working",
  "work_detail": "code",
  "active_tail": true,
  "observed_at": "2026-07-24T09:00:00Z"
}
```

### Verdict

`work_kind` is exactly one of `working`, `standby`, or `cli_queue`; code and
docs remain internal `work_detail` labels inside the single working zone. A
local row may be `working` only when its bounded active `*_live_tail` signal
shows active work. Apply a debounce before changing a local classification to
avoid tail/mtime flicker. A remote row has no local-tail proof and therefore
falls back to `standby`, never `working`. `cli_queue` is reserved for a D5
queue row. This is best-effort display metadata, not an execution authority.

### Sources

`monitor.py` `claude_live_tail`, `codex_live_tail`, and `collect_office`.

## D4 — pool_source

### JSON shape

```json
{
  "kind": "port",
  "proc": "python.exe",
  "cmd": "monitor.py",
  "ppid": 1234,
  "pool_source": "ai_opened"
}
```

### Verdict

`pool_source` is exactly one of `system`, `ai_opened`, or `ai_scheduled`.
P4 classifies a port/process as `ai_opened` only through configured,
documented `cmd`/`proc` heuristics; it classifies rows originating from the
scheduled-task list as `ai_scheduled`; every other row is `system`. The field
is heuristic, non-authoritative display metadata and must remain configurable
alongside `process_whitelist`.

### Sources

`monitor.py` `list_services(cfg, now)`, which supplies port `proc`, `cmd`, and
`ppid` fields plus the scheduled `tasks` list and `process_whitelist` config.

## D5 — cli_bridge collector

### JSON shape

```json
{
  "now_running": [
    {
      "agent": "codex",
      "model": "local-label",
      "pid": 4321,
      "started_at": "2026-07-24T09:00:00Z",
      "job_id": "job-123"
    }
  ],
  "recent": [
    {
      "agent": "codex",
      "model": "local-label",
      "outcome": "completed",
      "outcome_reason": "exit",
      "exit_code": 0,
      "duration_s": 42.5,
      "started_at": "2026-07-24T08:58:00Z",
      "job_id": "job-122",
      "lock_wait_s": 12.4,
      "claim_wait_s": 0.0,
      "wait_s": 12.4,
      "wait_source": "measured"
    }
  ],
  "wait_s": 12.4,
  "wait_source": "measured",
  "skipped": {"scanned": 14, "oversize": 0, "unreadable": 0, "invalid": 2}
}
```

### Verdict

P4 reads every matching `dispatch*.lock.meta.json` sidecar, never the held
lock. Each `now_running` holder passes a live-PID gate; a dead, unreadable, too
large, malformed, or schema-invalid record is dropped (fail closed) — and every
such drop is **counted and published**, never silent (see `skipped` below).
Recent logs are bounded to newest-N and expose only the allowlisted fields `agent`,
`model`, `outcome`, `outcome_reason`, `exit_code`, `duration_s`, `started_at`,
`job_id`, `lock_wait_s`, and `claim_wait_s`; prompt, stdout, stderr, and all
unlisted payload fields are excluded.

`wait_s` has two provenances and `wait_source` says which, because they are not
interchangeable. When the record carries `lock_wait_s` (dispatcher mcs-103
onward) the wait is **measured**: `lock_wait_s + claim_wait_s`. Otherwise it is
**estimated** as `max(0, mtime(log) - duration_s - started_at)` — an inference
whose inputs are themselves imprecise, since `started_at` is stamped before the
dispatcher takes its locks and so already contains the wait, and the log mtime
trails the backend by the time the record took to write. Legacy records keep the
estimate rather than being dropped; the UI prefixes an estimated value with `~`.
The top-level `wait_s` is a convenience copy of the newest row and always
travels with a top-level `wait_source` (`null` when there is no recent row), so
a consumer reading only that field can still tell a measurement from a guess.
Any record whose wait is non-finite — `Infinity` / `NaN`, which are legal JSON
input but not legal JSON output — is dropped, including the case where two
finite operands sum to infinity; a single such record would otherwise make the
whole payload unparseable to a browser rather than dropping only itself.

`skipped` is always present, zeros included, so a consumer never has to tell
"nothing was dropped" apart from "this build does not count". `scanned` is how
many of the newest-N candidates the pass actually examined — it stops early once
the recent list is full, so a bare "2 skipped" would be a number no consumer
could size. `oversize` is the one remaining size rejection: a per-file sanity
ceiling of 16 MB, six times the largest record ever observed, which exists only
so a single pathological record cannot spike memory on one `json.load`.

That ceiling replaces a 128 KB cap that was **not a sample but a selection**.
Measured on the real corpus 2026-08-25 (220 records / 78.5 MB): the old cap hid
137 of them (62%), and what it hid was not random — file size here is ~97%
`stdout`, and stdout verbosity tracks which agent ran and for how long. Hidden:
codex 136, antigravity 0; duration median 194 s against 86 s for the visible
half; and all three `outcome_reason: backend_error` records, meaning this panel
had never once displayed a backend error. Nor was the cap what bounded cost —
`_CLI_LOG_CANDIDATE_CAP` is. Records are extracted through a per-file cache keyed
on `(path, mtime, size)`, which is sound because the producer writes each log
once with `O_EXCL` and never rewrites it; only the extracted scalars are
retained, never the parsed record. Measured on that corpus: 55.6 ms cold,
1.3 ms steady.

The two wait fields stay separate in the payload rather than being pre-summed:
blocked behind another dispatch and blocked on the operator's own interactive
seat are different operational problems, and one number cannot tell them apart. The collector never writes, deletes, repairs, or clears a
lock, including a stale one. The observed acquisition interval is informative
only and does not authorize a write.

### Sources

The local cli_bridge sidecar convention: `dispatch*.lock.meta.json` and bounded
recent JSON log files. P1 records this as a new P4 collector contract; no
existing collector is reused.

## D6 — Signal Desk display identity and routing provenance

### JSON shape

```json
{
  "session_id": "cc-a1b2c3d4",
  "launch_id": "7f12c9a8-2c1d-4b98-a1f5-91c7d52c8e10",
  "agent_idx": 0,
  "status": "running",
  "work_kind": "working",
  "work_reason": "active_tail"
}
```

### Verdict

`agent_idx` is the non-negative ordinal recorded by the preset-spawn row for
that exact local `session_id`. It is display provenance only: the Signal Desk
labels such a parent `A<agent_idx + 1>`. A session with no matching spawn row
must omit `agent_idx`; the UI assigns its explicitly-labelled, persisted
fallback ordinal and must not pretend it was preset-spawned.

`work_reason` is an explicit, conservative explanation of the display
classification: `active_tail` for a verified local in-flight tail,
`no_active_tail` when the bounded local check has no active tool,
`remote_no_live_tail` for the safe remote fallback, and `status_stopped` when
the retained row's status is `stopped`. It is display metadata, not an
execution authority.

Stopped rows remain in the bounded Office feed with their original
`session_id`, `group_key`, and any verified `agent_idx`; enrichment must never
drop or replace that identity. The UI routes a retained stopped parent to its
Stopped zone before interpreting `work_kind`, which allows a keyed node to move
without fabricating a new parent or child state.

Known mini rows remain children of their parent. Their `a<parent>.<child>`
display token is assigned only by the UI from the parent identity and the
bounded known-child order; the collector does not claim an independent child
work state.

### Sources

`monitor.py` preset `spawns` rows (`session_id`, `launch_id`, `agent_idx`),
the bounded local-tail classifier, and the existing Office row enrichment.
