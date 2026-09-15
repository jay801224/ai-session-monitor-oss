# ai-session-monitor

A local, read-only dashboard for the AI coding sessions running on your own
machine — Claude Code, Codex, Copilot, and other CLI agents — in one place.

## What problem it solves

If you run more than one AI coding CLI, or several sessions at once, or the same
tool across two machines, you lose the thread: which sessions are still working,
which one is **waiting for you** to answer a prompt, which quietly stopped, how
much context each has burned, and how many tokens the day cost. This dashboard
reads the transcript files those tools already write to disk and shows all of it
on one page at `http://127.0.0.1:8787`. It never calls a model and never leaves
your machine.

## What you see

The dashboard has several views, switched from the top bar:

- **📋 List** — every session across all your CLIs, each row showing its state
  (running / idle / **waiting for you** / stopped), the model, context-window
  usage, current task, and how long it has been going.
- **🔍 Deep view** — drill into one session: its live transcript tail, its
  subagent tree, and its running token/cost burn.
- **🏢 Office** — a walking-figures view (Gather-style): every session is a
  little figure standing in the zone it is doing right now — coding, docs,
  testing, review, CLI, standby, offline. A corner of the room shows your own
  open GitHub pull requests, one figure each, colour-coded by merge state.
- **📊 Recap** — token, cost, and active-time statistics as bar charts: per
  project, per model, and per day. Answers "what did this week actually cost".
- **🔌 Services** — the local ports and processes on the machine, with a
  whitelist so the usual suspects don't look alarming.
- **🪝 Hook audit** — an inventory of your Claude Code hooks across your repos,
  charted over time, with a "deployed vs source" custody check.
- **🔑 Authz** — pending one-shot permission grants, if you drive sessions that
  ask for them.
- **🗑 Deletions** — a recent window of file-delete events surfaced from the
  session logs.

## Principles

- **Read-only.** It watches transcript files; it never writes to them.
- **Zero LLM calls.** The dashboard never sends anything to a model. A test in
  the suite fails the build if an API call appears in the source.
- **Local only.** Pure Python standard library, binds `127.0.0.1`, nothing
  leaves the machine. The one outbound request is an optional read of *your own*
  open pull requests through *your own* `gh auth` — no token is stored in or read
  by this repo.
- **Yours, not anyone else's.** Every path and account is configuration. The
  suite strips all of it and asserts the dashboard still runs
  (`tools/depersonalise.py --serve`), so a fresh clone starts blank and fills up
  with *your* data, never a copy of someone else's setup.

> The built-in UI labels are in Traditional Chinese (the icons above map to the
> real tab names). Everything else — config keys, code, tests — is in English.

## Quick start

Requires **Python 3.10+**. No third-party packages.

1. Point `claude_projects` at your Claude Code transcript root — the
   `.claude/projects` folder inside your home directory, scanned as
   `<root>/*/*.jsonl`. Put it in a **`config.local.json`** next to `config.json`
   (same keys, merged over `config.json`, and git-ignored so your paths never
   land in a tracked file):

   ```json
   { "claude_projects": ["C:/Users/<you>/.claude/projects"] }
   ```

   (macOS/Linux: `/Users/<you>/.claude/projects` or `/home/<you>/.claude/projects`.)

2. Run it:

   ```
   python monitor.py
   ```

3. Open <http://127.0.0.1:8787>.

Every other feature stays quietly empty until its key is set — the dashboard
prints "not configured" rather than drawing a fake zero. `PORT=8790 python
monitor.py` serves on another port.

## Optional features

Each is off until you configure its key; unset = that surface says "not
configured" and nothing else changes.

| Key(s) | What it turns on |
|---|---|
| `codex_session_index`, `hermes_state_db`, `copilot_session_db` / `copilot_state_dir`, `antigravity_main_log` | one extra column per additional CLI you use |
| `workspace_roots` | the folders your projects live under — scopes the hook audit + deletion monitoring, shortens project labels, and is the **spawn allowlist** (opening a new session refuses everything until this is set) |
| `hooks_source_repo` | the 🪝 hook custody audit, comparing your deployed hooks against their source repo |
| `office_secret`, `office_ntfy_topic` (put in `config.local.json`) | cross-machine relay — run `office_push.py` on another machine and this dashboard pulls its sessions in, pseudonymised |
| `kb_dir`, `handoff_dir`, `showcase`, `presets`, `machines` / `local_machine` | knowledge-base card, handoff board, showcase-deploy button, one-click batch launch, per-machine badges |

### The PR zone

The office's PR corner lists **your** open pull requests, one figure each. It
runs `gh api graphql` with `author:@me`, which resolves to whoever `gh auth
login` says you are — so a fresh clone on another account just shows that
account's PRs with no config edit. No GitHub token is stored, read, or proxied by
this repo; `gh` holds the credential. `github_pr.scope` picks `all` / `public` /
`private`.

### Idle / waiting notifications

Wire `notify_hook.py` into your own Claude Code `settings.json` to flip a row to
"waiting" the instant Claude asks for input:

```json
"hooks": { "Notification": [ { "matcher": "idle_prompt",
  "hooks": [ { "type": "command",
    "command": "python <path-to-this-repo>/notify_hook.py" } ] } ] }
```

The hook writes a small marker file next to the transcript; the dashboard only
reads it. No hook wired, no problem — the dashboard works without it.

## Avatars

The 🏢 office draws one figure per session, generated in the page itself: 26
data-URI SVG silhouettes, one hue each, **zero image files in the repo**.
Assignment is a stable hash of the session id, so a session keeps its figure
across reloads and two live sessions never share one.

Want real artwork instead? Drop your own PNGs into `ui/assets/avatars/` and point
the `CREATURES` registry at them (near the top of `ui/office_proto.html`; keep 26
`{key, img}` entries). Whatever images you choose, their licensing is your call —
this project ships none. The Signal Desk view's operator figure
(`ui/assets/signal-desk/operator-head-v1.png`) is an original drawing; replace
the file to reskin it.

## Tests

```
python tools/preflight_ui.py           # full suite (64 checks, 0 = green)
python tools/depersonalise.py --serve  # the dashboard as a stranger would see it
python tools/depersonalise.py --list   # what counts as personal, and where
```

## Deliberately absent

- **Any session data.** No transcripts, no runtime state, no filled-in config —
  the repo starts blank and is filled by *your* machine at runtime.
- **Third-party artwork.** The office draws its own figures rather than shipping
  image files (see Avatars for using your own).
- **Login / scraping automation.** Unrelated site-login helpers from the private
  tree are out of scope and out of the repo.
- **Cross-platform session spawning.** `tools/*.ps1` (open / close / hand off
  sessions from the dashboard) are Windows Terminal + PowerShell 5.1 only; the
  monitoring itself is OS-neutral. Spawning is allowlisted by `workspace_roots`
  at both the Python and the script layer, and refuses everything when unset.

## How this repo was built

It was ported from a private working copy as a **fresh history**, not a scrubbed
clone, so no commit carries anyone's paths. [`PLAN.md`](PLAN.md) is that port
plan — what ships, what was deliberately left out, and how each piece was proven.
