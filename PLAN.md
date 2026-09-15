# Port plan — ai-session-monitor → public release

This repo is empty on purpose. It exists so the port can be done as a **fresh
history**, not a scrub of an existing one: the private repo's `config.json` is
tracked, so every past commit of it carries the owner's paths. Copying files
forward and committing them here is the only way that ends up genuinely clean.

Written 2026-08-06 by the session that prepared it. **The next session executes
this plan; the owner accepts it afterwards.**

---

## Preconditions (前置條件)

- Source repo at `../ai-session-monitor`, `master` at `1ea09b9` or later.
- `python tools/preflight_ui.py` in the source repo is green (64 checks 0 FAIL).
- `gh auth` logged in; this repo created public as `<owner>/ai-session-monitor-oss`.

## Known (已知條件, all verified — not assumed)

- **`config.json` is tracked** in the source repo. 16 keys name the owner's
  machine or account; `tools/depersonalise.py --list` prints them and what they
  hold. `--emit <path>` writes the stripped version this repo should ship.
- **The tool already survives having them removed.** Both strip styles (blank the
  value / delete the line) were exercised against every read-only collector, and
  a stripped config served on a spare port returned 200 on `/api/status`,
  `/office2`, `/hooks`, `/api/prs` and `/`, drew all nine office zones, and
  showed zero console errors. The gate `check-config-depersonalised` keeps it
  that way.
- **`author:@me` needs no editing.** The PR zone resolves it to whoever `gh auth`
  is logged in as, so a reader sees their own pull requests.
- **Secrets never entered the tracked config.** They live in `config.local.json`,
  which is gitignored. The GitHub PR zone uses `gh auth` and holds no token.
- **`ui/assets/avatars/` is 26 official Pokémon PNGs, 5.5 MB.** Fine on the
  owner's own machine, not shippable. This is the one asset blocker and §2 is
  entirely about it.

## Unknown / would invalidate this plan if wrong (未知條件)

- Whether any file outside `config.json` still names the owner in prose rather
  than in a path. `depersonalise.py` scans for absolute paths, which is the
  mechanical majority — it cannot catch a label. §5 covers this by reading the
  page, which is how a machine label naming the packager's home was found in the
  first place.
- Whether a reader's Claude Code layout matches this one. Everything is derived
  from `~/.claude/projects`, but only Windows and a mounted mac root have ever
  been exercised.

---

## Decisions already made (do not re-litigate)

| Question | Decision |
|---|---|
| Repo name | `ai-session-monitor-oss` |
| Avatars | **Ship no images.** Geometry drawn in the page; README says plainly that a reader can drop their own images in. |
| `web_run.py`, `captcha_guard.py` | **Not included.** They automate site logins, are unrelated to the dashboard, and read as a scraping tool out of context. |
| History | Fresh. Never `git clone`/fork the private repo. |

---

## §0 — How to work: one piece at a time, connected back

Do **not** copy everything and then test. Take one row of the §1 table, bring it
across, make it run, and only then take the next. When something fails you want
the suspect to be one file, not a batch.

Each piece is proved twice, and the two tests cannot be run at the same time
**by design** — `depersonalise.py --serve` refuses to start if a
`config.local.json` is present, so neither result can quietly borrow the other's
configuration.

**Test A — a stranger's clone.** `python tools/depersonalise.py --serve`. Every
personal value removed. Proves the piece does not depend on the packager's setup.
Empty panels are the correct outcome here; a crash or a blank page is not.

**Test B — connected to real data.** In this repo, create `config.local.json`
pointing at the real transcript roots. `load_config()` merges it over
`config.json`, and `*.local.json` is gitignored, so the owner's paths make the
code run without ever entering a tracked file. Proves the piece actually works
against real sessions.

That pairing is what makes "the owner's data never ships" and "we know it works
on the owner's data" both true at once. **Never copy session data, transcripts,
`_state/`, or a filled-in `config.json` into this repo — point at them instead.**

### When acceptance finds a piece that will not connect

Diagnose which of the two it is before changing anything:

- **The handoff list was wrong** — the piece needs a file, a config key or a
  helper that §1 did not name. Symptom: it fails in Test B *and* would have
  failed on the source machine too. Fix: add the missing dependency to §1 and
  note what was missed, so the omission is visible rather than patched over.
- **The data side does not support it** — the code is complete but there is no
  signal for it on a fresh machine (no Codex index, no hooks source repo, no
  second machine relaying). Symptom: it fails in Test A, works in Test B. Fix:
  the surface must say it is unconfigured, never draw a fake zero. This project
  already refuses to draw a zone it cannot source; hold to that.

## §1 — Files that ship

Take them in this order — each row runs on its own once the rows above it are in
place. "Needs" is what has to be configured before the piece shows anything; a
row that fails Test B with its needs met is a §0 handoff-list problem.

| # | Bring across | Serves | Needs (config) |
|---|---|---|---|
| 1 | `monitor.py`, `ui/dashboard.html`, `.gitignore`, `config.json` | the server and 📋 列表 | `claude_projects` |
| 2 | `recap.py` | 📊 回顧 (token / time stats) | nothing beyond row 1 |
| 3 | `ui/session.html` | 🔍 深視圖 drill-down | nothing beyond row 1 |
| 4 | `ui/office_proto.html` **+ §2 avatars** | 🏢 辦公室, incl. the PR zone | `github_pr.scope`, `gh auth login` |
| 5 | `office.py`, `office_push.py` | cross-machine relay | `office_secret`, `office_ntfy_topic` (both local-only) |
| 6 | `hooks_audit.py`, `ui/hooks.html` | 🪝 Hook 稽核 | `hooks_source_repo`, `workspace_roots` |
| 7 | `ui/authz.html`, `command.py`, `command_drop.py` | 🔑 授權中心, command channel | `workspace_roots` |
| 8 | `notify_hook.py` | idle / permission notifications | hook wired in the reader's own settings.json |
| 9 | `tools/preflight_ui.py`, `tools/depersonalise.py`, `tools/office2_zone_liveness.py`, `tools/ui_browser_smoke.py` | the test suite and the pre-publication check | — |
| 10 | `tools/*.ps1` | spawning sessions | `workspace_roots` — **see §4 first** |

Row 9 can be pulled earlier if it helps: `preflight_ui.py` is what tells you a
row landed correctly, and several of its checks read `monitor.py` and the HTML
directly. It is listed late only because it is not needed to see a page.

> **§0 finding, 2026-08-06 (execution session): the row-1 list was incomplete.**
> `monitor.py` imports `recap`, `hooks_audit`, `office`, `command` and
> `command_drop` at module level (lines 26–30) and reads all five `ui/*.html`
> templates at import time (`_read_asset`), so row 1 as written cannot start —
> it would have failed the same way on the source machine with only those four
> files present. Fix taken: the startup closure (those 5 modules + 5 templates)
> came across **in row 1**; rows 2–7 keep their place in the table but are
> *proven* in their turn rather than *copied* in their turn. `office_push.py`
> (row 5), `notify_hook.py` (row 8) and the tools are genuinely standalone and
> arrive in their own rows. `tools/depersonalise.py` + `tools/preflight_ui.py`
> were pulled early as this paragraph allows.

Row 10 is last on purpose. It is the only row with a known defect for a reader.

Do **not** copy: `web_run.py`, `captcha_guard.py`, `ui/assets/avatars/*`,
`ui/_avatar_swatch.html`, `ui/_pixel_test.html`, `_handoff/`, `report/`,
`docs/` (owner's working notes), the **filled-in** `config.json`, anything under
`_state/`, and any session transcript. The owner's data is *pointed at* from a
gitignored `config.local.json` (§0 Test B), never carried over.

- **verify**: `git status` shows no file matching `config.local.json`, `_state/`,
  `*.png` under `ui/assets/`.

## §2 — Avatars: replace, do not omit

The office view is the reason to look at this project, so it cannot ship as empty
boxes. Replace the artwork, keep every behaviour.

`CREATURES` is `[{key, img}, …]` and `personEl` renders
`<img class="cre-img" src="${cre.img}" alt="${cre.key}">`. Everything else —
the stopped-state grayscale filter, the flip on direction change, the hop and
breathe animations, the hash-to-creature assignment, the subagent inheritance —
targets `.cre-img`. So:

- Keep `CREATURES` the same length (26) and the same `{key, img}` shape.
- Make each `img` a **data-URI SVG** built into the page: a simple silhouette
  (rounded body + head) filled from a per-key hue. 26 distinct hues at even
  spacing are visually separable and cost zero bytes on disk.
- Do not change `personEl`, the CSS, or the hash assignment. If a change there
  seems necessary, the replacement is the wrong shape.

- **verify**: `python tools/preflight_ui.py` green — `check-avatar-identity`
  already asserts the single-registry and stable-assignment properties, and it
  must pass without being edited.
- **verify**: office page renders 26 visually distinct figures; two different
  sessions never share one (that check already exists).

> **§0 findings, 2026-08-06 (execution session): two dependencies this section
> did not name.**
> 1. The Signal Desk view (`ui/dashboard.html`) has its own figure image,
>    `ui/assets/signal-desk/operator-head-v1.png` (2 MB in the source repo,
>    origin/licence unrecorded) — and `check-avatar-identity`'s inert fixture
>    freezes that exact path inside the rendered `<img class="desk-head">`, so
>    neither dropping the file nor renaming it passes unedited. Fix taken: an
>    **original** 1.3 KB head-and-shoulders figure (drawn by a stdlib script,
>    no third-party art) ships at the same path. Same "replace, do not omit"
>    treatment as the office sprites; the check still passes untouched.
> 2. `tools/preflight_ui.py` reads `docs/uiux-overhaul-design-system.md` as the
>    colour-token registry (`check-avatar-identity`, `check-color-tokens` FAIL
>    without it), so that one file ships despite the "no `docs/`" rule. Read in
>    full before copying: it is the frozen design contract, nothing personal.

## §3 — Config the reader fills in

Generate, do not hand-write:

```
python ../ai-session-monitor/tools/depersonalise.py --emit config.json
```

Then, in this repo's `config.json`, every key the reader must set gets a value
that is obviously a placeholder, never a working path from another machine.
Required vs optional, as measured:

- **Required**: `claude_projects` — the transcript root(s). Everything else is a
  feature that stays empty until configured. Note it is a **root**, scanned as
  `root/*/*.jsonl`; there is no per-project list to curate.
- **Per-feature**: `codex_session_index`, `hermes_state_db`, `copilot_session_db`,
  `copilot_state_dir`, `antigravity_main_log` (one per CLI);
  `workspace_roots` (spawning, deletion monitoring, hook audit scope);
  `hooks_source_repo`; `kb_dir`; `handoff_dir`; `showcase`; `presets`;
  `machines` / `local_machine`.
- **Leave alone**: `github_pr.scope` (`all` / `public` / `private`) already
  defaults sensibly and `author:@me` needs no edit.

- **verify**: `python tools/depersonalise.py --list` in THIS repo reports no
  absolute path in the config and none in the shipped source.
- **verify**: `python tools/preflight_ui.py check-config-depersonalised` green.

## §4 — The one thing that is actually broken for a reader

`tools/new_session.ps1` hardcodes `$ROOT` to the packager's own absolute disk
path. It is the outer half of the spawn allowlist (the Python half already reads
`workspace_roots` and refuses everything when unset). A reader on any other path
gets refused by the script, so "open a new session" does not work for them.

Fix it to take the allowed root from its caller, and keep it **failing closed**:
no root passed ⇒ refuse, never "allow anything".

- **verify**: this one cannot be verified by reading. Launch a real session from
  the dashboard on a machine whose root is not the packager's, watch a terminal
  actually open, then confirm a path outside the root is refused.
- If that cannot be arranged, ship with the spawn feature **documented as
  Windows-and-one-root only** rather than shipping an unverified security gate.

> **Done and verified, 2026-08-06 (execution session).** The root now arrives as
> a `;`-joined positional arg (monitor.py sends its `workspace_roots`), placed
> **before** the optional prompt — `wt` re-parses the command line and may drop
> empty `""` args, and a required arg must never sit behind one that is
> legitimately empty (found live: the empty prompt slot shifted the root into
> the mode position). Verified for real, all three legs: (1) dashboard with
> `workspace_roots` set to a throwaway test root (outside the packager's usual
> disk) spawned a session and the terminal opened — screen capture showed
> `Starting Claude (mode=default) in <that-root>\demo name='CC-...'`; (2)
> `C:\Windows` refused
> at BOTH layers (script alone, and the API); (3) no root passed ⇒ the script
> refuses everything, and the stranger's dashboard answers "no workspace_roots
> configured — every spawn refused". Shipped ps1 set = the seven monitor.py or
> a shipped script actually calls (new_session, close_session, connect_rc,
> handoff_inject, handoff_run, list_cc_sessions, mode_switch);
> `find_cc_by_cwd.ps1` (called by nothing) and the `_*.ps1` dev probes stay
> behind — an omission stated here, not a quiet drop.

## §5 — Read the page, not just the code

The scan finds absolute paths. It does not find a label. `DEFAULT_MACHINES` once
carried a machine label naming the packager's own home — not a path, so it
survived a clean path scan; it was only caught by serving a stripped config and
looking.

- Run `python tools/depersonalise.py --serve` and open every surface: the six
  dashboard tabs, `/office2`, `/hooks`, `/authz`.
- **verify**: nothing on any page names a person, a home, a company, a repo or a
  path belonging to the packager.
- **verify**: every page has content and no horizontal overflow.

## §6 — README

Must state, in the reader's terms:

1. What it is: a local read-only dashboard for AI coding sessions. Zero LLM
   calls, stdlib only, binds `127.0.0.1`, nothing leaves the machine.
2. Quick start: set `claude_projects`, run `python monitor.py`, open
   `http://127.0.0.1:8787`.
3. **Avatars**: the office view ships with drawn figures and no image files.
   Say plainly that a reader can drop their own PNGs into `ui/assets/avatars/`
   and point `CREATURES` at them — and that whatever they choose is their
   licensing call, not this project's.
4. The PR zone needs `gh auth login`; it holds no token and reads only the
   reader's own pull requests.
5. What is deliberately absent, and why.

---

## Acceptance (what the owner will check)

1. `python tools/preflight_ui.py` in **this** repo: 0 FAIL.
2. `python tools/depersonalise.py --list`: no absolute path in config or source.
3. A clean clone into an empty directory, `claude_projects` set, `python
   monitor.py` — the dashboard shows that machine's own sessions.
4. Every page has content and does not break layout.
5. No image file under `ui/assets/avatars/`.
6. `git log` shows this repo's own history only — no commit inherited from the
   private repo.
7. Every row of the §1 table passed **both** §0 tests, and any row that did not
   is written down with which of the two failure kinds it was. A row quietly
   dropped from the table is the one outcome that fails acceptance outright:
   the list being wrong is fine and expected, the list being edited to hide a
   gap is not.

---

## §7 — Re-syncing after the first port (read this before touching anything)

Everything above is the **first** port, and it is done. This section is the
standard for every port after it. If you are here because "the private repo moved
forward and the public one should catch up", you are in §7 and **you do not need
a new plan**. Follow this; do not re-derive it, and do not re-open anything under
"Decisions already made".

**The one fact that makes a bulk copy wrong.** This repo is not a subset of the
private one. It has diverged in two directions that must never be overwritten:

1. **Depersonalisation edits** — e.g. `hooks_audit.py` says "the source repo"
   where private says the private repo's actual name, and names no real
   worktrees; `command.py` / `command_drop.py` use `/Users/x/projects/demo`
   where private uses a real path.
2. **Fixes that exist only here** — e.g. the fresh-clone guard in
   `hooks_audit.py` (`if not source_repo: raise RuntimeError(...)`), which the
   private repo does not have. Copying private over it is a silent regression.

So: a file is never copied whole. Each differing hunk is classified first.

**Method.** The two histories are disjoint on purpose (Acceptance #6), so there
is no merge base and `git merge` is not available. Diff textually, per file, and
put every hunk in exactly one bucket:

| Bucket | What it looks like | Action |
|---|---|---|
| **A — new capability** | private has code this repo lacks | port it, then depersonalise it as if it were arriving in the first port |
| **B — depersonalisation** | the two differ only in a name, path, repo or label | **keep this repo's side**, unchanged |
| **C — public-only fix** | this repo has code private lacks | **keep this repo's side**; consider opening the same fix upstream |

A hunk you cannot classify is bucket A until proven otherwise — treat it as
carrying personal data.

**Gates — the same ones, not new ones.** §0 Test A and Test B (still mutually
exclusive by design), the §1 do-not-copy list, §3 `--emit` / `--list`, §5 read
the page. Nothing here replaces them.

**Pin the baseline.** The reason a re-sync is expensive is that nobody wrote down
where the last one stopped. Every re-sync ends by recording the private commit it
took from, so the next one diffs from there instead of from nothing:

| Synced on | Private repo at | Scope |
|---|---|---|
| 2026-08-06 | `1ea09b9` or later (§Preconditions) | first port, §1 rows 1–10 |
| 2026-09-15 | `afacd7e` (private local `master`) | codex/workflow dispatch integration (monitor.py `_codex_*`/`_bridge_*` defs + `collect_codex_bridge`/`collect_codex_pr_provenance`/`codex_poll_loop`/`handoff_recipient`; routes `/workflows`, `/api/ops/workflow`, `/api/workflows{,/auth,/capabilities,/catalog,/events,/hosts,/models}`, `/api/codex-pr-provenance`; `workflow_client.py` + 5 dispatch/config tools + `ui/workflows.{html,css,js}`), cp950 module-level stdout fix, per-session recap (`_rel_parts`/`_session_of`, TTL pricing), new `tests/` dir + config templates. `_EXEC_REPO` hardcoded-root regex → `_codex_exec_repo(cfg)` from `workspace_roots`; recap strip list → `_HOME_SLUG`. Excluded per Decisions: `captcha_guard.py`, `web_run.py`, `_*.ps1` probes, `find_cc_by_cwd.ps1`. |
| _(next)_ | _(record the SHA here)_ | _(what moved)_ |

**Acceptance for a re-sync** = the list above, with #6 and #7 replaced by:

6. `python tools/preflight_ui.py` still reports **0 FAIL and no fewer checks
   than before** the sync (baseline now 67 checks after the 2026-09-15 sync — was
   64 at first port; the sync added `check-costaxis` and the measured-wait D5 walk).
7. No bucket-B or bucket-C line was lost. Grep the known ones back: the
   `hooks_source_repo` guard is present, no shipped file names the private
   source repo, and `depersonalise.py --list` reports no owner path.
8. The baseline table above has a new row.
