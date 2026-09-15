"""History-recap aggregation for ai-session-monitor.

Token / cost / time-distribution over a date window, read straight from
~/.claude/projects/**/*.jsonl. Pure Python standard library, zero LLM calls,
read-only — same discipline as monitor.py.

WHY reimplemented (not imported): the equivalent logic already exists in a
separate internal usage_recap package, and importing it WORKS. But that package
pulls in `rich` (via its __init__ -> report.py) and would force this repo to
hardcode an absolute cross-repo sys.path. monitor.py's README commits to
"no dependencies — Python 3 standard library only" and a deliberately
zero-coupling separate repo. So the token/cost algorithm here is a verbatim
re-implementation of usage_recap/token_usage.py (prices, dedup, field names),
and the active-time heuristic mirrors usage_recap/time_tracking.py. Same
algorithm + same window => the totals match `recap.py week` from that skill,
which is the correctness baseline.

The price table is a snapshot (2026-01, Anthropic API list price, USD/1M
tokens); a model with no entry (e.g. fable) contributes $0, exactly as
upstream does.
"""
from __future__ import annotations

import glob
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

# Read the SAME source as the weekly-recap baseline (~/.claude/projects), so the
# acceptance comparison against `recap.py week` is apples-to-apples. Derived
# from the home dir, not a hardcoded absolute path.
PROJECTS_DIR = os.path.join(os.path.expanduser("~"), ".claude", "projects")

# Anthropic API list prices, USD per 1M tokens. Ported from
# usage_recap/token_usage.py (DEFAULT_PRICES, snapshot 2026-01). Substring
# match on the model id: "opus" / "sonnet" / "haiku".
#
# Cache WRITES are priced by TTL, not by one flat rate:
#   5-minute TTL -> 1.25x base input   (`cw`)
#   1-hour   TTL -> 2.00x base input   (`cw1h`)
# `cw` was the only rate here until 2026-08-23 and carried the 5-minute price,
# while this fleet writes overwhelmingly at the 1-hour TTL -- measured 84.7% of
# cache-write tokens over 14 days -- so every cost this file printed was low.
# Which TTL a turn used is in usage.cache_creation.ephemeral_{1h,5m}_input_tokens;
# nothing here read that sub-object before. KB ticket: asm-008.
PRICES_SNAPSHOT = "2026-01"
PRICES = {
    "opus":   dict(inp=15.00, out=75.00, cw=18.75, cw1h=30.00, cr=1.50),
    "sonnet": dict(inp=3.00,  out=15.00, cw=3.75,  cw1h=6.00,  cr=0.30),
    "haiku":  dict(inp=0.80,  out=4.00,  cw=1.00,  cw1h=1.60,  cr=0.08),
}

GAP_CAP_SEC = 5 * 60  # gap longer than this between messages => "stepped away"

# Windows this panel offers. Keys are the API contract with the front-end.
WINDOWS = ("today", "3d", "7d")


def _price_for(model):
    m = (model or "").lower()
    for key, p in PRICES.items():
        if key in m:
            return p
    return None


def _local_midnight(dt):
    """Local-midnight of dt's date, tz-aware (matches recap.py's window math)."""
    return dt.astimezone().replace(hour=0, minute=0, second=0, microsecond=0)


def resolve_window(window):
    """Return (since, until, label) for a window key.

    Bounds are tz-aware local datetimes; the date range is always computed
    from `now`, never hardcoded. Unknown keys fall back to the 7-day window.
    `7d` deliberately mirrors recap.py's `week`: local-midnight 7 days ago -> now.
    """
    now = datetime.now(timezone.utc).astimezone()
    if window == "today":
        return _local_midnight(now), now, "今天"
    if window == "3d":
        return _local_midnight(now - timedelta(days=3)), now, "過去 3 天"
    return _local_midnight(now - timedelta(days=7)), now, "過去 7 天"


def _parse_ts(raw):
    """Parse an ISO-8601 timestamp to a tz-aware datetime, tolerant of junk."""
    if not raw or not isinstance(raw, str):
        return None
    try:
        t = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return t


_MAC_HOME_RE = re.compile(r"^-Users-[^-]+-")  # mac slug "-Users-<user>-<proj>"
# The running user's home folded to slug form (Claude Code names a project dir by
# replacing every non-alphanumeric byte in the cwd with '-'). Derived from this
# machine's home so the prefix strip works for whoever runs it, not a baked-in path.
_HOME_SLUG = re.sub(r"[^A-Za-z0-9]", "-", os.path.expanduser("~"))


# How many sessions the per_session breakdown returns. The full count travels
# alongside as `per_session_total`, so a truncated list never reads as the
# whole set.
PER_SESSION_TOP_N = 12


def _rel_parts(fp, root):
    """Path segments of `fp` relative to the scanned `root`, or None if `fp` is
    not under it.

    Containment is decided on realpath+normcase (symlinked roots, and Windows
    case-insensitivity, both otherwise read as "not under the root"), but the
    RETURNED segments come from the un-normcased path -- normcase lower-cases on
    Windows and these segments are the displayed project name. Rejection is on a
    leading `..` SEGMENT, not on the string starting with ".." -- a project
    legitimately named `..foo` must not be thrown away. Different drives raise
    from commonpath and mean "not under it"."""
    if not root:
        return None
    try:
        rp_fp = os.path.realpath(fp)
        rp_root = os.path.realpath(root)
        if os.path.normcase(os.path.commonpath([rp_fp, rp_root])) != os.path.normcase(rp_root):
            return None
        rel = os.path.relpath(rp_fp, rp_root)
    except (ValueError, OSError):
        return None
    parts = rel.split(os.sep)
    if parts and parts[0] == os.pardir:
        return None
    return parts


def _session_of(fp, root=None):
    """Session id owning this transcript: the SECOND path segment under the
    scanned root. Anything nested below that -- a subagent trace, a workflow
    run's agents -- burns real tokens on behalf of the session that spawned it
    and must not become a session of its own. A transcript that IS the session
    (<slug>/<uuid>.jsonl) yields its own stem."""
    parts = _rel_parts(fp, root)
    if parts and len(parts) >= 2:
        return parts[1] if len(parts) > 2 else os.path.splitext(parts[1])[0]
    return os.path.splitext(os.path.basename(fp))[0]


def _project_of(fp, root=None):
    """The project-folder slug for a jsonl path, prettified for display.

    The project is the FIRST path segment under the scanned root, whatever
    nesting sits below it. Deriving it from basename(dirname()) instead put
    every NESTED transcript into a phantom project named after its parent
    directory, and per_project never rendered those buckets (it iterates
    proj_ts, which deliberately skips subagent files -- they burn tokens but
    are not wall-clock the owner spent). So the tokens simply disappeared,
    while the comment on proj_tokens claimed subagent files WERE counted.

    Measured on a 7-day window: 169,049,467 tokens (4.7%) lost to a phantom
    "subagents" project, plus a further 21,779,984 to a phantom
    "wf_a1c77f78-484" -- because there are at least two nesting shapes,
      <slug>/<uuid>/subagents/agent-*.jsonl
      <slug>/<uuid>/subagents/workflows/wf_<id>/agent-*.jsonl
    and hopping one fixed number of levels only ever fixes the shapes you
    happened to look at. Hence the root-relative rule rather than a special
    case per shape. Found by the asm-009 per-session tests. KB: asm-009.

    The display-prefix strip is derived from this machine's home slug
    (_HOME_SLUG), never a hardcoded owner disk root -- so a reader sees
    'my-project' instead of '<their-home-slug>-my-project' with zero config."""
    parts = _rel_parts(fp, root)
    if parts is not None and len(parts) == 1:
        # Directly under the scanned root: there IS no project directory, so the
        # file's own name is not one. Codex PR #15 XAI-002.
        return "(root)"
    slug = parts[0] if parts else os.path.basename(os.path.dirname(fp))
    for pre in (_HOME_SLUG + "-", _HOME_SLUG):
        if pre and slug.startswith(pre):
            return slug[len(pre):] or "(root)"
    m = _MAC_HOME_RE.match(slug)  # "-Users-<user>-<proj>" -> "<proj>"
    if m:
        return slug[m.end():] or "(root)"
    return slug or "(root)"


def _os_of_root(root):
    """Tag a scan root as 'mac' or 'win'. The Mac source is the synced
    `.claude-mac` tree; everything else is treated as the local (win) home."""
    return "mac" if "claude-mac" in root.replace("\\", "/").lower() else "win"


def _active_sec(ts_list):
    """Active seconds from a list of epoch timestamps: sum consecutive gaps,
    each capped at GAP_CAP_SEC. Same heuristic as usage_recap/time_tracking."""
    if len(ts_list) < 2:
        return 0
    ts_list = sorted(ts_list)
    total = 0
    for prev, curr in zip(ts_list, ts_list[1:]):
        gap = curr - prev
        if gap <= 0:
            continue
        total += min(gap, GAP_CAP_SEC)
    return int(total)


def build_recap(window, roots=None):
    """Aggregate token / cost / time distribution for `window`.

    `roots` is the list of `*/.../projects` dirs to scan. Default (None) is the
    local `~/.claude/projects` only — which keeps the totals aligned with the
    `recap.py week` baseline. Pass extra roots (e.g. a synced `.claude-mac`
    tree) to fold those in; each project is tagged with the os of its root.

    Returns a JSON-serializable dict. Token/cost scans every *.jsonl (incl.
    subagent traces) with message-id dedup — matching collect_usage so the
    totals line up with recap.py. Time distribution skips /subagents/ to avoid
    double-counting wall-clock, matching collect_sessions.
    """
    if not roots:
        roots = [PROJECTS_DIR]
    since, until, label = resolve_window(window)
    since_u = since.astimezone(timezone.utc)
    until_u = until.astimezone(timezone.utc)

    by_model = {}          # model -> {turns, inp, cw, cw1h, cw5m, cw_unsplit, cr, out}
    cw_mismatch_turns = 0  # turns where the TTL sub-object disagrees with the aggregate
    seen_ids = set()       # dedup: Claude Code writes streaming chunks 2-3x
    assistant_turns = 0
    per_day = defaultdict(lambda: {"tokens": 0, "turns": 0})
    proj_ts = defaultdict(list)        # project -> [epoch ts] (for active time)
    proj_sessions = defaultdict(set)   # project -> {session file} with in-window activity
    proj_tokens = defaultdict(int)     # project -> tokens; counts subagent files too,
                                       # unlike proj_ts -- a subagent burns real tokens
                                       # but is not wall-clock the owner spent
    proj_os = {}                       # project -> 'mac' | 'win' (first root seen)
    sess_tokens = defaultdict(int)     # (project, session) -> ALL tokens (nested traces folded in)
    sess_reread = defaultdict(int)     # (project, session) -> input-side only (see below)
    sess_turns = defaultdict(int)      # (project, session) -> assistant turns
    all_ts = []                        # every in-window ts (for global wall-clock)

    # Skip files that cannot hold an in-window line, by mtime, BEFORE opening them.
    # These transcripts are append-only, so a file whose last write predates the window
    # has no line inside it -- reading it is pure waste. Measured 2026-07-29 on this
    # machine: 1763 files / 977 MB total, but only 289 files / 254 MB were touched in
    # the last 7 days, so 74% of the bytes were being opened and JSON-parsed for nothing
    # (the 7d recap took 23.7s per click, and it is recomputed on every click).
    # SKEW absorbs clock skew and mtime granularity; it only ever includes MORE files,
    # so the result cannot lose data -- and the in-window ts test below is unchanged and
    # still decides what actually counts.
    _MTIME_SKEW_S = 86400
    cutoff = since_u.timestamp() - _MTIME_SKEW_S
    files = []
    skipped = 0
    for root in roots:
        os_tag = _os_of_root(root)
        for fp in glob.glob(os.path.join(root, "**", "*.jsonl"), recursive=True):
            try:
                if os.path.getmtime(fp) < cutoff:
                    skipped += 1
                    continue
            except OSError:
                pass          # unreadable stat -> fall through and let the reader decide
            files.append((fp, os_tag, root))

    for fp, os_tag, root in files:
        is_sub = "/subagents/" in fp.replace("\\", "/")
        # Resolved ONCE per file against the root that file actually came from.
        # Before this, `root` here was whatever the collection loop above left
        # behind -- the LAST root -- so with more than one root (the --mac path)
        # every file was resolved against the wrong tree and the phantom
        # projects came straight back. Single-root runs, which is everything
        # that was tested, happened to be correct. Codex PR #15 XAI-001.
        proj = _project_of(fp, root)
        sid = _session_of(fp, root)
        proj_os.setdefault(proj, os_tag)
        try:
            with open(fp, encoding="utf-8") as f:
                for line in f:
                    try:
                        d = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(d, dict):
                        continue
                    ts_raw = d.get("timestamp")
                    t = _parse_ts(ts_raw)
                    in_win = t is not None and since_u <= t <= until_u

                    # --- time distribution (skip subagent traces) ---
                    if in_win and not is_sub and d.get("type") in ("user", "assistant"):
                        epoch = t.timestamp()
                        proj_ts[proj].append(epoch)
                        proj_sessions[proj].add(fp)
                        all_ts.append(epoch)

                    # --- token / cost (all files, dedup by message id) ---
                    msg = d.get("message")
                    if not (isinstance(msg, dict) and msg.get("role") == "assistant"
                            and "usage" in msg and ts_raw):
                        continue
                    if not in_win:
                        continue
                    mid = msg.get("id")
                    if mid:
                        if mid in seen_ids:
                            continue
                        seen_ids.add(mid)
                    u = msg.get("usage") or {}
                    inp = u.get("input_tokens", 0) or 0
                    cw = u.get("cache_creation_input_tokens", 0) or 0
                    cr = u.get("cache_read_input_tokens", 0) or 0
                    out = u.get("output_tokens", 0) or 0
                    # Cache writes are priced by TTL. The split lives in the
                    # `cache_creation` sub-object; the aggregate above carries no
                    # TTL and is only a fallback. Measured over 30 days here:
                    # 39,174/39,174 turns HAD the sub-object, and 3 of them had a
                    # sub-object that did not sum to the aggregate -- so the two
                    # are not interchangeable, and the disagreement is counted
                    # rather than silently resolved.
                    cc = u.get("cache_creation")
                    if isinstance(cc, dict):
                        cw1h = cc.get("ephemeral_1h_input_tokens", 0) or 0
                        cw5m = cc.get("ephemeral_5m_input_tokens", 0) or 0
                        cw_unsplit = 0
                        if cw1h + cw5m != cw:
                            cw_mismatch_turns += 1
                    else:
                        cw1h = cw5m = 0
                        cw_unsplit = cw
                    model = msg.get("model") or "unknown"
                    acc = by_model.setdefault(
                        model, {"turns": 0, "inp": 0, "cw": 0, "cw1h": 0,
                                "cw5m": 0, "cw_unsplit": 0, "cr": 0, "out": 0})
                    acc["turns"] += 1
                    acc["inp"] += inp
                    acc["cw"] += cw
                    acc["cw1h"] += cw1h
                    acc["cw5m"] += cw5m
                    acc["cw_unsplit"] += cw_unsplit
                    acc["cr"] += cr
                    acc["out"] += out
                    assistant_turns += 1
                    day = t.astimezone().strftime("%Y-%m-%d")
                    per_day[day]["tokens"] += inp + cw + cr + out
                    per_day[day]["turns"] += 1
                    proj_tokens[proj] += inp + cw + cr + out
                    skey = (proj, sid)
                    sess_tokens[skey] += inp + cw + cr + out
                    # Input-side only. Output is GENERATED, never re-sent, so it
                    # is not part of what the next turn re-reads -- the same
                    # definition `claude_context_pct` uses for `occ`. Keeping
                    # them separate is what lets the per-turn figure be compared
                    # against the ctx_tokens thresholds at all. Codex PR #15
                    # XAI-003: the UI called the average "re-read per turn"
                    # while it was computed from the total.
                    sess_reread[skey] += inp + cw + cr
                    sess_turns[skey] += 1
        except OSError:
            continue

    # ---- token / cost rollup ----
    models = []
    tot = {"input": 0, "cache_creation": 0, "cache_read": 0, "output": 0}
    total_cost = 0.0
    unpriced_models = []
    ttl = {"h1": 0, "m5": 0, "unsplit": 0, "mismatch_turns": cw_mismatch_turns}
    for model, a in by_model.items():
        toks = a["inp"] + a["cw"] + a["cr"] + a["out"]
        p = _price_for(model)
        # cost is None -- NOT 0.0 -- when the model has no price. A zero is
        # indistinguishable from "this model really cost nothing", which is how
        # claude-fable-5 (22.6% of assistant turns over 14 days) vanished from
        # the headline without any warning. KB ticket: asm-008.
        cost = None
        if p:
            cost = (a["inp"] * p["inp"] + a["out"] * p["out"]
                    + a["cw1h"] * p["cw1h"] + a["cw5m"] * p["cw"]
                    + a["cw_unsplit"] * p["cw"] + a["cr"] * p["cr"]) / 1_000_000
            total_cost += cost
        elif toks:
            # Only warn for a model that actually moved tokens. `<synthetic>`
            # carries 0 and would otherwise light the banner on every single
            # render -- a warning that always fires is one nobody reads.
            unpriced_models.append(model)
        tot["input"] += a["inp"]
        tot["cache_creation"] += a["cw"]
        tot["cache_read"] += a["cr"]
        tot["output"] += a["out"]
        ttl["h1"] += a["cw1h"]
        ttl["m5"] += a["cw5m"]
        ttl["unsplit"] += a["cw_unsplit"]
        models.append({"model": model, "turns": a["turns"], "tokens": toks,
                       "cost": None if cost is None else round(cost, 4)})
    models.sort(key=lambda m: m["tokens"], reverse=True)
    total_tokens = sum(tot.values())

    # ---- time distribution ----
    global_active_sec = _active_sec(all_ts)
    projects = []
    proj_total_sec = 0
    proj_total_tok = 0
    for proj, ts_list in proj_ts.items():
        sec = _active_sec(ts_list)
        proj_total_sec += sec
        proj_total_tok += proj_tokens.get(proj, 0)
        projects.append({"project": proj, "active_min": round(sec / 60, 1),
                         "active_sec": sec, "sessions": len(proj_sessions[proj]),
                         "tokens": proj_tokens.get(proj, 0),
                         "os": proj_os.get(proj, "win")})
    for pr in projects:
        pr["pct"] = round(pr["active_sec"] / proj_total_sec * 100, 1) if proj_total_sec else 0.0
        pr["tok_pct"] = round(pr["tokens"] / proj_total_tok * 100, 1) if proj_total_tok else 0.0
        del pr["active_sec"]
    projects.sort(key=lambda p: p["active_min"], reverse=True)

    # ---- per-session token burn (asm-009) --------------------------------
    # Which SESSION spent it, not just which project. Counted in tokens, not
    # dollars: on a subscription the dollar figure is a list-price proxy rather
    # than a bill, and one model on this fleet has no price at all (see
    # `unpriced_models`), so a per-session dollar column would be silently short
    # for exactly the sessions that used it.
    sessions_out = [{"project": pr, "session": sid, "tokens": tk,
                     "turns": sess_turns[(pr, sid)],
                     "reread_tokens": sess_reread[(pr, sid)],
                     "avg_turn_reread": round(sess_reread[(pr, sid)]
                                              / sess_turns[(pr, sid)])
                     if sess_turns[(pr, sid)] else 0,
                     "os": proj_os.get(pr, "win")}
                    for (pr, sid), tk in sess_tokens.items()]
    sessions_out.sort(key=lambda s: -s["tokens"])
    per_session_total = len(sessions_out)
    sessions_out = sessions_out[:PER_SESSION_TOP_N]

    # ---- per-day: fill the whole range so the chart has no gaps ----
    days = []
    cur = since.date()
    end = until.date()
    while cur <= end:
        key = cur.strftime("%Y-%m-%d")
        d = per_day.get(key, {"tokens": 0, "turns": 0})
        days.append({"day": key, "tokens": d["tokens"], "turns": d["turns"]})
        cur += timedelta(days=1)

    return {
        "window": window,
        "label": label,
        "sources": sorted({_os_of_root(r) for r in roots}),  # ['win'] or ['mac','win']
        "range": "%s ~ %s" % (since.strftime("%Y-%m-%d"), until.strftime("%Y-%m-%d")),
        "since": since.strftime("%Y-%m-%d %H:%M"),
        "until": until.strftime("%Y-%m-%d %H:%M"),
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "prices_snapshot": PRICES_SNAPSHOT,
        "assistant_turns": assistant_turns,
        "total_tokens": total_tokens,
        "tokens": tot,
        "total_cost_usd": round(total_cost, 4),
        # Models with no row in PRICES contribute NOTHING to total_cost_usd.
        # Naming them is the only thing that keeps that omission visible.
        "unpriced_models": sorted(unpriced_models),
        "cache_creation_ttl": ttl,
        "by_model": models,
        "active_min": round(global_active_sec / 60, 1),
        "per_day": days,
        "per_project": projects,
        "per_session": sessions_out,
        "per_session_total": per_session_total,
    }


def merge_recap(base, remote, machine="company"):
    """Additively fold a remote (pre-aggregated) recap into a local one. Both are
    build_recap-shaped dicts for the SAME window. Totals sum; by_model merges by
    model id; per_project concatenates (remote entries tagged os=machine) with pct
    and tok_pct recomputed over the combined set. per_day is NOT merged (remote omits it to
    save relay bytes), so the daily chart stays local-only. A compact `office`
    summary (the company's own totals) is attached for the panel. Mutates+returns
    base."""
    if not isinstance(remote, dict):
        return base
    base["total_tokens"] = base.get("total_tokens", 0) + remote.get("total_tokens", 0)
    base["assistant_turns"] = base.get("assistant_turns", 0) + remote.get("assistant_turns", 0)
    base["total_cost_usd"] = round(base.get("total_cost_usd", 0.0) + remote.get("total_cost_usd", 0.0), 4)
    # A remote still on pre-asm-008 code sends neither field; absent folds to
    # "nothing to add", never to "verified empty".
    base["unpriced_models"] = sorted(set(base.get("unpriced_models") or [])
                                     | set(remote.get("unpriced_models") or []))
    bttl = base.setdefault("cache_creation_ttl",
                           {"h1": 0, "m5": 0, "unsplit": 0, "mismatch_turns": 0})
    rttl = remote.get("cache_creation_ttl") or {}
    for k in ("h1", "m5", "unsplit", "mismatch_turns"):
        bttl[k] = bttl.get(k, 0) + rttl.get(k, 0)
    bt = base.setdefault("tokens", {})
    rt = remote.get("tokens", {}) or {}
    for k in ("input", "cache_creation", "cache_read", "output"):
        bt[k] = bt.get(k, 0) + rt.get(k, 0)
    by = {m["model"]: dict(m) for m in base.get("by_model", [])}
    for m in remote.get("by_model", []):
        if m["model"] in by:
            x = by[m["model"]]
            x["turns"] += m.get("turns", 0)
            x["tokens"] += m.get("tokens", 0)
            # cost is None when a side could not price this model. If EITHER
            # side is unknown the merged total is unknown -- returning the known
            # half as if it were the total is the same silent under-report this
            # whole change exists to kill, and it comes straight back on the
            # cross-version path: a remote still on pre-asm-008 code sends
            # cost 0.0 for an unpriced model, and `(None or 0.0) + 0.0` would
            # quietly resurrect the 0. Found by codex review of PR #14 (XAI-001)
            # -- Claude's own first test asserted `None + 2.5 -> 2.5`, so the
            # wrong behaviour was encoded in the oracle and the suite passed.
            xc, mc = x.get("cost"), m.get("cost")
            x["cost"] = None if (xc is None or mc is None) else round(xc + mc, 4)
        else:
            by[m["model"]] = dict(m)
    base["by_model"] = sorted(by.values(), key=lambda m: -m["tokens"])
    allp = base.get("per_project", []) + [dict(p, os=machine) for p in remote.get("per_project", [])]
    tot = sum(p.get("active_min", 0) for p in allp)
    totk = sum(p.get("tokens", 0) for p in allp)
    for p in allp:
        p["pct"] = round(p.get("active_min", 0) / tot * 100, 1) if tot else 0.0
        # a remote still on pre-token-share code sends no "tokens": it lands at 0%
        # rather than distorting the machines that do report.
        p["tok_pct"] = round(p.get("tokens", 0) / totk * 100, 1) if totk else 0.0
    allp.sort(key=lambda p: -p.get("active_min", 0))
    base["per_project"] = allp
    alls = (base.get("per_session") or []) + [dict(s, os=machine) for s in (remote.get("per_session") or [])]
    alls.sort(key=lambda s: -s.get("tokens", 0))
    base["per_session_total"] = (base.get("per_session_total", 0)
                                 + remote.get("per_session_total", 0))
    base["per_session"] = alls[:PER_SESSION_TOP_N]
    base["active_min"] = round(base.get("active_min", 0.0) + remote.get("active_min", 0.0), 1)
    return base


def fmt_tokens(n):
    if n >= 1_000_000_000:
        return "%.2fB" % (n / 1_000_000_000)
    if n >= 1_000_000:
        return "%.2fM" % (n / 1_000_000)
    if n >= 1_000:
        return "%.1fk" % (n / 1_000)
    return str(n)


if __name__ == "__main__":
    import sys
    argv = sys.argv[1:]
    use_mac = "--mac" in argv
    argv = [a for a in argv if a != "--mac"]
    win = argv[0] if argv else "7d"
    if win == "week":  # accept the weekly-recap alias for convenience
        win = "7d"
    roots = None
    if use_mac:  # pull extra roots from monitor's config.json (no hardcoded path)
        try:
            cfg = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                               "config.json"), encoding="utf-8"))
            roots = cfg.get("claude_projects")
            if isinstance(roots, str):
                roots = [roots]
        except (OSError, json.JSONDecodeError):
            roots = None
    r = build_recap(win, roots=roots)
    print("=== recap %s  (%s)  %s  sources=%s ==="
          % (r["window"], r["label"], r["range"], "+".join(r["sources"])))
    print("assistant_turns:", r["assistant_turns"])
    print("total_tokens:", r["total_tokens"], "(%s)" % fmt_tokens(r["total_tokens"]))
    t = r["tokens"]
    print("  input:", t["input"], " cache_creation:", t["cache_creation"],
          " cache_read:", t["cache_read"], " output:", t["output"])
    print("total_cost_usd: %.4f" % r["total_cost_usd"])
    if r.get("unpriced_models"):
        print("  !! NOT in total_cost_usd (no price in PRICES): %s"
              % ", ".join(r["unpriced_models"]))
    t2 = r.get("cache_creation_ttl") or {}
    if t2:
        print("  cache writes by TTL: 1h=%s  5m=%s  unsplit=%s  (mismatch turns: %s)"
              % (t2.get("h1", 0), t2.get("m5", 0), t2.get("unsplit", 0),
                 t2.get("mismatch_turns", 0)))
    print("active_min:", r["active_min"])
    print("by_model:")
    for m in r["by_model"]:
        print("   %-40s turns=%d tok=%d cost=%s"
              % (m["model"], m["turns"], m["tokens"],
                 "unpriced" if m["cost"] is None else "%.4f" % m["cost"]))
    ss = r.get("per_session") or []
    if ss:
        print("per_session (top %d of %d):" % (len(ss), r.get("per_session_total", len(ss))))
        for s in ss:
            print("   [%s] %-26s %-10s %10s tok  %5d turns  avg re-read/turn %s"
                  % (s["os"], s["project"][:26], s["session"][:8],
                     fmt_tokens(s["tokens"]), s["turns"],
                     fmt_tokens(s["avg_turn_reread"])))
    print("per_project:")
    for p in r["per_project"]:
        print("   [%s] %-28s %6.1f min  %5.1f%%  %10s tok  %5.1f%%  %d sess"
              % (p["os"], p["project"], p["active_min"], p["pct"],
                 fmt_tokens(p["tokens"]), p["tok_pct"], p["sessions"]))
