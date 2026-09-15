#!/usr/bin/env python3
"""Company-side push agent for ai-session-monitor (Phase 4).

Runs on the COMPANY machine (which has NO dashboard). Scans the local
~/.claude/projects for live session status, PSEUDONYMIZES every project name
(raw names NEVER leave this machine), signs the snapshot with the shared HMAC
key, and POSTs it to the ntfy relay. The home dashboard pulls it. Pure stdlib.

Bring THREE files to the company machine, same folder: this file, office.py,
recap.py. Put the shared secret + topic in `config.local.json` next to them:

    { "office_secret": "<same 64-hex as home>", "office_ntfy_topic": "<same topic as home>" }

…or pass them via env vars OFFICE_SECRET / OFFICE_NTFY_TOPIC.

  one-shot (recommended — run from Task Scheduler every 1-2 min):
      python office_push.py
  loop mode (adaptive: 30s while active, 120s while idle):
      python office_push.py --loop
  include the usage recap too (larger payload — see note):
      python office_push.py --with-recap

NOTE: --with-recap adds the token/cost/time aggregate to the snapshot. It is a
bigger payload; ntfy bodies have a size limit, so it's OFF by default until the
home-side recap merge (Phase 5) is wired and the size is verified. Live session
status (the default) is small and safe.
"""
from __future__ import annotations

import glob
import json
import os
import socket
import sys
import time
import urllib.request
from datetime import datetime

import office
import recap  # build_recap reads ~/.claude/projects on THIS (company) machine

PROJECTS_DIR = recap.PROJECTS_DIR  # ~/.claude/projects
RECAP_WINDOW = "7d"
NTFY = "https://ntfy.sh/%s"
# This machine's OS, reported with each pushed row. It used to be the literal "win",
# which made every non-Windows pusher describe itself as Windows -- the machine badge
# was right and the OS glyph was wrong. Same three values monitor.os_of_cwd() emits.
_OS = "win" if os.name == "nt" else ("mac" if sys.platform == "darwin" else "linux")


def _conf():
    """config.json then config.local.json (local overrides). Never raises."""
    here = os.path.dirname(os.path.abspath(__file__))
    conf = {}
    for name in ("config.json", "config.local.json"):  # local overrides
        try:
            with open(os.path.join(here, name), encoding="utf-8") as f:
                conf.update(json.load(f))
        except (OSError, json.JSONDecodeError):
            pass
    return conf


def _thresholds():
    """(running_secs, idle_secs, max_age_hours, max_rows) from config.

    These four were literals up here (90 / 600 / 6 / 25) while config.json already
    carried the same four values for the dashboard, and this file was already reading
    that config for other keys. They agreed exactly, so nothing looked wrong -- but
    editing either side alone would have moved the dashboard and left the push behind,
    with no symptom until someone compared two screens. One source now.
    Defaults match config.json's own so an absent key changes nothing.
    """
    conf = _conf()
    return (int(conf.get("running_secs", 90)),
            int(conf.get("idle_alert_minutes", 10)) * 60,
            int(conf.get("max_age_hours", 6)),
            int(conf.get("max_rows_per_source", 25)))


def _load_conf():
    conf = _conf()
    secret = os.environ.get("OFFICE_SECRET") or conf.get("office_secret")
    topic = os.environ.get("OFFICE_NTFY_TOPIC") or conf.get("office_ntfy_topic")
    top = int(conf.get("office_recap_top_projects", 8))  # per-project breakdown cap
    # this machine's label key — how the hub demuxes + badges it (company / home / …)
    # one identity per box: office_machine is the legacy per-channel override,
    # local_machine is the canonical answer to "which machine am I" (monitor.py).
    machine = (os.environ.get("OFFICE_MACHINE") or conf.get("office_machine")
               or conf.get("local_machine") or socket.gethostname())
    return secret, topic, top, machine


def _notify_marker_ts(jsonl_path):
    """ts of this session's idle/permission marker (waiting), or None."""
    marker = os.path.splitext(jsonl_path)[0] + ".notify.json"
    try:
        with open(marker, "r", encoding="utf-8") as f:
            return float(json.load(f).get("ts"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        try:
            return os.path.getmtime(marker)
        except OSError:
            return None


def _status(ts, now, marker_ts, running_secs, idle_secs):
    if marker_ts is not None and marker_ts >= ts:
        return "waiting"
    age = now - ts
    if age < running_secs:
        return "running"
    if age < idle_secs:
        return "idle"
    return "stopped"


def _pending(jsonl_path, max_bytes=65536):
    """'question' (AskUserQuestion) / 'plan_review' (ExitPlanMode) if Claude's
    last action is blocked on the user, else None. Mirrors
    monitor.pending_user_action so remote alerts name the reason too."""
    try:
        size = os.path.getsize(jsonl_path)
        with open(jsonl_path, "rb") as f:
            if size > max_bytes:
                f.seek(-max_bytes, os.SEEK_END)
            chunk = f.read()
    except OSError:
        return None
    for line in reversed(chunk.splitlines()):
        if b'"tool_result"' in line:
            return None
        if b'"type":"tool_use"' in line:
            if b'"name":"AskUserQuestion"' in line:
                return "question"
            if b'"name":"ExitPlanMode"' in line:
                return "plan_review"
            return None
    return None


def _pmode(jsonl_path, max_bytes=65536):
    """Latest permission mode (bypassPermissions / plan / acceptEdits / default),
    so the hub can label the alert. Tail-scan; mirrors monitor.last_permission_mode."""
    try:
        size = os.path.getsize(jsonl_path)
        with open(jsonl_path, "rb") as f:
            if size > max_bytes:
                f.seek(-max_bytes, os.SEEK_END)
            chunk = f.read()
    except OSError:
        return ""
    for line in reversed(chunk.splitlines()):
        if b"permission-mode" not in line:
            continue
        try:
            o = json.loads(line.decode("utf-8", "ignore"))
        except (json.JSONDecodeError, ValueError):
            continue
        if o.get("type") == "permission-mode":
            return o.get("permissionMode") or ""
    return ""


def _scan_sessions(secret, now):
    out = []
    # read once per scan, not once per row (same shape as monitor's alert_loop, which
    # re-reads config each round so a config edit takes effect without a restart)
    running_secs, idle_secs, max_age_hours, max_rows = _thresholds()
    cutoff = now - max_age_hours * 3600
    for fp in glob.glob(os.path.join(PROJECTS_DIR, "*", "*.jsonl")):
        try:
            ts = os.path.getmtime(fp)
        except OSError:
            continue
        if ts < cutoff:
            continue
        slug = os.path.basename(os.path.dirname(fp))
        real_id = os.path.splitext(os.path.basename(fp))[0]
        pend = _pending(fp)  # blocked on user? names the reason
        status = "waiting" if pend else _status(ts, now, _notify_marker_ts(fp),
                                                running_secs, idle_secs)
        out.append({
            "session_token": office.session_token(real_id, secret),
            "label": office.alias_project(slug, secret),  # raw slug stays on this machine
            "status": status,
            "wait_kind": pend or ("idle" if status == "waiting" else None),
            "ts": round(ts, 3),
            "source_ai": "claude",
            "os": _OS,
            "pmode": _pmode(fp),  # permission mode for the hub's alert (Plan/Bypass/…)
        })
    out.sort(key=lambda s: s["ts"], reverse=True)
    return out[:max_rows]


def _aliased_recap(secret, top_projects=8):
    """Build the recap, alias project names, and cap the per-project breakdown to
    the top N (by active time) so the ntfy payload stays bounded on machines with
    many projects. TOTALS (cost / tokens / by_model) stay FULL — you still see the
    true company spend; only the project *breakdown* is the top N."""
    try:
        r = recap.build_recap(RECAP_WINDOW)
    except Exception:  # noqa: BLE001 — recap is optional; never block the push
        return None
    projs = r.get("per_project", [])  # already sorted desc by active_min
    r["per_project_total"] = len(projs)  # so home can say "top N of M"
    r["per_project"] = projs[:max(1, top_projects)]
    for p in r["per_project"]:  # alias real project names before they leave
        p["project"] = office.alias_project(p.get("project", ""), secret)
    r.pop("per_day", None)  # drop the daily series — not needed for company spend, saves bytes
    return r


def build_snapshot(secret, now, with_recap=False, top_projects=8, machine=None):
    """Build the signed envelope (no network). Returned for testing too."""
    sessions = _scan_sessions(secret, now)
    msg = {
        "schema": office.SCHEMA,
        "machine": machine or socket.gethostname(),
        "pushed_at": round(now, 3),
        "seq": int(now * 1000),  # monotonic across restarts (no counter to lose)
        "sessions": sessions,
        "recap": _aliased_recap(secret, top_projects) if with_recap else None,
    }
    return office.sign(msg, secret), sessions


def push_once(secret, topic, with_recap=False, top_projects=8, machine=None, verbose=True):
    now = time.time()
    env, sessions = build_snapshot(secret, now, with_recap, top_projects, machine)
    body = json.dumps(env).encode("utf-8")
    try:
        urllib.request.urlopen(
            urllib.request.Request(NTFY % topic, data=body,
                                   headers={"Content-Type": "application/json"}),
            timeout=10)
        if verbose:
            print("pushed %d sessions as '%s' (%d bytes) @ %s"
                  % (len(sessions), machine, len(body), datetime.now().strftime("%H:%M:%S")))
    except Exception as e:  # noqa: BLE001 — a failed push must not crash a loop
        if verbose:
            sys.stderr.write("push failed: %s\n" % e)
    return sessions


def main(argv):
    secret, topic, top, machine = _load_conf()
    if not secret or not topic:
        sys.stderr.write(
            "office_push: missing office_secret / office_ntfy_topic.\n"
            "  Put them in config.local.json next to this file, or set env\n"
            "  OFFICE_SECRET / OFFICE_NTFY_TOPIC. Must MATCH the home dashboard.\n")
        return 2
    with_recap = "--with-recap" in argv
    if "--loop" in argv:
        while True:
            sessions = push_once(secret, topic, with_recap, top, machine)
            active = any(s["status"] in ("running", "waiting") for s in sessions)
            time.sleep(30 if active else 120)
    push_once(secret, topic, with_recap, top, machine)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
