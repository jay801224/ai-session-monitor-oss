"""Accumulate which office2 zones real data actually reaches.

owner 2026-07-28: "office 我需要你交代下去，確保每一區都有確實輪到狀態（不可以用模擬）".

A single sample cannot answer that -- "nobody is writing docs right now" is not the
same claim as "the docs zone can never be filled". So this samples /api/status over
a window and records, per zone, whether a REAL row ever landed there. No fixtures,
no mock rows: the only input is the live monitor.

zoneOf() below mirrors ui/office_proto.html:558 exactly. It is duplicated rather than
extracted because the page is a single HTML file with no module boundary; if the page's
routing changes this file has to change with it (there is a guard for that at the end:
it re-reads the page and fails loudly if the rule text moved).

usage: PORT=8788 python tools/office2_zone_liveness.py --minutes 10
"""
import argparse
import collections
import json
import os
import re
import sys
import time
import urllib.request

ZONES = ["coding", "docs", "testing", "review", "council", "cli", "standby", "offline"]
BUCKETS = ("claude", "codex", "hermes", "copilot", "antigravity")


def _js_truthy(v):
    """JavaScript truthiness, which is NOT Python's.

    zoneOf() branches on `if(r.work_review)`. In JS an empty array or empty object is
    TRUTHY, in Python both are falsy -- so a row carrying work_review:[] routes to the
    review zone in the page and to standby in a naive mirror, and the liveness report
    would then claim the review zone was never reached when the page had filled it.
    Only JS's seven falsy values are false here.
    """
    return not (v is None or v is False or v == 0 or v == "" or
                (isinstance(v, float) and v != v))   # NaN


def zone_of(r):
    """Mirror of zoneOf() in ui/office_proto.html -- priority is fixed."""
    if r.get("status") in ("stopped", "stale"):
        return "offline"
    wc = r.get("work_council")
    if isinstance(wc, dict) and _js_truthy(wc.get("in_council")):
        return "council"
    if _js_truthy(r.get("work_review")):
        return "review"
    wk = r.get("work_kind")
    if wk == "cli_queue":
        return "cli"
    if wk == "standby":
        return "standby"
    if wk == "working":
        wd = r.get("work_detail")
        return "docs" if wd == "docs" else "testing" if wd == "test" else "coding"
    return "standby"


def zone_ignoring_stopped(r):
    """What the row's own work signal says, with the stopped-first rule removed.

    The gap between this and zone_of() is the answer to "is the signal missing, or is
    it there but unreachable?" -- a stopped row carrying work_kind:standby never gets
    to the standby zone, because zoneOf sends every stopped row to offline first.
    """
    return zone_of(dict(r, status="running"))


def sample(base):
    d = json.load(urllib.request.urlopen(base + "/api/status", timeout=10))
    rows = [r for b in BUCKETS for r in (d.get(b) or [])]
    live = collections.Counter(zone_of(r) for r in rows)
    latent = collections.Counter(zone_ignoring_stopped(r) for r in rows)
    try:
        cb = json.load(urllib.request.urlopen(base + "/api/cli-bridge", timeout=10))
        helpers = len(cb.get("now_running") or [])
    except Exception:
        helpers = 0
    if helpers:                      # mapCliBridge puts every live helper in the CLI zone
        live["cli"] += helpers
    return rows, live, latent


def guard_routing_unchanged(repo):
    """Fail loudly if the page's routing rule moved -- a silently stale mirror would
    make this whole report a lie."""
    page = os.path.join(repo, "ui", "office_proto.html")
    try:
        with open(page, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return "could not read ui/office_proto.html -- routing mirror unverified"
    # Pull out zoneOf()'s OWN body and check the branches inside it. Searching the whole
    # page for "'council'" etc. proves nothing: every one of those strings also appears in
    # the ZONES table and elsewhere in the UI, so the guard would still pass after zoneOf's
    # branches were rewritten or deleted -- a stale mirror that reports itself as fresh.
    start = text.find("function zoneOf(r){")
    if start < 0:
        return "ui/office_proto.html no longer defines zoneOf() -- mirror cannot be trusted"
    depth, end = 0, -1
    for i in range(text.find("{", start), len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end < 0:
        return "could not delimit zoneOf() -- mirror cannot be trusted"
    body = "".join(text[start:end].split())   # whitespace-insensitive compare

    # Each entry: the exact branch this file mirrors, in zoneOf's priority order.
    expected = [
        "if(r.status==='stopped'||r.status==='stale')return'offline';",
        "if(r.work_council&&r.work_council.in_council)return'council';",
        "if(r.work_review)return'review';",
        "if(wk==='cli_queue')return'cli';",
        "if(wk==='standby')return'standby';",
        "returnd==='docs'?'docs':d==='test'?'testing':'coding';",
    ]
    missing = [e for e in expected if e not in body]
    if missing:
        return ("zoneOf() no longer contains the branch(es) this script mirrors: %s "
                "-- update zone_of() before trusting the output" % " | ".join(missing))
    # priority order matters as much as presence
    idx = [body.index(e) for e in expected]
    if idx != sorted(idx):
        return "zoneOf()'s branch ORDER changed -- the mirror's priority is now wrong"
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=float, default=10.0)
    ap.add_argument("--every", type=float, default=20.0, help="seconds between samples")
    ap.add_argument("--out", default="report/office2_zone_liveness.json")
    args = ap.parse_args()

    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    stale = guard_routing_unchanged(repo)
    if stale:
        print("REFUSING: " + stale)
        return 2

    port = os.environ.get("PORT", "8788")
    if port == "8787":
        print("REFUSING: 8787 is the production daemon; preview on 8788")
        return 2
    base = "http://127.0.0.1:%s" % port

    ever = {z: 0 for z in ZONES}          # real rows that reached the zone
    ever_latent = {z: 0 for z in ZONES}   # rows whose own signal says the zone, stopped ignored
    peak = {z: 0 for z in ZONES}
    samples = 0
    deadline = time.time() + args.minutes * 60
    started = time.strftime("%Y-%m-%d %H:%M:%S")
    while time.time() < deadline:
        try:
            rows, live, latent = sample(base)
        except Exception as exc:
            print("sample failed (%s) -- monitor down?" % exc)
            time.sleep(args.every)
            continue
        samples += 1
        for z in ZONES:
            ever[z] += live.get(z, 0)
            ever_latent[z] += latent.get(z, 0)
            peak[z] = max(peak[z], live.get(z, 0))
        print("[%s] rows=%2d %s" % (time.strftime("%H:%M:%S"), len(rows),
              " ".join("%s=%d" % (z, live.get(z, 0)) for z in ZONES if live.get(z, 0))))
        time.sleep(args.every)

    reached = [z for z in ZONES if peak[z] > 0]
    never = [z for z in ZONES if peak[z] == 0]
    # a zone nobody reached, but whose signal exists on stopped rows, is UNROUTED, not absent
    unrouted = [z for z in never if ever_latent[z] > 0]
    absent = [z for z in never if ever_latent[z] == 0]

    out = {"started": started, "finished": time.strftime("%Y-%m-%d %H:%M:%S"),
           "samples": samples, "source": base + "/api/status (real data, no fixtures)",
           "peak_per_zone": peak, "row_hits_per_zone": ever,
           "row_hits_ignoring_stopped_rule": ever_latent,
           "reached": reached, "never_reached": never,
           "never_but_signal_exists_on_stopped_rows": unrouted,
           "never_and_no_signal_at_all": absent}
    path = os.path.join(repo, args.out)
    os.makedirs(os.path.dirname(path), exist_ok=True)  # fresh clones have no report/
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2)

    print("\n%d sample(s) over %.0f min" % (samples, args.minutes))
    print("reached by real data : %s" % (", ".join(reached) or "(none)"))
    print("never reached        : %s" % (", ".join(never) or "(none)"))
    if unrouted:
        print("  ^ of those, signal EXISTS but is unroutable (stopped-first rule): %s"
              % ", ".join(unrouted))
    if absent:
        print("  ^ of those, no signal at all in this window: %s" % ", ".join(absent))
    print("wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
