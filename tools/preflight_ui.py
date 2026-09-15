#!/usr/bin/env python
"""preflight_ui.py -- stdlib-only pre-flight checker for ai-session-monitor UI work.

Default (no args) runs the full pre-flight + selftest:
  1. py_compile monitor.py
  2. `import monitor` succeeds (in a subprocess, so this checker stays side-effect free)
  3. extract <script> blocks from ui/dashboard.html + ui/session.html, `node --check`
     each (SKIP with a warning if node is not on PATH -- not a failure)
  4. zero-LLM grep: no *.py in repo root or tools/ may contain the forbidden
     provider substrings (this file's own selftest builds them at runtime so the
     checker never false-positives on itself)
  5. built-in selftest: the scanner MUST flag a dirty string and MUST NOT flag a
     clean one (guards against a fake checker that always returns 0)

Sub-commands assert structure for later tasks (they exit 1 until those land):
  check-model     "model" row key populated from cx inside collect_claude + import
  check-kind      data-agent-kind present in ui/dashboard.html + node --check
  check-cockpit   cockpit_cards really CALLS collect_hermes(/collect_antigravity( + import
  check-srccolor  SRCCOLOR appears >= 2 times in ui/dashboard.html + node --check
  check-copilot     collect_copilot exists + build_status has "copilot" + cockpit_cards calls it
  check-copilot-ui  SRC + SRCCOLOR literals in dashboard.html include copilot + node --check
  check-deletions   collect_delete_events(cfg) functional fixture (v1 legacy kept, overwrite
                    excluded, garbage line skipped, v2 fields passed through) + /api/deletions
  check-delview     deletions view wiring + inert-payload render check. CONTRACT for B5:
                    dashboard.html must define renderDeletions(rows) callable with a plain
                    rows array; harness feeds <img onerror> payload in every agent-controlled
                    field and fails if raw "<img" or an on* attribute reaches an HTML sink.
  check-authz       functional authz check. CONTRACT for B6: monitor.py defines AUTHZ_GATES,
                    collect_authz_pending, _authz_request_rows, _authz_repo_map(cfg) and
                    ops_authorize(cfg, body) (body = {"id","gate"}, do_POST ops convention);
                    traversal id / unknown gate / junction realpath-divergent repo are all
                    rejected with NO marker written; a valid grant writes
                    <repo>/.claude/_state/authz_mass_delete_oneshot json carrying the pending
                    row's cmd_hash. Also: CONTEXT.md must contain ADR-005.
  check-authz-ui    ui/authz.html exists with __CSRF__ + /api/ops/authorize + dismiss key,
                    dashboard has /authz link + alertbar key item, node --check green,
                    inert-payload render check. CONTRACT for B7: authz.html must define
                    renderPending(rows) callable with a plain rows array (same XSS oracle).
  check-collapse    PREFS.collapsed present + applyCollapse appears >= 4 times (1 def + >=3
                    call sites) in dashboard.html + node --check
  check-tooltip     delegated tooltip timing/a11y/hover-persistence structure + node --check
                    + inert <img onerror> payload test for textContent rendering
  check-office-data D1--D5 office contract fixtures + AST read-only/fail-closed guards
  check-dashboard-interactions responsive view consistency, horizontal-overflow guard, and
                    keyboard contracts for source/service chips and collapsible cards
  check-deletions-readonly Deletions renderer/fetch is read-only: GET /api/deletions only,
                    with no dashboard destructive-action wiring
  check-signal-desk-contract Signal Desk spawn ordinal, work reason, and stopped-row
                    identity-retention fixture
  check-signal-desk-assets Signal Desk's source-mapped operator image is a real PNG with
                    accessible `<img>` use and a visible source label
  check-signal-desk-ui Signal Desk semantic floor, A/a identities, persisted display
                    ordinals, and stopped/queue routing
  check-signal-desk-surface-state Signal Desk floor depth, room contours, compact empty
                    Working state, and muted Stopped desks remain presentational CSS
  check-office-transition retained parent-node FLIP transition fixture, including reduced
                    motion and queue-ticket exclusion
  check-monitor-help-exits monitor.py's main() answers -h/--help with usage + sys.exit(0)
                    before any config load, thread start or socket bind, verified both
                    structurally (AST) and by actually invoking --help with PORT=0
  list-checks       asserts all required sub-commands are registered, then runs the default suite

Exit 0 = all green (SKIPs allowed). Exit 1 = at least one FAIL. Exit 2 = usage.
"""
import ast
import glob
import json
import os
import py_compile
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MONITOR = os.path.join(ROOT, "monitor.py")
DASHBOARD = os.path.join(ROOT, "ui", "dashboard.html")
SESSION = os.path.join(ROOT, "ui", "session.html")
OFFICE_PROTO = os.path.join(ROOT, "ui", "office_proto.html")
DESIGN_DOC = os.path.join(ROOT, "docs", "uiux-overhaul-design-system.md")
DATA_CONTRACTS = os.path.join(ROOT, "docs", "uiux-overhaul-data-contracts.md")
SIGNAL_DESK_HEAD = os.path.join(ROOT, "ui", "assets", "signal-desk", "operator-head-v1.png")
SELF = os.path.abspath(__file__)

# Forbidden provider substrings, built at runtime by concatenation so that this
# file itself never trips the scanner (selftest fixtures use the same trick).
NEEDLES = ("api." + "anthro" + "pic", "open" + "ai")

RESULTS = []  # (status, name, detail)


def record(status, name, detail=""):
    RESULTS.append((status, name, detail))
    line = "[%s] %s" % (status, name)
    if detail:
        line += " -- " + detail
    print(line)


# ---------------------------------------------------------------- primitives

def read_text(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def check_pycompile():
    try:
        py_compile.compile(MONITOR, doraise=True)
        record("PASS", "py_compile monitor.py")
        return True
    except py_compile.PyCompileError as e:
        record("FAIL", "py_compile monitor.py", str(e).splitlines()[-1])
        return False


def check_import_monitor():
    proc = subprocess.run(
        [sys.executable, "-c", "import monitor"],
        cwd=ROOT, capture_output=True, text=True, timeout=120)
    if proc.returncode == 0:
        record("PASS", "import monitor")
        return True
    tail = (proc.stderr or proc.stdout or "").strip().splitlines()
    record("FAIL", "import monitor", tail[-1] if tail else "nonzero exit")
    return False


def extract_scripts(html_path):
    """Inline <script> block bodies (skips <script src=...>)."""
    text = read_text(html_path)
    blocks = []
    for m in re.finditer(r"<script\b([^>]*)>(.*?)</script>", text,
                         re.DOTALL | re.IGNORECASE):
        attrs, body = m.group(1), m.group(2)
        if re.search(r"\bsrc\s*=", attrs, re.IGNORECASE):
            continue
        if body.strip():
            blocks.append(body)
    return blocks


def node_check(html_path):
    """node --check every inline <script> of html_path. SKIP (not fail) w/o node."""
    name = "node --check " + os.path.relpath(html_path, ROOT).replace(os.sep, "/")
    node = shutil.which("node")
    if not node:
        record("SKIP", name, "warning: node not on PATH, syntax check skipped")
        return True
    blocks = extract_scripts(html_path)
    if not blocks:
        record("FAIL", name, "no inline <script> block found")
        return False
    for i, body in enumerate(blocks):
        fd, tmp = tempfile.mkstemp(suffix=".js")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(body)
            proc = subprocess.run([node, "--check", tmp],
                                  capture_output=True, text=True, timeout=60)
            if proc.returncode != 0:
                err = (proc.stderr or "").strip().splitlines()
                record("FAIL", name,
                       "block %d: %s" % (i + 1, err[-1] if err else "syntax error"))
                return False
        finally:
            os.unlink(tmp)
    record("PASS", name, "%d block(s)" % len(blocks))
    return True


def scan_text_for_llm(text):
    """Return the list of forbidden needles found in text (case-insensitive)."""
    low = text.lower()
    return [n for n in NEEDLES if n in low]


def check_zero_llm():
    py_files = sorted(glob.glob(os.path.join(ROOT, "*.py"))
                      + glob.glob(os.path.join(ROOT, "tools", "*.py")))
    hits = []
    for p in py_files:
        if os.path.abspath(p) == SELF:
            continue  # this checker's selftest fixtures are runtime-built anyway
        found = scan_text_for_llm(read_text(p))
        if found:
            hits.append("%s: %s" % (os.path.relpath(p, ROOT), ",".join(found)))
    if hits:
        record("FAIL", "zero-LLM grep (*.py)", "; ".join(hits))
        return False
    record("PASS", "zero-LLM grep (*.py)", "%d files clean" % len(py_files))
    return True


def selftest():
    """Prove the scanner works: flags dirty input, stays quiet on clean input."""
    dirty_a = "client = " + "Open" + "AI" + "()"          # case-insensitive hit
    dirty_b = "url = 'https://" + "api." + "anthro" + "pic" + ".com/v1'"
    clean = "import os\nprint('hello world')\n"
    ok = (bool(scan_text_for_llm(dirty_a))
          and bool(scan_text_for_llm(dirty_b))
          and scan_text_for_llm(clean) == [])
    if ok:
        record("PASS", "selftest (scanner flags dirty, passes clean)")
        return True
    record("FAIL", "selftest",
           "dirty_a=%r dirty_b=%r clean=%r" % (scan_text_for_llm(dirty_a),
                                               scan_text_for_llm(dirty_b),
                                               scan_text_for_llm(clean)))
    return False


def function_node(func_name):
    """Top-level FunctionDef node + source segment for func_name in monitor.py."""
    src = read_text(MONITOR)
    tree = ast.parse(src, filename=MONITOR)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            return node, ast.get_source_segment(src, node)
    return None, None


# --------------------------------------------------------------- sub-commands

def cmd_check_model():
    node, seg = function_node("collect_claude")
    if node is None:
        record("FAIL", "check-model", "collect_claude not found in monitor.py")
        return False
    ok = False
    for line in seg.splitlines():
        if (re.search(r"['\"]model['\"]\s*:", line)
                and re.search(r"\bcx\b", line)
                and not re.search(r"['\"]model['\"]\s*:\s*None\b", line)):
            ok = True
            break
    if ok:
        record("PASS", "check-model", '"model" row key populated from cx')
    else:
        record("FAIL", "check-model",
               'no "model": ...cx... row in collect_claude (task not landed yet?)')
    return check_import_monitor() and ok


def called_names(func_node):
    names = set()
    for n in ast.walk(func_node):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name):
                names.add(f.id)
            elif isinstance(f, ast.Attribute):
                names.add(f.attr)
    return names


def _function_segment(name):
    node, segment = function_node(name)
    if node is None:
        raise AssertionError(name + " missing")
    return node, segment


def _d5_has_write_call(segment):
    tree = ast.parse(segment)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            mode = node.args[1].value if len(node.args) > 1 and isinstance(node.args[1], ast.Constant) else "r"
            if isinstance(mode, str) and any(flag in mode for flag in ("w", "a", "x", "+")):
                return True
        if isinstance(node.func, ast.Attribute) and node.func.attr in (
                "unlink", "remove", "rmdir", "rename", "replace", "write_text", "write_bytes"):
            return True
    return False


def cmd_check_office_data():
    """Exercise P4's bounded, display-only data contracts without live sources."""
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    import monitor
    ok = True
    required = ("enrich_office_rows", "collect_cli_bridge", "_bridge_regular_file",
                "_bridge_pid_live", "_pool_source", "_bridge_recent_entry")
    missing = [name for name in required if not hasattr(monitor, name)]
    if missing:
        record("FAIL", "check-office-data", "missing: " + ", ".join(missing))
        return False
    try:
        now = 2000.0
        parent = {"session_id": "parent", "status": "running", "source_ai": "claude"}
        remote = {"session_id": "remote", "status": "running", "source_ai": "claude"}
        old_tail = monitor.claude_live_tail
        monitor.claude_live_tail = lambda _path: {"tool": "edit", "tool_done": False,
                                                   "target": "README.md"}
        try:
            monitor.enrich_office_rows({}, [parent], now, True, {"parent": "launch-1"})
            monitor.enrich_office_rows({}, [remote], now, False, {"remote": "ignored"})
        finally:
            monitor.claude_live_tail = old_tail
        if not (parent.get("session_id") == "parent" and parent.get("launch_id") == "launch-1"
                and parent.get("group_key") == "launch-1" and parent.get("work_kind") == "standby"):
            raise AssertionError("D1/D3 grouping or no-tail fallback failed")
        if not (remote.get("group_key") == "remote" and remote.get("work_kind") == "standby"):
            raise AssertionError("remote standby fallback failed")
        local = {"session_id": "local", "status": "running", "source_ai": "claude",
                 "_office_path": "fixture.jsonl"}
        old_tail = monitor.claude_live_tail
        monitor.claude_live_tail = lambda _path: {"tool": "edit", "tool_done": False,
                                                   "target": "code.py"}
        try:
            monitor.enrich_office_rows({}, [local], now + 20, True, {})
        finally:
            monitor.claude_live_tail = old_tail
        if local.get("work_kind") != "working" or local.get("work_detail") != "code":
            raise AssertionError("local active tail is not working")
        # _debounced_work_kind returns (kind, detail): holding the kind while dropping
        # the detail filed every finished .md edit as coding, so the 寫文件 zone could
        # never light up. The detail must survive the debounce window with the kind.
        if monitor._debounced_work_kind("fixture-debounce", "working", now)[0] != "working" or \
                monitor._debounced_work_kind("fixture-debounce", "standby", now + 1)[0] != "working":
            raise AssertionError("work_kind debounce failed")
        if monitor._debounced_work_kind("fixture-docs", "working", now, "docs") != ("working", "docs"):
            raise AssertionError("debounce dropped the in-flight work_detail")
        if monitor._debounced_work_kind("fixture-docs", "standby", now + 1, None) != ("working", "docs"):
            raise AssertionError("a just-finished docs edit lost its detail and would draw as coding")
        # and the full command must be what decides 'test', not the 80-char digest
        long_cd = ("cd /c/myrepo/wt-uiux-overhaul && for i in 1 2 3 4 5 6; do "
                   "python tools/preflight_ui.py > /dev/null 2>&1; done")
        if "preflight_ui" in long_cd[:80]:
            raise AssertionError("fixture is not modelling truncation: token is inside 80 chars")
        if monitor._office_work_detail("Bash", long_cd[:80]) != "code":
            raise AssertionError("fixture no longer models the truncated-target case")
        if monitor._office_work_detail("Bash", long_cd[:80], long_cd) != "test":
            raise AssertionError("a test runner behind a `cd ... &&` prefix is still missed")
        with tempfile.TemporaryDirectory() as root:
            parent_path = os.path.join(root, "parent.jsonl")
            mini_dir = os.path.join(root, "parent", "subagents")
            os.makedirs(mini_dir)
            child_path = os.path.join(mini_dir, "agent-child.jsonl")
            with open(parent_path, "w", encoding="utf-8") as f:
                f.write("{}")
            with open(child_path, "w", encoding="utf-8") as f:
                f.write("{}")
            os.utime(child_path, (now - 1, now - 1))
            minis = monitor._mini_rows({"session_id": "parent", "group_key": "launch-1",
                                        "_office_path": parent_path}, now, {})
        if len(minis) != 1 or minis[0].get("parent_session_id") != "parent" or \
                minis[0].get("group_key") != "launch-1" or minis[0].get("vendor") != "cc":
            raise AssertionError("local mini inheritance failed")
        if monitor._pool_source({}, "python.exe", "C:/bin/claude", False) != "ai_opened":
            raise AssertionError("configured independent command heuristic missing")
        if monitor._pool_source({}, "svchost.exe", "", False) != "system":
            raise AssertionError("system heuristic fallback missing")
        if monitor._pool_source({}, "", "", True) != "ai_scheduled":
            raise AssertionError("scheduled classification missing")
        with tempfile.TemporaryDirectory() as root:
            logs = os.path.join(root, "log")
            os.mkdir(logs)
            meta = os.path.join(root, "dispatch.alpha.lock.meta.json")
            dead = os.path.join(root, "dispatch.dead.lock.meta.json")
            log = os.path.join(logs, "job.json")
            with open(meta, "w", encoding="utf-8") as f:
                json.dump({"pid": os.getpid(), "agent": "codex", "acquired_at": 100.0,
                           "unlisted": "drop"}, f)
            with open(dead, "w", encoding="utf-8") as f:
                json.dump({"pid": 99999999, "agent": "ghost", "acquired_at": 100.0}, f)
            with open(log, "w", encoding="utf-8") as f:
                json.dump({"agent": "codex", "model": "label", "outcome": "completed",
                           "outcome_reason": "exit", "exit_code": 0, "duration_s": 25.0,
                           "started_at": 100.0, "job_id": "job-1", "unlisted": "drop"}, f)
            os.utime(log, (200.0, 200.0))
            # A dispatcher-measured record (mcs-103). Its mtime is set so the OLD
            # inference would say 75.0 — if wait_s still comes back 75.0 here, the
            # measured fields are being ignored.
            measured = os.path.join(logs, "job2.json")
            with open(measured, "w", encoding="utf-8") as f:
                json.dump({"agent": "codex", "outcome": "completed",
                           "outcome_reason": "artifact_verified", "duration_s": 25.0,
                           "started_at": 100.0, "job_id": "job-2",
                           "lock_wait_s": 12.0, "claim_wait_s": 3.0}, f)
            os.utime(measured, (200.0, 200.0))
            # A record whose measured field is malformed must be DROPPED, never
            # silently fall back to the estimate (fail closed, as every other
            # field in this collector does).
            # `model: null` is what the dispatcher writes with no --model
            # override. It must be KEPT: rejecting it dropped 9 of 10 real
            # records and left the panel effectively blank.
            nomodel = os.path.join(logs, "job4.json")
            with open(nomodel, "w", encoding="utf-8") as f:
                json.dump({"agent": "codex", "model": None, "outcome": "completed",
                           "outcome_reason": "artifact_verified", "duration_s": 5.0,
                           "started_at": 100.0, "job_id": "job-4",
                           "lock_wait_s": 1.0, "claim_wait_s": 0.0}, f)
            os.utime(nomodel, (200.0, 200.0))
            # Non-finite waits must be dropped. `1e309` is legal JSON that
            # Python parses to inf; json.dumps would then emit the bare token
            # `Infinity`, which a browser's JSON.parse rejects — one bad record
            # would take out the whole panel instead of dropping itself.
            inf = os.path.join(logs, "job5.json")
            with open(inf, "w", encoding="utf-8") as f:
                f.write('{"agent": "codex", "outcome": "completed", '
                        '"outcome_reason": "exit", "duration_s": 5.0, '
                        '"started_at": 100.0, "job_id": "job-5", '
                        '"lock_wait_s": 1e309, "claim_wait_s": 0.0}')
            os.utime(inf, (200.0, 200.0))
            # Two FINITE operands whose SUM overflows to inf — validating the
            # inputs alone does not catch this.
            ovf = os.path.join(logs, "job6.json")
            with open(ovf, "w", encoding="utf-8") as f:
                f.write('{"agent": "codex", "outcome": "completed", '
                        '"outcome_reason": "exit", "duration_s": 5.0, '
                        '"started_at": 100.0, "job_id": "job-6", '
                        '"lock_wait_s": 1e308, "claim_wait_s": 1e308}')
            os.utime(ovf, (200.0, 200.0))
            # NaN sails through any bare `< 0` guard, because every comparison
            # against it is False.
            nan = os.path.join(logs, "job7.json")
            with open(nan, "w", encoding="utf-8") as f:
                f.write('{"agent": "codex", "outcome": "completed", '
                        '"outcome_reason": "exit", "duration_s": 5.0, '
                        '"started_at": 100.0, "job_id": "job-7", '
                        '"lock_wait_s": NaN, "claim_wait_s": 0.0}')
            os.utime(nan, (200.0, 200.0))
            # Same non-finite hole in the PRE-EXISTING duration_s check: it
            # validated `>= 0` but not finiteness, so an inf duration would have
            # serialised as `Infinity` through a neighbouring field.
            infdur = os.path.join(logs, "job8.json")
            with open(infdur, "w", encoding="utf-8") as f:
                f.write('{"agent": "codex", "outcome": "completed", '
                        '"outcome_reason": "exit", "duration_s": 1e309, '
                        '"started_at": 100.0, "job_id": "job-8"}')
            os.utime(infdur, (200.0, 200.0))
            bad = os.path.join(logs, "job3.json")
            with open(bad, "w", encoding="utf-8") as f:
                json.dump({"agent": "codex", "outcome": "completed",
                           "outcome_reason": "exit", "duration_s": 25.0,
                           "started_at": 100.0, "job_id": "job-3",
                           "lock_wait_s": -1.0}, f)
            os.utime(bad, (200.0, 200.0))
            # asm-011: a record LARGER than the retired 128 KB cap. On the real
            # corpus that cap hid 62% of all dispatches — 136 codex records
            # against 0 antigravity, because size here is ~97% `stdout` and how
            # chatty stdout is tracks which agent ran and for how long. So this
            # is not a sampling fixture: it is the fixture that goes red if
            # anyone reinstates a cap small enough to select by agent again.
            # The padding rides in `stdout`, which is NOT allowlisted, so a pass
            # also proves the big field never reaches the payload.
            big = os.path.join(logs, "job9.json")
            with open(big, "w", encoding="utf-8") as f:
                json.dump({"agent": "codex", "outcome": "completed",
                           "outcome_reason": "backend_error", "duration_s": 900.0,
                           "started_at": 100.0, "job_id": "job-9",
                           "lock_wait_s": 2.0, "claim_wait_s": 0.0,
                           "stdout": "x" * (400 * 1024)}, f)
            os.utime(big, (300.0, 300.0))
            old_root = monitor.CLI_BRIDGE_ROOT
            monitor.CLI_BRIDGE_ROOT = root
            monitor._cli_recent_cache.clear()
            try:
                bridge = monitor.collect_cli_bridge()
                # Cold vs warm must agree byte for byte. The cache is keyed on
                # (path, mtime, size) and dispatch logs are written once with
                # O_EXCL, so a hit that disagreed would mean the immutability
                # assumption underneath the key had stopped holding.
                warm = monitor.collect_cli_bridge()
                parses = []
                real_entry = monitor._bridge_recent_entry
                monitor._bridge_recent_entry = lambda *a: (parses.append(a), real_entry(*a))[1]
                try:
                    warm2 = monitor.collect_cli_bridge()
                finally:
                    monitor._bridge_recent_entry = real_entry
                # Caching hands the SAME dict back on every hit, which is a
                # hazard this collector did not have before: one consumer that
                # mutated a row in place would poison every later poll. Rows are
                # copied on the way out; poisoning a returned payload proves it.
                poisoned = monitor.collect_cli_bridge()
                for row in poisoned.get("recent") or []:
                    row["agent"], row["wait_s"] = "MUTATED", -1.0
                after_poison = monitor.collect_cli_bridge()
                # A sanity ceiling low enough to reject every fixture proves the
                # count, without writing a 16 MB file to prove the constant.
                real_cap = monitor._CLI_FILE_SANITY_BYTES
                monitor._CLI_FILE_SANITY_BYTES = 64
                try:
                    tiny = monitor.collect_cli_bridge()
                finally:
                    monitor._CLI_FILE_SANITY_BYTES = real_cap
                # asm-011 / codex review F3: the early `break` at
                # _CLI_RECENT_CAP is what makes `scanned` a PARTIAL window, and
                # nothing tested it — with only 4 valid fixtures against a cap of
                # 12, deleting the break left every assertion green. Lowering the
                # cap tests the break itself rather than the number 12, and it
                # pins the claim the payload makes: `scanned` stops when `recent`
                # fills, so it is a window, not a corpus total.
                real_recent = monitor._CLI_RECENT_CAP
                monitor._CLI_RECENT_CAP = 2
                try:
                    capped = monitor.collect_cli_bridge()
                finally:
                    monitor._CLI_RECENT_CAP = real_recent
                # codex review F1: a file swapped for a link behind a matching
                # mtime/size must fail closed even on a warm cache, which never
                # re-enters _bridge_json. Simulated at the scandir flag, the one
                # place the screen can run before the cache lookup.
                real_cands = monitor._bridge_candidates
                monitor._bridge_candidates = lambda pattern, cap: [
                    (m, s, True, p) if os.sep + "log" + os.sep in p else (m, s, l, p)
                    for m, s, l, p in real_cands(pattern, cap)]
                try:
                    linked = monitor.collect_cli_bridge()
                finally:
                    monitor._bridge_candidates = real_cands
                # codex review F1, second half: the fixture above simulates the
                # FLAG, so it cannot see whether the flag is computed correctly.
                # On Windows a junction is the reparse point this repo's own
                # CLAUDE.md warns about, and `is_symlink()` returns False for one
                # — so reading `st_file_attributes` is not a portability nicety,
                # it is the only form that catches the real case. Exercised on
                # stand-ins because a junction-to-a-file cannot be created
                # portably (junctions are directory-only; file symlinks need
                # privilege).
                class _Stat:
                    def __init__(self, attrs):
                        if attrs is not None:
                            self.st_file_attributes = attrs
                class _Entry:
                    def __init__(self, sym):
                        self.sym = sym
                    def is_symlink(self):
                        return self.sym
                link_cases = [((0x400 | 0x20), False, True,  "reparse bit set, is_symlink False (a junction)"),
                              (0x20,          True,  False, "no reparse bit: attributes win over is_symlink"),
                              (None,          True,  True,  "no attributes (posix): fall back to is_symlink"),
                              (None,          False, False, "no attributes, not a link")]
                # Fail-closed path: no cli_bridge root at all. It must still
                # report a skip breakdown — a consumer that has to tell "absent"
                # apart from "zero" is back to guessing what it is not seeing.
                monitor.CLI_BRIDGE_ROOT = os.path.join(root, "no-such-dir")
                closed = monitor.collect_cli_bridge()
            finally:
                monitor.CLI_BRIDGE_ROOT = old_root
        if set(closed.get("skipped") or {}) != {"scanned", "oversize", "unreadable", "invalid"}:
            raise AssertionError("the fail-closed snapshot must carry the skip "
                                 "breakdown too: %r" % (closed.get("skipped"),))
        for attrs, sym, want, why in link_cases:
            got = monitor._bridge_entry_is_link(_Stat(attrs), _Entry(sym))
            if got is not want:
                raise AssertionError("link detection wrong (%s): got %r want %r" % (why, got, want))
        if len(capped.get("recent") or []) != 2 or (capped.get("skipped") or {}).get("scanned") != 2:
            raise AssertionError("the collector must stop scanning once `recent` is "
                                 "full — that early break is what makes `scanned` a "
                                 "window rather than a corpus total: %r / %r"
                                 % (len(capped.get("recent") or []), capped.get("skipped")))
        if (linked.get("recent") or []) or (linked.get("skipped") or {}).get("unreadable") != 9:
            raise AssertionError("a link/reparse candidate must fail closed BEFORE the "
                                 "cache lookup and be counted unreadable: %r"
                                 % (linked.get("skipped"),))
        if json.dumps(warm, sort_keys=True) != json.dumps(bridge, sort_keys=True):
            raise AssertionError("a cache hit must reproduce the cold payload exactly")
        if parses:
            raise AssertionError("a warm scan re-parsed %d record(s); the parse "
                                 "cache is not being consulted" % len(parses))
        if warm2 != warm:
            raise AssertionError("instrumented warm scan diverged")
        if json.dumps(after_poison, sort_keys=True) != json.dumps(bridge, sort_keys=True):
            raise AssertionError("a consumer mutating a returned row corrupted the "
                                 "parse cache; rows must be copied out of it")
        skipped = bridge.get("skipped") or {}
        if set(skipped) != {"scanned", "oversize", "unreadable", "invalid"}:
            raise AssertionError("every collection must report a skip breakdown, "
                                 "zeros included: got %r" % (skipped,))
        if skipped.get("invalid") != 5 or skipped.get("scanned") != 9:
            raise AssertionError("the 5 malformed fixtures must be COUNTED as "
                                 "skipped, not silently discarded: %r" % (skipped,))
        if skipped.get("oversize") != 0:
            raise AssertionError("nothing here exceeds the sanity ceiling")
        tiny_skip = tiny.get("skipped") or {}
        if tiny_skip.get("oversize") != 9 or (tiny.get("recent") or []):
            raise AssertionError("records rejected by the sanity ceiling must be "
                                 "counted and reported: %r" % (tiny_skip,))
        recent = bridge.get("recent") or []
        if len(bridge.get("now_running") or []) != 1 or len(recent) != 4:
            raise AssertionError("live PID gate, valid records, or negative-wait "
                                 "drop failed (got %d recent)" % len(recent))
        allowed = set(monitor._CLI_ALLOWED_RECENT) | {"wait_s", "wait_source"}
        by_job = {r.get("job_id"): r for r in recent}
        legacy, meas = by_job.get("job-1"), by_job.get("job-2")
        if legacy is None or meas is None:
            raise AssertionError("expected both a legacy and a measured record")
        if set(legacy) - allowed or set(meas) - allowed:
            raise AssertionError("allowlist failed")
        if legacy.get("wait_s") != 75.0 or legacy.get("wait_source") != "estimated":
            raise AssertionError("legacy record must keep the mtime estimate")
        if meas.get("wait_s") != 15.0 or meas.get("wait_source") != "measured":
            raise AssertionError("a record carrying lock_wait_s must report the "
                                 "MEASURED wait (12+3), not the 75.0 inference")
        oversize = by_job.get("job-9")
        if oversize is None:
            raise AssertionError("a record above the retired 128 KB cap must now "
                                 "reach the panel — that cap selected by agent "
                                 "and duration, it did not sample (asm-011)")
        if "stdout" in oversize:
            raise AssertionError("the allowlist must still exclude stdout")
        if oversize.get("outcome_reason") != "backend_error":
            raise AssertionError("the backend_error the old cap hid must survive")
        nomodel = by_job.get("job-4")
        if nomodel is None or nomodel.get("wait_s") != 1.0:
            raise AssertionError("model: null is a valid record (no --model "
                                 "override) and must NOT be dropped")
        if "model" in nomodel and nomodel["model"] is not None:
            raise AssertionError("a null model must stay null, not be coerced")
        for gone in ("job-5", "job-6", "job-7", "job-8"):
            if gone in by_job:
                raise AssertionError("non-finite wait (%s) must be dropped, not "
                                     "serialised as Infinity/NaN" % gone)
        # The whole payload must be real JSON that a browser can parse.
        blob = json.dumps(bridge)
        if "Infinity" in blob or "NaN" in blob:
            raise AssertionError("payload contains a non-JSON numeric token")
        # The top-level wait_s must not travel without its provenance.
        if bridge.get("wait_source") != recent[0].get("wait_source"):
            raise AssertionError("top-level wait_s and wait_source must agree "
                                 "with the newest row")
    except (AssertionError, OSError, ValueError, TypeError) as e:
        record("FAIL", "check-office-data", str(e))
        return False
    # The read-only guard's SCOPE is derived from the D5 call graph, not from a
    # hand-kept list. Codex review of this change (F2) caught the failure mode
    # the list had: `_bridge_candidates` was edited here and was not on it, and
    # nothing could notice — a name missing from a list of things-to-check is
    # invisible to every check in the list. Walking `_bridge_*` callees from the
    # collector root means a helper cannot be added, or code moved into one,
    # without the guard following it.
    names, frontier = set(), ["collect_cli_bridge"]
    while frontier:
        fn = frontier.pop()
        if fn in names:
            continue
        names.add(fn)
        frontier.extend(name for name in re.findall("(_bridge_[a-z_]+)[(]", _function_segment(fn)[1])
                        if hasattr(monitor, name))
    if len(names) < 5:
        record("FAIL", "check-office-data",
               "D5 call-graph walk found only %d function(s) — the walk is broken, "
               "not the collector" % len(names))
        return False
    writers = sorted(n for n in names if _d5_has_write_call(_function_segment(n)[1]))
    if writers:
        record("FAIL", "check-office-data",
               "D5 collector contains a write/delete call: " + ", ".join(writers))
        return False
    # The parse cache is trimmed to the keys the current scan touched, so it has
    # to be able to hold more than one scan's worth. At _CLI_PARSE_CACHE_CAP <=
    # _CLI_LOG_CANDIDATE_CAP it would trim on every pass and silently degrade to
    # no cache at all — slower, never wrong, and therefore invisible.
    if monitor._CLI_PARSE_CACHE_CAP <= monitor._CLI_LOG_CANDIDATE_CAP:
        record("FAIL", "check-office-data",
               "_CLI_PARSE_CACHE_CAP (%d) must exceed _CLI_LOG_CANDIDATE_CAP (%d)"
               % (monitor._CLI_PARSE_CACHE_CAP, monitor._CLI_LOG_CANDIDATE_CAP))
        return False
    _node, bridge_seg = _function_segment("collect_cli_bridge")
    _node, entry_seg = _function_segment("_bridge_recent_entry")
    handler_seg = read_text(MONITOR)
    if ("dispatch*.lock.meta.json" not in bridge_seg or "_bridge_pid_live" not in bridge_seg
            or "_CLI_ALLOWED_RECENT" not in entry_seg or "collect_cli_bridge()" not in handler_seg
            or "_CLI_FILE_SANITY_BYTES" not in bridge_seg
            or 'route == "/api/cli-bridge"' not in handler_seg):
        record("FAIL", "check-office-data", "D5 route/allowlist/fail-closed structure missing")
        return False
    record("PASS", "check-office-data", "D1--D5 fixtures, allowlist, PID gate, wait formula, read-only AST")
    return True


def cmd_check_signal_desk_contract():
    """Freeze Signal Desk identity/reason fields with no live source access."""
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    import monitor
    required = ("_spawn_identity_by_session", "enrich_office_rows", "_work_kind_for_local")
    missing = [name for name in required if not hasattr(monitor, name)]
    if missing:
        record("FAIL", "check-signal-desk-contract", "missing: " + ", ".join(missing))
        return False
    contract = read_text(DATA_CONTRACTS)
    required_contract = ("## D6 — Signal Desk display identity and routing provenance",
                         "`agent_idx`", "`work_reason`", "`status_stopped`",
                         "A<agent_idx + 1>", "Stopped zone")
    absent = [needle for needle in required_contract if needle not in contract]
    if absent:
        record("FAIL", "check-signal-desk-contract",
               "data contract missing: " + ", ".join(absent))
        return False
    seen_sql = []

    class SpawnCursor:
        def fetchall(self):
            return [("known-parent", "launch-1", 0), ("known-stopped", "launch-1", 1),
                    ("bad-index", "launch-2", -1)]

    class SpawnConn:
        def execute(self, sql):
            seen_sql.append(sql)
            return SpawnCursor()

        def close(self):
            return None

    old_db_conn = monitor.db_conn
    old_tail = monitor.claude_live_tail
    try:
        monitor.db_conn = lambda: SpawnConn()
        provenance = monitor._spawn_identity_by_session()
        if (provenance != {"known-parent": {"launch_id": "launch-1", "agent_idx": 0},
                           "known-stopped": {"launch_id": "launch-1", "agent_idx": 1}} or
                not seen_sql or "agent_idx" not in seen_sql[0]):
            raise AssertionError("spawn provenance must retain only verified non-negative agent_idx")
        monitor.claude_live_tail = lambda _path: {"tool": "edit", "tool_done": False,
                                                   "target": "code.py"}
        now = 9000.0
        parent = {"session_id": "known-parent", "status": "running", "source_ai": "claude",
                  "_office_path": "fixture-parent.jsonl"}
        stopped = {"session_id": "known-stopped", "status": "stopped", "source_ai": "claude",
                   "_office_path": "fixture-stopped.jsonl"}
        remote = {"session_id": "remote-parent", "status": "running", "source_ai": "claude"}
        monitor.enrich_office_rows({}, [parent, stopped], now, True, provenance)
        monitor.enrich_office_rows({}, [remote], now, False,
                                   {"remote-parent": {"launch_id": "must-not-leak", "agent_idx": 9}})
        if not (parent.get("launch_id") == "launch-1" and parent.get("agent_idx") == 0 and
                parent.get("group_key") == "launch-1" and parent.get("work_kind") == "working" and
                parent.get("work_reason") == "active_tail"):
            raise AssertionError("known parent identity or active-tail reason failed")
        if not (stopped.get("session_id") == "known-stopped" and stopped.get("launch_id") == "launch-1" and
                stopped.get("agent_idx") == 1 and stopped.get("group_key") == "launch-1" and
                stopped.get("work_kind") == "standby" and stopped.get("work_reason") == "status_stopped"):
            raise AssertionError("stopped parent was not retained with explicit reason")
        if not (remote.get("session_id") == "remote-parent" and remote.get("group_key") == "remote-parent" and
                "agent_idx" not in remote and remote.get("work_kind") == "standby" and
                remote.get("work_reason") == "remote_no_live_tail"):
            raise AssertionError("remote fallback leaked local identity or reason")
    except (AssertionError, OSError, TypeError, ValueError) as e:
        record("FAIL", "check-signal-desk-contract", str(e))
        return False
    finally:
        monitor.db_conn = old_db_conn
        monitor.claude_live_tail = old_tail
    _node, enrich_seg = _function_segment("enrich_office_rows")
    _node, spawn_seg = _function_segment("_spawn_identity_by_session")
    for needle in ("work_reason", "status_stopped", "agent_idx"):
        if needle not in enrich_seg + spawn_seg:
            record("FAIL", "check-signal-desk-contract", "implementation missing: " + needle)
            return False
    record("PASS", "check-signal-desk-contract",
           "verified spawn ordinal provenance, conservative work reasons, and stopped identity retention")
    return True


def cmd_check_signal_desk_assets():
    """Fail closed when the Signal Desk portrait is detached or inaccessible."""
    ok = True
    try:
        with open(SIGNAL_DESK_HEAD, "rb") as f:
            header = f.read(24)
        if (len(header) != 24 or header[:8] != b"\x89PNG\r\n\x1a\n" or
                int.from_bytes(header[16:20], "big") < 32 or
                int.from_bytes(header[20:24], "big") < 32):
            raise ValueError("not a usable PNG")
        if os.path.getsize(SIGNAL_DESK_HEAD) < 1024:
            raise ValueError("asset is unexpectedly small")
    except (OSError, ValueError) as e:
        record("FAIL", "check-signal-desk-assets", "operator portrait: " + str(e))
        ok = False
    text = read_text(DASHBOARD)
    required = (
        "const SIGNAL_DESK_HEAD={claude:{src:'assets/signal-desk/operator-head-v1.png'",
        "function signalDeskHead(source)",
        '<img class="desk-head"',
        r'''alt="'+asset.alt+'"''',
        "signalDeskHead(r.src)",
        'class="srcname"',
        "sn.textContent=snm",
    )
    missing = [needle for needle in required if needle not in text]
    if "data:image" in text:
        missing.append("portrait must not be embedded as a data URL")
    # The HTML referencing the asset is not enough — the server must also route
    # /assets/ or the <img> 404s in a real browser (headless smoke on a fixture
    # server misses this). Assert monitor.py has a read-only assets route.
    monitor_src = read_text(MONITOR)
    if 'route.startswith("/assets/")' not in monitor_src:
        missing.append("monitor.py has no /assets/ route to serve ui/assets (img would 404)")
    if missing:
        record("FAIL", "check-signal-desk-assets", "missing/drift: " + ", ".join(missing))
        ok = False
    if ok:
        record("PASS", "check-signal-desk-assets",
               "real source-mapped PNG portrait, img alt text, and visible source label")
    return ok and node_check(DASHBOARD)


def cmd_check_kind():
    text = read_text(DASHBOARD)
    ok = "data-agent-kind" in text
    if ok:
        record("PASS", "check-kind", "data-agent-kind present in dashboard.html")
    else:
        record("FAIL", "check-kind",
               "data-agent-kind missing from dashboard.html (task not landed yet?)")
    return node_check(DASHBOARD) and ok


def cmd_check_cockpit():
    node, _seg = function_node("cockpit_cards")
    if node is None:
        record("FAIL", "check-cockpit", "cockpit_cards not found in monitor.py")
        return False
    calls = called_names(node)
    missing = [n for n in ("collect_hermes", "collect_antigravity") if n not in calls]
    if not missing:
        record("PASS", "check-cockpit",
               "cockpit_cards calls collect_hermes( and collect_antigravity(")
    else:
        record("FAIL", "check-cockpit",
               "cockpit_cards does not call: %s (task not landed yet?)"
               % ", ".join(missing))
    return check_import_monitor() and not missing


def cmd_check_srccolor():
    count = read_text(DASHBOARD).count("SRCCOLOR")
    if count >= 2:
        record("PASS", "check-srccolor", "SRCCOLOR x%d in dashboard.html" % count)
        ok = True
    else:
        record("FAIL", "check-srccolor",
               "SRCCOLOR x%d in dashboard.html, need >= 2 (task not landed yet?)"
               % count)
        ok = False
    return node_check(DASHBOARD) and ok


# ------------------------------------------------- B1 oracles for later tasks

AUTHZ_HTML = os.path.join(ROOT, "ui", "authz.html")

# XSS probe put into every agent-controlled field of the render fixtures.
_XSS = "<img src=x onerror=alert(1)>\"'"

DELVIEW_FIXTURE = [
    {"ts": "2026-07-20T00:00:00Z", "ts_epoch": 1786000000, "v": 2, "action": "block",
     "outcome": "blocked", "cmd_hash": "0123456789abcdef", "pattern": _XSS,
     "reason": _XSS, "cmd": _XSS, "agent": "main", "agent_id": _XSS,
     "repo": _XSS, "cwd": _XSS, "branch": _XSS, "capability": "v2"},
    {"ts": "2026-07-20T00:01:00Z", "ts_epoch": 1786000060, "v": 2, "action": "post",
     "outcome": "executed", "cmd_hash": "aaaabbbbccccdddd", "pattern": _XSS,
     "reason": _XSS, "cmd": _XSS, "agent": "sub", "agent_id": _XSS,
     "repo": _XSS, "cwd": _XSS, "branch": _XSS, "had_errors": True,
     "capability": "v1-legacy"},
]

AUTHZ_FIXTURE = [
    {"gate": "mass_delete", "repo": _XSS, "path": _XSS, "cmd": _XSS,
     "agent": "main", "agent_id": _XSS, "ts": "2026-07-20T00:00:00Z",
     "ts_epoch": 1786000000, "cmd_hash": "0123456789abcdef"},
]

TRANSCRIPT_FIXTURE = [
    {"role": "user", "text": _XSS, "tool": _XSS, "target": _XSS,
     "done": True, "ts": "2026-07-20T00:00:00Z"},
    {"role": "tool", "text": _XSS, "tool": _XSS, "target": _XSS,
     "done": False, "truncated": True, "ts": "2026-07-20T00:01:00Z"},
]

AVATAR_FIXTURE = {
    "claude": [{"session_id": "parent-a", "group_key": "launch-a",
                "vendor": _XSS, "label": _XSS, "task_current": _XSS,
                "status": "running", "subagents": 1,
                "mini_rows": [{"session_id": "parent-a/agent-1",
                               "vendor": "codex", "status": "stale"}]}],
    "codex": [], "hermes": [], "antigravity": [], "copilot": [],
}

# JS prelude: minimal DOM/browser stubs so page scripts run top-level under node.
# Every innerHTML/insertAdjacentHTML write is recorded in __SINKS; setAttribute
# of any on* attribute is recorded in __ATTR_BAD.
INERT_PRELUDE = r"""// generated by preflight_ui.py -- inert-render harness
var __SINKS = [];
var __ATTR_BAD = [];
var __DOC_LISTENERS = {};
function __fireDoc(type, event){
  var handlers = __DOC_LISTENERS[type] || [];
  for(var i=0;i<handlers.length;i++) handlers[i](event);
}
function __mkEl(tag){
  var el = {
    tagName: String(tag||'div').toUpperCase(),
    children: [], dataset: {}, style: {getPropertyValue:function(){return '';},setProperty:function(){}}, _text: '', _html: '', _attrs: {},
    classList: {add:function(){},remove:function(){},toggle:function(){},contains:function(){return false;}},
    setAttribute: function(n,v){ if(/^on/i.test(String(n))) __ATTR_BAD.push(String(n)); el._attrs[n]=String(v); },
    getAttribute: function(n){ return Object.prototype.hasOwnProperty.call(el._attrs,n)?el._attrs[n]:null; },
    removeAttribute: function(n){ delete el._attrs[n]; },
    appendChild: function(c){ el.children.push(c); return c; },
    append: function(){ for(var i=0;i<arguments.length;i++) el.children.push(arguments[i]); },
    prepend: function(){}, removeChild: function(){},
    replaceChildren: function(){ el.children=[]; },
    insertAdjacentHTML: function(_p,h){ __SINKS.push(String(h)); },
    addEventListener: function(){}, removeEventListener: function(){},
    querySelector: function(){ return __mkEl('div'); },
    querySelectorAll: function(){ return []; },
    closest: function(){ return null; },
    focus: function(){}, click: function(){}, remove: function(){}, scrollIntoView: function(){},
    getBoundingClientRect: function(){ return {top:0,left:0,width:0,height:0}; },
    contains: function(){ return false; }
  };
  Object.defineProperty(el,'innerHTML',{get:function(){return el._html;},set:function(v){el._html=String(v);__SINKS.push(String(v));}});
  Object.defineProperty(el,'outerHTML',{get:function(){return el._html;}});
  Object.defineProperty(el,'textContent',{get:function(){return el._text;},set:function(v){el._text=String(v);}});
  Object.defineProperty(el,'innerText',{get:function(){return el._text;},set:function(v){el._text=String(v);}});
  return el;
}
var __ids = {};
var document = {
  title: '', hidden: false, visibilityState: 'visible', cookie: '',
  body: __mkEl('body'), documentElement: __mkEl('html'), head: __mkEl('head'),
  createElement: function(t){ return __mkEl(t); },
  createTextNode: function(t){ return {nodeType:3, textContent:String(t)}; },
  createDocumentFragment: function(){ return __mkEl('#fragment'); },
  getElementById: function(id){ return __ids[id] || (__ids[id] = __mkEl('div')); },
  querySelector: function(){ return __mkEl('div'); },
  querySelectorAll: function(){ return []; },
  addEventListener: function(type, fn){ (__DOC_LISTENERS[type] || (__DOC_LISTENERS[type] = [])).push(fn); },
  removeEventListener: function(){}
};
var location = { search:'', href:'http://127.0.0.1/', pathname:'/', origin:'http://127.0.0.1', hash:'', reload:function(){} };
var localStorage = { _m:{}, getItem:function(k){return Object.prototype.hasOwnProperty.call(this._m,k)?this._m[k]:null;}, setItem:function(k,v){this._m[k]=String(v);}, removeItem:function(k){delete this._m[k];}, clear:function(){this._m={};} };
var sessionStorage = { getItem:function(){return null;}, setItem:function(){}, removeItem:function(){} };
var navigator = { userAgent:'preflight-harness', clipboard:{writeText:function(){return Promise.resolve();}} };
var history = { pushState:function(){}, replaceState:function(){} };
var window = { addEventListener:function(){}, removeEventListener:function(){}, location: location, localStorage: localStorage, innerWidth: 1280, innerHeight: 800, open:function(){}, focus:function(){}, matchMedia:function(){ return {matches:false, addEventListener:function(){}}; } };
var fetch = function(){ return new Promise(function(){}); };
var EventSource = function(){ return {addEventListener:function(){},close:function(){}}; };
var WebSocket = function(){ return {addEventListener:function(){},close:function(){},send:function(){}}; };
var MutationObserver = function(){ return {observe:function(){},disconnect:function(){}}; };
var Notification = function(){}; Notification.permission='denied'; Notification.requestPermission=function(){return Promise.resolve('denied');};
var getComputedStyle = function(){ return {getPropertyValue:function(){return '';}}; };
var requestAnimationFrame = function(){ return 0; };
var setInterval = function(){ return 0; }, setTimeout = function(){ return 0; };
var clearInterval = function(){}, clearTimeout = function(){};
var alert = function(){}, confirm = function(){ return false; }, prompt = function(){ return null; };
process.on('unhandledRejection', function(){});
"""

# Driver appended AFTER the page scripts. __FN__ / __ROWS__ substituted at run
# time. Page scripts are wrapped in one sloppy-mode try{} so a top-level throw
# cannot kill the driver (function declarations still publish via Annex B).
INERT_DRIVER = r"""
;(function(){
  var rows = __ROWS__;
  var fn = (typeof __FN__ === 'function') ? __FN__ : undefined;
  if (!fn) { console.log('PRECHECK_MISSING __FN__'); process.exit(3); }
  var start = __SINKS.length; __ATTR_BAD.length = 0;
  var out;
  try { out = fn(rows); }
  catch (e) { console.log('PRECHECK_THREW ' + (e && e.message ? e.message : e)); process.exit(4); }
  var sinks = __SINKS.slice(start);
  if (typeof out === 'string') sinks.push(out);
  var joined = sinks.join('\n');
  if (/<img/i.test(joined) || __ATTR_BAD.length) {
    console.log('PRECHECK_XSS_LEAK attrs=' + __ATTR_BAD.join(','));
    process.exit(5);
  }
  console.log('PRECHECK_INERT_OK sinks=' + sinks.length);
  process.exit(0);
})();
"""


def inert_render_check(html_path, fn_name, rows, name):
    """Run fn_name(rows) from html_path's scripts under a stub DOM in node and
    assert no raw <img / on*-attribute from the payload reaches an HTML sink."""
    label = "%s inert-render (%s)" % (name, fn_name)
    node = shutil.which("node")
    if not node:
        record("SKIP", label, "warning: node not on PATH, inert check skipped")
        return True
    blocks = extract_scripts(html_path)
    if not blocks:
        record("FAIL", label, "no inline <script> block in %s"
               % os.path.basename(html_path))
        return False
    driver = (INERT_DRIVER.replace("__FN__", fn_name)
              .replace("__ROWS__", json.dumps(rows, ensure_ascii=False)))
    code = (INERT_PRELUDE + "\ntry {\n" + "\n;\n".join(blocks)
            + "\n} catch (__e) { console.log('HARNESS_TOPLEVEL_ERR ' "
              "+ (__e && __e.message ? __e.message : __e)); }\n" + driver)
    fd, tmp = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(code)
        proc = subprocess.run([node, tmp], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    finally:
        os.unlink(tmp)
    out = (proc.stdout or "").strip()
    if proc.returncode == 0 and "PRECHECK_INERT_OK" in out:
        record("PASS", label, out.splitlines()[-1])
        return True
    if proc.returncode == 3:
        record("FAIL", label,
               "%s() not defined in page scripts (task not landed yet?)" % fn_name)
    elif proc.returncode == 5:
        record("FAIL", label, "payload leaked to an HTML sink: " + out)
    else:
        tail = (out + "\n" + (proc.stderr or "").strip()).strip().splitlines()
        record("FAIL", label, tail[-1] if tail else "harness exit %d" % proc.returncode)
    return False


def run_py_driver(code, name):
    """Run a functional fixture driver in a subprocess (cwd=ROOT) so this checker
    itself never imports monitor. Driver prints FAIL:/SKIPPART: lines + final OK."""
    fd, tmp = tempfile.mkstemp(suffix=".py")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(code)
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        proc = subprocess.run([sys.executable, tmp], cwd=ROOT, capture_output=True,
                              text=True, encoding="utf-8", errors="replace",
                              timeout=180, env=env)
    finally:
        os.unlink(tmp)
    out = (proc.stdout or "").strip()
    for line in out.splitlines():
        if line.startswith("SKIPPART:"):
            record("SKIP", name, line[len("SKIPPART:"):].strip())
    if proc.returncode == 0 and out.splitlines() and out.splitlines()[-1] == "OK":
        record("PASS", name, "functional fixture green")
        return True
    fails = [l for l in out.splitlines() if l.startswith("FAIL:")]
    if fails:
        record("FAIL", name, fails[-1][len("FAIL:"):].strip())
    else:
        tail = ((proc.stderr or "") + "\n" + out).strip().splitlines()
        record("FAIL", name, tail[-1] if tail else "driver exit %d" % proc.returncode)
    return False


DELETIONS_DRIVER = r'''
import datetime, json, os, shutil, sys, tempfile
sys.path.insert(0, os.getcwd())
import monitor

def fail(msg):
    print("FAIL: " + msg)
    sys.exit(1)

if not hasattr(monitor, "collect_delete_events"):
    fail("collect_delete_events not defined in monitor.py (task not landed yet?)")

tmp = tempfile.mkdtemp(prefix="pfdel_")
try:
    repo = os.path.join(tmp, "fakerepo")
    st = os.path.join(repo, ".claude", "_state")
    os.makedirs(st)
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rich = {"ts": now_iso, "v": 2, "action": "block", "outcome": "blocked",
            "cmd_hash": "0123456789abcdef", "pattern": "mass_delete",
            "reason": "destructive_delete_blocked", "cmd": "rm -rf src",
            "agent": "main", "agent_id": "", "repo": "fakerepo",
            "cwd": repo.replace("\\", "/"), "branch": "main"}
    lines = [
        json.dumps({"ts": now_iso, "reason": "destructive_delete_blocked",
                    "cmd": "rm -rf /tmp/x"}),
        json.dumps(rich),
        json.dumps({"ts": now_iso, "reason": "overwrite_existing_design",
                    "cmd": "cp a b"}),
        "this is not json {{{",
    ]
    with open(os.path.join(st, "hook_block_history.jsonl"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    cfg = {"workspace_roots": [tmp], "max_rows_per_source": 50, "max_age_hours": 6}
    res = monitor.collect_delete_events(cfg)
    rows = res if isinstance(res, list) else (res.get("rows") or res.get("events") or [])
    if len(rows) != 2:
        fail("expected 2 rows (1 legacy + 1 rich), got %d" % len(rows))
    for r in rows:
        blob = (str(r.get("reason", "")) + " " + str(r.get("pattern", ""))).lower()
        if "overwrite" in blob:
            fail("overwrite row leaked into results: %s" % ascii(r))
    match = [r for r in rows if r.get("cmd_hash") == "0123456789abcdef"]
    if not match:
        fail("rich v2 row missing or cmd_hash not passed through")
    r = match[0]
    for key, want in (("pattern", "mass_delete"), ("branch", "main"),
                      ("outcome", "blocked"), ("agent", "main")):
        if r.get(key) != want:
            fail("rich row field %s=%s, want %s" % (key, ascii(r.get(key)), want))
    print("OK")
finally:
    shutil.rmtree(tmp, ignore_errors=True)
'''


TRANSCRIPT_DRIVER = r'''
import json
import os
import shutil
import sys
import tempfile
sys.path.insert(0, os.getcwd())
import monitor

tmp = tempfile.mkdtemp(prefix="pftranscript_")
try:
    project = os.path.join(tmp, "fixture-project")
    os.makedirs(project)
    sid = "abcd1234"
    path = os.path.join(project, sid + ".jsonl")
    long_text = "x" * 2051
    rows = [
        {"type": "user", "timestamp": "2026-07-20T00:00:00Z",
         "message": {"role": "user", "content": "hello"}},
        {"type": "assistant", "timestamp": "2026-07-20T00:00:01Z",
         "message": {"role": "assistant", "content": [
             {"type": "text", "text": "working"},
             {"type": "tool_use", "id": "tool-1", "name": "Read",
              "input": {"file_path": "C:/safe.txt"}}]}},
        {"type": "user", "timestamp": "2026-07-20T00:00:02Z",
         "message": {"role": "user", "content": [
             {"type": "tool_result", "tool_use_id": "tool-1", "content": "ok"}]}},
        {"type": "assistant", "timestamp": "2026-07-20T00:00:03Z",
         "message": {"role": "assistant", "content": [{"type": "text", "text": long_text}]}},
        {"type": "user", "timestamp": "2026-07-20T00:00:04Z",
         "message": {"role": "user", "content": "<img src=x onerror=alert(1)>"}},
    ]
    with open(path, "w", encoding="utf-8") as f:
        for row in rows[:2]:
            f.write(json.dumps(row) + "\n")
        f.write("{bad json}\n")
        for row in rows[2:]:
            f.write(json.dumps(row) + "\n")
    cfg = {"claude_projects": [tmp], "codex_session_index": []}
    got = monitor.session_transcript(cfg, sid, None, 999)
    if got.get("source") != "claude" or len(got.get("turns") or []) > 60:
        raise RuntimeError("source/limit contract failed")
    if not isinstance(got.get("cursor"), str) or not got["cursor"].isdigit():
        raise RuntimeError("cursor is not a byte offset")
    tool = next((x for x in got["turns"] if x.get("tool") == "Read"), None)
    if not tool or not tool.get("done") or tool.get("target") != "C:/safe.txt":
        raise RuntimeError("tool result did not complete tool_use")
    if not any(x.get("truncated") for x in got["turns"]):
        raise RuntimeError("large text was not marked truncated")
    if not any(x.get("text") == "<img src=x onerror=alert(1)>" for x in got["turns"]):
        raise RuntimeError("payload was changed instead of passed to inert UI")
    if not monitor.session_transcript(cfg, sid, "not-a-cursor", 60).get("error"):
        raise RuntimeError("bad cursor was accepted")
    print("OK")
finally:
    shutil.rmtree(tmp, ignore_errors=True)
'''


AUTHZ_DRIVER = r'''
import datetime, json, os, shutil, subprocess, sys, tempfile
sys.path.insert(0, os.getcwd())
import monitor

def fail(msg):
    print("FAIL: " + msg)
    sys.exit(1)

for name in ("AUTHZ_GATES", "collect_authz_pending", "_authz_request_rows",
             "_authz_repo_map", "ops_authorize"):
    if not hasattr(monitor, name):
        fail(name + " not defined in monitor.py (task not landed yet?)")
with open("monitor.py", "r", encoding="utf-8", errors="replace") as f:
    if "/api/ops/authorize" not in f.read():
        fail("/api/ops/authorize route missing from monitor.py")
if not os.path.exists("CONTEXT.md"):
    fail("CONTEXT.md missing")
with open("CONTEXT.md", "r", encoding="utf-8", errors="replace") as f:
    if "ADR-005" not in f.read():
        fail("CONTEXT.md lacks ADR-005 (authz trust-domain ADR)")

CH = "fedcba9876543210"

def v2_blocked_line(repo_dir):
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return json.dumps({"ts": now_iso, "v": 2, "action": "block", "outcome": "blocked",
                       "cmd_hash": CH, "pattern": "mass_delete",
                       "reason": "destructive_delete_blocked", "cmd": "rm -rf src",
                       "agent": "main", "agent_id": "",
                       "repo": os.path.basename(repo_dir),
                       "cwd": repo_dir.replace("\\", "/"), "branch": "main"}) + "\n"

def make_repo(root, name):
    repo = os.path.join(root, name)
    st = os.path.join(repo, ".claude", "_state")
    os.makedirs(st)
    with open(os.path.join(st, "hook_block_history.jsonl"), "w", encoding="utf-8") as f:
        f.write(v2_blocked_line(repo))
    return repo, st

def repo_id_for(mapping, repo):
    want = os.path.normcase(os.path.realpath(repo))
    items = mapping.items() if isinstance(mapping, dict) else []
    for k, v in items:
        p = ""
        if isinstance(v, str):
            p = v
        elif isinstance(v, dict):
            p = v.get("path") or v.get("root") or v.get("repo") or ""
        if p and os.path.normcase(os.path.realpath(p)) == want:
            return k
    return None

def rejected(res):
    if not isinstance(res, dict):
        return True
    return res.get("code", 200) >= 400 or res.get("ok") is False

tmp = tempfile.mkdtemp(prefix="pfauthz_")
try:
    root1 = os.path.join(tmp, "root1")
    os.makedirs(root1)
    repo, st = make_repo(root1, "fakerepo")
    cfg = {"workspace_roots": [root1], "max_rows_per_source": 50, "max_age_hours": 6}
    rid = repo_id_for(monitor._authz_repo_map(cfg), repo)
    if rid is None:
        fail("_authz_repo_map did not discover the fixture repo")
    marker = os.path.join(st, "authz_mass_delete_oneshot")

    res = monitor.ops_authorize(cfg, {"id": "../../../evil", "gate": "mass_delete"})
    if not rejected(res):
        fail("traversal id was NOT rejected")
    res = monitor.ops_authorize(cfg, {"id": rid, "gate": "frobnicate"})
    if not rejected(res):
        fail("unknown gate was NOT rejected")
    if os.path.exists(marker):
        fail("a negative case wrote a marker file")

    root2 = os.path.join(tmp, "root2")
    os.makedirs(root2)
    real2, st2 = make_repo(tmp, "real2")
    link = os.path.join(root2, "linked")
    link_ok = False
    try:
        if os.name == "nt":
            r = subprocess.run(["cmd", "/c", "mklink", "/J", link, real2],
                               capture_output=True, timeout=30)
            link_ok = r.returncode == 0 and os.path.isdir(link)
        else:
            os.symlink(real2, link)
            link_ok = True
    except OSError:
        link_ok = False
    if link_ok:
        cfg2 = {"workspace_roots": [root2], "max_rows_per_source": 50, "max_age_hours": 6}
        rid2 = repo_id_for(monitor._authz_repo_map(cfg2), link)
        if rid2 is None:
            mapping2 = monitor._authz_repo_map(cfg2)
            keys = list(mapping2.keys()) if isinstance(mapping2, dict) else []
            rid2 = keys[0] if len(keys) == 1 else None
        if rid2 is not None:
            res = monitor.ops_authorize(cfg2, {"id": rid2, "gate": "mass_delete"})
            if not rejected(res):
                fail("realpath-divergent (junction/symlink) repo was NOT rejected")
            if os.path.exists(os.path.join(st2, "authz_mass_delete_oneshot")):
                fail("junction case wrote a marker file")
        else:
            print("SKIPPART: junction repo not in _authz_repo_map; realpath sub-check skipped")
    else:
        print("SKIPPART: cannot create junction/symlink here; realpath sub-check skipped")

    res = monitor.ops_authorize(cfg, {"id": rid, "gate": "mass_delete"})
    if rejected(res):
        fail("valid authorize was rejected: %s" % ascii(res))
    if not os.path.exists(marker):
        fail("marker authz_mass_delete_oneshot not written into the repo _state")
    with open(marker, "r", encoding="utf-8") as f:
        mk = json.load(f)
    if mk.get("cmd_hash") != CH:
        fail("marker cmd_hash=%s, want %s" % (ascii(mk.get("cmd_hash")), CH))
    if mk.get("gate") != "mass_delete":
        fail("marker gate=%s, want mass_delete" % ascii(mk.get("gate")))
    print("OK")
finally:
    shutil.rmtree(tmp, ignore_errors=True)
'''


def cmd_check_copilot():
    node, _seg = function_node("collect_copilot")
    if node is None:
        record("FAIL", "check-copilot",
               "collect_copilot not found in monitor.py (task not landed yet?)")
        return False
    ok = True
    _bs, bs_seg = function_node("build_status")
    if _bs is None or "copilot" not in bs_seg:
        record("FAIL", "check-copilot", 'build_status has no "copilot" section')
        ok = False
    cc, _ = function_node("cockpit_cards")
    if cc is None or "collect_copilot" not in called_names(cc):
        record("FAIL", "check-copilot", "cockpit_cards does not call collect_copilot(")
        ok = False
    if ok:
        record("PASS", "check-copilot",
               "collect_copilot wired into build_status + cockpit_cards")
    return check_import_monitor() and ok


def cmd_check_copilot_ui():
    text = read_text(DASHBOARD)
    src_m = re.search(r"\bSRC\s*=\s*\[[\s\S]*?\]\s*;", text)
    col_m = re.search(r"\bSRCCOLOR\s*=\s*\{[\s\S]*?\}", text)
    ok = True
    if not (src_m and "copilot" in src_m.group(0)):
        record("FAIL", "check-copilot-ui",
               "SRC literal lacks copilot (task not landed yet?)")
        ok = False
    if not (col_m and "copilot" in col_m.group(0)):
        record("FAIL", "check-copilot-ui",
               "SRCCOLOR literal lacks copilot (task not landed yet?)")
        ok = False
    if ok:
        record("PASS", "check-copilot-ui", "SRC + SRCCOLOR both include copilot")
    return node_check(DASHBOARD) and ok


def cmd_check_deletions():
    if "/api/deletions" not in read_text(MONITOR):
        record("FAIL", "check-deletions",
               "/api/deletions route missing from monitor.py (task not landed yet?)")
        return False
    return run_py_driver(DELETIONS_DRIVER, "check-deletions")


def cmd_check_delview():
    text = read_text(DASHBOARD)
    ok = True
    if "deletions" not in text:
        record("FAIL", "check-delview",
               'no "deletions" view wiring in dashboard.html (task not landed yet?)')
        ok = False
    inert = inert_render_check(DASHBOARD, "renderDeletions", DELVIEW_FIXTURE,
                               "check-delview")
    return node_check(DASHBOARD) and inert and ok


DELETIONS_READONLY_DRIVER = r"""
;(async function(){
  var renderRows=globalThis.__precheckRenderDeletions;
  var renderView=globalThis.__precheckRenderDeletionsView;
  var outcomeBadge=globalThis.__precheckDelOutcomeBadge;
  if(typeof renderRows !== 'function' || typeof renderView !== 'function' || typeof outcomeBadge !== 'function'){
    console.log('PRECHECK_DELETIONS_READONLY_MISSING'); process.exit(3);
  }
  var output=renderRows(__ROWS__,[]);
  if(output.indexOf('hook 記錄為已執行的 shell 命令（不是本 dashboard 發起）')<0 ||
     outcomeBadge('blocked').indexOf('攔截')<0 || outcomeBadge('attempt').indexOf('嘗試')<0){
    console.log('PRECHECK_DELETIONS_SEMANTICS_FAIL'); process.exit(4);
  }
  var calls=[];
  fetch=function(url, options){calls.push({url:String(url), hasOptions:arguments.length>1, options:options});return Promise.resolve({json:function(){return Promise.resolve({rows:__ROWS__,repos:[]});}});};
  await renderView(true);
  if(calls.length!==1 || calls[0].url!=='/api/deletions' || calls[0].hasOptions){
    console.log('PRECHECK_DELETIONS_FETCH_FAIL'); process.exit(5);
  }
  console.log('PRECHECK_DELETIONS_READONLY_OK'); process.exit(0);
})();
"""


def deletions_readonly_fixture_check():
    """Execute the Deletions renderer and assert its fetch remains a bare GET."""
    node = shutil.which("node")
    if not node:
        record("FAIL", "check-deletions-readonly fixture", "node is required for read-only fixture")
        return False
    blocks = extract_scripts(DASHBOARD)
    code = (INERT_PRELUDE + "\ntry {\n" + "\n;\n".join(blocks)
            + "\n;globalThis.__precheckRenderDeletions=renderDeletions;"
            + "globalThis.__precheckRenderDeletionsView=renderDeletionsView;"
            + "globalThis.__precheckDelOutcomeBadge=delOutcomeBadge;"
            + "\n} catch (__e) { console.log('HARNESS_TOPLEVEL_ERR ' "
            + "+ (__e && __e.message ? __e.message : __e)); }\n"
            + DELETIONS_READONLY_DRIVER.replace("__ROWS__", json.dumps(DELVIEW_FIXTURE,
                                                                   ensure_ascii=False)))
    fd, tmp = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(code)
        proc = subprocess.run([node, tmp], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    finally:
        os.unlink(tmp)
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode == 0 and "PRECHECK_DELETIONS_READONLY_OK" in out:
        record("PASS", "check-deletions-readonly fixture",
               "executed-hook disclosure and bare GET /api/deletions verified")
        return True
    record("FAIL", "check-deletions-readonly fixture",
           out.splitlines()[-1] if out else "harness exit %d" % proc.returncode)
    return False


def cmd_check_deletions_readonly():
    """Fail closed if the Deletions dashboard section gains destructive wiring."""
    text = read_text(DASHBOARD)
    start = text.find("function renderDeletions")
    end = text.find("// ---- recap view", start)
    section = text[start:end] if start >= 0 and end >= 0 else ""
    missing = []
    if not section:
        missing.append("Deletions renderer/fetch section")
    elif "fetch('/api/deletions'" not in section:
        missing.append("GET /api/deletions fetch")
    forbidden = (
        (r"\bopsPost\s*\(", "opsPost"),
        (r"\bopsAction\s*\(", "opsAction"),
        (r"\bmethod\s*:\s*['\"]POST['\"]", "POST request"),
        (r"/api/(?:ops(?:/|['\"])?|delete(?!tions))", "destructive API endpoint"),
    )
    if section:
        missing.extend(label for pattern, label in forbidden if re.search(pattern, section))
    if missing:
        record("FAIL", "check-deletions-readonly", "missing/forbidden: " + ", ".join(missing))
    else:
        record("PASS", "check-deletions-readonly",
               "Deletions section is bare GET /api/deletions with no destructive wiring")
    fixture = deletions_readonly_fixture_check()
    return not missing and fixture and node_check(DASHBOARD)


def cmd_check_authz():
    return run_py_driver(AUTHZ_DRIVER, "check-authz")


def cmd_check_authz_ui():
    if not os.path.exists(AUTHZ_HTML):
        record("FAIL", "check-authz-ui", "ui/authz.html missing (task not landed yet?)")
        return False
    text = read_text(AUTHZ_HTML)
    ok = True
    for needle, why in (("__CSRF__", "CSRF injection slot"),
                        ("/api/ops/authorize", "authorize POST route"),
                        ("dismiss", "localStorage dismiss key")):
        if needle not in text:
            record("FAIL", "check-authz-ui", "authz.html lacks %r (%s)" % (needle, why))
            ok = False
    dash = read_text(DASHBOARD)
    if "/authz" not in dash:
        record("FAIL", "check-authz-ui", "dashboard.html lacks /authz entry link")
        ok = False
    if "\U0001f511" not in dash:  # key emoji alertbar crit item
        record("FAIL", "check-authz-ui", "dashboard.html lacks key-emoji alertbar item")
        ok = False
    inert = inert_render_check(AUTHZ_HTML, "renderPending", AUTHZ_FIXTURE,
                               "check-authz-ui")
    nc = node_check(AUTHZ_HTML)
    if ok and inert and nc:
        record("PASS", "check-authz-ui", "authz.html + dashboard wiring green")
    return ok and inert and nc


def cmd_check_collapse():
    text = read_text(DASHBOARD)
    n = text.count("applyCollapse")
    ok = True
    if "PREFS.collapsed" not in text:
        record("FAIL", "check-collapse",
               "PREFS.collapsed missing from dashboard.html (task not landed yet?)")
        ok = False
    if n < 4:
        record("FAIL", "check-collapse",
               "applyCollapse x%d in dashboard.html, need >= 4 (1 def + >=3 calls)" % n)
        ok = False
    if ok:
        record("PASS", "check-collapse", "PREFS.collapsed + applyCollapse x%d" % n)
    return node_check(DASHBOARD) and ok


def cmd_check_transcript():
    node, segment = function_node("session_transcript")
    ok = True
    if node is None:
        record("FAIL", "check-transcript", "session_transcript not found in monitor.py")
        ok = False
    elif not all(needle in segment for needle in ("_find_claude_session", "_codex_rollout_path",
                                                   "_TRANSCRIPT_SCAN_BYTES")):
        record("FAIL", "check-transcript", "session_transcript lacks bounded Claude/Codex wiring")
        ok = False
    source = read_text(MONITOR)
    if 'route == "/api/session/transcript"' not in source or "session_transcript(load_config()" not in source:
        record("FAIL", "check-transcript", "GET /api/session/transcript route missing")
        ok = False
    if ok:
        record("PASS", "check-transcript", "bounded transcript reader + token-gated GET route present")
    return run_py_driver(TRANSCRIPT_DRIVER, "check-transcript") and ok


def cmd_check_transcript_ui():
    text = read_text(SESSION)
    required = ("id=\"transcript\"", "renderTranscript", "/api/session/transcript",
                "loadTranscript", "#subsbody", "overflow-y:auto", "100dvh")
    missing = [needle for needle in required if needle not in text]
    if missing:
        record("FAIL", "check-transcript-ui", "missing: " + ", ".join(missing))
    else:
        record("PASS", "check-transcript-ui", "scrollable transcript + bounded subagents wiring present")
    inert = inert_render_check(SESSION, "renderTranscript", TRANSCRIPT_FIXTURE,
                               "check-transcript-ui")
    return not missing and inert and node_check(SESSION)


LINEWIDTH_SELECTORS = (".turntext", ".txt", ".tool")


def cmd_check_transcript_linewidth(name="check-transcript-linewidth"):
    text = read_text(SESSION)
    problems = []
    # the text layer carries the cap, in ch, inside the readable 45--90ch band
    for sel in LINEWIDTH_SELECTORS:
        rule = re.search(r"(?<![\w.#-])" + re.escape(sel) + r"\{([^}]*)\}", text)
        if rule is None:
            problems.append("%s rule not found in ui/session.html" % sel)
            continue
        cap = re.search(r"max-width:\s*(\d+(?:\.\d+)?)ch", rule.group(1))
        if cap is None:
            problems.append("%s has no ch-based max-width -- its lines run the full viewport"
                            % sel)
        elif not 45.0 <= float(cap.group(1)) <= 90.0:
            problems.append("%s max-width %sch is outside the readable 45--90ch band"
                            % (sel, cap.group(1)))
    # 0c1ed8b: body stays uncapped so the page scrollbar keeps sitting at the far right
    for rule in re.finditer(r"(?<![\w.#-])body\s*\{([^}]*)\}", text):
        if "max-width" in rule.group(1):
            problems.append("body regained a max-width -- that is the 0c1ed8b scrollbar "
                            "regression; cap the text layer instead")
            break
    # 77e913b: the transcript container keeps its own height/scroll and stays full width
    container = re.search(r"#transcriptbody\{([^}]*)\}", text)
    if container is None:
        problems.append("#transcriptbody rule not found in ui/session.html")
    else:
        if not re.search(r"max-height:\s*\d+(?:\.\d+)?dvh", container.group(1)):
            problems.append("#transcriptbody lost its dvh max-height -- 77e913b regression")
        if "overflow-y:auto" not in container.group(1):
            problems.append("#transcriptbody lost overflow-y:auto -- 77e913b regression")
        if "max-width" in container.group(1):
            problems.append("#transcriptbody must stay full width -- the cap belongs on the "
                            "text layer, not on the scrolling container")
    for query, why in (("min-height:760px", "tall viewport"), ("max-width:520px", "phone")):
        override = re.search(r"@media\(" + re.escape(query) + r"\)\{.*?#transcriptbody\{([^}]*)\}",
                             text, re.S)
        if override is None or not re.search(r"max-height:\s*\d+(?:\.\d+)?dvh", override.group(1)):
            problems.append("@media(%s) lost its #transcriptbody %s height override -- "
                            "77e913b regression" % (query, why))
    if problems:
        record("FAIL", name, "; ".join(problems))
        return False
    record("PASS", name, "%s capped in ch inside the 45--90ch readable band; body still "
           "uncapped (scrollbar at the far right) and #transcriptbody keeps its full width "
           "plus dvh height/overflow-y in the base rule and both media queries"
           % ", ".join(LINEWIDTH_SELECTORS))
    return True


DESIGN_REQUIRED_HEADINGS = (
    "Color/identity channels",
    "Vendor emblem template",
    "Tooltip spec",
    "Office zones",
    "Pool display",
    "Layout",
    "Drift guard",
)
TOKEN_KEYS = ("BATCH_PALETTE", "SRCCOLOR", "STATUS_GLYPH")


def token_registry(text):
    """Read P1's single JSON token registry from the design document."""
    section = re.search(r"(?ms)^### Token registry[ \t]*\r?$\r?\n(.*?)(?=^## |\Z)", text)
    if not section:
        return None, "missing ### Token registry JSON block"
    blocks = re.findall(r"(?ms)^```json[ \t]*\r?$\r?\n(.*?)^```[ \t]*\r?$",
                        section.group(1))
    if len(blocks) != 1:
        return None, "Token registry needs exactly one JSON block"
    try:
        data = json.loads(blocks[0])
    except ValueError as e:
        return None, "token registry is invalid JSON: %s" % e
    if not isinstance(data, dict):
        return None, "token registry must be a JSON object"
    return data, ""


def cmd_check_design_doc():
    """Validate only the frozen P1 documentation structure, not later UI code."""
    ok = True
    for path, label in ((DESIGN_DOC, "design system"),
                        (DATA_CONTRACTS, "data contracts")):
        if not os.path.isfile(path):
            record("FAIL", "check-design-doc", "%s document missing: %s" % (label, path))
            ok = False
    if not ok:
        return False

    design = read_text(DESIGN_DOC)
    contracts = read_text(DATA_CONTRACTS)
    for heading in DESIGN_REQUIRED_HEADINGS:
        if not re.search(r"(?m)^## " + re.escape(heading) + r"[ \t]*\r?$", design):
            record("FAIL", "check-design-doc", "design system lacks ## %s" % heading)
            ok = False
    for label, text in (("design system", design), ("data contracts", contracts)):
        if re.search(r"\btbd\b", text, re.IGNORECASE):
            record("FAIL", "check-design-doc", "%s contains a TBD placeholder" % label)
            ok = False

    sections = dict(re.findall(
        r"(?ms)^## (D[1-5])\b.*?$\n(.*?)(?=^## |\Z)", contracts))
    for key in ("D1", "D2", "D3", "D4", "D5"):
        section = sections.get(key)
        if section is None:
            record("FAIL", "check-design-doc", "data contracts lacks ## %s" % key)
            ok = False
            continue
        json_blocks = re.findall(
            r"(?ms)^```json[ \t]*\r?$\r?\n(.*?)^```[ \t]*\r?$", section)
        if len(json_blocks) != 1:
            record("FAIL", "check-design-doc", "%s needs exactly one JSON shape" % key)
            ok = False
        else:
            try:
                shape = json.loads(json_blocks[0])
                if not isinstance(shape, dict):
                    raise ValueError("top-level value is not an object")
            except ValueError as e:
                record("FAIL", "check-design-doc", "%s JSON shape invalid: %s" % (key, e))
                ok = False
        verdict = re.search(r"(?ms)^### Verdict[ \t]*\r?$\r?\n(.*?)(?=^### |\Z)",
                            section)
        if not verdict or not verdict.group(1).strip():
            record("FAIL", "check-design-doc", "%s lacks a non-empty Verdict" % key)
            ok = False
        sources = re.search(r"(?ms)^### Sources[ \t]*\r?$\r?\n(.*?)(?=^### |\Z)",
                            section)
        if not sources or not sources.group(1).strip():
            record("FAIL", "check-design-doc", "%s lacks non-empty Sources" % key)
            ok = False
    if ok:
        record("PASS", "check-design-doc", "seven design sections + five JSON contracts")
    return ok


def cmd_check_color_tokens():
    """Enforce P1's documented token separation without requiring P5 code."""
    if not os.path.isfile(DESIGN_DOC):
        record("FAIL", "check-color-tokens", "design system document missing: %s" % DESIGN_DOC)
        return False
    registry, err = token_registry(read_text(DESIGN_DOC))
    if registry is None:
        record("FAIL", "check-color-tokens", err)
        return False
    sets = {}
    ok = True
    for key in TOKEN_KEYS:
        values = registry.get(key)
        if not isinstance(values, list) or not values:
            record("FAIL", "check-color-tokens", "%s must be a non-empty list" % key)
            ok = False
            continue
        if any(not isinstance(v, str) or not re.fullmatch(r"#[0-9A-Fa-f]{6}", v)
               for v in values):
            record("FAIL", "check-color-tokens", "%s contains a non-hex token" % key)
            ok = False
            continue
        normalized = [v.upper() for v in values]
        if len(normalized) != len(set(normalized)):
            record("FAIL", "check-color-tokens", "%s repeats a token" % key)
            ok = False
            continue
        sets[key] = set(normalized)
    for left, right in (("BATCH_PALETTE", "SRCCOLOR"),
                        ("BATCH_PALETTE", "STATUS_GLYPH"),
                        ("SRCCOLOR", "STATUS_GLYPH")):
        overlap = sets.get(left, set()) & sets.get(right, set())
        if overlap:
            record("FAIL", "check-color-tokens", "%s/%s overlap: %s" %
                   (left, right, ", ".join(sorted(overlap))))
            ok = False
    if ok:
        record("PASS", "check-color-tokens", "three documented token sets are disjoint")
    return ok


AVATAR_INERT_DRIVER = r"""
;(function(){
  var payload = __PAYLOAD__, source = __SOURCE__;
  var rows = officeRows(source);
  if (rows.length !== 1 || rows[0].id !== 'parent-a' || rows[0].groupKey !== 'launch-a') {
    console.log('PRECHECK_AVATAR_FIXTURE_BAD rows'); process.exit(4);
  }
  if (batchColor(rows[0].groupKey) !== batchColor('launch-a') ||
      rows[0].minis[0].vendor !== 'codex' || resolveVendor(payload).key !== 'neutral') {
    console.log('PRECHECK_AVATAR_FIXTURE_BAD resolver'); process.exit(4);
  }
  for (var i = 0, states = ['running','idle','waiting','stopped','stale']; i < states.length; i++) {
    if (!statusGlyph(states[i])) { console.log('PRECHECK_AVATAR_FIXTURE_BAD glyph'); process.exit(4); }
  }
  var start = __SINKS.length, desk = makeDesk(rows[0]);
  updateDesk(desk, rows[0]);
  var joined = __SINKS.slice(start).join('\n');
  var heads=joined.match(/<img\b[^>]*class="desk-head"[^>]*>/gi)||[];
  if (joined.indexOf(payload) >= 0 || heads.length!==1 ||
      heads[0].indexOf('assets/signal-desk/operator-head-v1.png')<0 || __ATTR_BAD.length) {
    console.log('PRECHECK_AVATAR_XSS_LEAK attrs=' + __ATTR_BAD.join(',')); process.exit(5);
  }
  console.log('PRECHECK_AVATAR_INERT_OK'); process.exit(0);
})();
"""


def avatar_inert_check():
    """Exercise the desk resolver with hostile parent data and a real mini row."""
    node = shutil.which("node")
    if not node:
        record("FAIL", "check-avatar-identity", "node is required for inert avatar checks")
        return False
    blocks = extract_scripts(DASHBOARD)
    driver = (AVATAR_INERT_DRIVER.replace("__PAYLOAD__", json.dumps(_XSS))
              .replace("__SOURCE__", json.dumps(AVATAR_FIXTURE, ensure_ascii=False)))
    code = (INERT_PRELUDE + "\ntry {\n" + "\n;\n".join(blocks)
            + "\n} catch (__e) { console.log('HARNESS_TOPLEVEL_ERR ' "
              "+ (__e && __e.message ? __e.message : __e)); }\n" + driver)
    fd, tmp = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(code)
        proc = subprocess.run([node, tmp], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    finally:
        os.unlink(tmp)
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode == 0 and "PRECHECK_AVATAR_INERT_OK" in out:
        record("PASS", "check-avatar-identity inert fixture", "hostile parent data remains inert")
        return True
    record("FAIL", "check-avatar-identity inert fixture",
           out.splitlines()[-1] if out else "harness exit %d" % proc.returncode)
    return False


def cmd_check_avatar_identity():
    """Fail closed when P5's three office identity channels drift or become unsafe."""
    if not shutil.which("node"):
        record("FAIL", "check-avatar-identity", "node is required for syntax and inert checks")
        return False
    text = read_text(DASHBOARD)
    required = (
        "const BATCH_PALETTE=", "const VENDOR_EMBLEM=", "const STATUS_GLYPH=",
        "function normalizeVendor", "function resolveVendor", "function batchColor",
        "function vendorEmblem", "function statusGlyph", "groupKey:String(r.group_key||r.session_id)",
        "id:String(r.session_id)", "miniSVG(mini)", "vendor:normalizeVendor(m.vendor)",
        "r.status==='stale'?'stopped'", "fill:var(--batch)",
    )
    missing = [needle for needle in required if needle not in text]
    for name in ("BATCH_PALETTE", "VENDOR_EMBLEM", "STATUS_GLYPH"):
        if text.count("const %s=" % name) != 1:
            missing.append("single %s registry" % name)
    for state in ("running", "idle", "waiting", "stopped", "stale"):
        if " %s:" % state not in text:
            missing.append("STATUS_GLYPH.%s" % state)
    identity = re.search(r"(?s)const BATCH_PALETTE=.*?const MODEMAP=", text)
    if not identity:
        missing.append("contiguous identity registry")
    else:
        registry, err = token_registry(read_text(DESIGN_DOC))
        allowed = set()
        if registry:
            for key in ("BATCH_PALETTE", "SRCCOLOR"):
                allowed.update(v.upper() for v in registry.get(key, []))
        found = [h.upper() for h in re.findall(r"#[0-9A-Fa-f]{6}", identity.group(0))]
        if set(found) != allowed or len(found) != len(allowed):
            missing.append("identity inline hex outside the two registries")
    if ".desk[data-st=running] .floorglow" in text or "fill:var(--st-" in text[text.find(".floorglow"):text.find("</style>")]:
        missing.append("status colour applied to avatar")
    if missing:
        record("FAIL", "check-avatar-identity", "missing/drift: " + ", ".join(missing))
    else:
        record("PASS", "check-avatar-identity", "single registries, stable batch, vendor whitelist, static glyphs")
    return not missing and avatar_inert_check() and node_check(DASHBOARD)


OFFICE_ZONE_FIXTURE = {
    "claude": [
        {"session_id": "working-a", "group_key": "launch-a", "vendor": "cc",
         "work_kind": "working", "status": "stopped"},
        {"session_id": "standby-a", "group_key": "launch-a", "vendor": "cc",
         "work_kind": "standby", "status": "running"},
        {"session_id": "bridge-a", "group_key": "bridge-a", "vendor": "cc",
         "work_kind": "cli_queue", "status": "waiting"},
    ]
}


OFFICE_ZONE_DRIVER = r"""
;(function(){
  var rows = officeRows(__SOURCE__);
  var byId = {}; rows.forEach(function(row){ byId[row.id] = row; });
  if (rows.length !== 3 || byId['working-a'].id !== 'working-a' ||
      byId['working-a'].groupKey !== 'launch-a' || byId['working-a'].vendor !== 'cc' ||
      byId['working-a'].workKind !== 'working' || byId['standby-a'].workKind !== 'standby' ||
      byId['bridge-a'].workKind !== 'cli_queue') {
    console.log('PRECHECK_OFFICE_ZONE_FIXTURE_BAD rows'); process.exit(4);
  }
  if (officeZoneFor(byId['working-a']) !== 'working' ||
      officeZoneFor(byId['standby-a']) !== 'standby' ||
      rows.filter(function(row){ return row.workKind !== 'cli_queue'; }).length !== 2) {
    console.log('PRECHECK_OFFICE_ZONE_FIXTURE_BAD work-kind'); process.exit(4);
  }
  console.log('PRECHECK_OFFICE_ZONE_FIXTURE_OK'); process.exit(0);
})();
"""


SIGNAL_DESK_UI_FIXTURE = {
    "claude": [
        {"session_id": "spawn-a", "agent_idx": 0, "group_key": "batch-a", "vendor": "cc",
         "work_kind": "working", "work_reason": "active_tail", "status": "running",
         "mini_rows": [{"session_id": "spawn-a/subagent-1", "vendor": "cc", "status": "idle"}]},
        {"session_id": "fallback-b", "group_key": "fallback-b", "vendor": "codex",
         "work_kind": "standby", "work_reason": "remote_no_live_tail", "status": "running",
         "subagents": 2, "mini_rows": [{"session_id": "fallback-b/subagent-1", "vendor": "codex", "status": "idle"}]},
        {"session_id": "stopped-c", "agent_idx": 2, "group_key": "batch-a", "vendor": "cc",
         "work_kind": "working", "work_reason": "status_stopped", "status": "stopped"},
        {"session_id": "queued-d", "agent_idx": 3, "group_key": "batch-a", "vendor": "cc",
         "work_kind": "cli_queue", "status": "waiting"},
    ]
}


SIGNAL_DESK_UI_DRIVER = r"""
;(function(){
  var rows=officeRows(__SOURCE__), byId={}; rows.forEach(function(row){byId[row.id]=row;});
  if(rows.length!==4 || byId['spawn-a'].parentOrdinal!==1 || byId['stopped-c'].parentOrdinal!==3 ||
     byId['queued-d'].parentOrdinal!==4 || byId['fallback-b'].parentOrdinal!==5){
    console.log('PRECHECK_SIGNAL_DESK_ORDINAL_FAIL'); process.exit(4);
  }
  if(signalDeskRoute(byId['spawn-a'])!=='working' || signalDeskRoute(byId['fallback-b'])!=='standby' ||
     signalDeskRoute(byId['stopped-c'])!=='stopped' || signalDeskRoute(byId['queued-d'])!=='queue'){
    console.log('PRECHECK_SIGNAL_DESK_ROUTE_FAIL'); process.exit(5);
  }
  if(signalChildLabel(byId['spawn-a'],0)!=='a1.1' || signalChildLabel(byId['fallback-b'],0)!=='a5.1' ||
     byId['fallback-b'].minis.length!==1){
    console.log('PRECHECK_SIGNAL_DESK_CHILD_FAIL'); process.exit(6);
  }
  var persisted=JSON.parse(localStorage.getItem('aimon')||'{}');
  if(!persisted.signalDeskOrdinals || persisted.signalDeskOrdinals['fallback-b']!==5 ||
     persisted.signalDeskNextOrdinal<6){
    console.log('PRECHECK_SIGNAL_DESK_PREF_FAIL'); process.exit(7);
  }
  console.log('PRECHECK_SIGNAL_DESK_UI_OK'); process.exit(0);
})();
"""


def signal_desk_ui_fixture_check():
    node = shutil.which("node")
    if not node:
        record("FAIL", "check-signal-desk-ui fixture", "node is required for Signal Desk fixture")
        return False
    blocks = extract_scripts(DASHBOARD)
    code = (INERT_PRELUDE + "\ntry {\n" + "\n;\n".join(blocks)
            + "\n} catch (__e) { console.log('HARNESS_TOPLEVEL_ERR ' "
              "+ (__e && __e.message ? __e.message : __e)); }\n"
            + SIGNAL_DESK_UI_DRIVER.replace("__SOURCE__", json.dumps(SIGNAL_DESK_UI_FIXTURE)))
    fd, tmp = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(code)
        proc = subprocess.run([node, tmp], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    finally:
        os.unlink(tmp)
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode == 0 and "PRECHECK_SIGNAL_DESK_UI_OK" in out:
        record("PASS", "check-signal-desk-ui fixture",
               "ordinal persistence, A/a labels, and stopped/queue/work routing")
        return True
    record("FAIL", "check-signal-desk-ui fixture",
           out.splitlines()[-1] if out else "harness exit %d" % proc.returncode)
    return False


def cmd_check_signal_desk_ui():
    """Verify the Signal Desk semantic shell, with or without T4 movement."""
    text = read_text(DASHBOARD)
    required = {
        "semantic desk shell": 'class="signal-desk"',
        "Working parent zone": 'data-zone="working"',
        "Standby/Review parent zone": 'Standby / Review',
        "Stopped parent zone": 'data-zone="stopped"',
        "separate CLI Queue tickets": 'class="signal-queue"',
        "right Inspector": 'class="signal-inspector"',
        "A parent label": "signal-parent-id",
        "a child label": "function signalChildLabel",
        "preference ordinal store": "PREFS.signalDeskOrdinals",
        "display-sequence explanation": "展示序",
        "explicit stopped-first routing": "if(r.status==='stopped')return 'stopped'",
        "queue is not a desk": "signalDeskRoute(r)!=='queue'",
        # asm-011: the D5 collector now reports what it dropped, and a count that
        # only ever reaches the payload is still a silent drop as far as the
        # operator is concerned. Both halves are pinned: the formatter, and the
        # line that actually puts it in front of someone.
        "skipped-record formatter": "function bridgeSkipText(sk)",
        "skipped records reach the screen": "' active'+(skipNote?' · '+skipNote:'')",
        "real portrait image": 'class="desk-head"',
        "source name": 'class="srcname"',
    }
    missing = [label for label, needle in required.items() if needle not in text]
    # asm-011: a marker proves the wiring exists; this proves the sentence an
    # operator actually reads. A skip line that renders "0 of 0 scanned skipped"
    # on a clean poll, or omits the breakdown, is a marker-passing regression.
    fn_start = text.find("function bridgeSkipText(sk)")
    fn_end = text.find(chr(10), fn_start)
    if fn_start >= 0:
        try:
            proc = subprocess.run(
                ["node", "-e", text[fn_start:fn_end] + """
const q=(o)=>bridgeSkipText(o);
const cases=[[undefined,''],[{scanned:9,oversize:0,unreadable:0,invalid:0},''],
             [{scanned:14,oversize:1,unreadable:0,invalid:2},'3 of 14 scanned skipped (1 oversize, 2 malformed)']];
for(const [inp,want] of cases){ const got=q(inp);
  if(got!==want){ console.log('SKIPTEXT_FAIL '+JSON.stringify(inp)+' -> '+JSON.stringify(got)); process.exit(3); } }
console.log('SKIPTEXT_OK');"""],
                capture_output=True, text=True, timeout=30)
            if "SKIPTEXT_OK" not in proc.stdout:
                missing.append("skip line renders wrong: " + (proc.stdout or proc.stderr).strip()[:120])
        except (OSError, subprocess.SubprocessError):
            pass  # node absent: node_check() below already reports the skip
    office_start = text.find("// ---- Signal Desk:")
    office_end = text.find("let _svcBusy=", office_start)
    section = text[office_start:office_end] if office_start >= 0 and office_end >= 0 else ""
    if not section:
        missing.append("Signal Desk implementation section")
    if "r.subagents" in text[text.find("function updateDesk"):text.find("function officeZoneFor")]:
        # Counts may be disclosed, but they must not manufacture a numbered child label.
        update = text[text.find("function updateDesk"):text.find("function officeZoneFor")]
        if "signalChildLabel(r,index)" not in update:
            missing.append("child labels are not derived from known mini identities")
    if missing:
        record("FAIL", "check-signal-desk-ui", "missing/drift: " + ", ".join(missing))
    else:
        record("PASS", "check-signal-desk-ui",
               "semantic floor, queue tickets, Inspector, and A/a identity wiring")
    return not missing and signal_desk_ui_fixture_check() and node_check(DASHBOARD)


def cmd_check_signal_desk_layout():
    """Static R1 guard: floor stays primary and only Inspector is sticky in the rail."""
    text = read_text(DASHBOARD)
    shell_start = text.find("function ensureOfficeShell")
    shell_end = text.find("function officeTicket", shell_start)
    shell = text[shell_start:shell_end] if shell_start >= 0 and shell_end >= 0 else ""
    required = {
        "wider desktop rail": ".signal-desk{display:grid;grid-template-columns:minmax(0,1fr) minmax(300px,.40fr)",
        "rail container": 'class="signal-rail"',
        "rail min width": ".signal-rail{display:grid;min-width:0;gap:12px;align-content:start}",
        "only Inspector sticky": ".signal-inspector{position:sticky;top:10px",
        "narrow one-column desk": "@media(max-width:820px){.signal-desk{grid-template-columns:1fr}.signal-inspector{position:static}",
        "queue hook preserved": "function paintOfficeQueue(){const office=ensureOfficeShell(),lane=office.querySelector('.signal-queue')",
        "pool hook preserved": "function paintOfficePool(){const office=ensureOfficeShell(),pool=office.querySelector('.office-pool')",
    }
    missing = [label for label, needle in required.items() if needle not in text]
    order = (shell.find('class="signal-floor"'), shell.find('class="signal-rail"'),
             shell.find('class="signal-inspector"'), shell.find('class="signal-queue"'),
             shell.find('class="office-pool"'))
    if not shell or min(order) < 0 or not (order[0] < order[1] < order[2] < order[3] < order[4]):
        missing.append("floor then rail/Inspector/Queue/Pool DOM order")
    if re.search(r"\.signal-rail\{[^}]*position\s*:\s*sticky", text):
        missing.append("rail must not be sticky")
    if missing:
        record("FAIL", "check-signal-desk-layout", "missing/drift: " + ", ".join(missing))
    else:
        record("PASS", "check-signal-desk-layout",
               "floor-primary rail, Inspector-only sticky, preserved Queue/Pool hooks, and narrow stack")
    return not missing and node_check(DASHBOARD)


def cmd_check_signal_desk_zone_vendor():
    """Keep Signal Desk zone accents and same-asset vendor treatment presentational."""
    text = read_text(DASHBOARD)
    required = {
        "working zone accent": '.signal-zone[data-zone="working"]{--zone-accent:#3fb950',
        "standby zone accent": '.signal-zone[data-zone="standby"]{--zone-accent:#d29922',
        "stopped zone accent": '.signal-zone[data-zone="stopped"]{--zone-accent:#8b949e',
        "zone header accent": ".signal-zone h2{color:var(--zone-accent)}",
        "zone count accent": ".signal-zone h2 .sub{background:var(--zone-accent);color:#0d1117}",
        "vendor data state": "el.dataset.vendor=vendor.key",
        "vendor head ring": ".desk[data-vendor] .desk-head{box-shadow:0 0 0 2px var(--vendor-ring)",
        "cc vendor treatment": '.desk[data-vendor="cc"]{--vendor-ring:#f0883e',
        "codex vendor treatment": '.desk[data-vendor="codex"]{--vendor-ring:#58a6ff',
        "hermes vendor treatment": '.desk[data-vendor="hermes"]{--vendor-ring:#a371f7',
        "antigravity vendor treatment": '.desk[data-vendor="antigravity"]{--vendor-ring:#3fb950',
        "copilot vendor treatment": '.desk[data-vendor="copilot"]{--vendor-ring:#39c5cf',
        "unchanged real asset lookup": "const SIGNAL_DESK_HEAD={claude:{src:'assets/signal-desk/operator-head-v1.png'",
        "unchanged real asset renderer": "function signalDeskHead(source){const asset=SIGNAL_DESK_HEAD[source]||SIGNAL_DESK_HEAD.default;",
    }
    missing = [label for label, needle in required.items() if needle not in text]
    # Contract: vendor identity is emblem + registry ring only — the figure face must NOT be tinted.
    if "--vendor-filter" in text or "filter:var(--vendor-filter)" in text:
        missing.append("vendor face filter forbidden (contract: emblem + ring only, never the figure face)")
    if missing:
        record("FAIL", "check-signal-desk-zone-vendor", "missing/drift: " + ", ".join(missing))
    else:
        record("PASS", "check-signal-desk-zone-vendor",
               "working/standby/stopped header counts and five same-asset vendor treatments")
    return not missing and node_check(DASHBOARD)


def cmd_check_signal_desk_surface_state():
    """Guard the P4/P5 presentational treatment without touching desk semantics."""
    text = read_text(DASHBOARD)
    required = {
        "floor radial depth": "#office{background:radial-gradient(ellipse 90% 70% at 50% 42%,#16203033 0%,transparent 65%)",
        "floor linear depth": "linear-gradient(180deg,#0b1017 0%,#0f1622 55%,#131d2c 100%)",
        "building floor outline": ".signal-floor{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0;align-items:start;position:relative;border:2px solid #2b3a4a",
        "room de-carded": ".signal-zone{background:transparent;border:0;border-radius:0;padding:12px;position:relative}",
        "room accent strip": '.signal-zone::before{content:"";position:absolute;inset:0 0 auto 0;height:3px;background:var(--zone-accent)',
        "working room wall": '.signal-zone[data-zone="working"]{--zone-accent:#3fb950;border-right:2px solid #24323f',
        "standby room floor": '.signal-zone[data-zone="standby"]{--zone-accent:#d29922;background:linear-gradient(180deg,rgba(210,153,34,.06)',
        "stopped room wall": '.signal-zone[data-zone="stopped"]{--zone-accent:#8b949e;border-top:2px solid #24323f',
        "desk seated minimum": ".desk{position:relative;min-width:0;min-height:150px;text-align:center;border:0;border-radius:0;background:transparent",
        "desk contact shadow": '.desk::after{content:"";position:absolute;left:50%;bottom:14px',
        "compact Working empty floor": '.signal-zone[data-zone="working"] .signal-desks:has(.office-empty){min-height:64px}',
        "compact Working empty message": '.signal-zone[data-zone="working"] .office-empty{min-height:48px;padding:4px 0}',
        "whole stopped desk muted": '.signal-zone[data-zone="stopped"] .desk{filter:grayscale(.55) brightness(.8);opacity:.82}',
    }
    missing = [label for label, needle in required.items() if needle not in text]
    # Negative guards: the old card look must be GONE (de-carding actually happened).
    if ".signal-zone{background:rgba(13,20,30,.8)" in text:
        missing.append("zone still a card (background:rgba(13,20,30,.8))")
    if "box-shadow:0 7px 16px rgba(0,0,0,.5)" in text:
        missing.append("desk still a card (0 7px 16px shadow)")
    if missing:
        record("FAIL", "check-signal-desk-surface-state", "missing/drift: " + ", ".join(missing))
    else:
        record("PASS", "check-signal-desk-surface-state",
               "top-down floor plan: building outline, de-carded rooms with walls, seated desks with contact shadow")
    return not missing and node_check(DASHBOARD)


OFFICE_TRANSITION_DRIVER = r"""
;(function(){
  var frames=[], timers=[];
  requestAnimationFrame=function(fn){frames.push(fn);return frames.length;};
  setTimeout=function(fn){timers.push(fn);return timers.length;};
  window.matchMedia=function(){return {matches:false};};
  function zone(name,left,top){return {name:name,rect:{left:left,top:top},children:[],appendChild:function(el){
    if(el.parentElement){var old=el.parentElement.children,ix=old.indexOf(el);if(ix>=0)old.splice(ix,1);}
    this.children.push(el);el.parentElement=this;return el;
  }};}
  function desk(parent){var names={};var el={dataset:{sessionId:'parent-1',zone:'working'},parentElement:parent,
    style:{transition:'',transform:''},classList:{add:function(n){names[n]=true;},remove:function(n){delete names[n];},contains:function(n){return !!names[n];}},
    getBoundingClientRect:function(){return {left:this.parentElement.rect.left,top:this.parentElement.rect.top};}};
    Object.defineProperty(el,'offsetWidth',{get:function(){return 148;}});parent.children.push(el);return el;
  }
  if(typeof signalDeskReparentDesk!=='function'){console.log('PRECHECK_TRANSITION_MISSING');process.exit(3);}
  var working=zone('working',0,0),standby=zone('standby',220,0),stopped=zone('stopped',0,230),queue=zone('queue',220,230),el=desk(working),same=el;
  if(!signalDeskReparentDesk(el,standby,'standby') || el!==same || el.parentElement!==standby || el.dataset.sessionId!=='parent-1' || el.dataset.transition!=='working>standby' || !/^translate\(/.test(el.style.transform)){
    console.log('PRECHECK_TRANSITION_STANDBY_FAIL');process.exit(4);
  }
  if(frames.length!==1){console.log('PRECHECK_TRANSITION_FRAME_FAIL');process.exit(5);}frames.shift()();
  if(!el.classList.contains('signal-flip-moving') || el.style.transform!==''){console.log('PRECHECK_TRANSITION_PLAY_FAIL');process.exit(6);}frames.shift()();timers.shift()();
  if(el.classList.contains('signal-flip-moving')){console.log('PRECHECK_TRANSITION_CLEANUP_FAIL');process.exit(7);}
  frames=[];timers=[];
  if(!signalDeskReparentDesk(el,stopped,'stopped') || el!==same || el.parentElement!==stopped || el.dataset.transition!=='standby>stopped'){
    console.log('PRECHECK_TRANSITION_STOPPED_FAIL');process.exit(8);
  }
  window.matchMedia=function(){return {matches:true};};frames=[];timers=[];
  if(signalDeskReparentDesk(el,working,'working') || el!==same || el.parentElement!==working || 'transition' in el.dataset || el.style.transform!=='' || el.classList.contains('signal-flip-moving') || frames.length!==0){
    console.log('PRECHECK_TRANSITION_REDUCED_FAIL');process.exit(9);
  }
  var ticket=desk(standby);
  if(signalDeskReparentDesk(ticket,queue,'queue') || ticket.parentElement!==standby || queue.children.length!==0){
    console.log('PRECHECK_TRANSITION_QUEUE_FAIL');process.exit(10);
  }
  console.log('PRECHECK_OFFICE_TRANSITION_OK');process.exit(0);
})();
"""


def office_transition_fixture_check():
    node = shutil.which("node")
    if not node:
        record("FAIL", "check-office-transition fixture", "node is required for FLIP fixture")
        return False
    blocks = extract_scripts(DASHBOARD)
    code = (INERT_PRELUDE + "\ntry {\n" + "\n;\n".join(blocks)
            + "\n} catch (__e) { console.log('HARNESS_TOPLEVEL_ERR ' "
              "+ (__e && __e.message ? __e.message : __e)); }\n"
            + OFFICE_TRANSITION_DRIVER)
    fd, tmp = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(code)
        proc = subprocess.run([node, tmp], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    finally:
        os.unlink(tmp)
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode == 0 and "PRECHECK_OFFICE_TRANSITION_OK" in out:
        record("PASS", "check-office-transition fixture",
               "same parent node crosses working/standby/stopped; reduced motion and queue stay inert")
        return True
    record("FAIL", "check-office-transition fixture",
           out.splitlines()[-1] if out else "harness exit %d" % proc.returncode)
    return False


def cmd_check_office_transition():
    """Require a controlled FLIP path only for retained non-queue parent desks."""
    text = read_text(DASHBOARD)
    required = {
        "stable session DOM key": "el.dataset.sessionId=r.id",
        "FLIP reparent helper": "function signalDeskReparentDesk(el,zone,route)",
        "old/new layout reads": "getBoundingClientRect()",
        "single animation frame": "requestAnimationFrame(function()",
        "ephemeral transform class": ".desk.signal-flip-moving",
        "reduced-motion guard": "function signalDeskPrefersReducedMotion()",
        "queue exclusion": "if(route==='queue'||!moved)return false;",
        "render uses FLIP helper": "signalDeskReparentDesk(el,zone,route);",
        "reduced-motion CSS override": ".desk.signal-flip-moving{transform:none!important",
    }
    missing = [label for label, needle in required.items() if needle not in text]
    if missing:
        record("FAIL", "check-office-transition", "missing/drift: " + ", ".join(missing))
    else:
        record("PASS", "check-office-transition",
               "retained desk FLIP, reduced-motion guard, and queue exclusion are wired")
    return not missing and office_transition_fixture_check() and node_check(DASHBOARD)


def cmd_check_dashboard_interactions():
    """Fail closed if responsive view state or keyboard contracts drift."""
    text = read_text(DASHBOARD)
    required = {
        "no narrow-office text fallback": "let view=PREFS.view;",
        "responsive view toggle wrapping": ".viewtog{margin-left:0;max-width:100%;flex-wrap:wrap",
        "source/service keyboard control setup": "function enableKeyboardControls(root)",
        "source filter selector": "[data-src]",
        "safe service selectors": '[data-svc="localonly"]',
        "keyboard focus assignment": "c.tabIndex=0",
        "Enter/Space activation": "if(e.key!=='Enter'&&e.key!==' ')return",
        "safe service action allowlist": "^(localonly|susponly|refresh|unlock)$",
        "collapsible heading semantics": "h.setAttribute('aria-expanded'",
        "collapsible heading state sync": "h.setAttribute('aria-expanded',PREFS.collapsed[cid]",
    }
    missing = [label for label, needle in required.items() if needle not in text]
    if "if(view==='office'&&window.innerWidth<=520)view='text'" in text:
        missing.append("narrow-office fallback still present")
    if re.search(r"(?:^|[;}])\s*(?:html|body|:root)\s*\{[^}]*overflow-x\s*:\s*(?:hidden|clip)",
                 text, re.IGNORECASE | re.DOTALL):
        missing.append("global horizontal-overflow hiding")
    if missing:
        record("FAIL", "check-dashboard-interactions", "missing/drift: " + ", ".join(missing))
    else:
        record("PASS", "check-dashboard-interactions",
               "responsive view state, keyboard controls, and overflow guard present")
    fixture = dashboard_interaction_fixture_check()
    return not missing and fixture and node_check(DASHBOARD)


DASHBOARD_INTERACTION_DRIVER = r"""
;(function(){
  function control(dataset){
    var el = {dataset:dataset||{}, _attrs:{}, tabIndex:-1, clicks:0,
      classList:{contains:function(){return false;}},
      setAttribute:function(k,v){this._attrs[k]=String(v);},
      getAttribute:function(k){return Object.prototype.hasOwnProperty.call(this._attrs,k)?this._attrs[k]:null;},
      removeAttribute:function(k){delete this._attrs[k];},
      closest:function(){return this;}, click:function(){this.clicks++;}};
    return el;
  }
  if(typeof enableKeyboardControls !== 'function' || typeof applyCollapse !== 'function'){
    console.log('PRECHECK_DASHBOARD_INTERACTIONS_MISSING'); process.exit(3);
  }
  var source=control({src:'claude'}), service=control({svc:'localonly'});
  enableKeyboardControls({querySelectorAll:function(){return [source,service];}});
  function key(target,key){var prevented=false;__fireDoc('keydown',{target:target,key:key,preventDefault:function(){prevented=true;}});return prevented;}
  if(source.tabIndex!==0 || source.getAttribute('role')!=='button' ||
     service.tabIndex!==0 || service.getAttribute('role')!=='button' ||
     !key(source,'Enter') || source.clicks!==1 || !key(service,' ') || service.clicks!==1){
    console.log('PRECHECK_DASHBOARD_KEYBOARD_FAIL'); process.exit(4);
  }
  var card={dataset:{cid:'fixture:card'},_clps:false,
    classList:{toggle:function(name,on){if(name==='clps')card._clps=!!on;}},querySelector:function(){return heading;}};
  var heading=control({});heading.parentElement=card;
  heading.closest=function(){return heading;};
  heading.click=function(){this.clicks++;__fireDoc('click',{target:heading});};
  applyCollapse({querySelectorAll:function(){return [card];}});
  if(heading.getAttribute('aria-expanded')!=='true' || !key(heading,' ') || !card._clps ||
     heading.getAttribute('aria-expanded')!=='false' || !key(heading,'Enter') || card._clps ||
     heading.getAttribute('aria-expanded')!=='true'){
    console.log('PRECHECK_DASHBOARD_COLLAPSE_FAIL'); process.exit(5);
  }
  console.log('PRECHECK_DASHBOARD_INTERACTIONS_OK'); process.exit(0);
})();
"""


def dashboard_interaction_fixture_check():
    """Execute the dashboard's real delegated keyboard/collapse handlers."""
    node = shutil.which("node")
    if not node:
        record("FAIL", "check-dashboard-interactions fixture", "node is required for keyboard behavior fixture")
        return False
    blocks = extract_scripts(DASHBOARD)
    code = (INERT_PRELUDE + "\ntry {\n" + "\n;\n".join(blocks)
            + "\n} catch (__e) { console.log('HARNESS_TOPLEVEL_ERR ' "
            + "+ (__e && __e.message ? __e.message : __e)); }\n"
            + DASHBOARD_INTERACTION_DRIVER)
    fd, tmp = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(code)
        proc = subprocess.run([node, tmp], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    finally:
        os.unlink(tmp)
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode == 0 and "PRECHECK_DASHBOARD_INTERACTIONS_OK" in out:
        record("PASS", "check-dashboard-interactions fixture",
               "source/service Enter/Space delegation and collapse aria state sync")
        return True
    record("FAIL", "check-dashboard-interactions fixture",
           out.splitlines()[-1] if out else "harness exit %d" % proc.returncode)
    return False


TOOLTIP_DRIVER = r"""
;(function(){
  var payload = __PAYLOAD__;
  if (typeof openTooltip !== 'function') {
    console.log('PRECHECK_MISSING openTooltip'); process.exit(3);
  }
  var trigger = __mkEl('button');
  trigger.dataset.tip = payload;
  var start = __SINKS.length; __ATTR_BAD.length = 0;
  openTooltip(trigger);
  var bubble = document.getElementById('tooltip');
  var joined = __SINKS.slice(start).join('\n');
  if (bubble.textContent !== payload || /<img/i.test(joined) || __ATTR_BAD.length) {
    console.log('PRECHECK_TOOLTIP_XSS_LEAK attrs=' + __ATTR_BAD.join(','));
    process.exit(5);
  }
  console.log('PRECHECK_TOOLTIP_INERT_OK'); process.exit(0);
})();
"""


def tooltip_inert_check():
    """Exercise the tooltip opener with a hostile data-tip value."""
    label = "check-tooltip inert payload"
    node = shutil.which("node")
    if not node:
        record("SKIP", label, "warning: node not on PATH, inert check skipped")
        return True
    blocks = extract_scripts(DASHBOARD)
    payload = '<img src=x onerror=alert(1)>"\''
    code = (INERT_PRELUDE + "\ntry {\n" + "\n;\n".join(blocks)
            + "\n} catch (__e) { console.log('HARNESS_TOPLEVEL_ERR ' "
              "+ (__e && __e.message ? __e.message : __e)); }\n"
            + TOOLTIP_DRIVER.replace("__PAYLOAD__", json.dumps(payload)))
    fd, tmp = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(code)
        proc = subprocess.run([node, tmp], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    finally:
        os.unlink(tmp)
    out = (proc.stdout or "").strip()
    if proc.returncode == 0 and "PRECHECK_TOOLTIP_INERT_OK" in out:
        record("PASS", label, "textContent keeps <img onerror> inert")
        return True
    tail = (out + "\n" + (proc.stderr or "").strip()).strip().splitlines()
    record("FAIL", label, tail[-1] if tail else "harness exit %d" % proc.returncode)
    return False


def cmd_check_tooltip():
    if not shutil.which("node"):
        record("FAIL", "check-tooltip", "node is required for syntax and inert-payload checks")
        return False
    text = read_text(DASHBOARD)
    required = {
        "tooltip bubble": 'id="tooltip" role="tooltip"',
        "data-tip trigger": "dataset.tip",
        "textContent rendering": "tooltip.textContent=message",
        "no native tooltip source": "b.removeAttribute('title')",
        "1.5 second delay": "},1500);",
        "hover close": "'mouseleave'",
        "focus close": "'blur'",
        "Escape close": "e.key==='Escape'",
        "hover persistence": "tooltip.contains(next)",
        "reduced motion": "@media(prefers-reduced-motion:reduce){#tooltip{transition:none}}",
        "Launch affordance": ".pbtn.launch:hover",
        "icon-only label": "setAttribute('aria-label','Retry agent')",
        "preset binding": "data-preset=",
        "retry index": "data-idx=",
    }
    missing = [label for label, needle in required.items() if needle not in text]
    if missing:
        record("FAIL", "check-tooltip", "missing: " + ", ".join(missing))
    else:
        record("PASS", "check-tooltip", "delegated tooltip, labels, and Launch affordance present")
    inert = tooltip_inert_check()
    syntax = node_check(DASHBOARD)
    return not missing and inert and syntax


def cmd_check_office2_no_shell():
    """no-shell gate (owner: '不接受辦公室有任何區塊空殼'): every /office2 zone
    must have a REAL data source. A ZONES key is valid only if zoneOf() can return
    it from real /api/status rows, OR it is 'cli' (sourced from /api/cli-bridge
    now_running via mapCliBridge). Any zone with no signal path is an empty shell.
    'review' is now signal-backed (work_review <- reviewer/panel subagent agentType);
    'meeting' has no signal source yet and must never reappear in ZONES.
    Widened to all 8 zones: every zone key must ALSO name its signal in the
    ledger below, and both ends of that signal (backend producer in monitor.py,
    front-end consumer in office_proto.html) must still be wired -- so a 9th
    zone with no declared signal, or a removal of the council / standby-split
    wiring, fails here."""
    name = "check-office2-no-shell"
    if not os.path.exists(OFFICE_PROTO):
        record("SKIP", name, "ui/office_proto.html absent")
        return True
    text = read_text(OFFICE_PROTO)
    m = re.search(r"const ZONES\s*=\s*\[(.*?)\];", text, re.S)
    if not m:
        record("FAIL", name, "ZONES array not found")
        return False
    zone_keys = re.findall(r"key:'([a-z]+)'", m.group(1))
    # zoneOf() body = from its opening brace to the next top-level `function `.
    anchor = "function zoneOf(r){"
    start = text.find(anchor)
    if start < 0:
        record("FAIL", name, "zoneOf() not found")
        return False
    rest = text[start + len(anchor):]
    nxt = rest.find("function ")
    zbody = rest[:nxt] if nxt >= 0 else rest
    zone_outputs = set(re.findall(r"'([a-z_]+)'", zbody))
    cli_bridge_wired = "mapCliBridge" in text and "/api/cli-bridge" in text
    # Same shape as cli: PR figures never come out of zoneOf() because they are not
    # sessions -- their signal path is /api/prs -> mapPRs, so that path IS the proof
    # the zone is not a shell. Rip the fetch out and the zone fails here.
    prs_wired = "mapPRs" in text and "/api/prs" in text
    allowed = set(zone_outputs)
    if cli_bridge_wired:
        allowed.add("cli")
    if prs_wired:
        allowed.add("pr")
    missing = ["zone '%s' has no signal source (shell)" % k
               for k in zone_keys if k not in allowed]
    missing += ["signal-less shell '%s' reintroduced" % s
                for s in ("meeting",) if s in zone_keys]
    # Per-zone signal ledger: naming the concrete producer (monitor.py) and the
    # consumer (office_proto.html) for EVERY drawn zone. A zone absent from the
    # ledger is a shell by definition; a ledger needle that vanished means the
    # zone is still drawn after its signal was ripped out.
    mon = read_text(MONITOR) if os.path.exists(MONITOR) else ""
    sources = {"ui": text, "monitor": mon}
    zone_signals = {
        "coding":  {"ui": ["r.work_kind", "r.work_detail"],
                    "monitor": ['row["work_kind"]', 'row["work_detail"]']},
        "docs":    {"ui": ["r.work_detail"], "monitor": ['row["work_detail"]']},
        "testing": {"ui": ["r.work_detail"], "monitor": ['row["work_detail"]']},
        "review":  {"ui": ["r.work_review"], "monitor": ['row["work_review"]']},
        # 3AI council: work_council on office rows <- _COUNCIL_CMD_RE/council_cmd
        "council": {"ui": ["r.work_council", "COUNCIL_PHASE"],
                    "monitor": ['row["work_council"]', "_COUNCIL_CMD_RE", "council_cmd"]},
        "cli":     {"ui": ["mapCliBridge", "/api/cli-bridge"], "monitor": ["now_running"]},
        # PR zone: GitHub's own open-PR list <- collect_github_prs (one gh api graphql
        # call, cached, served from /api/prs and never from build_status). _pr_state is
        # the honest bucketing -- without it the zone would have to guess 可合併/等CI/衝突.
        "pr":      {"ui": ["mapPRs", "/api/prs", "PR_STATE", "prNote"],
                    "monitor": ["collect_github_prs", "_pr_state"]},
        # standby is SPLIT: 等你回覆 <- wait_kind, 真閒置 <- absence of wait_kind
        "standby": {"ui": ["standbyWait", "standbyGroup", "r.wait_kind", "WAIT_PHRASE"],
                    "monitor": ['"wait_kind": s.get("wait_kind")']},
        "offline": {"ui": ["r.status==='stopped'"],
                    "monitor": ['"status": s.get("status")']},
    }
    def wired(needle, src):
        # identifier-exact: `_COUNCIL_CMD_RE` must not be satisfied by `_COUNCIL_CMD_REX`
        return re.search(r"(?<![A-Za-z0-9_])" + re.escape(needle) + r"(?![A-Za-z0-9_])",
                         src) is not None
    for k in zone_keys:
        reqs = zone_signals.get(k)
        if reqs is None:
            missing.append("zone '%s' names no signal in the no-shell ledger (shell)" % k)
            continue
        for where in sorted(reqs):
            missing += ["zone '%s': %s signal %r is gone" % (k, where, n)
                        for n in reqs[where] if not wired(n, sources[where])]
    if "standby" in zone_keys:
        # standby split must keep BOTH seat groups: wait (has wait_kind) and idle (has not)
        sg = re.search(r"function standbyGroup\(a\)\{(.*?)\}", text, re.S)
        if not sg:
            missing.append("standbyGroup() gone: 待命 split has no wait/idle grouping")
        elif not ("'wait'" in sg.group(1) and "'idle'" in sg.group(1)):
            missing.append("standbyGroup() lost the wait/idle split (等你回覆 vs 真閒置)")
        # ...and the 等你回覆 group must still be GATED on wait_kind, not just label it
        sw = re.search(r"function standbyWait\(r\)\{(.*?)\}", text, re.S)
        if not sw:
            missing.append("standbyWait() gone: 等你回覆 has no wait_kind source")
        elif not re.search(r"&&\s*r\.wait_kind(?![A-Za-z0-9_])", sw.group(1)):
            missing.append("standbyWait() no longer gates 等你回覆 on r.wait_kind")
    if missing:
        record("FAIL", name, "; ".join(missing))
        return False
    record("PASS", name,
           "%d zones all signal-backed (cli<-/api/cli-bridge, rest<-zoneOf) + "
           "per-zone ledger wired end-to-end (council<-work_council, standby split<-wait_kind)"
           % len(zone_keys))
    return True


OFFICE2_COUNCIL_DRIVER = r'''
import json, os, sys, tempfile
sys.path.insert(0, os.getcwd())
import monitor

def fail(msg):
    print("FAIL: " + msg)
    sys.exit(1)

if not hasattr(monitor, "_COUNCIL_CMD_RE"):
    fail("_COUNCIL_CMD_RE not defined in monitor.py (task not landed yet?)")
for marker in ("cli_bridge_dispatch.py", "codex exec", "gemini --", "agy "):
    if not monitor._COUNCIL_CMD_RE.search("x " + marker + " y"):
        fail("_COUNCIL_CMD_RE does not match marker %r" % marker)

# Real dispatch shape: `cd <repo>` on line 1, dispatch on line 2+ -- exactly the
# case _tool_target() (line 1, 80 chars) cannot see.
DISPATCH = "cd /c/myrepo/x\npython /c/myrepo/tools/cli_bridge_dispatch.py --agent codex"

def tail_of(command):
    tmp = tempfile.mkdtemp(prefix="pfcouncil_")
    p = os.path.join(tmp, "s.jsonl")
    line = {"type": "assistant", "message": {"content": [
        {"type": "tool_use", "name": "Bash", "input": {"command": command}}]}}
    with open(p, "w", encoding="utf-8") as f:
        f.write(json.dumps(line) + "\n")
    return monitor.claude_live_tail(p)

hit = tail_of(DISPATCH)
if "council_cmd" not in hit:
    fail("claude_live_tail() does not expose a 'council_cmd' key")
if hit["council_cmd"] != "cli_bridge_dispatch.py":
    fail("dispatch command not detected: council_cmd=%r" % (hit["council_cmd"],))
if "cli_bridge_dispatch" in (hit.get("target") or ""):
    fail("fixture is not exercising the full-command scan (target already carries it)")

miss = tail_of("ls -la")
if miss.get("council_cmd") is not None:
    fail("plain 'ls -la' falsely detected as council dispatch: %r"
         % (miss["council_cmd"],))
if miss.get("tool") != "Bash":
    fail("non-council tail lost its tool name: %r" % (miss.get("tool"),))

print("OK")
'''


def cmd_check_office2_council():
    """3AI council dispatch detection: monitor.py must carry the marker regex and
    claude_live_tail() must expose a `council_cmd` key derived from the FULL
    tool_use command, not the line-1/80-char `target`."""
    return run_py_driver(OFFICE2_COUNCIL_DRIVER, "check-office2-council")


OFFICE2_COUNCIL_PHASE_DRIVER = r'''
import inspect, os, sys
sys.path.insert(0, os.getcwd())
import monitor

def fail(msg):
    print("FAIL: " + msg)
    sys.exit(1)

for name in ("_council_state", "_council_helper_running", "enrich_office_rows"):
    if not hasattr(monitor, name):
        fail("monitor.%s not defined (task not landed yet?)" % name)

MARKER = {"text": None, "tool": "Bash", "target": "cd /c/myrepo/x",
          "council_cmd": "cli_bridge_dispatch.py"}
CALLS = []

def run(rows, tail, running=(), now=1000.0):
    """Drive the REAL enrich_office_rows; the bridge + tail are the only fixtures."""
    monitor._council_bridge_cache.update({"at": 0.0, "running": False})
    def bridge():
        CALLS.append(1)
        return {"now_running": list(running), "recent": [], "wait_s": 0.0}
    old_tail, old_bridge = monitor.claude_live_tail, monitor.collect_cli_bridge
    monitor.claude_live_tail = lambda _p: dict(tail)
    monitor.collect_cli_bridge = bridge
    try:
        monitor.enrich_office_rows({}, rows, now, True, {})
    finally:
        monitor.claude_live_tail, monitor.collect_cli_bridge = old_tail, old_bridge
    return rows

def phase(label, tail, wait_kind=None, running=(), sid=None):
    row = {"session_id": sid or ("fx-" + label), "source_ai": "claude",
           "status": "waiting" if wait_kind else "running",
           "wait_kind": wait_kind, "_office_path": "fixture.jsonl"}
    run([row], tail, running)
    wc = row.get("work_council")
    if not isinstance(wc, dict) or set(wc) != {"in_council", "phase"}:
        fail("work_council must be {'in_council':..,'phase':..}; %s got %r" % (label, wc))
    if "_office_live" in row:
        fail("internal live-tail scratch key leaked onto the office row")
    return wc

# --- phase 'wait', in-flight dispatch (no helper visible yet) -----------------
wc = phase("inflight", dict(MARKER, tool_done=False))
if wc != {"in_council": True, "phase": "wait"}:
    fail("in-flight dispatch must be phase 'wait'; got %r" % (wc,))

# --- phase 'wait', run_in_background dispatch (43% of real ones): the Bash call
# already returned, so ONLY the marker + a live helper can see it ---------------
wc = phase("bg", dict(MARKER, tool_done=True), running=[{"agent": "codex", "pid": 1}])
if wc != {"in_council": True, "phase": "wait"}:
    fail("background dispatch with a live helper must be 'wait' (not 'integrate'); got %r" % (wc,))

# --- phase 'integrate' (inferred): helper gone, parent not executing again -----
wc = phase("integrate", dict(MARKER, tool_done=True))
if wc != {"in_council": True, "phase": "integrate"}:
    fail("helper gone + parent not executing must be 'integrate'; got %r" % (wc,))

# --- phase 'await_user' beats BOTH wait and integrate -------------------------
wc = phase("await-over-wait", dict(MARKER, tool_done=False), wait_kind="ask",
           running=[{"agent": "codex", "pid": 1}])
if wc != {"in_council": True, "phase": "await_user"}:
    fail("await_user must outrank wait; got %r" % (wc,))
wc = phase("await-over-integrate", dict(MARKER, tool_done=True), wait_kind="plan")
if wc != {"in_council": True, "phase": "await_user"}:
    fail("await_user must outrank integrate; got %r" % (wc,))

# --- no dispatch marker -> not in council at all ------------------------------
wc = phase("plain", {"text": None, "tool": "Bash", "target": "ls -la",
                     "tool_done": False, "council_cmd": None})
if wc != {"in_council": False, "phase": None}:
    fail("a non-council row must be {in_council: False, phase: None}; got %r" % (wc,))
wc = phase("plain-wait", {"text": None, "tool": "Bash", "target": "ls -la",
                          "tool_done": True, "council_cmd": None}, wait_kind="ask")
if wc != {"in_council": False, "phase": None}:
    fail("await_user must NOT fire without a council marker; got %r" % (wc,))

# --- perf iron rule: at most ONE collect_cli_bridge() per poll, never per row --
del CALLS[:]
rows = [{"session_id": "perf-%d" % i, "source_ai": "claude", "status": "running",
         "wait_kind": None, "_office_path": "fixture.jsonl"} for i in range(6)]
run(rows, dict(MARKER, tool_done=True))
if len(CALLS) > 1:
    fail("collect_cli_bridge() called %d times for 6 rows (must be cached, <=1)" % len(CALLS))
if any(r.get("work_council", {}).get("phase") != "integrate" for r in rows):
    fail("cached bridge snapshot changed the resolved phase")

# --- honesty: 'integrate' must be documented as an inference, not a measurement -
src = inspect.getsource(monitor._council_state) + inspect.getsource(monitor._council_helper_running)
if "infer" not in src.lower():
    fail("'integrate' is inferred, not measured -- the backend must say so at the source")

print("OK")
'''


def cmd_check_office2_council_phase():
    """Council phase resolution on office rows: work_council = {in_council, phase}
    with phase in wait/integrate/await_user, priority await_user > wait > integrate,
    'integrate' honestly marked inferred, and ONE bridge snapshot per poll."""
    return run_py_driver(OFFICE2_COUNCIL_PHASE_DRIVER, "check-office2-council-phase")


# Renamed off the old "zones8" spelling 2026-08-05: the count moved to 9 when the PR zone
# filled the grid cell that was until then deliberately left empty, and a check whose NAME
# pins a headcount has to be renamed every time the floor grows. The layout invariants below
# (3 rows, no overlap, on-floor) are what actually matters, not the number.
OFFICE2_ZONE_KEYS = ["coding", "docs", "testing", "review", "council",
                     "cli", "standby", "pr", "offline"]

OFFICE2_ZONES_DRIVER = r"""
function fail(m){console.log("FAIL: "+m);process.exit(1);}
__ZONE_OF__
var IN={in_council:true,phase:"wait"}, OUT={in_council:false,phase:null};
// offline outranks everything, council included
if(zoneOf({status:"stopped",work_council:IN,work_review:true,work_kind:"working",work_detail:"code"})!=="offline")
  fail("offline must outrank council");
if(zoneOf({status:"stale",work_council:IN})!=="offline")fail("a stale row must be offline");
// council outranks review
if(zoneOf({status:"running",work_council:IN,work_review:true,work_kind:"working",work_detail:"code"})!=="council")
  fail("council must outrank review");
// council outranks work_detail and standby
if(zoneOf({status:"running",work_council:{in_council:true,phase:"integrate"},work_kind:"working",work_detail:"docs"})!=="council")
  fail("council must outrank work_detail");
if(zoneOf({status:"running",work_council:{in_council:true,phase:"await_user"},work_kind:"standby"})!=="council")
  fail("council must outrank standby");
// review still outranks work_detail once council is out of the way
if(zoneOf({status:"running",work_council:OUT,work_review:true,work_kind:"working",work_detail:"code"})!=="review")
  fail("review must outrank work_detail");
// work_detail outranks the standby floor
if(zoneOf({status:"running",work_kind:"working",work_detail:"docs"})!=="docs")fail("work_detail docs -> docs");
if(zoneOf({status:"running",work_kind:"working",work_detail:"test"})!=="testing")fail("work_detail test -> testing");
if(zoneOf({status:"running",work_kind:"working",work_detail:"code"})!=="coding")fail("work_detail code -> coding");
// standby is the floor, and in_council:false must never reach the council zone
if(zoneOf({status:"running",work_kind:"standby"})!=="standby")fail("work_kind standby -> standby");
if(zoneOf({status:"running"})!=="standby")fail("unknown work_kind must fall back to standby");
if(zoneOf({status:"running",work_council:OUT,work_kind:"standby"})!=="standby")
  fail("in_council:false must not route to the council zone");
if(zoneOf({status:"running",work_council:OUT,work_kind:"cli_queue"})!=="cli")
  fail("cli_queue routing was lost");
console.log("OK");
"""


def extract_js_function(text, anchor):
    """Brace-matched source of the JS function starting at `anchor`, else None."""
    start = text.find(anchor)
    if start < 0:
        return None
    depth = 0
    for j in range(text.find("{", start), len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[start:j + 1]
    return None


def office2_zones_zoneof_problem(text):
    """Run the extracted zoneOf() DOM-free and assert the fixed zone priority
    offline > council > review > work_detail > standby. Returns a problem string
    (folded into the single check-office2-zones record) or None when green."""
    node = shutil.which("node")
    if not node:
        return "node is required for the zone-priority fixture"
    src = extract_js_function(text, "function zoneOf(r){")
    if not src:
        return "zoneOf() not found in ui/office_proto.html"
    fd, tmp = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(OFFICE2_ZONES_DRIVER.replace("__ZONE_OF__", src))
        proc = subprocess.run([node, tmp], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    finally:
        os.unlink(tmp)
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode == 0 and out.splitlines()[-1:] == ["OK"]:
        return None
    return ("zoneOf priority: "
            + (out.splitlines()[-1] if out else "harness exit %d" % proc.returncode))


def cmd_check_office2_zones():
    """Office floor layout: ZONES holds exactly the layout cells named in
    OFFICE2_ZONE_KEYS -- the 3AI council zone and the PR zone that fills the fourth
    cell of row 2 (fixed full-bleed, 3 rows, no overlap and no overflow), zoneOf()
    routes work_council with priority offline > council > review > work_detail >
    standby, the council sub-phase labels are wired through COUNCIL_PHASE with the
    'integrate' one keeping its honest "(推估)" suffix (only 17% of real dispatches
    show a positive integrate signal -- it is inferred, not measured), and the
    cli_bridge helper tokens stay in the CLI-queue zone."""
    name = "check-office2-zones"
    if not os.path.exists(OFFICE_PROTO):
        record("SKIP", name, "ui/office_proto.html absent")
        return True
    text = read_text(OFFICE_PROTO)
    m = re.search(r"const ZONES\s*=\s*\[(.*?)\];", text, re.S)
    if not m:
        record("FAIL", name, "ZONES array not found")
        return False
    block = m.group(1)
    problems = []
    keys = re.findall(r"key:'([a-z_]+)'", block)
    if keys != OFFICE2_ZONE_KEYS:
        problems.append("ZONES keys %r != expected %d %r"
                        % (keys, len(OFFICE2_ZONE_KEYS), OFFICE2_ZONE_KEYS))
    if "3AI共議" not in block:
        problems.append("the council zone carries no 【3AI共議】 label")
    # decimals are required since the 2026-07-29 uniform grid (cols are 23.375 wide);
    # the old (\d+) silently matched nothing and reported "got 1"
    _num = r"([0-9]+(?:\.[0-9]+)?)"
    rects = re.findall(r"key:'([a-z_]+)'.*?x:\s*%s,\s*y:\s*%s,\s*w:\s*%s,\s*h:\s*%s"
                       % (_num, _num, _num, _num), block)
    if len(rects) != len(OFFICE2_ZONE_KEYS):
        problems.append("could not parse %d zone rects (got %d)"
                        % (len(OFFICE2_ZONE_KEYS), len(rects)))
    else:
        rows = {}
        for k, x, y, w, h in rects:
            x, y, w, h = float(x), float(y), float(w), float(h)
            if x + w > 100.001 or y + h > 100.001:   # float slack
                problems.append("zone '%s' runs off the floor's 0-100 coordinate box" % k)
            rows.setdefault(y, []).append((x, x + w, k))
        if len(rows) != 3:
            problems.append("layout must stay 3 rows, found %d" % len(rows))
        if not 9 <= len(rows) * max(len(c) for c in rows.values()) <= 12:
            problems.append("3-row cell budget blown: %d rows x %d widest"
                            % (len(rows), max(len(c) for c in rows.values())))
        for y, cells in rows.items():
            cells.sort()
            for a, b in zip(cells, cells[1:]):
                if b[0] < a[1]:
                    problems.append("zones '%s'/'%s' overlap in row y=%d" % (a[2], b[2], y))
    cm = re.search(r"const COUNCIL_PHASE\s*=\s*\{(.*?)\};", text, re.S)
    if not cm:
        problems.append("COUNCIL_PHASE sub-phase label map not found")
    else:
        for phase, label in (("wait", "等待別家"), ("integrate", "整合中(推估)"),
                             ("await_user", "等你決定")):
            if not re.search(r"\b%s\s*:\s*'%s'" % (phase, re.escape(label)), cm.group(1)):
                problems.append("phase '%s' must be labelled '%s'" % (phase, label))
        if "(推估)" not in cm.group(1):
            problems.append("the integrate label dropped its honest '(推估)' suffix")
    if "COUNCIL_PHASE[r.work_council.phase]" not in text:
        problems.append("mapStatus does not feed work_council.phase through COUNCIL_PHASE")
    helpers = extract_js_function(text, "function mapCliBridge(")
    if helpers is None or "zone:'cli'" not in helpers or "council" in helpers:
        problems.append("cli_bridge helper tokens must stay in the CLI-queue zone")
    # The PR figures are the same shape of non-session token: they must stay in their own
    # zone, and they must NOT invent an AI vendor for something that has none.
    prs = extract_js_function(text, "function mapPRs(")
    if prs is None or "zone:'pr'" not in prs or "vend:''" not in prs:
        problems.append("PR tokens must stay in the PR zone and claim no vendor")
    zone_problem = office2_zones_zoneof_problem(text)
    if zone_problem:
        problems.append(zone_problem)
    if problems:
        record("FAIL", name, "; ".join(problems))
        return False
    record("PASS", name, "%d zones incl. 3AI共議 and PR, 3 non-overlapping full-bleed rows, "
           "offline > council > review > work_detail > standby, integrate label keeps (推估)"
           % len(OFFICE2_ZONE_KEYS))
    return True


OFFICE2_STANDBY_SPLIT_DRIVER = r"""
function fail(m){console.log("FAIL: "+esc(m));process.exit(1);}
// keep CJK, drop emoji: the parent prints this line on a cp950 console
function esc(s){return String(s).replace(/[^\x20-\x7e一-鿿]/g,"?");}
__ZONES__
__SEAT__
__SUB__
__SUB_DROP__
__STALL_BOX__
__SEAT_BAND__
__WAIT_PHRASE__
__ZONE_OF__
__STANDBY_WAIT__
__STANDBY_GROUP__
__SEAT_BAND_FN__
__SEAT_GRID__
__SEAT_XY__
function row(wait_kind){return {status:"running",work_kind:"standby",wait_kind:wait_kind};}
// 1. every wait_kind maps to the EXISTING backend label (monitor._wait_phrase)
var CASES=[["question","__L_QUESTION__"],["plan_review","__L_PLAN__"],
           ["idle","__L_OTHER__"],["ask","__L_OTHER__"]];
CASES.forEach(function(c){
  var got=standbyWait(row(c[0]));
  if(got!==c[1])fail("wait_kind '"+c[0]+"' must map to the existing label "+esc(c[1])+"; got "+esc(got));
  if(standbyGroup({zone:"standby",wait:got})!=="wait")
    fail("a person with wait_kind '"+c[0]+"' must sit in the 等你回覆 group");
});
// 2. no wait_kind -> 真閒置 (no label, other group)
if(standbyWait(row(null))!==null)fail("a person with no wait_kind must carry no wait label");
if(standbyWait({status:"running",work_kind:"standby"})!==null)
  fail("a missing wait_kind must not fabricate a label");
if(standbyGroup({zone:"standby",wait:null})!=="idle")fail("no wait_kind must land in 真閒置");
if(standbyGroup({zone:"standby",wait:null})===standbyGroup({zone:"standby",wait:"x"}))
  fail("等你回覆 and 真閒置 must be different groups");
// 3. the split is standby-only: the council zone keeps its own sub-phase label
if(standbyWait({status:"running",work_council:{in_council:true,phase:"await_user"},
                wait_kind:"question"})!==null)
  fail("a council row must not also get a standby wait label (double label)");
if(standbyGroup({zone:"council",wait:"x"})!==null)fail("only the standby zone is split");
if(standbyGroup({zone:"coding",wait:null})!==null)fail("only the standby zone is split");
// 4. the two groups are rendered at visibly different seats, both inside the zone rect
var z=ZONES.filter(function(q){return q.key==="standby";})[0];
if(!z)fail("standby zone missing from ZONES");
var w=seatXY("standby",0,"wait"), i=seatXY("standby",0,"idle");
if(!(Math.abs(w.py-i.py)>=z.h*0.2))
  fail("the two standby groups must be seated in visibly separate rows");
[["wait",w],["idle",i]].forEach(function(p){
  if(p[1].py<z.y||p[1].py>z.y+z.h||p[1].px<z.x||p[1].px>z.x+z.w)
    fail("the '"+p[0]+"' group is seated outside the 待命 zone");
});
// 5. seating for every other zone is untouched
var c=ZONES.filter(function(q){return q.key==="coding";})[0];
if(Math.abs(seatXY("coding",0,null).py-(c.y+c.h*0.44))>1e-9)
  fail("non-standby seating drifted");
console.log("OK");
"""


def office2_standby_split_js_problem(text, labels):
    """Run the extracted standby-split helpers DOM-free: each wait_kind -> its
    existing backend label, no wait_kind -> 真閒置, and the two groups get
    visibly separate seats inside the 待命 zone."""
    node = shutil.which("node")
    if not node:
        return "node is required for the standby-split fixture"
    parts = {
        "__ZONE_OF__": extract_js_function(text, "function zoneOf(r){"),
        "__STANDBY_WAIT__": extract_js_function(text, "function standbyWait(r){"),
        "__STANDBY_GROUP__": extract_js_function(text, "function standbyGroup(a){"),
        "__SEAT_BAND_FN__": extract_js_function(text, "function seatBand(zoneKey, grp){"),
        "__STALL_BOX__": extract_js_function(text, "function stallBox(k){"),
        "__SEAT_GRID__": extract_js_function(text, "function seatGrid(zoneKey, grp, n, kmax){"),
        "__SEAT_XY__": extract_js_function(text, "function seatXY(zoneKey, idx, grp, n, kmax){"),
    }
    for m, pat in (("__ZONES__", r"const ZONES\s*=\s*\[.*?\];"),
                   ("__SEAT__", r"const SEAT\s*=\s*\{.*?\};"),
                   ("__SUB__", r"const SUB\s*=\s*\{.*?\};"),
                   ("__SUB_DROP__", r"const SUB_DROP\s*=[^;]+;"),
                   ("__SEAT_BAND__", r"const SEAT_BAND\s*=\s*\{.*?\};"),
                   ("__WAIT_PHRASE__", r"const WAIT_PHRASE\s*=\s*\{.*?\};")):
        hit = re.search(pat, text, re.S)
        parts[m] = hit.group(0) if hit else None
    missing = [k for k, v in parts.items() if not v]
    if missing:
        return "not found in ui/office_proto.html: " + ", ".join(sorted(missing))
    src = OFFICE2_STANDBY_SPLIT_DRIVER
    for k, v in parts.items():
        src = src.replace(k, v)
    for k, v in (("__L_QUESTION__", labels["question"]),
                 ("__L_PLAN__", labels["plan_review"]), ("__L_OTHER__", labels["other"])):
        src = src.replace(k, v)
    fd, tmp = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(src)
        proc = subprocess.run([node, tmp], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    finally:
        os.unlink(tmp)
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode == 0 and out.splitlines()[-1:] == ["OK"]:
        return None
    return "standby split: " + (out.splitlines()[-1] if out
                                else "harness exit %d" % proc.returncode)


def py_function_source(src, header):
    """Source of a top-level python def, from `header` to the next top-level def /
    class. (extract_js_function's brace matching cannot be used on python: an
    f-string's {placeholder} closes the match early.)"""
    start = src.find(header)
    if start < 0:
        return None
    rest = src[start + len(header):]
    ends = [i for i in (rest.find("\ndef "), rest.find("\nclass ")) if i >= 0]
    return header + (rest[:min(ends)] if ends else rest)


def monitor_wait_labels():
    """The THREE wait phrases already shipped by monitor._wait_phrase, so the UI is
    forced to reuse them instead of inventing new wording. None when unparseable."""
    body = py_function_source(read_text(MONITOR), "def _wait_phrase(kind):")
    if not body:
        return None
    q = re.search(r'"question"\s*:\s*"([^"]+)"', body)
    p = re.search(r'"plan_review"\s*:\s*"([^"]+)"', body)
    o = re.search(r'\.get\(kind,\s*"([^"]+)"\)', body)
    if not (q and p and o):
        return None
    return {"question": q.group(1), "plan_review": p.group(1), "other": o.group(1)}


def cmd_check_office2_standby_split():
    """待命 zone split (owner: standby must stop being a dumping ground): a person
    WITH a wait_kind sits in the 等你回覆 group carrying monitor._wait_phrase's
    EXISTING label, a person with NO wait_kind is 真閒置 and is drawn as a visibly
    separate group. Display-only -- the waiting-state push already fires backend-side,
    so no new notification call may appear."""
    name = "check-office2-standby-split"
    if not os.path.exists(OFFICE_PROTO):
        record("SKIP", name, "ui/office_proto.html absent")
        return True
    text = read_text(OFFICE_PROTO)
    labels = monitor_wait_labels()
    problems = []
    if not labels:
        problems.append("monitor._wait_phrase labels not parseable -- cannot prove reuse")
    else:
        for kind, lab in sorted(labels.items()):
            if lab not in text:
                problems.append("wait label for '%s' is not the existing backend string" % kind)
    for group in ("等你回覆", "真閒置"):
        if group not in text:
            problems.append("standby group '%s' is not rendered" % group)
    furn = extract_js_function(text, "function furnHTML(key){")
    if not furn or "等你回覆" not in furn or "真閒置" not in furn:
        problems.append("the 待命 room draws no group bands for the two standby groups")
    if "standbyWait(r)" not in text:
        problems.append("mapStatus does not feed wait_kind through standbyWait()")
    # display-only: no notification sink may be introduced in the office UI, and the
    # backend waiting alert must stay a SINGLE push (no double-notify of the owner).
    sinks = [s for s in ("ntfy", "send_alert", "notify_hook", "new Notification",
                         "telegram") if s in text]
    if sinks:
        problems.append("notification code introduced in the office UI: " + ", ".join(sinks))
    upd = py_function_source(read_text(MONITOR), "def update_and_alert(cfg, rows, source):")
    if upd is None:
        problems.append("monitor.update_and_alert not found")
    elif upd.count("send_alert(") != 2:
        problems.append("update_and_alert fires %d alerts (expected the existing 2: "
                        "waiting + quiet) -- the split must not add a push"
                        % upd.count("send_alert("))
    if not problems:
        js = office2_standby_split_js_problem(text, labels)
        if js:
            problems.append(js)
    if problems:
        record("FAIL", name, "; ".join(problems))
        return False
    record("PASS", name, "待命 split into 等你回覆 (existing _wait_phrase labels) + 真閒置, "
           "separate seats, no new notification")
    return True


def office2_mach_badge_js(text):
    """machBadge() plus the MACHINES registry it closes over. personEl() calls it, so
    every DOM-free personEl fixture has to inject it (same reason __STALE_BADGE__ is
    injected everywhere). `let` so a fixture can load a registry into it. None when
    either half is gone."""
    fn = extract_js_function(text, "function machBadge(a){")
    reg = re.search(r"let MACHINES\s*=\s*\{[^{}]*\};", text)
    # LOCALM (this box's registry key, from /api/status) is the second thing machBadge
    # closes over: a local row carries no `machine`, so without it every local row falls
    # back to its OS and two Windows boxes render identically. Injected here for the same
    # reason MACHINES is -- a DOM-free fixture must see the whole closure.
    loc = re.search(r"let LOCALM\s*=\s*'[^']*';", text)
    los = re.search(r"let LOCALOS\s*=\s*'[^']*';", text)
    return ((reg.group(0) + "\n" + loc.group(0) + "\n" + los.group(0) + "\n" + fn)
            if (fn and reg and loc and los) else None)


def office2_stale_badge_js(text):
    """staleBadge() plus the STALE_* constants it closes over. personEl() calls it, so
    every DOM-free personEl fixture has to inject it (same reason __CTX_BADGE__ is
    injected everywhere). None when either half is gone."""
    fn = extract_js_function(text, "function staleBadge(a){")
    consts = re.search(r"const STALE_PHRASE\s*=.*?;", text, re.S)
    return (consts.group(0) + "\n" + fn) if (fn and consts) else None


def office2_hook_pm_js(text):
    """pmBadge()/hookBadge() plus the PMODE/HOOKSTEP tables they close over. personEl()
    calls both, so every DOM-free personEl fixture has to inject them (same reason
    __STALE_BADGE__ is injected everywhere). None when any of the four halves is gone."""
    parts = [re.search(r"const PMODE\s*=\s*\{.*?\};", text, re.S),
             re.search(r"const HOOKSTEP\s*=\s*\[.*?\];", text, re.S)]
    if not all(parts):
        return None
    fns = [extract_js_function(text, "function pmBadge(a){"),
           extract_js_function(text, "function hookBadge(a){")]
    if not all(fns):
        return None
    return "\n".join([p.group(0) for p in parts] + fns)


def office2_subs_badge_js(text):
    """subsBadge() plus the SUB_GLYPH/SUB_HIDDEN_* literals it closes over. personEl()
    calls it, so every DOM-free personEl fixture has to inject it (same reason
    __HOOK_PM__ is injected everywhere). None when either half is gone."""
    consts = re.search(r"const SUB_GLYPH\s*=.*?;", text, re.S)
    fn = extract_js_function(text, "function subsBadge(a){")
    return (consts.group(0) + "\n" + fn) if (fn and consts) else None


def office2_person_el_js(text):
    """personEl() plus personTip(), the tooltip helper it calls (routing evidence, how long
    this turn has run, and task progress), the four row badges it draws (project / model /
    open tasks / age, with the ago() and fmtMin() time formats they mirror out of
    ui/dashboard.html), and batchColor()/BATCH_PALETTE, the launch-batch colour it stamps
    on the figure. Every DOM-free personEl fixture fills its __PERSON_EL__ slot with this,
    so the helpers travel with the function that needs them (same reason __STALE_BADGE__ is
    injected everywhere). None when any half is gone."""
    consts = [re.search(r"const PROJ_GLYPH\s*=.*?;", text),
              re.search(r"const ELAPSED_GLYPH\s*=.*?;", text),
              re.search(r"const BATCH_PALETTE\s*=\s*\[.*?\];", text, re.S),
              # TOKSTEP/tokBadge: the cost-axis badge personEl draws next to the
              # ctx one (asm-009). Travels here for the reason in the docstring
              # -- without it every DOM-free personEl fixture ReferenceErrors.
              re.search(r"const TOKSTEP\s*=\s*\[.*?\];", text, re.S)]
    fns = [extract_js_function(text, a) for a in (
        "function batchColor(k){", "function projBadge(a){", "function modelBadge(a){",
        "function tasksBadge(a){", "function ago(ts){", "function ageBadge(a){",
        "function fmtMin(sec){", "function elapsedText(a){", "function tokBadge(n){",
        "function personTip(a){", "function personEl(a, mini){")]
    if not (all(consts) and all(fns)):
        return None
    return "\n".join([c.group(0) for c in consts] + fns)


def office2_map_status_js(text):
    """mapStatus() plus routeEvidence() and the ROUTE_EVIDENCE wording it closes over,
    and officeOrdinals(), the stable display-ordinal pass it runs over the whole poll.
    mapStatus calls both on every poll, so every DOM-free fixture that maps /api/status
    has to inject them (same reason __STALE_BADGE__ is injected everywhere). None when
    any of the four halves is gone."""
    consts = re.search(r"const ROUTE_EVIDENCE\s*=\s*\{.*?\};", text, re.S)
    route = extract_js_function(text, "function routeEvidence(r){")
    ordinals = extract_js_function(text, "function officeOrdinals(rows){")
    fn = extract_js_function(text, "function mapStatus(d){")
    return ("\n".join([consts.group(0), route, ordinals, fn])
            if (consts and route and ordinals and fn) else None)


OFFICE2_OS_ICON_DRIVER = r"""
function fail(m){console.log("FAIL: "+asc(m));process.exit(1);}
// keep CJK, drop emoji: the parent prints this line on a cp950 console.
// NAMED asc(), NOT esc(). The page has its own esc() (HTML-escape) and the functions
// under test call it; a console helper also called esc() SHADOWED it, so machBadge's
// esc(m.icon) stripped the emoji to "?" and the registry-icon assertion failed on a
// correct page. The real esc() is injected below via __ESC__, same as every other driver.
function asc(s){return String(s).replace(/[^\x20-\x7e一-鿿]/g,"?");}
__ESC__
// fixture stubs -- personEl only reads .img/.key off a creature and never touches the real DOM
var CREATURES=[{key:"c0",img:"a.png"},{key:"c1",img:"b.png"}];
var document={createElement:function(){return {style:{setProperty:function(){}},
  querySelector:function(){return null;}};}};
__VEND__
__STDOT__
__OSICON__
__OS_ICON__
__MACH_BADGE__
__COUNCIL_PHASE__
__WAIT_PHRASE__
__CTXSTEP__
__HASH_INT__
__ZONE_OF__
__ST_OF__
__STANDBY_WAIT__
__CTX_BADGE__
__STALE_BADGE__
__HOOK_PM__
__SUBS_BADGE__
__PERSON_EL__
__MAP_STATUS__
function plate(a){return String(personEl(a,false).innerHTML);}
function base(extra){var a={id:"A1",vend:"cc",cre:0,st:"working",label:"L",subs:[]};
  for(var k in extra)a[k]=extra[k];return a;}
// 1. mapStatus must CARRY the backend os/machine signal through to the person model
var rows={claude:[{session_id:"s1",status:"running",work_kind:"working",os:"mac"},
                  {session_id:"s2",status:"running",work_kind:"working",os:"win",machine:"company"},
                  {session_id:"s3",status:"running",work_kind:"working"}]};
var m=mapStatus(rows);
if(m.length!==3)fail("mapStatus returned "+m.length+" people (expected 3)");
if(!("os" in m[0]))fail("mapStatus drops the backend os field -- office2 loses the OS signal");
if(m[0].os!=="mac")fail("mapStatus must carry r.os; got "+asc(m[0].os));
if(m[1].os!=="win")fail("mapStatus must carry r.os; got "+asc(m[1].os));
if(m[1].machine!=="company")fail("mapStatus must carry r.machine; got "+asc(m[1].machine));
if(m[2].os!=="")fail("a row with no os must map to an empty os, not "+asc(m[2].os));
if(m[2].machine!=="")fail("a row with no machine must map to empty, not "+asc(m[2].machine));
// 2. EVERY os value the backend can emit maps to an icon, end to end through personEl.
// CASES is derived from monitor.os_of_cwd + the dashboard's OSI glyphs -- never hardcoded here.
__OS_CASES__
CASES.forEach(function(c){
  if(osIcon({os:c[0]})!==c[1])fail("os '"+c[0]+"' must map to its icon; got "+asc(osIcon({os:c[0]})));
  var h=plate(base({os:c[0]}));
  if(h.indexOf('<span class="osi">'+c[1]+"</span>")<0)
    fail("personEl must render the OS icon for '"+c[0]+"'");
  if(h.indexOf('class="nameplate"')<0||h.indexOf('class="osi"')>h.indexOf("</div>"))
    fail("the OS icon must sit inside the nameplate (fixed no-scroll layout)");
});
// machine (a registry key) wins when it names an OS, else the os value still shows
function want(k){for(var i=0;i<CASES.length;i++)if(CASES[i][0]===k)return CASES[i][1];
  fail("the backend can emit os '"+k+"' but no icon is expected for it");}
if(osIcon({os:"win",machine:"company"})!==want("win"))
  fail("an unrecognised machine must fall back to the os icon");
if(osIcon({os:"win",machine:"mac"})!==want("mac"))fail("machine must win over os");
// 3. a row with NO os degrades gracefully: no icon element, no empty box, no "undefined"
[base({}),base({os:""}),base({os:"",machine:""}),base({os:null,machine:null}),
 base({os:"",machine:"company"}),base({os:"freebsd"})].forEach(function(a,i){
  if(osIcon(a)!=="")fail("case "+i+": an unknown/absent os must yield no icon");
  var h=plate(a);
  if(h.indexOf('class="osi"')>=0)fail("case "+i+": an absent os must render NO icon element "+
    "(an empty .osi box is a regression)");
  if(h.indexOf("undefined")>=0||h.indexOf("null")>=0)
    fail("case "+i+": the nameplate leaked a raw undefined/null");
});
// 4. the vendor emblem logic is UNTOUCHED (owner: leave it alone)
["cc","codex","hermes"].forEach(function(v){
  var h=plate(base({vend:v,os:"win"}));
  if(h.indexOf('<div class="emblem">'+VEND[v].em+"</div>")<0)
    fail("the vendor emblem markup changed for "+v);
  if(h.indexOf('<span class="em" style="color:'+VEND[v].color+'">'+VEND[v].em+"</span>")<0)
    fail("the nameplate vendor glyph changed for "+v);
});
if(plate(base({vend:"cc",os:"win"})).indexOf('<div class="emblem">🪟')>=0)
  fail("the OS icon leaked into the vendor emblem");
// 5. reverse assertion: EVERY machine-registry key must produce a non-empty glyph.
// `machine` values like "company"/"home" are not OS names, so OSICON can never cover them --
// those rows drew nothing at all while ui/dashboard.html gave each machine an icon + label +
// its own colour. REG is monitor.py's own registry, injected, so office2 cannot keep a copy.
__REGISTRY__
MACHINES=REG;
Object.keys(REG).forEach(function(k){
  var m=REG[k], b=machBadge({machine:k});
  if(!b)fail("machine '"+k+"' is on the registry but renders no badge at all");
  if(b.indexOf(m.icon)<0)fail("the badge for '"+k+"' drops the registry icon");
  if(b.indexOf(m.label)<0)fail("the badge for '"+k+"' drops the registry label");
  if(b.indexOf(m.bg)<0||b.indexOf(m.fg)<0)
    fail("the badge for '"+k+"' does not use the registry colours");
  var h=plate(base({machine:k}));
  if(h.indexOf(m.icon)<0||h.indexOf(m.label)<0)
    fail("personEl does not draw the machine badge for '"+k+"'");
  if(h.indexOf('class="nameplate"')<0||h.indexOf('class="machb"')>h.indexOf("</div>"))
    fail("the machine badge must sit inside the nameplate (fixed no-scroll layout)");
  if(h.indexOf('<span class="osi">')>=0)
    fail("'"+k+"' draws the machine badge AND the plain OS icon -- the glyph is doubled");
  if(h.indexOf("undefined")>=0||h.indexOf("null")>=0)
    fail("the machine badge leaked a raw undefined/null for '"+k+"'");
  // dashboard keys off machine||os, so a local row carrying only `os` must resolve too
  if(plate(base({os:k})).indexOf(m.label)<0)
    fail("a row whose os is the registry key '"+k+"' shows no machine badge");
});
// a machine that is not on the registry must not swallow the OS signal, and a row with
// neither must still draw nothing (an empty coloured pill would be a fake machine)
if(plate(base({os:"win",machine:"nope"})).indexOf('<span class="osi">'+want("win")+"</span>")<0)
  fail("an unregistered machine must fall back to the OS icon");
// LOCALM must actually PARTICIPATE, not merely be declared: a local row carries no
// `machine`, so a box that declared itself must see its own badge on it. Without these
// four, reverting machBadge to `a.machine||a.os` while leaving the declaration in place
// passes every assertion above -- the check would guard nothing.
var OSK={win:1,mac:1,linux:1};
var selfKey=Object.keys(REG).filter(function(k){return !OSK[k];})[0];
var foreignOs=Object.keys(REG).filter(function(k){return OSK[k]&&k!=="win";})[0];
if(selfKey){
  LOCALM=selfKey;LOCALOS="win";
  if(machBadge({}).indexOf(REG[selfKey].label)<0)
    fail("a local row does not inherit local_machine -- LOCALM is declared but unused");
  if(machBadge({os:"win"}).indexOf(REG[selfKey].label)<0)
    fail("a local row whose os matches this box does not inherit local_machine");
  // ...but it must NOT claim a row read out of a mounted root owned by another machine
  if(foreignOs&&machBadge({os:foreignOs}).indexOf(REG[foreignOs].label)<0)
    fail("a mounted-root row on another OS was swallowed by local_machine");
  var relay=Object.keys(REG).filter(function(k){return k!==selfKey;})[0];
  if(relay&&machBadge({machine:relay}).indexOf(REG[relay].label)<0)
    fail("an explicitly relayed machine must still win over local_machine");
  LOCALM="";LOCALOS="";
}
if(machBadge(base({}))!=="")fail("a row with no machine and no os still drew a badge");
if(plate(base({})).indexOf('class="machb"')>=0)
  fail("a row with no machine and no os still drew a badge element");
console.log("OK");
"""


def office2_os_icon_domain():
    """Derive the OS-icon domain from the backend rather than re-hardcoding a list that
    can drift. Returns (os_keys, machine_keys):
      os_keys      -- every non-empty value monitor.os_of_cwd() can return. office2 MUST
                      have an icon for each; a missing one is a lost signal.
      machine_keys -- the machine-registry keys, the only other values a row's `machine`
                      can carry. An OSICON entry naming one of these is still reachable;
                      anything outside both sets is unreachable from real data.
    """
    mon = read_text(MONITOR)
    body = re.search(r"\ndef os_of_cwd\(cwd\):(.*?)\n\ndef ", mon, re.S)
    os_keys = []
    for k in re.findall(r'return\s+"([A-Za-z]*)"', body.group(1) if body else ""):
        if k and k not in os_keys:
            os_keys.append(k)
    return os_keys, list(office2_machine_registry())


def office2_machine_registry():
    """The machine registry exactly as monitor.py declares it: {key: {icon,label,bg,fg,..}}.
    Derived, never re-hardcoded here -- office2 has to read the registry off /api/status
    (the user overrides it in config.json), so a hand-written copy in the oracle would
    make drift invisible (same reasoning as office2_ctx_scale()). {} when unparsable."""
    hit = re.search(r"\nDEFAULT_MACHINES = (\{.*?\n\})", read_text(MONITOR), re.S)
    if not hit:
        return {}
    try:
        reg = ast.literal_eval(hit.group(1))
    except (ValueError, SyntaxError):
        return {}
    return reg if isinstance(reg, dict) else {}


def js_icon_map(text, const):
    """Parse a `const <name> = {win:'X',...};` glyph map out of an HTML asset."""
    hit = re.search(r"const %s\s*=\s*\{(.*?)\};" % const, text, re.S)
    if not hit:
        return None
    return dict(re.findall(r"(\w+)\s*:\s*'([^']*)'", hit.group(1)))


def office2_os_icon_js_problem(text, cases, registry):
    """Run mapStatus + personEl DOM-free and assert the OS/machine signal survives
    the mapping, renders as an icon (a registry machine as its icon + label + colour),
    and degrades to nothing when absent. `cases` (os value -> expected glyph) and
    `registry` (monitor's machine registry) are derived and injected, so neither the
    fixture nor office2 can keep a copy that drifts."""
    node = shutil.which("node")
    if not node:
        return "node is required for the os-icon fixture"
    parts = {
        "__OS_CASES__": "var CASES=%s;" % json.dumps([list(c) for c in cases]),
        "__REGISTRY__": "var REG=%s;" % json.dumps(registry, ensure_ascii=False),
        "__OS_ICON__": extract_js_function(text, "function osIcon(a){"),
        "__CTX_BADGE__": extract_js_function(text, "function ctxBadge(p){"),
        "__STALE_BADGE__": office2_stale_badge_js(text),
        "__HOOK_PM__": office2_hook_pm_js(text),
        "__SUBS_BADGE__": office2_subs_badge_js(text),
        "__MACH_BADGE__": office2_mach_badge_js(text),
        "__PERSON_EL__": office2_person_el_js(text),
        "__MAP_STATUS__": office2_map_status_js(text),
        "__ZONE_OF__": extract_js_function(text, "function zoneOf(r){"),
        "__ST_OF__": extract_js_function(text, "function stOf(s){"),
        "__STANDBY_WAIT__": extract_js_function(text, "function standbyWait(r){"),
        "__HASH_INT__": extract_js_function(text, "function hashInt(s){"),
        # the page's real HTML-escape. machBadge/personEl call it, so this fixture must
        # run the REAL one -- the driver's console helper is asc(), deliberately not esc().
        "__ESC__": extract_js_function(text, "function esc(s){"),
    }
    for m, pat in (("__VEND__", r"const VEND\s*=\s*\{.*?\n\};"),
                   ("__STDOT__", r"const STDOT\s*=\s*\{.*?\};"),
                   ("__OSICON__", r"const OSICON\s*=\s*\{.*?\};"),
                   ("__CTXSTEP__", r"const CTXSTEP\s*=\s*\[.*?\];"),
                   ("__COUNCIL_PHASE__", r"const COUNCIL_PHASE\s*=\s*\{.*?\};"),
                   ("__WAIT_PHRASE__", r"const WAIT_PHRASE\s*=\s*\{.*?\};")):
        hit = re.search(pat, text, re.S)
        parts[m] = hit.group(0) if hit else None
    missing = [k for k, v in parts.items() if not v]
    if missing:
        return "not found in ui/office_proto.html: " + ", ".join(sorted(missing))
    src = OFFICE2_OS_ICON_DRIVER
    for k, v in parts.items():
        src = src.replace(k, v)
    fd, tmp = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(src)
        proc = subprocess.run([node, tmp], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    finally:
        os.unlink(tmp)
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode == 0 and out.splitlines()[-1:] == ["OK"]:
        return None
    return "os icon: " + (out.splitlines()[-1] if out
                          else "harness exit %d" % proc.returncode)


def cmd_check_office2_os_icon():
    """OS/machine signal parity (owner: office2 replaces the Signal Desk, so NO
    pre-existing signal may be lost). The backend has always emitted `os`
    (monitor.os_of_cwd) and `machine` on relayed rows, and ui/dashboard.html renders
    it -- office2 never read it. mapStatus must carry it and personEl must draw a
    small OS icon; the vendor emblem stays exactly as it was."""
    name = "check-office2-os-icon"
    if not os.path.exists(OFFICE_PROTO):
        record("SKIP", name, "ui/office_proto.html absent")
        return True
    text = read_text(OFFICE_PROTO)
    problems = []
    # the backend must actually still emit the signal this check propagates
    mon = read_text(MONITOR)
    if "def os_of_cwd(" not in mon or '"os": os_of_cwd(' not in mon:
        problems.append("monitor no longer emits `os` on office rows -- the check's premise is stale")
    # the icon domain is DERIVED from the backend, never hardcoded here (it drifted once)
    os_keys, machine_keys = office2_os_icon_domain()
    if not os_keys:
        problems.append("could not derive the os_of_cwd() value domain from monitor.py")
    # ...and so is the machine registry, which carries the OTHER half of the signal
    # (icon + label + per-machine colour) for the values OSICON can never name.
    registry = office2_machine_registry()
    if not registry:
        problems.append("could not derive the machine registry (DEFAULT_MACHINES) from monitor.py")
    if '"machines": cfg.get("machines") or DEFAULT_MACHINES' not in mon:
        problems.append("monitor no longer publishes the machine registry on /api/status -- "
                        "office2 would have no source for the machine icon/label/colour")
    if "d.machines" not in text:
        problems.append("office2 never reads d.machines off /api/status -- the registry the "
                        "user overrides in config.json is the only honest source")
    if not extract_js_function(text, "function machBadge(a){"):
        problems.append("no machBadge in the office UI -- registry machines (%s) render nothing"
                        % ", ".join(sorted(registry)))
    # a second, hand-written copy of the registry inside office2 would drift the moment the
    # user renames a machine in config.json
    for key in sorted(registry):
        label = (registry[key] or {}).get("label")
        if label and label in text:
            problems.append("ui/office_proto.html hardcodes the '%s' machine label -- it must "
                            "come from the registry on /api/status" % key)
    dash = js_icon_map(read_text(DASHBOARD), "OSI") if os.path.exists(DASHBOARD) else None
    icons = js_icon_map(text, "OSICON")
    cases = []
    if icons is None:
        problems.append("no OSICON map in the office UI")
    else:
        for key in os_keys:
            if not icons.get(key):
                problems.append("OSICON has no '%s' case -- os_of_cwd() emits it, so office2 "
                                "would silently drop a signal the dashboard shows" % key)
        for key in sorted(icons):
            if key not in os_keys and key not in machine_keys:
                problems.append("OSICON pins '%s', which neither os_of_cwd() nor the machine "
                                "registry can ever emit" % key)
        for key, glyph in sorted((dash or {}).items()):
            if icons.get(key) and icons[key] != glyph:
                # ascii(): the glyphs are emoji and this message must survive a cp950 console
                problems.append("OSICON '%s' is %s but ui/dashboard.html already renders %s -- "
                                "office2 must reuse the existing vocabulary"
                                % (key, ascii(icons[key]), ascii(glyph)))
        cases = [(k, (dash or {}).get(k) or icons.get(k, "")) for k in os_keys]
    mapper = extract_js_function(text, "function mapStatus(d){")
    if not mapper:
        problems.append("mapStatus not found")
    else:
        if "r.os" not in mapper:
            problems.append("mapStatus does not propagate r.os to the person model")
        if "r.machine" not in mapper:
            problems.append("mapStatus does not propagate r.machine to the person model")
    person = extract_js_function(text, "function personEl(a, mini){")
    if not person:
        problems.append("personEl not found")
    else:
        if "osIcon(a)" not in person:
            problems.append("personEl does not render the OS icon")
        if 'class="osi"' not in person:
            problems.append("the OS icon has no .osi hook to keep it small")
        if "machBadge(a)" not in person:
            problems.append("personEl does not render the machine badge")
        # owner: do NOT touch the vendor emblem
        if '<div class="emblem">${v.em}</div>' not in person:
            problems.append("the vendor emblem markup was modified (owner: leave it alone)")
        if "VEND[a.vend]" not in person:
            problems.append("the vendor emblem lookup was modified")
    # non-intrusive: the icon rides the existing nameplate flex row, no new positioned box
    if not re.search(r"\.nameplate \.osi\{[^}]*font-size:9px", text):
        problems.append("no small .nameplate .osi style -- the icon may break the fixed layout")
    if re.search(r"\.osi\{[^}]*position:absolute", text):
        problems.append(".osi is absolutely positioned -- it must ride the nameplate flow")
    if not re.search(r"\.nameplate \.machb\{[^}]*font-size:9px", text):
        problems.append("no small .nameplate .machb style -- the badge may break the fixed layout")
    if re.search(r"\.machb\{[^}]*position:absolute", text):
        problems.append(".machb is absolutely positioned -- it must ride the nameplate flow")
    if not problems:
        js = office2_os_icon_js_problem(text, cases, registry)
        if js:
            problems.append(js)
    if problems:
        record("FAIL", name, "; ".join(problems))
        return False
    record("PASS", name, "mapStatus carries os/machine, personEl draws the %s icon in the "
           "nameplate (domain derived from os_of_cwd, glyphs match the dashboard), every "
           "registry machine (%s) draws its icon+label+colour from the /api/status registry "
           "instead of vanishing, absent os renders no icon, vendor emblem untouched"
           % ("/".join(os_keys), "/".join(sorted(registry))))
    return True


OFFICE2_SEAT_OVERLAP_DRIVER = r"""
function fail(m){console.log("FAIL: "+m);process.exit(1);}
__ZONES__
__SEAT__
__SUB__
__SUB_DROP__
__STALL_BOX__
__SEAT_BAND__
__SEAT_BAND_FN__
__SEAT_GRID__
__SEAT_XY__
__SUB_XY__
// .person / .person.mini bounding boxes, straight out of the CSS the sprites are drawn
// against: width x height px, anchored at (left - ml, top - mt) and scaled about the feet.
var BOX={w:__PW__, h:__PH__, mt:__PMT__, ml:__PML__};
var MINI={w:__MW__, h:__MH__, mt:__MMT__, ml:__MML__};
var EPS=1e-6;
// the JS seat constants must describe the SAME boxes the browser paints, or the whole
// occupancy model is fiction
if(SEAT.w!==BOX.w||SEAT.h!==BOX.h)fail("SEAT w/h != the .person CSS box");
if(SEAT.up!==BOX.mt||SEAT.dn!==BOX.h-BOX.mt)fail("SEAT.up/dn != the .person margin/height");
if(SUB.w!==MINI.w||SUB.h!==MINI.h)fail("SUB w/h != the .person.mini CSS box");
if(SUB.up!==MINI.mt||SUB.dn!==MINI.h-MINI.mt)fail("SUB.up/dn != the .person.mini margin/height");
if(!(SUB.w<SEAT.w&&SUB.h<SEAT.h))fail("the sub sprite must stay smaller than its parent");
if(SUB_DROP<SEAT.dn+SUB.up)fail("SUB_DROP is below the parent/child box clearance "+
  (SEAT.dn+SUB.up));
// floor canvas mirrors the page's floorW()/floorH(): 100vw x max(100dvh - 41px, 820px).
// Vertical scrolling is ALLOWED from 2026-07-29 (owner: uniform cells + offline may run
// below the fold); horizontal scrolling is still a regression and is asserted against.
var VIEWS=[[1024,768],[1280,800],[1440,900],[1920,1080]];
var BUCKETS=[];
ZONES.forEach(function(z){
  if(z.key==="standby"){BUCKETS.push([z.key,"wait"]);BUCKETS.push([z.key,"idle"]);}
  else BUCKETS.push([z.key,null]);
});
// subagent profiles: k(i) = how many mini sprites parent i carries. 0..4 covers the old
// fixed offset table, 6 covers its [0, 9+i*6] fallback branch, and the mixed rows put
// DIFFERENT sub counts on neighbouring parents (the cross-owner child collision).
var PROFILES=[
  {tag:"k=0",     kmax:0, strict:true, k:function(i){return 0;}},
  {tag:"k=1",     kmax:1, k:function(i){return 1;}},
  {tag:"k=2",     kmax:2, k:function(i){return 2;}},
  {tag:"k=3",     kmax:3, k:function(i){return 3;}},
  {tag:"k=4",     kmax:4, k:function(i){return 4;}},
  {tag:"k=6",     kmax:6, k:function(i){return 6;}},
  {tag:"k=i%5",   kmax:4, k:function(i){return i%5;}},
  {tag:"k=0|4",   kmax:4, k:function(i){return i%2?4:0;}},
  {tag:"k=6then", kmax:6, k:function(i){return i===0?6:i%3;}}
];
// every sprite the page would actually draw for this bucket: parents from seatXY, their
// children from the shipped subXY -- no reimplementation of either.
function drawn(zone,grp,n,prof,sw,sh){
  var boxes=[], cap=-1, seats=0;
  for(var i=0;i<n;i++){
    var s=seatXY(zone,i,grp,n,prof.kmax);
    cap=s.cap;
    if(!(s.s>0&&s.s<=1))return {err:"avatar scale must be in (0,1], got "+s.s};
    if(i>=s.cap)continue;   // over capacity -> not drawn at all, the room shows +N
    seats++;
    var cx=s.px/100*sw, cy=s.py/100*sh;
    boxes.push({x0:cx-BOX.ml*s.s, x1:cx-BOX.ml*s.s+BOX.w*s.s,
                y0:cy-BOX.mt*s.s, y1:cy-BOX.mt*s.s+BOX.h*s.s, id:"seat"+i});
    var k=prof.k(i);
    if(k>prof.kmax)return {err:"profile kmax "+prof.kmax+" is below k("+i+")="+k};
    for(var j=0;j<k;j++){
      var q=subXY(s,j,k), mx=q.px/100*sw, my=q.py/100*sh;
      boxes.push({x0:mx-MINI.ml*s.s, x1:mx-MINI.ml*s.s+MINI.w*s.s,
                  y0:my-MINI.mt*s.s, y1:my-MINI.mt*s.s+MINI.h*s.s, id:"sub"+i+"."+j});
    }
  }
  return {boxes:boxes, cap:cap, seats:seats};
}
VIEWS.forEach(function(v){
  globalThis.innerWidth=v[0];globalThis.innerHeight=v[1];
  var sw=v[0], sh=Math.max(v[1]-41, 820);
  BUCKETS.forEach(function(b){
    PROFILES.forEach(function(prof){
      var tag=b[0]+(b[1]?":"+b[1]:"")+" @"+v[0]+"x"+v[1]+" "+prof.tag;
      for(var n=1;n<=24;n++){
        var r=drawn(b[0],b[1],n,prof,sw,sh);
        if(r.err)fail(tag+" n="+n+": "+r.err);
        if(r.cap<1)fail(tag+" n="+n+": no seat capacity at all");
        if(r.seats!==Math.min(n,r.cap))fail(tag+" n="+n+": drew "+r.seats+" of cap "+r.cap);
        // with no subagents, 1..24 must all still be drawn -- modelling the minis may not
        // dilute the guarantee the plain crowd already had
        if(prof.strict&&r.seats!==n)
          fail(tag+" n="+n+": only "+r.seats+" seats fit; 1..24 must all be drawn");
        var boxes=r.boxes;
        for(var p=0;p<boxes.length;p++){
          var A=boxes[p];
          if(A.x0<-EPS||A.y0<-EPS||A.x1>sw+EPS||A.y1>sh+EPS)
            fail(tag+" n="+n+": "+A.id+" box ["+A.x0.toFixed(1)+","+A.y0.toFixed(1)+","+
                 A.x1.toFixed(1)+","+A.y1.toFixed(1)+"] leaves the fixed full-bleed floor "+
                 sw+"x"+sh);
          for(var q2=p+1;q2<boxes.length;q2++){
            var B=boxes[q2];
            var ox=Math.min(A.x1,B.x1)-Math.max(A.x0,B.x0);
            var oy=Math.min(A.y1,B.y1)-Math.max(A.y0,B.y0);
            if(ox>EPS&&oy>EPS)
              fail(tag+" n="+n+": "+A.id+"/"+B.id+" overlap by "+
                   ox.toFixed(1)+"x"+oy.toFixed(1)+"px");
          }
        }
      }
    });
  });
});
// the crowd must actually change the layout, not just get lucky on a roomy zone
globalThis.innerWidth=1440;globalThis.innerHeight=900;
BUCKETS.forEach(function(b){
  if(seatXY(b[0],0,b[1],24).s>seatXY(b[0],0,b[1],1).s)
    fail(b[0]+": 24 occupants may not be drawn larger than 1");
});
// the tightest bucket (待命/等你回覆 band) can only fit 24 by shrinking
if(!(seatXY("standby",0,"wait",24).s<1))
  fail("the crowded 待命 wait group must shrink its avatars to fit");
if(seatXY("coding",1,null,12).px===seatXY("coding",1,null,4).px)
  fail("seat columns must adapt to the occupant count");
// subagents must be paid for out of the SAME seat budget, not squeezed in for free
if(!(seatXY("coding",0,null,8,3).s<seatXY("coding",0,null,8,0).s))
  fail("subagent sprites must cost seat budget (stallBox is not reserving room)");
// ...and they must stay visibly attached to their own parent, inside that parent's stall
var sx=seatXY("coding",0,null,4,2), c0=subXY(sx,0,2), c1=subXY(sx,1,2);
if(!(c0.py>sx.py&&c1.py>sx.py))fail("subagents must sit under their parent's feet");
if(Math.abs((c0.px+c1.px)/2-sx.px)>1e-9)fail("the sub row must stay centred on its parent");
if(Math.abs(c0.px-sx.px)/100*1440>stallBox(2).w*sx.s/2+EPS)
  fail("a subagent left its parent's own stall");
console.log("OK");
"""


def office2_seat_overlap_js_problem(text, box, mini):
    """Run the extracted seat-layout functions DOM-free and assert that, for every
    zone/standby group, every occupancy 1..24 and every subagent profile at four
    viewports, no two DRAWN sprite boxes overlap -- parent/parent, parent/child and
    child/child across different parents -- and none leaves the fixed full-bleed floor."""
    node = shutil.which("node")
    if not node:
        return "node is required for the seat-overlap fixture"
    parts = {
        "__SEAT_BAND_FN__": extract_js_function(text, "function seatBand(zoneKey, grp){"),
        "__STALL_BOX__": extract_js_function(text, "function stallBox(k){"),
        "__SEAT_GRID__": extract_js_function(text, "function seatGrid(zoneKey, grp, n, kmax){"),
        "__SEAT_XY__": extract_js_function(text, "function seatXY(zoneKey, idx, grp, n, kmax){"),
        "__SUB_XY__": extract_js_function(text, "function subXY(seat, i, k){"),
    }
    for m, pat in (("__ZONES__", r"const ZONES\s*=\s*\[.*?\];"),
                   ("__SEAT__", r"const SEAT\s*=\s*\{.*?\};"),
                   ("__SUB__", r"const SUB\s*=\s*\{.*?\};"),
                   ("__SUB_DROP__", r"const SUB_DROP\s*=[^;]+;"),
                   ("__SEAT_BAND__", r"const SEAT_BAND\s*=\s*\{.*?\};")):
        hit = re.search(pat, text, re.S)
        parts[m] = hit.group(0) if hit else None
    missing = [k for k, v in parts.items() if not v]
    if missing:
        return "not found in ui/office_proto.html: " + ", ".join(sorted(missing))
    src = OFFICE2_SEAT_OVERLAP_DRIVER
    for k, v in parts.items():
        src = src.replace(k, v)
    for k, v in (("__PW__", box[0]), ("__PH__", box[1]),
                 ("__PMT__", box[2]), ("__PML__", box[3]),
                 ("__MW__", mini[0]), ("__MH__", mini[1]),
                 ("__MMT__", mini[2]), ("__MML__", mini[3])):
        src = src.replace(k, v)
    fd, tmp = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(src)
        proc = subprocess.run([node, tmp], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=120)
    finally:
        os.unlink(tmp)
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode == 0 and out.splitlines()[-1:] == ["OK"]:
        return None
    return "seat overlap: " + (out.splitlines()[-1] if out
                               else "harness exit %d" % proc.returncode)


def cmd_check_office2_seat_overlap():
    """Crowded-zone sprite occupancy (owner-reported bug: agents landing in the SAME zone
    drew on top of each other). Two halves, both asserted here: seat placement adapts to
    that zone's occupant count -- columns AND avatar scale -- AND the subagent mini sprites
    are laid out inside their own parent's reserved stall instead of a fixed offset table
    plus a zone-wide clamp (which collapsed neighbouring parents' children onto one point).
    For ANY occupancy 1..24 and any per-parent subagent count, no two DRAWN boxes overlap
    (parent/parent, parent/child, child/child across different parents) and every box stays
    on the fixed full-bleed floor (no scrollbar, cf. 77e913b). Proven geometrically: the
    real seatXY/seatGrid/subXY are extracted and evaluated under node."""
    name = "check-office2-seat-overlap"
    if not os.path.exists(OFFICE_PROTO):
        record("SKIP", name, "ui/office_proto.html absent")
        return True
    text = read_text(OFFICE_PROTO)
    problems = []
    # the geometry the oracle asserts against must be the geometry the browser draws
    css = re.search(r"\.person\{[^}]*?width:(\d+)px;height:(\d+)px;"
                    r"margin:-(\d+)px 0 0 -(\d+)px", text, re.S)
    if not css:
        problems.append(".person box (width/height/margin) not parseable from the CSS")
    mcss = re.search(r"\.person\.mini\{[^}]*?width:(\d+)px;height:(\d+)px;"
                     r"margin:-(\d+)px 0 0 -(\d+)px", text, re.S)
    if not mcss:
        problems.append(".person.mini box (width/height/margin) not parseable from the CSS -- "
                        "subagent sprites are real boxes on the floor and must be modelled")
    if not re.search(r"\.person\.mini\{[^}]*transform-origin:50% 95%", text, re.S):
        problems.append(".person.mini does not scale about its feet -- the sub anchor would drift")
    if not re.search(r"\.person\{[^}]*transform:scale\(var\(--ps", text, re.S):
        problems.append(".person has no scale(var(--ps)) hook -- the computed scale never "
                        "reaches the DOM")
    if not re.search(r"\.person\{[^}]*transform-origin:50% 93\.333%", text, re.S):
        problems.append(".person does not scale about its feet -- the seat anchor would drift")
    if "p.style.setProperty('--ps'" not in text:
        problems.append("place() never applies the per-seat scale to the person element")
    if not re.search(r"place\(a,\s*animate,\s*tot,\s*kmx\)", text):
        problems.append("render() does not feed the per-bucket occupant count AND subagent "
                        "count into place()")
    if not re.search(r"kmx\[bk\]=Math\.max\(", text):
        problems.append("render() never counts the busiest parent's subagents per bucket")
    # the child sprites must go through the same seat budget the oracle drives, so the
    # old fixed offset table + zone-wide clamp cannot come back through the side door
    placer = extract_js_function(text, "function place(a, animate, tot, kmx){")
    if not placer:
        problems.append("place(a, animate, tot, kmx) not found")
    else:
        if "subXY(" not in placer:
            problems.append("place() does not lay subagents out through subXY() -- the oracle "
                            "would model geometry the page does not draw")
        if re.search(r"\[\s*\[\s*-?\d+\s*,\s*-?\d+\s*\]", placer):
            problems.append("place() still carries a fixed subagent offset table")
        if re.search(r"z\.x\+z\.w-|z\.y\+z\.h-", placer):
            problems.append("place() still clamps subagents into the zone rect -- that is what "
                            "collapses neighbouring parents' children onto the same point")
        if "m.style.setProperty('--ps', seat.s)" not in placer:
            problems.append("subagent sprites do not inherit the seat scale -- the modelled "
                            "mini box would not be the drawn one")
    # 77e913b was the dashboard transcript panel growing the page. Office2 may now scroll
    # VERTICALLY (owner 2026-07-29), but a HORIZONTAL scrollbar is still the regression.
    if not re.search(r"#stage\{[^}]*overflow-x:hidden", text):
        problems.append("#stage lost overflow-x:hidden -- a horizontal scrollbar regression")
    if not re.search(r"#floor\{[^}]*min-height|#floor\{[^}]*max\(", text):
        problems.append("#floor no longer pins a minimum height -- cells get squashed again, "
                        "which is what made the nameplates overlap")
    # zone routing/priority stays untouched
    if "offline > council > review > work_detail > standby" not in text:
        problems.append("the fixed zone priority comment/routing was disturbed")
    if not problems:
        js = office2_seat_overlap_js_problem(text, css.groups(), mcss.groups())
        if js:
            problems.append(js)
    if problems:
        record("FAIL", name, "; ".join(problems))
        return False
    record("PASS", name, "seatXY/stallBox reserve columns, avatar scale AND a per-parent sub "
           "row from one budget; subXY seats children inside their own parent's stall: "
           "1..24 occupants x 9 subagent profiles (0..4, >4 fallback, mixed neighbours) per "
           "zone/standby group, 4 viewports, zero pairwise overlap across ALL drawn sprites "
           "including cross-owner child pairs, all boxes inside the fixed full-bleed floor")
    return True


OFFICE2_SEAT_DESK_DRIVER = r"""
function fail(m){console.log("FAIL: "+m);process.exit(1);}
__ZONES__
__SEAT__
__SUB__
__SUB_DROP__
__STALL_BOX__
__SEAT_BAND__
__SEAT_BAND_FN__
__SEAT_GRID__
__SEAT_XY__
__DESK__
__DESK_ZONES__
__DESK_XY__
__DESK_HTML__
var EPS=1e-6;
// the box the browser paints for a desk is .furn.desk -- DESK.h claims to be that height
if(DESK.h!==__CSSH__)fail("DESK.h "+DESK.h+" != the .furn.desk CSS height __CSSH__");
// a desk as wide as the seat pitch would run into the neighbour's desk
if(!(DESK.w<SEAT.w))fail("DESK.w "+DESK.w+" must stay under the seat pitch SEAT.w="+SEAT.w);
// floor canvas mirrors the page's floorW()/floorH(): 100vw x max(100dvh - 41px, 820px).
// Vertical scrolling is ALLOWED from 2026-07-29 (owner: uniform cells + offline may run
// below the fold); horizontal scrolling is still a regression and is asserted against.
var VIEWS=[[1024,768],[1280,800],[1440,900],[1920,1080]];
var BUCKETS=[];
ZONES.forEach(function(z){
  if(z.key==="standby"){BUCKETS.push([z.key,"wait"]);BUCKETS.push([z.key,"idle"]);}
  else BUCKETS.push([z.key,null]);
});
var KMAX=[0,1,2,3,4,6];
// read the markup deskHTML really writes into the desk layer -- the oracle must judge the
// page's own output, not a reimplementation of it
function parse(html){
  var out=[], parts=html.split("<div ");
  if(parts[0]!=="")fail("deskHTML emitted something that is not a list of <div>: "+
                        parts[0].slice(0,60));
  for(var i=1;i<parts.length;i++){
    var s=parts[i];
    if(s.indexOf('class="furn desk"')!==0)
      fail("deskHTML emitted a non-desk node: "+s.slice(0,60));
    var g=/left:([-+\deE.]+)%;top:([-+\deE.]+)%;width:([-+\deE.]+)%;height:([-+\deE.]+)%/.exec(s);
    if(!g)fail("a desk node carries no four-percentage box: "+s.slice(0,80));
    out.push({x:+g[1], y:+g[2], w:+g[3], h:+g[4]});
  }
  return out;
}
VIEWS.forEach(function(v){
  globalThis.innerWidth=v[0];globalThis.innerHeight=v[1];
  var sw=v[0], sh=Math.max(v[1]-41, 820);
  BUCKETS.forEach(function(b){
    KMAX.forEach(function(k){
      for(var n=1;n<=24;n++){
        var bk=b[0]+(b[1]?":"+b[1]:""), tot={}, kmx={};
        tot[bk]=n;kmx[bk]=k;
        var tag=bk+" @"+v[0]+"x"+v[1]+" kmax="+k+" n="+n;
        var desks=parse(deskHTML(tot,kmx));
        var g=seatGrid(b[0],b[1],n,k), drawnSeats=Math.min(n,g.cap);
        if(!DESK_ZONES[b[0]]){
          // 機櫃/沙發/置物櫃的區本來就沒有辦公桌:不能無中生有畫一張
          if(desks.length)fail(tag+": zone has no desk furniture but drew "+desks.length);
          continue;
        }
        if(desks.length!==drawnSeats)
          fail(tag+": "+desks.length+" desks for "+drawnSeats+" drawn occupants");
        var ys={};
        for(var i=0;i<drawnSeats;i++){
          var seat=seatXY(b[0],i,b[1],n,k), d=desks[i];
          ys[d.y.toFixed(6)]=1;
          if(Math.abs(d.x+d.w/2-seat.px)>EPS)
            fail(tag+" seat"+i+": desk centre "+(d.x+d.w/2).toFixed(4)+"% is not the seat's "+
                 seat.px.toFixed(4)+"%");
          // the whole point of this oracle: the desk's top edge IS that occupant's feet.
          // the old fixed furniture sat a body height below them (measured y=302/338 vs
          // feet y=238 at 1440x900) -- everybody floated in mid-air.
          var gap=Math.abs(d.y-seat.py)/100*sh;
          if(gap>EPS)
            fail(tag+" seat"+i+": desk top is "+gap.toFixed(1)+"px away from the occupant's "+
                 "feet -- the sprite floats");
          if(Math.abs(d.w/100*sw-DESK.w*seat.s)>1e-6)
            fail(tag+" seat"+i+": desk width does not follow the seat scale "+seat.s);
          if(Math.abs(d.h/100*sh-DESK.h*seat.s)>1e-6)
            fail(tag+" seat"+i+": desk height does not follow the seat scale "+seat.s);
          if(d.x<-EPS||d.y<-EPS||d.x+d.w>100+EPS||d.y+d.h>100+EPS)
            fail(tag+" seat"+i+": desk box ["+d.x.toFixed(2)+","+d.y.toFixed(2)+"] leaves the "+
                 "fixed full-bleed floor");
          var z=ZONES.filter(function(q){return q.key===b[0];})[0];
          if(d.x<z.x-EPS||d.x+d.w>z.x+z.w+EPS)
            fail(tag+" seat"+i+": desk sticks out of its own room");
        }
        // a crowd must grow desk ROWS with the seat rows -- a fixed pair of shared desks
        // would collapse every row onto the same y
        var want=Math.ceil(drawnSeats/g.cols);
        if(Object.keys(ys).length!==want)
          fail(tag+": desks occupy "+Object.keys(ys).length+" rows, the seats occupy "+want);
        for(var p=0;p<desks.length;p++)for(var q2=p+1;q2<desks.length;q2++){
          var A=desks[p], B=desks[q2];
          var ox=Math.min(A.x+A.w,B.x+B.w)-Math.max(A.x,B.x);
          var oy=Math.min(A.y+A.h,B.y+B.h)-Math.max(A.y,B.y);
          if(ox/100*sw>EPS&&oy/100*sh>EPS)
            fail(tag+": desk"+p+"/desk"+q2+" overlap -- two occupants drawn on one desk");
        }
      }
    });
  });
});
// occupancy must move BOTH: more people -> more desks, and never bigger ones
globalThis.innerWidth=1440;globalThis.innerHeight=900;
function bucket(z,n){var m={};m[z]=n;return m;}
Object.keys(DESK_ZONES).forEach(function(z){
  var one=parse(deskHTML(bucket(z,1),bucket(z,0)));
  var many=parse(deskHTML(bucket(z,24),bucket(z,0)));
  if(!(many.length>one.length))fail(z+": a crowded zone must draw more desks than an empty one");
  if(many[0].w>one[0].w+EPS)fail(z+": desks may not grow as the zone fills up");
});
// the tightest desk zone (專家審視) can only seat 24 by shrinking -- its desks shrink too,
// which is the whole point of deriving them from the seats
if(!DESK_ZONES.review)fail("the review zone lost its desks");
var r1=parse(deskHTML(bucket("review",1),bucket("review",0)));
var r24=parse(deskHTML(bucket("review",24),bucket("review",0)));
if(!(r24[0].w<r1[0].w))fail("a crowded 專家審視 must shrink its desks with its seats");
console.log("OK");
"""


def office2_seat_desk_js_problem(text, css_h):
    """Run the shipped seat AND desk coordinate source DOM-free: for every desk zone,
    occupancy 1..24, subagent budget and viewport, take the markup deskHTML() really
    emits and assert every drawn occupant has exactly one desk, centred on that seat and
    with its top edge on that occupant's feet, scaled by the same seat scale."""
    node = shutil.which("node")
    if not node:
        return "node is required for the seat/desk alignment fixture"
    parts = {
        "__SEAT_BAND_FN__": extract_js_function(text, "function seatBand(zoneKey, grp){"),
        "__STALL_BOX__": extract_js_function(text, "function stallBox(k){"),
        "__SEAT_GRID__": extract_js_function(text, "function seatGrid(zoneKey, grp, n, kmax){"),
        "__SEAT_XY__": extract_js_function(text, "function seatXY(zoneKey, idx, grp, n, kmax){"),
        "__DESK_XY__": extract_js_function(text, "function deskXY(seat){"),
        "__DESK_HTML__": extract_js_function(text, "function deskHTML(tot, kmx){"),
    }
    for m, pat in (("__ZONES__", r"const ZONES\s*=\s*\[.*?\];"),
                   ("__SEAT__", r"const SEAT\s*=\s*\{.*?\};"),
                   ("__SUB__", r"const SUB\s*=\s*\{.*?\};"),
                   ("__SUB_DROP__", r"const SUB_DROP\s*=[^;]+;"),
                   ("__SEAT_BAND__", r"const SEAT_BAND\s*=\s*\{.*?\};"),
                   ("__DESK__", r"const DESK\s*=\s*\{.*?\};"),
                   ("__DESK_ZONES__", r"const DESK_ZONES\s*=\s*\{.*?\};")):
        hit = re.search(pat, text, re.S)
        parts[m] = hit.group(0) if hit else None
    missing = [k for k, v in parts.items() if not v]
    if missing:
        return "not found in ui/office_proto.html: " + ", ".join(sorted(missing))
    src = OFFICE2_SEAT_DESK_DRIVER
    for k, v in parts.items():
        src = src.replace(k, v)
    src = src.replace("__CSSH__", css_h)
    fd, tmp = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(src)
        proc = subprocess.run([node, tmp], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=120)
    finally:
        os.unlink(tmp)
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode == 0 and out.splitlines()[-1:] == ["OK"]:
        return None
    return "seat/desk alignment: " + (out.splitlines()[-1] if out
                                      else "harness exit %d" % proc.returncode)


def cmd_check_office2_seat_desk_align():
    """Occupants must stand AT a desk, not a body height above one (owner-reported: the
    office draws desks nobody is sitting at). The defect was two independent coordinate
    systems: furnHTML() painted a fixed pair of desks per room at top:62%/72% while the
    people came from seatXY()'s SEAT_BAND -- measured at 1440x900 the coding-zone desks
    landed at y=302/338 and the occupants' feet at y=238. The fix is one source: desks are
    DERIVED from the seat coordinates (deskXY/deskHTML), so a desk exists exactly where a
    person stands and both scale together from 1 to 24 occupants. Proven geometrically:
    the shipped seatXY/seatGrid/deskXY/deskHTML are extracted and evaluated under node,
    and the markup deskHTML really emits is parsed back and matched against the seats."""
    name = "check-office2-seat-desk-align"
    if not os.path.exists(OFFICE_PROTO):
        record("SKIP", name, "ui/office_proto.html absent")
        return True
    text = read_text(OFFICE_PROTO)
    problems = []
    furn = extract_js_function(text, "function furnHTML(key){")
    if not furn:
        problems.append("furnHTML(key) not found")
    elif "furn desk" in furn:
        problems.append("furnHTML still paints desks at fixed room percentages -- that is the "
                        "second coordinate system the occupants never meet")
    desk_html = extract_js_function(text, "function deskHTML(tot, kmx){")
    if not desk_html:
        problems.append("deskHTML(tot, kmx) not found -- the desks must be generated from the "
                        "same coordinates the people are placed by")
    else:
        if "seatXY(" not in desk_html:
            problems.append("deskHTML does not read seatXY() -- the desks would not be the "
                            "coordinate source the occupants are placed by")
        if re.search(r"top:\s*\d+(\.\d+)?%", desk_html):
            problems.append("deskHTML carries a hardcoded top percentage -- the fixed "
                            "furniture band came back through the side door")
    body = extract_js_function(text, "function render(animate){")
    if not body:
        problems.append("render(animate) not found")
    elif not re.search(r"deskLayer\.innerHTML\s*=\s*deskHTML\(tot,\s*kmx\)", body):
        problems.append("render() does not redraw the desks from the SAME tot/kmx it feeds "
                        "place() -- occupancy would move the people but not their desks")
    if "floor.appendChild(deskLayer)" not in text:
        problems.append("the desk layer is never mounted on the floor")
    if not re.search(r"#desks\{position:absolute;inset:0", text):
        problems.append("#desks is not a full-floor layer -- the desk percentages would not "
                        "share the seats' coordinate space")
    if not re.search(r"\.person\{[^}]*z-index:5", text, re.S):
        problems.append(".person lost its z-index -- the derived desks would cover the "
                        "occupants instead of sitting under them")
    css = re.search(r"\.furn\.desk\{height:(\d+)px", text)
    if not css:
        problems.append(".furn.desk height not parseable from the CSS")
    if not problems:
        js = office2_seat_desk_js_problem(text, css.group(1))
        if js:
            problems.append(js)
    if problems:
        record("FAIL", name, "; ".join(problems))
        return False
    record("PASS", name, "desks are derived from seatXY, not a fixed furniture band: for "
           "every desk zone, 1..24 occupants x 6 subagent budgets x 4 viewports, the markup "
           "deskHTML emits gives each DRAWN occupant exactly one desk, centred on that seat "
           "with its top edge on that occupant's feet (0px float), scaled by the same seat "
           "scale, one desk row per seat row, no two desks overlapping, none leaving its own "
           "room or the fixed full-bleed floor; zones furnished with racks/couch/lockers "
           "draw none")
    return True


def cmd_check_office2_tab():
    """🏢 tab cut-over (owner: 'owner 看不到自己核准的辦公室'): clicking the office
    tab must show office2, not the retired Signal Desk renderer. Shipped in
    189471b: renderOffice() mounts <iframe id="office2frame" src="/office2">,
    CSS gives it the full tab area, and sizeOffice2() recomputes its height on
    resize. Static-only guard against a silent regression -- the three legs
    (mount / fill+resize / route) must all stay wired, since losing any one of
    them leaves the tab blank or back on the Signal Desk."""
    name = "check-office2-tab"
    if not os.path.exists(DASHBOARD):
        record("SKIP", name, "ui/dashboard.html absent")
        return True
    text = read_text(DASHBOARD)
    src = extract_js_function(text, "function renderOffice(d){")
    if not src:
        record("FAIL", name, "renderOffice(d) not found in ui/dashboard.html")
        return False
    problems = []
    # (a) the tab mounts an iframe served by the /office2 route
    mount = re.search(r"<iframe\b[^>]*>", src)
    if not mount:
        problems.append("renderOffice mounts no <iframe> -- the office tab fell back to the "
                        "Signal Desk renderer and owner still cannot see office2")
    else:
        tag = mount.group(0)
        if not re.search(r"""src=["']/office2["']""", tag):
            problems.append("the iframe renderOffice mounts is not src=\"/office2\"")
        if not re.search(r"""id=["']office2frame["']""", tag):
            problems.append("the mounted iframe has no id=\"office2frame\" -- both the fill "
                            "CSS and sizeOffice2() key off that id")
    # (b) fill behaviour in CSS + a resize-driven sizing path
    host_css = re.search(r"#office\.office2-host\{([^}]*)\}", text)
    if not host_css:
        problems.append("no #office.office2-host CSS rule -- the Signal Desk padding/border "
                        "still boxes the iframe in")
    elif not re.search(r"padding:\s*0", host_css.group(1)):
        problems.append("#office.office2-host does not drop its padding, so the iframe cannot "
                        "fill the tab area")
    if "office2-host" not in src:
        problems.append("renderOffice never puts the office2-host class on #office")
    frame_css = re.search(r"#office2frame\{([^}]*)\}", text)
    if not frame_css:
        problems.append("no #office2frame CSS rule -- the iframe has no fill behaviour")
    else:
        decl = frame_css.group(1)
        if not re.search(r"width:\s*100%", decl):
            problems.append("#office2frame has no width:100% -- it will not span the tab")
        if not re.search(r"display:\s*block", decl):
            problems.append("#office2frame is not display:block -- an inline iframe leaves a "
                            "baseline gap under the office")
    sizer = extract_js_function(text, "function sizeOffice2(){")
    if not sizer:
        problems.append("sizeOffice2() not found -- nothing gives the iframe a height")
    else:
        if "office2frame" not in sizer:
            problems.append("sizeOffice2() no longer targets #office2frame")
        if "style.height" not in sizer or "innerHeight" not in sizer:
            problems.append("sizeOffice2() does not derive the iframe height from the viewport")
    if "sizeOffice2()" not in src:
        problems.append("renderOffice does not call sizeOffice2() when the tab is rendered")
    if not re.search(r"""addEventListener\(\s*["']resize["']\s*,\s*sizeOffice2""", text):
        problems.append("no resize listener re-runs sizeOffice2 -- the iframe keeps a stale "
                        "height after the window is resized")
    # (c) the route the iframe loads must still exist
    mon = read_text(MONITOR) if os.path.exists(MONITOR) else ""
    if not re.search(r"""route\s*==\s*["']/office2["']""", mon):
        problems.append("monitor.py no longer serves the /office2 route -- the iframe 404s")
    if "OFFICE2_PAGE" not in mon:
        problems.append("OFFICE2_PAGE asset is gone -- /office2 has nothing to serve")
    if problems:
        record("FAIL", name, "; ".join(problems))
        return False
    record("PASS", name, "the office tab mounts <iframe id=office2frame src=/office2>, the "
           "host/frame CSS lets it fill the tab area, sizeOffice2() sizes it from the viewport "
           "on render and on resize, and monitor.py still serves /office2")
    return True


OFFICE2_LABEL_DRIVER = r"""
function asc(s){return String(s).replace(/[^\x20-\x7e一-鿿]/g,"?");}
function bad(m){console.log("FAIL: "+asc(m));process.exit(1);}
// fixture stubs -- personEl only reads .img/.key off a creature and never touches the real DOM
var CREATURES=[{key:"c0",img:"a.png"},{key:"c1",img:"b.png"}];
var document={createElement:function(){return {style:{setProperty:function(){}},
  querySelector:function(){return null;}};}};
__VEND__
__STDOT__
__OSICON__
__OS_ICON__
__MACH_BADGE__
__COUNCIL_PHASE__
__WAIT_PHRASE__
__CTXSTEP__
__ESC__
__HASH_INT__
__ZONE_OF__
__ST_OF__
__STANDBY_WAIT__
__CTX_BADGE__
__STALE_BADGE__
__HOOK_PM__
__SUBS_BADGE__
__PERSON_EL__
__MAP_STATUS__
function plate(a){var h=String(personEl(a,false).innerHTML);
  var i=h.indexOf("</div>");return i<0?h:h.slice(0,i);}   // the nameplate is the first div
// 1. mapStatus must CARRY the backend label through to the person model
var rows={claude:[{session_id:"s1",status:"running",work_kind:"working",label:"wt-uiux-overhaul"},
                  {session_id:"s2",status:"running",work_kind:"working",label:"ai-session-monitor"},
                  {session_id:"s3",status:"running",work_kind:"working"}]};
var m=mapStatus(rows);
if(m.length!==3)bad("mapStatus returned "+m.length+" people (expected 3)");
if(!("label" in m[0]))bad("mapStatus drops the backend label -- office2 falls back to the loop "+
  "ordinal and no session can be told from another");
if(m[0].label!=="wt-uiux-overhaul")bad("mapStatus must carry r.label; got "+asc(m[0].label));
if(m[1].label!=="ai-session-monitor")bad("mapStatus must carry r.label; got "+asc(m[1].label));
if(m[2].label)bad("a row with no label must map to an empty label, not "+asc(m[2].label));
// 2. the nameplate must SHOW it -- that is the whole point (A1/A2/A3 identifies nobody)
var h0=plate(m[0]), h1=plate(m[1]);
if(h0.indexOf("wt-uiux-overhaul")<0)bad("personEl does not draw the session label");
if(h1.indexOf("ai-session-monitor")<0)bad("personEl does not draw the session label");
if(h0.indexOf('class="nameplate"')<0)bad("the label must sit inside the nameplate");
if(h0===h1)bad("two different sessions render the same nameplate");
if(h0.indexOf(m[0].id)>=0)bad("the nameplate still shows the loop ordinal "+asc(m[0].id)+
  " even though the row carries a label");
// 3. no label -> fall back to the stable id, and never leak a raw undefined/null
var h2=plate(m[2]);
if(h2.indexOf(m[2].id)<0)bad("a row with no label must fall back to the id");
if(h2.indexOf("undefined")>=0||h2.indexOf("null")>=0)
  bad("the nameplate leaked a raw undefined/null");
// 4. the label is backend text on an innerHTML path: it must be escaped, like the dashboard's
// esc(r.label), or a project/thread name becomes live markup
var evil=mapStatus({claude:[{session_id:"s4",status:"running",work_kind:"working",
  label:"<img src=x onerror=alert(1)>\"&"}]})[0];
var he=plate(evil);
if(/<img/i.test(he))bad("the session label reached the nameplate as live markup");
if(he.indexOf("&lt;img")<0||he.indexOf("&quot;")<0||he.indexOf("&amp;")<0)
  bad("the label is not escaped the way ui/dashboard.html escapes it");
console.log("OK");
"""


def office2_label_js_problem(text):
    """Run mapStatus + personEl DOM-free and assert the session label survives the
    mapping, reaches the nameplate, falls back to the id when absent, and is escaped
    on the way in. Returns a problem string (folded into the single
    check-office2-label record) or None when green."""
    node = shutil.which("node")
    if not node:
        return "node is required for the label fixture"
    parts = {
        "__ESC__": extract_js_function(text, "function esc(s){"),
        "__OS_ICON__": extract_js_function(text, "function osIcon(a){"),
        "__CTX_BADGE__": extract_js_function(text, "function ctxBadge(p){"),
        "__STALE_BADGE__": office2_stale_badge_js(text),
        "__HOOK_PM__": office2_hook_pm_js(text),
        "__SUBS_BADGE__": office2_subs_badge_js(text),
        "__MACH_BADGE__": office2_mach_badge_js(text),
        "__PERSON_EL__": office2_person_el_js(text),
        "__MAP_STATUS__": office2_map_status_js(text),
        "__ZONE_OF__": extract_js_function(text, "function zoneOf(r){"),
        "__ST_OF__": extract_js_function(text, "function stOf(s){"),
        "__STANDBY_WAIT__": extract_js_function(text, "function standbyWait(r){"),
        "__HASH_INT__": extract_js_function(text, "function hashInt(s){"),
    }
    for m, pat in (("__VEND__", r"const VEND\s*=\s*\{.*?\n\};"),
                   ("__STDOT__", r"const STDOT\s*=\s*\{.*?\};"),
                   ("__OSICON__", r"const OSICON\s*=\s*\{.*?\};"),
                   ("__CTXSTEP__", r"const CTXSTEP\s*=\s*\[.*?\];"),
                   ("__COUNCIL_PHASE__", r"const COUNCIL_PHASE\s*=\s*\{.*?\};"),
                   ("__WAIT_PHRASE__", r"const WAIT_PHRASE\s*=\s*\{.*?\};")):
        hit = re.search(pat, text, re.S)
        parts[m] = hit.group(0) if hit else None
    missing = [k for k, v in parts.items() if not v]
    if missing:
        return "not found in ui/office_proto.html: " + ", ".join(sorted(missing))
    src = OFFICE2_LABEL_DRIVER
    for k, v in parts.items():
        src = src.replace(k, v)
    fd, tmp = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(src)
        proc = subprocess.run([node, tmp], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    finally:
        os.unlink(tmp)
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode == 0 and out.splitlines()[-1:] == ["OK"]:
        return None
    return "label fixture: " + (out.splitlines()[-1] if out
                                else "harness exit %d" % proc.returncode)


def cmd_check_office2_label():
    """Session identity (P0: office2 replaces the Signal Desk, and a floor of
    identical A1/A2/A3 nameplates identifies nobody). The backend has always sent
    `label` on session rows and ui/dashboard.html draws it as esc(r.label);
    mapStatus never carried it, so personEl fell through to a.id -- the render-loop
    ordinal. mapStatus must carry the field and the nameplate must show it, escaped
    the same way the dashboard escapes it."""
    name = "check-office2-label"
    if not os.path.exists(OFFICE_PROTO):
        record("SKIP", name, "ui/office_proto.html absent")
        return True
    text = read_text(OFFICE_PROTO)
    problems = []
    # the backend must actually still emit the signal this check propagates
    if '"label":' not in read_text(MONITOR):
        problems.append("monitor.py no longer emits `label` on session rows -- the check's "
                        "premise is stale")
    # the escaping convention is the dashboard's, not a second one invented here
    if os.path.exists(DASHBOARD) and "esc(r.label)" not in read_text(DASHBOARD):
        problems.append("ui/dashboard.html no longer renders esc(r.label) -- office2 is "
                        "mirroring a convention that moved")
    mapper = extract_js_function(text, "function mapStatus(d){")
    if not mapper:
        problems.append("mapStatus not found")
    elif "r.label" not in mapper:
        problems.append("mapStatus does not propagate r.label to the person model, so every "
                        "nameplate falls back to the A<n> render-loop ordinal")
    person = extract_js_function(text, "function personEl(a, mini){")
    if not person:
        problems.append("personEl not found")
    else:
        if "a.label" not in person:
            problems.append("personEl does not draw the session label")
        if "esc(" not in person:
            problems.append("personEl interpolates the label into innerHTML unescaped")
    if not problems:
        js = office2_label_js_problem(text)
        if js:
            problems.append(js)
    if problems:
        record("FAIL", name, "; ".join(problems))
        return False
    record("PASS", name, "mapStatus carries r.label, the nameplate shows it instead of the "
           "render-loop ordinal, an absent label still falls back to the stable id, and the "
           "label is escaped the way ui/dashboard.html escapes it")
    return True


OFFICE2_CTX_DRIVER = r"""
function asc(s){return String(s).replace(/[^\x20-\x7e一-鿿]/g,"?");}
function bad(m){console.log("FAIL: "+asc(m));process.exit(1);}
// fixture stubs -- personEl only reads .img/.key off a creature and never touches the real DOM
var CREATURES=[{key:"c0",img:"a.png"},{key:"c1",img:"b.png"}];
var document={createElement:function(){return {style:{setProperty:function(){}},
  querySelector:function(){return null;}};}};
__VEND__
__STDOT__
__OSICON__
__OS_ICON__
__MACH_BADGE__
__COUNCIL_PHASE__
__WAIT_PHRASE__
__CTXSTEP__
__ESC__
__HASH_INT__
__ZONE_OF__
__ST_OF__
__STANDBY_WAIT__
__CTX_BADGE__
__STALE_BADGE__
__HOOK_PM__
__SUBS_BADGE__
__PERSON_EL__
__MAP_STATUS__
__CTX_CASES__
function plate(a){var h=String(personEl(a,false).innerHTML);
  var i=h.indexOf("</div>");return i<0?h:h.slice(0,i);}   // the nameplate is the first div
// 1. every step of ui/dashboard.html's OWN colour scale (derived, injected as CASES) must
//    survive mapStatus -> personEl unchanged: office2 may not invent a second scale
CASES.forEach(function(c){
  var pct=c[0], bg=c[1], fg=c[2], hot=c[3];
  var m=mapStatus({claude:[{session_id:"s"+pct,status:"running",work_kind:"working",
                            label:"proj",ctx:pct}]});
  if(m.length!==1)bad("mapStatus returned "+m.length+" people for ctx="+pct);
  if(m[0].ctx!==pct)bad("mapStatus drops the context reading: ctx="+pct+" became "+asc(m[0].ctx));
  var h=plate(m[0]);
  if(h.indexOf(pct+"%")<0)bad("the nameplate does not show the reading for ctx="+pct);
  if(h.indexOf(bg)<0)bad("ctx="+pct+" must use the dashboard background "+bg+", got "+asc(h));
  if(h.indexOf(fg)<0)bad("ctx="+pct+" must use the dashboard foreground "+fg+", got "+asc(h));
  var isHot=/\bhot\b/.test(h);
  if(hot&&!isHot)bad("ctx="+pct+" is above the dashboard's top step and must pulse");
  if(!hot&&isHot)bad("ctx="+pct+" is below the dashboard's top step and must NOT pulse");
  if(h.indexOf("undefined")>=0||h.indexOf("null")>=0)
    bad("the ctx badge leaked a raw undefined/null at ctx="+pct);
});
// 2. no reading -> NO badge at all (a fake 0% would be a lie about the session)
var none=mapStatus({claude:[{session_id:"s_none",status:"running",work_kind:"working",
                             label:"proj"}]})[0];
if(none.ctx!==null)bad("a row with no ctx must map to null, not "+asc(none.ctx));
var hn=plate(none);
if(hn.indexOf("ctxb")>=0)bad("a row with no context reading still drew a badge");
if(hn.indexOf("%")>=0)bad("a row with no context reading still drew a percentage");
// 3. relayed rows are foreign JSON: a non-numeric ctx must be dropped, never rendered
var evil=mapStatus({claude:[{session_id:"s_evil",status:"running",work_kind:"working",
  label:"proj",ctx:"<img src=x onerror=alert(1)>"}]})[0];
if(evil.ctx!==null)bad("a non-numeric ctx must be dropped, not carried as "+asc(evil.ctx));
if(/<img/i.test(plate(evil)))bad("a non-numeric ctx reached the nameplate as live markup");
console.log("OK");
"""

# `p>85?'#f8514922':p>60?'#d2992222':'#6e768122'` -- one (threshold, value) per step.
_CTX_STEP_RE = re.compile(r"p>(\d+)\s*\?\s*'([^']*)'")


def office2_ctx_scale():
    """Derive the context-window colour scale from ui/dashboard.html's ctxBadge instead of
    re-hardcoding it here -- the scale already has to be mirrored once inside office2, and a
    second hand-written copy in the oracle would make drift invisible (same reasoning as
    office2_os_icon_domain(), which derives the OS domain from monitor.py).
    Returns [(threshold or None, bg, fg, pulse), ...] worst step first, or None when
    ctxBadge() can no longer be parsed."""
    if not os.path.exists(DASHBOARD):
        return None
    src = extract_js_function(read_text(DASHBOARD), "function ctxBadge(p){")
    if not src:
        return None

    def stmt(var):
        """`var <name> = <expr>;` -- the terminating ';' is found by scanning outside
        string literals, because one of the values is itself a css declaration that
        ends in a semicolon."""
        hit = re.search(r"var\s+%s\s*=\s*" % var, src)
        if not hit:
            return None
        quote = None
        for i in range(hit.end(), len(src)):
            ch = src[i]
            if quote:
                if ch == quote:
                    quote = None
            elif ch in "'\"":
                quote = ch
            elif ch == ";":
                return src[hit.end():i]
        return None

    def chain(var):
        expr = stmt(var)
        if expr is None:
            return None
        tail = re.search(r":\s*'([^']*)'\s*$", expr)
        return ([(int(t), v) for t, v in _CTX_STEP_RE.findall(expr)],
                tail.group(1) if tail else None)

    bg, fg, pl = chain("bg"), chain("fg"), chain("pl")
    if not (bg and fg and pl) or not bg[0] or bg[1] is None or fg[1] is None:
        return None
    if [t for t, _ in bg[0]] != [t for t, _ in fg[0]]:
        return None            # the two chains disagree on where the steps are
    pulses = {t for t, v in pl[0] if v}
    scale = [(t, v, fg[0][i][1], t in pulses) for i, (t, v) in enumerate(bg[0])]
    scale.append((None, bg[1], fg[1], bool(pl[1])))
    if any(not str(b).startswith("#") or not str(f).startswith("#")
           for _, b, f, _ in scale):
        return None
    return scale


def office2_ctx_cases(scale):
    """Sample percentages that exercise every step and both sides of every boundary,
    paired with the colours ui/dashboard.html would use for them."""
    thresholds = [t for t, _, _, _ in scale if t is not None]
    pcts = sorted({0, 100} | {t for t in thresholds} | {t + 1 for t in thresholds})
    cases = []
    for p in pcts:
        for t, bg, fg, hot in scale:
            if t is None or p > t:
                cases.append([p, bg, fg, hot])
                break
    return cases


def office2_ctx_js_problem(text, scale):
    """Run mapStatus + personEl DOM-free and assert the context reading survives the
    mapping, renders with the dashboard's own colours at every step, pulses only above the
    dashboard's top step, and draws nothing at all when there is no reading. Returns a
    problem string (folded into the single check-office2-ctx record) or None when green."""
    node = shutil.which("node")
    if not node:
        return "node is required for the ctx fixture"
    parts = {
        "__CTX_CASES__": "var CASES=%s;" % json.dumps(office2_ctx_cases(scale)),
        "__ESC__": extract_js_function(text, "function esc(s){"),
        "__OS_ICON__": extract_js_function(text, "function osIcon(a){"),
        "__CTX_BADGE__": extract_js_function(text, "function ctxBadge(p){"),
        "__STALE_BADGE__": office2_stale_badge_js(text),
        "__HOOK_PM__": office2_hook_pm_js(text),
        "__SUBS_BADGE__": office2_subs_badge_js(text),
        "__MACH_BADGE__": office2_mach_badge_js(text),
        "__PERSON_EL__": office2_person_el_js(text),
        "__MAP_STATUS__": office2_map_status_js(text),
        "__ZONE_OF__": extract_js_function(text, "function zoneOf(r){"),
        "__ST_OF__": extract_js_function(text, "function stOf(s){"),
        "__STANDBY_WAIT__": extract_js_function(text, "function standbyWait(r){"),
        "__HASH_INT__": extract_js_function(text, "function hashInt(s){"),
    }
    for m, pat in (("__VEND__", r"const VEND\s*=\s*\{.*?\n\};"),
                   ("__STDOT__", r"const STDOT\s*=\s*\{.*?\};"),
                   ("__OSICON__", r"const OSICON\s*=\s*\{.*?\};"),
                   ("__CTXSTEP__", r"const CTXSTEP\s*=\s*\[.*?\];"),
                   ("__COUNCIL_PHASE__", r"const COUNCIL_PHASE\s*=\s*\{.*?\};"),
                   ("__WAIT_PHRASE__", r"const WAIT_PHRASE\s*=\s*\{.*?\};")):
        hit = re.search(pat, text, re.S)
        parts[m] = hit.group(0) if hit else None
    missing = [k for k, v in parts.items() if not v]
    if missing:
        return "not found in ui/office_proto.html: " + ", ".join(sorted(missing))
    src = OFFICE2_CTX_DRIVER
    for k, v in parts.items():
        src = src.replace(k, v)
    fd, tmp = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(src)
        proc = subprocess.run([node, tmp], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    finally:
        os.unlink(tmp)
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode == 0 and out.splitlines()[-1:] == ["OK"]:
        return None
    return "ctx fixture: " + (out.splitlines()[-1] if out
                              else "harness exit %d" % proc.returncode)


def cmd_check_office2_ctx():
    """Context-window signal (P0: office2 replaces the Signal Desk, and 'how full is this
    session' is the field the owner triages on). The backend has always emitted `ctx` and
    ui/dashboard.html draws ctxBadge(r.ctx) with two steps plus a pulse above the top one;
    office2 never read it. mapStatus must carry the field, personEl must draw the badge with
    the colours DERIVED from ui/dashboard.html (never a second hand-written scale), and a row
    with no reading must draw no badge at all."""
    name = "check-office2-ctx"
    if not os.path.exists(OFFICE_PROTO):
        record("SKIP", name, "ui/office_proto.html absent")
        return True
    text = read_text(OFFICE_PROTO)
    problems = []
    # the backend must actually still emit the signal this check propagates
    if '"ctx":' not in read_text(MONITOR):
        problems.append("monitor.py no longer emits `ctx` on session rows -- the check's "
                        "premise is stale")
    if os.path.exists(DASHBOARD) and "ctxBadge(r.ctx)" not in read_text(DASHBOARD):
        problems.append("ui/dashboard.html no longer draws ctxBadge(r.ctx) -- office2 is "
                        "mirroring a scale that moved")
    scale = office2_ctx_scale()
    if not scale:
        problems.append("could not derive the colour scale from ui/dashboard.html's "
                        "ctxBadge() -- it must be parsed from the dashboard, never "
                        "re-hardcoded in this checker")
    mapper = extract_js_function(text, "function mapStatus(d){")
    if not mapper:
        problems.append("mapStatus not found")
    elif "r.ctx" not in mapper:
        problems.append("mapStatus does not propagate r.ctx to the person model, so office2 "
                        "shows nothing for a session that is about to run out of context")
    person = extract_js_function(text, "function personEl(a, mini){")
    if not person:
        problems.append("personEl not found")
    elif "ctxBadge(" not in person:
        problems.append("personEl never draws the context badge")
    # the pulse the dashboard uses above its top step has to exist in office2's stylesheet,
    # otherwise the `hot` class the fixture sees is a no-op
    if scale and scale[0][3]:
        if "@keyframes pulse" not in text:
            problems.append("no @keyframes pulse in ui/office_proto.html -- the >%d%% step "
                            "would carry a class that animates nothing" % scale[0][0])
        if not re.search(r"\.ctxb\.hot\s*\{[^}]*animation:\s*pulse", text):
            problems.append("no .ctxb.hot rule drives the pulse animation")
    if not problems:
        js = office2_ctx_js_problem(text, scale)
        if js:
            problems.append(js)
    if problems:
        record("FAIL", name, "; ".join(problems))
        return False
    record("PASS", name, "mapStatus carries r.ctx, the nameplate badge uses the %d-step "
           "colour scale parsed out of ui/dashboard.html's ctxBadge (pulsing above %d%%), "
           "a non-numeric or absent reading draws no badge"
           % (len(scale), scale[0][0]))
    return True


OFFICE2_STALE_DRIVER = r"""
function asc(s){return String(s).replace(/[^\x20-\x7e一-鿿]/g,"?");}
function bad(m){console.log("FAIL: "+asc(m));process.exit(1);}
// fixture stubs -- personEl only reads .img/.key off a creature and never touches the real DOM
var CREATURES=[{key:"c0",img:"a.png"},{key:"c1",img:"b.png"}];
var document={createElement:function(){return {style:{setProperty:function(){}},
  querySelector:function(){return null;}};}};
__VEND__
__STDOT__
__OSICON__
__OS_ICON__
__MACH_BADGE__
__COUNCIL_PHASE__
__WAIT_PHRASE__
__CTXSTEP__
__ESC__
__HASH_INT__
__ZONE_OF__
__ST_OF__
__STANDBY_WAIT__
__CTX_BADGE__
__STALE_BADGE__
__HOOK_PM__
__SUBS_BADGE__
__PERSON_EL__
__MAP_STATUS__
__STALE_CASES__
function plate(a){var h=String(personEl(a,false).innerHTML);
  var i=h.indexOf("</div>");return i<0?h:h.slice(0,i);}   // the nameplate is the first div
function one(row){var m=mapStatus({claude:[row]});
  if(m.length!==1)bad("mapStatus returned "+m.length+" people for status "+asc(row.status));
  return m[0];}
// 1. a disconnected machine must NOT map to the same thing as a session the owner stopped
var st=one({session_id:"s1",status:"stale",work_kind:"working",label:"proj",
            machine:"company",stale_age:900});
var sp=one({session_id:"s2",status:"stopped",work_kind:"working",label:"proj"});
if(sp.st!=="stopped")bad("a stopped row must still map to stopped, got "+asc(sp.st));
if(st.st===sp.st)bad("a stale (link down, state possibly wrong) session still maps to the "+
  "same status as a stopped one ("+asc(st.st)+")");
// ...but it is still not running: distinguishing it must not move it out of the offline zone
if(zoneOf({status:"stale",work_kind:"working",work_detail:"code"})!=="offline")
  bad("a stale row left the offline zone");
// 2. the notice and the age reach the nameplate in ui/dashboard.html's OWN words
CASES.forEach(function(c){
  var age=c[0], want=c[1];
  var h=plate(one({session_id:"s"+age,status:"stale",work_kind:"working",label:"proj",
                   stale_age:age}));
  if(h.indexOf(want)<0)bad("stale_age="+age+" must render "+asc(want)+", got "+asc(h));
  if(h.indexOf("undefined")>=0||h.indexOf("null")>=0)
    bad("the stale notice leaked a raw undefined/null at stale_age="+age);
});
// 3. no age (the relay may omit the whole field) -> still warn, but invent no minutes
var noage=one({session_id:"s_noage",status:"stale",work_kind:"working",label:"proj"});
if(noage.stale_age!==null)
  bad("a stale row with no age must map to null, not "+asc(noage.stale_age));
var hn=plate(noage);
if(hn.indexOf(PHRASE)<0)bad("a stale row with no age must still warn that the link is down");
if(hn.indexOf(SUFFIX)>=0)bad("a stale row with no age fabricated an age");
// 4. a stopped session is not disconnected -- no warning at all
if(plate(sp).indexOf(PHRASE)>=0)bad("a stopped session is being labelled as disconnected");
// 5. relayed rows are foreign JSON: a non-numeric age must be dropped, never rendered
var evil=one({session_id:"s_evil",status:"stale",work_kind:"working",label:"proj",
              stale_age:"<img src=x onerror=alert(1)>"});
if(evil.stale_age!==null)
  bad("a non-numeric stale_age must be dropped, not carried as "+asc(evil.stale_age));
if(/<img/i.test(plate(evil)))bad("a non-numeric stale_age reached the nameplate as live markup");
console.log("OK");
"""

# ui/dashboard.html rowsTbl draws the disconnect notice as
#   r.status==='stale'?' <span ...>⚠ 連線中斷'+(r.stale_age?' · '+Math.round(r.stale_age/60)
#   +'m 前':'')+'</span>':''
# -- both halves are parsed out of the dashboard so office2's mirrored copy cannot drift.
_STALE_PHRASE_RE = re.compile(r"r\.status\s*===\s*'stale'\s*\?\s*'[^']*?>([^'<]+)'")
_STALE_AGE_RE = re.compile(r"r\.stale_age\s*\?\s*'([^']*)'\s*\+\s*Math\.round\(\s*"
                           r"r\.stale_age\s*/\s*(\d+)\s*\)\s*\+\s*'([^']*)'")


def office2_stale_notice():
    """Derive the disconnect wording from ui/dashboard.html instead of re-hardcoding it
    here (same reasoning as office2_ctx_scale(): the wording is already mirrored once
    inside office2, and a second hand-written copy in the oracle would make drift
    invisible). Returns (phrase, separator, seconds_per_unit, suffix) or None when the
    dashboard's stale notice can no longer be parsed."""
    if not os.path.exists(DASHBOARD):
        return None
    src = extract_js_function(read_text(DASHBOARD), "function rowsTbl(rows,src){")
    if not src:
        return None
    phrase, age = _STALE_PHRASE_RE.search(src), _STALE_AGE_RE.search(src)
    if not (phrase and age):
        return None
    divisor = int(age.group(2))
    if divisor <= 0:
        return None
    return (phrase.group(1), age.group(1), divisor, age.group(3))


def office2_stale_cases(notice):
    """Ages that exercise the rounding, paired with the text ui/dashboard.html would show."""
    phrase, sep, divisor, suffix = notice
    return [[age, phrase + sep + str((age + divisor // 2) // divisor) + suffix]
            for age in (divisor, 15 * divisor, 60 * divisor + 1)]


def office2_stale_js_problem(text, notice):
    """Run mapStatus + personEl DOM-free and assert a stale row keeps its own status,
    stays offline, shows the dashboard's disconnect notice with the age in minutes,
    warns without inventing an age when none was relayed, and stays silent on a stopped
    row. Returns a problem string (folded into the single check-office2-stale record)
    or None when green."""
    node = shutil.which("node")
    if not node:
        return "node is required for the stale fixture"
    parts = {
        "__STALE_CASES__": "var CASES=%s;var PHRASE=%s;var SUFFIX=%s;"
                           % (json.dumps(office2_stale_cases(notice)),
                              json.dumps(notice[0]), json.dumps(notice[3])),
        "__ESC__": extract_js_function(text, "function esc(s){"),
        "__OS_ICON__": extract_js_function(text, "function osIcon(a){"),
        "__CTX_BADGE__": extract_js_function(text, "function ctxBadge(p){"),
        "__STALE_BADGE__": office2_stale_badge_js(text),
        "__HOOK_PM__": office2_hook_pm_js(text),
        "__SUBS_BADGE__": office2_subs_badge_js(text),
        "__MACH_BADGE__": office2_mach_badge_js(text),
        "__PERSON_EL__": office2_person_el_js(text),
        "__MAP_STATUS__": office2_map_status_js(text),
        "__ZONE_OF__": extract_js_function(text, "function zoneOf(r){"),
        "__ST_OF__": extract_js_function(text, "function stOf(s){"),
        "__STANDBY_WAIT__": extract_js_function(text, "function standbyWait(r){"),
        "__HASH_INT__": extract_js_function(text, "function hashInt(s){"),
    }
    for m, pat in (("__VEND__", r"const VEND\s*=\s*\{.*?\n\};"),
                   ("__STDOT__", r"const STDOT\s*=\s*\{.*?\};"),
                   ("__OSICON__", r"const OSICON\s*=\s*\{.*?\};"),
                   ("__CTXSTEP__", r"const CTXSTEP\s*=\s*\[.*?\];"),
                   ("__COUNCIL_PHASE__", r"const COUNCIL_PHASE\s*=\s*\{.*?\};"),
                   ("__WAIT_PHRASE__", r"const WAIT_PHRASE\s*=\s*\{.*?\};")):
        hit = re.search(pat, text, re.S)
        parts[m] = hit.group(0) if hit else None
    missing = [k for k, v in parts.items() if not v]
    if missing:
        return "not found in ui/office_proto.html: " + ", ".join(sorted(missing))
    src = OFFICE2_STALE_DRIVER
    for k, v in parts.items():
        src = src.replace(k, v)
    fd, tmp = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(src)
        proc = subprocess.run([node, tmp], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    finally:
        os.unlink(tmp)
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode == 0 and out.splitlines()[-1:] == ["OK"]:
        return None
    return "stale fixture: " + (out.splitlines()[-1] if out
                                else "harness exit %d" % proc.returncode)


def cmd_check_office2_stale():
    """Stale-vs-stopped (semantic gap: monitor.collect_office forces the rows of a machine
    whose signed snapshot went past office_stale_secs to status 'stale' -- 'this reading is
    old and may be wrong', which is NOT the owner having stopped the session).
    ui/dashboard.html says so with an amber '⚠ 連線中斷' plus the age in minutes; office2's
    stOf() collapsed stale into stopped and never read stale_age, so a whole disconnected
    machine looked exactly like sessions somebody shut down. office2 must keep stale as its
    own status, still park it in the offline zone, and show the dashboard's own notice."""
    name = "check-office2-stale"
    if not os.path.exists(OFFICE_PROTO):
        record("SKIP", name, "ui/office_proto.html absent")
        return True
    text = read_text(OFFICE_PROTO)
    problems = []
    # the backend must actually still emit the signal this check propagates
    if '"stale_age":' not in read_text(MONITOR):
        problems.append("monitor.py no longer emits `stale_age` on office rows -- the check's "
                        "premise is stale")
    notice = office2_stale_notice()
    if not notice:
        problems.append("could not parse the '<stale> + stale_age minutes' notice out of "
                        "ui/dashboard.html's rowsTbl() -- the wording must be derived from "
                        "the dashboard, never re-hardcoded in this checker")
    elif notice[0] not in text:
        problems.append("ui/office_proto.html does not use ui/dashboard.html's own disconnect "
                        "wording %r -- office2 must reuse the existing vocabulary" % notice[0])
    mapper = extract_js_function(text, "function mapStatus(d){")
    if not mapper:
        problems.append("mapStatus not found")
    elif "r.stale_age" not in mapper:
        problems.append("mapStatus does not propagate r.stale_age to the person model, so "
                        "office2 cannot say how long the machine has been unreachable")
    st_of = extract_js_function(text, "function stOf(s){")
    if not st_of:
        problems.append("stOf not found")
    elif "'stale'" not in st_of:
        problems.append("stOf no longer distinguishes 'stale' -- a disconnected machine is "
                        "being reported as stopped")
    person = extract_js_function(text, "function personEl(a, mini){")
    if not person:
        problems.append("personEl not found")
    elif "staleBadge(" not in person:
        problems.append("personEl never draws the disconnect notice")
    # an unstyled badge is an invisible warning
    if not re.search(r"\.staleb\s*\{", text):
        problems.append("no .staleb rule in ui/office_proto.html -- the disconnect notice "
                        "would render unstyled")
    if not problems:
        js = office2_stale_js_problem(text, notice)
        if js:
            problems.append(js)
    if problems:
        record("FAIL", name, "; ".join(problems))
        return False
    record("PASS", name, "stale keeps its own status (still seated in the offline zone) and "
           "the nameplate carries ui/dashboard.html's own disconnect notice with the age in "
           "%ds units; no age relayed draws the warning without inventing minutes, a stopped "
           "row draws none" % notice[2])
    return True


OFFICE2_HOOK_PM_DRIVER = r"""
function asc(s){return String(s).replace(/[^\x20-\x7e一-鿿]/g,"?");}
function bad(m){console.log("FAIL: "+asc(m));process.exit(1);}
// fixture stubs -- personEl only reads .img/.key off a creature and never touches the real DOM
var CREATURES=[{key:"c0",img:"a.png"},{key:"c1",img:"b.png"}];
var document={createElement:function(){return {style:{setProperty:function(){}},
  querySelector:function(){return null;}};}};
__VEND__
__STDOT__
__OSICON__
__OS_ICON__
__MACH_BADGE__
__COUNCIL_PHASE__
__WAIT_PHRASE__
__CTXSTEP__
__ESC__
__HASH_INT__
__ZONE_OF__
__ST_OF__
__STANDBY_WAIT__
__CTX_BADGE__
__STALE_BADGE__
__HOOK_PM__
__SUBS_BADGE__
__PERSON_EL__
__MAP_STATUS__
__HOOK_PM_CASES__
function plate(a){var h=String(personEl(a,false).innerHTML);
  var i=h.indexOf("</div>");return i<0?h:h.slice(0,i);}   // the nameplate is the first div
function one(row){row.status=row.status||"running";row.work_kind="working";row.label="proj";
  var m=mapStatus({claude:[row]});
  if(m.length!==1)bad("mapStatus returned "+m.length+" people for "+asc(row.session_id));
  return m[0];}
// 1. every permission mode ui/dashboard.html knows (pmBadge's map PLUS the Signal Desk's
//    MODEMAP, injected as PM) must survive mapStatus and reach the nameplate with the
//    dashboard's OWN glyph and colour -- office2 may not invent a second vocabulary
PM.forEach(function(c){
  var key=c[0], text=c[1], color=c[2];
  var a=one({session_id:"pm_"+key, pmode:key});
  if(a.pmode!==key)bad("mapStatus drops the permission mode "+asc(key)+", got "+asc(a.pmode));
  var h=plate(a);
  if(h.indexOf("pmb")<0)bad("permission mode "+asc(key)+" draws no badge on the nameplate");
  if(!new RegExp(color+"[^<>]*>"+text).test(h))
    bad("permission mode "+asc(key)+" must render the dashboard's own "+asc(text)+" in "+
        color+", got "+asc(h));
});
// 2. the mode the dashboard stays silent on, plus absent / unknown / hostile values, draw
//    nothing at all -- a badge for a mode nobody recognises is a made-up claim
[SILENT,"","nope","constructor","__proto__","toString",
 "<img src=x onerror=alert(1)>"].forEach(function(v){
  var h=plate(one({session_id:"pm_q", pmode:v}));
  if(h.indexOf("pmb")>=0)bad("permission mode "+asc(v)+" must draw no badge, got "+asc(h));
  if(/<img/i.test(h))bad("a hostile permission mode reached the nameplate as live markup");
});
if(plate(one({session_id:"pm_none"})).indexOf("pmb")>=0)
  bad("a row with no permission mode still drew a badge");
// 3. a mixed hook tally shows all three of the dashboard's marks, with ITS success
//    arithmetic (hits minus cancelled minus errors), not a raw hit count
var mix=one({session_id:"hk_mix", hooks:{hits:5,cancelled:1,errors:1}});
if(!mix.hooks)bad("mapStatus drops the hook tally, so office2 cannot show hook health");
var hm=plate(mix), WANT={ok:3,cancelled:1,errors:1};
HOOK.forEach(function(p){
  var kind=p[0], glyph=p[1], color=p[2];
  if(!new RegExp(color+"[^<>]*>"+glyph+WANT[kind]).test(hm))
    bad("hook "+kind+"="+WANT[kind]+" must render "+asc(glyph+WANT[kind])+" in "+color+
        ", got "+asc(hm));
});
// 4. a clean run shows the success mark only
var clean=plate(one({session_id:"hk_ok", hooks:{hits:4}}));
if(clean.indexOf(OKG+"4")<0)
  bad("4 clean hook hits must render "+asc(OKG+"4")+", got "+asc(clean));
if(clean.indexOf(CANG)>=0||clean.indexOf(ERRG)>=0)
  bad("a clean hook tally still drew a cancelled/error mark");
// 5. nothing succeeded -> no success mark (the dashboard only pushes it when ok>0)
var allc=plate(one({session_id:"hk_c", hooks:{hits:2,cancelled:2}}));
if(allc.indexOf(OKG)>=0)bad("every hook was cancelled but a success mark was still drawn");
if(allc.indexOf(CANG+"2")<0)bad("the cancelled count never reached the nameplate");
// 6. no activity: hits=0, the empty {} a relayed row carries, and a missing field all draw
//    no badge at all
[{hits:0},{},null].forEach(function(h){
  if(plate(one({session_id:"hk_z", hooks:h})).indexOf("hookb")>=0)
    bad("a row with no hook activity still drew a badge");
});
if(plate(one({session_id:"hk_m"})).indexOf("hookb")>=0)
  bad("a row with no hooks field still drew a badge");
// 7. relayed rows are foreign JSON: non-numeric counts must be dropped, never rendered
var evil=plate(one({session_id:"hk_e",
                    hooks:{hits:"<img src=x onerror=alert(1)>",cancelled:2}}));
if(evil.indexOf("hookb")>=0)bad("a non-numeric hit count still drew a hook badge");
if(/<img/i.test(evil))bad("a non-numeric hook count reached the nameplate as live markup");
var evil2=plate(one({session_id:"hk_e2",
                     hooks:{hits:3,errors:"<img src=x onerror=alert(1)>"}}));
if(/<img/i.test(evil2))bad("a non-numeric hook error count reached the nameplate as live markup");
if(evil2.indexOf(OKG+"3")<0)bad("a dropped error count must not disturb the success total");
console.log("OK");
"""

# ui/dashboard.html pmBadge: `var map={bypassPermissions:['🔓bypass','#f85149'],...};`
_PMBADGE_ENTRY_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*:\s*\[\s*'([^']*)'\s*,\s*"
                               r"'(#[0-9a-fA-F]{3,8})'\s*\]")
# ui/dashboard.html MODEMAP: `bypassPermissions:['bypass','🔓']` -- label + glyph, no colour.
_MODEMAP_ENTRY_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*:\s*\[\s*'([^']*)'\s*,\s*'([^']*)'\s*\]")
# `function pmBadge(m){if(!m||m==='default')return '';` -- the mode the dashboard is silent on.
_PM_SILENT_RE = re.compile(r"!m\s*\|\|\s*m\s*===\s*'([^']*)'")
# `if(ok>0)p.push('<span style="color:#3fb950" title="hook success">✓'+ok+...`
_HOOK_MARK_RE = re.compile(r"p\.push\('<span style=\"color:(#[0-9a-fA-F]{3,8})\" "
                           r"title=\"([^\"]*)\">([^']+)'\s*\+\s*(?:h\.)?(\w+)")
# `var ok=h.hits-(h.cancelled||0)-(h.errors||0);` -- the success arithmetic office2 mirrors.
_HOOK_OK_RE = re.compile(r"ok\s*=\s*h\.hits\s*-\s*\(\s*h\.cancelled\s*\|\|\s*0\s*\)\s*-\s*"
                         r"\(\s*h\.errors\s*\|\|\s*0\s*\)")
_HOOK_KINDS = ("ok", "cancelled", "errors")


def office2_pmode_domain():
    """Derive the permission-mode vocabulary from ui/dashboard.html rather than re-hardcoding
    it here (same reasoning as office2_ctx_scale()). The dashboard states it twice: pmBadge()
    carries glyph+colour, and the Signal Desk's MODEMAP carries the wider key domain (it also
    knows dontAsk). A MODEMAP-only key inherits the rendering of the pmBadge key it shares a
    MODEMAP entry with -- the dashboard has already declared the two identical, so nothing is
    invented. Returns ({mode: (text, colour)}, silent_mode) or None when either half of the
    dashboard's definition can no longer be parsed."""
    if not os.path.exists(DASHBOARD):
        return None
    dash = read_text(DASHBOARD)
    src = extract_js_function(dash, "function pmBadge(m){")
    modemap = re.search(r"const MODEMAP\s*=\s*\{[^;]*\};", dash)
    if not (src and modemap):
        return None
    silent = _PM_SILENT_RE.search(src)
    domain = {k: (text, colour) for k, text, colour in _PMBADGE_ENTRY_RE.findall(src)}
    if not (silent and domain):
        return None
    pairs = {k: (a, b) for k, a, b in _MODEMAP_ENTRY_RE.findall(modemap.group(0))}
    for key, pair in sorted(pairs.items()):
        if key in domain:
            continue
        twin = [t for t, p in sorted(pairs.items()) if p == pair and t in domain]
        if not twin:
            return None   # a mode only MODEMAP knows, with no pmBadge twin to inherit from
        domain[key] = domain[twin[0]]
    return domain, silent.group(1)


def office2_hook_marks():
    """Derive the hook-health marks from ui/dashboard.html's hookBadge -- glyph, colour and
    title per tally, plus a guard that its success arithmetic is still hits-cancelled-errors
    (office2 mirrors that sum, so a change to it must fail here rather than silently make
    office2 lie). Returns [(kind, glyph, colour, title), ...] in the dashboard's own order,
    or None when hookBadge can no longer be parsed."""
    if not os.path.exists(DASHBOARD):
        return None
    src = extract_js_function(read_text(DASHBOARD), "function hookBadge(h){")
    if not (src and _HOOK_OK_RE.search(src) and "if(!h||!h.hits)return ''" in src):
        return None
    marks = [(kind, glyph, colour, title)
             for colour, title, glyph, kind in _HOOK_MARK_RE.findall(src)]
    if sorted(m[0] for m in marks) != sorted(_HOOK_KINDS):
        return None
    return marks


def office2_hook_pm_js_problem(text, pmode, marks):
    """Run mapStatus + personEl DOM-free and assert every permission mode the dashboard knows
    reaches the nameplate in the dashboard's own glyph and colour, that an unrecognised or
    hostile mode draws nothing, and that the hook tally renders the dashboard's three marks
    with its own success arithmetic and stays silent when there was no hook activity. Returns
    a problem string (folded into the single check-office2-hooks-pmode record) or None."""
    node = shutil.which("node")
    if not node:
        return "node is required for the hooks/pmode fixture"
    domain, silent = pmode
    glyph = {kind: g for kind, g, _c, _t in marks}
    cases = ("var PM=%s;var SILENT=%s;var HOOK=%s;var OKG=%s,CANG=%s,ERRG=%s;"
             % (json.dumps(sorted([k, t, c] for k, (t, c) in domain.items())),
                json.dumps(silent),
                json.dumps([[kind, g, c] for kind, g, c, _t in marks]),
                json.dumps(glyph["ok"]), json.dumps(glyph["cancelled"]),
                json.dumps(glyph["errors"])))
    parts = {
        "__HOOK_PM_CASES__": cases,
        "__ESC__": extract_js_function(text, "function esc(s){"),
        "__OS_ICON__": extract_js_function(text, "function osIcon(a){"),
        "__CTX_BADGE__": extract_js_function(text, "function ctxBadge(p){"),
        "__STALE_BADGE__": office2_stale_badge_js(text),
        "__HOOK_PM__": office2_hook_pm_js(text),
        "__SUBS_BADGE__": office2_subs_badge_js(text),
        "__MACH_BADGE__": office2_mach_badge_js(text),
        "__PERSON_EL__": office2_person_el_js(text),
        "__MAP_STATUS__": office2_map_status_js(text),
        "__ZONE_OF__": extract_js_function(text, "function zoneOf(r){"),
        "__ST_OF__": extract_js_function(text, "function stOf(s){"),
        "__STANDBY_WAIT__": extract_js_function(text, "function standbyWait(r){"),
        "__HASH_INT__": extract_js_function(text, "function hashInt(s){"),
    }
    for m, pat in (("__VEND__", r"const VEND\s*=\s*\{.*?\n\};"),
                   ("__STDOT__", r"const STDOT\s*=\s*\{.*?\};"),
                   ("__OSICON__", r"const OSICON\s*=\s*\{.*?\};"),
                   ("__CTXSTEP__", r"const CTXSTEP\s*=\s*\[.*?\];"),
                   ("__COUNCIL_PHASE__", r"const COUNCIL_PHASE\s*=\s*\{.*?\};"),
                   ("__WAIT_PHRASE__", r"const WAIT_PHRASE\s*=\s*\{.*?\};")):
        hit = re.search(pat, text, re.S)
        parts[m] = hit.group(0) if hit else None
    missing = [k for k, v in parts.items() if not v]
    if missing:
        return "not found in ui/office_proto.html: " + ", ".join(sorted(missing))
    src = OFFICE2_HOOK_PM_DRIVER
    for k, v in parts.items():
        src = src.replace(k, v)
    fd, tmp = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(src)
        proc = subprocess.run([node, tmp], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    finally:
        os.unlink(tmp)
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode == 0 and out.splitlines()[-1:] == ["OK"]:
        return None
    return "hooks/pmode fixture: " + (out.splitlines()[-1] if out
                                      else "harness exit %d" % proc.returncode)


def cmd_check_office2_hooks_pmode():
    """Hook health (`hooks`) and permission mode (`pmode`) -- both emitted by monitor.py since
    the first version and both drawn by ui/dashboard.html (hookBadge's success/cancelled/error
    marks, pmBadge's coloured mode glyph), yet office2 read neither: a session running with
    bypassPermissions looked exactly like a default one, and a run whose hooks were all being
    cancelled or erroring showed nothing at all. office2 must carry both fields through
    mapStatus and draw them on the nameplate with ui/dashboard.html's OWN glyphs, colours and
    key domain (pmBadge plus the Signal Desk's MODEMAP), never a second invented set."""
    name = "check-office2-hooks-pmode"
    if not os.path.exists(OFFICE_PROTO):
        record("SKIP", name, "ui/office_proto.html absent")
        return True
    text = read_text(OFFICE_PROTO)
    problems = []
    # the backend must actually still emit the signals this check propagates
    mon = read_text(MONITOR)
    for field in ("hooks", "pmode"):
        if '"%s":' % field not in mon:
            problems.append("monitor.py no longer emits `%s` on session rows -- the check's "
                            "premise is stale" % field)
    if os.path.exists(DASHBOARD):
        dash = read_text(DASHBOARD)
        for call in ("hookBadge(r.hooks)", "pmBadge(r.pmode)"):
            if call not in dash:
                problems.append("ui/dashboard.html no longer draws %s -- office2 is mirroring "
                                "a definition that moved" % call)
    pmode = office2_pmode_domain()
    if not pmode:
        problems.append("could not derive the permission-mode vocabulary from "
                        "ui/dashboard.html's pmBadge() + MODEMAP -- it must be parsed from "
                        "the dashboard, never re-hardcoded in this checker")
    marks = office2_hook_marks()
    if not marks:
        problems.append("could not derive the hook marks (and the success arithmetic) from "
                        "ui/dashboard.html's hookBadge() -- same anti-drift reason")
    mapper = extract_js_function(text, "function mapStatus(d){")
    if not mapper:
        problems.append("mapStatus not found")
    else:
        if "r.hooks" not in mapper:
            problems.append("mapStatus does not propagate r.hooks to the person model, so a "
                            "session whose hooks are all being cancelled shows nothing")
        if "r.pmode" not in mapper:
            problems.append("mapStatus does not propagate r.pmode to the person model, so a "
                            "bypassPermissions session is indistinguishable from a default one")
    person = extract_js_function(text, "function personEl(a, mini){")
    if not person:
        problems.append("personEl not found")
    else:
        for fn in ("pmBadge(", "hookBadge("):
            if fn not in person:
                problems.append("personEl never draws %s)" % fn)
    # an unstyled badge is an unreadable one
    for cls in ("pmb", "hookb"):
        if not re.search(r"\.%s\s*[,{]" % cls, text):
            problems.append("no .%s rule in ui/office_proto.html -- the badge would render "
                            "unstyled" % cls)
    if not problems:
        js = office2_hook_pm_js_problem(text, pmode, marks)
        if js:
            problems.append(js)
    if problems:
        record("FAIL", name, "; ".join(problems))
        return False
    record("PASS", name, "the nameplate carries all %d permission modes ui/dashboard.html "
           "knows (pmBadge + MODEMAP) in the dashboard's own glyphs and colours, stays silent "
           "on %r/unknown/hostile values, and shows its %d hook marks with the dashboard's own "
           "success arithmetic; no hook activity (hits=0, a relayed {}, or no field) draws no "
           "badge and non-numeric counts are dropped"
           % (len(pmode[0]), pmode[1], len(marks)))
    return True


# --------------------------------------------- office2 hidden-subagent disclosure
#
# monitor._mini_rows() truncates mini_rows at _OFFICE_MINI_CAP, and office2 draws one
# small figure per mini row: every subagent past the cap simply vanished from the floor.
# `subagents` is the un-truncated count and ui/dashboard.html already discloses the gap
# in two places (the Signal Desk's 🔬N, drawn only when the true count exceeds the minis
# whose identity is known, and the inspector's 「另有 N 位子代理，身分不可得」). Both the
# glyph and the sentence are parsed back out of the dashboard here -- office2 keeps a
# literal copy for rendering, and this check is what makes that copy fail on drift.
_SUBS_GLYPH_RE = re.compile(r"r\.subs>known\.length\?\('([^']+)'\+r\.subs\)")
_SUBS_PHRASE_RE = re.compile(r">(另有[^'<]*)'\+\(row\.subs-known\.length\)\+'([^'<]*)<")
_SUBS_TINT_RE = re.compile(r'style="color:(#[0-9a-fA-F]+);background:(#[0-9a-fA-F]+)"'
                           r'\s*title="active subagents')


def office2_subagent_vocab():
    """Derive the hidden-subagent vocabulary from ui/dashboard.html itself: the glyph it
    puts on a desk whose true subagent count exceeds the identities it can name, the two
    halves of the sentence its inspector writes about the remainder, and the colour pair
    of its own 🔬 badge. Returns (glyph, pre, post, colour, background) or None when any
    of the three definitions can no longer be found -- never a re-hardcoded copy."""
    if not os.path.exists(DASHBOARD):
        return None
    dash = read_text(DASHBOARD)
    glyph = _SUBS_GLYPH_RE.search(dash)
    phrase = _SUBS_PHRASE_RE.search(dash)
    tint = _SUBS_TINT_RE.search(dash)
    if not (glyph and phrase and tint):
        return None
    return (glyph.group(1), phrase.group(1), phrase.group(2), tint.group(1), tint.group(2))


def office2_mini_cap():
    """monitor.py's _OFFICE_MINI_CAP, i.e. how many mini rows a parent can ever ship.
    Returns (cap, None) or (None, problem) when the truncation this check exists for is
    no longer there."""
    mon = read_text(MONITOR)
    hit = re.search(r"^_OFFICE_MINI_CAP\s*=\s*(\d+)\s*$", mon, re.M)
    if not hit:
        return None, ("monitor.py no longer defines _OFFICE_MINI_CAP -- this check's premise "
                      "(mini_rows is truncated, `subagents` is the true count) is stale")
    if "found[:_OFFICE_MINI_CAP]" not in mon:
        return None, ("monitor._mini_rows no longer truncates at _OFFICE_MINI_CAP -- the "
                      "premise that minis can go missing is stale")
    return int(hit.group(1)), None


OFFICE2_SUBS_DRIVER = r"""
function asc(s){return String(s).replace(/[^\x20-\x7e一-鿿]/g,"?");}
function bad(m){console.log("FAIL: "+asc(m));process.exit(1);}
// fixture stubs -- personEl only reads .img/.key off a creature and never touches the real DOM
var CREATURES=[{key:"c0",img:"a.png"},{key:"c1",img:"b.png"}];
var document={createElement:function(){return {style:{setProperty:function(){}},
  querySelector:function(){return null;}};}};
__VEND__
__STDOT__
__OSICON__
__OS_ICON__
__MACH_BADGE__
__COUNCIL_PHASE__
__WAIT_PHRASE__
__CTXSTEP__
__ESC__
__HASH_INT__
__ZONE_OF__
__ST_OF__
__STANDBY_WAIT__
__CTX_BADGE__
__STALE_BADGE__
__HOOK_PM__
__SUBS_BADGE__
__PERSON_EL__
__CLIVEND__
__ST_KNOWN__
__SUB_ST__
__SUB_VEND__
__MAP_STATUS__
__SUBS_CASES__
function plate(a){var h=String(personEl(a,false).innerHTML);
  var i=h.indexOf("</div>");return i<0?h:h.slice(0,i);}   // the nameplate is the first div
function minis(k){var out=[];for(var i=0;i<k;i++)out.push({session_id:"p/agent-"+i});return out;}
function one(row){row.status=row.status||"running";row.work_kind="working";
  var m=mapStatus({claude:[row]});
  if(m.length!==1)bad("mapStatus returned "+m.length+" people for "+asc(row.session_id));
  return m[0];}
function hidden(a){return plate(a).indexOf("subb")>=0;}
// 1. the shape this check exists for: the backend capped mini_rows at CAP, `subagents`
//    says there are more. The nameplate must show the dashboard's glyph with the TRUE
//    count and name the remainder in the dashboard's own sentence.
var over=one({session_id:"s1", label:"L", mini_rows:minis(CAP), subagents:CAP+5});
if(over.subs.length!==CAP)
  bad("a capped row must still draw "+CAP+" minis, got "+over.subs.length);
if(over.subs_total!==CAP+5)
  bad("mapStatus drops r.subagents, so office2 cannot know anyone is missing; got "+
      asc(over.subs_total));
var h=plate(over);
if(h.indexOf("subb")<0)
  bad(CAP+" minis drawn but "+(CAP+5)+" subagents running draws nothing at all: "+asc(h));
if(h.indexOf(GLYPH+(CAP+5))<0)
  bad("the nameplate must show the dashboard's own "+asc(GLYPH+(CAP+5))+" (the TRUE count), "+
      "got "+asc(h));
if(h.indexOf(PRE+"5"+POST)<0)
  bad("the hidden subagents must be named with ui/dashboard.html's own sentence "+
      asc(PRE+"5"+POST)+", got "+asc(h));
// 2. nothing is hidden -> no badge. The minis are already standing on the floor; a second
//    count would be noise, and the dashboard is silent in exactly this case too.
if(hidden(one({session_id:"s2", mini_rows:minis(3), subagents:3})))
  bad("every subagent is drawn, but the nameplate still claimed some were hidden");
if(hidden(one({session_id:"s3", mini_rows:[], subagents:0})))
  bad("a session with no subagents at all still drew the hidden-subagent badge");
// 3. no `subagents` field (codex rows, relayed rows) -> fall back to what IS drawn, never
//    a made-up count and never a raw undefined/NaN on the nameplate
var nof=one({session_id:"s4", mini_rows:minis(2)});
if(nof.subs_total!==2)
  bad("with no r.subagents the total must fall back to the drawn minis (2), got "+
      asc(nof.subs_total));
if(hidden(nof))bad("a row with no r.subagents invented hidden subagents");
var pn=plate(nof);
if(pn.indexOf("undefined")>=0||pn.indexOf("NaN")>=0||pn.indexOf("null")>=0)
  bad("the nameplate leaked a raw undefined/NaN/null: "+asc(pn));
// 4. a backend count BELOW the drawn minis must never produce a negative remainder
var under=one({session_id:"s5", mini_rows:minis(4), subagents:1});
if(hidden(under))bad("r.subagents=1 with 4 minis drawn still claimed subagents were hidden");
// 5. non-numeric / hostile counts draw nothing and never reach the plate as live markup
["7", null, true, {}, [], NaN, -3, "<img src=x onerror=alert(1)>"].forEach(function(v){
  var p=plate(one({session_id:"s6", mini_rows:minis(1), subagents:v}));
  if(p.indexOf("subb")>=0)
    bad("a non-numeric subagent count "+asc(v)+" must draw no badge, got "+asc(p));
  if(/<img/i.test(p))bad("a hostile subagent count reached the nameplate as live markup");
});
// 6. the cap is not the only way to lose minis: mini_rows can be empty while subagents
//    still counts live ones (a mini's file falls outside the recent window). Then EVERY
//    subagent is hidden and the badge is the only thing that says so.
var blind=plate(one({session_id:"s7", mini_rows:[], subagents:4}));
if(blind.indexOf(GLYPH+"4")<0||blind.indexOf(PRE+"4"+POST)<0)
  bad("4 subagents with no identities at all must still be disclosed, got "+asc(blind));
// 7. a mini has no subagents of its own -- the badge belongs to the session only
if(String(personEl(over,true).innerHTML).indexOf("subb")>=0)
  bad("a mini figure drew the hidden-subagent badge");
// 8. which session is hiding them: with no label the nameplate falls back to the short
//    session key ui/dashboard.html links on (r.sub), not office2's own loop ordinal
var keyed=one({session_id:"s8", sub:"ab12cd34", mini_rows:minis(1), subagents:9});
if(keyed.sub!=="ab12cd34")bad("mapStatus drops r.sub; got "+asc(keyed.sub));
var hk=plate(keyed);
if(hk.indexOf("ab12cd34")<0)
  bad("a row with no label must fall back to the short session key, got "+asc(hk));
if(hk.indexOf(">"+keyed.id+"<")>=0||hk.indexOf(keyed.id+"<span")>=0)
  bad("the nameplate still shows the loop ordinal "+asc(keyed.id)+" instead of the key");
var lab=plate(one({session_id:"s9", label:"proj", sub:"ab12cd34"}));
if(lab.indexOf("proj")<0||lab.indexOf("ab12cd34")>=0)
  bad("a labelled row must keep showing its label, got "+asc(lab));
if(plate(one({session_id:"s10"})).indexOf("A1")<0)
  bad("with neither label nor short key the nameplate must still fall back to the id");
var ev=plate(one({session_id:"s11", sub:"<img src=x onerror=alert(1)>"}));
if(/<img/i.test(ev))bad("the short session key reached the nameplate as live markup");
if(ev.indexOf("&lt;img")<0)bad("the short session key is not escaped the way the label is");
console.log("OK");
"""


def office2_subs_js_problem(text, cap, vocab):
    """Run mapStatus + personEl DOM-free over a capped parent and assert office2 discloses
    the subagents it cannot draw, in ui/dashboard.html's own glyph and sentence, and stays
    silent when nothing is hidden. Returns a problem string (folded into the single
    check-office2-subagent-disclosure record) or None when green."""
    node = shutil.which("node")
    if not node:
        return "node is required for the subagent-disclosure fixture"
    glyph, pre, post = vocab[0], vocab[1], vocab[2]
    cases = ("var CAP=%d;var GLYPH=%s;var PRE=%s;var POST=%s;"
             % (cap, json.dumps(glyph), json.dumps(pre), json.dumps(post)))
    parts = {
        "__SUBS_CASES__": cases,
        "__ESC__": extract_js_function(text, "function esc(s){"),
        "__OS_ICON__": extract_js_function(text, "function osIcon(a){"),
        "__CTX_BADGE__": extract_js_function(text, "function ctxBadge(p){"),
        "__STALE_BADGE__": office2_stale_badge_js(text),
        "__HOOK_PM__": office2_hook_pm_js(text),
        "__SUBS_BADGE__": office2_subs_badge_js(text),
        "__MACH_BADGE__": office2_mach_badge_js(text),
        "__PERSON_EL__": office2_person_el_js(text),
        "__MAP_STATUS__": office2_map_status_js(text),
        "__ZONE_OF__": extract_js_function(text, "function zoneOf(r){"),
        "__ST_OF__": extract_js_function(text, "function stOf(s){"),
        # mapStatus derives each mini's own vendor/status through these
        "__SUB_ST__": extract_js_function(text, "function subSt(s){"),
        "__SUB_VEND__": extract_js_function(text, "function subVend(v){"),
        "__STANDBY_WAIT__": extract_js_function(text, "function standbyWait(r){"),
        "__HASH_INT__": extract_js_function(text, "function hashInt(s){"),
    }
    for m, pat in (("__VEND__", r"const VEND\s*=\s*\{.*?\n\};"),
                   ("__STDOT__", r"const STDOT\s*=\s*\{.*?\};"),
                   ("__CLIVEND__", r"const CLIVEND\s*=\s*\{.*?\};"),
                   ("__ST_KNOWN__", r"const ST_KNOWN\s*=\s*\[.*?\];"),
                   ("__OSICON__", r"const OSICON\s*=\s*\{.*?\};"),
                   ("__CTXSTEP__", r"const CTXSTEP\s*=\s*\[.*?\];"),
                   ("__COUNCIL_PHASE__", r"const COUNCIL_PHASE\s*=\s*\{.*?\};"),
                   ("__WAIT_PHRASE__", r"const WAIT_PHRASE\s*=\s*\{.*?\};")):
        hit = re.search(pat, text, re.S)
        parts[m] = hit.group(0) if hit else None
    missing = [k for k, v in parts.items() if not v]
    if missing:
        return "not found in ui/office_proto.html: " + ", ".join(sorted(missing))
    src = OFFICE2_SUBS_DRIVER
    for k, v in parts.items():
        src = src.replace(k, v)
    fd, tmp = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(src)
        proc = subprocess.run([node, tmp], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    finally:
        os.unlink(tmp)
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode == 0 and out.splitlines()[-1:] == ["OK"]:
        return None
    return "subagent-disclosure fixture: " + (out.splitlines()[-1] if out
                                              else "harness exit %d" % proc.returncode)


def cmd_check_office2_subagent_disclosure():
    """Subagents office2 cannot draw must still be admitted to. monitor._mini_rows caps
    mini_rows at _OFFICE_MINI_CAP and office2 draws exactly one figure per mini row, so
    everything past the cap disappeared without a word -- while `subagents` (the true,
    un-truncated count) has been on the row all along and ui/dashboard.html discloses the
    gap twice over (🔬N on the desk, 「另有 N 位子代理，身分不可得」 in the inspector).
    office2 must carry the count, draw the dashboard's glyph with it, name the remainder
    in the dashboard's own sentence, and say nothing when nothing is hidden. It also has
    to say WHICH session is hiding them: `sub`, the short session key the dashboard links
    on, replaces office2's meaningless loop ordinal when a row has no label."""
    name = "check-office2-subagent-disclosure"
    if not os.path.exists(OFFICE_PROTO):
        record("SKIP", name, "ui/office_proto.html absent")
        return True
    text = read_text(OFFICE_PROTO)
    problems = []
    cap, capproblem = office2_mini_cap()
    if capproblem:
        problems.append(capproblem)
    mon = read_text(MONITOR)
    for field in ("subagents", "sub"):
        if '"%s":' % field not in mon:
            problems.append("monitor.py no longer emits `%s` on session rows -- the check's "
                            "premise is stale" % field)
    vocab = office2_subagent_vocab()
    if not vocab:
        problems.append("could not derive the hidden-subagent glyph, sentence and colours "
                        "from ui/dashboard.html -- they must be parsed from the dashboard, "
                        "never re-hardcoded in this checker")
    elif os.path.exists(DASHBOARD):
        if "r.subagents||minis.length" not in read_text(DASHBOARD):
            problems.append("ui/dashboard.html's officeRows no longer derives the desk's "
                            "subagent total as r.subagents||minis.length -- office2 mirrors "
                            "that derivation and would now be lying")
    mapper = extract_js_function(text, "function mapStatus(d){")
    if not mapper:
        problems.append("mapStatus not found")
    else:
        if "r.subagents" not in mapper:
            problems.append("mapStatus never reads r.subagents, so office2 cannot know that "
                            "the capped mini_rows it draws are not all of them")
        if not re.search(r"r\.sub(?![\w$])", mapper):
            problems.append("mapStatus never reads r.sub, so a session with no label is still "
                            "named by office2's own loop ordinal and cannot be looked up")
    person = extract_js_function(text, "function personEl(a, mini){")
    if not person:
        problems.append("personEl not found")
    else:
        if "subsBadge(" not in person:
            problems.append("personEl never draws subsBadge(), so hidden subagents stay hidden")
        if "a.sub" not in person:
            problems.append("personEl never falls back to the short session key (a.sub)")
    rule = re.search(r"\.subb\s*\{([^}]*)\}", text)
    if not rule:
        problems.append("no .subb rule in ui/office_proto.html -- the badge would render "
                        "unstyled")
    elif vocab:
        for tint in vocab[3:]:
            if tint not in rule.group(1):
                problems.append("the .subb badge does not use ui/dashboard.html's own %s for "
                                "its subagent badge" % tint)
    if not problems:
        js = office2_subs_js_problem(text, cap, vocab)
        if js:
            problems.append(js)
    if problems:
        record("FAIL", name, "; ".join(problems))
        return False
    # the glyph itself is deliberately not printed: this line goes to a cp950 console
    record("PASS", name, "a parent capped at monitor._OFFICE_MINI_CAP=%d with more subagents "
           "running discloses the true count with ui/dashboard.html's own desk glyph and "
           "names the remainder in the dashboard's own sentence (%s N%s); nothing hidden, a "
           "missing count, a count below the drawn minis and non-numeric/hostile values all "
           "draw no badge, and a row with no label is named by its short session key"
           % (cap, vocab[1].strip(), vocab[2]))
    return True


def mini_rows_emitter_src():
    """monitor._mini_rows' body -- the premise of check-office2-mini-identity is that each
    mini row already carries its OWN vendor and status. None when the function is gone."""
    mon = read_text(MONITOR)
    i = mon.find("def _mini_rows(")
    if i < 0:
        return None
    j = mon.find("\ndef ", i + 1)
    return mon[i:j if j > 0 else len(mon)]


OFFICE2_MINI_IDENTITY_DRIVER = r"""
function asc(s){return String(s).replace(/[^\x20-\x7e一-鿿]/g,"?");}
function bad(m){console.log("FAIL: "+asc(m));process.exit(1);}
// fixture stubs -- personEl/place only reach createElement, style, classList, appendChild
var CREATURES=[{key:"c0",img:"a.png"},{key:"c1",img:"b.png"}];
function mkEl(){return {className:"",innerHTML:"",
  style:{left:"",top:"",setProperty:function(k,v){this[k]=v;}},
  classList:{add:function(){},remove:function(){},toggle:function(){}},
  appendChild:function(){},querySelector:function(){return null;},
  remove:function(){this.gone=true;}};}
var document={createElement:function(){return mkEl();}};
var floor={appendChild:function(){}};
var seatUse={}, seatOver={}, nodes={};
globalThis.innerWidth=1440;globalThis.innerHeight=900;
__VEND__
__STDOT__
__OSICON__
__CTXSTEP__
__COUNCIL_PHASE__
__WAIT_PHRASE__
__CLIVEND__
__ST_KNOWN__
__ZONES__
__SEAT__
__SUB__
__SUB_DROP__
__SEAT_BAND__
__ESC__
__HASH_INT__
__OS_ICON__
__MACH_BADGE__
__CTX_BADGE__
__STALE_BADGE__
__HOOK_PM__
__SUBS_BADGE__
__PERSON_EL__
__ZONE_OF__
__ST_OF__
__SUB_ST__
__SUB_VEND__
__STANDBY_WAIT__
__STANDBY_GROUP__
__MAP_STATUS__
__SEAT_BAND_FN__
__STALL_BOX__
__SEAT_GRID__
__SEAT_XY__
__SUB_XY__
__PLACE__
function one(row){row.status=row.status||"running";row.work_kind=row.work_kind||"working";
  var src=row.__src||"claude";var d={};d[src]=[row];
  var m=mapStatus(d);
  if(m.length!==1)bad("mapStatus returned "+m.length+" people for "+asc(row.session_id));
  return m[0];}
function draw(a){for(var k in nodes)delete nodes[k];
  for(var b in seatUse)delete seatUse[b];
  var bk=a.zone; var tot={},kmx={}; tot[bk]=1; kmx[bk]=(a.subs||[]).length;
  place(a,false,tot,kmx);return nodes;}
// 1. the shape this check exists for: a STOPPED subagent under a RUNNING parent. The
//    backend gives every mini its own vendor+status; office2 used to clone the parent's.
var a=one({session_id:"s1", label:"P", mini_rows:[
  {session_id:"s1/x", vendor:"cc",    status:"stopped"},
  {session_id:"s1/y", vendor:"codex", status:"running"}]});
if(a.st!=="working")bad("the parent itself must stay working, got "+asc(a.st));
if(a.subs.length!==2)bad("one mini row must draw one subagent, got "+a.subs.length);
if(typeof a.subs[0]!=="object"||a.subs[0]===null)
  bad("a subagent is still a bare id with no identity of its own: "+asc(a.subs[0]));
if(a.subs[0].id!=="A1.1"||a.subs[1].id!=="A1.2")
  bad("the subagent node ids changed shape: "+asc(a.subs[0].id)+"/"+asc(a.subs[1].id));
if(a.subs[0].st!=="stopped")
  bad("a stopped subagent under a running parent is still carried as "+asc(a.subs[0].st));
if(a.subs[1].st!=="working")bad("a running subagent must be working, got "+asc(a.subs[1].st));
if(a.subs[0].vend!=="cc"||a.subs[1].vend!=="codex")
  bad("the minis did not keep their own vendor: "+asc(a.subs[0].vend)+"/"+asc(a.subs[1].vend));
var n=draw(a), m1=n["A1.1"], m2=n["A1.2"];
if(!n["A1"])bad("place() drew no parent figure");
if(!m1||!m2)bad("place() no longer keys the subagent figures by their own id");
if(n["A1"].className.indexOf("st-working")<0)
  bad("the parent figure lost its own status: "+asc(n["A1"].className));
if(m1.className.indexOf("st-stopped")<0)
  bad("the stopped subagent is still drawn with the parent's pose: "+asc(m1.className));
if(m2.className.indexOf("st-working")<0)
  bad("the running subagent is not drawn working: "+asc(m2.className));
if(m1.className.indexOf(" mini")<0||m2.className.indexOf(" mini")<0)
  bad("the subagent figures are no longer the .person.mini box the seat oracle models");
if(m2.style["--vend"]!==VEND.codex.color)
  bad("the mini's vendor colour is not its own: "+asc(m2.style["--vend"]));
if(m2.innerHTML.indexOf(">"+VEND.codex.em+"<")<0||m2.innerHTML.indexOf(">"+VEND.cc.em+"<")>=0)
  bad("the mini still wears the parent's vendor emblem: "+asc(m2.innerHTML));
// 2. every raw status monitor can put on a mini row maps to office2's own vocabulary,
//    exactly as it does for a session row -- the minis get no second, private mapping
ST_KNOWN.forEach(function(raw){
  var p=one({session_id:"r-"+raw, mini_rows:[{session_id:"r/"+raw, vendor:"cc", status:raw}]});
  if(p.subs[0].st!==stOf(raw))
    bad("a mini with status "+asc(raw)+" drew "+asc(p.subs[0].st)+", but a session row with "+
        "the same status draws "+asc(stOf(raw)));
});
// 3. a missing / unrecognised / hostile status must NOT fall through to "working" --
//    that fallthrough IS the lie this check exists for. Mirror the dashboard: idle.
[undefined, null, "", "bogus", 3, {}, [], "<img src=x onerror=alert(1)>"].forEach(function(v){
  var p=one({session_id:"u1", mini_rows:[{session_id:"u/1", vendor:"cc", status:v}]});
  if(p.subs[0].st==="working")
    bad("a mini whose status is "+asc(v)+" was drawn as working");
  if(p.subs[0].st!==stOf("idle"))
    bad("an unusable mini status must fall back the way ui/dashboard.html's normalizeStatus "+
        "does (idle), got "+asc(p.subs[0].st));
  var h=draw(p)["A1.1"].innerHTML;
  if(/onerror|src=x/i.test(h))bad("a hostile mini status reached the figure as live markup");
});
// 4. an unrecognised / missing mini vendor falls back to office2's own unknown emblem and
//    never silently inherits the parent's identity
var c=one({__src:"codex", session_id:"s3", mini_rows:[
  {session_id:"s3/a", vendor:"nope"}, {session_id:"s3/b"},
  {session_id:"s3/c", vendor:"<img src=x onerror=alert(1)>"}]});
if(c.vend!=="codex")bad("the parent vendor came from the wrong bucket: "+asc(c.vend));
c.subs.forEach(function(s){
  if(s.vend==="codex")bad("a mini with no usable vendor inherited the parent's");
  if(VEND[s.vend])bad("an unusable mini vendor resolved to a real vendor: "+asc(s.vend));
});
var un=draw(c);
["A1.1","A1.2","A1.3"].forEach(function(k){
  if(un[k].innerHTML.indexOf(">?<")<0)
    bad(k+" does not wear office2's own unknown-vendor emblem: "+asc(un[k].innerHTML));
  if(/onerror|src=x/i.test(un[k].innerHTML))
    bad("a hostile mini vendor reached the figure as live markup");
});
// 5. the vendor aliases the backend actually emits resolve, and they resolve to the same
//    key office2 already uses for a session of that vendor
[["claude","cc"],["cc","cc"],["CC","cc"],["Codex","codex"],["hermes","hermes"]].forEach(
  function(p){
    var s=one({session_id:"v"+p[0], mini_rows:[{session_id:"v/1", vendor:p[0]}]}).subs[0];
    if(s.vend!==p[1])bad("mini vendor "+asc(p[0])+" resolved to "+asc(s.vend)+", want "+
                         asc(p[1]));
  });
// 6. a mini_rows entry that is not an object at all must not throw and must not be drawn
//    as a working Claude agent
[null, "s1/x", 7].forEach(function(v){
  var p=one({session_id:"j1", mini_rows:[v]});
  if(p.subs.length!==1)bad("a junk mini row changed the drawn count");
  if(p.subs[0].st==="working")bad("a junk mini row was drawn as working");
  if(VEND[p.subs[0].vend])bad("a junk mini row claimed a real vendor");
});
console.log("OK");
"""


def office2_mini_identity_js_problem(text):
    """Run mapStatus + place + personEl DOM-free and assert every subagent figure office2
    draws carries the vendor and status of ITS OWN mini row -- never the parent's -- and
    that an unusable vendor/status falls back the way ui/dashboard.html's
    normalizeVendor/normalizeStatus do instead of reading as a running Claude agent.
    Returns a problem string (folded into the single check-office2-mini-identity record)
    or None when green."""
    node = shutil.which("node")
    if not node:
        return "node is required for the mini-identity fixture"
    parts = {
        "__ESC__": extract_js_function(text, "function esc(s){"),
        "__OS_ICON__": extract_js_function(text, "function osIcon(a){"),
        "__CTX_BADGE__": extract_js_function(text, "function ctxBadge(p){"),
        "__STALE_BADGE__": office2_stale_badge_js(text),
        "__HOOK_PM__": office2_hook_pm_js(text),
        "__SUBS_BADGE__": office2_subs_badge_js(text),
        "__MACH_BADGE__": office2_mach_badge_js(text),
        "__PERSON_EL__": office2_person_el_js(text),
        "__MAP_STATUS__": office2_map_status_js(text),
        "__ZONE_OF__": extract_js_function(text, "function zoneOf(r){"),
        "__ST_OF__": extract_js_function(text, "function stOf(s){"),
        "__SUB_ST__": extract_js_function(text, "function subSt(s){"),
        "__SUB_VEND__": extract_js_function(text, "function subVend(v){"),
        "__STANDBY_WAIT__": extract_js_function(text, "function standbyWait(r){"),
        "__STANDBY_GROUP__": extract_js_function(text, "function standbyGroup(a){"),
        "__HASH_INT__": extract_js_function(text, "function hashInt(s){"),
        "__SEAT_BAND_FN__": extract_js_function(text, "function seatBand(zoneKey, grp){"),
        "__STALL_BOX__": extract_js_function(text, "function stallBox(k){"),
        "__SEAT_GRID__": extract_js_function(text, "function seatGrid(zoneKey, grp, n, kmax){"),
        "__SEAT_XY__": extract_js_function(text, "function seatXY(zoneKey, idx, grp, n, kmax){"),
        "__SUB_XY__": extract_js_function(text, "function subXY(seat, i, k){"),
        "__PLACE__": extract_js_function(text, "function place(a, animate, tot, kmx){"),
    }
    for m, pat in (("__VEND__", r"const VEND\s*=\s*\{.*?\n\};"),
                   ("__STDOT__", r"const STDOT\s*=\s*\{.*?\};"),
                   ("__OSICON__", r"const OSICON\s*=\s*\{.*?\};"),
                   ("__CTXSTEP__", r"const CTXSTEP\s*=\s*\[.*?\];"),
                   ("__COUNCIL_PHASE__", r"const COUNCIL_PHASE\s*=\s*\{.*?\};"),
                   ("__WAIT_PHRASE__", r"const WAIT_PHRASE\s*=\s*\{.*?\};"),
                   ("__CLIVEND__", r"const CLIVEND\s*=\s*\{.*?\};"),
                   ("__ST_KNOWN__", r"const ST_KNOWN\s*=\s*\[.*?\];"),
                   ("__ZONES__", r"const ZONES\s*=\s*\[.*?\];"),
                   ("__SEAT__", r"const SEAT\s*=\s*\{.*?\};"),
                   ("__SUB__", r"const SUB\s*=\s*\{.*?\};"),
                   ("__SUB_DROP__", r"const SUB_DROP\s*=[^;]+;"),
                   ("__SEAT_BAND__", r"const SEAT_BAND\s*=\s*\{.*?\};")):
        hit = re.search(pat, text, re.S)
        parts[m] = hit.group(0) if hit else None
    missing = [k for k, v in parts.items() if not v]
    if missing:
        return "not found in ui/office_proto.html: " + ", ".join(sorted(missing))
    src = OFFICE2_MINI_IDENTITY_DRIVER
    for k, v in parts.items():
        src = src.replace(k, v)
    fd, tmp = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(src)
        proc = subprocess.run([node, tmp], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    finally:
        os.unlink(tmp)
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode == 0 and out.splitlines()[-1:] == ["OK"]:
        return None
    return "mini-identity fixture: " + (out.splitlines()[-1] if out
                                        else "harness exit %d" % proc.returncode)


def cmd_check_office2_mini_identity():
    """A subagent figure must be its OWN row. office2 built every mini out of the parent
    ({vend:a.vend, st:a.st}), so a stopped subagent parked under a running parent was drawn
    as if it were still working -- a semantic lie, not a missing badge. monitor._mini_rows
    has always put a vendor and a status on each mini row, and ui/dashboard.html's officeRows
    already reads them per mini (normalizeVendor(m.vendor)/normalizeStatus(m.status)) for the
    Signal Desk followers. office2 must do the same, and an unusable vendor/status must fall
    back the way the dashboard's normalizers do -- to the unknown emblem and to idle -- never
    to the parent's identity and never to 'working'."""
    name = "check-office2-mini-identity"
    if not os.path.exists(OFFICE_PROTO):
        record("SKIP", name, "ui/office_proto.html absent")
        return True
    text = read_text(OFFICE_PROTO)
    problems = []
    emitter = mini_rows_emitter_src()
    if emitter is None:
        problems.append("monitor._mini_rows is gone -- this check's premise (every mini row "
                        "carries its own vendor and status) is stale")
    else:
        for field in ("vendor", "status"):
            if '"%s":' % field not in emitter:
                problems.append("monitor._mini_rows no longer puts `%s` on a mini row -- "
                                "office2 would have nothing per-mini to read" % field)
    if os.path.exists(DASHBOARD):
        dash = read_text(DASHBOARD)
        for expr in ("normalizeVendor(m.vendor)", "normalizeStatus(m.status)"):
            if expr not in dash:
                problems.append("ui/dashboard.html's officeRows no longer derives the mini's "
                                "identity as %s -- office2 mirrors that derivation and this "
                                "check's reference behaviour is gone" % expr)
        glyphs = re.search(r"const STATUS_GLYPH\s*=\s*\{(.*?)\n\};", dash, re.S)
        known = re.search(r"const ST_KNOWN\s*=\s*\[(.*?)\];", text, re.S)
        if not glyphs:
            problems.append("STATUS_GLYPH not found in ui/dashboard.html")
        elif not known:
            problems.append("ui/office_proto.html has no ST_KNOWN whitelist, so an unknown "
                            "mini status still falls through stOf() to 'working'")
        else:
            want = set(re.findall(r"^\s*([A-Za-z]+)\s*:", glyphs.group(1), re.M))
            got = set(re.findall(r"'([^']+)'", known.group(1)))
            if want != got:
                problems.append("office2's ST_KNOWN %s drifted from the raw statuses "
                                "ui/dashboard.html accepts %s"
                                % (sorted(got), sorted(want)))
    placer = extract_js_function(text, "function place(a, animate, tot, kmx){")
    renderer = extract_js_function(text, "function render(animate){")
    if not placer:
        problems.append("place(a, animate, tot, kmx) not found")
    else:
        if re.search(r"vend\s*:\s*a\.vend", placer) or re.search(r"st\s*:\s*a\.st", placer):
            problems.append("place() still builds the mini figure out of the parent's vendor/"
                            "status -- that is exactly the lie this check exists for")
        cleanup = re.search(r"\.concat\((.*?)\)\.forEach", placer)
        if cleanup and ".id" not in cleanup.group(1):
            problems.append("place()'s over-capacity cleanup still treats a subagent entry as "
                            "a node id -- the node map is keyed by the mini's own id")
    if not renderer:
        problems.append("render(animate) not found")
    else:
        for arg in re.findall(r"live\.add\(([^()]*)\)", renderer):
            if "." not in arg:
                problems.append("render() puts the subagent entry itself into the live-node "
                                "set (live.add(%s)) -- the node map is keyed by the mini's "
                                "own id, so every mini figure would be dropped each poll"
                                % arg.strip())
    if not problems:
        js = office2_mini_identity_js_problem(text)
        if js:
            problems.append(js)
    if problems:
        record("FAIL", name, "; ".join(problems))
        return False
    record("PASS", name, "every subagent figure is drawn from its own mini row: a stopped "
           "subagent under a running parent is drawn stopped, each mini wears its own vendor "
           "emblem and colour, every raw status maps through the same stOf() a session row "
           "uses, and a missing/unrecognised/hostile vendor or status falls back to the "
           "unknown emblem and to idle instead of the parent's identity or 'working'")
    return True


# ------------------------------------------------------ office2 routing evidence
#
# `work_reason` is the backend's own answer to "why is this row in that zone"
# (monitor.py sets it alongside work_kind). ui/dashboard.html already names three
# of those reasons in signalDeskRouteLabel's `const labels={...}` and shows the
# wording as the desk's aria-label and as the inspector's "Routing evidence".
# office2 read none of it, so a session parked in 待命 could equally have been a
# machine nobody can reach or a session genuinely idle. The three strings are
# parsed back out of the dashboard here -- office2 keeps one literal copy for
# rendering, and this check is what makes that copy fail on drift.
_ROUTE_LABELS_RE = re.compile(r"const labels\s*=\s*\{([^{}]*)\}")
_ROUTE_PAIR_RE = re.compile(r"([A-Za-z_][\w]*)\s*:\s*'([^']*)'")
_WORK_REASON_ASSIGN_RE = re.compile(r'row\["work_reason"\]\s*=\s*(.+)')


def office2_route_labels():
    """Derive the routing-evidence wording from ui/dashboard.html's signalDeskRouteLabel
    instead of re-hardcoding it here (same reasoning as office2_stale_notice(): the
    strings are already mirrored once inside office2, and a second hand-written copy in
    the oracle would make drift invisible). Returns {work_reason: label} or None when the
    dashboard's own map can no longer be parsed."""
    if not os.path.exists(DASHBOARD):
        return None
    src = extract_js_function(read_text(DASHBOARD), "function signalDeskRouteLabel(r){")
    if not src:
        return None
    hit = _ROUTE_LABELS_RE.search(src)
    if not hit:
        return None
    return dict(_ROUTE_PAIR_RE.findall(hit.group(1))) or None


def office2_work_reason_emitter():
    """Every literal monitor.py can assign to row["work_reason"] -- the premise of this
    check is that the reasons the dashboard names are still emitted, so that office2 does
    not mirror dead wording. Empty set when the field is no longer written at all."""
    out = set()
    for rhs in _WORK_REASON_ASSIGN_RE.findall(read_text(MONITOR)):
        out |= set(re.findall(r'"([^"]*)"', rhs))
    return out


OFFICE2_WORK_REASON_DRIVER = r"""
function asc(s){return String(s).replace(/[^\x20-\x7e一-鿿]/g,"?");}
function bad(m){console.log("FAIL: "+asc(m));process.exit(1);}
// fixture stubs -- personEl/place only reach createElement, style, classList, appendChild
var CREATURES=[{key:"c0",img:"a.png"},{key:"c1",img:"b.png"}];
function mkEl(){return {className:"",innerHTML:"",title:"",
  style:{left:"",top:"",setProperty:function(k,v){this[k]=v;}},
  classList:{add:function(){},remove:function(){},toggle:function(){}},
  appendChild:function(){},querySelector:function(){return null;},
  remove:function(){this.gone=true;}};}
var document={createElement:function(){return mkEl();}};
var floor={appendChild:function(){}};
var seatUse={}, seatOver={}, nodes={};
globalThis.innerWidth=1440;globalThis.innerHeight=900;
__LABELS__
__VEND__
__STDOT__
__OSICON__
__CTXSTEP__
__COUNCIL_PHASE__
__WAIT_PHRASE__
__CLIVEND__
__ST_KNOWN__
__ZONES__
__SEAT__
__SUB__
__SUB_DROP__
__SEAT_BAND__
__ESC__
__HASH_INT__
__OS_ICON__
__MACH_BADGE__
__CTX_BADGE__
__STALE_BADGE__
__HOOK_PM__
__SUBS_BADGE__
__PERSON_EL__
__ZONE_OF__
__ST_OF__
__SUB_ST__
__SUB_VEND__
__STANDBY_WAIT__
__STANDBY_GROUP__
__MAP_STATUS__
__SEAT_BAND_FN__
__STALL_BOX__
__SEAT_GRID__
__SEAT_XY__
__SUB_XY__
__PLACE__
function one(row){row.status=row.status||"running";row.work_kind=row.work_kind||"working";
  var d={claude:[row]};
  var m=mapStatus(d);
  if(m.length!==1)bad("mapStatus returned "+m.length+" people for "+asc(row.session_id));
  return m[0];}
function draw(a){for(var k in nodes)delete nodes[k];
  for(var b in seatUse)delete seatUse[b];
  place(a,false,{},{});return nodes;}
var KEYS=Object.keys(LABELS);
if(!KEYS.length)bad("the dashboard's routing-evidence map came through empty");
// 1. every reason ui/dashboard.html names reaches the figure with the dashboard's OWN
//    wording -- and reaches it as text (.title), never as markup
KEYS.forEach(function(k){
  var a=one({session_id:"s-"+k, label:"P", work_reason:k,
             status:k==="status_stopped"?"stopped":"running"});
  if(a.route!==LABELS[k])
    bad("mapStatus carried "+asc(k)+" as "+asc(a.route)+", want "+asc(LABELS[k]));
  var t=draw(a)["A1"].title;
  if(t!==LABELS[k])
    bad("the figure for work_reason "+asc(k)+" says "+asc(t)+", want "+asc(LABELS[k]));
  if(!t)bad("work_reason "+asc(k)+" is in office2's map but draws nothing");
});
// 2. a reason office2 has no wording for is NOT given an invented one, and a hostile /
//    unusable value is neither echoed nor drawn as live markup. 'no_active_tail' is real
//    (monitor emits it) and deliberately unnamed by the dashboard: silence, not a guess.
["no_active_tail", undefined, null, "", "bogus", 3, {}, [],
 "__proto__", "constructor", "toString", "hasOwnProperty",
 "<img src=x onerror=alert(1)>"].forEach(function(v){
  var a=one({session_id:"u1", label:"P", work_reason:v});
  if(a.route!=="")
    bad("work_reason "+asc(v)+" was given the invented reason "+asc(a.route));
  var n=draw(a)["A1"];
  if(n.title!=="")bad("work_reason "+asc(v)+" put "+asc(n.title)+" on the figure");
  KEYS.forEach(function(k){
    if(String(n.title).indexOf(LABELS[k])>=0)
      bad("work_reason "+asc(v)+" borrowed the wording of "+asc(k));
  });
  if(/onerror|src=x/i.test(n.innerHTML))
    bad("a hostile work_reason reached the figure as live markup");
});
// 3. the routing evidence does not evict the task progress the tooltip already carried
var wt=one({session_id:"t1", label:"P", work_reason:"active_tail",
            task_total:3, task_index:2, task_done:1, task_current:"C", task_eta:"5m"});
var tt=draw(wt)["A1"].title;
if(tt.indexOf(LABELS.active_tail)<0)bad("a row with a task lost its routing evidence: "+asc(tt));
if(tt.indexOf("Task 2/3")<0)bad("the routing evidence evicted the task progress: "+asc(tt));
// 4. a subagent figure has no work_reason of its own and must not wear the parent's
var pm=one({session_id:"p1", label:"P", work_reason:"active_tail",
            mini_rows:[{session_id:"p1/x", vendor:"cc", status:"running"}]});
var mn=draw(pm);
if(!mn["A1.1"])bad("place() drew no subagent figure");
if(mn["A1.1"].title!=="")
  bad("a subagent wears the parent's routing evidence: "+asc(mn["A1.1"].title));
// 5. figures are reused across polls: a session that stops must not keep the reason it
//    was routed by on the previous poll
for(var k0 in nodes)delete nodes[k0];
for(var b0 in seatUse)delete seatUse[b0];
var p1=one({session_id:"m1", label:"P", work_reason:"active_tail"});
place(p1,false,{},{});
if(nodes.A1.title!==LABELS.active_tail)
  bad("the first poll did not put the routing evidence on the figure: "+asc(nodes.A1.title));
for(var b1 in seatUse)delete seatUse[b1];
var p2=one({session_id:"m1", label:"P", work_reason:"status_stopped", status:"stopped"});
place(p2,false,{},{});
if(nodes.A1.title!==LABELS.status_stopped)
  bad("a reused figure kept the previous poll's routing evidence: "+asc(nodes.A1.title));
console.log("OK");
"""


def office2_work_reason_js_problem(text, labels):
    """Run mapStatus + place + personEl DOM-free and assert every work_reason
    ui/dashboard.html names reaches the office2 figure in the dashboard's own wording,
    that an unnamed / unusable / hostile reason is answered with silence rather than an
    invented one, and that a reused figure does not keep the previous poll's reason.
    Returns a problem string (folded into the single check-office2-work-reason record)
    or None when green."""
    node = shutil.which("node")
    if not node:
        return "node is required for the routing-evidence fixture"
    parts = {
        "__LABELS__": "var LABELS=%s;" % json.dumps(labels, ensure_ascii=False),
        "__ESC__": extract_js_function(text, "function esc(s){"),
        "__OS_ICON__": extract_js_function(text, "function osIcon(a){"),
        "__CTX_BADGE__": extract_js_function(text, "function ctxBadge(p){"),
        "__STALE_BADGE__": office2_stale_badge_js(text),
        "__HOOK_PM__": office2_hook_pm_js(text),
        "__SUBS_BADGE__": office2_subs_badge_js(text),
        "__MACH_BADGE__": office2_mach_badge_js(text),
        "__PERSON_EL__": office2_person_el_js(text),
        "__MAP_STATUS__": office2_map_status_js(text),
        "__ZONE_OF__": extract_js_function(text, "function zoneOf(r){"),
        "__ST_OF__": extract_js_function(text, "function stOf(s){"),
        "__SUB_ST__": extract_js_function(text, "function subSt(s){"),
        "__SUB_VEND__": extract_js_function(text, "function subVend(v){"),
        "__STANDBY_WAIT__": extract_js_function(text, "function standbyWait(r){"),
        "__STANDBY_GROUP__": extract_js_function(text, "function standbyGroup(a){"),
        "__HASH_INT__": extract_js_function(text, "function hashInt(s){"),
        "__SEAT_BAND_FN__": extract_js_function(text, "function seatBand(zoneKey, grp){"),
        "__STALL_BOX__": extract_js_function(text, "function stallBox(k){"),
        "__SEAT_GRID__": extract_js_function(text, "function seatGrid(zoneKey, grp, n, kmax){"),
        "__SEAT_XY__": extract_js_function(text, "function seatXY(zoneKey, idx, grp, n, kmax){"),
        "__SUB_XY__": extract_js_function(text, "function subXY(seat, i, k){"),
        "__PLACE__": extract_js_function(text, "function place(a, animate, tot, kmx){"),
    }
    for m, pat in (("__VEND__", r"const VEND\s*=\s*\{.*?\n\};"),
                   ("__STDOT__", r"const STDOT\s*=\s*\{.*?\};"),
                   ("__OSICON__", r"const OSICON\s*=\s*\{.*?\};"),
                   ("__CTXSTEP__", r"const CTXSTEP\s*=\s*\[.*?\];"),
                   ("__COUNCIL_PHASE__", r"const COUNCIL_PHASE\s*=\s*\{.*?\};"),
                   ("__WAIT_PHRASE__", r"const WAIT_PHRASE\s*=\s*\{.*?\};"),
                   ("__CLIVEND__", r"const CLIVEND\s*=\s*\{.*?\};"),
                   ("__ST_KNOWN__", r"const ST_KNOWN\s*=\s*\[.*?\];"),
                   ("__ZONES__", r"const ZONES\s*=\s*\[.*?\];"),
                   ("__SEAT__", r"const SEAT\s*=\s*\{.*?\};"),
                   ("__SUB__", r"const SUB\s*=\s*\{.*?\};"),
                   ("__SUB_DROP__", r"const SUB_DROP\s*=[^;]+;"),
                   ("__SEAT_BAND__", r"const SEAT_BAND\s*=\s*\{.*?\};")):
        hit = re.search(pat, text, re.S)
        parts[m] = hit.group(0) if hit else None
    missing = [k for k, v in parts.items() if not v]
    if missing:
        return "not found in ui/office_proto.html: " + ", ".join(sorted(missing))
    src = OFFICE2_WORK_REASON_DRIVER
    for k, v in parts.items():
        src = src.replace(k, v)
    fd, tmp = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(src)
        proc = subprocess.run([node, tmp], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    finally:
        os.unlink(tmp)
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode == 0 and out.splitlines()[-1:] == ["OK"]:
        return None
    return "routing-evidence fixture: " + (out.splitlines()[-1] if out
                                           else "harness exit %d" % proc.returncode)


def cmd_check_office2_work_reason():
    """Why a session sits where it sits. monitor.py already puts `work_reason` on every
    session row and ui/dashboard.html already turns three of those reasons into wording a
    human can read (signalDeskRouteLabel, shown as the desk's aria-label and as the
    inspector's "Routing evidence"). office2 read none of it, so 待命 could equally mean a
    session genuinely idle or a remote machine nobody has heard from. office2 must carry
    the field and show the dashboard's OWN three strings -- a reason the dashboard does not
    name (monitor's `no_active_tail`) gets silence, never an invented one, because office2's
    eight zones and the dashboard's four are different vocabularies."""
    name = "check-office2-work-reason"
    if not os.path.exists(OFFICE_PROTO):
        record("SKIP", name, "ui/office_proto.html absent")
        return True
    text = read_text(OFFICE_PROTO)
    problems, labels = [], office2_route_labels()
    if not labels:
        problems.append("ui/dashboard.html's signalDeskRouteLabel no longer defines its own "
                        "`const labels={...}` map -- office2 mirrors those exact strings and "
                        "this check has no reference wording left to compare against")
    else:
        emitted = office2_work_reason_emitter()
        if not emitted:
            problems.append("monitor.py no longer assigns row[\"work_reason\"] -- this check's "
                            "premise (the backend says why a row was routed) is stale")
        else:
            for key in sorted(set(labels) - emitted):
                problems.append("ui/dashboard.html names the work_reason %r but monitor.py "
                                "never emits it -- office2 would be mirroring dead wording"
                                % key)
        mirror = re.search(r"const ROUTE_EVIDENCE\s*=\s*\{([^{}]*)\};", text)
        if not mirror:
            problems.append("ui/office_proto.html defines no ROUTE_EVIDENCE map, so office2 "
                            "has no wording for the routing evidence at all")
        else:
            got = dict(_ROUTE_PAIR_RE.findall(mirror.group(1)))
            if got != labels:
                problems.append("office2's ROUTE_EVIDENCE %s drifted from the wording "
                                "ui/dashboard.html's signalDeskRouteLabel uses %s -- office2 "
                                "must reuse the existing vocabulary"
                                % (sorted(got.items()), sorted(labels.items())))
    mapper = extract_js_function(text, "function mapStatus(d){")
    if not mapper:
        problems.append("mapStatus(d) not found in ui/office_proto.html")
    elif "routeEvidence(r)" not in mapper:
        problems.append("mapStatus never derives the routing evidence from r.work_reason, so "
                        "office2 still cannot say why a session is in the zone it is in")
    placer = extract_js_function(text, "function place(a, animate, tot, kmx){")
    if not placer:
        problems.append("place(a, animate, tot, kmx) not found in ui/office_proto.html")
    elif "personTip(a)" not in placer:
        problems.append("place() never refreshes the tooltip on a node it reuses across "
                        "polls, so a session that stops would keep the reason it was routed "
                        "by on the previous poll")
    if not problems:
        js = office2_work_reason_js_problem(text, labels)
        if js:
            problems.append(js)
    if problems:
        record("FAIL", name, "; ".join(problems))
        return False
    record("PASS", name, "office2 reads r.work_reason and shows the %d reason(s) "
           "ui/dashboard.html itself names (%s) in the dashboard's own wording; a reason it "
           "has no wording for, a missing/hostile value and a subagent row all stay silent "
           "instead of borrowing one, the task progress in the same tooltip survives, and a "
           "figure reused across polls is re-stamped rather than keeping the old reason"
           % (len(labels), ", ".join(sorted(labels))))
    return True


# --------------------------------------- office2 stable ordinal + launch batch
#
# monitor.py puts two identity fields on every session row: `agent_idx` (which
# agent of its launch this is) and `group_key` (which launch it belongs to).
# office2 numbered its figures with the loop position instead, so a session
# joining or leaving renumbered everybody -- and that number is also office2's
# node key, so the renumber handed a drawn figure to a different session. The
# launch grouping was lost outright. ui/dashboard.html already reads both
# (signalDeskOrdinals' agentIdx+1, batchColor(groupKey)), so the palette is
# parsed back out of the dashboard here -- office2 keeps one mirrored copy and
# this oracle is what stops it drifting.


def office2_batch_palette():
    """ui/dashboard.html's own BATCH_PALETTE, in its own order, parsed instead of
    re-hardcoded here (same reasoning as office2_ctx_scale(): the palette is already
    mirrored once inside office2, and a second hand-written copy in the oracle would
    make drift invisible). [] when the registry is gone."""
    hit = re.search(r"const BATCH_PALETTE=\[(.*?)\];", read_text(DASHBOARD), re.S)
    return re.findall(r"#[0-9A-Fa-f]{6}", hit.group(1)) if hit else []


def office2_identity_emitters():
    """The two identity fields monitor.py assigns -- the premise of this check is that
    the backend still says which agent of which launch a row is. Returns the subset of
    {"agent_idx", "group_key"} still written."""
    mon = read_text(MONITOR)
    return set(f for f in ("agent_idx", "group_key")
               if re.search(r'row\["%s"\]\s*=' % f, mon))


OFFICE2_IDENTITY_DRIVER = r"""
function asc(s){return String(s).replace(/[^\x20-\x7e一-鿿]/g,"?");}
function bad(m){console.log("FAIL: "+asc(m));process.exit(1);}
// fixture stubs -- personEl/place only reach createElement, style, classList, appendChild
var CREATURES=[{key:"c0",img:"a.png"},{key:"c1",img:"b.png"}];
function mkEl(){return {className:"",innerHTML:"",title:"",
  style:{left:"",top:"",setProperty:function(k,v){this[k]=v;}},
  classList:{add:function(){},remove:function(){},toggle:function(){}},
  appendChild:function(){},querySelector:function(){return null;},
  remove:function(){this.gone=true;}};}
var document={createElement:function(){return mkEl();}};
var floor={appendChild:function(){}};
var seatUse={}, seatOver={}, nodes={};
globalThis.innerWidth=1440;globalThis.innerHeight=900;
__PALETTE__
__VEND__
__STDOT__
__OSICON__
__CTXSTEP__
__COUNCIL_PHASE__
__WAIT_PHRASE__
__CLIVEND__
__ST_KNOWN__
__ZONES__
__SEAT__
__SUB__
__SUB_DROP__
__SEAT_BAND__
__ESC__
__HASH_INT__
__OS_ICON__
__MACH_BADGE__
__CTX_BADGE__
__STALE_BADGE__
__HOOK_PM__
__SUBS_BADGE__
__PERSON_EL__
__ZONE_OF__
__ST_OF__
__SUB_ST__
__SUB_VEND__
__STANDBY_WAIT__
__STANDBY_GROUP__
__MAP_STATUS__
__SEAT_BAND_FN__
__STALL_BOX__
__SEAT_GRID__
__SEAT_XY__
__SUB_XY__
__PLACE__
function map(rows){rows.forEach(function(r){r.status=r.status||"running";
  r.work_kind=r.work_kind||"working";});return mapStatus({claude:rows});}
function ids(rows){return map(rows).map(function(a){return a.id;}).join(",");}
function draw(people){for(var k in nodes)delete nodes[k];
  for(var b in seatUse)delete seatUse[b];
  people.forEach(function(a){place(a,false,{},{});});return nodes;}
// 1. the ordinal is the backend's agent_idx+1, not the position in this poll
if(ids([{session_id:"a",agent_idx:2},{session_id:"b",agent_idx:0},{session_id:"c",agent_idx:1}])
   !=="A3,A1,A2")
  bad("agent_idx is not the ordinal; got "+asc(ids([{session_id:"a",agent_idx:2},
      {session_id:"b",agent_idx:0},{session_id:"c",agent_idx:1}])));
// 2. sessions joining and leaving must not renumber the ones that stayed -- the
//    ordinal is also office2's node key, so a renumber hands a figure to someone else
var before=map([{session_id:"a",agent_idx:2},{session_id:"b",agent_idx:0},
                {session_id:"c",agent_idx:1}]);
var after=map([{session_id:"d",agent_idx:5},{session_id:"a",agent_idx:2},
               {session_id:"c",agent_idx:1}]);
var wasA=before[0].id, wasC=before[2].id, nowA=after[1].id, nowC=after[2].id;
if(wasA!==nowA||wasC!==nowC)
  bad("a session that stayed was renumbered when the poll changed: "+asc(wasA+"/"+wasC)+
      " became "+asc(nowA+"/"+nowC));
if(after[0].id!=="A6")bad("a newly seen agent_idx did not take its own ordinal: "+asc(after[0].id));
// 3. rows the backend gives no agent_idx (not spawned by the launcher) still get a
//    number, and never one already taken by a fixed ordinal
if(ids([{session_id:"p",agent_idx:1},{session_id:"q"},{session_id:"s"}])!=="A2,A1,A3")
  bad("the fallback ordinals collide with or ignore the fixed one: "+
      asc(ids([{session_id:"p",agent_idx:1},{session_id:"q"},{session_id:"s"}])));
// 4. two rows carrying the SAME agent_idx (two launches) must not share a figure
var dup=map([{session_id:"x",agent_idx:0},{session_id:"y",agent_idx:0},{session_id:"z"}]);
var seen={};dup.forEach(function(a){if(seen[a.id])bad("two sessions share the ordinal "+
  asc(a.id)+" -- they would share one figure");seen[a.id]=1;});
// 5. an unusable agent_idx is not turned into a number: no NaN/undefined ordinal
[ "1", -1, 1.5, NaN, null, undefined, {}, [], true, "0", Infinity, -0.5,
  "__proto__" ].forEach(function(v){
  var a=map([{session_id:"u",agent_idx:v}])[0];
  if(!/^A[1-9][0-9]*$/.test(a.id))
    bad("agent_idx "+asc(v)+" produced the ordinal "+asc(a.id));
});
// 6. the subagent ids hang off the parent's stable ordinal
var pa=map([{session_id:"p1",agent_idx:3,mini_rows:[{session_id:"p1/x",vendor:"cc",status:"running"},
                                                    {session_id:"p1/y",vendor:"cc",status:"running"}]}])[0];
if(pa.id!=="A4"||pa.subs[0].id!=="A4.1"||pa.subs[1].id!=="A4.2")
  bad("the subagent ids do not follow the parent's ordinal: "+asc(pa.id)+"/"+asc(pa.subs[0].id));
// 7. the launch batch is carried off r.group_key, with the dashboard's own fallback
var g=map([{session_id:"s1",group_key:"launch-a"},{session_id:"s2",group_key:"launch-a"},
           {session_id:"s3",group_key:"launch-b"},{session_id:"s4"}]);
if(g[0].batch!==g[1].batch)bad("two sessions of one launch are not in the same batch: "+
  asc(g[0].batch)+"/"+asc(g[1].batch));
if(g[0].batch===g[2].batch)bad("two different launches were merged into one batch");
if(g[3].batch!=="s4")
  bad("a row with no group_key must fall back to its own session, got "+asc(g[3].batch));
// 8. the colour comes from the dashboard's palette and nothing else, and the whole
//    palette is reachable (a single-colour 'batch' would say nothing)
var reach={};
for(var i=0;i<300;i++){var c=batchColor("launch-"+i);
  if(PALETTE.indexOf(c)<0)bad("batchColor returned "+asc(c)+", outside the dashboard palette");
  reach[c]=1;}
if(Object.keys(reach).length!==PALETTE.length)
  bad("only "+Object.keys(reach).length+" of the "+PALETTE.length+" batch colours are reachable");
[null,undefined,"",{},[],0,"<img src=x onerror=alert(1)>"].forEach(function(v){
  if(PALETTE.indexOf(batchColor(v))<0)
    bad("batchColor("+asc(v)+") is not one of the dashboard's colours: "+asc(batchColor(v)));});
// 9. the colour is a function of the launch key alone
if(batchColor("launch-a")!==batchColor("launch-a"))bad("batchColor is not deterministic");
var v1=map([{session_id:"m1",group_key:"launch-a"}])[0];
var v2=map([{session_id:"m2",group_key:"launch-a",vendor:"codex",work_kind:"standby"}])[0];
if(batchColor(v1.batch)!==batchColor(v2.batch))
  bad("the batch colour changed with the session/vendor instead of the launch key");
// 10. it reaches the figure, and the whole launch wears it
var pal=[];for(var j=0;j<PALETTE.length;j++){for(var q=0;q<300;q++){
  if(batchColor("k"+q)===PALETTE[j]){pal.push("k"+q);break;}}}
if(pal.length<2)bad("could not find two launch keys with different colours");
var people=map([{session_id:"f1",group_key:pal[0],mini_rows:[{session_id:"f1/x",vendor:"cc",status:"running"}]},
                {session_id:"f2",group_key:pal[0]},{session_id:"f3",group_key:pal[1]}]);
var n=draw(people);
var k1=people[0].id,k2=people[1].id,k3=people[2].id;
if(n[k1].style["--batch"]!==batchColor(pal[0]))
  bad("the figure does not wear its launch colour: "+asc(n[k1].style["--batch"]));
if(n[k1].style["--batch"]!==n[k2].style["--batch"])
  bad("two figures of one launch wear different colours");
if(n[k1].style["--batch"]===n[k3].style["--batch"])
  bad("a different launch wears the same colour");
if(!n[k1+".1"])bad("place() drew no subagent figure");
if(n[k1+".1"].style["--batch"]!==n[k1].style["--batch"])
  bad("a subagent does not wear its parent's launch colour: "+asc(n[k1+".1"].style["--batch"]));
// 11. a hostile group_key is a palette lookup, never markup
var hostile=map([{session_id:"h1",group_key:"<img src=x onerror=alert(1)>"}]);
var hn=draw(hostile)[hostile[0].id];
if(PALETTE.indexOf(hn.style["--batch"])<0)
  bad("a hostile group_key reached the figure as a colour: "+asc(hn.style["--batch"]));
if(/onerror|src=x/i.test(hn.innerHTML))
  bad("a hostile group_key reached the figure as live markup");
// 12. the figure the ordinal keys is reused across polls, not rebuilt for a new session
for(var k0 in nodes)delete nodes[k0];
for(var b0 in seatUse)delete seatUse[b0];
var poll1=map([{session_id:"r1",agent_idx:1},{session_id:"r2",agent_idx:0}]);
poll1.forEach(function(a){place(a,false,{},{});});
var keptNode=nodes["A2"];
for(var b1 in seatUse)delete seatUse[b1];
var poll2=map([{session_id:"r1",agent_idx:1}]);
if(poll2[0].id!=="A2")bad("the surviving session lost its ordinal when the other left: "+asc(poll2[0].id));
poll2.forEach(function(a){place(a,false,{},{});});
if(nodes["A2"]!==keptNode)bad("the surviving session's figure was rebuilt instead of reused");
console.log("OK");
"""


def office2_identity_js_problem(text, palette):
    """Run mapStatus + place + personEl DOM-free and assert the display ordinal is the
    backend's agent_idx (stable across sessions joining/leaving, unique, fallback-safe),
    that the subagent ids hang off it, and that the launch batch is carried off
    r.group_key and drawn with the dashboard's own palette. Returns a problem string
    (folded into the single check-office2-identity-stable record) or None when green."""
    node = shutil.which("node")
    if not node:
        return "node is required for the identity fixture"
    parts = {
        "__PALETTE__": "var PALETTE=%s;" % json.dumps(palette),
        "__ESC__": extract_js_function(text, "function esc(s){"),
        "__OS_ICON__": extract_js_function(text, "function osIcon(a){"),
        "__CTX_BADGE__": extract_js_function(text, "function ctxBadge(p){"),
        "__STALE_BADGE__": office2_stale_badge_js(text),
        "__HOOK_PM__": office2_hook_pm_js(text),
        "__SUBS_BADGE__": office2_subs_badge_js(text),
        "__MACH_BADGE__": office2_mach_badge_js(text),
        "__PERSON_EL__": office2_person_el_js(text),
        "__MAP_STATUS__": office2_map_status_js(text),
        "__ZONE_OF__": extract_js_function(text, "function zoneOf(r){"),
        "__ST_OF__": extract_js_function(text, "function stOf(s){"),
        "__SUB_ST__": extract_js_function(text, "function subSt(s){"),
        "__SUB_VEND__": extract_js_function(text, "function subVend(v){"),
        "__STANDBY_WAIT__": extract_js_function(text, "function standbyWait(r){"),
        "__STANDBY_GROUP__": extract_js_function(text, "function standbyGroup(a){"),
        "__HASH_INT__": extract_js_function(text, "function hashInt(s){"),
        "__SEAT_BAND_FN__": extract_js_function(text, "function seatBand(zoneKey, grp){"),
        "__STALL_BOX__": extract_js_function(text, "function stallBox(k){"),
        "__SEAT_GRID__": extract_js_function(text, "function seatGrid(zoneKey, grp, n, kmax){"),
        "__SEAT_XY__": extract_js_function(text, "function seatXY(zoneKey, idx, grp, n, kmax){"),
        "__SUB_XY__": extract_js_function(text, "function subXY(seat, i, k){"),
        "__PLACE__": extract_js_function(text, "function place(a, animate, tot, kmx){"),
    }
    for m, pat in (("__VEND__", r"const VEND\s*=\s*\{.*?\n\};"),
                   ("__STDOT__", r"const STDOT\s*=\s*\{.*?\};"),
                   ("__OSICON__", r"const OSICON\s*=\s*\{.*?\};"),
                   ("__CTXSTEP__", r"const CTXSTEP\s*=\s*\[.*?\];"),
                   ("__COUNCIL_PHASE__", r"const COUNCIL_PHASE\s*=\s*\{.*?\};"),
                   ("__WAIT_PHRASE__", r"const WAIT_PHRASE\s*=\s*\{.*?\};"),
                   ("__CLIVEND__", r"const CLIVEND\s*=\s*\{.*?\};"),
                   ("__ST_KNOWN__", r"const ST_KNOWN\s*=\s*\[.*?\];"),
                   ("__ZONES__", r"const ZONES\s*=\s*\[.*?\];"),
                   ("__SEAT__", r"const SEAT\s*=\s*\{.*?\};"),
                   ("__SUB__", r"const SUB\s*=\s*\{.*?\};"),
                   ("__SUB_DROP__", r"const SUB_DROP\s*=[^;]+;"),
                   ("__SEAT_BAND__", r"const SEAT_BAND\s*=\s*\{.*?\};")):
        hit = re.search(pat, text, re.S)
        parts[m] = hit.group(0) if hit else None
    missing = [k for k, v in parts.items() if not v]
    if missing:
        return "not found in ui/office_proto.html: " + ", ".join(sorted(missing))
    src = OFFICE2_IDENTITY_DRIVER
    for k, v in parts.items():
        src = src.replace(k, v)
    fd, tmp = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(src)
        proc = subprocess.run([node, tmp], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    finally:
        os.unlink(tmp)
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode == 0 and out.splitlines()[-1:] == ["OK"]:
        return None
    return "identity fixture: " + (out.splitlines()[-1] if out
                                   else "harness exit %d" % proc.returncode)


def cmd_check_office2_identity_stable():
    """Who this is, and who it was launched with. monitor.py puts `agent_idx` (which agent
    of its launch a row is) and `group_key` (which launch) on every session row, and
    ui/dashboard.html reads both -- signalDeskOrdinals turns agent_idx into the A# it
    shows, batchColor turns group_key into the desk's colour. office2 read neither: it
    numbered figures by their position in the current poll, so one session joining or
    leaving renumbered everybody, and because that number is also office2's node key the
    renumber handed a drawn figure to a different session; the launch grouping was lost
    outright. office2 must take the ordinal from agent_idx and colour the figure by
    group_key with the dashboard's OWN palette."""
    name = "check-office2-identity-stable"
    if not os.path.exists(OFFICE_PROTO):
        record("SKIP", name, "ui/office_proto.html absent")
        return True
    text, dash = read_text(OFFICE_PROTO), read_text(DASHBOARD)
    problems = []
    emitted = office2_identity_emitters()
    for field in ("agent_idx", "group_key"):
        if field not in emitted:
            problems.append("monitor.py no longer assigns row[%r] -- this check's premise "
                            "(the backend says which agent of which launch a row is) is "
                            "stale" % field)
    if "groupKey:String(r.group_key||r.session_id)" not in dash:
        problems.append("ui/dashboard.html no longer derives its groupKey from "
                        "r.group_key||r.session_id -- office2 mirrors that fallback and this "
                        "check has no reference derivation left")
    if not re.search(r"r\.parentOrdinal\s*=\s*r\.agentIdx\s*\+\s*1", dash):
        problems.append("ui/dashboard.html's signalDeskOrdinals no longer turns agentIdx "
                        "into agentIdx+1 -- office2 mirrors that ordinal")
    palette = office2_batch_palette()
    if not palette:
        problems.append("ui/dashboard.html's BATCH_PALETTE is gone -- office2 mirrors those "
                        "exact colours and this check has no reference palette left")
    else:
        mine = re.search(r"const BATCH_PALETTE\s*=\s*\[(.*?)\];", text, re.S)
        if not mine:
            problems.append("ui/office_proto.html defines no BATCH_PALETTE, so office2 has no "
                            "colour vocabulary for the launch batch at all")
        else:
            got = re.findall(r"#[0-9A-Fa-f]{6}", mine.group(1))
            if [c.upper() for c in got] != [c.upper() for c in palette]:
                problems.append("office2's BATCH_PALETTE %s drifted from the palette "
                                "ui/dashboard.html's batchColor uses %s -- office2 must reuse "
                                "the existing colours" % (got, palette))
    ordinals = extract_js_function(text, "function officeOrdinals(rows){")
    if not ordinals:
        problems.append("ui/office_proto.html defines no officeOrdinals(rows), so the display "
                        "ordinal is still whatever the current poll happened to enumerate")
    elif "r.agent_idx" not in ordinals:
        problems.append("officeOrdinals never reads r.agent_idx, so the ordinal is not the "
                        "one the backend already assigned")
    mapper = extract_js_function(text, "function mapStatus(d){")
    if not mapper:
        problems.append("mapStatus(d) not found in ui/office_proto.html")
    else:
        if "officeOrdinals(" not in mapper:
            problems.append("mapStatus never runs the ordinal pass over the poll, so a "
                            "session joining or leaving still renumbers everybody")
        if "r.group_key" not in mapper:
            problems.append("mapStatus never reads r.group_key, so office2 still cannot say "
                            "which sessions were launched together")
    placer = extract_js_function(text, "function place(a, animate, tot, kmx){")
    if not placer:
        problems.append("place(a, animate, tot, kmx) not found in ui/office_proto.html")
    elif "batch:a.batch" not in placer:
        problems.append("place() builds its subagent figures without the parent's batch, so "
                        "a subagent would not wear the launch colour of the session it "
                        "belongs to")
    if not re.search(r"\.bglow\{[^}]*var\(--batch", text):
        problems.append("no .bglow rule painted with var(--batch) in ui/office_proto.html -- "
                        "the launch colour would reach no pixels (ui/dashboard.html draws it "
                        "as .floorglow{fill:var(--batch)})")
    if not problems:
        js = office2_identity_js_problem(text, palette)
        if js:
            problems.append(js)
    if problems:
        record("FAIL", name, "; ".join(problems))
        return False
    record("PASS", name, "office2's A# is the backend's agent_idx+1 -- it survives sessions "
           "joining and leaving, never collides (duplicate/absent/unusable agent_idx all "
           "fall back to a free number), and the subagent ids hang off it; the launch batch "
           "comes off r.group_key with ui/dashboard.html's own session fallback and is drawn "
           "on the figure (subagents included) in the dashboard's own %d-colour palette, "
           "which a hostile key cannot escape" % len(palette))
    return True


# ------------------------------------------------ office2 remaining row badges
#
# ui/dashboard.html's rowsTbl has always drawn four more session-row signals that
# office2 read none of: which project a session is in (drawn ONLY when the project
# name is not already the label), which model it is on, how many tasks it still has
# open (`tasks` -- a DIFFERENT backend field from the task_total progress office2
# already shows on the figure), and how long ago it last moved (ago(ts), with the raw
# ISO `last` on hover). The desk card adds one more: how long the current turn has
# been running (fmtMin(elapsed)). Every glyph, colour, time format and "when not to
# draw it" condition is parsed back out of the dashboard here -- office2 keeps one
# mirrored copy for rendering and this oracle is what makes that copy fail the moment
# it drifts (same anti-drift pattern as STALE_PHRASE / CTXSTEP / ROUTE_EVIDENCE).
_ROWB_PROJ_RE = re.compile(r"r\.project&&r\.project!==r\.label\?' <span "
                           r'style="background:(#[0-9a-fA-F]+);color:(#[0-9a-fA-F]+);'
                           r'[^"]*" title="project">(\S+) \'\+esc\(r\.project\)')
_ROWB_MODEL_RE = re.compile(r"r\.model\?' <span "
                            r'style="background:(#[0-9a-fA-F]+);color:(#[0-9a-fA-F]+);'
                            r'[^"]*" title="model">\'\+esc\(r\.model\)')
_ROWB_TASKS_RE = re.compile(r"r\.tasks\?' <span class=\"tbadge\" "
                            r'title="open tasks">(\S+)\'\+r\.tasks')
_ROWB_TBADGE_RE = re.compile(r"\.tbadge\{background:(#[0-9a-fA-F]+);color:(#[0-9a-fA-F]+)")
_ROWB_AGE_RE = re.compile(r"class=\"sub\" title=\"'\+esc\(r\.last\)\+'\">'\+ago\(r\.ts\)")
_ROWB_SUBCSS_RE = re.compile(r"\n\.sub\{color:(#[0-9a-fA-F]+)\}")
_ROWB_ELAPSED_RE = re.compile(r"<span>(\S+) <b>'\+fmtMin\(r\.elapsed\)")


def office2_row_badge_vocab():
    """Derive the four remaining row signals from ui/dashboard.html itself: the project
    badge (its glyph, its colours and the fact that it is drawn only when the project
    name differs from the label), the model badge, the open-task badge (glyph + the
    .tbadge colours it borrows), the last-activity cell (ago(ts) shown, esc(r.last) on
    hover, in the .sub grey) and the desk card's elapsed glyph + fmtMin format. Returns
    a dict, or (None, problem) style None when any of them can no longer be found --
    never a re-hardcoded copy."""
    if not os.path.exists(DASHBOARD):
        return None
    dash = read_text(DASHBOARD)
    proj = _ROWB_PROJ_RE.search(dash)
    model = _ROWB_MODEL_RE.search(dash)
    tasks = _ROWB_TASKS_RE.search(dash)
    tbadge = _ROWB_TBADGE_RE.search(dash)
    subcss = _ROWB_SUBCSS_RE.search(dash)
    elapsed = _ROWB_ELAPSED_RE.search(dash)
    ago = extract_js_function(dash, "function ago(ts){")
    fmt = extract_js_function(dash, "function fmtMin(sec){")
    if not (proj and model and tasks and tbadge and subcss and elapsed and ago and fmt
            and _ROWB_AGE_RE.search(dash)):
        return None
    return {"proj_bg": proj.group(1), "proj_fg": proj.group(2), "proj_glyph": proj.group(3),
            "model_bg": model.group(1), "model_fg": model.group(2),
            "tasks_glyph": tasks.group(1),
            "tasks_bg": tbadge.group(1), "tasks_fg": tbadge.group(2),
            "age_fg": subcss.group(1), "elapsed_glyph": elapsed.group(1),
            "ago": ago, "fmt": fmt}


def _squash(src):
    """Whitespace-free form of a JS source, so a mirrored copy can be compared to the
    dashboard's original without depending on how either one is wrapped."""
    return re.sub(r"\s+", "", src or "")


OFFICE2_ROW_BADGE_DRIVER = r"""
function asc(s){return String(s).replace(/[^\x20-\x7e一-鿿]/g,"?");}
function bad(m){console.log("FAIL: "+asc(m));process.exit(1);}
// fixture stubs -- personEl/place reach createElement, style, classList, appendChild and
// the one querySelector office2 uses to re-stamp the age badge on a figure it reuses
var CREATURES=[{key:"c0",img:"a.png"},{key:"c1",img:"b.png"}];
function mkEl(){return {className:"",innerHTML:"",title:"",
  style:{left:"",top:"",setProperty:function(k,v){this[k]=v;}},
  classList:{add:function(){},remove:function(){},toggle:function(){}},
  appendChild:function(){},
  querySelector:function(s){if(s!==".ageb")return null;
    if(!this._age)this._age={textContent:"",title:""};return this._age;},
  remove:function(){this.gone=true;}};}
var document={createElement:function(){return mkEl();}};
var floor={appendChild:function(){}};
var seatUse={}, seatOver={}, nodes={};
globalThis.innerWidth=1440;globalThis.innerHeight=900;
__ROW_BADGE_CASES__
__VEND__
__STDOT__
__OSICON__
__CTXSTEP__
__COUNCIL_PHASE__
__WAIT_PHRASE__
__CLIVEND__
__ST_KNOWN__
__ZONES__
__SEAT__
__SUB__
__SUB_DROP__
__SEAT_BAND__
__ESC__
__HASH_INT__
__OS_ICON__
__MACH_BADGE__
__CTX_BADGE__
__STALE_BADGE__
__HOOK_PM__
__SUBS_BADGE__
__PERSON_EL__
__ZONE_OF__
__ST_OF__
__SUB_ST__
__SUB_VEND__
__STANDBY_WAIT__
__STANDBY_GROUP__
__MAP_STATUS__
__SEAT_BAND_FN__
__STALL_BOX__
__SEAT_GRID__
__SEAT_XY__
__SUB_XY__
__PLACE__
function one(row){row.status=row.status||"running";row.work_kind=row.work_kind||"working";
  var m=mapStatus({claude:[row]});
  if(m.length!==1)bad("mapStatus returned "+m.length+" people for "+asc(row.session_id));
  return m[0];}
// the nameplate is the first <div> of the figure -- the badges all live in it
function plate(a,mini){var h=String(personEl(a,!!mini).innerHTML);
  var i=h.indexOf("</div>");return i<0?h:h.slice(0,i);}
function draw(a){for(var k in nodes)delete nodes[k];for(var b in seatUse)delete seatUse[b];
  place(a,false,{},{});return nodes[a.id];}
function now(){return Date.now()/1000;}
// 1. the four fields reach the person model at all
var full=one({session_id:"s1",label:"L",project:"proj-x",model:"opus-5",tasks:3,
              ts:now()-90.5,last:"2026-07-27T10:00:00+08:00",elapsed:120});
[["project","proj-x"],["model","opus-5"],["tasks",3],
 ["last","2026-07-27T10:00:00+08:00"],["elapsed",120]].forEach(function(p){
  if(full[p[0]]!==p[1])bad("mapStatus drops r."+p[0]+": "+asc(full[p[0]]));});
if(typeof full.ts!=="number")bad("mapStatus drops r.ts, so office2 cannot age the row");
// 2. project: drawn with the dashboard's glyph, and NOT drawn when it is the label
var hp=plate(full);
if(hp.indexOf(PROJ_G)<0||hp.indexOf("proj-x")<0)
  bad("no project badge on the nameplate: "+asc(hp));
if(plate(one({session_id:"s2",label:"same",project:"same"})).indexOf(PROJ_G)>=0)
  bad("the project badge is drawn even though the project name IS the label -- the "+
      "dashboard draws it only when the two differ");
[undefined,null,"",7,{},[]].forEach(function(v){
  if(plate(one({session_id:"s3",label:"L",project:v})).indexOf(PROJ_G)>=0)
    bad("a row whose project is "+asc(v)+" still drew a project badge");});
var hx=plate(one({session_id:"s4",label:"L",project:"<img src=x onerror=alert(1)>"}));
if(hx.indexOf("<img")>=0)bad("a hostile project name reached the nameplate as live markup");
if(hx.indexOf("&lt;img")<0)bad("the project name is not escaped the way the label is");
// 3. model
var hm=plate(one({session_id:"m1",label:"L",model:"claude-x"}));
if(hm.indexOf("claude-x")<0||hm.indexOf('class="modelb"')<0)
  bad("no model badge on the nameplate: "+asc(hm));
[undefined,null,"",7,{},[]].forEach(function(v){
  if(plate(one({session_id:"m2",label:"L",model:v})).indexOf('class="modelb"')>=0)
    bad("a row whose model is "+asc(v)+" still drew a model badge");});
var hmx=plate(one({session_id:"m3",label:"L",model:"<img src=x onerror=alert(1)>"}));
if(hmx.indexOf("<img")>=0)bad("a hostile model name reached the nameplate as live markup");
// 4. open tasks: the dashboard's own glyph, and NOT the task_total progress field
var ht=plate(one({session_id:"t1",label:"L",tasks:3}));
if(ht.indexOf(TASKS_G+"3")<0)
  bad("the open-task count is not drawn with the dashboard's own glyph: "+asc(ht));
var prog=one({session_id:"t2",label:"L",task_total:9,task_done:2,task_index:3});
if(plate(prog).indexOf(TASKS_G)>=0)
  bad("a row carrying only task_total drew an open-task badge -- task_total is the "+
      "progress through this run, `tasks` is the open-task count, and they are "+
      "different backend fields");
if(plate(prog).indexOf('class="tprog"')<0)
  bad("the task progress office2 already drew is gone");
var only=one({session_id:"t3",label:"L",tasks:2});
if(only.task!==null)bad("`tasks` was turned into a task-progress object");
if(plate(only).indexOf('class="tprog"')>=0)
  bad("`tasks` was drawn as the task progress -- the two fields were conflated");
[0,-1,undefined,null,"3",NaN,{},[],true].forEach(function(v){
  if(plate(one({session_id:"t4",label:"L",tasks:v})).indexOf(TASKS_G)>=0)
    bad("a row whose tasks is "+asc(v)+" still drew an open-task badge");});
// 5. age: the dashboard's own four scales, and silence when there is no usable ts
[[30.5,"30s"],[90.5,"1m"],[7200.5,"2h"],[172800.5,"2d"]].forEach(function(c){
  var h=plate(one({session_id:"g"+c[0],label:"L",ts:now()-c[0]}));
  if(h.indexOf(">"+c[1]+"<")<0)
    bad("a row last seen "+c[0]+"s ago is not shown as "+c[1]+": "+asc(h));});
[undefined,null,0,"123",{},[],-1,NaN].forEach(function(v){
  var h=plate(one({session_id:"g0",label:"L",ts:v}));
  if(!/class="ageb" title="[^"]*"><\/span>/.test(h))
    bad("a row with no usable ts must draw no age text at all, got "+asc(h));});
// 6. the raw backend timestamp is the hover text, exactly as in the dashboard's cell
var hl=plate(one({session_id:"l1",label:"L",ts:now()-90.5,
                  last:"2026-07-27T10:00:00+08:00"}));
if(hl.indexOf('title="2026-07-27T10:00:00+08:00"')<0)
  bad("the raw timestamp is not the age badge's hover text: "+asc(hl));
var hlx=plate(one({session_id:"l2",label:"L",ts:now()-90.5,
                   last:'"><img src=x onerror=alert(1)>'}));
if(hlx.indexOf("<img")>=0)
  bad("a hostile last-activity timestamp reached the nameplate as live markup");
if(hlx.indexOf("&quot;")<0)bad("the hover timestamp is not escaped");
// 7. the age is re-stamped on a figure reused across polls (it would otherwise freeze
//    at the moment the figure was created, and keep claiming the session just moved)
var node=draw(one({session_id:"r1",label:"L",ts:now()-90.5,last:"first"}));
if(!node)bad("place() drew no figure");
if(node._age.textContent!=="1m")
  bad("place() did not stamp the age on the figure: "+asc(node._age.textContent));
if(node._age.title!=="first")
  bad("place() did not stamp the raw timestamp: "+asc(node._age.title));
for(var b1 in seatUse)delete seatUse[b1];
var later=one({session_id:"r1",label:"L",ts:now()-7200.5,last:"second"});
place(later,false,{},{});
if(nodes[later.id]!==node)
  bad("the figure was rebuilt instead of reused -- the re-stamp assertion is meaningless");
if(node._age.textContent!=="2h")
  bad("a figure reused across polls keeps the age it was created with: "+
      asc(node._age.textContent));
if(node._age.title!=="second")
  bad("the raw timestamp was not refreshed on the reused figure");
// 8. how long this turn has been running, in the dashboard's own format, on the tooltip
if(String(personEl(one({session_id:"e1",label:"L",elapsed:120}),false).title)
   .indexOf(ELAPSED_G+" 2m")<0)
  bad("the turn's running time is not on the figure's tooltip: "+
      asc(personEl(one({session_id:"e1",label:"L",elapsed:120}),false).title));
[undefined,null,"120",NaN,{},[],-1].forEach(function(v){
  var t=String(personEl(one({session_id:"e2",label:"L",elapsed:v}),false).title);
  if(t.indexOf(ELAPSED_G)>=0)
    bad("a row whose elapsed is "+asc(v)+" still showed a running time");
  if(t.indexOf("—")>=0)
    bad("the dashboard's table placeholder leaked onto a figure with no running time");});
var n2=draw(one({session_id:"q1",label:"L",elapsed:60}));
if(String(n2.title).indexOf(ELAPSED_G+" 1m")<0)
  bad("place() did not stamp the running time on the figure: "+asc(n2.title));
for(var b2 in seatUse)delete seatUse[b2];
place(one({session_id:"q1",label:"L",elapsed:7200}),false,{},{});
if(String(n2.title).indexOf(ELAPSED_G+" 2h0m")<0)
  bad("a figure reused across polls keeps the running time it was created with: "+
      asc(n2.title));
// 9. a subagent has no project, model, todo list or last-activity time of its own
var mp=plate({id:"A1.1",vend:"cc",cre:0,st:"working",project:"proj-x",model:"opus-5",
              tasks:4,ts:now()-90.5,last:"iso"},true);
['class="projb"','class="modelb"','class="tasksb"','class="ageb"'].forEach(function(c){
  if(mp.indexOf(c)>=0)
    bad("a subagent figure carries "+c+", but the backend gives it none of those");});
console.log("OK");
"""


def office2_row_badge_js_problem(text, vocab):
    """Run mapStatus + personEl + place DOM-free and assert office2 draws the dashboard's
    four remaining row signals with its glyphs and its skip conditions -- project only when
    it is not the label, the open-task count never confused with the task_total progress,
    the age in the dashboard's own scales with the raw timestamp on hover and re-stamped on
    a reused figure, and the turn's running time on the tooltip. Returns a problem string
    (folded into the single check-office2-row-badges record) or None when green."""
    node = shutil.which("node")
    if not node:
        return "node is required for the row-badge fixture"
    cases = ("var PROJ_G=%s;var TASKS_G=%s;var ELAPSED_G=%s;"
             % (json.dumps(vocab["proj_glyph"]), json.dumps(vocab["tasks_glyph"]),
                json.dumps(vocab["elapsed_glyph"])))
    parts = {
        "__ROW_BADGE_CASES__": cases,
        "__ESC__": extract_js_function(text, "function esc(s){"),
        "__OS_ICON__": extract_js_function(text, "function osIcon(a){"),
        "__CTX_BADGE__": extract_js_function(text, "function ctxBadge(p){"),
        "__STALE_BADGE__": office2_stale_badge_js(text),
        "__HOOK_PM__": office2_hook_pm_js(text),
        "__SUBS_BADGE__": office2_subs_badge_js(text),
        "__MACH_BADGE__": office2_mach_badge_js(text),
        "__PERSON_EL__": office2_person_el_js(text),
        "__MAP_STATUS__": office2_map_status_js(text),
        "__ZONE_OF__": extract_js_function(text, "function zoneOf(r){"),
        "__ST_OF__": extract_js_function(text, "function stOf(s){"),
        "__SUB_ST__": extract_js_function(text, "function subSt(s){"),
        "__SUB_VEND__": extract_js_function(text, "function subVend(v){"),
        "__STANDBY_WAIT__": extract_js_function(text, "function standbyWait(r){"),
        "__STANDBY_GROUP__": extract_js_function(text, "function standbyGroup(a){"),
        "__HASH_INT__": extract_js_function(text, "function hashInt(s){"),
        "__SEAT_BAND_FN__": extract_js_function(text, "function seatBand(zoneKey, grp){"),
        "__STALL_BOX__": extract_js_function(text, "function stallBox(k){"),
        "__SEAT_GRID__": extract_js_function(text, "function seatGrid(zoneKey, grp, n, kmax){"),
        "__SEAT_XY__": extract_js_function(text, "function seatXY(zoneKey, idx, grp, n, kmax){"),
        "__SUB_XY__": extract_js_function(text, "function subXY(seat, i, k){"),
        "__PLACE__": extract_js_function(text, "function place(a, animate, tot, kmx){"),
    }
    for m, pat in (("__VEND__", r"const VEND\s*=\s*\{.*?\n\};"),
                   ("__STDOT__", r"const STDOT\s*=\s*\{.*?\};"),
                   ("__OSICON__", r"const OSICON\s*=\s*\{.*?\};"),
                   ("__CTXSTEP__", r"const CTXSTEP\s*=\s*\[.*?\];"),
                   ("__COUNCIL_PHASE__", r"const COUNCIL_PHASE\s*=\s*\{.*?\};"),
                   ("__WAIT_PHRASE__", r"const WAIT_PHRASE\s*=\s*\{.*?\};"),
                   ("__CLIVEND__", r"const CLIVEND\s*=\s*\{.*?\};"),
                   ("__ST_KNOWN__", r"const ST_KNOWN\s*=\s*\[.*?\];"),
                   ("__ZONES__", r"const ZONES\s*=\s*\[.*?\];"),
                   ("__SEAT__", r"const SEAT\s*=\s*\{.*?\};"),
                   ("__SUB__", r"const SUB\s*=\s*\{.*?\};"),
                   ("__SUB_DROP__", r"const SUB_DROP\s*=[^;]+;"),
                   ("__SEAT_BAND__", r"const SEAT_BAND\s*=\s*\{.*?\};")):
        hit = re.search(pat, text, re.S)
        parts[m] = hit.group(0) if hit else None
    missing = [k for k, v in parts.items() if not v]
    if missing:
        return "not found in ui/office_proto.html: " + ", ".join(sorted(missing))
    src = OFFICE2_ROW_BADGE_DRIVER
    for k, v in parts.items():
        src = src.replace(k, v)
    fd, tmp = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(src)
        proc = subprocess.run([node, tmp], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    finally:
        os.unlink(tmp)
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode == 0 and out.splitlines()[-1:] == ["OK"]:
        return None
    return "row-badge fixture: " + (out.splitlines()[-1] if out
                                    else "harness exit %d" % proc.returncode)


def cmd_check_office2_row_badges():
    """The last four signals ui/dashboard.html draws on a session row and office2 did not:
    the project a session is in, the model it runs on, how many tasks it still has open,
    and how long ago it last moved (plus how long the current turn has been running). Each
    one is a field monitor.py has always emitted; office2 simply never read them, so a
    figure said nothing about which repo it was in, which model was burning the context, or
    whether it had been standing still for three hours. office2 must draw them in the
    dashboard's own glyphs, colours and skip conditions -- the project only when it is not
    already the label, the open-task count kept apart from the task_total progress it
    already shows, and the age re-stamped on every poll instead of freezing at the moment
    the figure was drawn."""
    name = "check-office2-row-badges"
    if not os.path.exists(OFFICE_PROTO):
        record("SKIP", name, "ui/office_proto.html absent")
        return True
    text = read_text(OFFICE_PROTO)
    problems = []
    mon = read_text(MONITOR)
    for field in ("model", "project", "tasks", "ts", "last", "elapsed"):
        if '"%s":' % field not in mon and '"%s"]' % field not in mon:
            problems.append("monitor.py no longer emits `%s` on session rows -- this check's "
                            "premise (the backend already has the signal) is stale" % field)
    vocab = office2_row_badge_vocab()
    if not vocab:
        problems.append("could not derive the project/model/open-task/age vocabulary from "
                        "ui/dashboard.html's rowsTbl (glyphs, colours, the "
                        "project!==label condition, ago(ts) with esc(r.last) on hover) and "
                        "fmtMin(r.elapsed) from its desk card -- they must be parsed from "
                        "the dashboard, never re-hardcoded in this checker")
    else:
        for fn, want in (("function ago(ts){", vocab["ago"]),
                         ("function fmtMin(sec){", vocab["fmt"])):
            mine = extract_js_function(text, fn)
            if not mine:
                problems.append("ui/office_proto.html defines no %s, so office2 has no time "
                                "format for the row's age at all" % fn[9:fn.index("{")])
            elif _squash(mine) != _squash(want):
                problems.append("office2's %s drifted from ui/dashboard.html's own copy -- "
                                "the same seconds would read as two different ages on the two "
                                "screens" % fn[9:fn.index("{")])
        for const, key in (("PROJ_GLYPH", "proj_glyph"), ("TASKS_GLYPH", "tasks_glyph"),
                           ("ELAPSED_GLYPH", "elapsed_glyph")):
            hit = re.search(r"%s\s*=\s*'([^']*)'" % const, text)
            if not hit:
                problems.append("ui/office_proto.html defines no %s" % const)
            elif hit.group(1) != vocab[key]:
                problems.append("office2's %s drifted from the glyph ui/dashboard.html draws "
                                "for that signal" % const)
        for cls, tints in (("projb", (vocab["proj_bg"], vocab["proj_fg"])),
                           ("modelb", (vocab["model_bg"], vocab["model_fg"])),
                           ("tasksb", (vocab["tasks_bg"], vocab["tasks_fg"])),
                           ("ageb", (vocab["age_fg"],))):
            rule = re.search(r"\.%s\s*\{([^}]*)\}" % cls, text)
            if not rule:
                problems.append("no .%s rule in ui/office_proto.html -- the badge would "
                                "render unstyled" % cls)
            else:
                for tint in tints:
                    if tint not in rule.group(1):
                        problems.append("the .%s badge does not use ui/dashboard.html's own "
                                        "%s for that signal" % (cls, tint))
    mapper = extract_js_function(text, "function mapStatus(d){")
    if not mapper:
        problems.append("mapStatus(d) not found in ui/office_proto.html")
    else:
        for field in ("project", "model", "tasks", "ts", "last", "elapsed"):
            if not re.search(r"r\.%s(?![\w$])" % field, mapper):
                problems.append("mapStatus never reads r.%s, so the signal never reaches a "
                                "figure" % field)
    person = extract_js_function(text, "function personEl(a, mini){")
    if not person:
        problems.append("personEl(a, mini) not found in ui/office_proto.html")
    else:
        for call in ("projBadge(", "modelBadge(", "tasksBadge(", "ageBadge("):
            if call not in person:
                problems.append("personEl never draws %s), so that signal reaches no pixels"
                                % call)
    tip = extract_js_function(text, "function personTip(a){")
    if not tip:
        problems.append("personTip(a) not found in ui/office_proto.html")
    elif "elapsedText(" not in tip:
        problems.append("personTip never shows elapsedText(), so office2 still cannot say "
                        "how long the current turn has been running")
    placer = extract_js_function(text, "function place(a, animate, tot, kmx){")
    if not placer:
        problems.append("place(a, animate, tot, kmx) not found in ui/office_proto.html")
    elif ".ageb" not in placer or "ago(a.ts)" not in placer:
        problems.append("place() never re-stamps the age on a figure it reuses across polls, "
                        "so the badge would freeze at the moment the figure was drawn and go "
                        "on claiming the session just moved")
    if not problems:
        js = office2_row_badge_js_problem(text, vocab)
        if js:
            problems.append(js)
    if problems:
        record("FAIL", name, "; ".join(problems))
        return False
    # the glyphs themselves are deliberately not printed: this line goes to a cp950 console
    record("PASS", name, "office2 draws the four row signals ui/dashboard.html has always "
           "drawn -- project (only when it is not already the label), model, open tasks "
           "(the `tasks` field, kept apart from the task_total progress) and last activity "
           "in the dashboard's own glyphs, colours and s/m/h/d scale with the raw timestamp "
           "on hover -- plus the turn's running time in the dashboard's own fmtMin; missing, "
           "zero, non-numeric and hostile values draw nothing rather than a fake or live "
           "markup, subagents claim none of the five, and a figure reused across polls has "
           "its age and running time re-stamped")
    return True


# ------------------------------------------------- office2 field-parity ledger
#
# Every key below is a session-row field that ui/dashboard.html draws but
# ui/office_proto.html does not read, together with the reason it is allowed to
# stay missing. Two kinds of reason:
#   * "pending:<task title>" -- a debt owed by that task of
#     _handoff/plans/plan_office2-parity_2026-07-27.md. The task that fixes the
#     field deletes its own rows here; the plan is only complete when no
#     "pending:" reason is left.
#   * anything else -- a permanent, written exemption: office2 already carries
#     the signal by another route, so the missing r.<field> read is not a gap.
OFFICE2_PARITY_EXEMPT = {
    "src": "vendor identity, not a lost signal: office2 takes the vendor from the "
           "/api/status bucket it is iterating (mapStatus b[1], ui/office_proto.html) "
           "instead of reading it off the row",
    "vendor": "vendor identity, not a lost signal: same bucket-key derivation as src",
}

# Functions whose `r` is a raw /api/status session row.
OFFICE2_PARITY_RAW_FNS = ("function rowsTbl(rows,src){",
                          "function renderAlert(d){",
                          "function officeRows(d){")
# Functions whose `r` is an officeRows() output object -- their reads are resolved
# back to raw field names through officeRows' own out.push({...}) mapping.
OFFICE2_PARITY_MAPPED_FNS = ("function updateDesk(el,r){",
                             "function paintSignalInspector(rows){")

# r.<field>, excluding method calls (r.json() is a fetch response, not a row field).
_ROW_FIELD_RE = re.compile(r"\br\.([A-Za-z_$][\w$]*)(?![\w$])(?!\s*\()")
# Anti-bypass: either of these hides the real field set from a static r.<field> scan.
_ROW_DESTRUCTURE_RE = re.compile(r"(?:const|let|var)\s*\{[^{}]*\}\s*=\s*r(?![\w$])")
_ROW_DYNAMIC_RE = re.compile(r"\br\[")


def office2_row_fields(src):
    """Field names read as r.<field> in `src`."""
    return set(_ROW_FIELD_RE.findall(src))


def office2_row_alias_map(office_rows_src):
    """officeRows()'s out.push({outName: ...r.raw...}) is dashboard's own mapping
    layer. Returns {outName: {raw field names}} so that reads in updateDesk() and
    paintSignalInspector() can be compared on the same raw vocabulary office2 uses.
    Returns None when the object literal cannot be located."""
    i = office_rows_src.find("out.push({")
    if i < 0:
        return None
    start = office_rows_src.index("{", i)
    depth, end = 0, -1
    for j in range(start, len(office_rows_src)):
        if office_rows_src[j] in "([{":
            depth += 1
        elif office_rows_src[j] in ")]}":
            depth -= 1
            if depth == 0:
                end = j
                break
    if end < 0:
        return None
    alias, cur, depth = {}, "", 0
    for ch in office_rows_src[start + 1:end] + ",":
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            part = cur.strip()
            if ":" in part:
                k, v = part.split(":", 1)
                alias[k.strip()] = office2_row_fields(v)
            elif part:  # shorthand {label} -- out name is the raw name
                alias[part] = {part}
            cur = ""
        else:
            cur += ch
    return alias


def cmd_check_office2_field_parity():
    """Permanent field-parity oracle (owner: '原本有的訊號都要在'). Statically
    diffs the session-row fields ui/dashboard.html draws against the ones
    ui/office_proto.html reads, so a missing signal is *scanned for* instead of
    being stumbled on -- the previous two gaps (OS/machine, linux) were both found
    by accident. Anything in the difference that is not written down in
    OFFICE2_PARITY_EXEMPT is a FAIL."""
    name = "check-office2-field-parity"
    if not (os.path.exists(DASHBOARD) and os.path.exists(OFFICE_PROTO)):
        record("SKIP", name, "ui/dashboard.html or ui/office_proto.html absent")
        return True
    dash, off = read_text(DASHBOARD), read_text(OFFICE_PROTO)
    problems, scanned, regions = [], [("ui/office_proto.html", off)], {}
    for anchor in OFFICE2_PARITY_RAW_FNS + OFFICE2_PARITY_MAPPED_FNS:
        fn = anchor[len("function "):anchor.index("(")]
        src = extract_js_function(dash, anchor)
        if src is None:
            problems.append("%s() not found in ui/dashboard.html -- the parity scan can no "
                            "longer see what the dashboard draws" % fn)
        else:
            regions[anchor] = src
            scanned.append(("ui/dashboard.html %s()" % fn, src))
    # Anti-bypass: a static r.<field> scan is blind to destructuring and to
    # computed access, so either one is a hard FAIL rather than a silent hole.
    for label, src in scanned:
        if _ROW_DESTRUCTURE_RE.search(src):
            problems.append("%s destructures the row (const {..}=r) -- the parity scan reads "
                            "r.<field> and would silently miss every destructured field"
                            % label)
        if _ROW_DYNAMIC_RE.search(src):
            problems.append("%s reads the row with computed access (r[..]) -- the parity scan "
                            "cannot resolve the field name, so the gap would go unseen" % label)
    if problems:
        record("FAIL", name, "; ".join(problems))
        return False
    raw = set()
    for anchor in OFFICE2_PARITY_RAW_FNS:
        raw |= office2_row_fields(regions[anchor])
    alias = office2_row_alias_map(regions["function officeRows(d){"])
    if alias is None:
        record("FAIL", name, "officeRows() no longer builds its rows with out.push({...}) -- "
                             "the mapped-name reads in updateDesk()/paintSignalInspector() "
                             "can no longer be resolved back to raw row fields")
        return False
    drawn = set(raw)
    for anchor in OFFICE2_PARITY_MAPPED_FNS:
        for field in office2_row_fields(regions[anchor]):
            if field in raw:
                drawn.add(field)
            elif field in alias:
                drawn |= alias[field]
            # else: computed inside dashboard (e.g. parentOrdinal), not a row field
    missing = sorted(drawn - office2_row_fields(off))
    gaps = [f for f in missing if f not in OFFICE2_PARITY_EXEMPT]
    if gaps:
        record("FAIL", name, "ui/dashboard.html draws these session-row fields but "
               "ui/office_proto.html never reads them: %s -- either read them in office2 or "
               "add a written reason to OFFICE2_PARITY_EXEMPT" % ", ".join(gaps))
        return False
    pending = sorted(f for f in missing
                     if OFFICE2_PARITY_EXEMPT[f].startswith("pending:"))
    record("PASS", name, "%d row field(s) drawn by dashboard, %d not read by office2 and all "
           "of them written down in OFFICE2_PARITY_EXEMPT (%d still pending: %s); no "
           "destructuring or computed row access in either file"
           % (len(drawn), len(missing), len(pending), ", ".join(pending) or "none"))
    return True


def cmd_check_monitor_help_exits():
    """`python monitor.py --help` used to start a listening server. monitor.py had no argv
    handling at all -- every argument was silently ignored and the process bound the port
    anyway. On 2026-07-27 a stray `monitor.py --help` left over from three days earlier was
    found sitting on port 8787 alongside the real daemon, and CONTEXT.md records that a
    second bind on an occupied port can silently listen while only the first process really
    serves: the owner's dashboard may have been served by that old code for days. main()
    must answer -h/--help with a usage message and exit 0 BEFORE it loads config, starts a
    thread or binds a socket. The structural half of this check is what makes the
    behavioural half safe to run: only once the guard is proven to be the first thing main()
    does does this checker actually invoke --help (and even then with PORT=0, so a
    regression can never land on the production port)."""
    name = "check-monitor-help-exits"
    mon = read_text(MONITOR)
    problems = []
    try:
        tree = ast.parse(mon)
    except SyntaxError as e:
        record("FAIL", name, "monitor.py does not parse: %s" % e)
        return False
    if not any(isinstance(n, ast.Import) and any(a.name == "sys" for a in n.names)
               for n in tree.body):
        problems.append("monitor.py does not `import sys` at module level, so no argv "
                        "guard can work")
    fn = next((n for n in tree.body
               if isinstance(n, ast.FunctionDef) and n.name == "main"), None)
    if fn is None:
        problems.append("monitor.py defines no module-level main()")
    else:
        body = [s for s in fn.body
                if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
                        and isinstance(s.value.value, str))]
        guard = body[0] if body else None
        if not isinstance(guard, ast.If):
            problems.append("the first statement of main() is not an `if` -- the help "
                            "guard must run before anything else, or --help still binds "
                            "the port")
        else:
            src = ast.get_source_segment(mon, guard) or ""
            if "sys.argv" not in src:
                problems.append("main()'s first statement never looks at sys.argv")
            for flag in ('"-h"', "'-h'"), ('"--help"', "'--help'"):
                if not any(f in src for f in flag):
                    problems.append("the guard does not mention %s" % flag[0])
            exits_zero = any(
                isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == "exit"
                and isinstance(n.func.value, ast.Name) and n.func.value.id == "sys"
                and len(n.args) == 1 and isinstance(n.args[0], ast.Constant)
                and n.args[0].value == 0
                for n in ast.walk(guard))
            if not exits_zero:
                problems.append("the guard does not sys.exit(0) -- execution would fall "
                                "through into the server start-up")
            prints = any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                         and n.func.id == "print" for n in ast.walk(guard))
            if not prints:
                problems.append("the guard exits without printing any usage text")
        rest = ast.dump(ast.Module(body=body[1:], type_ignores=[])) if body else ""
        if "ThreadingHTTPServer" not in rest:
            problems.append("main() no longer starts a ThreadingHTTPServer after the "
                            "guard -- this check must not pass on a gutted main()")
    if problems:
        record("FAIL", name, "; ".join(problems))
        return False
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PORT="0")
    for flag in ("-h", "--help"):
        try:
            proc = subprocess.run([sys.executable, MONITOR, flag], cwd=ROOT,
                                  capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=60, env=env)
        except subprocess.TimeoutExpired:
            record("FAIL", name, "`monitor.py %s` did not exit within 60s -- it is serving, "
                                 "not printing help" % flag)
            return False
        out = proc.stdout or ""
        if proc.returncode != 0:
            record("FAIL", name, "`monitor.py %s` exited %d, expected 0"
                   % (flag, proc.returncode))
            return False
        if "usage" not in out.lower():
            record("FAIL", name, "`monitor.py %s` printed no usage line" % flag)
            return False
        if "http://" in out:
            record("FAIL", name, "`monitor.py %s` printed the serving banner -- it bound a "
                                 "port" % flag)
            return False
    record("PASS", name, "-h/--help print usage and exit 0 before any config load, thread "
           "start or socket bind")
    return True


CONFIG_DEPERSONALISED_DRIVER = r'''
import json, os, sys, tempfile, time, traceback
sys.path.insert(0, os.getcwd())
sys.path.insert(0, os.path.join(os.getcwd(), "tools"))
import monitor, hooks_audit
# The key list and both strip styles come from the tool the owner actually runs
# before publishing (tools/depersonalise.py). Keeping a second copy here would drift
# the first time a config key is added, and this gate would then quietly be checking
# less than its name claims -- the same duplicated-constant fault this session spent
# its afternoon removing from office_push.
import depersonalise

base = json.load(open(monitor.CONFIG_PATH, encoding="utf-8"))
emptied = depersonalise.strip(base, "blank")
removed = depersonalise.strip(base, "remove")


def fail(m):
    print("FAIL: " + m)
    sys.exit(1)


# collect_github_prs is deliberately NOT exercised here: it shells out to the network,
# and an offline or rate-limited machine must not turn this gate red. Its own
# no-cache / no-gh / disabled paths are covered where that collector is tested.
for scenario, data in (("values emptied", emptied), ("lines removed", removed)):
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    monitor.CONFIG_PATH = path
    monitor._PR_CACHE.update({"ts": 0.0, "data": None})
    monitor._KB_CACHE.update({"ts": 0.0, "data": None})
    try:
        cfg = monitor.load_config()
        for label, fn in (("build_status", monitor.build_status),
                          ("collect_handoff",
                           lambda: monitor.collect_handoff(cfg, time.time())),
                          ("collect_kb_today", lambda: monitor.collect_kb_today(cfg)),
                          ("collect_cli_bridge", monitor.collect_cli_bridge),
                          ("list_services", lambda: monitor.list_services(cfg, time.time())),
                          ("hooks scan_deployed", lambda: hooks_audit.scan_deployed(cfg))):
            try:
                fn()
            except Exception:
                fail("%s with personal keys %s: %s"
                     % (label, scenario, traceback.format_exc().strip().splitlines()[-1]))
    finally:
        os.unlink(path)

# The spawn gate must FAIL CLOSED. With no workspace_roots configured the operator
# has not said where opening a session is allowed, and the one wrong reading of that
# silence is "anywhere" -- which on a published copy would be every reader's whole
# disk. A path the real config allows has to be refused once the roots are gone.
# `base`, not monitor.CONFIG_PATH: the loop above repointed CONFIG_PATH at temp files
# and deleted them on the way out, so re-reading it here opens a path that is gone.
allowed_with_real_config = None
for root in (base.get("workspace_roots") or []):
    if os.path.isdir(root):
        allowed_with_real_config = root
        break
if allowed_with_real_config:
    full, err = monitor._validate_new_session_folder(allowed_with_real_config,
                                                     {"workspace_roots": [allowed_with_real_config]})
    if err:
        fail("spawn gate refuses a folder inside its own configured root: %s" % err)
    full, err = monitor._validate_new_session_folder(allowed_with_real_config, {})
    if not err:
        fail("SPAWN GATE FAILED OPEN: no workspace_roots configured but %r was allowed"
             % allowed_with_real_config)
    if monitor._aitest_folders({}):
        fail("the new-session picker offers folders with no workspace_roots configured")

# A handoff root that is not set must count nothing -- NOT whatever .md files happen
# to sit in the process's cwd, which is what os.path.join("", "*.md") globs.
fd, path = tempfile.mkstemp(suffix=".json")
with os.fdopen(fd, "w", encoding="utf-8") as f:
    json.dump(removed, f, ensure_ascii=False)
monitor.CONFIG_PATH = path
try:
    h = monitor.collect_handoff(monitor.load_config(), time.time())
    if h.get("open"):
        fail("unset handoff_dir counted %d file(s) -- it globbed the cwd"
             % len(h["open"]))
finally:
    os.unlink(path)
print("OK")
'''


def cmd_check_config_depersonalised():
    """The tool has to still RUN once the owner's private values are gone.

    Publishing this repo means every path and account below becomes someone else's to
    fill in. Before this gate, deleting a line took the whole dashboard down rather
    than the one feature that needed it: build_status indexed cfg["claude_projects"]
    directly, so a stripped config raised out of the MAIN POLL. Both real strip styles
    -- blank the value, delete the line -- are exercised against every read-only
    collector the dashboard calls.
    """
    return run_py_driver(CONFIG_DEPERSONALISED_DRIVER, "check-config-depersonalised")


NEW_CHECKS = ("check-copilot", "check-copilot-ui", "check-deletions", "check-delview",
              "check-deletions-readonly",
              "check-authz", "check-authz-ui", "check-collapse", "check-design-doc",
              "check-color-tokens", "check-tooltip", "check-transcript",
              "check-transcript-ui", "check-transcript-linewidth",
              "check-office-data", "check-avatar-identity",
               "check-dashboard-interactions",
               "check-signal-desk-contract", "check-signal-desk-assets", "check-signal-desk-ui",
              "check-signal-desk-layout", "check-signal-desk-zone-vendor",
              "check-signal-desk-surface-state",
              "check-office-transition", "check-office2-no-shell",
              "check-office2-council", "check-office2-council-phase",
              "check-office2-zones", "check-office2-standby-split",
              "check-office2-os-icon", "check-office2-seat-overlap",
              "check-office2-seat-desk-align",
              "check-office2-tab", "check-office2-field-parity",
              "check-office2-label", "check-office2-ctx", "check-office2-stale",
              "check-office2-hooks-pmode", "check-office2-subagent-disclosure",
              "check-office2-mini-identity", "check-office2-work-reason",
              "check-office2-identity-stable", "check-office2-row-badges",
              "check-monitor-help-exits", "check-config-depersonalised",
               "list-checks")


def cmd_list_checks():
    names = sorted(CMDS)
    print("registered sub-commands (%d):" % len(names))
    for n in names:
        print("  " + n)
    missing = [n for n in NEW_CHECKS if n not in CMDS]
    if missing:
        record("FAIL", "list-checks", "unregistered: " + ", ".join(missing))
        return False
    record("PASS", "list-checks",
           "all %d required sub-commands registered; running default suite" % len(NEW_CHECKS))
    return cmd_default()


def cmd_default():
    ok = True
    ok &= check_pycompile()
    ok &= check_import_monitor()
    ok &= node_check(DASHBOARD)
    ok &= node_check(SESSION)
    ok &= node_check(OFFICE_PROTO)
    ok &= cmd_check_office2_no_shell()
    ok &= cmd_check_office2_council()
    ok &= cmd_check_office2_council_phase()
    ok &= cmd_check_office2_zones()
    ok &= cmd_check_office2_standby_split()
    ok &= cmd_check_office2_os_icon()
    ok &= cmd_check_office2_seat_overlap()
    ok &= cmd_check_office2_seat_desk_align()
    ok &= cmd_check_office2_tab()
    ok &= cmd_check_office2_field_parity()
    ok &= cmd_check_office2_label()
    ok &= cmd_check_office2_ctx()
    ok &= cmd_check_office2_stale()
    ok &= cmd_check_office2_hooks_pmode()
    ok &= cmd_check_office2_subagent_disclosure()
    ok &= cmd_check_office2_mini_identity()
    ok &= cmd_check_office2_work_reason()
    ok &= cmd_check_office2_identity_stable()
    ok &= cmd_check_office2_row_badges()
    ok &= cmd_check_costaxis()
    ok &= cmd_check_monitor_help_exits()
    ok &= cmd_check_config_depersonalised()
    ok &= check_zero_llm()
    ok &= selftest()
    ok &= cmd_check_design_doc()
    ok &= cmd_check_color_tokens()
    ok &= cmd_check_tooltip()
    ok &= cmd_check_transcript()
    ok &= cmd_check_transcript_ui()
    ok &= cmd_check_transcript_linewidth()
    ok &= cmd_check_deletions_readonly()
    ok &= cmd_check_office_data()
    ok &= cmd_check_signal_desk_contract()
    ok &= cmd_check_signal_desk_assets()
    ok &= cmd_check_signal_desk_ui()
    ok &= cmd_check_signal_desk_layout()
    ok &= cmd_check_signal_desk_zone_vendor()
    ok &= cmd_check_signal_desk_surface_state()
    ok &= cmd_check_office_transition()
    ok &= cmd_check_avatar_identity()
    ok &= cmd_check_dashboard_interactions()
    return bool(ok)




# ---------------------------------------------- asm-009 cost axis (PR #15)

# Two fields on the per-session card come from a scanned path, so both are
# agent-influenced: probe both.
COSTAXIS_FIXTURE = {
    "window": "7d", "label": "L", "range": "r", "since": "s", "until": "u",
    "generated": "g", "prices_snapshot": "2026-01", "assistant_turns": 3,
    "total_tokens": 100, "tokens": {"input": 1, "cache_creation": 1,
                                    "cache_read": 1, "output": 1},
    "total_cost_usd": 0.0, "unpriced_models": [], "by_model": [],
    "cache_creation_ttl": {"h1": 1, "m5": 1, "unsplit": 0, "mismatch_turns": 0},
    "active_min": 1.0, "per_day": [], "per_project": [],
    "per_session_total": 40,
    "per_session": [
        {"project": _XSS, "session": _XSS, "tokens": 900000, "turns": 2,
         "reread_tokens": 1600000, "avg_turn_reread": 800000, "os": "company"},
        {"project": "p2", "session": "s2", "tokens": 10, "turns": 1,
         "reread_tokens": 500000, "avg_turn_reread": 500000, "os": "win"},
        {"project": "p3", "session": "s3", "tokens": 10, "turns": 1,
         "reread_tokens": 306000, "avg_turn_reread": 306000, "os": "win"},
    ],
}

# `let _recapData` is declared INSIDE the harness try-block, so a driver
# appended after it cannot see the binding -- only `function` declarations get
# hoisted out, which is why paintRecap alone is reachable. The setter is
# exported from inside that block, the same way check-deletions-readonly does.
COSTAXIS_EXPORT = (";globalThis.__precheckSetRecap="
                   "function(d){_recapData=d;_recapBusy=false;};")

COSTAXIS_DRIVER = r"""
;(function(){
  var setRecap = globalThis.__precheckSetRecap;
  if (typeof setRecap !== 'function' || typeof paintRecap !== 'function') {
    console.log('COSTAXIS_HARNESS_MISSING'); process.exit(2);
  }
  function paint(data){
    __SINKS.length = 0;
    setRecap(data);
    paintRecap();
    return __SINKS.join('\n');
  }
  var out;
  try { out = paint(__FIXTURE__); }
  catch (e) { console.log('COSTAXIS_THREW ' + (e && e.message ? e.message : e)); process.exit(3); }

  // 1. the card exists and discloses the truncation
  if (out.indexOf('recap:sessions') < 0) { console.log('COSTAXIS_NO_CARD'); process.exit(4); }
  if (out.indexOf('40') < 0) { console.log('COSTAXIS_NO_TOTAL'); process.exit(5); }

  // 2. nothing agent-controlled reaches the sink raw
  if (out.indexOf('<img src=x') >= 0) { console.log('COSTAXIS_XSS_RAW'); process.exit(6); }
  if (__ATTR_BAD.length) { console.log('COSTAXIS_XSS_ATTR ' + __ATTR_BAD.join(',')); process.exit(7); }

  // 3. the three cost bands must really be three different colours, and the
  //    306k row -- the fleet median -- must be the calm one. A badge stuck on
  //    one colour would still pass a grep.
  var red = out.indexOf('#ff7b72') >= 0, amber = out.indexOf('#e3b341') >= 0, grey = out.indexOf('#8b949e') >= 0;
  if (!(red && amber && grey)) {
    console.log('COSTAXIS_BANDS red=' + red + ' amber=' + amber + ' grey=' + grey); process.exit(8);
  }

  // 4. a non-local session names its machine
  if (out.indexOf('company') < 0) { console.log('COSTAXIS_NO_MACHINE'); process.exit(9); }

  // 5. a remote still on pre-asm-009 code sends no per_session at all
  var legacy = JSON.parse(JSON.stringify(__FIXTURE__));
  delete legacy.per_session; delete legacy.per_session_total;
  var out2;
  try { out2 = paint(legacy); }
  catch (e2) { console.log('COSTAXIS_LEGACY_THREW ' + (e2 && e2.message ? e2.message : e2)); process.exit(10); }
  if (out2.indexOf('recap:sessions') >= 0) { console.log('COSTAXIS_LEGACY_CARD'); process.exit(11); }

  console.log('COSTAXIS_OK'); process.exit(0);
})();
"""


def costaxis_render_check():
    """Render the per-session card for real (node + stub DOM) rather than
    grepping for it: asserts escaping, that the three threshold bands are
    actually distinct, the machine tag, and that a legacy remote carrying no
    per_session neither throws nor renders an empty card."""
    label = "check-costaxis render"
    node = shutil.which("node")
    if not node:
        record("SKIP", label, "warning: node not on PATH, render check skipped")
        return True
    blocks = extract_scripts(DASHBOARD)
    code = (INERT_PRELUDE
            + "\ntry {\n" + "\n;\n".join(blocks)
            + "\n" + COSTAXIS_EXPORT
            + "\n} catch (__e) { console.log('HARNESS_TOPLEVEL_ERR ' "
            + "+ (__e && __e.message ? __e.message : __e)); }\n"
            + COSTAXIS_DRIVER.replace("__FIXTURE__",
                                      json.dumps(COSTAXIS_FIXTURE,
                                                 ensure_ascii=False)))
    fd, tmp = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(code)
        proc = subprocess.run([node, tmp], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    finally:
        os.unlink(tmp)
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode == 0 and "COSTAXIS_OK" in out:
        record("PASS", label,
               "card renders; payload escaped; 3 threshold bands distinct; "
               "machine tagged; legacy remote inert")
        return True
    record("FAIL", label,
           out.splitlines()[-1] if out else "harness exit %d" % proc.returncode)
    return False


def cmd_check_costaxis():
    """asm-009: the per-turn cost axis must stay wired end to end.

    `ctx_tokens` rides on THREE row builders and its badge is a separate scale
    from `ctxBadge` -- a change that keeps one of those and drops the others
    still looks fine on screen, which is exactly how the field shipped with no
    coverage at all the first time."""
    text = read_text(DASHBOARD)
    ok = True
    for needle, why in (
            ("function tokBadge",
             "the cost-axis badge (a separate scale from ctxBadge)"),
            ("r.ctx_tokens", "the session table row must read ctx_tokens"),
            ("s.avg_turn_reread",
             "the per-session card must show RE-READ, not the total"),
            ("recap:sessions", "the per-session card itself"),
            ("function ctxBadge",
             "ctxBadge must survive -- it answers a different question"),
    ):
        if needle not in text:
            record("FAIL", "check-costaxis", "%s missing (%s)" % (needle, why))
            ok = False
    mon = read_text(os.path.join(ROOT, "monitor.py"))
    n = mon.count('"ctx_tokens": cx["occ"] if cx else None')
    if n >= 3:
        record("PASS", "check-costaxis",
               "ctx_tokens on %d row builders + dashboard wiring present" % n)
    else:
        record("FAIL", "check-costaxis",
               "ctx_tokens on %d row builder(s), expected >= 3 "
               "(collect_claude / session_detail / cockpit_cards)" % n)
        ok = False
    return node_check(DASHBOARD) and costaxis_render_check() and ok


CMDS = {
    "check-model": cmd_check_model,
    "check-kind": cmd_check_kind,
    "check-cockpit": cmd_check_cockpit,
    "check-srccolor": cmd_check_srccolor,
    "check-copilot": cmd_check_copilot,
    "check-copilot-ui": cmd_check_copilot_ui,
    "check-transcript": cmd_check_transcript,
    "check-transcript-ui": cmd_check_transcript_ui,
    "check-transcript-linewidth": cmd_check_transcript_linewidth,
    "check-deletions": cmd_check_deletions,
    "check-delview": cmd_check_delview,
    "check-deletions-readonly": cmd_check_deletions_readonly,
    "check-authz": cmd_check_authz,
    "check-authz-ui": cmd_check_authz_ui,
    "check-collapse": cmd_check_collapse,
    "check-design-doc": cmd_check_design_doc,
    "check-color-tokens": cmd_check_color_tokens,
    "check-tooltip": cmd_check_tooltip,
    "check-office-data": cmd_check_office_data,
    "check-signal-desk-contract": cmd_check_signal_desk_contract,
    "check-signal-desk-assets": cmd_check_signal_desk_assets,
    "check-signal-desk-ui": cmd_check_signal_desk_ui,
    "check-signal-desk-layout": cmd_check_signal_desk_layout,
    "check-signal-desk-zone-vendor": cmd_check_signal_desk_zone_vendor,
    "check-signal-desk-surface-state": cmd_check_signal_desk_surface_state,
    "check-office-transition": cmd_check_office_transition,
    "check-avatar-identity": cmd_check_avatar_identity,
    "check-office2-no-shell": cmd_check_office2_no_shell,
    "check-office2-council": cmd_check_office2_council,
    "check-office2-council-phase": cmd_check_office2_council_phase,
    "check-office2-zones": cmd_check_office2_zones,
    "check-office2-standby-split": cmd_check_office2_standby_split,
    "check-office2-os-icon": cmd_check_office2_os_icon,
    "check-office2-seat-overlap": cmd_check_office2_seat_overlap,
    "check-office2-seat-desk-align": cmd_check_office2_seat_desk_align,
    "check-office2-tab": cmd_check_office2_tab,
    "check-office2-field-parity": cmd_check_office2_field_parity,
    "check-office2-label": cmd_check_office2_label,
    "check-office2-ctx": cmd_check_office2_ctx,
    "check-office2-stale": cmd_check_office2_stale,
    "check-office2-hooks-pmode": cmd_check_office2_hooks_pmode,
    "check-office2-subagent-disclosure": cmd_check_office2_subagent_disclosure,
    "check-office2-mini-identity": cmd_check_office2_mini_identity,
    "check-office2-work-reason": cmd_check_office2_work_reason,
    "check-office2-identity-stable": cmd_check_office2_identity_stable,
    "check-office2-row-badges": cmd_check_office2_row_badges,
    "check-dashboard-interactions": cmd_check_dashboard_interactions,
    "check-monitor-help-exits": cmd_check_monitor_help_exits,
    "check-config-depersonalised": cmd_check_config_depersonalised,
    "check-costaxis": cmd_check_costaxis,
    "list-checks": cmd_list_checks,
}


def main(argv):
    if len(argv) == 0:
        ok = cmd_default()
    elif len(argv) == 1 and argv[0] in CMDS:
        ok = CMDS[argv[0]]()
    else:
        print("usage: python tools/preflight_ui.py [%s]" % "|".join(sorted(CMDS)))
        return 2
    fails = sum(1 for s, _, _ in RESULTS if s == "FAIL")
    skips = sum(1 for s, _, _ in RESULTS if s == "SKIP")
    print("preflight_ui: %d check(s), %d FAIL, %d SKIP -> %s"
          % (len(RESULTS), fails, skips, "OK" if ok else "NOT OK"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
