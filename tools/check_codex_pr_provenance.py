"""Offline contract checks for the Windows Codex PR provenance observer."""
import os
import sys
import inspect
import json
import sqlite3
import tempfile
import threading
import urllib.request
from http.server import HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import monitor  # noqa: E402


PR = {"repo": "owner/repo", "node_id": "PR_node", "head_ref": "codex/demo",
      "head_sha": "abc123", "base_sha": "def456"}
THREAD = {"git_origin_url": "git@github.com:owner/repo.git", "git_branch": "codex/demo",
          "git_sha": "abc123"}


def check(name, actual, expected):
    assert actual == expected, "%s: got %r expected %r" % (name, actual, expected)


check("exact", monitor._codex_pr_match(PR, THREAD), "verified")
check("sha-changed", monitor._codex_pr_match(PR, dict(THREAD, git_sha="deadbeef")), "stale")
check("branch-mismatch", monitor._codex_pr_match(PR, dict(THREAD, git_branch="main")), None)
check("repo-mismatch", monitor._codex_pr_match(PR, dict(THREAD, git_origin_url="https://github.com/other/repo.git")), None)
check("missing-sha", monitor._codex_pr_match(PR, dict(THREAD, git_sha="")), "unverifiable")
check("non-github", monitor._codex_pr_match(PR, dict(THREAD, git_origin_url="https://example.test/owner/repo")), "unverifiable")
check("missing-pr-oid", monitor._codex_pr_match(dict(PR, head_sha=""), THREAD), "unverifiable")
check("ssh-normalize", monitor._github_repo_from_origin("git@github.com:Owner/Repo.git"), "owner/repo")
check("https-normalize", monitor._github_repo_from_origin("https://github.com/Owner/Repo/"), "owner/repo")

old_prs, old_threads = monitor.collect_github_prs, monitor._codex_pr_threads
try:
    monitor.collect_github_prs = lambda cfg: {"available": True, "stale": False, "note": "", "checked": 1,
                                               "rows": [dict(PR, number=7, url="https://example/pr/7")]}
    monitor._codex_pr_threads = lambda cfg: [dict(THREAD, session_id="codex-a", updated_at=1, source_kind="interactive")]
    check("collector-verified", monitor.collect_codex_pr_provenance({})["rows"][0]["state"], "verified")
    monitor._codex_pr_threads = lambda cfg: [dict(THREAD, git_sha="deadbeef", session_id="codex-a", updated_at=1, source_kind="interactive")]
    check("collector-stale", monitor.collect_codex_pr_provenance({})["rows"][0]["state"], "stale")
    check("collector-stale-proof", monitor.collect_codex_pr_provenance({})["rows"][0]["proof"], "thread_head_sha_mismatch")
    monitor._codex_pr_threads = lambda cfg: [
        dict(THREAD, git_sha="deadbeef", session_id="codex-a", updated_at=2, source_kind="interactive"),
        dict(THREAD, git_sha="deadbeef", session_id="codex-b", updated_at=1, source_kind="interactive"),
    ]
    deduped = monitor.collect_codex_pr_provenance({})["rows"]
    check("collector-dedupes-same-sha", len(deduped), 1)
    check("collector-keeps-latest-thread", deduped[0]["codex"]["session_id"], "codex-a")
    monitor._codex_pr_threads = lambda cfg: []
    check("collector-unverifiable", monitor.collect_codex_pr_provenance({})["rows"][0]["state"], "unverifiable")
    monitor.collect_github_prs = lambda cfg: {"available": False, "stale": False, "note": "gh failed", "checked": None, "rows": []}
    unavailable = monitor.collect_codex_pr_provenance({})
    check("collector-unavailable", (unavailable["available"], unavailable["rows"]), (False, []))
    monitor.collect_github_prs = lambda cfg: {"available": True, "stale": True, "note": "cached", "checked": 1, "rows": [PR]}
    stale_snapshot = monitor.collect_codex_pr_provenance({})
    check("collector-stale-snapshot", (stale_snapshot["stale"], stale_snapshot["rows"]), (True, []))
finally:
    monitor.collect_github_prs, monitor._codex_pr_threads = old_prs, old_threads

local_index = os.path.join(os.path.expanduser("~"), ".codex", "session_index.jsonl")
check("local-index", monitor._is_local_windows_codex_index(local_index), True)
check("remote-index", monitor._is_local_windows_codex_index(os.path.join(os.path.expanduser("~"), ".codex-mac", "session_index.jsonl")), False)
old_os_name = monitor.os.name
try:
    monitor.os.name = "posix"
    check("non-windows", monitor._is_local_windows_codex_index(local_index), False)
finally:
    monitor.os.name = old_os_name

old_realpath = monitor.os.path.realpath
try:
    local_index_norm = monitor.os.path.normcase(monitor.os.path.abspath(local_index))
    monitor.os.path.realpath = lambda path: (r"C:\\redirected\\session_index.jsonl"
                                             if monitor.os.path.normcase(monitor.os.path.abspath(path)) == local_index_norm
                                             else old_realpath(path))
    check("unreferenced-local-index-path", monitor._is_local_windows_codex_index(local_index), True)
finally:
    monitor.os.path.realpath = old_realpath

with tempfile.TemporaryDirectory() as home_dir:
    local_root = os.path.join(home_dir, ".codex")
    os.mkdir(local_root)
    missing_index = os.path.join(local_root, "session_index.jsonl")
    old_expanduser = monitor.os.path.expanduser
    try:
        monitor.os.path.expanduser = lambda path: home_dir if path == "~" else old_expanduser(path)
        check("missing-local-index-uses-root", monitor._is_local_windows_codex_index(missing_index), True)
    finally:
        monitor.os.path.expanduser = old_expanduser

old_realpath = monitor.os.path.realpath
try:
    local_root_norm = monitor.os.path.normcase(monitor.os.path.abspath(os.path.dirname(local_index)))
    monitor.os.path.realpath = lambda path: (r"C:\\redirected\\.codex"
                                             if monitor.os.path.normcase(monitor.os.path.abspath(path)) == local_root_norm
                                             else old_realpath(path))
    check("redirected-local-root", monitor._is_local_windows_codex_index(local_index), False)
finally:
    monitor.os.path.realpath = old_realpath

with tempfile.TemporaryDirectory() as db_dir:
    for name, updated_at in (("state_9.sqlite", 10), ("state_10.sqlite", 20)):
        db_path = os.path.join(db_dir, name)
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE threads (id TEXT, updated_at REAL)")
        conn.execute("INSERT INTO threads VALUES (?, ?)", (name, updated_at))
        conn.commit()
        conn.close()
    chosen = monitor._local_codex_pr_state_db(os.path.join(db_dir, "session_index.jsonl"))
    check("freshest-state-db", os.path.basename(chosen), "state_10.sqlite")

with tempfile.TemporaryDirectory() as db_dir:
    db_path = os.path.join(db_dir, "state_redirected.sqlite")
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE threads (id TEXT, updated_at REAL)")
    conn.execute("INSERT INTO threads VALUES (?, ?)", ("redirected", 1))
    conn.commit()
    conn.close()
    old_path_check = monitor._is_unredirected_path
    try:
        monitor._is_unredirected_path = lambda path: False if path == db_path else old_path_check(path)
        check("redirected-state-db", monitor._local_codex_pr_state_db(os.path.join(db_dir, "session_index.jsonl")), None)
    finally:
        monitor._is_unredirected_path = old_path_check

with tempfile.TemporaryDirectory() as db_dir:
    db_path = os.path.join(db_dir, "state_cached.sqlite")
    index_path = os.path.join(db_dir, "session_index.jsonl")
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE threads (id TEXT, updated_at REAL)")
    conn.execute("INSERT INTO threads VALUES (?, ?)", ("cached", 1))
    conn.commit()
    conn.close()
    monitor._codex_db_cache.pop(index_path, None)
    check("cached-state-db-initial", monitor._codex_state_db(index_path), db_path)
    old_path_check = monitor._is_unredirected_path
    try:
        monitor._is_unredirected_path = lambda path: False if path == db_path else old_path_check(path)
        check("redirected-cached-state-db", monitor._codex_state_db(index_path), None)
    finally:
        monitor._is_unredirected_path = old_path_check
        monitor._codex_db_cache.pop(index_path, None)

with tempfile.TemporaryDirectory() as db_dir:
    db_path = os.path.join(db_dir, "state_1.sqlite")
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE threads (id TEXT, updated_at REAL, git_origin_url TEXT, git_branch TEXT, git_sha TEXT)")
    conn.execute("INSERT INTO threads VALUES (?, ?, ?, ?, ?)",
                 ("source-less", 1, THREAD["git_origin_url"], THREAD["git_branch"], THREAD["git_sha"]))
    conn.commit()
    conn.close()
    old_index_check, old_selector = monitor._is_local_windows_codex_index, monitor._local_codex_pr_state_db
    try:
        monitor._is_local_windows_codex_index = lambda path: True
        monitor._local_codex_pr_state_db = lambda path: db_path
        source_less = monitor._codex_pr_threads({"codex_session_index": [os.path.join(db_dir, "session_index.jsonl")]})
        check("source-column-optional", source_less[0]["source_kind"], "interactive")
    finally:
        monitor._is_local_windows_codex_index, monitor._local_codex_pr_state_db = old_index_check, old_selector
assert 'route == "/api/codex-pr-provenance"' in inspect.getsource(monitor.Handler.do_GET)

old_cfg, old_endpoint = monitor.load_config, monitor.collect_codex_pr_provenance
server = None
server_thread = None
try:
    monitor.load_config = lambda: {}
    monitor.collect_codex_pr_provenance = lambda cfg: {"available": False, "rows": [], "note": "fixture"}
    server = HTTPServer(("127.0.0.1", 0), monitor.Handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    url = "http://127.0.0.1:%d/api/codex-pr-provenance" % server.server_port
    for attempt in range(3):
        try:
            with opener.open(url, timeout=5) as response:
                check("route-status", response.status, 200)
                assert response.headers.get_content_type() == "application/json"
                check("route-payload", json.loads(response.read().decode("utf-8"))["note"], "fixture")
            break
        except OSError:  # read-phase timeout raises builtin TimeoutError (an OSError, NOT a URLError)
            if attempt == 2:
                raise
            threading.Event().wait(0.1)
finally:
    if server is not None:
        server.shutdown()
        if server_thread is not None:
            server_thread.join(timeout=2)
        server.server_close()
    monitor.load_config, monitor.collect_codex_pr_provenance = old_cfg, old_endpoint
print("codex-pr-provenance fixtures: PASS")
