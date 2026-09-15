"""Offline safety checks for the Codex liveness state-DB reader.

All SQLite files live in TemporaryDirectory fixtures.  This runner must never
rename, write, or otherwise touch the user's ~/.codex state store.

Depersonalised: the exec-fragment fixtures use RELATIVE path fragments and a
generic `workspace_roots` anchor ("work"), never an absolute owner disk path or
a real repo name -- the label extraction searches for the same substrings
either way, so the coverage is unchanged while nothing here names a machine.
"""
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import monitor  # noqa: E402


def check(name, actual, expected):
    assert actual == expected, "%s: got %r expected %r" % (name, actual, expected)


now = time.time()
cfg = {"running_secs": 90, "idle_alert_minutes": 10,
       "max_age_hours": 6, "max_rows_per_source": 10}

with tempfile.TemporaryDirectory() as db_dir:
    index_path = os.path.join(db_dir, "session_index.jsonl")
    for name, updated_at in (("state_9.sqlite", now - 20), ("state_10.sqlite", now - 10)):
        db_path = os.path.join(db_dir, name)
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE threads (id TEXT, updated_at REAL)")
        conn.execute("INSERT INTO threads VALUES (?, ?)", (name, updated_at))
        conn.commit()
        conn.close()
    selected = monitor._codex_state_db(index_path)
    check("freshest-state-db", os.path.basename(selected), "state_10.sqlite")
    rows = monitor._codex_db_rows(selected, cfg, now, "win", now - 3600, 10)
    check("optional-columns-row-count", len(rows), 1)
    check("missing-cwd-safe", rows[0]["project"], None)
    check("missing-rollout-safe", rows[0]["_office_path"], None)

with tempfile.TemporaryDirectory() as fixture_dir:
    index_path = os.path.join(fixture_dir, "session_index.jsonl")
    with open(index_path, "w", encoding="utf-8") as fh:
        fh.write('{"id":"fallback-id","thread_name":"Fallback","updated_at":"%s"}\n'
                 % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)))
    old_selector = monitor._codex_state_db
    try:
        monitor._codex_state_db = lambda path: None
        rows = monitor.collect_codex(dict(cfg, codex_session_index=[index_path]), now)
        check("fallback-row-count", len(rows), 1)
        check("fallback-source", monitor._CODEX_SOURCE["_shown"], "index-fallback")
    finally:
        monitor._codex_state_db = old_selector

# Same-name/different-face guard (owner-reported 2026-08-21). The office draws
# the face from session_id and the name from the label, so two rows that share a
# label are two figures with one name. Neither a subagent (title inherited from
# the parent) nor a repeat automation run (same title AND same index thread_name)
# has a distinguishing title, and neither does a repeat `exec` dispatch of one
# template prompt, so the labels have to come from somewhere else. The exec
# fixtures below use RELATIVE fragments and the "work" workspace-root anchor
# (set on the cfg), never an owner path -- the repo name is extracted the same
# way from `work/<repo>` as it would be from any reader's own root.
with tempfile.TemporaryDirectory() as ident_dir:
    index_path = os.path.join(ident_dir, "session_index.jsonl")
    db_path = os.path.join(ident_dir, "state_1.sqlite")
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE threads (id TEXT, updated_at REAL, title TEXT, source TEXT, "
                 "agent_nickname TEXT, agent_role TEXT, thread_source TEXT)")
    conn.executemany("INSERT INTO threads VALUES (?, ?, ?, ?, ?, ?, ?)", [
        ("parent-1", now - 10, "compare the client code rules", "vscode", None, None, "user"),
        ("kid-1", now - 11, "compare the client code rules", '{"subagent":{}}', "Beauvoir", "explorer", "subagent"),
        ("kid-2", now - 12, "compare the client code rules", '{"subagent":{}}', "Godel", "explorer", "subagent"),
        ("kid-3", now - 13, "compare the client code rules", '{"subagent":{}}', "Singer", None, "subagent"),
        ("auto-1", now - 14, "Automation: weekly digest", "vscode", None, None, "automation"),
        ("auto-2", now - 15, "Automation: weekly digest", "vscode", None, None, "automation"),
        ("exec-1", now - 16, "DOC-REVIEW (read-only consultation)", "exec", None, None, "user"),
        ("exec-2", now - 17, "DOC-REVIEW (read-only consultation)", "exec", None, None, "user"),
        # exec fragment extraction (owner 2026-08-21: the resting nameplate shows
        # ~14 chars, so the visible prefix must name the PR/ticket/file, not the
        # template head). Ids stay <= 8 chars: the suffix is tid[:8].
        ("ex-pr", now - 18, "You are reviewing the change set (PR #103) in REPO ROOT: "
         "work/demo-kb/wt/x read only", "exec", None, None, "user"),
        ("ex-prl", now - 19, "You are a code reviewer. Review pr40 in "
         "work/demo-kb/pr40", "exec", None, None, "user"),
        ("ex-prh", now - 20, "SECURITY REVIEW (ROUND 2) — PR#115 queue_bypass token hooks",
         "exec", None, None, "user"),
        ("ex-tk", now - 21, "doc-review. Read this file by ABSOLUTE path and review it: "
         "work/demo-kb/tickets/tk-006.md",
         "exec", None, None, "user"),
        ("ex-file", now - 22, "doc-review. Read this file by ABSOLUTE path and review it: "
         "misc/foo-card.md", "exec", None, None, "user"),
        ("ex-repo", now - 23, "You are a senior code reviewer, READ-ONLY. Target repo: "
         "work/demo-app", "exec", None, None, "user"),
        ("ex-dot", now - 24, "You are a senior code reviewer, READ-ONLY. Target repo: "
         "work/demo-app. Review the diff.", "exec", None, None, "user"),
        ("ex-long", now - 25, "Review work/demo-skills/shared/"
         "very-long-reference-card-name-2026-08-21.md carefully", "exec", None, None, "user"),
        ("ex-sha", now - 26, "Verify the sha-256 of the bundle against rfc-793 framing; "
         "reply PASS or FAIL", "exec", None, None, "user"),
        ("ex-none", now - 27, None, "exec", None, None, "user"),
        ("ex-idx", now - 28, "Review (PR #7) in work/demo-kb/x",
         "exec", None, None, "user"),
        ("ex-multi", now - 29, "REVIEW TARGET: PR #124 of demo-skills — two fail-open "
         "paths. Compare with PR #126, PR #126, PR #126 history.", "exec", None, None, "user"),
    ])
    conn.commit()
    conn.close()
    with open(index_path, "w", encoding="utf-8") as fh:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
        for tid in ("auto-1", "auto-2"):  # both runs carry ONE index name
            fh.write('{"id":"%s","thread_name":"Weekly digest","updated_at":"%s"}\n'
                     % (tid, stamp))
        # an exec row that DID reach the index: its summary must not overwrite
        # the fragment (0/146 real exec rows were indexed; this is the guard)
        fh.write('{"id":"ex-idx","thread_name":"Some summary","updated_at":"%s"}\n' % stamp)
    # 20 fixture rows > the 10-row cap the other fixtures use; raise it here so
    # the cap does not silently hide a label regression in the dropped rows.
    # workspace_roots gives the exec repo-extractor its anchor ("work"), the
    # depersonalised replacement for the old hardcoded owner-root regex.
    rows = monitor.collect_codex(dict(cfg, codex_session_index=[index_path],
                                      max_rows_per_source=30,
                                      workspace_roots=["work"]), now)
    labels = {r["session_id"]: r["label"] for r in rows}
    check("identity-row-count", len(rows), 20)
    check("identity-labels-unique", len(set(labels.values())), 20)
    check("exec-frag-pr-repo", labels["codex-ex-pr"], "PR #103 · demo-kb #ex-pr")
    check("exec-frag-pr-lower", labels["codex-ex-prl"], "PR #40 · demo-kb #ex-prl")
    check("exec-frag-pr-nohash-norepo", labels["codex-ex-prh"], "PR #115 #ex-prh")
    check("exec-frag-ticket", labels["codex-ex-tk"], "tk-006 · demo-kb #ex-tk")
    check("exec-frag-file-only", labels["codex-ex-file"], "foo-card.md #ex-file")
    check("exec-frag-repo-only", labels["codex-ex-repo"], "demo-app #ex-repo")
    check("exec-frag-repo-trailing-dot", labels["codex-ex-dot"], "demo-app #ex-dot")
    check("exec-frag-long-primary-drops-repo", labels["codex-ex-long"],
          "very-long-reference-card-name-2026-08-21.md #ex-long")
    check("exec-frag-exclusion-falls-back", labels["codex-ex-sha"],
          "Verify the sha-256 of the bundle against rfc-793 framing; reply PASS or FAIL"[:50]
          + " #ex-sha")
    check("exec-frag-title-none-safe", labels["codex-ex-none"], "ex-none #ex-none")
    check("exec-frag-index-does-not-override", labels["codex-ex-idx"],
          "PR #7 · demo-kb #ex-idx")
    check("exec-frag-first-pr-wins", labels["codex-ex-multi"], "PR #124 #ex-multi")
    check("subagent-nickname-role", labels["codex-kid-1"], "Beauvoir · explorer")
    check("subagent-role-optional", labels["codex-kid-3"], "Singer")
    check("parent-keeps-title", labels["codex-parent-1"], "compare the client code rules")
    check("automation-run-suffix", labels["codex-auto-1"], "Weekly digest #auto-1")
    check("exec-dispatch-suffix", labels["codex-exec-1"],
          "DOC-REVIEW (read-only consultation) #exec-1")
    # _office_path is stripped later by enrich_office_rows; _tsrc has no such
    # consumer, so it must not survive its one use here and reach /api/status.
    check("tsrc-not-published", [r for r in rows if "_tsrc" in r], [])

print("codex-liveness-source fixtures: PASS")
