"""Offline contract checks for the cross-AI handoff recipient view in collect_handoff.

Fixture only (TemporaryDirectory); never reads the owner's real _handoff/ dirs.
Run: python tools/check_handoff_inbox.py   -> prints "handoff-inbox fixtures: PASS" and exits 0.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import monitor  # noqa: E402


def check(name, actual, expected):
    assert actual == expected, "%s: got %r expected %r" % (name, actual, expected)


def write(root, name, text):
    with open(os.path.join(root, name), "w", encoding="utf-8") as f:
        f.write(text)


with tempfile.TemporaryDirectory() as tmp:
    a = os.path.join(tmp, "repoA", "_handoff")
    b = os.path.join(tmp, "repoB", "_handoff")
    os.makedirs(a)
    os.makedirs(b)
    write(a, "handoff_x_2026-08-21.md", "# h\n- 出：Claude Code\n- 收：Codex\n\n## 我做了什麼\n")
    write(a, "handoff_y_2026-08-20.md", "# h\n- 出：Codex\n- 收：Claude Code（Windows）\n")
    write(a, "handoff_z_2026-08-19_DONE.md", "# h\n- 收：Claude\n")          # closed: not counted
    write(a, "handoff_w_2026-08-18.md", "# h\n- 收：下一個接手的 session（Codex 或 Claude 皆可）\n")
    write(a, "handoff_v_2026-08-17.md", "# h\n- 收：owner\n")                # names neither agent
    write(a, "plan_something_2026-08-17.md", "- 收：Codex\n")                 # not a handoff_ file: no recipient
    write(b, "handoff_q_2026-08-16.md", "- to: Claude\n")                    # English alias
    write(b, "handoff_bom_2026-08-15.md", "﻿- 收：Codex\n")              # UTF-8 BOM on line 1 (codex F1)
    write(b, "README.md", "noise\n")

    # recipient parser
    check("codex", monitor.handoff_recipient(os.path.join(a, "handoff_x_2026-08-21.md")), "Codex")
    check("claude-code", monitor.handoff_recipient(os.path.join(a, "handoff_y_2026-08-20.md")), "Claude")
    check("both", monitor.handoff_recipient(os.path.join(a, "handoff_w_2026-08-18.md")), "both")
    check("other", monitor.handoff_recipient(os.path.join(a, "handoff_v_2026-08-17.md")), "other")
    check("english-alias", monitor.handoff_recipient(os.path.join(b, "handoff_q_2026-08-16.md")), "Claude")
    check("bom-line-1", monitor.handoff_recipient(os.path.join(b, "handoff_bom_2026-08-15.md")), "Codex")
    check("no-line", monitor.handoff_recipient(os.path.join(b, "README.md")), "")

    # legacy single key still works, alone
    out = monitor.collect_handoff({"handoff_dir": a, "handoff_dirs": []}, 0)
    check("legacy-open", out["counts"]["OPEN"], 5)            # x y w v + plan_something
    check("legacy-done", out["counts"]["DONE"], 1)
    check("legacy-by-recipient", out["by_recipient"], {"Claude": 1, "Codex": 1, "both": 1, "other": 1})
    check("legacy-roots", out["roots"], 1)

    # list key adds a second root; duplicates collapse; README noise skipped
    out = monitor.collect_handoff({"handoff_dir": a, "handoff_dirs": [b, a, ""]}, 0)
    check("multi-roots", out["roots"], 2)
    check("multi-open", out["counts"]["OPEN"], 7)
    check("multi-by-recipient", out["by_recipient"], {"Claude": 2, "Codex": 2, "both": 1, "other": 1})

    # handoff_dirs that is not a list (a string would split per character; None/int must not raise)
    for bad in ("nope", None, 7, {"x": 1}):
        out = monitor.collect_handoff({"handoff_dir": a, "handoff_dirs": bad}, 0)
        check("non-list-handoff_dirs %r -> ignored" % (bad,), out["roots"], 1)
    rec = {r["label"]: r["recipient"] for r in out["open"]}
    check("row-recipient", rec["handoff_x_2026-08-21.md"], "Codex")
    check("row-no-recipient-for-plan", rec["plan_something_2026-08-17.md"], "")

    # nothing configured: zero rows, never the cwd
    out = monitor.collect_handoff({"handoff_dir": "", "handoff_dirs": []}, 0)
    check("unset-roots", out["roots"], 0)
    check("unset-open", out["counts"]["OPEN"], 0)

print("handoff-inbox fixtures: PASS")
