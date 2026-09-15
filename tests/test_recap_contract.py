"""Root resolution across MULTIPLE roots, and the per_session public contract.

Everything here exists because a codex review of PR #15 found gaps the first
round of tests could not see, all of them sharing one cause: the fixtures used
a single scanned root and referenced the module's own constants, so they agreed
with the implementation instead of pinning it.

- XAI-001: the processing loop resolved every file against `root`, but `root`
  there was whatever the *collection* loop left behind -- the LAST root. One
  root (every test, and the default config) is accidentally correct; two roots
  (the `--mac` path, which folds in a synced `.claude-mac` tree) sent every file
  through the wrong tree and put the nested transcripts straight back into
  phantom projects.
- XAI-002: a transcript sitting directly in the scanned root reported its own
  filename as the project name.
- XAI-004: `PER_SESSION_TOP_N` was asserted against `recap.PER_SESSION_TOP_N`,
  so changing the constant changed the expectation too and the cap was not
  actually pinned. Here it is pinned to the literal 12.

Run:  python -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import recap  # noqa: E402


def _turn(mid, inp=0, cr=0, cw=0, out=0):
    ts = datetime.now(timezone.utc) - timedelta(minutes=5)
    return {"timestamp": ts.isoformat().replace("+00:00", "Z"),
            "type": "assistant",
            "message": {"role": "assistant", "id": mid,
                        "model": "claude-opus-5",
                        "usage": {"input_tokens": inp, "output_tokens": out,
                                  "cache_creation_input_tokens": cw,
                                  "cache_read_input_tokens": cr}}}


def _write(root, rel, turns):
    fp = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(fp), exist_ok=True)
    with open(fp, "w", encoding="utf-8") as f:
        for t in turns:
            f.write(json.dumps(t) + "\n")
    return fp


class MultipleRoots(unittest.TestCase):
    """XAI-001. Each file must resolve against the root it was FOUND under."""

    def test_two_independent_roots_each_resolve_correctly(self):
        with tempfile.TemporaryDirectory() as r1, \
                tempfile.TemporaryDirectory() as r2:
            _write(r1, "alpha/sess-a.jsonl", [_turn("a", cr=100)])
            _write(r1, "alpha/sess-a/subagents/agent-x.jsonl",
                   [_turn("b", cr=400)])
            _write(r2, "beta/sess-b.jsonl", [_turn("c", cr=1000)])
            r = recap.build_recap("7d", roots=[r1, r2])

        projects = sorted(p["project"] for p in r["per_project"])
        self.assertEqual(projects, ["alpha", "beta"])
        by_sess = {s["session"]: s for s in r["per_session"]}
        self.assertEqual(sorted(by_sess), ["sess-a", "sess-b"])
        # the subagent under r1 folded into its own session, not r2's tree
        self.assertEqual(by_sess["sess-a"]["tokens"], 500)
        self.assertEqual(by_sess["sess-a"]["project"], "alpha")
        self.assertEqual(sum(p["tokens"] for p in r["per_project"]),
                         r["total_tokens"])

    def test_no_phantom_project_appears_with_two_roots(self):
        """The exact regression: with the last-root bug, the nested file under
        the FIRST root resolved to nothing and fell back to its parent dir."""
        with tempfile.TemporaryDirectory() as r1, \
                tempfile.TemporaryDirectory() as r2:
            _write(r1, "alpha/sess-a/subagents/agent-x.jsonl",
                   [_turn("a", cr=400)])
            _write(r1, "alpha/sess-a.jsonl", [_turn("b", cr=1)])
            _write(r2, "beta/sess-b.jsonl", [_turn("c", cr=1)])
            r = recap.build_recap("7d", roots=[r1, r2])
        self.assertNotIn("subagents", [p["project"] for p in r["per_project"]])
        self.assertNotIn("subagents", [s["session"] for s in r["per_session"]])

    def test_root_order_does_not_change_the_answer(self):
        with tempfile.TemporaryDirectory() as r1, \
                tempfile.TemporaryDirectory() as r2:
            _write(r1, "alpha/sess-a/subagents/agent-x.jsonl",
                   [_turn("a", cr=400)])
            _write(r2, "beta/sess-b.jsonl", [_turn("b", cr=1000)])
            fwd = recap.build_recap("7d", roots=[r1, r2])
            rev = recap.build_recap("7d", roots=[r2, r1])
        self.assertEqual(sorted(p["project"] for p in fwd["per_project"]),
                         sorted(p["project"] for p in rev["per_project"]))
        self.assertEqual(fwd["total_tokens"], rev["total_tokens"])

    def test_a_trailing_separator_on_the_root_is_harmless(self):
        with tempfile.TemporaryDirectory() as root:
            _write(root, "alpha/sess-a.jsonl", [_turn("a", cr=100)])
            r = recap.build_recap("7d", roots=[root + os.sep])
        self.assertEqual([p["project"] for p in r["per_project"]], ["alpha"])
        self.assertEqual([s["session"] for s in r["per_session"]], ["sess-a"])


class RootRelativeEdges(unittest.TestCase):
    """XAI-002 and the containment rule itself."""

    def test_transcript_directly_under_the_root_has_no_project_dir(self):
        root = os.path.join("X:", os.sep, "root")
        fp = os.path.join(root, "s.jsonl")
        self.assertEqual(recap._project_of(fp, root), "(root)")

    def test_a_project_named_with_leading_dots_is_not_rejected(self):
        """Rejection is on a `..` SEGMENT, not on the string starting with '..'."""
        root = os.path.join("X:", os.sep, "root")
        fp = os.path.join(root, "..foo", "s.jsonl")
        self.assertEqual(recap._project_of(fp, root), "..foo")

    def test_case_differences_do_not_break_containment_on_windows(self):
        if os.path.normcase("A") == "A":       # POSIX: case-sensitive, skip
            self.skipTest("case-insensitive containment is a Windows concern")
        with tempfile.TemporaryDirectory() as root:
            fp = _write(root, "alpha/s.jsonl", [_turn("a")])
            self.assertEqual(recap._project_of(fp, root.upper()), "alpha")

    def test_path_outside_the_root_falls_back_rather_than_guessing(self):
        self.assertIsNone(recap._rel_parts(
            os.path.join("Y:", os.sep, "other", "x.jsonl"),
            os.path.join("X:", os.sep, "root")))


class PerSessionPublicContract(unittest.TestCase):
    """XAI-004: pin the contract to literals, not to the module's own values."""

    def recap_of(self, files):
        with tempfile.TemporaryDirectory() as root:
            for rel, turns in files.items():
                _write(root, rel, turns)
            return recap.build_recap("7d", roots=[root])

    def test_the_cap_is_twelve(self):
        self.assertEqual(recap.PER_SESSION_TOP_N, 12)
        files = {"demo/s%02d.jsonl" % i: [_turn("m%02d" % i, cr=i + 1)]
                 for i in range(20)}
        r = self.recap_of(files)
        self.assertEqual(len(r["per_session"]), 12)
        self.assertEqual(r["per_session_total"], 20)

    def test_tokens_includes_output_but_reread_does_not(self):
        """The distinction the UI labels depend on. Output is generated, never
        re-sent, so it is not part of what the next turn re-reads."""
        r = self.recap_of({"demo/s.jsonl": [
            _turn("a", inp=1, cw=2, cr=3, out=94)]})
        s = r["per_session"][0]
        self.assertEqual(s["tokens"], 100)
        self.assertEqual(s["reread_tokens"], 6)
        self.assertEqual(s["avg_turn_reread"], 6)

    def test_avg_turn_reread_divides_by_turns_not_by_files(self):
        r = self.recap_of({
            "demo/s.jsonl": [_turn("a", cr=100), _turn("b", cr=300)],
            "demo/s/subagents/agent-x.jsonl": [_turn("c", cr=200)],
        })
        s = r["per_session"][0]
        self.assertEqual(s["turns"], 3)
        self.assertEqual(s["reread_tokens"], 600)
        self.assertEqual(s["avg_turn_reread"], 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
