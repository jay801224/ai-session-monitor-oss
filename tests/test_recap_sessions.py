"""Per-session token breakdown in recap.py (KB ticket asm-009).

The cost driver measured on this fleet is per-turn context size multiplied by
turn count, and the dashboard could show neither: `ctx` is occupancy of the
model's window (a capacity signal), and recap aggregated only per PROJECT.
This covers the per-SESSION axis added for asm-009.

It also covers a pre-existing silent accounting hole that the per-session work
exposed. Project and session used to be derived with basename(dirname()), so a
NESTED transcript landed in a phantom project named after its parent directory:

    <slug>/<uuid>/subagents/agent-*.jsonl                 -> "subagents"
    <slug>/<uuid>/subagents/workflows/wf_<id>/agent-*.jsonl -> "wf_<id>"

Those buckets were never rendered (per_project iterates proj_ts, which skips
subagent files), so the tokens simply vanished -- 169,049,467 then a further
21,779,984 on one 7-day window, while the comment on proj_tokens claimed the
opposite. Two shapes is the point: hopping a fixed number of levels only fixes
the shapes you happened to look at, which is why the rule is root-relative.
`test_no_tokens_are_dropped_from_per_project` is the oracle for the whole class.

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


def _turn(mid, model="claude-opus-5", cr=0):
    ts = datetime.now(timezone.utc) - timedelta(minutes=5)
    return {"timestamp": ts.isoformat().replace("+00:00", "Z"),
            "type": "assistant",
            "message": {"role": "assistant", "id": mid, "model": model,
                        "usage": {"input_tokens": 0, "output_tokens": 0,
                                  "cache_creation_input_tokens": 0,
                                  "cache_read_input_tokens": cr}}}


def _p(root, *parts):
    return os.path.join(root, *parts)


class ProjectAndSessionResolution(unittest.TestCase):
    """Both helpers key off the path relative to the SCANNED ROOT, so any
    nesting depth resolves to the real project and the owning session."""

    ROOT = os.path.join("X:", os.sep, "projects")

    def test_plain_transcript(self):
        fp = _p(self.ROOT, "slug", "abc-123.jsonl")
        self.assertEqual(recap._project_of(fp, self.ROOT), "slug")
        self.assertEqual(recap._session_of(fp, self.ROOT), "abc-123")

    def test_subagent_trace(self):
        fp = _p(self.ROOT, "slug", "abc-123", "subagents", "agent-x.jsonl")
        self.assertEqual(recap._project_of(fp, self.ROOT), "slug")
        self.assertEqual(recap._session_of(fp, self.ROOT), "abc-123")

    def test_workflow_run_agent_trace(self):
        """The second shape, and the reason the rule is not a fixed level hop."""
        fp = _p(self.ROOT, "slug", "abc-123", "subagents", "workflows",
                "wf_deadbeef", "agent-y.jsonl")
        self.assertEqual(recap._project_of(fp, self.ROOT), "slug")
        self.assertEqual(recap._session_of(fp, self.ROOT), "abc-123")

    def test_arbitrary_future_nesting_still_resolves(self):
        fp = _p(self.ROOT, "slug", "abc-123", "a", "b", "c", "d", "z.jsonl")
        self.assertEqual(recap._project_of(fp, self.ROOT), "slug")
        self.assertEqual(recap._session_of(fp, self.ROOT), "abc-123")

    def test_display_prefix_is_still_stripped(self):
        # The strip prefix is derived from THIS machine's home slug
        # (recap._HOME_SLUG), never a hardcoded owner disk root -- so the
        # fixture builds the slug from that, and the assertion holds on any
        # reader's machine rather than only the packager's.
        slug = recap._HOME_SLUG + "-my-project"
        fp = _p(self.ROOT, slug, "s.jsonl")
        self.assertEqual(recap._project_of(fp, self.ROOT), "my-project")

    def test_path_outside_the_root_falls_back_instead_of_guessing(self):
        fp = os.path.join("Y:", os.sep, "elsewhere", "slug", "s.jsonl")
        self.assertEqual(recap._project_of(fp, self.ROOT), "slug")
        self.assertEqual(recap._session_of(fp, self.ROOT), "s")


class PerSession(unittest.TestCase):
    def recap_of(self, files):
        """files: {relative-path: [turn, ...]} under a throwaway projects root."""
        with tempfile.TemporaryDirectory() as root:
            for rel, turns in files.items():
                fp = os.path.join(root, *rel.split("/"))
                os.makedirs(os.path.dirname(fp), exist_ok=True)
                with open(fp, "w", encoding="utf-8") as f:
                    for t in turns:
                        f.write(json.dumps(t) + "\n")
            return recap.build_recap("7d", roots=[root])

    def test_sessions_are_listed_and_ranked_by_tokens(self):
        r = self.recap_of({
            "demo/small.jsonl": [_turn("a", cr=10)],
            "demo/big.jsonl": [_turn("b", cr=900), _turn("c", cr=100)],
        })
        got = [(s["session"], s["tokens"], s["turns"]) for s in r["per_session"]]
        self.assertEqual(got, [("big", 1000, 2), ("small", 10, 1)])

    def test_subagent_tokens_fold_into_the_parent_session(self):
        r = self.recap_of({
            "demo/sess-1.jsonl": [_turn("a", cr=100)],
            "demo/sess-1/subagents/agent-x.jsonl": [_turn("b", cr=400)],
        })
        self.assertEqual([s["session"] for s in r["per_session"]], ["sess-1"])
        self.assertEqual(r["per_session"][0]["tokens"], 500)
        self.assertEqual(r["per_session"][0]["turns"], 2)

    def test_workflow_agent_tokens_fold_into_the_parent_session(self):
        r = self.recap_of({
            "demo/sess-1.jsonl": [_turn("a", cr=100)],
            "demo/sess-1/subagents/workflows/wf_x/agent-y.jsonl":
                [_turn("b", cr=400)],
        })
        self.assertEqual([s["session"] for s in r["per_session"]], ["sess-1"])
        self.assertEqual(r["per_session"][0]["tokens"], 500)

    def test_no_tokens_are_dropped_from_per_project(self):
        """The oracle for the phantom-project class. Every nesting shape must
        land on a rendered project row; nothing may fall between the two."""
        r = self.recap_of({
            "demo/sess-1.jsonl": [_turn("a", cr=100)],
            "demo/sess-1/subagents/agent-x.jsonl": [_turn("b", cr=400)],
            "demo/sess-1/subagents/workflows/wf_x/agent-y.jsonl":
                [_turn("c", cr=1000)],
        })
        self.assertEqual(sum(p["tokens"] for p in r["per_project"]),
                         r["total_tokens"])
        self.assertEqual([p["project"] for p in r["per_project"]], ["demo"])

    def test_avg_turn_reread_is_the_cost_signal(self):
        r = self.recap_of({"demo/s.jsonl": [_turn("a", cr=300),
                                            _turn("b", cr=500)]})
        self.assertEqual(r["per_session"][0]["avg_turn_reread"], 400)

    def test_truncation_is_visible_never_silent(self):
        """A capped list that reads as the whole set is the failure mode here."""
        files = {"demo/s%02d.jsonl" % i: [_turn("m%02d" % i, cr=i + 1)]
                 for i in range(recap.PER_SESSION_TOP_N + 5)}
        r = self.recap_of(files)
        self.assertEqual(len(r["per_session"]), recap.PER_SESSION_TOP_N)
        self.assertEqual(r["per_session_total"], recap.PER_SESSION_TOP_N + 5)
        self.assertGreater(r["per_session_total"], len(r["per_session"]))


class MergePerSession(unittest.TestCase):
    @staticmethod
    def env(sessions, total=None):
        return {"total_tokens": 0, "assistant_turns": 0, "total_cost_usd": 0.0,
                "tokens": {"input": 0, "cache_creation": 0, "cache_read": 0,
                           "output": 0},
                "by_model": [], "per_project": [], "active_min": 0.0,
                "per_session": sessions,
                "per_session_total": total if total is not None
                else len(sessions)}

    @staticmethod
    def sess(name, tokens, os_="win"):
        return {"project": "p", "session": name, "tokens": tokens, "turns": 1,
                "avg_turn_reread": tokens, "os": os_}

    def test_remote_sessions_are_tagged_with_the_remote_machine(self):
        r = recap.merge_recap(self.env([self.sess("local", 10)]),
                              self.env([self.sess("remote", 20)]),
                              machine="company")
        by = {s["session"]: s["os"] for s in r["per_session"]}
        self.assertEqual(by, {"local": "win", "remote": "company"})

    def test_merged_list_is_re_ranked_across_machines(self):
        r = recap.merge_recap(self.env([self.sess("local", 10)]),
                              self.env([self.sess("remote", 99)]))
        self.assertEqual([s["session"] for s in r["per_session"]],
                         ["remote", "local"])

    def test_merged_list_is_re_truncated_but_the_total_still_adds(self):
        n = recap.PER_SESSION_TOP_N
        a = self.env([self.sess("a%d" % i, 1000 + i) for i in range(n)], total=50)
        b = self.env([self.sess("b%d" % i, 2000 + i) for i in range(n)], total=70)
        r = recap.merge_recap(a, b)
        self.assertEqual(len(r["per_session"]), n)
        self.assertEqual(r["per_session_total"], 120)
        self.assertTrue(all(s["session"].startswith("b")
                            for s in r["per_session"]))

    def test_legacy_remote_without_per_session_folds_cleanly(self):
        r = recap.merge_recap(self.env([self.sess("local", 10)], total=3),
                              {"total_tokens": 0, "by_model": []})
        self.assertEqual([s["session"] for s in r["per_session"]], ["local"])
        self.assertEqual(r["per_session_total"], 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
