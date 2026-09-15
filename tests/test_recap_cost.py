"""Cost-model tests for recap.py (KB ticket asm-008).

Why this file exists, and why it is the first test file in this repo: the two
defects asm-008 fixed were both SILENT financial under-reports -- the numbers
stayed plausible and nothing errored. A third instance of the same class was
then introduced by the fix itself and caught only by external review (codex,
PR #14 XAI-001): on the cross-version merge path an unknown cost plus a legacy
remote's 0.0 quietly became 0.0 again.

That is the specific reason "evidence in the PR description is enough" does not
hold here -- the missing test IS the thing that would have caught it. Worse,
the ad-hoc suite running at the time asserted `None + 2.5 -> 2.5` as CORRECT,
so the wrong behaviour was encoded in the oracle and the run was green.

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


def _turn(mid, model, inp=0, cr=0, out=0, cw=None, h1=None, m5=None):
    """One assistant transcript line. `cw` is the aggregate; h1/m5 the TTL split.
    Leave both h1 and m5 as None to omit the `cache_creation` sub-object
    entirely (the pre-split shape), which must fall back to the flat rate."""
    usage = {"input_tokens": inp, "cache_read_input_tokens": cr,
             "output_tokens": out,
             "cache_creation_input_tokens": (cw if cw is not None else 0)}
    if h1 is not None or m5 is not None:
        usage["cache_creation"] = {"ephemeral_1h_input_tokens": h1 or 0,
                                   "ephemeral_5m_input_tokens": m5 or 0}
    ts = datetime.now(timezone.utc) - timedelta(minutes=5)
    return {"timestamp": ts.isoformat().replace("+00:00", "Z"),
            "type": "assistant",
            "message": {"role": "assistant", "id": mid, "model": model,
                        "usage": usage}}


class FixtureRecap(unittest.TestCase):
    """build_recap over a throwaway projects tree. Never touches ~/.claude."""

    def recap_of(self, turns):
        with tempfile.TemporaryDirectory() as root:
            proj = os.path.join(root, "demo-project")
            os.makedirs(proj)
            with open(os.path.join(proj, "s.jsonl"), "w", encoding="utf-8") as f:
                for t in turns:
                    f.write(json.dumps(t) + "\n")
            return recap.build_recap("7d", roots=[root])

    # ---- D1: cache writes are priced by TTL -----------------------------
    def test_one_hour_write_is_2x_base_input(self):
        r = self.recap_of([_turn("a", "claude-opus-5", cw=1000000, h1=1000000)])
        self.assertAlmostEqual(r["total_cost_usd"], 30.0, places=4)
        self.assertEqual(r["cache_creation_ttl"]["h1"], 1000000)
        self.assertEqual(r["cache_creation_ttl"]["m5"], 0)

    def test_five_minute_write_is_1_25x_base_input(self):
        r = self.recap_of([_turn("a", "claude-opus-5", cw=1000000, m5=1000000)])
        self.assertAlmostEqual(r["total_cost_usd"], 18.75, places=4)

    def test_the_two_ttls_are_not_the_same_price(self):
        """The whole defect in one assertion: before asm-008 both were 18.75."""
        h = self.recap_of([_turn("a", "claude-opus-5", cw=1000000, h1=1000000)])
        m = self.recap_of([_turn("a", "claude-opus-5", cw=1000000, m5=1000000)])
        self.assertNotEqual(h["total_cost_usd"], m["total_cost_usd"])

    def test_missing_sub_object_falls_back_to_flat_rate_and_is_reported(self):
        r = self.recap_of([_turn("a", "claude-opus-5", cw=1000000)])
        self.assertAlmostEqual(r["total_cost_usd"], 18.75, places=4)
        self.assertEqual(r["cache_creation_ttl"]["unsplit"], 1000000)

    def test_sub_object_disagreeing_with_aggregate_is_counted_not_swallowed(self):
        """Measured 3x in 39,174 real turns, so it is not hypothetical."""
        r = self.recap_of([_turn("a", "claude-opus-5", cw=250950, h1=335046)])
        self.assertEqual(r["cache_creation_ttl"]["mismatch_turns"], 1)

    # ---- D2: an unpriced model must not read as free --------------------
    def test_unpriced_model_cost_is_none_not_zero(self):
        r = self.recap_of([_turn("a", "claude-fable-5", cr=1000000)])
        self.assertIsNone(r["by_model"][0]["cost"])
        self.assertIn("claude-fable-5", r["unpriced_models"])

    def test_unpriced_tokens_still_counted_only_the_cost_is_unknown(self):
        r = self.recap_of([_turn("a", "claude-fable-5", cr=1000000)])
        self.assertEqual(r["tokens"]["cache_read"], 1000000)
        self.assertEqual(r["total_cost_usd"], 0.0)  # nothing priceable was seen

    def test_zero_token_model_does_not_raise_the_banner(self):
        """`<synthetic>` carries 0 tokens; a banner that always fires is noise."""
        r = self.recap_of([_turn("a", "<synthetic>"),
                           _turn("b", "claude-opus-5", cr=1000000)])
        self.assertEqual(r["unpriced_models"], [])

    # ---- the regression guard: only COST may move -----------------------
    def test_token_buckets_are_untouched_by_the_pricing_change(self):
        r = self.recap_of([
            _turn("a", "claude-opus-5", inp=11, cr=22, out=33, cw=44, h1=40, m5=4),
            _turn("b", "claude-sonnet-5", inp=1, cr=2, out=3, cw=4, m5=4),
        ])
        self.assertEqual(r["tokens"], {"input": 12, "cache_creation": 48,
                                       "cache_read": 24, "output": 36})
        self.assertEqual(r["assistant_turns"], 2)

    def test_streaming_duplicates_are_deduped_by_message_id(self):
        t = _turn("same-id", "claude-opus-5", cr=1000000)
        r = self.recap_of([t, dict(t), dict(t)])
        self.assertEqual(r["assistant_turns"], 1)


class MergeRecap(unittest.TestCase):
    """merge_recap folds a remote machine's pre-aggregated recap into a local
    one. The remote may still be running pre-asm-008 code."""

    @staticmethod
    def env(model, cost, **extra):
        return {"total_tokens": 1, "assistant_turns": 1, "total_cost_usd": 0.0,
                "tokens": {"input": 0, "cache_creation": 0, "cache_read": 0,
                           "output": 0},
                "by_model": [{"model": model, "turns": 1, "tokens": 1,
                              "cost": cost}],
                "per_project": [], "active_min": 0.0, **extra}

    def merged_cost(self, local, remote):
        return recap.merge_recap(self.env("m", local),
                                 self.env("m", remote))["by_model"][0]["cost"]

    def test_unknown_plus_unknown_stays_unknown(self):
        self.assertIsNone(self.merged_cost(None, None))

    def test_unknown_plus_known_stays_unknown(self):
        """Returning the known half as if it were the total under-reports --
        the same failure mode asm-008 exists to remove."""
        self.assertIsNone(self.merged_cost(None, 2.5))
        self.assertIsNone(self.merged_cost(1.25, None))

    def test_new_side_unknown_plus_legacy_remote_zero_stays_unknown(self):
        """codex PR #14 XAI-001. A remote on pre-asm-008 code sends 0.0 for an
        unpriced model; `(None or 0.0) + 0.0` used to resurrect the silent 0."""
        self.assertIsNone(self.merged_cost(None, 0.0))

    def test_known_plus_known_adds(self):
        self.assertAlmostEqual(self.merged_cost(1.25, 2.5), 3.75)

    def test_a_real_zero_is_still_a_number(self):
        self.assertEqual(self.merged_cost(0.0, 0.0), 0.0)

    def test_unpriced_models_union_is_sorted_and_deduped(self):
        r = recap.merge_recap(self.env("m", None, unpriced_models=["b"]),
                              self.env("m", None, unpriced_models=["a", "b"]))
        self.assertEqual(r["unpriced_models"], ["a", "b"])

    def test_legacy_remote_without_the_new_fields_folds_cleanly(self):
        r = recap.merge_recap(
            self.env("m", 1.0, unpriced_models=["x"],
                     cache_creation_ttl={"h1": 1, "m5": 2, "unsplit": 3,
                                         "mismatch_turns": 4}),
            {"total_tokens": 1,
             "by_model": [{"model": "m", "turns": 1, "tokens": 1,
                           "cost": 0.5}]})
        self.assertEqual(r["unpriced_models"], ["x"])
        self.assertEqual(r["cache_creation_ttl"],
                         {"h1": 1, "m5": 2, "unsplit": 3, "mismatch_turns": 4})
        self.assertAlmostEqual(r["by_model"][0]["cost"], 1.5)

    def test_ttl_counters_sum(self):
        r = recap.merge_recap(
            self.env("m", 1.0, cache_creation_ttl={"h1": 1, "m5": 2,
                                                   "unsplit": 3,
                                                   "mismatch_turns": 4}),
            self.env("m", 1.0, cache_creation_ttl={"h1": 10, "m5": 20,
                                                   "unsplit": 30,
                                                   "mismatch_turns": 40}))
        self.assertEqual(r["cache_creation_ttl"],
                         {"h1": 11, "m5": 22, "unsplit": 33,
                          "mismatch_turns": 44})


if __name__ == "__main__":
    unittest.main(verbosity=2)
