"""The per-turn cost axis on the session rows (KB ticket asm-009, part A).

`claude_context_pct` has always computed two numbers and every caller kept only
one: `pct`, occupancy of the model's window. That answers "will this session
overflow". It does not answer "how expensive is a turn", and with a 1M window
the two questions came apart -- a 306k-token turn is 31% (grey badge) yet the
whole 306k is re-read on every single turn, which is where the cost actually
goes. `occ` was already sitting there, discarded, so the rows now carry it as
`ctx_tokens`.

Three row builders expose it, and each needs its own oracle: dropping
`ctx_tokens` from `collect_claude` was caught only after a mutation run showed
part A had NO coverage at all, and a codex review of PR #15 (XAI-004) then
showed the same mutation still survived in `session_detail` and
`cockpit_cards`. One covered caller is not coverage of the field.

Run:  python -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import monitor  # noqa: E402

LIMITS = {"claude-opus-5": 1000000, "default": 200000}


def _assistant(mid="m1", model="claude-opus-5", inp=0, cr=0, cw=0, out=0):
    ts = (datetime.now(timezone.utc) - timedelta(minutes=1)) \
        .isoformat().replace("+00:00", "Z")
    return {"timestamp": ts, "type": "assistant",
            "message": {"role": "assistant", "id": mid, "model": model,
                        "usage": {"input_tokens": inp,
                                  "cache_read_input_tokens": cr,
                                  "cache_creation_input_tokens": cw,
                                  "output_tokens": out}}}


class _Fixture(unittest.TestCase):
    """A throwaway projects root with one session. Never touches ~/.claude."""

    def cfg_and_root(self, stack, rec):
        root = stack.enter_context(tempfile.TemporaryDirectory())
        proj = os.path.join(root, "demo-project")
        os.makedirs(proj)
        with open(os.path.join(proj, "sess-1.jsonl"), "w",
                  encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
        cfg = dict(monitor._CONFIG_DEFAULTS)
        cfg["claude_projects"] = [root]
        cfg["context_limits"] = dict(LIMITS)
        return cfg


class ContextPct(unittest.TestCase):
    def occ_of(self, rec):
        with tempfile.TemporaryDirectory() as d:
            fp = os.path.join(d, "s.jsonl")
            with open(fp, "w", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
            return monitor.claude_context_pct(fp, LIMITS)

    def test_occ_is_everything_that_gets_re_sent_next_turn(self):
        cx = self.occ_of(_assistant(inp=1000, cr=300000, cw=5000, out=999))
        self.assertEqual(cx["occ"], 306000)

    def test_output_tokens_are_excluded_from_occ(self):
        """Output is generated, not re-sent -- it is not next turn's context."""
        a = self.occ_of(_assistant(inp=10, cr=20, cw=30, out=0))
        b = self.occ_of(_assistant(inp=10, cr=20, cw=30, out=999999))
        self.assertEqual(a["occ"], b["occ"])

    def test_a_costly_turn_can_still_look_calm_as_a_percentage(self):
        """The reason ctx_tokens exists, as an assertion rather than a comment:
        306k re-read every turn shows up as a quiet 31% of a 1M window."""
        cx = self.occ_of(_assistant(cr=306000))
        self.assertEqual(cx["occ"], 306000)
        self.assertEqual(cx["pct"], 31)
        self.assertLess(cx["pct"], 60)  # below even the amber ctx threshold


class _RowBuilder(unittest.TestCase):
    """Shared fixture for the three callers that build a session row."""

    REC = None  # set per subclass call

    def build(self, rec):
        raise NotImplementedError

    def rows_for(self, rec):
        with tempfile.TemporaryDirectory() as root:
            proj = os.path.join(root, "demo-project")
            os.makedirs(proj)
            with open(os.path.join(proj, "sess-1.jsonl"), "w",
                      encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
            cfg = dict(monitor._CONFIG_DEFAULTS)
            cfg["claude_projects"] = [root]
            cfg["context_limits"] = dict(LIMITS)
            return self.build(cfg)


class SessionTableRow(_RowBuilder):
    """collect_claude -> the main session table."""

    def build(self, cfg):
        return monitor.collect_claude(cfg, time.time())

    def test_row_carries_the_absolute_token_count(self):
        rows = self.rows_for(_assistant(inp=1000, cr=300000, cw=5000, out=10))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ctx_tokens"], 306000)

    def test_the_percentage_signal_is_untouched(self):
        """ctxBadge's input must keep meaning exactly what it meant before."""
        rows = self.rows_for(_assistant(inp=1000, cr=300000, cw=5000, out=10))
        self.assertEqual(rows[0]["ctx"], 31)

    def test_the_two_signals_are_different_numbers(self):
        rows = self.rows_for(_assistant(cr=306000))
        self.assertNotEqual(rows[0]["ctx"], rows[0]["ctx_tokens"])


class SessionDetailRow(_RowBuilder):
    """session_detail -> the single-session deep view (codex XAI-004)."""

    def build(self, cfg):
        return monitor.session_detail(cfg, "sess-1")

    def test_detail_carries_the_absolute_token_count(self):
        d = self.rows_for(_assistant(inp=1000, cr=300000, cw=5000, out=10))
        self.assertEqual(d["ctx_tokens"], 306000)

    def test_detail_keeps_the_percentage_too(self):
        d = self.rows_for(_assistant(inp=1000, cr=300000, cw=5000, out=10))
        self.assertEqual(d["ctx"], 31)


class CockpitCardRow(_RowBuilder):
    """cockpit_cards -> the cockpit view (codex XAI-004)."""

    def build(self, cfg):
        return monitor.cockpit_cards(cfg)

    def cards(self, rec):
        return [c for c in self.rows_for(rec)["cards"]
                if c.get("source") == "claude"]

    def test_card_carries_the_absolute_token_count(self):
        cards = self.cards(_assistant(inp=1000, cr=300000, cw=5000, out=10))
        self.assertEqual(len(cards), 1)
        self.assertEqual(cards[0]["ctx_tokens"], 306000)

    def test_card_keeps_the_percentage_too(self):
        cards = self.cards(_assistant(inp=1000, cr=300000, cw=5000, out=10))
        self.assertEqual(cards[0]["ctx"], 31)


if __name__ == "__main__":
    unittest.main(verbosity=2)
