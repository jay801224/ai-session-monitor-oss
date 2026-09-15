"""A vendor schema change must read as "unknown", never as "no DB here".

`_codex_state_db` returns a path or None, and before the status split those two
Nones were the same value:

  - a synced ~/.codex-mac root legitimately has no state_*.sqlite (Syncthing
    carries the one jsonl and correctly excludes the live WAL-backed DBs), and
  - a codex upgrade that renames `threads` makes every candidate lose.

Both fell back to the index. The first is correct; the second shows a frozen
snapshot with no error anywhere -- present-but-stale passing every check. The
rule these tests pin is the one `codex_dispatch_poll.py` already states: a check
that could not be ESTABLISHED never degrades into a business state.

NOTE on fixtures: every temp path goes through os.path.realpath first. On macOS
tempfile hands back /var/folders/..., /var is a symlink to /private/var, and
`_is_unredirected_path` rejects any path whose realpath differs from itself --
so an unresolved fixture path is rejected for PROVENANCE and lands on "unknown"
for the wrong reason, making the schema test pass without testing anything.
"""
import os
import sqlite3
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import monitor  # noqa: E402


def probe(directory):
    monitor._codex_db_cache.clear()
    return monitor._codex_db_probe(
        os.path.join(os.path.realpath(directory), "session_index.jsonl"))


def write_db(directory, table):
    path = os.path.join(os.path.realpath(directory), "state_5.sqlite")
    conn = sqlite3.connect(path)
    try:
        conn.execute("CREATE TABLE %s (id TEXT, updated_at REAL)" % table)
        conn.execute("INSERT INTO %s VALUES ('x', ?)" % table, (time.time(),))
        conn.commit()
    finally:
        conn.close()
    return path


class CodexDbStatus(unittest.TestCase):
    def test_no_candidate_at_all_is_absent(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(probe(d), (None, "absent"))

    def test_usable_threads_table_is_ok(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_db(d, "threads")
            self.assertEqual(probe(d), (path, "ok"))

    def test_renamed_table_is_unknown_not_absent(self):
        # The load-bearing one: a candidate EXISTS, so "there is no DB here" is
        # a false statement, and saying it would send the dashboard to a stale
        # index without a word.
        with tempfile.TemporaryDirectory() as d:
            write_db(d, "conversations")
            self.assertEqual(probe(d), (None, "unknown"))

    def test_the_three_states_are_distinguishable(self):
        # Guards against a future simplification that collapses them back.
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b, \
                tempfile.TemporaryDirectory() as c:
            write_db(b, "threads")
            write_db(c, "conversations")
            self.assertEqual(
                sorted({probe(a)[1], probe(b)[1], probe(c)[1]}),
                ["absent", "ok", "unknown"])

    def test_selector_and_status_share_one_probe(self):
        # The fixture MUST change between the two calls, or the assertion is
        # vacuous: with an unchanged root, a status accessor that re-probed
        # independently would return the same answer and pass anyway. Swapping
        # the DB is what makes "shared cache" and "second probe" diverge --
        # shared says ok (the cached selection), independent says unknown.
        with tempfile.TemporaryDirectory() as d:
            path = write_db(d, "threads")
            index = os.path.join(os.path.realpath(d), "session_index.jsonl")
            monitor._codex_db_cache.clear()
            self.assertEqual(monitor._codex_state_db(index), path)
            os.remove(path)
            write_db(d, "conversations")  # same filename, no threads table
            self.assertEqual(monitor._codex_db_status(index), "ok")

    def test_a_second_independent_probe_would_have_disagreed(self):
        # Pins the counterexample above as a real divergence and not a story:
        # clearing the cache between the two calls DOES flip the answer.
        with tempfile.TemporaryDirectory() as d:
            path = write_db(d, "threads")
            index = os.path.join(os.path.realpath(d), "session_index.jsonl")
            monitor._codex_db_cache.clear()
            monitor._codex_state_db(index)
            os.remove(path)
            write_db(d, "conversations")
            monitor._codex_db_cache.clear()
            self.assertEqual(monitor._codex_db_status(index), "unknown")


class CodexSourceReachesTheScreen(unittest.TestCase):
    """The status must survive into the published flag, not stop at the probe.

    Computing a trichotomy nothing consumes leaves the two fallbacks identical
    on the dashboard, which is the exact condition the split exists to end.
    These assert the OBSERVABLE value, not the helper's return.
    """

    def setUp(self):
        monitor._codex_db_cache.clear()
        monitor._CODEX_SOURCE.clear()
        self.addCleanup(monitor._CODEX_SOURCE.clear)
        self.addCleanup(monitor._codex_db_cache.clear)

    def collect(self, directory):
        index = os.path.join(os.path.realpath(directory), "session_index.jsonl")
        open(index, "a", encoding="utf-8").close()
        monitor.collect_codex(
            {"codex_session_index": [index], "max_rows_per_source": 10, "max_age_hours": 6},
            time.time())
        return monitor._CODEX_SOURCE.get("_shown")

    def test_root_with_no_db_publishes_index_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.collect(d), "index-fallback")

    def test_root_whose_db_is_unreadable_publishes_db_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            write_db(d, "conversations")  # vendor renamed `threads`
            self.assertEqual(self.collect(d), "db-unknown")

    def test_the_two_fallbacks_are_not_the_same_published_value(self):
        # Without this the split is invisible where it matters. Both roots fall
        # back to the index; only one of them is a problem.
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            write_db(b, "conversations")
            self.assertNotEqual(self.collect(a), self.collect(b))


if __name__ == "__main__":
    unittest.main()
