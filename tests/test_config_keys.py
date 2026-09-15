"""A key the template gained later must be reported, including a nested one.

config.json is per-machine and gitignored, so it is created once by copying the
template and never updated again. A `git pull` delivers code that reads a new
key but nothing delivers the key, and `(cfg.get("x") or {}).get("enabled")`
reads a missing key as "disabled" -- the feature lands switched off in silence.

The nested case is the one worth a test. A top-level-only comparison reports a
config holding `{"codex_poll": {}}` as CLEAN while every setting inside it is
absent, so the check would pass while the property it exists to protect is
false. That specific false pass is what `test_nested_gap_*` pins down.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import check_config_keys  # noqa: E402


class KeyPaths(unittest.TestCase):
    def test_nested_dicts_become_dotted_paths(self):
        self.assertEqual(
            check_config_keys.key_paths({"a": {"b": 1}, "c": 2}),
            ["a", "a.b", "c"])

    def test_lists_are_values_not_schema(self):
        # A list's elements are data the machine supplies; `p[0]` is not a key
        # the template promises, so its absence is not drift.
        self.assertEqual(check_config_keys.key_paths({"p": [{"q": 1}]}), ["p"])


class MissingKeyPaths(unittest.TestCase):
    def test_nested_gap_is_reported(self):
        missing = check_config_keys.missing_key_paths(
            {"codex_poll": {"enabled": True, "interval_seconds": 300}, "other": 1},
            {"codex_poll": {}, "other": 1})
        self.assertEqual(missing, ["codex_poll.enabled", "codex_poll.interval_seconds"])

    def test_nested_gap_is_invisible_to_a_top_level_comparison(self):
        # Pins the false pass this checker exists to prevent: the naive version
        # of this check sees nothing wrong with the same input.
        template = {"codex_poll": {"enabled": True}, "other": 1}
        config = {"codex_poll": {}, "other": 1}
        self.assertEqual([k for k in template if k not in config], [])
        self.assertTrue(check_config_keys.missing_key_paths(template, config))

    def test_template_dict_against_config_scalar_reports_the_subtree(self):
        self.assertEqual(
            check_config_keys.missing_key_paths({"a": {"b": 1}}, {"a": 5}),
            ["a.b"])

    def test_values_never_matter(self):
        # local_machine and alerts_enabled are SUPPOSED to differ per machine
        # (hub vs spoke). A value diff is configuration, not drift.
        self.assertEqual(
            check_config_keys.missing_key_paths(
                {"local_machine": "win", "alerts_enabled": True},
                {"local_machine": "mac", "alerts_enabled": False}),
            [])


class CheckReadsFiles(unittest.TestCase):
    def test_unreadable_file_is_returned_as_an_error_not_raised(self):
        # load_config() owns fail-loud for a missing config; this advisory check
        # must not raise a second, different exception for the same condition.
        with tempfile.TemporaryDirectory() as d:
            tpl = os.path.join(d, "tpl.json")
            with open(tpl, "w", encoding="utf-8") as fh:
                json.dump({"a": 1}, fh)
            missing, err = check_config_keys.check(tpl, os.path.join(d, "nope.json"))
            self.assertEqual(missing, [])
            self.assertIn("FileNotFoundError", err)


if __name__ == "__main__":
    unittest.main()
