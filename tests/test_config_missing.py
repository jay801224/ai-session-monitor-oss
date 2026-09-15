"""An unreadable config.json must fail loudly, and fail in a catchable way.

config.json is gitignored and per-machine now, so "absent" is a state every fresh
clone starts in -- and on Windows the daemon runs under pythonw, where a bare
traceback goes to a console nobody is looking at.
"""
import http.server
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import monitor


class ConfigMissing(unittest.TestCase):
    def setUp(self):
        self._original = monitor.CONFIG_PATH
        self.addCleanup(setattr, monitor, "CONFIG_PATH", self._original)

    def test_message_names_the_file_and_the_fix(self):
        monitor.CONFIG_PATH = os.path.join(
            os.path.dirname(self._original), "no_such_config.json")
        with self.assertRaises(monitor.ConfigError) as caught:
            monitor.load_config()
        message = str(caught.exception)
        self.assertIn("no_such_config.json", message)
        self.assertIn("cp config.template.json config.json", message)

    def test_catchable_by_the_loop_guards(self):
        """The background loops guard with `except Exception` and their comments say
        "must never crash the server". SystemExit is a BaseException and would slip
        past all of them, killing alert_loop / office_pull_loop / tg_poll_loop /
        hooks_snapshot_loop while the process stayed bound to the port. This is the
        regression that lock exists for -- not "does it raise"."""
        self.assertTrue(issubclass(monitor.ConfigError, Exception))
        monitor.CONFIG_PATH = os.path.join(
            os.path.dirname(self._original), "no_such_config.json")
        try:
            monitor.load_config()
        except Exception:  # noqa: BLE001 — the guard being asserted is this broad
            return
        self.fail("load_config() did not raise for a missing config")

    def test_malformed_json_is_not_swallowed(self):
        """ADR-008: a config that cannot be parsed must fail, never fall back to
        defaults -- alerts_enabled quietly reverting to True is the failure mode the
        flag exists to prevent. Distinct from the missing-file case: this one goes
        through json.load, not the open()."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                         encoding="utf-8") as f:
            f.write("{ this is not json")
            broken = f.name
        self.addCleanup(os.unlink, broken)
        monitor.CONFIG_PATH = broken
        with self.assertRaises(json.JSONDecodeError):
            monitor.load_config()


class ConfigMissingAtRuntime(unittest.TestCase):
    """The config is re-read per request, so it can vanish under a LIVE server.

    Before this lock, ConfigError escaped do_GET/do_POST -- outside any handler
    try/except -- and aborted the request thread, so the browser got a bare
    connection reset with no hint that the config was the problem.
    """

    def test_get_answers_503_with_the_actionable_message(self):
        original = monitor.CONFIG_PATH
        monitor.CONFIG_PATH = os.path.join(
            os.path.dirname(original), "no_such_config.json")
        self.addCleanup(setattr, monitor, "CONFIG_PATH", original)
        # port 0 = ephemeral: never collides with the 8787 production daemon
        # (CONTEXT.md "one instance per port at a time").
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), monitor.Handler)
        self.addCleanup(srv.server_close)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        url = "http://127.0.0.1:%d/" % srv.server_address[1]
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(url, timeout=5)
        self.assertEqual(503, caught.exception.code)
        self.assertIn("cp config.template.json config.json",
                      caught.exception.read().decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
