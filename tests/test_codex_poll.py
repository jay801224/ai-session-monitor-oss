"""The codex-poll caller must not fail silently.

Three of these pin fixes for findings a codex review raised against the first
version (report/feedback_codex_20260826T162029Z.md). Each one is written so the
PRE-FIX behaviour goes red -- verified by mutation, not by reading:

  F4  the loop floored the interval at 60s but recorded the raw value, so a
      config of 5 ran every 60s while the card said "every 5s".
  F2  the summary dropped a falsy correlation key, while the poller keys on
      `is None` -- so an empty-string id was a judged dispatch over there and an
      invisible one here.
  F1  a state write that could not land was swallowed, leaving the previous
      `ok: true` record standing. The card then shows a success that stopped
      happening. It raises now; the card's staleness rule is the visible half.

Run: python tests/test_codex_poll.py
"""
import io
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import monitor  # noqa: E402

FAILED = []


def check(label, got, want):
    if got != want:
        FAILED.append("%s: got %r want %r" % (label, got, want))
        print("FAIL %-52s got=%r want=%r" % (label, got, want))
    else:
        print("ok   %s" % label)


def scenario_interval_floor_is_what_gets_recorded(tmp):
    check("interval 5 -> effective 60",
          monitor._codex_poll_interval({"codex_poll": {"interval_seconds": 5}}), 60)
    check("interval 300 -> 300",
          monitor._codex_poll_interval({"codex_poll": {"interval_seconds": 300}}), 300)
    check("unparseable interval -> default 300",
          monitor._codex_poll_interval({"codex_poll": {"interval_seconds": "x"}}), 300)


def scenario_empty_string_id_is_a_key_not_unkeyed(tmp):
    """`""` is a real key to the poller (it tests `k is None`), so the summary
    must agree or the two disagree about the same row."""
    led = os.path.join(tmp, "ledger.jsonl")
    rows = [
        {"ts": "t1", "client_user_message_id": "", "branch": "b-empty"},
        {"ts": "t2", "client_user_message_id": None, "branch": "b-null"},
        {"ts": "t3", "client_user_message_id": "cc-real", "branch": "b-real"},
        {"ts": "t4", "kind": "poll", "client_user_message_id": "cc-real",
         "state": "done", "reason": "r"},
    ]
    io.open(led, "w", encoding="utf-8").write(
        "\n".join(json.dumps(r) for r in rows))
    s = monitor._codex_ledger_summary(led)
    check("empty-string id counts as a dispatch", s["total"], 2)
    check("only the None id is unkeyed", s["unkeyed"], 1)
    check("a dispatch with no verdict reads un-judged, not pending",
          sorted(r["state"] for r in s["rows"]), ["done", "un-judged"])


def scenario_unwritable_state_raises(tmp):
    """The blocked step has to be the WRITE. A path that already dies in
    makedirs would go red for a swallowing implementation too, and would pin
    nothing."""
    saved = monitor._CODEX_POLL_PATH
    blocked = os.path.join(tmp, "blocked", "state.json")
    os.makedirs(blocked + ".tmp", exist_ok=True)   # a DIR where the temp file goes
    monitor._CODEX_POLL_PATH = blocked
    raised = None
    try:
        monitor._codex_poll_write({"ts": "x"})
    except Exception as e:  # noqa: BLE001 — the type is not the point, raising is
        raised = type(e).__name__
    finally:
        monitor._CODEX_POLL_PATH = saved
    check("an unwritable state file raises rather than leaving a stale record",
          raised is not None, True)


def scenario_disabled_yields_no_record(tmp):
    check("disabled config sweeps nothing",
          monitor._codex_poll_once({"codex_poll": {"enabled": False}}), None)
    check("absent config sweeps nothing", monitor._codex_poll_once({}), None)


def test_codex_poll_checks_pass():
    """pytest entry: run every scenario in a fresh tempdir and assert none FAILED."""
    assert main() == 0


def main():
    with tempfile.TemporaryDirectory() as tmp:
        for fn in (scenario_interval_floor_is_what_gets_recorded,
                   scenario_empty_string_id_is_a_key_not_unkeyed,
                   scenario_unwritable_state_raises,
                   scenario_disabled_yields_no_record):
            fn(tmp)
    if FAILED:
        print("\n%d FAILED" % len(FAILED))
        return 1
    print("\nall codex-poll checks pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
