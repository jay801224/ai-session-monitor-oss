"""Command-drop transport — signed commands over a shared (Syncthing) folder.

C0 transport for Phase C. The hub writes a signed command FILE into a shared
folder that Syncthing replicates to the Mac spoke; the spoke validates + executes
exactly once + writes a signed ACK file back. Poll-based, no inbound port, reuses
the existing in-home Syncthing TLS+device-auth transport (KB:
crossmachine-syncthing-requirements — currently a one-way Mac->Win folder; this
needs a NEW send-receive folder, see the setup note at the bottom).

Layout under <root> (the synced folder):
    <root>/cmd/<cmd_id>.json   command envelopes (hub -> spoke)
    <root>/ack/<cmd_id>.json   ack envelopes     (spoke -> hub)

Why files, not a queue: Syncthing already gives us an authenticated, encrypted,
no-inbound-port channel between exactly these two machines. A file per cmd_id is
naturally idempotent (re-sync of the same file is the same cmd_id -> the ledger
dedupes it). Exactly-once EXECUTION comes from command.Ledger, NOT from the
transport, so lazy GC of old files is safe.

This module is transport-specific (file I/O) but swappable: a LAN-HTTP transport
would expose the same publish/poll/ack verbs. It does NOT touch monitor's live
threads — wiring that in needs the Syncthing folder to exist + a restart + the
Mac-native dispatch (C-Mac). Pure Python standard library.
"""
from __future__ import annotations

import glob
import json
import os
import time

import office     # sign / verify (HMAC envelope) — command channel uses the CMD key
import command    # make_command / validate / Ledger

ACK_KIND = "ack"


# ---------------------------------------------------------------------------
# atomic file drop helpers
# ---------------------------------------------------------------------------
def _ensure(root):
    cmd_dir = os.path.join(root, "cmd")
    ack_dir = os.path.join(root, "ack")
    os.makedirs(cmd_dir, exist_ok=True)
    os.makedirs(ack_dir, exist_ok=True)
    return cmd_dir, ack_dir


def _atomic_write_json(path, obj):
    """Write obj as JSON to path atomically. The reader globs *.json only, so the
    .tmp is never seen mid-write; os.replace makes the final swap atomic."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
    os.replace(tmp, path)


def _read_envelopes(d):
    """Yield (cmd_id, envelope_dict) for each readable *.json under d. Unreadable /
    malformed files are skipped (never raise) — a half-synced file just waits for
    the next poll. cmd_id is taken from the filename (the source of truth is the
    signed envelope, re-checked by validate)."""
    out = []
    for p in sorted(glob.glob(os.path.join(d, "*.json"))):
        cmd_id = os.path.splitext(os.path.basename(p))[0]
        try:
            with open(p, "r", encoding="utf-8") as f:
                out.append((cmd_id, json.load(f), p))
        except (OSError, json.JSONDecodeError, ValueError):
            continue
    return out


# ---------------------------------------------------------------------------
# hub side: publish a command, collect acks
# ---------------------------------------------------------------------------
def publish_command(root, msg, cmd_secret):
    """Sign msg (a command dict from command.make_command) with the CMD key and drop
    it as <root>/cmd/<cmd_id>.json. Returns the cmd_id."""
    cmd_dir, _ = _ensure(root)
    env = office.sign(msg, cmd_secret)
    _atomic_write_json(os.path.join(cmd_dir, msg["cmd_id"] + ".json"), env)
    return msg["cmd_id"]


def poll_acks(root, cmd_secret):
    """Return {cmd_id: ack_msg} for every authentic ack currently in <root>/ack/.
    An ack with a bad signature / wrong kind is dropped (fail-closed)."""
    _, ack_dir = _ensure(root)
    acks = {}
    for cmd_id, env, _p in _read_envelopes(ack_dir):
        msg = office.verify(env, cmd_secret)
        if msg is None or msg.get("kind") != ACK_KIND:
            continue
        if msg.get("cmd_id") == cmd_id:           # filename must match signed body
            acks[cmd_id] = msg
    return acks


# ---------------------------------------------------------------------------
# spoke side: process pending commands exactly once, ack each
# ---------------------------------------------------------------------------
def process_pending(root, cmd_secret, this_machine, ledger, dispatch, now=None):
    """Validate + run every pending command addressed to this_machine, exactly once,
    and write a signed ack for each. Returns a list of per-command outcome dicts.

    - dispatch(msg) -> result dict, called AT MOST once per cmd_id (command.Ledger).
      A re-synced duplicate file returns the cached ack and re-writes it (idempotent).
    - A command that fails validation (bad sig / unknown verb / wrong target / expired
      / bad args) is NOT executed and NOT acked as success — it gets a 'rejected' ack
      so the hub learns why, and the file is left for GC. Fail-closed throughout."""
    if now is None:
        now = time.time()
    cmd_dir, _ = _ensure(root)
    outcomes = []
    for cmd_id, env, _p in _read_envelopes(cmd_dir):
        msg, reason = command.validate(env, cmd_secret, this_machine, now=now)
        if msg is None:
            # Only ack rejections we can attribute to THIS machine's cmd_id namespace;
            # a wrong-target command is silently ignored (it's for another spoke).
            if reason != "wrong-target":
                _write_ack(root, cmd_id, this_machine, cmd_secret,
                           result="rejected", detail=reason, now=now)
            outcomes.append({"cmd_id": cmd_id, "ran": False, "result": "rejected", "detail": reason})
            continue
        result, did_run = ledger.run_once(msg, dispatch)
        _write_ack(root, cmd_id, this_machine, cmd_secret,
                   result=result.get("result", "ok"), detail=result.get("detail", ""),
                   payload=result, now=now)
        outcomes.append({"cmd_id": cmd_id, "ran": did_run, "result": result.get("result", "ok"),
                         "detail": result.get("detail", "")})
    return outcomes


def _write_ack(root, cmd_id, machine, cmd_secret, result, detail="", payload=None, now=None):
    if now is None:
        now = time.time()
    _, ack_dir = _ensure(root)
    ack = {"schema": office.SCHEMA, "kind": ACK_KIND, "cmd_id": cmd_id,
           "machine": machine, "result": result, "detail": detail,
           "payload": payload or {}, "completed_at": now}
    env = office.sign(ack, cmd_secret)
    _atomic_write_json(os.path.join(ack_dir, cmd_id + ".json"), env)


# ---------------------------------------------------------------------------
# lazy GC — safe because exactly-once lives in the ledger, not in file presence
# ---------------------------------------------------------------------------
def gc(root, older_than_secs=3600, now=None):
    """Delete cmd/ack files older than older_than_secs (by mtime). Re-delivery of a
    GC'd command is harmless: the ledger already recorded it, so it would re-ack
    without re-running. Returns the count removed."""
    if now is None:
        now = time.time()
    removed = 0
    for d in (os.path.join(root, "cmd"), os.path.join(root, "ack")):
        for p in glob.glob(os.path.join(d, "*.json")):
            try:
                if now - os.path.getmtime(p) > older_than_secs:
                    os.remove(p)
                    removed += 1
            except OSError:
                continue
    return removed


# ---------------------------------------------------------------------------
# self-test: full hub<->spoke round-trip in a temp dir (no network, no Syncthing).
#   publish -> spoke validate+run-once+ack -> replay (no re-run) -> hub reads ack.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sqlite3
    import tempfile

    CMD_SECRET = "cmd-secret-" + "c" * 24
    MAC = "mac"
    root = tempfile.mkdtemp(prefix="cmddrop_")

    runs = {"n": 0}

    def dispatch(m):
        runs["n"] += 1
        return {"cmd_id": m["cmd_id"], "result": "ok", "detail": "opened %s" % m["args"]["folder"]}

    # hub publishes a new_session command for the Mac
    msg = command.make_command("new_session", MAC, {"folder": "/Users/x/projects/demo", "mode": "default"})
    cid = publish_command(root, msg, CMD_SECRET)
    print("hub published:", cid)

    # spoke processes it (its own ledger)
    conn = sqlite3.connect(":memory:")
    ledger = command.Ledger(conn)
    out1 = process_pending(root, CMD_SECRET, MAC, ledger, dispatch)
    assert out1 == [{"cmd_id": cid, "ran": True, "result": "ok", "detail": "opened /Users/x/projects/demo"}], out1
    assert runs["n"] == 1

    # Syncthing re-delivers the SAME file (e.g. after a resync) -> spoke must NOT re-run
    out2 = process_pending(root, CMD_SECRET, MAC, ledger, dispatch)
    assert out2[0]["ran"] is False and out2[0]["result"] == "ok", out2
    assert runs["n"] == 1, ("dispatch ran %d times, expected exactly 1" % runs["n"])
    print("replay handled: dispatch ran exactly once, ack re-written")

    # hub reads the ack back and matches the cmd_id
    acks = poll_acks(root, CMD_SECRET)
    assert cid in acks and acks[cid]["result"] == "ok" and acks[cid]["machine"] == MAC, acks
    print("hub got ack:", acks[cid]["result"], "-", acks[cid]["detail"])

    # a command for ANOTHER machine sitting in the shared folder is ignored (no ack, no run)
    other = command.make_command("close_session", "company", {"token": "CC-abc123"})
    publish_command(root, other, CMD_SECRET)
    before = runs["n"]
    out3 = process_pending(root, CMD_SECRET, MAC, ledger, dispatch)
    assert all(o["cmd_id"] != other["cmd_id"] or o["result"] == "rejected" for o in out3)
    assert other["cmd_id"] not in poll_acks(root, CMD_SECRET), "must not ack another machine's cmd"
    assert runs["n"] == before, "must not run another machine's cmd"
    print("wrong-target command ignored (no run, no ack)")

    # a forged command (wrong key) is rejected with a 'rejected' ack, never executed
    forged = office.sign(command.make_command("new_session", MAC, {"folder": "/x"}), "WRONG-KEY")
    _ensure(root)
    _atomic_write_json(os.path.join(root, "cmd", forged["msg"][:0] + "forged0001.json"), forged)
    before = runs["n"]
    out4 = process_pending(root, CMD_SECRET, MAC, ledger, dispatch)
    rej = [o for o in out4 if o["cmd_id"] == "forged0001"]
    assert rej and rej[0]["result"] == "rejected" and rej[0]["detail"] == "bad-signature", out4
    assert runs["n"] == before, "forged command must not execute"
    print("forged command rejected (bad-signature), not executed")

    # gc removes nothing fresh, everything when aged
    assert gc(root, older_than_secs=3600) == 0
    aged = gc(root, older_than_secs=0, now=time.time() + 10)
    print("gc aged removed:", aged, "files")

    # cleanup temp
    for d in ("cmd", "ack"):
        for p in glob.glob(os.path.join(root, d, "*")):
            os.remove(p)
    os.rmdir(os.path.join(root, "cmd")); os.rmdir(os.path.join(root, "ack")); os.rmdir(root)
    print("ALL COMMAND-DROP SELF-TESTS PASSED")
