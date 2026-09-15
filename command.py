"""Command-channel core — sign / validate remote session-control commands.

C0 transport-agnostic core for Phase C (remote session control to a Mac spoke).
Reuses office.sign / office.verify (the HMAC-SHA256 envelope) but with a SEPARATE
key (`office_cmd_secret`, NOT the read/snapshot key) and adds the semantics a
read-only snapshot never needed:

  - closed verb vocabulary            -> no arbitrary remote execution (Gate 3)
  - cmd_id (unique) + executed ledger -> exactly-once EXECUTION, replay-safe (Gate 1)
  - target_machine binding            -> a command runs only on its addressee
  - issued_at / expires_at TTL        -> bounded replay window, fail-closed

Trust model: the channel may be replayed/forged/reordered by anyone WITHOUT the
key. Authenticity comes from office HMAC; freshness + exactly-once come from here.
The transport (Syncthing command-drop / LAN HTTP) is deliberately NOT decided in
this module — it only produces/validates the bytes.

See _handoff/plans/plan_phaseC-mac-remote-control_2026-06-20.md (Gate 1 / Gate 3).
Pure Python standard library.
"""
from __future__ import annotations

import json
import re
import secrets
import sqlite3
import time

import office  # reuse sign / verify / SCHEMA — same envelope, different key

KIND = "command"                       # distinguishes a command from a snapshot msg
VERBS = ("new_session", "close_session", "handoff")  # closed vocabulary — no others
DEFAULT_TTL_SECS = 120

# permission modes `claude --permission-mode` accepts (verified via `claude --help`,
# 2026-06-20: default / acceptEdits / auto / bypassPermissions)
MODES = ("default", "acceptEdits", "auto", "bypassPermissions")
_TOKEN_RE = re.compile(r"(?i)^CC-[A-Za-z0-9_-]+$")


# ---------------------------------------------------------------------------
# build (hub side) — caller signs the returned dict with office.sign(msg, cmd_secret)
# ---------------------------------------------------------------------------
def make_command(verb, target_machine, args=None, ttl_secs=DEFAULT_TTL_SECS, now=None):
    """Build an UNSIGNED command msg dict. `cmd_id` is a fresh nonce — it is the
    exactly-once key the spoke dedupes on. Sign with office.sign(msg, cmd_secret)."""
    if now is None:
        now = time.time()
    return {
        "schema": office.SCHEMA,       # so office.verify accepts the envelope
        "kind": KIND,                  # so a snapshot can never be parsed as a command
        "cmd_id": secrets.token_hex(8),
        "verb": verb,
        "target_machine": target_machine,
        "args": args or {},
        "issued_at": now,
        "expires_at": now + max(1, int(ttl_secs)),
    }


# ---------------------------------------------------------------------------
# validate (spoke side) — fail-closed, BEFORE consulting the executed-ledger
# ---------------------------------------------------------------------------
def validate(envelope, cmd_secret, this_machine, now=None):
    """Verify + semantically validate a received command envelope, fail-closed.

    Returns (msg, None) when the command is authentic, well-formed, addressed to
    THIS machine, and not expired; otherwise (None, reason). Authenticity is
    office.verify (HMAC under the cmd key, constant-time); everything else is
    command policy.

    Does NOT check the executed-ledger — the caller does that AFTER validate, so a
    re-delivered cmd_id returns the cached ack instead of being silently dropped."""
    if now is None:
        now = time.time()
    msg = office.verify(envelope, cmd_secret)   # HMAC + schema==SCHEMA, fail-closed
    if msg is None:
        return None, "bad-signature"
    if msg.get("kind") != KIND:
        return None, "not-a-command"
    if msg.get("verb") not in VERBS:
        return None, "unknown-verb"             # closed vocabulary (Gate 3)
    if msg.get("target_machine") != this_machine:
        return None, "wrong-target"             # binding — replay aimed at another box
    cmd_id = msg.get("cmd_id")
    if not isinstance(cmd_id, str) or not cmd_id:
        return None, "no-cmd-id"
    exp = msg.get("expires_at")
    if not isinstance(exp, (int, float)) or now > exp:
        return None, "expired"                  # TTL, fail-closed
    ok, why = _validate_args(msg["verb"], msg.get("args") or {})
    if not ok:
        return None, why
    return msg, None


def _validate_args(verb, args):
    """Per-verb arg SHAPE only (cheap first gate). The executor STILL re-checks
    against the real filesystem / tab list — C:\\myrepo (or Mac root) allowlist,
    junction/reparse-point segments, and CC- single-tab uniqueness — before it
    sends a single keystroke. Nothing here reads an arbitrary arg key into a
    command line, so a 'raw shell' field is never executed (Gate 3)."""
    if not isinstance(args, dict):
        return False, "args-not-dict"
    if verb == "new_session":
        folder = args.get("folder")
        if not isinstance(folder, str) or not folder:
            return False, "new_session-needs-folder"
        if args.get("mode", "default") not in MODES:
            return False, "bad-mode"
    elif verb == "close_session":
        token = args.get("token")
        if not isinstance(token, str) or not _TOKEN_RE.match(token):
            return False, "close-needs-cc-token"
    elif verb == "handoff":
        sid = args.get("sid8")
        if not isinstance(sid, str) or not sid:
            return False, "handoff-needs-sid8"
    return True, None


# ---------------------------------------------------------------------------
# executed-command ledger (spoke side) — exactly-once EXECUTION (Gate 1)
# ---------------------------------------------------------------------------
class Ledger:
    """Persisted executed-command ledger. Re-delivery of a seen cmd_id returns the
    cached ack instead of re-running the side effect. Backed by sqlite (shares
    monitor.db in prod via a passed-in connection; a temp db in tests). The table
    is created idempotently, so it composes with monitor.db_conn()."""

    def __init__(self, conn):
        self.conn = conn
        conn.execute(
            "CREATE TABLE IF NOT EXISTS executed_commands("
            "cmd_id TEXT PRIMARY KEY, verb TEXT, result TEXT, executed_at REAL)")
        conn.commit()

    def seen(self, cmd_id):
        """Cached result dict if this cmd_id already executed, else None."""
        row = self.conn.execute(
            "SELECT result FROM executed_commands WHERE cmd_id=?", (cmd_id,)).fetchone()
        if row is None:
            return None
        try:
            return json.loads(row[0])
        except (ValueError, TypeError):
            return {}

    def record(self, cmd_id, verb, result, now=None):
        """Persist a command's result. INSERT OR IGNORE so a concurrent race on the
        same cmd_id can never double-write (the first writer wins)."""
        if now is None:
            now = time.time()
        self.conn.execute(
            "INSERT OR IGNORE INTO executed_commands(cmd_id, verb, result, executed_at) "
            "VALUES(?,?,?,?)", (cmd_id, verb, json.dumps(result), now))
        self.conn.commit()

    def run_once(self, msg, fn):
        """Exactly-once executor: if msg['cmd_id'] was already run, return its cached
        result (and did_run=False); else run fn(msg) -> result, record it, return it
        (did_run=True). fn is the verb->ops_* dispatch the caller supplies."""
        cmd_id = msg["cmd_id"]
        cached = self.seen(cmd_id)
        if cached is not None:
            return cached, False
        result = fn(msg)
        self.record(cmd_id, msg.get("verb"), result)
        return result, True


# ---------------------------------------------------------------------------
# self-test: Gate 3 (vocab/validation) + Gate 1 (replay -> exactly-once). No network.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    CMD_SECRET = "cmd-secret-" + "a" * 24
    OTHER_SECRET = "read-secret-" + "b" * 24   # the snapshot key — must NOT validate cmds
    ME = "mac"

    # --- Gate 3: a well-formed command for THIS machine validates ---
    good = make_command("new_session", ME, {"folder": "/Users/x/projects/demo", "mode": "bypassPermissions"})
    env = office.sign(good, CMD_SECRET)
    msg, err = validate(env, CMD_SECRET, ME)
    assert msg is not None and err is None, ("good command must validate", err)
    print("Gate3 valid command -> ok (verb=%s mode=%s)" % (msg["verb"], msg["args"]["mode"]))

    # wrong key (the snapshot key) must be rejected -> key separation
    assert validate(env, OTHER_SECRET, ME) == (None, "bad-signature"), "wrong key must reject"
    # tamper the signed bytes
    tampered = {"sig": env["sig"], "msg": env["msg"].replace("new_session", "close_session")}
    assert validate(tampered, CMD_SECRET, ME)[0] is None, "tampered command must reject"

    # closed vocabulary: an unknown verb is refused (build via office.sign of a raw msg)
    bad_verb = dict(good); bad_verb["verb"] = "rm_rf"; bad_verb["cmd_id"] = secrets.token_hex(8)
    assert validate(office.sign(bad_verb, CMD_SECRET), CMD_SECRET, ME) == (None, "unknown-verb")
    # target binding: a command for 'company' is refused on 'mac'
    other_tgt = make_command("close_session", "company", {"token": "CC-abc123"})
    assert validate(office.sign(other_tgt, CMD_SECRET), CMD_SECRET, ME) == (None, "wrong-target")
    # bad args: close without a CC- token; new_session with an unknown mode
    bad_tok = make_command("close_session", ME, {"token": "not-a-cc"})
    assert validate(office.sign(bad_tok, CMD_SECRET), CMD_SECRET, ME) == (None, "close-needs-cc-token")
    bad_mode = make_command("new_session", ME, {"folder": "/x", "mode": "rootmode"})
    assert validate(office.sign(bad_mode, CMD_SECRET), CMD_SECRET, ME) == (None, "bad-mode")
    # TTL: an expired command is refused
    stale = make_command("handoff", ME, {"sid8": "deadbeef"}, ttl_secs=10, now=1000.0)
    assert validate(office.sign(stale, CMD_SECRET), CMD_SECRET, ME, now=2000.0) == (None, "expired")
    print("Gate3 rejects: wrong-key, tamper, unknown-verb, wrong-target, bad-args, expired ok")

    # --- Gate 1: replay the SAME cmd_id N times -> the side effect runs exactly once ---
    conn = sqlite3.connect(":memory:")
    ledger = Ledger(conn)
    runs = {"n": 0}

    def _dispatch(m):
        runs["n"] += 1
        return {"cmd_id": m["cmd_id"], "result": "ok", "detail": "session opened"}

    replayed = make_command("new_session", ME, {"folder": "/Users/x/projects/demo"})
    r1, did1 = ledger.run_once(replayed, _dispatch)   # first delivery -> runs
    r2, did2 = ledger.run_once(replayed, _dispatch)   # replay -> cached
    r3, did3 = ledger.run_once(replayed, _dispatch)   # replay -> cached
    assert (did1, did2, did3) == (True, False, False), "must execute exactly once"
    assert r1 == r2 == r3, "replays must return the identical cached ack"
    assert runs["n"] == 1, ("side effect ran %d times, expected 1" % runs["n"])
    # baseline-reset attack: a fresh ledger (deleted db) must NOT re-run a delivered cmd
    # -> in prod the ledger file is persistent; here we assert the dedup keys on cmd_id,
    #    so as long as the row survives, the replay is blocked.
    assert ledger.seen(replayed["cmd_id"]) is not None, "executed cmd must stay recorded"
    print("Gate1 replay x3 -> executed exactly once, cached ack returned ok")

    print("ALL COMMAND-CORE SELF-TESTS PASSED")
