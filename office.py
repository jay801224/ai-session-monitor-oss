"""Office remote-source core — sign / verify / pseudonymize / staleness.

Shared by BOTH ends of the relay:
  - company side (office_push.py): alias_project / session_token / sign
  - home side   (monitor.py):      verify / apply_aliases / load_office_snapshot

The relay (ntfy) is fully untrusted. Every guarantee comes from here:
  - HMAC-SHA256 over the transmitted bytes  -> forgery is impossible without the key
  - timestamp-derived monotonic `seq`       -> replay/reorder guard (enforced at ingest)
  - HMAC pseudonyms for project names        -> the relay only ever sees opaque ids

Pure Python standard library. No third-party crypto (none is needed for the part
that matters — authenticity — and a hand-rolled stream cipher would be theater).
See docs/plan_office_relay_2026-06-13.md for the full design + threat model.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time

SCHEMA = 1
DEFAULT_STALE_SECS = 150  # 5x a 30s push; older than this => override to 'stale'


# ---------------------------------------------------------------------------
# canonical bytes + HMAC envelope
# ---------------------------------------------------------------------------
def _canon(obj):
    """Deterministic JSON string — identical on both ends or every MAC fails."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def sign(msg_obj, secret):
    """Wrap a message object in a signed envelope {sig, msg}.

    `msg` is the canonical STRING; the signature covers exactly those bytes, so
    the verifier never has to re-serialize (canonicalization can't drift)."""
    msg = _canon(msg_obj)
    sig = hmac.new(_key(secret), msg.encode("utf-8"), hashlib.sha256).hexdigest()
    return {"sig": sig, "msg": msg}


def verify(envelope, secret):
    """Return the decoded msg object if the envelope is authentic, else None.

    Fail-closed at every step. Uses compare_digest (constant-time) — never ==.
    Verifies the literal received `msg` bytes, not a re-serialization."""
    if not isinstance(envelope, dict):
        return None
    sig = envelope.get("sig")
    msg = envelope.get("msg")
    if not isinstance(sig, str) or not isinstance(msg, str):
        return None
    expect = hmac.new(_key(secret), msg.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, sig):
        return None
    try:
        obj = json.loads(msg)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(obj, dict) or obj.get("schema") != SCHEMA:
        return None
    return obj


def _key(secret):
    if isinstance(secret, bytes):
        return secret
    return (secret or "").encode("utf-8")


# ---------------------------------------------------------------------------
# pseudonymization (company side) — raw names never leave the machine
# ---------------------------------------------------------------------------
def alias_project(slug, secret):
    """Stable opaque alias for a project slug: 'proj#<6 hex>'.

    HMAC (not bare SHA256) so the small, guessable space of real project names
    can't be brute-forced back from the alias by anyone who sniffs the relay."""
    h = hmac.new(_key(secret), (slug or "").encode("utf-8"), hashlib.sha256).hexdigest()
    return "proj#" + h[:6]


def session_token(real_id, secret, day=None):
    """Rotating per-day handle for a session — NOT the raw UUID, so the relay
    can't correlate a session across days. Stable within a day for the UI."""
    if day is None:
        day = time.strftime("%Y-%m-%d", time.gmtime())
    h = hmac.new(_key(secret), ("%s|%s" % (real_id, day)).encode("utf-8"),
                 hashlib.sha256).hexdigest()
    return h[:8]


def apply_aliases(label, aliases):
    """Home-side: turn 'proj#a3f1' into a friendly name if the user mapped it.

    `aliases` maps the 6-hex suffix (or the full 'proj#xxxxxx') to a nickname.
    Unmapped aliases are shown verbatim (opaque, still useful for grouping)."""
    if not isinstance(aliases, dict) or not isinstance(label, str):
        return label
    if label in aliases:
        return aliases[label]
    if label.startswith("proj#"):
        suffix = label[len("proj#"):]
        if suffix in aliases:
            return aliases[suffix]
    return label


# ---------------------------------------------------------------------------
# home side: load + freshness-gate a snapshot file
# ---------------------------------------------------------------------------
def load_office_snapshot(path, secret, stale_secs=DEFAULT_STALE_SECS,
                         aliases=None, now=None):
    """Read a snapshot file written by the poller, verify it, and apply the
    staleness override.

    Returns a dict the dashboard can consume directly:
      { ok, machine, pushed_at, fetched_at, age_sec, stale, sessions, recap, error }
    `ok` is False (with `error`) when the file is missing/corrupt/forged — the
    caller renders nothing rather than trusting partial data. When the snapshot
    is too old, `stale` is True and every session status is forced to 'stale' so
    a frozen/offline company machine can never show a false 'running'.

    Freshness is measured from the FILE MTIME (when the snapshot last landed on
    this machine) using the home clock — immune to company/home clock skew.
    `pushed_at` is for display only.
    """
    if now is None:
        now = time.time()
    out = {"ok": False, "machine": None, "pushed_at": None, "fetched_at": None,
           "age_sec": None, "stale": True, "sessions": [], "recap": None, "error": None}
    try:
        fetched_at = os.path.getmtime(path)
    except OSError:
        out["error"] = "no snapshot yet"
        return out
    try:
        with open(path, "r", encoding="utf-8") as f:
            envelope = json.load(f)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        out["error"] = "unreadable snapshot: %s" % e
        return out

    msg = verify(envelope, secret)
    if msg is None:
        out["error"] = "signature/schema check failed — dropped"
        return out

    age = now - fetched_at
    stale = age > max(1, stale_secs)
    raw_sessions = msg.get("sessions")
    sessions = []
    if isinstance(raw_sessions, list):
        for s in raw_sessions:
            if not isinstance(s, dict):
                continue
            tok = s.get("session_token") or ""
            row = {
                "session_id": "office-" + str(tok),
                "label": apply_aliases(s.get("label", "?"), aliases),
                "status": "stale" if stale else (s.get("status") or "idle"),
                "ts": s.get("ts"),
                "source_ai": s.get("source_ai") or "claude",
                "os": s.get("os") or "win",
                "ctx": s.get("ctx"),
                "elapsed": s.get("elapsed"),
                "wait_kind": s.get("wait_kind"),
                "pmode": s.get("pmode") or "",
            }
            sessions.append(row)

    out.update({
        "ok": True,
        "machine": msg.get("machine"),
        "pushed_at": msg.get("pushed_at"),
        "fetched_at": fetched_at,
        "age_sec": int(age),
        "stale": stale,
        "sessions": sessions,
        "recap": msg.get("recap") if isinstance(msg.get("recap"), dict) else None,
    })
    return out


# ---------------------------------------------------------------------------
# self-test: build -> sign -> verify -> tamper -> stale  (no network)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import tempfile

    SECRET = "test-secret-" + "0" * 20
    pushed = 1_700_000_000.0
    msg = {
        "schema": SCHEMA,
        "machine": "OFFICE-PC",
        "pushed_at": pushed,
        "seq": int(pushed * 1000),
        "sessions": [
            {"session_token": session_token("uuid-1234", SECRET, "2026-06-13"),
             "label": alias_project("C--work-company-playwright-x", SECRET),
             "status": "running", "ts": pushed - 10, "source_ai": "claude",
             "os": "win", "ctx": 42, "elapsed": 130},
        ],
        "recap": None,
    }
    env = sign(msg, SECRET)
    print("envelope sig:", env["sig"][:16], "… msg bytes:", len(env["msg"]))
    print("aliased label:", msg["sessions"][0]["label"],
          "| session_token:", msg["sessions"][0]["session_token"])

    assert verify(env, SECRET) is not None, "valid envelope must verify"
    assert verify(env, "wrong-secret") is None, "wrong key must be rejected"
    tampered = {"sig": env["sig"], "msg": env["msg"].replace("running", "stopped")}
    assert verify(tampered, SECRET) is None, "tampered msg must be rejected"
    print("verify: valid OK, wrong-key rejected, tamper rejected ✓")

    # fresh vs stale via file mtime
    fd, p = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(env, f)
    fresh = load_office_snapshot(p, SECRET, stale_secs=150)
    print("fresh -> ok=%s stale=%s status=%s machine=%s"
          % (fresh["ok"], fresh["stale"], fresh["sessions"][0]["status"], fresh["machine"]))
    assert fresh["ok"] and not fresh["stale"]
    assert fresh["sessions"][0]["status"] == "running"
    # force stale: pretend the file is 10 min old
    old = time.time() + 700
    stale = load_office_snapshot(p, SECRET, stale_secs=150, now=old)
    print("stale -> stale=%s status=%s age=%ss"
          % (stale["stale"], stale["sessions"][0]["status"], stale["age_sec"]))
    assert stale["stale"] and stale["sessions"][0]["status"] == "stale"
    # friendly alias
    al = load_office_snapshot(p, SECRET, aliases={msg["sessions"][0]["label"]: "客戶A專案"})
    print("alias  -> label=%s" % al["sessions"][0]["label"])
    assert al["sessions"][0]["label"] == "客戶A專案"
    os.unlink(p)
    print("ALL SELF-TESTS PASSED ✓")
