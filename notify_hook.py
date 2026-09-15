#!/usr/bin/env python3
"""Claude Code Notification hook for ai-session-monitor.

Fires when Claude is waiting for you (Notification matcher `idle_prompt`). It
writes a tiny marker file *next to the session transcript* — `<session>.notify.json`
— so the dashboard can flip that row to a `waiting` state and push a Telegram
alert. The marker lives inside ~/.claude/projects/<slug>/, which means it rides
Syncthing to other machines for free; the dashboard only ever READS it (the
dashboard stays read-only — only this user-installed hook writes).

Zero LLM calls, pure stdlib, fire-and-forget: a hook must never disrupt the
session, so every failure path is swallowed.

Install (both machines' settings.json, see README §B4). The command needs the
absolute path to THIS file on the machine being configured -- the placeholder below
is not a location anyone should copy verbatim:
  "hooks": { "Notification": [ { "matcher": "idle_prompt",
    "hooks": [ { "type": "command",
      "command": "python <path-to-this-repo>/notify_hook.py" } ] } ] }
"""
import json
import os
import sys
import time


def main():
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError, OSError):
        return  # never raise — a hook must not disrupt the session
    transcript = data.get("transcript_path")
    sid = data.get("session_id")
    if not transcript or not sid:
        return
    marker = os.path.splitext(transcript)[0] + ".notify.json"
    payload = {
        "ts": time.time(),
        "session_id": sid,
        "notification_type": data.get("notification_type", ""),
        "message": data.get("message", ""),
    }
    try:
        with open(marker, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)
    except OSError:
        pass


if __name__ == "__main__":
    main()
