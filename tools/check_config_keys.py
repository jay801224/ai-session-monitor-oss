"""Report template keys that this machine's config.json has never heard of.

WHY this exists. `config.json` is per-machine and gitignored: it is created ONCE
by copying `config.template.json`, and from then on the two drift apart in one
direction only. A `git pull` delivers CODE that reads a new key, but nothing
delivers the KEY, so the new feature lands switched off and says nothing. That
is not hypothetical — on 2026-09-02 this Mac pulled 14 commits including the
codex-poll caller, and `config.json` was still missing `codex_poll` /
`codex_bridge`; `(cfg.get("codex_poll") or {}).get("enabled")` reads a missing
key as "disabled", so the feature was silently off with no error anywhere.

WHAT it compares. Key PATHS only, recursively — `codex_poll.enabled` counts as
its own path, so a config holding a bare `{"codex_poll": {}}` is still reported.
It NEVER compares values: `local_machine` and `alerts_enabled` are SUPPOSED to
differ per machine (hub vs spoke, see CONTEXT.md Glossary), so a value diff is
not drift. The question this answers is "do you know this key exists", not "is
your value right".

WHAT it does NOT do. It does not exit non-zero and it does not repair anything.
`load_config()` owns fail-loud for a missing or malformed config file; this is a
separate, advisory signal and the two must not be conflated.
"""
import json
import os
import sys


def key_paths(node, prefix=""):
    """Every dotted key path in `node`, depth-first.

    Only dicts are descended. A list is a VALUE here: its elements are data the
    machine supplies, not schema the template promises, so `codex_projects[0]`
    is not a key path and its absence is not drift.
    """
    out = []
    if not isinstance(node, dict):
        return out
    for k, v in node.items():
        path = "%s.%s" % (prefix, k) if prefix else k
        out.append(path)
        if isinstance(v, dict):
            out.extend(key_paths(v, path))
    return out


def missing_key_paths(template, config):
    """Template key paths absent from `config`, in template order.

    A path is missing when the config has no key there OR when the template has
    a dict at that path and the config has a non-dict — in the latter case the
    whole subtree is unreachable, so the children are reported too (they are,
    because `key_paths` walked the template, not the config).
    """
    have = set(key_paths(config))
    return [p for p in key_paths(template) if p not in have]


def check(template_path, config_path):
    """(missing_paths, error). `error` is a string when a file could not be read.

    A missing config.json is NOT this checker's error to raise — `load_config()`
    already fails loudly on it. Returning the error lets the caller decide.
    """
    try:
        with open(template_path, "r", encoding="utf-8") as fh:
            template = json.load(fh)
        with open(config_path, "r", encoding="utf-8") as fh:
            config = json.load(fh)
    except (OSError, ValueError) as e:
        return [], "%s: %s" % (type(e).__name__, e)
    return missing_key_paths(template, config), None


def main(argv):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    template_path = argv[1] if len(argv) > 1 else os.path.join(root, "config.template.json")
    config_path = argv[2] if len(argv) > 2 else os.path.join(root, "config.json")
    missing, err = check(template_path, config_path)
    if err:
        print("config key check skipped: %s" % err)
        return 0
    for path in missing:
        print("⚠ config behind template: %s" % path)
    if not missing:
        print("config key check: clean (%d template keys)" % len(key_paths(
            json.load(open(template_path, "r", encoding="utf-8")))))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
