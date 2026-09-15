"""What does this dashboard look like to someone who is not its owner?

Publishing this tool means handing every "which machine / which account" value to a
stranger to fill in. The failure that matters is not a leak -- it is the tool simply
not working once those values are gone, which a read-through does not catch and a
grep for paths does not catch either. (Machine labels that named the packager's own
home once sat in monitor.DEFAULT_MACHINES through a clean path grep; they only
surfaced by serving a stripped config and looking at the page.)

So: strip, then RUN.

    python tools/depersonalise.py --serve [--port 8789]
        Serve the real dashboard with every personal value removed. Open it and you
        are looking at a stranger's first launch.

    python tools/depersonalise.py --emit <path>
        Write the stripped config out. This is the config.json a public repo ships:
        every personal key removed, every generic default kept.

    python tools/depersonalise.py --list
        Print the keys treated as personal, and what each currently holds.

PERSONAL_KEYS below is the single source of truth. tools/preflight_ui.py's
check-config-depersonalised imports it from here rather than keeping a second copy --
two lists would drift the first time someone adds a config key, and then the gate
would be quietly checking less than it claims.
"""
import argparse
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# Keys whose value answers "which machine is this" or "which account is this".
# Secrets are NOT here: they live in config.local.json, which is gitignored and never
# reaches a published copy in the first place.
PERSONAL_KEYS = [
    "claude_projects",        # where THIS box keeps Claude transcripts
    "codex_session_index",
    "hermes_state_db",
    "copilot_session_db",
    "copilot_state_dir",
    "antigravity_main_log",
    "workspace_roots",        # which folders this owner codes in
    "hooks_source_repo",
    "kb_dir",
    "handoff_dir",
    "handoff_dirs",
    "showcase",               # this owner's apps repo + published URL
    "presets",                # launch presets, each naming a local project dir
    "kb_links",               # the shape of this owner's knowledge base
    "machines",               # this owner's machine names
    "office_machine",
    "local_machine",
]


def strip(config, style="remove"):
    """`remove` deletes the key; `blank` keeps it with an empty value of the same type.

    Both are things people really do when scrubbing a config before publishing, and
    they fail differently: a blanked list still satisfies cfg["k"], a deleted one does
    not. Anything that has to survive publication has to survive both.
    """
    if style == "remove":
        return {k: v for k, v in config.items() if k not in PERSONAL_KEYS}
    out = dict(config)
    for key in PERSONAL_KEYS:
        current = config.get(key)
        out[key] = [] if isinstance(current, list) else (
            {} if isinstance(current, dict) else "")
    return out


def load_config():
    with open(os.path.join(ROOT, "config.json"), encoding="utf-8") as f:
        return json.load(f)


# An absolute path in a published file names somebody's disk. Written as a pattern
# rather than a list of known strings on purpose: a hand-typed grep is exactly what
# let `_AITEST_ROOT = r"C:\myrepo"` sit in monitor.py through a "clean" scan (the
# backslash form was mis-escaped), and what let a home-naming machine label through
# (not a path at all).
#
# The lookbehind is load-bearing: without it the `s:` of "https://" is a drive letter
# and the scan drowns in its own false positives (measured -- every URL in the repo
# plus every `x:\s*%s` in a regex). A drive letter is a letter with no letter before it.
_ABS_PATH = re.compile(
    r"""(?:(?<![A-Za-z])[A-Za-z]:[\\/]|/(?:Users|home)/)[A-Za-z0-9_.][^"'\s,)]*""")
# Regex and format-string fragments that survive the pattern above: `C:\d+`, `x:/%s`.
# A real path does not contain these.
_NOT_A_PATH = ("\\s", "\\d", "\\w", "\\.", "%", "*", "+", "(", "?", "|")


def residual_paths(text):
    """Absolute paths left in a blob, de-duplicated, in first-seen order."""
    seen, out = set(), []
    for hit in _ABS_PATH.findall(text):
        key = hit.rstrip(".,;")
        if len(key) < 6 or any(frag in key for frag in _NOT_A_PATH):
            continue
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


def scan_sources():
    """Absolute paths still written into the shipped source, per file.

    Comment or code is not distinguished: both travel with a published copy, and a
    comment that says "must live under C:\\myrepo" is as wrong on someone else's box
    as the constant would be.
    """
    found = {}
    targets = sorted(glob.glob(os.path.join(ROOT, "*.py")))
    targets += sorted(glob.glob(os.path.join(ROOT, "tools", "*.py")))
    targets += sorted(glob.glob(os.path.join(ROOT, "ui", "*.html")))
    for path in targets:
        if os.path.basename(path) == os.path.basename(__file__):
            continue          # this file documents the patterns it looks for
        try:
            with open(path, encoding="utf-8") as f:
                hits = residual_paths(f.read())
        except OSError:
            continue
        if hits:
            found[os.path.relpath(path, ROOT).replace("\\", "/")] = hits
    return found


def report_residue(stripped_config):
    """Print what a published copy would still carry. Returns the number of findings.

    Heuristic, and says so: it catches absolute paths, which is the largest and most
    mechanical class. It cannot catch a value that names its owner in prose. Serving
    the stripped config and reading the page is still the real check.
    """
    n = 0
    left = residual_paths(json.dumps(stripped_config, ensure_ascii=False))
    if left:
        n += len(left)
        print("\nabsolute paths STILL IN THE STRIPPED CONFIG (%d):" % len(left))
        for key, value in stripped_config.items():
            for hit in residual_paths(json.dumps(value, ensure_ascii=False)):
                print("  %-24s %s" % (key, hit))
    srcs = scan_sources()
    if srcs:
        n += sum(len(v) for v in srcs.values())
        print("\nabsolute paths in shipped SOURCE (%d file(s)):" % len(srcs))
        for path, hits in srcs.items():
            for hit in hits:
                print("  %-28s %s" % (path, hit))
    if not n:
        print("\nno absolute path found in the stripped config or the shipped source.")
    print("\n(Heuristic: absolute paths only. A value can name its owner without being "
          "a path -- a home-naming machine label did. --serve and read the page.)")
    return n


def cmd_list(config):
    print("personal keys (%d) -- each becomes the reader's to fill in:\n" % len(PERSONAL_KEYS))
    for key in PERSONAL_KEYS:
        if key not in config:
            print("  %-24s (not in this config)" % key)
            continue
        shown = json.dumps(config[key], ensure_ascii=False)
        print("  %-24s %s" % (key, shown if len(shown) <= 68 else shown[:65] + "..."))
    kept = [k for k in config if k not in PERSONAL_KEYS and not k.startswith("_")]
    print("\ngeneric keys kept as-is (%d): %s" % (len(kept), ", ".join(sorted(kept))))
    report_residue(strip(config, "remove"))
    return 0


def cmd_emit(config, path):
    stripped = strip(config, "remove")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(stripped, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print("wrote %s -- %d personal key(s) removed, %d kept"
          % (path, len(config) - len(stripped), len(stripped)))
    print("Every removed key is one the reader must set before the matching surface "
          "shows anything. None of them stops the dashboard from starting.")
    # Non-zero exit on residue: emitting a config for a public repo is the last
    # moment this is cheap to notice, so it fails loudly rather than printing a
    # warning under a success message.
    return 1 if report_residue(stripped) else 0


def cmd_serve(config, port):
    # config.local.json lives next to monitor.py and load_config merges it over
    # config.json, which would put the owner's secrets straight back into this run.
    if os.path.exists(os.path.join(ROOT, "config.local.json")):
        sys.stderr.write(
            "refusing to serve: config.local.json is present and load_config would "
            "merge it over the stripped config, so this would NOT be a stranger's "
            "view. Move it aside for the duration of the check.\n")
        return 2
    sys.path.insert(0, ROOT)
    import monitor  # noqa: E402 -- after the path insert, on purpose

    out = os.path.join(ROOT, "_state", "depersonalised-config.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(strip(config, "remove"), f, ensure_ascii=False, indent=2)
    # Only CONFIG_PATH moves. monitor.HERE stays put: it is also the root for
    # /assets/ and the ui/*.html reads, so repointing it 404s every avatar and makes
    # the harness look like a product bug (it did, once).
    monitor.CONFIG_PATH = out
    os.environ["PORT"] = str(port)
    print("serving a STRANGER'S view on http://127.0.0.1:%d" % port)
    print("  %d personal key(s) removed; config written to %s" % (len(PERSONAL_KEYS), out))
    print("  Empty session zones are the CORRECT result -- no configured paths means")
    print("  nothing to scan. What you are checking is that the page still works and")
    print("  that nothing on it belongs to you. Ctrl-C to stop.")
    # monitor.main() never returns, and Python block-buffers stdout when it is not a
    # terminal -- so without this the banner above is still sitting in the buffer when
    # the run is piped or redirected, and the log reads as an empty file.
    sys.stdout.flush()
    monitor.main()
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--serve", action="store_true",
                      help="run the dashboard with personal values removed")
    mode.add_argument("--emit", metavar="PATH",
                      help="write the stripped config a public repo would ship")
    mode.add_argument("--list", action="store_true",
                      help="show which keys count as personal and what they hold")
    ap.add_argument("--port", type=int, default=8789,
                    help="port for --serve (default 8789; 8787 is the production "
                         "daemon and 8788 the usual preview -- do not reuse either)")
    args = ap.parse_args(argv)

    config = load_config()
    if args.list:
        return cmd_list(config)
    if args.emit:
        return cmd_emit(config, args.emit)
    return cmd_serve(config, args.port)


if __name__ == "__main__":
    sys.exit(main())
