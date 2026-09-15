"""Hook inventory audit for ai-session-monitor.

Answers three questions about every AI hook on this machine, per day:
total line count, which hook EVENT types are declared, and total file count —
split by vendor (Claude / Codex / Antigravity) and by scope (global / project).
Pure Python standard library, read-only of sources, zero LLM — same discipline
as monitor.py and recap.py.

WHY custody is content-first and NOT inode-first
------------------------------------------------
The obvious model ("centrally managed == hardlinked back to the source repo")
is wrong, and measurably so on this machine:

  * ~/.claude/global-hooks/*.sh are COPIES, not hardlinks — both sides carry
    nlink=1 with different inodes and identical sizes. sync-manifest.json backs
    this up: only the `per-repo-hooks` row declares link_type=hardlink; the
    global rows declare copy/managed_keys. An inode test marks the entire
    Claude global surface as non-managed on day one.
  * The consumer repos hardlink to EACH OTHER, not to the source. pre_agent.sh:
    the source working-tree file has nlink=1 while sixteen consumer repos share
    one inode with nlink=16. A source-side rewrite (git pull / checkout / an
    Edit-tool write — see the global CLAUDE.md hardlink-break rule) de-links
    every consumer at once without changing a byte of their content.

So: CONTENT (normalised sha256 against the source WORKING TREE — that is what a
hardlink actually points at) is the primary signal, and inode identity is a
secondary "is the link still intact" flag that only counts as a deviation on
rows the manifest declares as link_target.

WHY hashes are newline-normalised
---------------------------------
.gitattributes eol=lf only applies at checkout; files predating the setting were
never renormalised. Measured: pre_agent.sh / post_agent.sh / pre_compact.sh /
on_task_complete.sh have CRLF in the working tree and LF in the blob. Hashing
raw bytes marks all four as hand-edited when nobody touched them. Both sides get
\r\n -> \n before hashing; line counts are unaffected either way.

WHY the oracle is the FULL history, not a 30-day slice
------------------------------------------------------
"behind" (deployed content is an older source version) vs "divergent" (content
the source never had) is only honest if the search covers everything the source
ever contained. Measured cost of the full index: one `git log --raw` call
(0.19 s, 290 commits, 397 unique blobs) plus one `git cat-file --batch`. That is
cheaper than the 30-day slice it replaces, so there is no reason to be partial.

This module NEVER decides whether something is a violation. It reports counts
and custody states; the human reads them against the architecture diagram.
"""
from __future__ import annotations

import datetime
import fnmatch
import glob
import hashlib
import json
import os
import re
import subprocess
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = os.path.join(HERE, "_state", "hooks")

DEFAULT_BACKFILL_DAYS = 30
SOURCE_BRANCH = "master"
ASOF_HOUR = 12  # a day's source datapoint = last commit before 12:00 that day
GIT_TIMEOUT = 120
# Hide the console window when shelling out to git so nothing flashes.
_NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

# One lock for every read-modify-write of _state/hooks/. The server is a
# ThreadingHTTPServer and the snapshot thread runs concurrently with requests.
_LOCK = threading.Lock()

# Rescan is user-triggered from a button; shelling out to git on every click
# would be a free way to fork-bomb the box. Same shape as monitor._KB_CACHE.
_SCAN_CACHE = {"ts": 0.0, "data": None}
_SCAN_CACHE_TTL = 30
_INDEX_CACHE = {"key": None, "data": None}


# ---------------------------------------------------------------------------
# scan surfaces — every hook-bearing location, declared explicitly
# ---------------------------------------------------------------------------
# "sources of truth" note: manifest_row is the id in the hooks source repo's
# sync-manifest.json that governs this surface, or None when the manifest does
# not declare it. None is REPORTED, never silently defaulted — an undeclared
# sync path is itself something the owner wants to see (verified 2026-07-29:
# there is no manifest row for global-hooks/*.sh -> ~/.claude/global-hooks/).
SURFACES = [
    dict(id="claude-global-settings", vendor="claude", scope="global", kind="settings",
         deployed="~/.claude/settings.json", source="global-hooks/settings-hooks.json",
         verify="managed_keys", manifest_row="global-hooks"),
    dict(id="claude-global-scripts", vendor="claude", scope="global", kind="files",
         deployed_dir="~/.claude/global-hooks", patterns=("*.sh",),
         source_dir="global-hooks", verify="sha256", manifest_row=None),
    dict(id="claude-global-runtime-deps", vendor="claude", scope="global", kind="files",
         deployed_dir="~/.claude/global-hooks", patterns=("*.py", "*.jsonl"),
         source_dir="global-hooks", verify="sha256", manifest_row=None),
    dict(id="claude-statusline", vendor="claude", scope="global", kind="files",
         deployed_dir="~/.claude", patterns=("statusline.js",),
         source_dir="global-hooks", verify="sha256", manifest_row="statusline-js"),
    dict(id="claude-project-settings", vendor="claude", scope="project", kind="settings",
         per_repo=True, deployed=".claude/settings.json",
         source="global-hooks/per-repo/settings.json",
         verify="sha256", manifest_row="per-repo-settings"),
    dict(id="claude-project-scripts", vendor="claude", scope="project", kind="files",
         per_repo=True, deployed_dir=".claude/hooks", patterns=("*.sh",),
         source_dir="global-hooks/per-repo/hooks",
         verify="link_target", manifest_row="per-repo-hooks"),
    dict(id="codex-global", vendor="codex", scope="global", kind="settings",
         deployed="~/.codex/hooks.json", source=None, verify=None, manifest_row=None),
    dict(id="codex-project", vendor="codex", scope="project", kind="settings",
         per_repo=True, deployed=".codex/hooks.json",
         source=None, verify=None, manifest_row=None),
    dict(id="antigravity-githooks", vendor="antigravity", scope="project", kind="files",
         per_repo=True, deployed_dir=".git/hooks", patterns=("*",), exclude=("*.sample",),
         source_dir="global-hooks/per-repo/githooks",
         verify=None, manifest_row=None),
]

# Vendors with NO hook surface. Declared, not omitted — "we checked and there is
# nothing" and "we forgot to look" must not render identically (the sync-manifest
# `declared_local` convention, applied here).
NO_HOOK_SURFACES = [
    dict(id="gemini", vendor="gemini", checked="~/.gemini/settings.json",
         note="只有 security 鍵，無 hooks 區段"),
    dict(id="copilot", vendor="copilot", checked="~/.copilot/config.json",
         note="只有 app state（firstLaunchAt / appTipShown 等），無 hooks 區段"),
]

# Lives under global-hooks/ but is not a hook. Counting these inflates the source
# curve against a deployed curve that can never contain them.
SOURCE_EXCLUDE = (
    "/tests/",
    "gitignore-managed-block.txt",
    "context-md-claude-block.md",
    ".template",
)

# Path-ish tokens inside a hook `command` string, so a hook pointing at a script
# that is not deployed shows up.
_CMD_PATH_RE = re.compile(r"[A-Za-z]:[\\/][^\s\"';|]+\.(?:sh|py|js|ps1)"
                          r"|[\w./\\$~{}-]+\.(?:sh|py|js|ps1)")

# A deployed script resolving a SIBLING file: `$(dirname "${BASH_SOURCE[0]}")/x.py`
# and friends. This is the strong form of the "hook points at something that was
# never deployed" defect — verified live on this machine: the deployed
# kb_before_web.sh resolves kb_resolver.py as a sibling, and kb_resolver.py is
# present in the source repo but absent from ~/.claude/global-hooks/.
_SIBLING_REF_RE = re.compile(
    r"(?:BASH_SOURCE\[0\]|\$0)[^\n]{0,40}?/([\w.-]+\.(?:sh|py|js|ps1))")

# Repos carrying this marker have deliberately opted OUT of the skills sync.
# Enumerating "missing" hooks for them would be reporting a decision as a defect.
OPT_OUT_MARKER = ".no-mcs-onboard"


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def _expand(path):
    return os.path.expanduser(path)


def _norm_sha(data):
    """sha256 over newline-normalised bytes. See module docstring (CRLF)."""
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def _count_lines(data):
    if not data:
        return 0
    n = data.count(b"\n")
    return n if data.endswith(b"\n") else n + 1


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def _iso(ts):
    return datetime.datetime.fromtimestamp(ts).isoformat(timespec="seconds")


def _today():
    return datetime.date.today()


def _git(repo, args, timeout=GIT_TIMEOUT, stdin=None):
    """Run git and return raw stdout bytes. Raises on any failure.

    Deliberately subprocess.run + input= and NEVER text=True: `cat-file --batch`
    emits a byte-framed stream (`<sha> blob <size>\\n<payload>\\n`) and newline
    translation would desynchronise the parser against the declared sizes. Popen
    with manual write/read would also deadlock on the pipe buffer and could not
    carry a timeout.
    """
    p = subprocess.run(["git", "-C", repo] + list(args), input=stdin,
                       capture_output=True, timeout=timeout,
                       creationflags=_NO_WINDOW)
    if p.returncode != 0:
        raise RuntimeError("git %s failed: %s"
                           % (" ".join(args[:2]), p.stderr.decode("utf-8", "replace")[:200]))
    return p.stdout


def _source_repo(cfg):
    # No built-in default: the hook source repo is one machine's local path, and a
    # baked-in one is wrong everywhere except the box it was written on. Unset means
    # the audit says 母本不可用 instead of auditing against a path nobody chose.
    return (cfg or {}).get("hooks_source_repo") or ""


def _backfill_days(cfg):
    try:
        return int((cfg or {}).get("hooks_backfill_days") or DEFAULT_BACKFILL_DAYS)
    except (TypeError, ValueError):
        return DEFAULT_BACKFILL_DAYS


def _is_excluded_source(rel):
    rel = rel.replace("\\", "/")
    return any(tok in rel for tok in SOURCE_EXCLUDE)


def repos(cfg):
    """Main-worktree repos under the configured workspace roots.

    A linked worktree's `.git` is a FILE (`gitdir: ...`), a main worktree's is a
    directory — verified against several real linked worktrees. Worktrees are excluded: the owner
    audits each project's main checkout, and a worktree would double-count the
    same deployed hooks.
    """
    # Same reasoning as _source_repo: no baked-in scan root. monitor.py's own readers
    # (build_status, the authorize gate) already treat an unset workspace_roots as an
    # empty list rather than substituting one, so this stays consistent with them.
    roots = (cfg or {}).get("workspace_roots") or []
    if isinstance(roots, str):
        roots = [roots]
    out = []
    for root in roots:
        try:
            names = sorted(os.listdir(root))
        except OSError:
            continue
        for name in names:
            path = os.path.join(root, name)
            if os.path.isdir(os.path.join(path, ".git")):
                out.append(path)
    return out


# ---------------------------------------------------------------------------
# source index — every version of every hook the source repo ever held
# ---------------------------------------------------------------------------
def build_source_index(repo):
    """{normalised_sha -> {paths, first, last}} over the full history, plus the
    current working-tree state.

    One `git log --raw` call yields every (commit-date, path, blob) triple; one
    `git cat-file --batch` then reads each unique blob exactly once. Blob shas
    are NOT usable as the key — a blob stored with CRLF hashes differently from
    the same logical content stored with LF — so every blob body is re-hashed
    through _norm_sha.
    """
    log = _git(repo, ["log", "--format=C%x00%H%x00%cI", "--raw", "--no-abbrev",
                      "--no-renames", "-m", "--", "global-hooks/"])
    date_of_blob = {}   # blob sha -> earliest/latest commit dates seen
    path_of_blob = {}
    cur_date = None
    for line in log.decode("utf-8", "replace").splitlines():
        if line.startswith("C\x00"):
            parts = line.split("\x00")
            cur_date = parts[2][:10] if len(parts) > 2 else None
            continue
        if not line.startswith(":") or cur_date is None:
            continue
        meta, _, path = line.partition("\t")
        fields = meta.split()
        if len(fields) < 5:
            continue
        blob = fields[3]
        if blob == "0" * 40:  # deletion
            continue
        lo, hi = date_of_blob.get(blob, (cur_date, cur_date))
        date_of_blob[blob] = (min(lo, cur_date), max(hi, cur_date))
        path_of_blob.setdefault(blob, set()).add(path)

    index = {}
    if date_of_blob:
        shas = sorted(date_of_blob)
        raw = _git(repo, ["cat-file", "--batch"],
                   stdin=("\n".join(shas) + "\n").encode("ascii"))
        pos = 0
        while pos < len(raw):
            nl = raw.find(b"\n", pos)
            if nl < 0:
                break
            header = raw[pos:nl].split()
            if len(header) < 3:            # "<sha> missing"
                pos = nl + 1
                continue
            sha = header[0].decode("ascii")
            size = int(header[2])
            body = raw[nl + 1:nl + 1 + size]
            pos = nl + 1 + size + 1        # payload is followed by a bare \n
            nsha = _norm_sha(body)
            first, last = date_of_blob.get(sha, (None, None))
            entry = index.setdefault(nsha, {"paths": set(), "first": first, "last": last})
            entry["paths"] |= path_of_blob.get(sha, set())
            if first and (entry["first"] is None or first < entry["first"]):
                entry["first"] = first
            if last and (entry["last"] is None or last > entry["last"]):
                entry["last"] = last

    head_date = _git(repo, ["log", "-1", "--format=%cI", SOURCE_BRANCH]
                     ).decode("ascii", "replace").strip()[:10]
    return {"index": index, "head_date": head_date, "repo": repo}


def _source_files(repo, rel_dir, patterns=("*",)):
    """Working-tree source files for a surface. The working tree — not a blob —
    is what a hardlinked consumer file actually points at."""
    base = os.path.join(repo, rel_dir.replace("/", os.sep))
    out = {}
    if not os.path.isdir(base):
        return out
    for name in sorted(os.listdir(base)):
        path = os.path.join(base, name)
        if not os.path.isfile(path):
            continue
        if not any(fnmatch.fnmatch(name, p) for p in patterns):
            continue
        if _is_excluded_source(os.path.join(rel_dir, name)):
            continue
        out[name] = path
    return out


# ---------------------------------------------------------------------------
# custody
# ---------------------------------------------------------------------------
def _custody(dep_path, dep_data, src_path, idx, link_expected):
    """Classify one deployed file against the source. See module docstring.

    Returns the content state plus the link state; the two are independent axes
    and the caller must not collapse them.
    """
    dep_st = os.stat(dep_path)
    rec = {
        "lines": _count_lines(dep_data),
        "bytes": len(dep_data),
        "deployed_mtime": _iso(dep_st.st_mtime),
        "link": "na",
        "link_expected": bool(link_expected),
        "behind_by_days": None,
        "matched_source_date": None,
        "matched_other_path": None,
        "source_mtime": None,
        "post_deploy_edit": False,
    }
    if not src_path:
        rec["custody"] = "local"          # the source never carried this file
        return rec

    src_st = os.stat(src_path)
    rec["source_mtime"] = _iso(src_st.st_mtime)
    # (st_dev, st_ino) as a pair — st_ino alone can collide across volumes.
    rec["link"] = ("linked" if (dep_st.st_dev, dep_st.st_ino) == (src_st.st_dev, src_st.st_ino)
                   else "copy")

    dep_sha = _norm_sha(dep_data)
    if dep_sha == _norm_sha(_read(src_path)):
        rec["custody"] = "current"
        return rec

    hit = idx["index"].get(dep_sha)
    if hit:
        rec["matched_source_date"] = hit["last"]
        try:
            d0 = datetime.date.fromisoformat(hit["last"])
            d1 = datetime.date.fromisoformat(idx["head_date"])
            rec["behind_by_days"] = (d1 - d0).days
        except (TypeError, ValueError):
            pass
        # Path-scoped first: content that only ever lived under a DIFFERENT name
        # is a weaker match and gets its own state rather than being folded in.
        name = os.path.basename(src_path)
        if any(os.path.basename(p) == name for p in hit["paths"]):
            rec["custody"] = "behind"
        else:
            rec["custody"] = "behind_other_path"
            rec["matched_other_path"] = sorted(hit["paths"])[0]
        return rec

    rec["custody"] = "divergent"
    # The ONLY combination that actually means "someone edited the consumer copy
    # after it was deployed". A plain `behind` never implies this.
    rec["post_deploy_edit"] = dep_st.st_mtime > src_st.st_mtime
    return rec


# ---------------------------------------------------------------------------
# settings-style surfaces (event declarations)
# ---------------------------------------------------------------------------
def _referenced_scripts(blob):
    """Script paths named inside hook `command` strings, with existence checked."""
    found = {}

    def walk(node):
        if isinstance(node, dict):
            for key, val in node.items():
                if key == "command" and isinstance(val, str):
                    for m in _CMD_PATH_RE.finditer(val):
                        tok = m.group(0)
                        if tok.startswith("$") or "{" in tok:
                            continue  # runtime-expanded, cannot be resolved statically
                        found.setdefault(tok, None)
                else:
                    walk(val)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(blob)
    out = []
    for tok in sorted(found):
        path = _expand(tok)
        out.append({"ref": tok, "exists": os.path.isfile(path) if os.path.isabs(path) else None})
    return out


def _scan_settings(surface, deployed_path, repo_label):
    """Read one settings.json / hooks.json and report its declared events."""
    row = {"surface": surface["id"], "vendor": surface["vendor"], "scope": surface["scope"],
           "repo": repo_label, "path": deployed_path, "present": False,
           "events": [], "lines": 0, "referenced": []}
    if not os.path.isfile(deployed_path):
        return row
    row["present"] = True
    try:
        data = _read(deployed_path)
        blob = json.loads(data.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as e:
        row["error"] = "unreadable: %s" % e
        return row
    hooks = blob.get("hooks")
    if not isinstance(hooks, dict):
        return row
    row["events"] = sorted(hooks)
    # Lines attributable to the hooks block only, not the whole settings file.
    row["lines"] = _count_lines(json.dumps(hooks, ensure_ascii=False, indent=2).encode("utf-8"))
    row["referenced"] = _referenced_scripts(hooks)
    return row


# ---------------------------------------------------------------------------
# deployed scan
# ---------------------------------------------------------------------------
def _broken_sibling_refs(deployed_dir, files):
    """Sibling files that deployed scripts resolve but that are not deployed."""
    out = []
    for rec in files:
        path = os.path.join(deployed_dir, rec["name"])
        try:
            body = _read(path).decode("utf-8", "replace")
        except OSError:
            continue
        for ref in sorted(set(_SIBLING_REF_RE.findall(body))):
            if not os.path.exists(os.path.join(deployed_dir, ref)):
                out.append({"by": rec["name"], "ref": ref})
    return out


def _scan_files(surface, deployed_dir, repo_label, source_repo, idx, repo_path=None):
    """Inventory one file-bearing surface: deployed files, plus source files the
    deployment does not have.

    A source file with no deployed counterpart is only called `missing` when the
    manifest declares a contract for this surface. Without a declared contract,
    "the source has it and you don't" is an unprovable assertion about intent —
    it is reported as `absent` (informational) instead. Same reason a repo that
    opted out of the sync gets ONE row saying so rather than N defect rows.
    """
    patterns = surface.get("patterns", ("*",))
    exclude = surface.get("exclude", ())
    contract = surface.get("manifest_row")
    src_map = ({} if not surface.get("source_dir") or idx is None
               else _source_files(source_repo, surface["source_dir"], patterns))
    link_expected = surface.get("verify") == "link_target"

    base = {"surface": surface["id"], "vendor": surface["vendor"], "scope": surface["scope"],
            "repo": repo_label, "path": deployed_dir, "manifest_row": contract,
            "contract": ("manifest:%s" % contract) if contract else None,
            "verify": surface.get("verify")}

    # An opted-out repo still gets a full inventory of what IS deployed — the
    # marker suppresses the "you should also have X" assertion below, nothing
    # else. (ai-session-monitor carries the marker and has 19 hooks deployed.)
    opted_out = bool(repo_path) and os.path.exists(os.path.join(repo_path, OPT_OUT_MARKER))

    files, seen = [], set()
    if os.path.isdir(deployed_dir):
        for name in sorted(os.listdir(deployed_dir)):
            path = os.path.join(deployed_dir, name)
            if not os.path.isfile(path):
                continue
            if not any(fnmatch.fnmatch(name, p) for p in patterns):
                continue
            if any(fnmatch.fnmatch(name, p) for p in exclude):
                continue
            try:
                data = _read(path)
            except OSError:
                continue  # vanished mid-scan; the repo-level guard reports it
            seen.add(name)
            rec = {"name": name}
            if idx is None:
                # No source index (git unavailable) -> report the file, but never
                # invent a custody verdict for it.
                st = os.stat(path)
                rec.update(lines=_count_lines(data), bytes=len(data), custody="unknown",
                           link="na", link_expected=link_expected,
                           deployed_mtime=_iso(st.st_mtime))
            else:
                rec.update(_custody(path, data, src_map.get(name), idx, link_expected))
            files.append(rec)

    state = "missing" if contract else "absent"
    missing = [] if opted_out else [
        {"name": n, "custody": state,
         "source_lines": _count_lines(_read(p)) if os.path.isfile(p) else 0}
        for n, p in sorted(src_map.items()) if n not in seen]

    return dict(base,
                present=os.path.isdir(deployed_dir),
                opted_out=opted_out,
                files=files, missing=missing,
                broken_refs=_broken_sibling_refs(deployed_dir, files),
                lines=sum(f["lines"] for f in files),
                count=len(files))


def scan_deployed(cfg, now=None):
    """Full live inventory of every hook surface on this machine (~80 ms)."""
    now = now or time.time()
    source_repo = _source_repo(cfg)

    idx, source_note = None, None
    try:
        if not source_repo:
            # Guarded separately: os.path.join("", ".git") is the RELATIVE ".git",
            # which isdir() happily confirms whenever the process happens to sit in
            # a git repo -- an unset config would then audit against the cwd.
            raise RuntimeError("hooks_source_repo not configured")
        if not os.path.isdir(os.path.join(source_repo, ".git")):
            raise RuntimeError("source repo not found: %s" % source_repo)
        idx = _index_cached(source_repo)
    except Exception as e:  # noqa: BLE001 — the scan degrades, it never dies
        source_note = "母本不可用（custody 無法判定）：%s" % e

    repo_list = repos(cfg)
    rows, unavailable = [], []
    for surface in SURFACES:
        if surface.get("per_repo"):
            targets = [(os.path.basename(r), r) for r in repo_list]
        else:
            targets = [("(global)", None)]
        for label, repo_path in targets:
            try:
                if surface["kind"] == "settings":
                    rel = surface["deployed"]
                    path = _expand(rel) if repo_path is None else os.path.join(repo_path, rel)
                    row = _scan_settings(surface, path, label)
                    row["manifest_row"] = surface.get("manifest_row")
                else:
                    rel = surface["deployed_dir"]
                    path = _expand(rel) if repo_path is None else os.path.join(repo_path, rel)
                    row = _scan_files(surface, path, label, source_repo, idx, repo_path)
                if row.get("present") or row.get("missing") or row.get("opted_out"):
                    rows.append(row)
            except Exception as e:  # noqa: BLE001
                # A repo mid-checkout must be recorded as unavailable, NEVER as a
                # zero — snapshots are permanent history and a fake 0 stays forever.
                unavailable.append({"surface": surface["id"], "repo": label, "error": str(e)})

    return {
        "generated": _iso(now),
        "captured_at": _iso(now),
        "source": {"available": idx is not None, "note": source_note,
                   "repo": source_repo,
                   "head_date": idx["head_date"] if idx else None},
        "rows": rows,
        "unavailable": unavailable,
        "no_hook_surfaces": [dict(s, checked_path=_expand(s["checked"]),
                                  checked_exists=os.path.exists(_expand(s["checked"])))
                             for s in NO_HOOK_SURFACES],
        "totals": _totals(rows),
    }


def _totals(rows):
    """Aggregate by (vendor, scope). `distinct` counts unique CONTENT so it is
    comparable with the source curve — the deployed file count is the same ~20
    source files fanned out across ~16 repos and would read as 15x drift."""
    agg = {}
    for row in rows:
        key = "%s/%s" % (row["vendor"], row["scope"])
        slot = agg.setdefault(key, {"vendor": row["vendor"], "scope": row["scope"],
                                    "files": 0, "lines": 0, "events": set(),
                                    "distinct": {}, "custody": {}})
        slot["events"].update(row.get("events") or [])
        for f in row.get("files", []):
            slot["files"] += 1
            slot["lines"] += f.get("lines", 0)
            # Keyed by NAME, not by (name, size): the same hook at two different
            # versions across repos is still ONE hook. Keying on content would
            # count a mid-rollout file twice and inflate the deployed curve above
            # the source curve it is meant to be compared with.
            name = f["name"]
            slot["distinct"][name] = max(slot["distinct"].get(name, 0), f.get("lines") or 0)
            slot["custody"][f["custody"]] = slot["custody"].get(f["custody"], 0) + 1
        for f in row.get("missing", []):
            slot["custody"][f["custody"]] = slot["custody"].get(f["custody"], 0) + 1
        slot["broken_refs"] = slot.get("broken_refs", 0) + len(row.get("broken_refs") or [])
        if row.get("lines") and not row.get("files"):
            slot["lines"] += row["lines"]        # settings-style surface
    out = []
    for key in sorted(agg):
        slot = agg[key]
        out.append({"key": key, "vendor": slot["vendor"], "scope": slot["scope"],
                    "files": slot["files"], "lines": slot["lines"],
                    "distinct_files": len(slot["distinct"]),
                    # distinct_* is the deployed side de-duplicated by hook name,
                    # so it is comparable with the source curve; the raw file/line
                    # totals are the same ~24 source files fanned out over ~16
                    # repos and would read as 15x drift on a shared axis.
                    "distinct_lines": sum(slot["distinct"].values()),
                    "broken_refs": slot.get("broken_refs", 0),
                    "events": sorted(slot["events"]), "custody": slot["custody"]})
    return out


def _index_cached(source_repo):
    head = _git(source_repo, ["rev-parse", SOURCE_BRANCH]).decode("ascii").strip()
    if _INDEX_CACHE["key"] == head and _INDEX_CACHE["data"] is not None:
        return _INDEX_CACHE["data"]
    idx = build_source_index(source_repo)
    _INDEX_CACHE["key"] = head
    _INDEX_CACHE["data"] = idx
    return idx


# ---------------------------------------------------------------------------
# source backfill — the one curve that CAN be reconstructed retroactively
# ---------------------------------------------------------------------------
def backfill_source(source_repo, days=DEFAULT_BACKFILL_DAYS, asof_hour=ASOF_HOUR, today=None):
    """Per-day source inventory from git. Each day's datapoint is the tree at the
    last MAINLINE commit before <asof_hour>:00 that day, on SOURCE_BRANCH only.

    --first-parent is load-bearing, not decoration. `rev-list --before` walks by
    commit date over everything reachable, so merging a branch whose commits are
    dated earlier than the cutoff retroactively changes the answer for days that
    already had a datapoint — a past day's line count would silently rewrite
    itself hours later. Observed on 2026-07-29: merging PR #126 at 16:54 moved
    that day's "before 12:00" commit onto the merged branch and dropped the
    reported total by 206 lines. Following only first parents pins each day to
    what the mainline actually looked like, and a later merge lands on its own
    (later-dated) merge commit instead of rewriting history.

    Reading a branch ref touches refs + the object DB, never the working tree or
    index.lock, so this is safe while the repo is mid-rebase or on a detached
    HEAD checkout.
    """
    today = today or _today()
    out = []
    blob_sizes = {}
    trees = {}
    for i in range(days):
        day = today - datetime.timedelta(days=i)
        try:
            sha = _git(source_repo, ["rev-list", "-1", "--first-parent",
                                     "--before=%s %02d:00" % (day.isoformat(), asof_hour),
                                     SOURCE_BRANCH]).decode("ascii").strip()
        except Exception:  # noqa: BLE001
            sha = ""
        if not sha:
            continue
        if sha not in trees:
            entries = []
            raw = _git(source_repo, ["ls-tree", "-r", sha, "--", "global-hooks/"])
            for line in raw.decode("utf-8", "replace").splitlines():
                meta, _, path = line.partition("\t")
                fields = meta.split()
                if len(fields) >= 3 and fields[1] == "blob" and not _is_excluded_source(path):
                    entries.append((fields[2], path))
                    blob_sizes.setdefault(fields[2], None)
            trees[sha] = entries
        out.append({"date": day.isoformat(), "commit": sha[:12], "_entries": trees[sha]})

    # One batch read for every blob any day referenced (measured: 1455 lookups
    # collapse to ~116 unique blobs over 30 days).
    if blob_sizes:
        raw = _git(source_repo, ["cat-file", "--batch"],
                   stdin=("\n".join(sorted(blob_sizes)) + "\n").encode("ascii"))
        pos = 0
        while pos < len(raw):
            nl = raw.find(b"\n", pos)
            if nl < 0:
                break
            header = raw[pos:nl].split()
            if len(header) < 3:
                pos = nl + 1
                continue
            sha, size = header[0].decode("ascii"), int(header[2])
            blob_sizes[sha] = _count_lines(raw[nl + 1:nl + 1 + size])
            pos = nl + 1 + size + 1

    for point in out:
        entries = point.pop("_entries")
        hooks = [(s, p) for s, p in entries
                 if p.endswith(".sh") or p.endswith(".py") or p.endswith(".js")]
        point["files"] = len(hooks)
        point["lines"] = sum(blob_sizes.get(s) or 0 for s, _ in hooks)
        point["deployable_files"] = len([1 for _, p in hooks
                                         if "/per-repo/hooks/" in p or p.count("/") == 1])
    out.sort(key=lambda r: r["date"])
    return out


# ---------------------------------------------------------------------------
# snapshots
# ---------------------------------------------------------------------------
_HISTORY_PATH = os.path.join(STATE_DIR, "source-history.json")


def _backfill_cached(source_repo, days, allow_write=False):
    """Backfill, reusing the on-disk result while the source HEAD and the date
    are both unchanged. The walk itself is ~2 s; a page load should not pay that
    every time.

    allow_write is False on every request path. Only the snapshot thread refills
    the cache, so a GET stays strictly side-effect-free (see build_hooks). A GET
    that misses simply computes in memory and returns without persisting.
    """
    head = _git(source_repo, ["rev-parse", SOURCE_BRANCH]).decode("ascii").strip()
    key = {"head": head, "date": _today().isoformat(), "days": days}
    with _LOCK:
        try:
            with open(_HISTORY_PATH, encoding="utf-8") as f:
                cached = json.load(f)
            if all(cached.get(k) == v for k, v in key.items()):
                return cached["points"]
        except (OSError, ValueError, KeyError):
            pass
    points = backfill_source(source_repo, days)
    if allow_write:
        with _LOCK:
            _write_atomic(_HISTORY_PATH, dict(key, points=points))
    return points


def _snapshot_path(day):
    return os.path.join(STATE_DIR, "deployed-%s.json" % day)


def _write_atomic(path, payload):
    """tmp + os.replace, same as monitor._office_pull_once. A reader must never
    observe a half-written snapshot."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False)
    os.replace(tmp, path)


def snapshot_if_due(cfg, now=None):
    """Write today's deployed snapshot if there isn't one yet. Idempotent.

    NO time-of-day gate: the deployed side is a live capture, not a historical
    reconstruction, so a 09:00 sample is just as valid as a 12:00 one — and
    gating would silently drop every day the machine is only on in the morning,
    on the one curve that can never be backfilled. The source side's 12:00 rule
    is a separate concern (see backfill_source) and the two need not align.
    """
    now = now or time.time()
    # Keep the source-history cache warm here rather than on the request path,
    # so /api/hooks never has to write anything to be fast.
    try:
        _backfill_cached(_source_repo(cfg), _backfill_days(cfg), allow_write=True)
    except Exception:  # noqa: BLE001 — a cold cache costs latency, never data
        pass

    day = datetime.date.fromtimestamp(now).isoformat()
    path = _snapshot_path(day)
    with _LOCK:
        if os.path.exists(path):
            return None
        snap = scan_deployed(cfg, now)
        snap["date"] = day
        _write_atomic(path, snap)
        _prune(_backfill_days(cfg) * 2)
        return day


def _prune(keep_days):
    cutoff = (_today() - datetime.timedelta(days=keep_days)).isoformat()
    for path in glob.glob(os.path.join(STATE_DIR, "deployed-*.json")):
        day = os.path.basename(path)[len("deployed-"):-len(".json")]
        if day < cutoff:
            try:
                os.remove(path)
            except OSError:
                pass


def _load_snapshot(day):
    try:
        with open(_snapshot_path(day), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _snapshot_days():
    days = []
    for path in sorted(glob.glob(os.path.join(STATE_DIR, "deployed-*.json"))):
        days.append(os.path.basename(path)[len("deployed-"):-len(".json")])
    return days


# ---------------------------------------------------------------------------
# API payload
# ---------------------------------------------------------------------------
def build_hooks(cfg, date=None, rescan=False):
    """Payload for /api/hooks.

    `rescan` recomputes the live scan and returns it WITHOUT writing anything —
    all writes belong to the snapshot thread. _token_ok waves localhost through,
    and every write endpoint sits behind do_POST's Origin+CSRF gate, so a GET
    that writes would be a CSRF-free local write primitive.
    """
    source_repo = _source_repo(cfg)
    days = _backfill_days(cfg)

    if rescan:
        live = scan_deployed(cfg)
    else:
        with _LOCK:
            hit = (_SCAN_CACHE["data"] is not None
                   and time.time() - _SCAN_CACHE["ts"] < _SCAN_CACHE_TTL)
            live = _SCAN_CACHE["data"] if hit else None
        if live is None:
            live = scan_deployed(cfg)
            with _LOCK:
                _SCAN_CACHE.update(ts=time.time(), data=live)

    try:
        if not source_repo:
            # Same guard as scan_deployed: git -C "" runs in the CWD, so an
            # unset config would backfill against whatever repo the server
            # happens to sit in (a fresh clone sees a confusing git error).
            raise RuntimeError("hooks_source_repo not configured")
        source_history = _backfill_cached(source_repo, days)
        source_err = None
    except Exception as e:  # noqa: BLE001
        source_history, source_err = [], "母本回溯失敗：%s" % e
    if not source_history and not source_err:
        # backfill_source swallows per-day rev-list failures, so an empty result
        # is silent by construction. Never render "unavailable" without a reason.
        source_err = (live["source"].get("note")
                      or "母本回溯無資料（%s 上找不到 %s 分支的歷史）" % (source_repo, SOURCE_BRANCH))

    snap_days = _snapshot_days()
    deployed_since = snap_days[0] if snap_days else None
    deployed_history = []
    for day in snap_days:
        snap = _load_snapshot(day)
        if not snap:
            continue
        totals = snap.get("totals", [])
        # The plotted series is the CLAUDE surfaces only, de-duplicated by hook
        # name — that is the population the source repo actually governs. Codex
        # and antigravity hooks have no counterpart in global-hooks/, so folding
        # them into the same line would show a gap that no deployment could close.
        claude = [t for t in totals if t.get("vendor") == "claude"]
        deployed_history.append({
            "date": day,
            "files": sum(t["files"] for t in totals),
            "lines": sum(t["lines"] for t in totals),
            "distinct_files": sum(t.get("distinct_files", 0) for t in claude),
            "distinct_lines": sum(t.get("distinct_lines", 0) for t in claude),
            "captured_at": snap.get("captured_at")})

    payload = {
        "generated": _iso(time.time()),
        "window_days": days,
        "source": {"available": bool(source_history), "note": source_err,
                   "repo": source_repo, "branch": SOURCE_BRANCH, "asof_hour": ASOF_HOUR},
        "source_history": source_history,
        "deployed_history": deployed_history,
        "deployed_since": deployed_since,
        "today": live,
    }

    if date:
        payload["date"] = date
        payload["date_source"] = next((p for p in source_history if p["date"] == date), None)
        snap = _load_snapshot(date)
        if snap:
            payload["date_deployed"] = snap
        else:
            payload["date_deployed"] = None
            if deployed_since and date < deployed_since:
                payload["date_deployed_reason"] = {
                    "kind": "before_start",
                    "text": "早於部署快照起始日（%s）——此日期永遠不會有資料，非遺失。" % deployed_since}
            else:
                payload["date_deployed_reason"] = {
                    "kind": "gap",
                    "text": "當日沒有快照（機器未開機），母本仍有資料。"}
    return payload


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _cfg_from_disk():
    for name in ("config.json", "config.example.json"):
        path = os.path.join(HERE, name)
        if os.path.isfile(path):
            try:
                with open(path, encoding="utf-8") as f:
                    return json.load(f)
            except ValueError:
                pass
    return {}


def _print_scan(snap):
    print("captured %s   source=%s" % (snap["captured_at"],
                                       "ok" if snap["source"]["available"]
                                       else snap["source"]["note"]))
    for total in snap["totals"]:
        print("  %-18s files=%-4d distinct=%-3d lines=%-7d custody=%s"
              % (total["key"], total["files"], total["distinct_files"], total["lines"],
                 total["custody"] or "-"))
        if total["events"]:
            print("       events: %s" % ", ".join(total["events"]))
    refs = [(r["repo"], b) for r in snap["rows"] for b in (r.get("broken_refs") or [])]
    if refs:
        print("  BROKEN REF (已部署的 script 找不到它引用的同層檔案):")
        for repo, b in refs:
            print("    %s / %s -> %s" % (repo, b["by"], b["ref"]))
    opted = sorted({r["repo"] for r in snap["rows"] if r.get("opted_out")})
    if opted:
        print("  已退出同步（%s）：%s" % (OPT_OUT_MARKER, ", ".join(opted)))
    miss = [(r["repo"], m["name"], m["custody"]) for r in snap["rows"]
            for m in r.get("missing", []) if m["custody"] == "missing"]
    if miss:
        print("  MISSING (有 manifest 契約，母本有、部署沒有):")
        for repo, name, _ in miss:
            print("    %s / %s" % (repo, name))
    bad = [(r["repo"], f["name"], f["custody"]) for r in snap["rows"]
           for f in r.get("files", []) if f["custody"] not in ("current", "local")]
    if bad:
        print("  非 current/local:")
        for repo, name, state in bad[:40]:
            print("    %-24s %-26s %s" % (repo, name, state))
        if len(bad) > 40:
            print("    ... +%d more" % (len(bad) - 40))
    for nh in snap["no_hook_surfaces"]:
        print("  無 hook 面: %-12s %s (%s)" % (nh["vendor"], nh["note"], nh["checked"]))
    if snap["unavailable"]:
        print("  UNAVAILABLE: %s" % snap["unavailable"])


if __name__ == "__main__":
    import sys

    cfg = _cfg_from_disk()
    cmd = sys.argv[1] if len(sys.argv) > 1 else "scan"
    t0 = time.time()
    if cmd == "scan":
        _print_scan(scan_deployed(cfg))
    elif cmd == "backfill":
        for point in backfill_source(_source_repo(cfg), _backfill_days(cfg)):
            print("%s %s files=%-3d lines=%-6d deployable=%d"
                  % (point["date"], point["commit"], point["files"], point["lines"],
                     point["deployable_files"]))
    elif cmd == "snapshot":
        day = snapshot_if_due(cfg)
        print("wrote %s" % day if day else "today's snapshot already exists")
    elif cmd == "show":
        print(json.dumps(build_hooks(cfg, date=sys.argv[2] if len(sys.argv) > 2 else None),
                         ensure_ascii=False, indent=1)[:8000])
    else:
        print(__doc__)
        sys.exit(2)
    print("(%.2fs)" % (time.time() - t0))
