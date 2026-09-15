# new_session.ps1 - launch a new Claude Code session in a SAFE, allowlisted folder.
# Used by the TG "/new" flow. cd into the chosen folder, then start claude in bypass
# (permission-on) with a stable display name (-n) so the session is reliably lockable.
#
# SECURITY (user requirement): a new session may ONLY open under an allowed root the
# CALLER passes in (monitor.py sends its configured workspace_roots). Opening Claude
# at an arbitrary path on the whole machine is refused here (defense in depth - the
# Python side validates against the same roots before this script ever runs).
# FAIL CLOSED: no root passed => refuse everything, never "allow anything".
#
# Run via: powershell -NoExit -ExecutionPolicy Bypass -File new_session.ps1 <dir> <name> <mode> <roots> <prompt>
# Read args POSITIONALLY from $args (NOT a param() block). param-binding via the
# wt-spawned powershell was intermittently failing with AmbiguousParameterSet; the
# automatic $args array bypasses binding entirely and is immune.
#   arg0 = folder (required), arg1 = display name (optional), arg2 = permission mode (optional)
# mode is one of: default / acceptEdits / auto / bypassPermissions (default = bypassPermissions,
# backward compatible with the original bypass-only behaviour). bypassPermissions maps to the
# proven --dangerously-skip-permissions flag; the others map to --permission-mode <mode>.
$Folder = if ($args.Count -ge 1) { [string]$args[0] } else { "" }
$Name = if ($args.Count -ge 2) { [string]$args[1] } else { "" }
$Mode = if ($args.Count -ge 3 -and $args[2]) { [string]$args[2] } else { "bypassPermissions" }
# arg3 = the allowed root(s), ';'-joined, from the caller's workspace_roots. A
# positional arg rather than an env var because a `wt -w <existing>` tab runs
# under the ALREADY-RUNNING WindowsTerminal process, which never saw env vars
# set for this spawn. Deliberately placed BEFORE the optional prompt: shells
# that re-parse the command line (wt) may drop empty "" args, and a required
# arg must never sit behind one that is legitimately empty. Was a hardcoded
# C:\myrepo - the packager's disk, nobody else's.
$RootsArg = if ($args.Count -ge 4 -and $args[3]) { [string]$args[3] } else { "" }
# arg4 = optional initial prompt (G2 preset template) — passed to claude as its
# positional prompt argument; empty/absent = interactive start, unchanged.
$Prompt = if ($args.Count -ge 5 -and $args[4]) { [string]$args[4] } else { "" }
$ErrorActionPreference = "Stop"
if (-not $Folder) { Write-Host "REFUSED: no folder given"; Start-Sleep 6; exit 1 }
$VALID_MODES = @('default', 'acceptEdits', 'auto', 'bypassPermissions')
if ($VALID_MODES -notcontains $Mode) {
    Write-Host "REFUSED: invalid permission mode '$Mode'"; Start-Sleep 6; exit 1
}
if (-not $RootsArg) {
    Write-Host "REFUSED: no allowed root passed. The caller must supply its workspace_roots; without one every spawn is refused (fail closed)."
    Start-Sleep 6; exit 1
}

try {
    $full = [System.IO.Path]::GetFullPath($Folder)
} catch {
    Write-Host "REFUSED: bad folder path '$Folder'"; Start-Sleep 6; exit 1
}
# Reject UNC / device paths outright (\\server\share, \\?\C:\...).
if ($full.StartsWith('\\')) {
    Write-Host "REFUSED: UNC/device path not allowed: '$full'"; Start-Sleep 6; exit 1
}
# The folder must sit under ONE of the allowed roots; remember which, for the
# reparse-point walk below.
$ROOT = $null
foreach ($r in ($RootsArg -split ';' | Where-Object { $_ })) {
    try { $cand = [System.IO.Path]::GetFullPath($r) } catch { continue }
    if ($cand.StartsWith('\\')) { continue }   # a UNC root would widen, not scope
    $prefix = $cand.TrimEnd('\') + '\'
    if ($full.ToLower() -eq $cand.ToLower() -or $full.ToLower().StartsWith($prefix.ToLower())) {
        $ROOT = $cand; break
    }
}
if (-not $ROOT) {
    Write-Host "REFUSED: '$full' is outside every allowed root ($RootsArg). New sessions are scoped to workspace_roots only (safety)."
    Start-Sleep 6; exit 1
}
if (-not (Test-Path -LiteralPath $full -PathType Container)) {
    Write-Host "REFUSED: '$full' is not an existing folder."; Start-Sleep 6; exit 1
}
# R6: GetFullPath does NOT resolve junctions/symlinks, so a reparse point INSIDE
# C:\myrepo could point OUT (e.g. C:\myrepo\x -> C:\Windows) and pass the prefix check.
# Walk every path component within the root; refuse if any is a reparse point.
$cur = $full
$rootLower = $ROOT.ToLower()
while ($cur.ToLower().StartsWith($rootLower) -and $cur.Length -gt $ROOT.Length) {
    $it = Get-Item -LiteralPath $cur -Force -ErrorAction SilentlyContinue
    if ($it -and (($it.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
        Write-Host "REFUSED: '$cur' is a junction/symlink (could escape $ROOT)."; Start-Sleep 6; exit 1
    }
    $parent = [System.IO.Path]::GetDirectoryName($cur)   # PS5.1: Split-Path -LiteralPath -Parent is an invalid param set
    if (-not $parent -or $parent -eq $cur) { break }
    $cur = $parent
}

Set-Location -LiteralPath $full
Write-Host "Starting Claude (mode=$Mode) in $full  name='$Name' ..."
if ($Mode -eq 'bypassPermissions') {
    $cargs = @('--dangerously-skip-permissions')   # proven bypass path, unchanged
} else {
    $cargs = @('--permission-mode', $Mode)
}
if ($Name) { $cargs += @('-n', $Name) }
if ($Prompt) { $cargs += @($Prompt) }
& claude @cargs
