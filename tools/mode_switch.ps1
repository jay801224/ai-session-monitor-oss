# mode_switch.ps1 - drive an EXISTING Claude session back to a "never-ask" mode
# (bypass / auto), for use when the user is remote and a plan-approval flipped the
# session into an asking/editing mode.
#
# Targets WITHOUT any wrapper, via ~/.claude/sessions/<pid>.json:
#   sessionId  = stable id (match by prefix)
#   name       = live WT tab title (read at run time -> survives "name drift")
#   waitingFor = "permission prompt" when stuck at a Yes/No
#   pid        = OS pid (liveness check)
#
# MODE READ (verified 2026-06-18): read the live mode badge from the WT TermControl
# UIA element's visible text (TextPattern). NOT the transcript tail (it lags the UI).
#   "<...> bypass permissions on (shift+tab to cycle)" -> bypass
#   "<...> auto mode on (shift+tab to cycle)"          -> auto
#   "<...> accept edits on (shift+tab to cycle)"       -> acceptEdits
#   "<...> plan mode on (shift+tab to cycle)"          -> plan
#   (no badge line)                                    -> default
# Ring (shift+tab forward): plan -> bypass -> auto -> default -> acceptEdits -> (plan).
#
# KEY SEND (verified 2026-06-18): native Win32 keybd_event P/Invoke (~40ms, reliable),
# NOT AutoHotkey (per-key process spawn ~1s, flaky). Foreground injection only, so:
#   - verify GetForegroundWindow()==target hwnd IMMEDIATELY before each key; abort else.
#   - ~40ms inter-key delay so the TUI registers Shift held during Tab.
#   - ALWAYS release modifiers in finally (a stuck Shift is system-wide).
#
# CORE RULE: never count presses. Read the live mode each step; stop exactly at the
# first bypass/auto reached. At a permission prompt, send Enter first (standing
# approval), then resume. No progress -> retry once; still none -> FAIL.
#
# SAFETY (a wrong tab corrupts another live session): abort unless EXACTLY one tab
# Name matches; refuse generic/empty names; refuse ambiguous sessionId prefix; refuse
# split panes (>1 TermControl); verify selection + foreground before every key.
#
# NOTE: ASCII-only (PS 5.1 misreads non-BOM UTF-8 .ps1 as cp950, corrupting literals).
#
# Usage:
#   powershell -File mode_switch.ps1 -SessionPrefix 17763eda            # switch to bypass/auto
#   powershell -File mode_switch.ps1 -SessionPrefix 17763eda -ReadOnly  # just report mode, send nothing
param(
    [Parameter(Mandatory)][string]$SessionPrefix,
    [ValidateSet('any', 'bypass', 'auto')][string]$Target = 'any',
    [switch]$ReadOnly
)
$ErrorActionPreference = "Stop"
$SDIR = Join-Path $env:USERPROFILE ".claude\sessions"
$TARGETS = switch ($Target) { 'bypass' { @('bypass') } 'auto' { @('auto') } default { @('bypass', 'auto') } }
$GENERIC = @('PowerShell', 'Windows PowerShell', 'Command Prompt', 'cmd', 'pwsh', 'Developer PowerShell')
$MAXACTIONS = 8
$KEYDELAY = 40
$LOCK = Join-Path $env:TEMP 'mode_switch.lock'

Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
Add-Type @"
using System;using System.Runtime.InteropServices;
public class Win {
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint flags, UIntPtr extra);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a, uint b, bool attach);
}
"@
$VK_SHIFT = 0x10; $VK_TAB = 0x09; $VK_RET = 0x0D; $KEYUP = 0x2; $SW_RESTORE = 9

$script:lockHeld = $false
function Cleanup { if ($script:lockHeld) { Remove-Item -LiteralPath $LOCK -Force -EA SilentlyContinue } }
function Release-Mods { try { [Win]::keybd_event([byte]$VK_SHIFT, 0, $KEYUP, [UIntPtr]::Zero) } catch {} }
function Fail($m) { Release-Mods; Cleanup; Write-Output "FAIL: $m -> use Remote Control instead"; exit 2 }
function Done($m) { Cleanup; Write-Output $m; exit 0 }

# --- single-instance lock (no two runs injecting keys at once) ---
if (-not $ReadOnly) {
    try { $fs = [System.IO.File]::Open($LOCK, 'CreateNew', 'Write'); $fs.Close(); $script:lockHeld = $true }
    catch { Write-Output "FAIL: another mode_switch is already running (lock held) -> try again shortly"; exit 3 }
}

# --- resolve session: unique prefix, live pid, usable name ---
function Resolve-Session {
    $hits = @()
    foreach ($f in Get-ChildItem (Join-Path $SDIR "*.json") -EA SilentlyContinue) {
        try { $o = Get-Content $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
        if ($o.sessionId -like "$SessionPrefix*") { $hits += $o }
    }
    if ($hits.Count -eq 0) { Fail "session '$SessionPrefix' not found in sessions/" }
    if ($hits.Count -gt 1) { Fail "ambiguous prefix '$SessionPrefix' matches $($hits.Count) sessions" }
    $o = $hits[0]
    if (-not (Get-Process -Id $o.pid -EA SilentlyContinue)) { Fail "session pid $($o.pid) not alive (stale json)" }
    if (-not $o.name) { Fail "session has no tab name (generic tab) - cannot target uniquely" }
    if ($GENERIC -contains $o.name) { Fail "session name '$($o.name)' is generic - refusing (collision risk)" }
    return $o
}

$cc = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ClassNameProperty, 'CASCADIA_HOSTING_WINDOW_CLASS')
$tc = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::TabItem)
$termCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ClassNameProperty, 'TermControl')

# Find the UNIQUE tab whose Name contains $name. Returns @{tab;win;hwnd} or $null.
function Find-Tab($name) {
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $hits = @()
    foreach ($w in $root.FindAll([System.Windows.Automation.TreeScope]::Children, $cc)) {
        foreach ($t in $w.FindAll([System.Windows.Automation.TreeScope]::Descendants, $tc)) {
            if ($t.Current.Name -like "*$name*") {
                $hits += @{ tab = $t; win = $w; hwnd = [IntPtr]$w.Current.NativeWindowHandle }
            }
        }
    }
    if ($hits.Count -ne 1) { return $null }
    return $hits[0]
}

# Force a window to the foreground (handles minimized + foreground lock). Returns bool.
function Bring-Foreground([IntPtr]$h) {
    if ([Win]::IsIconic($h)) { [Win]::ShowWindow($h, $SW_RESTORE) | Out-Null; Start-Sleep -Milliseconds 150 }
    if ([Win]::GetForegroundWindow() -eq $h) { return $true }
    $fg = [Win]::GetForegroundWindow()
    $procId = [uint32]0
    $fgThread = [Win]::GetWindowThreadProcessId($fg, [ref]$procId)
    $myThread = [Win]::GetCurrentThreadId()
    $attached = $false
    if ($fgThread -ne 0 -and $fgThread -ne $myThread) { $attached = [Win]::AttachThreadInput($myThread, $fgThread, $true) }
    [Win]::SetForegroundWindow($h) | Out-Null
    if ($attached) { [Win]::AttachThreadInput($myThread, $fgThread, $false) | Out-Null }
    Start-Sleep -Milliseconds 150
    return ([Win]::GetForegroundWindow() -eq $h)
}

# Select the target tab, verify selected, verify exactly one terminal (no split pane),
# bring its window to foreground. Returns the win element on success, else $null.
function Select-Target($ft) {
    try { $ft.tab.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select() } catch { return $null }
    Start-Sleep -Milliseconds 250
    if (-not $ft.tab.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Current.IsSelected) { return $null }
    $terms = $ft.win.FindAll([System.Windows.Automation.TreeScope]::Descendants, $termCond)
    if ($terms.Count -gt 1) { Fail "target tab has split panes ($($terms.Count) terminals) - cannot disambiguate" }
    if (-not (Bring-Foreground $ft.hwnd)) { return $null }
    # CRITICAL: after Select()+foreground, keyboard focus sits on the tab strip, not
    # the terminal pane -> injected keys never reach Claude. Move focus onto the
    # TermControl content area explicitly.
    if ($terms.Count -eq 1) { try { $terms[0].SetFocus() } catch {} ; Start-Sleep -Milliseconds 120 }
    return $ft.win
}

# Read the LIVE permission mode from the bottom status badge.
function Read-Mode($win) {
    $term = $null
    for ($i = 0; $i -lt 4 -and -not $term; $i++) {
        $term = $win.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $termCond)
        if (-not $term) { Start-Sleep -Milliseconds 100 }
    }
    if (-not $term) { return 'unknown' }
    $txt = $term.GetCurrentPattern([System.Windows.Automation.TextPattern]::Pattern).DocumentRange.GetText(-1)
    if (-not $txt -or $txt.Length -lt 20) { return 'unknown' }
    $lines = $txt -split "`r?`n"
    $badge = $null
    foreach ($l in $lines) { if ($l -match 'shift\+tab to cycle') { $badge = $l } }   # last (bottom) wins
    if ($badge) {
        if     ($badge -match 'bypass permissions on') { return 'bypass' }
        elseif ($badge -match 'auto mode on')          { return 'auto' }
        elseif ($badge -match 'accept edits on')       { return 'acceptEdits' }
        elseif ($badge -match 'plan mode on')          { return 'plan' }
        else                                           { return 'unknownBadge' }
    }
    # no badge line. Confirm we truly read the live status region (token/model bar)
    # before calling it 'default'; otherwise it's an unread frame.
    if ($txt -match 'shift\+tab|/clear|context|ctx ') { return 'default' }
    return 'unknown'
}

# Inject one key into the (verified foreground) target. Modifiers released in finally.
function Send-Key($key, [IntPtr]$hwnd) {
    if ([Win]::GetForegroundWindow() -ne $hwnd) { return $false }   # TOCTOU guard: abort if not foreground
    try {
        if ($key -eq 'shifttab') {
            [Win]::keybd_event([byte]$VK_SHIFT, 0, 0, [UIntPtr]::Zero);      Start-Sleep -Milliseconds $KEYDELAY
            [Win]::keybd_event([byte]$VK_TAB,   0, 0, [UIntPtr]::Zero);      Start-Sleep -Milliseconds $KEYDELAY
            [Win]::keybd_event([byte]$VK_TAB,   0, $KEYUP, [UIntPtr]::Zero); Start-Sleep -Milliseconds $KEYDELAY
        } else {
            # Enter
            [Win]::keybd_event([byte]$VK_RET, 0, 0, [UIntPtr]::Zero);        Start-Sleep -Milliseconds $KEYDELAY
            [Win]::keybd_event([byte]$VK_RET, 0, $KEYUP, [UIntPtr]::Zero)
        }
    } finally {
        [Win]::keybd_event([byte]$VK_SHIFT, 0, $KEYUP, [UIntPtr]::Zero)      # always release Shift
    }
    return $true
}

# ============================ main ============================
$sess = Resolve-Session
$name = $sess.name
$ft = Find-Tab $name
if (-not $ft) { Fail "tab matching name '$name' is not unique/selectable" }
$win = Select-Target $ft
if (-not $win) { Fail "could not select/foreground target tab" }
$mode = Read-Mode $win
if ($mode -eq 'unknown' -or $mode -eq 'unknownBadge' -or $mode -eq 'multipane') { Fail "cannot read mode reliably (read=$mode)" }
Write-Output "TARGET: $($sess.sessionId.Substring(0,8)) name='$name' status=$($sess.status) waitingFor='$($sess.waitingFor)'"
Write-Output "START: mode=$mode"

if ($ReadOnly) { Done "READONLY: mode=$mode (no keys sent)" }
if ($TARGETS -contains $mode) { Done "DONE: already at '$mode' (no action)" }

$seen = @{}
for ($n = 1; $n -le $MAXACTIONS; $n++) {
    $sess = Resolve-Session                       # fresh: liveness + waitingFor + name (re-verify each step)
    if ($sess.name -ne $name) { Fail "tab name changed mid-run ('$name' -> '$($sess.name)') - aborting" }
    $ft = Find-Tab $name
    if (-not $ft) { Fail "target tab no longer unique/selectable" }
    $win = Select-Target $ft
    if (-not $win) { Fail "lost foreground/selection on target" }

    $atPrompt = [bool]$sess.waitingFor
    if (-not $atPrompt) {
        $mode = Read-Mode $win
        if ($TARGETS -contains $mode) { Done "DONE: landed on '$mode' after $($n-1) keystroke(s)" }
        if ($mode -eq 'unknown' -or $mode -eq 'unknownBadge') { Fail "mode read unreliable mid-run (read=$mode)" }
        if ($seen.ContainsKey($mode)) { Fail "ring traversed without reaching bypass/auto - session has no never-ask mode" }
        $seen[$mode] = $true
    }

    $key = if ($atPrompt) { 'enter' } else { 'shifttab' }
    $label = if ($atPrompt) { "Enter(clear-prompt)" } else { "Shift+Tab" }
    $beforeMode = if ($atPrompt) { "(prompt)" } else { $mode }
    $beforeWait = $sess.waitingFor

    # send + verify, with up to 3 attempts. Covers BOTH failure modes safely:
    #   - foreground stolen before send (user switched back to look) -> re-acquire & retry
    #   - key sent but no mode change (window-timing miss)           -> re-acquire & retry
    # A wrong-window send is impossible: Send-Key re-checks foreground and refuses.
    $changed = $false; $afterMode = $beforeMode; $afterWait = $beforeWait
    for ($attempt = 1; $attempt -le 3 -and -not $changed; $attempt++) {
        if ($attempt -gt 1) {
            $ft = Find-Tab $name; if (-not $ft) { Fail "target tab lost on retry" }
            $win = Select-Target $ft; if (-not $win) { Fail "lost foreground/selection on retry" }
        }
        if (-not (Send-Key $key $ft.hwnd)) {
            Write-Output "action ${n} ($label): foreground not held (you may have switched back) -> re-acquire & retry"
            continue   # no key was sent; loop re-acquires
        }
        for ($p = 0; $p -lt 12; $p++) {
            Start-Sleep -Milliseconds 100
            $afterWait = (Resolve-Session).waitingFor
            $afterMode = if ([bool]$afterWait) { "(prompt)" } else { Read-Mode $win }
            if (($afterMode -ne $beforeMode) -or ($beforeWait -and -not $afterWait)) { $changed = $true; break }
        }
        if (-not $changed) { Write-Output "action ${n} ($label): no progress -> retry" }
    }
    if (-not $changed) { Fail "no progress after 3 attempts at action $n (cannot hold the window / catch timing)" }
    Write-Output "action ${n}: $label  mode: $beforeMode -> $afterMode  waitingFor: '$beforeWait' -> '$afterWait'"
}
Fail "did not reach bypass/auto within $MAXACTIONS actions"
