# handoff_run.ps1 - Phase A context handoff orchestrator (single process, holds ONE
# tab UIA element across the WHOLE sequence so /clear's title-reset can't make us
# re-find the wrong tab). Sequence:
#   1) make the session write a handoff file (wrap-up prompt, clipboard paste)
#   2) poll until the file exists AND the session is idle (2 consecutive idle reads)
#   3) /clear  (verified: keeps process + Remote Control, clears context)
#   4) tell the fresh session to read the handoff file and continue
#
# SAFETY (edge-case hardened):
#   R1/R2 hold the SAME tab element; never re-find by the (reset) title after /clear.
#   R3/R5/Y1/Y2 /clear is the point of no return -> fires ONLY when the handoff file
#       exists, the idle badge is seen twice in a row, the input line is empty, and the
#       foreground is still the held hwnd. Otherwise ABORT (no /clear, no data loss).
#   R4 wrap-up prompt is write-ONE-file only: no git / no push / no delete / no new work.
#   R10 shares the global cc_inject.lock with the other injectors.
#   Verify GetForegroundWindow()==hwnd before EVERY paste and EVERY Enter.
#
# ASCII-only. Usage:
#   powershell -File handoff_run.ps1 -TabTitle CC-xxxxxx -HandoffPath C:\myrepo\proj\_handoff\handoff_123.md
param(
    [Parameter(Mandatory)][string]$TabTitle,
    [Parameter(Mandatory)][string]$HandoffPath,
    [int]$WriteTimeoutSec = 600
)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
Add-Type @"
using System;using System.Runtime.InteropServices;
public class HR {
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
$VK_CTRL = 0x11; $VK_V = 0x56; $VK_RET = 0x0D; $KEYUP = 0x2; $SW_RESTORE = 9

# global injection mutex (shared with handoff_inject / mode_switch)
$LOCK = Join-Path $env:TEMP 'cc_inject.lock'
try { $script:lk = [System.IO.File]::Open($LOCK, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None) }
catch { Write-Output "BUSY: another injection in progress"; exit 3 }
function Fail($m) { [HR]::keybd_event([byte]$VK_CTRL,0,$KEYUP,[UIntPtr]::Zero); Write-Output "FAIL: $m"; exit 2 }

$cc = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ClassNameProperty, 'CASCADIA_HOSTING_WINDOW_CLASS')
$tcCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::TabItem)
$termCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ClassNameProperty, 'TermControl')

# locate the UNIQUE tab ONCE; hold the element + window + hwnd for the whole run
$root = [System.Windows.Automation.AutomationElement]::RootElement
$hits = @()
foreach ($w in $root.FindAll([System.Windows.Automation.TreeScope]::Children, $cc)) {
    foreach ($t in $w.FindAll([System.Windows.Automation.TreeScope]::Descendants, $tcCond)) {
        if ($t.Current.Name -like "*$TabTitle*") { $hits += @{ tab = $t; win = $w; hwnd = [IntPtr]$w.Current.NativeWindowHandle } }
    }
}
if ($hits.Count -ne 1) { Fail "tab matching '$TabTitle' is not unique (count=$($hits.Count))" }
$TAB = $hits[0].tab; $WIN = $hits[0].win; $HWND = $hits[0].hwnd

function Bring-Foreground {
    if ([HR]::IsIconic($HWND)) { [HR]::ShowWindow($HWND, $SW_RESTORE) | Out-Null; Start-Sleep -Milliseconds 150 }
    if ([HR]::GetForegroundWindow() -eq $HWND) { return $true }
    $fg = [HR]::GetForegroundWindow(); $procId = [uint32]0
    $fgT = [HR]::GetWindowThreadProcessId($fg, [ref]$procId); $myT = [HR]::GetCurrentThreadId(); $att = $false
    if ($fgT -ne 0 -and $fgT -ne $myT) { $att = [HR]::AttachThreadInput($myT, $fgT, $true) }
    [HR]::SetForegroundWindow($HWND) | Out-Null
    if ($att) { [HR]::AttachThreadInput($myT, $fgT, $false) | Out-Null }
    Start-Sleep -Milliseconds 150
    return ([HR]::GetForegroundWindow() -eq $HWND)
}
# Select the HELD tab element (valid even after /clear renames it), foreground, SetFocus.
function Focus-Target {
    try { $TAB.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select() } catch { return $false }
    Start-Sleep -Milliseconds 250
    try { if (-not $TAB.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Current.IsSelected) { return $false } } catch { return $false }
    $terms = $WIN.FindAll([System.Windows.Automation.TreeScope]::Descendants, $termCond)
    if ($terms.Count -ne 1) { return $false }   # split pane or no terminal -> unsafe
    if (-not (Bring-Foreground)) { return $false }
    try { $terms[0].SetFocus() } catch {}
    Start-Sleep -Milliseconds 120
    return ([HR]::GetForegroundWindow() -eq $HWND)
}
function Read-Screen {
    $term = $WIN.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $termCond)
    if (-not $term) { return "" }
    try { return $term.GetCurrentPattern([System.Windows.Automation.TextPattern]::Pattern).DocumentRange.GetText(-1) } catch { return "" }
}
function Is-Idle { param($txt) return ($txt -match 'shift\+tab to cycle') }   # badge shows only at the prompt
function Input-Empty { param($txt)
    # Claude's prompt char is U+276F; build it at runtime so the SOURCE stays ASCII
    # (PS 5.1 reads a non-BOM UTF-8 .ps1 as cp950 and would corrupt a literal char).
    $p = [char]0x276F
    $re = '^\s*(>|' + $p + ')'
    $line = (($txt -split "`r?`n") | Where-Object { $_ -match $re } | Select-Object -Last 1)
    if (-not $line) { return $false }
    return ($line -match ($re + '\s*$'))
}
function Paste-Text { param($text, [switch]$NoEnter)
    if (-not (Focus-Target)) { return $false }
    Set-Clipboard -Value $text; Start-Sleep -Milliseconds 120
    if ([HR]::GetForegroundWindow() -ne $HWND) { return $false }
    try {
        [HR]::keybd_event([byte]$VK_CTRL,0,0,[UIntPtr]::Zero); Start-Sleep -Milliseconds 30
        [HR]::keybd_event([byte]$VK_V,0,0,[UIntPtr]::Zero);   Start-Sleep -Milliseconds 30
        [HR]::keybd_event([byte]$VK_V,0,$KEYUP,[UIntPtr]::Zero); Start-Sleep -Milliseconds 30
    } finally { [HR]::keybd_event([byte]$VK_CTRL,0,$KEYUP,[UIntPtr]::Zero) }
    Start-Sleep -Milliseconds 250
    if (-not $NoEnter) {
        if ([HR]::GetForegroundWindow() -ne $HWND) { return $false }
        [HR]::keybd_event([byte]$VK_RET,0,0,[UIntPtr]::Zero); Start-Sleep -Milliseconds 40
        [HR]::keybd_event([byte]$VK_RET,0,$KEYUP,[UIntPtr]::Zero)
    }
    return $true
}
# wait until the session is idle (badge) for 2 consecutive reads; returns bool
function Wait-Idle { param($timeoutSec)
    $deadline = (Get-Date).AddSeconds($timeoutSec); $streak = 0
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 700
        if (Is-Idle (Read-Screen)) { $streak++ } else { $streak = 0 }
        if ($streak -ge 2) { return $true }
    }
    return $false
}

# ---- step 0: must start idle + empty input ----
if (-not (Wait-Idle 30)) { Fail "session not idle at start - aborting" }
if (-not (Input-Empty (Read-Screen))) { Fail "input box not empty at start - aborting (would corrupt the prompt)" }

# ---- step 1: wrap-up prompt (write ONE file only; no git/rm/push/new work) ----
$wrap = @"
AUTOMATED CONTEXT HANDOFF. This session's context window is nearly full and is about to be reset to free space. Do the following and NOTHING else:
Write a handoff note to this exact file: $HandoffPath  (create the _handoff folder if missing).
The note must capture: (1) what you were working on, (2) where you are stuck / the current state, (3) any question you were about to ask me, (4) open tasks / TODOs, (5) any leftover bug and how to reproduce it, (6) the exact next step to continue.
HARD RULES: write ONLY that one file. Do NOT run git, do NOT commit or push, do NOT modify or delete any other file, do NOT start or continue any other task. After the file is written, stop and wait.
"@
if (-not (Paste-Text $wrap)) { Fail "could not inject wrap-up prompt (foreground lost) - no action taken" }
Write-Output "STEP1: wrap-up prompt sent; waiting for handoff file + idle..."

# ---- step 2: wait for the handoff file AND idle (2 consecutive) ----
$deadline = (Get-Date).AddSeconds($WriteTimeoutSec)
$ok = $false
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 2
    if (Test-Path -LiteralPath $HandoffPath) {
        # file exists; now require the session to be idle (done writing) - 2 reads
        $s = 0
        for ($i = 0; $i -lt 6; $i++) { Start-Sleep -Milliseconds 700; if (Is-Idle (Read-Screen)) { $s++ } else { $s = 0 }; if ($s -ge 2) { break } }
        if ($s -ge 2) { $ok = $true; break }
    }
}
if (-not $ok) { Fail "handoff file not written / session still busy within ${WriteTimeoutSec}s - NOT clearing (no data loss)" }
Write-Output "STEP2: handoff file present + session idle: $HandoffPath"

# ---- step 3: /clear (point of no return) - triple gate before firing ----
if (-not (Focus-Target)) { Fail "lost foreground before /clear - aborting (context NOT cleared)" }
$scr = Read-Screen
if (-not (Is-Idle $scr)) { Fail "session not idle right before /clear - aborting" }
if (-not (Input-Empty $scr)) { Fail "input not empty right before /clear - aborting" }
if (-not (Paste-Text "/clear")) { Fail "could not submit /clear (foreground lost)" }
Start-Sleep -Seconds 3
if (-not (Wait-Idle 30)) { Fail "session did not return to idle after /clear (RC may need manual check)" }
Write-Output "STEP3: /clear submitted; context cleared (RC survives per Step-0)"

# ---- step 4: tell the fresh session to read the handoff and continue ----
$cont = "Read the handoff note at $HandoffPath and continue the work from where the previous session left off. Follow what it says."
if (-not (Paste-Text $cont)) { Fail "could not inject read-handoff prompt (foreground lost) - handoff file exists at $HandoffPath, please continue manually" }
Write-Output "DONE: handoff complete. fresh session reading $HandoffPath"
