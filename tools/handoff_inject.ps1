# handoff_inject.ps1 - reliably inject TEXT (+ Enter) into an EXISTING Claude session's
# WT tab, for the context-handoff / new-session flows. Reuses mode_switch.ps1's safe
# targeting (unique sessionId prefix -> unique tab by name -> select -> foreground ->
# SetFocus the terminal pane -> verify foreground before every key).
#
# Why clipboard paste, not typing: per KB, sending a long text STRING char-by-char into
# conpty is unreliable; Set-Clipboard + Ctrl+V is robust. Short control sequences (Enter)
# go via keybd_event.
#
# ASCII-only (PS 5.1 cp950). Usage:
#   powershell -File handoff_inject.ps1 -SessionPrefix 17763eda -Text "/clear"
#   powershell -File handoff_inject.ps1 -SessionPrefix 17763eda -Text "long prompt..." -NoEnter
# Target EITHER by -SessionPrefix (resolve via sessions/<pid>.json name) OR by
# -TabTitle (match the live WT tab title directly via UIA). TabTitle is more robust
# because the json 'name' field is often empty while the WT tab always has a title.
param(
    [string]$SessionPrefix,
    [string]$TabTitle,
    [string]$Text,
    [switch]$NoEnter,
    [switch]$EnterOnly    # send only Enter (submit whatever is already in the input box)
)
if (-not $SessionPrefix -and -not $TabTitle) { Write-Output "FAIL: need -SessionPrefix or -TabTitle"; exit 2 }
if (-not $EnterOnly -and -not $Text) { Write-Output "FAIL: need -Text (or -EnterOnly)"; exit 2 }

# R10: ONE global injection mutex shared by all foreground keystroke tools, so two
# automations never fight for foreground / inject into the wrong tab. FileShare.None =
# auto-released when this process exits (even on crash), no stale-lock deadlock.
$LOCK = Join-Path $env:TEMP 'cc_inject.lock'
try { $script:lk = [System.IO.File]::Open($LOCK, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None) }
catch { Write-Output "BUSY: another injection in progress - try again shortly"; exit 3 }
$ErrorActionPreference = "Stop"
$SDIR = Join-Path $env:USERPROFILE ".claude\sessions"
$GENERIC = @('PowerShell', 'Windows PowerShell', 'Command Prompt', 'cmd', 'pwsh', 'Developer PowerShell')

Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
Add-Type @"
using System;using System.Runtime.InteropServices;
public class HW {
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

function Fail($m) { Write-Output "FAIL: $m"; exit 2 }

function Resolve-Session {
    $hits = @()
    foreach ($f in Get-ChildItem (Join-Path $SDIR "*.json") -EA SilentlyContinue) {
        try { $o = Get-Content $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
        if ($o.sessionId -like "$SessionPrefix*") { $hits += $o }
    }
    if ($hits.Count -eq 0) { Fail "session '$SessionPrefix' not found" }
    if ($hits.Count -gt 1) { Fail "ambiguous prefix '$SessionPrefix' ($($hits.Count) match)" }
    $o = $hits[0]
    if (-not (Get-Process -Id $o.pid -EA SilentlyContinue)) { Fail "pid $($o.pid) not alive (stale)" }
    if (-not $o.name) { Fail "session has no tab name" }
    if ($GENERIC -contains $o.name) { Fail "name '$($o.name)' is generic - refusing" }
    return $o
}

$cc = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ClassNameProperty, 'CASCADIA_HOSTING_WINDOW_CLASS')
$tc = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::TabItem)
$termCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ClassNameProperty, 'TermControl')

function Find-Tab($name) {
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $hits = @()
    foreach ($w in $root.FindAll([System.Windows.Automation.TreeScope]::Children, $cc)) {
        foreach ($t in $w.FindAll([System.Windows.Automation.TreeScope]::Descendants, $tc)) {
            if ($t.Current.Name -like "*$name*") { $hits += @{ tab = $t; win = $w; hwnd = [IntPtr]$w.Current.NativeWindowHandle } }
        }
    }
    if ($hits.Count -ne 1) { return $null }
    return $hits[0]
}

function Bring-Foreground([IntPtr]$h) {
    if ([HW]::IsIconic($h)) { [HW]::ShowWindow($h, $SW_RESTORE) | Out-Null; Start-Sleep -Milliseconds 150 }
    if ([HW]::GetForegroundWindow() -eq $h) { return $true }
    $fg = [HW]::GetForegroundWindow(); $procId = [uint32]0
    $fgThread = [HW]::GetWindowThreadProcessId($fg, [ref]$procId); $myThread = [HW]::GetCurrentThreadId()
    $attached = $false
    if ($fgThread -ne 0 -and $fgThread -ne $myThread) { $attached = [HW]::AttachThreadInput($myThread, $fgThread, $true) }
    [HW]::SetForegroundWindow($h) | Out-Null
    if ($attached) { [HW]::AttachThreadInput($myThread, $fgThread, $false) | Out-Null }
    Start-Sleep -Milliseconds 150
    return ([HW]::GetForegroundWindow() -eq $h)
}

function Select-Target($ft) {
    try { $ft.tab.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select() } catch { return $false }
    Start-Sleep -Milliseconds 250
    if (-not $ft.tab.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Current.IsSelected) { return $false }
    $terms = $ft.win.FindAll([System.Windows.Automation.TreeScope]::Descendants, $termCond)
    if ($terms.Count -gt 1) { Fail "target tab has split panes ($($terms.Count)) - refusing" }
    if (-not (Bring-Foreground $ft.hwnd)) { return $false }
    if ($terms.Count -eq 1) { try { $terms[0].SetFocus() } catch {} ; Start-Sleep -Milliseconds 120 }
    return $true
}

if ($TabTitle) {
    $name = $TabTitle; $idLabel = "tab:'$TabTitle'"
} else {
    $sess = Resolve-Session; $name = $sess.name; $idLabel = "sid $($sess.sessionId.Substring(0,8))"
}
$ft = Find-Tab $name
if (-not $ft) { Fail "tab matching '$name' not unique/selectable" }
if (-not (Select-Target $ft)) { Fail "could not select/foreground target tab" }

# paste the text via clipboard (reliable for any length), then optional Enter
if (-not $EnterOnly) {
    Set-Clipboard -Value $Text
    Start-Sleep -Milliseconds 120
    if ([HW]::GetForegroundWindow() -ne $ft.hwnd) { Fail "foreground lost before paste - aborted (no input sent)" }
    try {
        [HW]::keybd_event([byte]$VK_CTRL, 0, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds 30
        [HW]::keybd_event([byte]$VK_V, 0, 0, [UIntPtr]::Zero);   Start-Sleep -Milliseconds 30
        [HW]::keybd_event([byte]$VK_V, 0, $KEYUP, [UIntPtr]::Zero); Start-Sleep -Milliseconds 30
    } finally {
        [HW]::keybd_event([byte]$VK_CTRL, 0, $KEYUP, [UIntPtr]::Zero)
    }
    Start-Sleep -Milliseconds 250
}
if (-not $NoEnter) {
    if ([HW]::GetForegroundWindow() -ne $ft.hwnd) { Fail "foreground lost before Enter - text pasted but NOT submitted" }
    [HW]::keybd_event([byte]$VK_RET, 0, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds 40
    [HW]::keybd_event([byte]$VK_RET, 0, $KEYUP, [UIntPtr]::Zero)
}
$tlen = if ($Text) { $Text.Length } else { 0 }
Write-Output "OK: injected into '$name' ($idLabel) text=${tlen}ch enter=$(-not $NoEnter) enterOnly=$EnterOnly"
