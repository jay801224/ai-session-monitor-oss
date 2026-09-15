# close_session.ps1 - safely close ONE managed Claude session tab by its CC-<token>.
#
# SAFETY (irreversible action; user was burned by over-eager automation):
#   - Only ever closes a WT tab whose title contains a CC-<token> (managed session).
#     A CC-token is extracted by regex; the user's own work tabs and the controller's
#     own session do NOT contain a CC-token -> they can NEVER be matched/closed.
#   - The requested token must resolve to EXACTLY ONE tab; 0 or >1 -> refuse.
#   - Closes via that tab's precise UIA close button (Invoke) - never keystrokes,
#     never the active tab, never an index, never "close all".
#
# Consent is enforced UPSTREAM (the user pastes the verbatim `yes close <token>`
# pass-phrase in Telegram); this script is the mechanism, gated to CC- tabs only.
# ASCII-only. Usage: powershell -File close_session.ps1 -TabTitle CC-ae1bba
param([Parameter(Mandatory)][string]$TabTitle)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes

# normalize the requested token (case-insensitive); must itself be a CC- token
$m = [regex]::Match($TabTitle, '(?i)CC-[A-Za-z0-9_-]+')
if (-not $m.Success) { Write-Output "REFUSED: '$TabTitle' is not a CC-<token> (only managed sessions can be closed)"; exit 2 }
$want = $m.Value

$cc = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ClassNameProperty, 'CASCADIA_HOSTING_WINDOW_CLASS')
$tc = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::TabItem)
$btnCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)
$root = [System.Windows.Automation.AutomationElement]::RootElement

# find every tab whose title carries a CC-token equal to $want (case-insensitive)
$hits = @()
foreach ($w in $root.FindAll([System.Windows.Automation.TreeScope]::Children, $cc)) {
    foreach ($t in $w.FindAll([System.Windows.Automation.TreeScope]::Descendants, $tc)) {
        $tm = [regex]::Match($t.Current.Name, '(?i)CC-[A-Za-z0-9_-]+')
        if ($tm.Success -and ($tm.Value -ieq $want)) { $hits += @{ tab = $t; name = $t.Current.Name } }
    }
}
if ($hits.Count -eq 0) { Write-Output "REFUSED: no managed session tab matches '$want' (already closed?)"; exit 2 }
if ($hits.Count -gt 1) { Write-Output "REFUSED: '$want' matches $($hits.Count) tabs - ambiguous, not closing"; exit 2 }

$tab = $hits[0].tab
$btn = $tab.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $btnCond)   # the tab's close button
if (-not $btn) { Write-Output "FAIL: close button not found for '$($hits[0].name)'"; exit 2 }
$btn.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
Start-Sleep -Milliseconds 600

# verify it's gone
$still = $false
foreach ($w in $root.FindAll([System.Windows.Automation.TreeScope]::Children, $cc)) {
    foreach ($t in $w.FindAll([System.Windows.Automation.TreeScope]::Descendants, $tc)) {
        $tm = [regex]::Match($t.Current.Name, '(?i)CC-[A-Za-z0-9_-]+')
        if ($tm.Success -and ($tm.Value -ieq $want)) { $still = $true }
    }
}
if ($still) { Write-Output "FAIL: '$want' still present after close attempt"; exit 2 }
Write-Output "OK: closed managed session $want"
