# connect_rc.ps1 - reliably connect a freshly-opened, named (CC-<token>) session to
# Remote Control. Waits until the session is actually IDLE at its prompt (badge
# "shift+tab to cycle") before injecting /remote-control (R12: never type into a
# not-yet-ready prompt), then verifies the "/rc" indicator appeared; retries once.
# Reading needs no lock; the actual /remote-control send is delegated to
# handoff_inject.ps1 (which holds the global cc_inject.lock). ASCII-only.
#
# Usage: powershell -File connect_rc.ps1 -TabTitle CC-xxxxxx [-WaitSec 50]
param(
    [Parameter(Mandatory)][string]$TabTitle,
    [int]$WaitSec = 50
)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$cc = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ClassNameProperty, 'CASCADIA_HOSTING_WINDOW_CLASS')
$tc = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::TabItem)
$termCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ClassNameProperty, 'TermControl')
$inject = Join-Path $PSScriptRoot 'handoff_inject.ps1'

# Select the unique CC-token tab and read its terminal text (must be selected to read
# the live TermControl). Returns text, or $null if not found / not unique.
function Read-Tab {
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $hits = @()
    foreach ($w in $root.FindAll([System.Windows.Automation.TreeScope]::Children, $cc)) {
        foreach ($t in $w.FindAll([System.Windows.Automation.TreeScope]::Descendants, $tc)) {
            if ($t.Current.Name -like "*$TabTitle*") { $hits += @{ tab = $t; win = $w } }
        }
    }
    if ($hits.Count -ne 1) { return $null }
    try { $hits[0].tab.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select() } catch {}
    Start-Sleep -Milliseconds 250
    $term = $hits[0].win.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $termCond)
    if (-not $term) { return $null }
    try { return $term.GetCurrentPattern([System.Windows.Automation.TextPattern]::Pattern).DocumentRange.GetText(-1) } catch { return $null }
}

# 1) wait for idle prompt (badge present)
$deadline = (Get-Date).AddSeconds($WaitSec)
$ready = $false
while ((Get-Date) -lt $deadline) {
    $txt = Read-Tab
    if ($txt -and ($txt -match 'shift\+tab to cycle')) { $ready = $true; break }
    Start-Sleep -Milliseconds 800
}
if (-not $ready) { Write-Output "FAIL: session '$TabTitle' not ready (no idle prompt within ${WaitSec}s)"; exit 2 }

# already connected?
$txt = Read-Tab
if ($txt -match '/rc') { Write-Output "OK: RC already connected ($TabTitle)"; exit 0 }

# 2) inject /remote-control WITH the same name (so the Claude App / Remote Control shows
#    the SAME CC-<token> as the WT tab title and Telegram -> one consistent identity,
#    so the user closes the right session). Up to 2 attempts; verify /rc appears.
for ($attempt = 1; $attempt -le 2; $attempt++) {
    & powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $inject -TabTitle $TabTitle -Text "/remote-control $TabTitle" | Out-Null
    for ($i = 0; $i -lt 10; $i++) {
        Start-Sleep -Milliseconds 800
        $txt = Read-Tab
        if ($txt -match '/rc') { Write-Output "OK: RC connected ($TabTitle, attempt $attempt)"; exit 0 }
    }
}
Write-Output "FAIL: injected /remote-control but '/rc' indicator did not appear ($TabTitle)"
exit 2
