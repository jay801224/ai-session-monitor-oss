# list_cc_sessions.ps1 - list the managed Claude sessions (WT tabs carrying a
# CC-<token> title) that /close can target. One token per line. Reading tab TITLES
# needs no tab selection (non-disruptive). ASCII-only.
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$cc = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ClassNameProperty, 'CASCADIA_HOSTING_WINDOW_CLASS')
$tc = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::TabItem)
$root = [System.Windows.Automation.AutomationElement]::RootElement
$seen = New-Object System.Collections.Generic.HashSet[string]
foreach ($w in $root.FindAll([System.Windows.Automation.TreeScope]::Children, $cc)) {
    foreach ($t in $w.FindAll([System.Windows.Automation.TreeScope]::Descendants, $tc)) {
        $m = [regex]::Match($t.Current.Name, '(?i)CC-[A-Za-z0-9_-]+')
        if ($m.Success) { [void]$seen.Add($m.Value) }
    }
}
foreach ($s in ($seen | Sort-Object)) { Write-Output $s }
