<#
  HomeShield Windows agent - local status.
  Run from an ELEVATED PowerShell (the agent folder is locked to SYSTEM/Admins):
    powershell -ExecutionPolicy Bypass -File .\homeshield-status.ps1
#>
$ErrorActionPreference = 'SilentlyContinue'
$Dir = "$env:ProgramData\HomeShield"
$HostsPath = Join-Path $env:WINDIR 'System32\drivers\etc\hosts'

function Line($label, $value, $color = 'Gray') {
  Write-Host ('  {0,-16}' -f $label) -NoNewline
  Write-Host $value -ForegroundColor $color
}

Write-Host ''
Write-Host '  HomeShield Agent Status' -ForegroundColor Cyan
Write-Host '  -----------------------'

# Scheduled task (the agent should run as a SYSTEM task)
$task = Get-ScheduledTask -TaskName 'HomeShieldAgent'
if ($task) {
  $info = $task | Get-ScheduledTaskInfo
  Line 'Service' "$($task.State) (last run $($info.LastRunTime), result 0x$('{0:X}' -f $info.LastTaskResult))" `
    ($(if ($task.State -eq 'Running') { 'Green' } else { 'Red' }))
} else {
  Line 'Service' 'NOT INSTALLED as a scheduled task — re-run the installer as Administrator' 'Red'
}

# Live status written by the agent each cycle
$statusFile = Join-Path $Dir 'status.json'
if (Test-Path $statusFile) {
  $s = Get-Content $statusFile -Raw | ConvertFrom-Json
  $age = [int]((Get-Date) - [datetime]$s.updated).TotalSeconds
  Line 'Last heartbeat' "$age s ago" ($(if ($age -lt 60) { 'Green' } else { 'Red' }))
  Line 'Agent version' $s.version
  Line 'Device ID' $s.device_id
  Line 'Server' $s.api
  Line 'Registered' $s.registered ($(if ($s.registered) { 'Green' } else { 'Red' }))
  Line 'Firewall' $s.firewall
  Line 'DNS filtering' $s.dns
  if ($s.last_error) { Line 'Last error' $s.last_error 'Red' }
} else {
  Line 'Heartbeat' 'no status.json yet — agent has not completed a cycle' 'Yellow'
}

# Applied firewall rules
$rules = Get-NetFirewallRule -DisplayName 'HomeShield-*'
Line 'FW rules applied' (@($rules).Count)
foreach ($r in $rules) { Write-Host "    - $($r.DisplayName) [$($r.Direction)/$($r.Action)]" -ForegroundColor DarkGray }

# Sinkholed domains (hosts file)
$blocked = (Select-String -Path $HostsPath -Pattern '^0\.0\.0\.0 ' | Where-Object { $_.Line -notmatch 'localhost' }).Count
Line 'Domains blocked' $blocked

Write-Host ''
Write-Host '  Recent log:' -ForegroundColor Cyan
Get-Content (Join-Path $Dir 'agent.log') -Tail 8 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
Write-Host ''
