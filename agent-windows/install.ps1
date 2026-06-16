<#
  Installs the HomeShield Windows agent as a SYSTEM scheduled task that starts
  at boot and keeps running. Run from an elevated PowerShell.

  Example:
    .\install.ps1 -Api "https://shield.example.com" -Token "<AGENT_TOKEN>"
#>
#Requires -RunAsAdministrator
param(
  [Parameter(Mandatory = $true)][string]$Api,
  [Parameter(Mandatory = $true)][string]$Token,
  [int]$PollSeconds = 15
)

$ErrorActionPreference = 'Stop'
$Dir = "$env:ProgramData\HomeShield"
$TaskName = 'HomeShieldAgent'

New-Item -ItemType Directory -Force -Path $Dir | Out-Null
Copy-Item -Path (Join-Path $PSScriptRoot 'homeshield-agent.ps1') -Destination (Join-Path $Dir 'homeshield-agent.ps1') -Force
# Local status command (run elevated to see agent health on the box).
$statusSrc = Join-Path $PSScriptRoot 'homeshield-status.ps1'
if (Test-Path $statusSrc) { Copy-Item -Path $statusSrc -Destination (Join-Path $Dir 'homeshield-status.ps1') -Force }

@{ api = $Api; token = $Token; poll_seconds = $PollSeconds } |
  ConvertTo-Json | Set-Content -Path (Join-Path $Dir 'agent.json') -Encoding UTF8

# Lock down the config (contains the agent token) to SYSTEM/Administrators.
try {
  icacls $Dir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
} catch { Write-Warning "Could not tighten ACLs on $Dir : $_" }

$agentPath = Join-Path $Dir 'homeshield-agent.ps1'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
  -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$agentPath`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 999 `
  -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "HomeShield agent installed and started." -ForegroundColor Green
Write-Host "  Config: $Dir\agent.json"
Write-Host "  Logs:   $Dir\agent.log"
Write-Host "  Status: powershell -ExecutionPolicy Bypass -File $Dir\homeshield-status.ps1"
Write-Host "  Manage: Get-ScheduledTask HomeShieldAgent | Get-ScheduledTaskInfo"
