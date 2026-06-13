/**
 * Builds a single self-contained Windows installer ("bootstrap") that embeds
 * the agent script, so the operator can download one .ps1 from the console and
 * run it. Pure — unit tested in bootstrap.test.mjs.
 */

/**
 * @param agentScript the full text of agent-windows/homeshield-agent.ps1
 * @param defaultApi  the management API base URL to pre-fill (from the request)
 */
export function buildWindowsBootstrap(agentScript, defaultApi = '') {
  const b64 = Buffer.from(agentScript || '', 'utf8').toString('base64');
  const api = String(defaultApi || '').replace(/[`"$]/g, '');

  return [
    '<#  HomeShield NGFW - Windows agent installer (self-contained).',
    '    Run from an ELEVATED PowerShell:',
    `      .\\homeshield-install.ps1 -Token "<AGENT_TOKEN>"`,
    '    The API URL is pre-filled; override with -Api if needed.  #>',
    '#Requires -RunAsAdministrator',
    'param(',
    `  [string]$Api = "${api}",`,
    '  [Parameter(Mandatory = $true)][string]$Token,',
    '  [int]$PollSeconds = 15',
    ')',
    '$ErrorActionPreference = "Stop"',
    '$Dir = "$env:ProgramData\\HomeShield"',
    'New-Item -ItemType Directory -Force -Path $Dir | Out-Null',
    '',
    '# Embedded agent script',
    `$agentB64 = "${b64}"`,
    '[IO.File]::WriteAllBytes((Join-Path $Dir "homeshield-agent.ps1"), [Convert]::FromBase64String($agentB64))',
    '',
    '@{ api = $Api; token = $Token; poll_seconds = $PollSeconds } |',
    '  ConvertTo-Json | Set-Content -Path (Join-Path $Dir "agent.json") -Encoding UTF8',
    'try { icacls $Dir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null } catch {}',
    '',
    '$agentPath = Join-Path $Dir "homeshield-agent.ps1"',
    '$action = New-ScheduledTaskAction -Execute "powershell.exe" `',
    '  -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$agentPath`""',
    '$trigger = New-ScheduledTaskTrigger -AtStartup',
    '$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest',
    '$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 999 `',
    '  -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew',
    'Register-ScheduledTask -TaskName "HomeShieldAgent" -Action $action -Trigger $trigger `',
    '  -Principal $principal -Settings $settings -Force | Out-Null',
    'Start-ScheduledTask -TaskName "HomeShieldAgent"',
    '',
    'Write-Host "HomeShield agent installed and started." -ForegroundColor Green',
    'Write-Host "  API:  $Api"',
    'Write-Host "  Logs: $Dir\\agent.log"',
    '',
  ].join('\n');
}
