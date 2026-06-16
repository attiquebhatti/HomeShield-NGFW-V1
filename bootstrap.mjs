/**
 * Builds a single self-contained Windows installer ("bootstrap") that embeds
 * the agent script, so the operator can download one .ps1 from the console and
 * run it. Pure — unit tested in bootstrap.test.mjs.
 */

/**
 * @param agentScript  the full text of agent-windows/homeshield-agent.ps1
 * @param defaultApi   the management API base URL to pre-fill (from the request)
 * @param statusScript optional text of agent-windows/homeshield-status.ps1, also
 *                     dropped into the install dir so the operator gets the local
 *                     `homeshield-status.ps1` health command.
 */
export function buildWindowsBootstrap(agentScript, defaultApi = '', statusScript = '') {
  const b64 = Buffer.from(agentScript || '', 'utf8').toString('base64');
  const api = String(defaultApi || '').replace(/[`"$]/g, '');
  const statusLines = statusScript
    ? [
        '',
        '# Embedded local status command',
        `$statusB64 = "${Buffer.from(statusScript, 'utf8').toString('base64')}"`,
        '[IO.File]::WriteAllBytes((Join-Path $Dir "homeshield-status.ps1"), [Convert]::FromBase64String($statusB64))',
      ]
    : [];

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
    ...statusLines,
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

/**
 * Builds a one-click, self-elevating .cmd installer with the API URL and token
 * baked in. The user double-clicks it and approves the UAC prompt — no
 * execution-policy fiddling, no signing. The PowerShell payload is appended
 * after a marker and run from the file itself (so there's no command-line
 * length limit on the embedded agent).
 *
 * NOTE: embeds the agent token, so this download is admin-only.
 */
export function buildWindowsCmd(agentScript, api, token, statusScript = '') {
  const b64 = Buffer.from(agentScript || '', 'utf8').toString('base64');
  const apiLit = String(api || '').replace(/'/g, "''");
  const tokenLit = String(token || '').replace(/'/g, "''");
  const statusLines = statusScript
    ? [
        `$statusB64 = '${Buffer.from(statusScript, 'utf8').toString('base64')}'`,
        '[IO.File]::WriteAllBytes((Join-Path $Dir "homeshield-status.ps1"), [Convert]::FromBase64String($statusB64))',
      ]
    : [];

  const lines = [
    '@echo off',
    'rem HomeShield NGFW - one-click Windows agent installer',
    'net session >nul 2>&1',
    'if %errorlevel% neq 0 (',
    "  powershell -NoProfile -Command \"Start-Process -Verb RunAs -FilePath '%~f0'\"",
    '  exit /b',
    ')',
    'powershell -NoProfile -ExecutionPolicy Bypass -Command "$c=[IO.File]::ReadAllText(\'%~f0\'); $m=$c.LastIndexOf(\'#PSPAYLOAD#\'); Invoke-Expression $c.Substring($m+11)"',
    'exit /b',
    '#PSPAYLOAD#',
    `$Api = '${apiLit}'`,
    `$Token = '${tokenLit}'`,
    `$agentB64 = '${b64}'`,
    '$Dir = "$env:ProgramData\\HomeShield"',
    'New-Item -ItemType Directory -Force -Path $Dir | Out-Null',
    '[IO.File]::WriteAllBytes((Join-Path $Dir "homeshield-agent.ps1"), [Convert]::FromBase64String($agentB64))',
    ...statusLines,
    '@{ api = $Api; token = $Token; poll_seconds = 15 } | ConvertTo-Json | Set-Content -Path (Join-Path $Dir "agent.json") -Encoding UTF8',
    'try { icacls $Dir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null } catch {}',
    '$agentPath = Join-Path $Dir "homeshield-agent.ps1"',
    '$arg = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"" + $agentPath + "`""',
    '$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arg',
    '$trigger = New-ScheduledTaskTrigger -AtStartup',
    '$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest',
    '$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew',
    'Register-ScheduledTask -TaskName "HomeShieldAgent" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null',
    'Start-ScheduledTask -TaskName "HomeShieldAgent"',
    'Write-Host "HomeShield agent installed and started." -ForegroundColor Green',
    'Write-Host "Logs:   $Dir\\agent.log"',
    'Write-Host "Status: powershell -ExecutionPolicy Bypass -File $Dir\\homeshield-status.ps1"',
    'Start-Sleep -Seconds 4',
  ];
  return lines.join('\r\n');
}
