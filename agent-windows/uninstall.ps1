<#
  Removes the HomeShield Windows agent: stops/unregisters the scheduled task,
  removes the HomeShield firewall rules and the VPN connection, and deletes the
  config directory. Run from an elevated PowerShell.
#>
#Requires -RunAsAdministrator
param([switch]$KeepVpn)

$TaskName = 'HomeShieldAgent'
$Dir = "$env:ProgramData\HomeShield"

Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

Get-NetFirewallRule -DisplayName 'HomeShield-*' -ErrorAction SilentlyContinue |
  Remove-NetFirewallRule -ErrorAction SilentlyContinue

# Remove the managed hosts-file DNS sinkhole section
$hostsPath = Join-Path $env:WINDIR 'System32\drivers\etc\hosts'
if (Test-Path $hostsPath) {
  $content = Get-Content $hostsPath -Raw
  $clean = [regex]::Replace($content, "(?s)\r?\n?# HomeShield BEGIN.*?# HomeShield END", '').TrimEnd()
  Set-Content -Path $hostsPath -Value $clean -Encoding ASCII -Force
  ipconfig /flushdns | Out-Null
}

if (-not $KeepVpn) {
  Remove-VpnConnection -AllUserConnection -Name 'HomeShield VPN' -Force -ErrorAction SilentlyContinue
  Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq 'CN=HomeShield CA' } |
    Remove-Item -ErrorAction SilentlyContinue
}

Remove-Item -Path $Dir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "HomeShield agent uninstalled." -ForegroundColor Green
