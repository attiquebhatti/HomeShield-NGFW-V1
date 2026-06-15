<#
  HomeShield NGFW - Windows enforcement agent.

  Runs as SYSTEM (installed via install.ps1 as a scheduled task). Each cycle it:
    1. Registers/heartbeats this device with the management server.
    2. Applies pending firewall policy jobs via Windows Firewall, with a
       commit-confirm rollback timer (mirrors the Linux agent).
    3. Provisions the IKEv2/IPSec VPN client when IPSec is enabled.
    4. Reports a health snapshot.

  Config: %ProgramData%\HomeShield\agent.json  { api, token, poll_seconds }
  Requires: Windows PowerShell 5.1+, administrator/SYSTEM, the Windows
  Defender Firewall service.
#>
param([string]$ConfigPath = "$env:ProgramData\HomeShield\agent.json")

$ErrorActionPreference = 'Stop'
$AgentVersion = '1.0.0'
$VpnName = 'HomeShield VPN'

# ─── Config & identity ──────────────────────────────────────────────────────
if (-not (Test-Path $ConfigPath)) { throw "Config not found at $ConfigPath - run install.ps1 first" }
$cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$Api = ($cfg.api).TrimEnd('/')
$Token = $cfg.token
$PollSeconds = if ($cfg.poll_seconds) { [int]$cfg.poll_seconds } else { 15 }
$StateDir = Split-Path $ConfigPath
$DeviceIdPath = Join-Path $StateDir 'device-id'

if (Test-Path $DeviceIdPath) {
  $DeviceId = (Get-Content $DeviceIdPath -Raw).Trim()
} else {
  $DeviceId = [guid]::NewGuid().ToString()
  Set-Content -Path $DeviceIdPath -Value $DeviceId -Encoding Ascii
}

function Write-Log($msg) {
  $line = "{0} {1}" -f (Get-Date -Format 'o'), $msg
  Write-Output $line
  try { Add-Content -Path (Join-Path $StateDir 'agent.log') -Value $line -ErrorAction SilentlyContinue } catch {}
}

# ─── API helper ─────────────────────────────────────────────────────────────
function Invoke-Agent {
  param([string]$Method, [string]$Path, $Body)
  $headers = @{ 'X-Agent-Token' = $Token }
  $uri = "$Api/api/agent$Path"
  if ($null -ne $Body) {
    $json = $Body | ConvertTo-Json -Depth 8 -Compress
    return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ContentType 'application/json' -Body $json -TimeoutSec 30
  }
  return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -TimeoutSec 30
}

# ─── 1. Device registration / heartbeat ─────────────────────────────────────
function Register-Device {
  $ip = $null
  try {
    $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' } |
      Sort-Object -Property SkipAsSource | Select-Object -First 1).IPAddress
  } catch {}
  $osv = ''
  try { $osv = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption } catch {}
  Invoke-Agent -Method POST -Path '/register' -Body @{
    device_id = $DeviceId; hostname = $env:COMPUTERNAME; os = 'windows'
    os_version = $osv; agent_version = $AgentVersion; ip_address = $ip
  } | Out-Null
}

# ─── 2. Firewall policy apply (commit-confirm) ──────────────────────────────
function Sync-Firewall {
  $resp = Invoke-Agent -Method GET -Path '/job?os=windows'
  $job = $resp.data
  if (-not $job) { return }
  Write-Log "Applying firewall job $($job.id) ($($job.rules_count) rules)"

  try {
    if ($job.compiled_output) {
      # The compiled script removes old HomeShield-* rules then adds the new
      # ruleset (authored by an admin on the management server).
      Invoke-Expression $job.compiled_output
    }
    Invoke-Agent -Method POST -Path "/job/$($job.id)/result" -Body @{ status = 'applied' } | Out-Null
  } catch {
    Write-Log "Apply failed: $_"
    Invoke-Agent -Method POST -Path "/job/$($job.id)/result" -Body @{ status = 'failed'; error_message = "$_" } | Out-Null
    return
  }

  # Commit-confirm: wait for the operator to confirm; otherwise revert.
  $timer = [int]$job.rollback_timer_seconds
  if ($timer -le 0) { $timer = 30 }
  $deadline = (Get-Date).AddSeconds($timer + 10)
  $confirmed = $false
  while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 2
    try {
      $st = (Invoke-Agent -Method GET -Path "/job/$($job.id)").data.status
      if ($st -eq 'confirmed') { $confirmed = $true; break }
      if ($st -eq 'rolled_back' -or $st -eq 'failed') { break }
    } catch {}
  }
  if (-not $confirmed) {
    Write-Log "Job $($job.id) not confirmed - removing HomeShield rules (revert to Windows defaults)"
    Get-NetFirewallRule -DisplayName 'HomeShield-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    try { Invoke-Agent -Method POST -Path "/job/$($job.id)/result" -Body @{ status = 'rolled_back' } | Out-Null } catch {}
  } else {
    Write-Log "Job $($job.id) confirmed"
  }
}

# ─── 3. IKEv2 VPN client provisioning ───────────────────────────────────────
function Sync-Vpn {
  $v = (Invoke-Agent -Method GET -Path '/vpn-client').data
  if (-not $v -or -not $v.enabled) { return }
  if (-not $v.endpoint -or -not $v.ca_cert) { return }

  # Import the CA into the machine Trusted Root store (idempotent).
  $caFile = Join-Path $StateDir 'homeshield-ca.cer'
  Set-Content -Path $caFile -Value $v.ca_cert -Encoding Ascii
  try {
    $existingCa = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
      Where-Object { $_.Subject -eq 'CN=HomeShield CA' }
    if (-not $existingCa) {
      Import-Certificate -FilePath $caFile -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
      Write-Log 'Imported HomeShield CA'
    }
  } catch { Write-Log "CA import failed: $_" }

  $existing = Get-VpnConnection -AllUserConnection -Name $VpnName -ErrorAction SilentlyContinue
  if ($existing -and $existing.ServerAddress -eq $v.endpoint) { return } # already provisioned
  if ($existing) { Remove-VpnConnection -AllUserConnection -Name $VpnName -Force -ErrorAction SilentlyContinue }

  $eapXml = '<EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig"><EapMethod><Type xmlns="http://www.microsoft.com/provisioning/EapCommon">26</Type><VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId><VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType><AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId></EapMethod><Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig"><Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>26</Type><EapType xmlns="http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1"><UseWinLogonCredentials>false</UseWinLogonCredentials></EapType></Eap></Config></EapHostConfig>'
  $split = -not $v.full_tunnel
  try {
    Add-VpnConnection -Name $VpnName -ServerAddress $v.endpoint -TunnelType Ikev2 `
      -AuthenticationMethod Eap -EapConfigXml $eapXml -EncryptionLevel Required `
      -SplitTunneling:$split -RememberCredential -AllUserConnection -Force
    Write-Log "Provisioned VPN connection '$VpnName' -> $($v.endpoint)"
  } catch { Write-Log "VPN provisioning failed: $_" }
}

# ─── 4. DNS category / App-ID enforcement (hosts-file sinkhole) ──────────────
# App-ID and URL-category policies are domain-based, so we enforce them on the
# endpoint by sinkholing their domains in the Windows hosts file. The server's
# /dns-config returns the block/allow lists (DNS entries + threat domains +
# enabled App-ID/URL policy domains).
function Sync-Dns {
  $cfg = Invoke-Agent -Method GET -Path '/dns-config'
  $hostsPath = Join-Path $env:WINDIR 'System32\drivers\etc\hosts'
  $begin = '# HomeShield BEGIN (managed - do not edit)'
  $end = '# HomeShield END'

  $entries = New-Object System.Collections.Generic.List[string]
  if ($cfg.enabled -and $cfg.entries) {
    $allow = New-Object System.Collections.Generic.HashSet[string]
    foreach ($e in $cfg.entries) { if ($e.list_type -eq 'allowlist' -and $e.domain) { [void]$allow.Add(($e.domain).ToLower().Trim()) } }
    $seen = New-Object System.Collections.Generic.HashSet[string]
    foreach ($e in $cfg.entries) {
      if ($e.list_type -eq 'allowlist') { continue }
      $d = ($e.domain).ToLower().Trim()
      if (-not $d -or $allow.Contains($d)) { continue }
      # apex + common subdomains (hosts can't wildcard)
      foreach ($h in @($d, "www.$d", "m.$d")) {
        if ($seen.Add($h)) { $entries.Add("0.0.0.0 $h"); $entries.Add(":: $h") }
      }
    }
  }

  $content = if (Test-Path $hostsPath) { Get-Content $hostsPath -Raw } else { '' }
  $clean = [regex]::Replace($content, "(?s)\r?\n?$([regex]::Escape($begin)).*?$([regex]::Escape($end))", '').TrimEnd()
  $managed = if ($entries.Count) { "`r`n$begin`r`n" + ($entries -join "`r`n") + "`r`n$end`r`n" } else { '' }
  $new = if ($clean) { "$clean$managed" } else { $managed.TrimStart("`r", "`n") }

  if ($new -ne $content) {
    Set-Content -Path $hostsPath -Value $new -Encoding ASCII -Force
    ipconfig /flushdns | Out-Null
    Write-Log "DNS enforcement: $($entries.Count / 2) host entries sinkholed"
  }
}

# ─── 5. Health telemetry ────────────────────────────────────────────────────
function Send-Health {
  try {
    $os = Get-CimInstance Win32_OperatingSystem
    $cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
    $ramPct = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize * 100, 1)
    $c = Get-PSDrive C
    $diskPct = if (($c.Used + $c.Free) -gt 0) { [math]::Round($c.Used / ($c.Used + $c.Free) * 100, 1) } else { 0 }
    Invoke-Agent -Method POST -Path '/telemetry' -Body @{
      health = @{
        cpu_percent = [double]$cpu; ram_percent = $ramPct
        ram_total_mb = [math]::Round($os.TotalVisibleMemorySize / 1024, 0)
        disk_percent = $diskPct
        services = @{ agent = 'running'; platform = 'windows'; device_id = $DeviceId }
      }
    } | Out-Null
  } catch { Write-Log "Health telemetry failed: $_" }
}

# ─── Main loop ──────────────────────────────────────────────────────────────
Write-Log "HomeShield Windows agent $AgentVersion starting - device $DeviceId, API $Api"
$lastHealth = [datetime]::MinValue

while ($true) {
  try { Register-Device } catch { Write-Log "register: $_" }
  try { Sync-Firewall }  catch { Write-Log "firewall: $_" }
  try { Sync-Dns }       catch { Write-Log "dns: $_" }
  try { Sync-Vpn }       catch { Write-Log "vpn: $_" }
  if ((Get-Date) - $lastHealth -gt [timespan]::FromSeconds(60)) {
    Send-Health
    $lastHealth = Get-Date
  }
  Start-Sleep -Seconds $PollSeconds
}
