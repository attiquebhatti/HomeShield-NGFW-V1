# HomeShield Windows Agent

A PowerShell-based enforcement agent for Windows. It enrolls the device with
the management server, applies firewall policy (Windows Defender Firewall),
provisions the IKEv2/IPSec VPN client, and reports health.

## What it does each cycle

1. **Device enrollment / heartbeat** — registers a persistent device-ID,
   hostname, OS and IP. The device appears on the **Devices** page (online if
   seen in the last 2 minutes).
2. **Firewall policy** — picks up pending Windows apply jobs and applies them
   via `New-NetFirewallRule`, with the same **commit-confirm rollback**: if the
   operator doesn't confirm in the UI within the timer, the agent removes the
   HomeShield rules (reverting to Windows defaults — a desktop can't be locked
   out this way).
3. **VPN** — when IPSec is enabled and the gateway CA is provisioned, the agent
   imports the CA into Trusted Root and creates the **HomeShield VPN** IKEv2
   connection. You then connect with a VPN username/password.
4. **Health** — CPU/RAM/disk snapshot every 60s.

## Prerequisites

- Windows 10/11 or Server 2019+ with **Windows PowerShell 5.1+** (built in).
- **Administrator** rights to install (the agent runs as **SYSTEM**).
- Network access from the Windows machine to the management server.
- `AGENT_TOKEN` set on the server (same value used here).
- For the firewall feature: the **Windows Defender Firewall** service running
  (default).
- For VPN: a reachable IKEv2 gateway — i.e. the **Linux agent + strongSwan**
  with IPSec enabled in the VPN page, and udp/500 + udp/4500 forwarded to it.

No runtime to install — it uses built-in Windows cmdlets.

## Install

From an **elevated** PowerShell, in this folder:

```powershell
.\install.ps1 -Api "https://shield.example.com" -Token "<AGENT_TOKEN>"
```

This copies the agent to `%ProgramData%\HomeShield`, writes `agent.json`
(locked down to SYSTEM/Administrators), and registers a SYSTEM scheduled task
that starts at boot and restarts on failure. It starts immediately.

Check it:

```powershell
Get-ScheduledTask HomeShieldAgent | Get-ScheduledTaskInfo
Get-Content $env:ProgramData\HomeShield\agent.log -Tail 20
```

Within ~15s the device should appear on the **Devices** page.

## Connect the VPN

Once IPSec is enabled on the gateway and the agent has created the connection:

```powershell
rasdial "HomeShield VPN" <vpn-username> <vpn-password>
```

(or use **Settings → Network → VPN → HomeShield VPN → Connect**). VPN users are
created in the VPN page's IPSec section.

## Uninstall

```powershell
.\uninstall.ps1            # also removes the VPN connection + CA
.\uninstall.ps1 -KeepVpn   # leave the VPN connection in place
```

## Security notes

- `agent.json` holds the shared agent token; the installer restricts the
  directory ACL to SYSTEM/Administrators.
- Firewall jobs are admin-authored PowerShell compiled by the management
  server and run as SYSTEM (same trust model as the Linux agent running
  `nft -f`). A future iteration will compile policy from structured data on the
  agent to avoid executing server-provided script.
