# HomeShield NGFW - Firewall Policy Model

## Overview

Firewall policies are the core configuration objects in HomeShield NGFW. Each policy defines a match condition and an action. Policies are evaluated in priority order (lowest number = highest priority).

---

## Policy Schema

```typescript
interface FirewallPolicy {
  id: string;              // UUID, system-generated
  name: string;            // Human-readable rule name
  description: string;     // Optional description
  enabled: boolean;        // Whether the rule is active
  action: PolicyAction;    // What to do when matched
  direction: Direction;    // Traffic direction
  src_ip: string;          // Source IP/CIDR or "any"
  dst_ip: string;          // Destination IP/CIDR or "any"
  src_port: string;        // Source port, range, or "any"
  dst_port: string;        // Destination port, range, or "any"
  protocol: Protocol;      // Transport protocol
  interface: string;       // Network interface name or "any"
  schedule: string;        // "always" or schedule name
  tags: string[];          // Organizational tags
  priority: number;        // Rule evaluation order (lower = first)
  log_enabled: boolean;    // Whether to log matched traffic
  created_at: string;      // ISO timestamp
  updated_at: string;      // ISO timestamp
}
```

---

## Field Definitions

### action

| Value | Description |
|---|---|
| `allow` | Permit the traffic and continue |
| `deny` | Silently drop the packet |
| `reject` | Drop and send ICMP unreachable / TCP RST |
| `log-only` | Log the traffic but take no action |

### direction

| Value | Description |
|---|---|
| `inbound` | Traffic arriving at the host/LAN interface |
| `outbound` | Traffic leaving the host/WAN interface |
| `forward` | Traffic transiting through the firewall (gateway mode only) |

### protocol

| Value | Description |
|---|---|
| `tcp` | TCP only |
| `udp` | UDP only |
| `icmp` | ICMP only |
| `any` | All protocols |

---

## IP/Port Notation

| Format | Example | Meaning |
|---|---|---|
| Single IP | `192.168.1.100` | Exact host |
| CIDR | `192.168.1.0/24` | Subnet |
| Keyword | `any` | Match all |
| Single port | `443` | Exact port |
| Port range | `8000-8999` | Port range |
| Keyword | `any` | All ports |

---

## Priority and Ordering

- Rules are evaluated in ascending priority order (priority 1 before priority 100)
- The first matching rule wins
- If no rule matches, the default action is applied (configurable; defaults to deny-inbound, allow-outbound)
- Priorities can be reordered via the UI (drag-and-drop)
- Priority gaps are recommended (10, 20, 30...) to allow insertion

---

## Dry-Run Validation

Before applying rules, the system performs:

1. Schema validation (all required fields present)
2. IP/port syntax check
3. nftables syntax test (Linux only, `nft -c`)
4. Conflict detection (shadowed rules warning)
5. Lockout detection (would management access be blocked?)

---

## Rollback Mechanism

1. Current ruleset is exported and stored as a backup before every apply
2. A configurable rollback timer (default 30 seconds) starts
3. If the admin confirms the change within the timer, the backup is kept but not applied
4. If the timer expires without confirmation (e.g., due to lockout), the previous ruleset is restored

---

## nftables Compilation

Each policy is compiled to an nftables rule. Example:

```
# Allow HTTPS outbound
rule inet homeshield output tcp dport 443 counter accept
```

Rules are written to a table named `homeshield` in `inet` family to allow dual IPv4/IPv6 support.

The generated ruleset is applied atomically using `nft -f` with a full table flush and reload.

---

## Windows Compilation

On Windows, each policy is translated to a `netsh advfirewall` command or Windows Firewall PowerShell equivalent:

```powershell
New-NetFirewallRule -DisplayName "HomeShield - Block Telnet" `
  -Direction Inbound -Protocol TCP -LocalPort 23 -Action Block
```

Rules created by HomeShield are tagged with the `HomeShield-` prefix to allow safe removal.

---

## Default Policy Behavior

| Situation | Default |
|---|---|
| No rules match inbound | Deny |
| No rules match outbound | Allow |
| No rules match forward | Deny |
| IDS alert matched | Alert only (IDS mode) / Drop (IPS mode, Phase 2) |
