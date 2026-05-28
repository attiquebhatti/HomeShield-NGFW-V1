# HomeShield NGFW - System Architecture

## Overview

HomeShield NGFW is a modular, cross-platform next-generation firewall for advanced home users, homelabs, freelancers, and small offices. It is inspired by enterprise NGFW concepts but designed for safe, realistic, and maintainable personal deployment.

---

## Deployment Modes

| Mode | Description |
|---|---|
| **Linux Host Mode** | Protects the machine itself. Inbound/outbound filtering. |
| **Linux Gateway Mode** | Machine acts as router/firewall between WAN and LAN. NAT, stateful rules, conntrack. |
| **Windows Host Mode** | Manages Windows Defender Firewall rules via WFP APIs. |

---

## Architecture Planes

```
┌─────────────────────────────────────────────────────────────────┐
│  Management Plane (Web Console + REST API)                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  React UI    │  │  Auth / RBAC │  │  REST API (Go/Gin)   │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  Control Plane (Policy Engine + Configuration)                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  Policy CRUD │  │  Rule Compiler│  │  Config Store (DB)   │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  Data Plane (Enforcement Agents)                                │
│  ┌──────────────────────┐  ┌─────────────────────────────────┐  │
│  │  Linux Agent         │  │  Windows Agent                  │  │
│  │  - nftables backend  │  │  - WFP / PowerShell backend     │  │
│  │  - conntrack         │  │  - netstat / active sessions    │  │
│  │  - NFQUEUE (Phase 2) │  │  - Kernel driver (Phase 3+)     │  │
│  └──────────────────────┘  └─────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  Telemetry Plane (Logging + Visibility)                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  Firewall    │  │  Suricata    │  │  DNS Logs            │  │
│  │  Logs        │  │  Eve JSON    │  │  Session Tracker     │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  Plugin / Integration Plane                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  Threat Feed │  │  DNS Filter  │  │  Future Plugins      │  │
│  │  Manager     │  │  (dnsmasq)   │  │  (nDPI, Zeek, AI)    │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Component Directory

```
homeshield-ngfw/
  apps/
    web-console/          # React + TypeScript + Tailwind management UI
    desktop-shell/        # Optional Electron wrapper (Phase 3)
  services/
    api/                  # Go REST API server (Gin framework)
    agent-linux/          # Linux firewall agent (nftables, conntrack, Suricata)
    agent-windows/        # Windows firewall agent (WFP, PowerShell)
    worker/               # Background jobs (feed refresh, log rotation, reports)
  packages/
    shared-types/         # Shared TypeScript types
    policy-schema/        # JSON schema for firewall policy model
    ui-kit/               # Shared UI components
  plugins/
    example-plugin/       # Plugin architecture reference implementation
```

---

## Database Schema (MVP - SQLite / Supabase)

| Table | Purpose |
|---|---|
| `firewall_policies` | Rule definitions |
| `firewall_logs` | Per-connection event log |
| `dns_entries` | Blocklist/allowlist domains |
| `dns_logs` | DNS query events |
| `ids_alerts` | Suricata IDS alert records |
| `threat_feeds` | Threat intelligence feed sources |
| `threat_indicators` | Individual IOCs |
| `network_interfaces` | Detected interfaces and roles |
| `nat_rules` | NAT/port forwarding rules |
| `system_settings` | Key-value configuration |
| `audit_log` | Immutable configuration change trail |
| `sessions` | Active/recent conntrack sessions |

---

## API Design

Base path: `/api/v1`

Authentication: JWT bearer tokens

Key endpoints:
- `POST /auth/login` / `POST /auth/logout`
- `GET/POST/PUT/DELETE /policies`
- `GET /logs` (paginated, filterable)
- `GET /sessions`
- `GET/POST/DELETE /dns/entries`
- `GET /dns/logs`
- `GET /ids/alerts`
- `GET/POST /nat/rules`
- `GET /interfaces`
- `GET /threat-feeds`
- `GET/POST /settings`
- `GET /audit`
- `GET /dashboard/stats`
- `WebSocket /ws/logs`

---

## Security Architecture

1. **Separation of privilege**: Web UI communicates only with the API. The agent runs as a privileged process separately.
2. **Audit logging**: All configuration changes are immutably logged.
3. **Rollback safety**: Config is backed up before every firewall apply. An auto-rollback timer prevents lockout.
4. **Secrets**: No hardcoded secrets. All credentials stored encrypted.
5. **Input validation**: All API inputs are validated and sanitized.
6. **CORS**: Locked to management IP/network.
7. **Rate limiting**: API endpoints rate-limited to prevent brute force.

---

## Phase Roadmap

| Phase | Focus |
|---|---|
| 0 | Architecture, scaffold, mock agents |
| 1 | MVP firewall core (Linux + Windows host mode) |
| 2 | Visibility, DNS filtering, Suricata IDS |
| 3 | WireGuard VPN, IPS mode, nDPI, traffic shaping |
| 4 | RBAC, MFA, TLS inspection, plugin framework, AI |
