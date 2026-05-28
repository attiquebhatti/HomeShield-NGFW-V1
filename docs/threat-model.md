# HomeShield NGFW - Threat Model

## Scope

This threat model covers the HomeShield NGFW MVP deployed in:
- Linux host protection mode
- Linux gateway/router mode
- Windows host protection mode

---

## Assets

| Asset | Sensitivity | Notes |
|---|---|---|
| Admin credentials | Critical | Full system access |
| Firewall ruleset | High | Changes expose or block network paths |
| Audit log | High | Evidence of changes; must not be tampered |
| Threat feed API keys | Medium | Third-party service abuse |
| Session/log data | Medium | Privacy-sensitive network metadata |
| DNS query logs | Medium | User browsing patterns |
| Config database | High | Contains all policy state |

---

## Threat Actors

| Actor | Motivation | Capability |
|---|---|---|
| External attacker | Bypass firewall, access internal network | Network-level, automated scanning |
| Compromised LAN device | Pivot, exfiltrate data | Local network access |
| Malicious admin insider | Disable rules, exfiltrate logs | Full console access |
| Supply chain attacker | Backdoor the software | Code/package injection |
| Automated bots | Port scanning, brute force | Large-scale, scripted |

---

## STRIDE Analysis

### Spoofing
- **Threat**: Attacker spoofs admin session to modify rules
- **Mitigation**: JWT authentication, session expiry, MFA (Phase 4), audit trail

### Tampering
- **Threat**: Rules modified via direct database access
- **Mitigation**: RLS policies in Supabase, audit log for all changes, config backups

### Repudiation
- **Threat**: Admin denies making a rule change
- **Mitigation**: Immutable audit log with actor, timestamp, IP, and change details

### Information Disclosure
- **Threat**: Log data exfiltrated reveals internal topology
- **Mitigation**: Logs stored locally, API access requires auth, no plaintext secrets

### Denial of Service
- **Threat**: API flooded to exhaust resources
- **Mitigation**: Rate limiting on API, agent process separation, firewall rules protect management port

### Elevation of Privilege
- **Threat**: Web UI compromise leads to OS-level command execution
- **Mitigation**: Agent runs as separate process with narrowly scoped capabilities; UI cannot directly invoke OS commands

---

## Attack Scenarios

### 1. Management UI Lockout
- **Scenario**: Admin applies a deny-all rule that blocks access to the web console
- **Mitigation**: Auto-rollback timer (default 30s); local console recovery mode; emergency allow rule for management IP

### 2. Rule Injection via API
- **Scenario**: XSS/CSRF attack injects a malicious firewall rule
- **Mitigation**: CSRF tokens, CORS locked to management network, input validation, audit trail alerts

### 3. Suricata Config Tampering
- **Scenario**: Attacker modifies Suricata rules to blind the IDS
- **Mitigation**: Rule files checksummed; agent validates before apply; audit log records IDS config changes

### 4. Threat Feed Poisoning
- **Scenario**: Compromised feed URL delivers malicious IP blocklist that blocks legitimate traffic
- **Mitigation**: Feed changes applied as additive (not replace-all) in MVP; manual review recommended; rollback available

### 5. Database Credential Exposure
- **Scenario**: `.env` file or config exposed
- **Mitigation**: Secrets never committed to source; env-based config; principle of least privilege for DB user

---

## Out of Scope (MVP)

- Physical access attacks (JTAG, cold boot)
- Kernel-level rootkits
- Hardware supply chain attacks
- Side-channel attacks
- Full enterprise threat modeling (covered in Phase 4 hardening guide)

---

## Security Contacts

Report security issues via `SECURITY.md` responsible disclosure process. Do not file public issues for security vulnerabilities.
