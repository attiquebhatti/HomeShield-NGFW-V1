# HomeShield Linux Enforcement Agent

The agent is the component that turns HomeShield from a management console into
an actual firewall. It runs as root on the protected Linux machine, polls the
management API for pending rule-apply jobs, applies them with nftables, and
enforces the commit-confirm rollback timer server-side (so a bad ruleset that
locks you out of the UI still gets reverted).

## How an apply works

1. In the UI you click **Apply → Confirm**. This inserts a `rule_apply_history`
   row with `status = 'pending'` containing the compiled nftables script.
2. The agent picks up the pending job, backs up the **entire current ruleset**
   to `STATE_DIR/backup-<job>.nft`, validates the new script (`nft -c -f`),
   applies it atomically (`nft -f`), and reports `status = 'applied'`.
3. The agent then waits for the operator to confirm in the UI within
   `rollback_timer_seconds`. If confirmed → the ruleset stays. If not (browser
   closed, locked out, timer expired) → the agent restores the backup and
   reports `status = 'rolled_back'`.

The generated ruleset only ever replaces `table inet homeshield`; rules from
Docker, libvirt, fail2ban etc. are untouched.

## Telemetry and visibility

Besides applying rules, the agent feeds the UI with live data:

- **Firewall logs** — policies with logging enabled emit kernel log lines
  prefixed `hs-<action>:`. The agent follows the kernel journal
  (`journalctl -k`) with a persisted cursor (survives restarts without losing
  or duplicating entries) and ingests matching lines into the Logs page.
- **Sessions** — the connection table from `/proc/net/nf_conntrack` is
  parsed and reported, populating the Sessions page. For byte/packet counters
  enable conntrack accounting: `sysctl -w net.netfilter.nf_conntrack_acct=1`.
- **Interfaces & health** — `ip -j addr` inventory plus CPU/RAM/disk/load
  snapshots every `TELEMETRY_SECONDS`.

The server prunes `firewall_logs`, `dns_logs` and health snapshots daily
according to the `log_retention_days` system setting (default 90 days).

## DNS filtering

The agent includes a UDP DNS proxy, toggled by the **DNS Filtering** switch in
Settings (no agent restart needed — it picks up the change within
`DNS_REFRESH_SECONDS`). When enabled it listens on udp/53:

- Domains on the blocklist (DNS Filtering page) are sinkholed: A → `0.0.0.0`,
  AAAA → `::`, other types → NXDOMAIN. Entries match the domain itself and all
  subdomains; allowlist entries override blocklist entries.
- Everything else is forwarded to the upstream resolver (`dns_upstream`
  setting, default `1.1.1.1`).
- Every query is logged to the DNS Logs page with client IP, verdict and
  matched list entry.

To actually use it, point clients at the agent machine for DNS — either per
device, via your router's DHCP DNS option, or in gateway mode with a DNAT rule
redirecting port 53.

**Port 53 conflicts:** on distros with systemd-resolved, free the port first:

```sh
sudo mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/homeshield.conf
sudo systemctl restart systemd-resolved
```

Limitations (current iteration): UDP only (no DNS-over-TCP fallback), IPv4
listener only, and the proxy is an open resolver on all interfaces — run it on
a trusted LAN and block udp/53 from WAN with a firewall policy.

## Intrusion prevention (Suricata IPS)

Set **Suricata Mode** in Settings to `ids` (detect only) or `ips` (inline
block). In both modes the agent tails Suricata's `eve.json` and ingests alerts
into the IDS / IPS Alerts page; the Verdict column shows whether each alert was
`detected` or `blocked`.

In **IPS mode** the agent additionally installs an nftables NFQUEUE hook
(`table inet homeshield_ips`) that hands packets to Suricata for an
accept/drop verdict. Key safety properties:

- **Fail-open** — the queue uses `bypass`, so if Suricata isn't running,
  packets are accepted. A Suricata crash never takes down connectivity.
- **Self-healing** — the hook is a separate table at priority 10, independent
  of your policy ruleset. It's re-asserted every config cycle, so it's
  restored within `DNS_REFRESH_SECONDS` even after a policy rollback (which
  flushes the global ruleset).

### Installing Suricata in NFQUEUE mode

1. Install Suricata and update rules:

   ```sh
   sudo apt install suricata          # or dnf/pacman
   sudo suricata-update
   ```

2. Run Suricata reading the same queue number as the **NFQUEUE Number** setting
   (default 0). For inline drops, signatures must use the `drop` action and
   Suricata must run in IPS/queue mode:

   ```sh
   sudo suricata -q 0 --set action-order=pass,drop,reject,alert
   ```

   Or as a service, set `NFQUEUE` run mode in `/etc/default/suricata` and
   ensure `eve.json` logging is enabled (it is by default at
   `/var/log/suricata/eve.json`).

3. Set **Suricata Mode** to `ips` in Settings. The agent installs the hook
   within one config cycle. Confirm with `sudo nft list table inet homeshield_ips`.

**Avoid locking yourself out:** Suricata drop rules can block legitimate
traffic. Add Suricata `pass` rules for your management/SSH flows before
enabling drops, and remember the firewall policy ruleset and the IPS queue are
independent layers — both must permit your management traffic.

## Requirements

- Linux with nftables (`nft`) and iproute2 (`ip`)
- Node.js 18+
- Root (or `CAP_NET_ADMIN`)

## Setup

1. On the **server**, set a shared secret and restart it:

   ```sh
   export AGENT_TOKEN="$(openssl rand -hex 32)"
   node server.js
   ```

2. On the **firewall machine**, install the agent:

   ```sh
   sudo mkdir -p /opt/homeshield/agent /etc/homeshield /var/lib/homeshield
   sudo cp homeshield-agent.mjs /opt/homeshield/agent/
   sudo tee /etc/homeshield/agent.env >/dev/null <<EOF
   AGENT_TOKEN=<same token as the server>
   HOMESHIELD_API=http://<server-address>:3000
   EOF
   sudo chmod 600 /etc/homeshield/agent.env
   sudo cp homeshield-agent.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now homeshield-agent
   ```

3. Check it: `journalctl -u homeshield-agent -f`. Within a minute the
   Interfaces page and Dashboard health data should populate with real data.

## Important: don't lock yourself out

The generated input chain has `policy drop`. Established connections survive an
apply, but **new** inbound connections are dropped unless a rule allows them.
Before applying on a remote machine, make sure you have an inbound `allow` rule
for your SSH and management ports (e.g. tcp 22 and tcp 3000). If you do get it
wrong, the rollback timer will restore the previous ruleset automatically.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `HOMESHIELD_API` | `http://127.0.0.1:3000` | Management API base URL |
| `AGENT_TOKEN` | — (required) | Shared secret, must match the server |
| `STATE_DIR` | `/var/lib/homeshield` | Ruleset backups and apply files |
| `POLL_SECONDS` | `5` | Job poll interval |
| `TELEMETRY_SECONDS` | `60` | Interface/health reporting interval |
| `DNS_PORT` | `53` | DNS proxy listen port |
| `DNS_REFRESH_SECONDS` | `30` | How often DNS config/blocklists are re-fetched |
