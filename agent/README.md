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
