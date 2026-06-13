# HomeShield NGFW — Deployment

Two pieces ship separately:

- **Management server** (UI + API + DB) — run with Docker Compose, or directly
  with Node. Runs anywhere.
- **Enforcement agent** — runs as root on the Linux machine being protected.
  Installed from a `.deb` or copied manually.

## Management server (Docker Compose)

```sh
cp .env.example .env
# edit .env — set DB_PASS, DB_ROOT_PASS, JWT_SECRET, AGENT_TOKEN
#   openssl rand -hex 32   # for the secrets

docker compose up -d --build
```

The UI/API is then on `http://<host>:3000`. Tables are auto-created on first
run; open the UI and create the first admin account.

To run without Docker:

```sh
npm ci && npm run build
export DB_HOST=... DB_NAME=... DB_USER=... DB_PASS=...
export JWT_SECRET="$(openssl rand -hex 32)"
export AGENT_TOKEN="$(openssl rand -hex 32)"
npm start
```

## Enforcement agent (.deb)

Build the package (needs `dpkg-deb`, typically on a Debian/Ubuntu box):

```sh
packaging/agent/build-deb.sh 1.0.0
# → dist-pkg/homeshield-agent_1.0.0_all.deb
```

Install on the firewall machine:

```sh
sudo apt install ./homeshield-agent_1.0.0_all.deb
sudo cp /etc/homeshield/agent.env.example /etc/homeshield/agent.env
sudo nano /etc/homeshield/agent.env      # set AGENT_TOKEN + HOMESHIELD_API
sudo chmod 600 /etc/homeshield/agent.env
sudo systemctl enable --now homeshield-agent
journalctl -u homeshield-agent -f
```

See [agent/README.md](../agent/README.md) for what the agent enforces and the
per-feature setup (Suricata, WireGuard, GeoIP, DNS).

## Monitoring (Prometheus + Grafana)

The server exposes Prometheus metrics at `/metrics`. Start the bundled stack:

```sh
docker compose --profile monitoring up -d
```

- Prometheus: `http://<host>:9090` (scrapes the app every 30s)
- Grafana: `http://<host>:3001` (admin / `GRAFANA_PASS`, default `admin`)
  with the **HomeShield NGFW** dashboard pre-provisioned.

If you set `METRICS_TOKEN`, add it to [deploy/prometheus.yml](../deploy/prometheus.yml)
(see the commented `authorization` / `params` block) so scrapes authenticate.

Key metrics: `homeshield_ids_alerts_unacknowledged`,
`homeshield_dns_queries_24h{action}`, `homeshield_firewall_events_24h{action}`,
`homeshield_threat_indicators{indicator_type}`, `homeshield_app_flows_24h{category}`,
`homeshield_cpu_percent`, `homeshield_interface_rx_bytes{interface}`.
