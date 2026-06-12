# HomeShield NGFW

A next-generation firewall for home and lab use, inspired by enterprise NGFW
concepts (Palo Alto, FortiGate, Check Point) but built to be safe and
maintainable for personal deployment.

## Components

| Component | Path | Description |
|---|---|---|
| Web console | [src/](src/) | React + TypeScript + Tailwind management UI: policies, NAT, DNS filtering, IDS alerts, threat feeds, sessions, logs, audit trail |
| Management API | [server.js](server.js) | Express + MySQL REST API with JWT auth, serves the built UI from `dist/` |
| Rule compiler | [src/lib/nftables.ts](src/lib/nftables.ts) | Compiles policies into an atomic nftables ruleset (Linux) or PowerShell firewall script (Windows) |
| Enforcement agent | [agent/](agent/) | Root service on the protected Linux machine: applies rulesets, enforces the commit-confirm rollback timer, reports interfaces and health |

## Quick start

```sh
npm install
npm run build

# Required environment
export DB_HOST=... DB_NAME=... DB_USER=... DB_PASS=...
export JWT_SECRET="$(openssl rand -hex 32)"
export AGENT_TOKEN="$(openssl rand -hex 32)"   # enables the agent API

npm start    # serves UI + API on :3000, auto-creates tables on first run
```

Open `http://localhost:3000`, create the admin account (signup is only open
while no account exists), then install the agent on the firewall machine —
see [agent/README.md](agent/README.md).

## Development

```sh
npm run dev        # Vite dev server on :5173 (set CORS_ORIGIN=http://localhost:5173 on the API)
npm run test       # unit tests (rule compiler)
npm run typecheck
npm run lint
```

## How rule enforcement works

Applying policies uses a commit-confirm flow (like `commit confirmed` on
Junos): the UI compiles and queues the ruleset, the agent applies it
atomically with `nft -f`, and if the operator doesn't confirm within the
rollback timer the agent restores the previous ruleset — so a bad rule can't
permanently lock you out.

## Docs

- [docs/architecture.md](docs/architecture.md)
- [docs/firewall-policy-model.md](docs/firewall-policy-model.md)
- [docs/threat-model.md](docs/threat-model.md)
