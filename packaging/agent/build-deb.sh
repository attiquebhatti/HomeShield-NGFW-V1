#!/usr/bin/env bash
# Builds a homeshield-agent .deb package.
# Usage: packaging/agent/build-deb.sh [version]
# Output: dist-pkg/homeshield-agent_<version>_all.deb
set -euo pipefail

VERSION="${1:-1.0.0}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STAGE="$(mktemp -d)"
OUT="$ROOT/dist-pkg"
PKG="homeshield-agent_${VERSION}_all"

echo "Building $PKG from $ROOT"

# Layout
install -d "$STAGE/DEBIAN"
install -d "$STAGE/opt/homeshield/agent"
install -d "$STAGE/lib/systemd/system"
install -d "$STAGE/etc/homeshield"

# Agent code (the dependency-free .mjs modules)
cp "$ROOT"/agent/*.mjs "$STAGE/opt/homeshield/agent/"
cp "$ROOT/agent/homeshield-agent.service" "$STAGE/lib/systemd/system/"

# Example env file (real one is created by the admin, chmod 600)
cat > "$STAGE/etc/homeshield/agent.env.example" <<'EOF'
# Copy to agent.env and fill in. chmod 600 agent.env
AGENT_TOKEN=
HOMESHIELD_API=http://127.0.0.1:3000
EOF

# Control metadata
cat > "$STAGE/DEBIAN/control" <<EOF
Package: homeshield-agent
Version: $VERSION
Section: net
Priority: optional
Architecture: all
Depends: nodejs (>= 18), nftables, iproute2
Recommends: wireguard-tools, suricata
Maintainer: HomeShield <noreply@homeshield.local>
Description: HomeShield NGFW enforcement agent
 Applies firewall, IPS, threat-intel, GeoIP, DNS and WireGuard configuration
 from the HomeShield management server and reports telemetry.
EOF

# Post-install: reload systemd, hint the admin
cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
systemctl daemon-reload || true
if [ ! -f /etc/homeshield/agent.env ]; then
  echo "HomeShield agent installed. Create /etc/homeshield/agent.env (chmod 600)"
  echo "from /etc/homeshield/agent.env.example, then: systemctl enable --now homeshield-agent"
fi
exit 0
EOF
chmod 755 "$STAGE/DEBIAN/postinst"

# Pre-remove: stop the service
cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
systemctl disable --now homeshield-agent 2>/dev/null || true
exit 0
EOF
chmod 755 "$STAGE/DEBIAN/prerm"

mkdir -p "$OUT"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT/$PKG.deb"
rm -rf "$STAGE"
echo "Built $OUT/$PKG.deb"
