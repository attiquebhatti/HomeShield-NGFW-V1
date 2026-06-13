/**
 * WireGuard server-side config generation and telemetry parsing for the
 * HomeShield agent. Pure functions — unit tested in wg.test.mjs.
 */

/**
 * Builds a wg-quick(8) server config from the server settings and peers.
 *
 * Note the asymmetry vs the client config: on the SERVER, each peer's
 * AllowedIPs is that peer's own tunnel address (/32), which tells WireGuard
 * which source the peer is permitted to use. The client's "0.0.0.0/0" lives
 * only in the client config.
 *
 * @param server { interface, private_key, listen_port, address }
 * @param peers  array of { public_key, preshared_key?, address }
 */
export function buildServerConfig(server, peers = []) {
  const lines = [
    '# HomeShield NGFW - WireGuard server config (managed)',
    '[Interface]',
    `Address = ${server.address}`,
    `ListenPort = ${server.listen_port}`,
    `PrivateKey = ${server.private_key}`,
    '',
  ];

  for (const peer of peers) {
    if (!peer.public_key || !peer.address) continue;
    lines.push('[Peer]', `PublicKey = ${peer.public_key}`);
    if (peer.preshared_key) lines.push(`PresharedKey = ${peer.preshared_key}`);
    // Strip any prefix the stored address carries; the server pins each peer
    // to a single /32 (or /128 for IPv6).
    const ip = String(peer.address).split('/')[0];
    const cidr = ip.includes(':') ? `${ip}/128` : `${ip}/32`;
    lines.push(`AllowedIPs = ${cidr}`, '');
  }

  return lines.join('\n');
}

/**
 * Builds the nftables masquerade table so VPN clients can reach the internet.
 * Source-NATs traffic originating from the VPN subnet.
 *
 * @param serverAddress e.g. "10.8.0.1/24" → masquerades "10.8.0.0/24"
 */
export function buildVpnNatTable(serverAddress) {
  const [ip, prefix = '24'] = String(serverAddress).split('/');
  const octets = ip.split('.');
  // Derive the network address for the masquerade source match.
  const network = `${octets[0]}.${octets[1]}.${octets[2]}.0/${prefix}`;
  return [
    '#!/usr/sbin/nft -f',
    '# HomeShield NGFW - WireGuard NAT',
    'table inet homeshield_vpn',
    'delete table inet homeshield_vpn',
    '',
    'table inet homeshield_vpn {',
    '  chain postrouting {',
    '    type nat hook postrouting priority 100; policy accept;',
    `    ip saddr ${network} counter masquerade`,
    '  }',
    '}',
    '',
  ].join('\n');
}

/**
 * Parses `wg show <iface> dump` output into per-peer telemetry.
 *
 * The first line describes the interface; subsequent lines are peers:
 *   public_key  preshared_key  endpoint  allowed_ips  latest_handshake  rx  tx  keepalive
 * latest_handshake is a unix timestamp (0 = never).
 */
export function parseWgDump(text) {
  const lines = String(text).trim().split('\n').filter(Boolean);
  const peers = [];
  // Skip line 0 (the interface itself).
  for (let i = 1; i < lines.length; i++) {
    const f = lines[i].split('\t');
    if (f.length < 7) continue;
    const handshake = parseInt(f[4], 10) || 0;
    peers.push({
      public_key: f[0],
      endpoint: f[2] === '(none)' ? '' : f[2],
      last_handshake: handshake > 0 ? new Date(handshake * 1000).toISOString().slice(0, 19).replace('T', ' ') : null,
      rx_bytes: parseInt(f[5], 10) || 0,
      tx_bytes: parseInt(f[6], 10) || 0,
    });
  }
  return peers;
}
