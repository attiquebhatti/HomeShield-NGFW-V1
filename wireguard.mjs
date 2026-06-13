/**
 * WireGuard key management, address allocation and client-config generation
 * for the HomeShield management server.
 *
 * WireGuard uses Curve25519 (X25519) keypairs encoded as base64 of the raw
 * 32-byte values. Node's crypto can generate and derive these; we extract the
 * raw key bytes from the DER encodings. Pure/deterministic helpers are unit
 * tested in wireguard.test.mjs.
 */

import crypto from 'node:crypto';

// Fixed ASN.1 PKCS8 prefix for an X25519 private key (16 bytes), followed by
// the 32-byte raw key. Used to rebuild a KeyObject from a stored private key.
const PKCS8_X25519_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

/** Generates a WireGuard keypair as { privateKey, publicKey } (base64). */
export function generateKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
  const priv = privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32);
  const pub = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  return { privateKey: priv.toString('base64'), publicKey: pub.toString('base64') };
}

/** Derives the base64 public key from a base64 WireGuard private key. */
export function derivePublicKey(privateKeyB64) {
  const raw = Buffer.from(privateKeyB64, 'base64');
  if (raw.length !== 32) throw new Error('invalid private key length');
  const keyObject = crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_X25519_PREFIX, raw]),
    format: 'der',
    type: 'pkcs8',
  });
  const pub = crypto.createPublicKey(keyObject).export({ type: 'spki', format: 'der' }).subarray(-32);
  return pub.toString('base64');
}

/** Generates a WireGuard pre-shared key (32 random bytes, base64). */
export function generatePresharedKey() {
  return crypto.randomBytes(32).toString('base64');
}

/**
 * Allocates the next free host address in the server's subnet.
 *
 * @param serverAddress e.g. "10.8.0.1/24"
 * @param usedAddresses array of peer addresses, e.g. ["10.8.0.2/32", ...]
 * @returns next free address as "10.8.0.X/32"
 * @throws if the IPv4 /24-style pool is exhausted
 */
export function nextPeerAddress(serverAddress, usedAddresses = []) {
  const [serverIp] = String(serverAddress).split('/');
  const octets = serverIp.split('.').map(Number);
  if (octets.length !== 4 || octets.some(o => Number.isNaN(o))) {
    throw new Error(`invalid server address: ${serverAddress}`);
  }

  const used = new Set();
  used.add(octets[3]); // server's own host octet
  for (const addr of usedAddresses) {
    const host = Number(String(addr).split('/')[0].split('.')[3]);
    if (!Number.isNaN(host)) used.add(host);
  }

  for (let host = 2; host <= 254; host++) {
    if (!used.has(host)) {
      return `${octets[0]}.${octets[1]}.${octets[2]}.${host}/32`;
    }
  }
  throw new Error('address pool exhausted');
}

/**
 * Builds a WireGuard client (.conf) for a peer.
 *
 * @param server { public_key, endpoint, listen_port, dns }
 * @param peer   { private_key, address, allowed_ips, preshared_key? }
 */
export function buildClientConfig(server, peer) {
  const lines = [
    '[Interface]',
    `PrivateKey = ${peer.private_key}`,
    `Address = ${peer.address}`,
  ];
  if (server.dns) lines.push(`DNS = ${server.dns}`);

  lines.push('', '[Peer]', `PublicKey = ${server.public_key}`);
  if (peer.preshared_key) lines.push(`PresharedKey = ${peer.preshared_key}`);

  const endpointHost = String(server.endpoint || '').trim();
  if (endpointHost) lines.push(`Endpoint = ${endpointHost}:${server.listen_port}`);
  lines.push(
    `AllowedIPs = ${peer.allowed_ips || '0.0.0.0/0'}`,
    'PersistentKeepalive = 25',
    ''
  );

  return lines.join('\n');
}
