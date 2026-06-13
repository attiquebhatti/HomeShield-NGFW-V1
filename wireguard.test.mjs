import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  derivePublicKey,
  generatePresharedKey,
  nextPeerAddress,
  buildClientConfig,
} from './wireguard.mjs';

describe('WireGuard keys', () => {
  it('generates valid 32-byte base64 keypairs', () => {
    const { privateKey, publicKey } = generateKeyPair();
    expect(Buffer.from(privateKey, 'base64')).toHaveLength(32);
    expect(Buffer.from(publicKey, 'base64')).toHaveLength(32);
  });

  it('derives the same public key the generator produced', () => {
    const { privateKey, publicKey } = generateKeyPair();
    expect(derivePublicKey(privateKey)).toBe(publicKey);
  });

  it('rejects malformed private keys', () => {
    expect(() => derivePublicKey('tooShort')).toThrow();
  });

  it('generates 32-byte preshared keys', () => {
    expect(Buffer.from(generatePresharedKey(), 'base64')).toHaveLength(32);
  });
});

describe('nextPeerAddress', () => {
  it('returns the first free host, skipping the server and used peers', () => {
    expect(nextPeerAddress('10.8.0.1/24', [])).toBe('10.8.0.2/32');
    expect(nextPeerAddress('10.8.0.1/24', ['10.8.0.2/32'])).toBe('10.8.0.3/32');
    expect(nextPeerAddress('10.8.0.1/24', ['10.8.0.2/32', '10.8.0.4/32'])).toBe('10.8.0.3/32');
  });

  it('never reissues the server address', () => {
    expect(nextPeerAddress('10.8.0.5/24', [])).toBe('10.8.0.2/32');
    expect(nextPeerAddress('10.8.0.2/24', [])).toBe('10.8.0.3/32');
  });

  it('throws on an invalid server address', () => {
    expect(() => nextPeerAddress('not-an-ip', [])).toThrow();
  });
});

describe('buildClientConfig', () => {
  const server = { public_key: 'SRVPUB', endpoint: 'vpn.example.com', listen_port: 51820, dns: '1.1.1.1' };
  const peer = { private_key: 'PEERPRIV', address: '10.8.0.2/32', allowed_ips: '0.0.0.0/0' };

  it('produces a complete config', () => {
    const cfg = buildClientConfig(server, peer);
    expect(cfg).toContain('PrivateKey = PEERPRIV');
    expect(cfg).toContain('Address = 10.8.0.2/32');
    expect(cfg).toContain('DNS = 1.1.1.1');
    expect(cfg).toContain('PublicKey = SRVPUB');
    expect(cfg).toContain('Endpoint = vpn.example.com:51820');
    expect(cfg).toContain('AllowedIPs = 0.0.0.0/0');
    expect(cfg).toContain('PersistentKeepalive = 25');
  });

  it('includes the preshared key when present', () => {
    expect(buildClientConfig(server, { ...peer, preshared_key: 'PSK' })).toContain('PresharedKey = PSK');
  });

  it('omits the endpoint line when none is configured', () => {
    expect(buildClientConfig({ ...server, endpoint: '' }, peer)).not.toContain('Endpoint =');
  });

  it('supports split-tunnel AllowedIPs', () => {
    expect(buildClientConfig(server, { ...peer, allowed_ips: '10.8.0.0/24, 192.168.1.0/24' }))
      .toContain('AllowedIPs = 10.8.0.0/24, 192.168.1.0/24');
  });
});
