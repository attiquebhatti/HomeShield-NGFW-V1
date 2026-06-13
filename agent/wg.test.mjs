import { describe, it, expect } from 'vitest';
import { buildServerConfig, buildVpnNatTable, parseWgDump } from './wg.mjs';

describe('buildServerConfig', () => {
  const server = { interface: 'wg0', private_key: 'SRVPRIV', listen_port: 51820, address: '10.8.0.1/24' };

  it('builds the interface section', () => {
    const cfg = buildServerConfig(server, []);
    expect(cfg).toContain('Address = 10.8.0.1/24');
    expect(cfg).toContain('ListenPort = 51820');
    expect(cfg).toContain('PrivateKey = SRVPRIV');
  });

  it('pins each peer to a /32 AllowedIPs (not 0.0.0.0/0)', () => {
    const cfg = buildServerConfig(server, [
      { public_key: 'PEER1', address: '10.8.0.2/32' },
      { public_key: 'PEER2', address: '10.8.0.3', preshared_key: 'PSK2' },
    ]);
    expect(cfg).toContain('PublicKey = PEER1');
    expect(cfg).toContain('AllowedIPs = 10.8.0.2/32');
    expect(cfg).toContain('PublicKey = PEER2');
    expect(cfg).toContain('PresharedKey = PSK2');
    expect(cfg).toContain('AllowedIPs = 10.8.0.3/32');
    expect(cfg).not.toContain('0.0.0.0/0');
  });

  it('skips peers missing a key or address', () => {
    const cfg = buildServerConfig(server, [{ public_key: '', address: '10.8.0.2/32' }]);
    expect(cfg).not.toContain('AllowedIPs');
  });
});

describe('buildVpnNatTable', () => {
  it('masquerades the VPN subnet', () => {
    const out = buildVpnNatTable('10.8.0.1/24');
    expect(out).toContain('ip saddr 10.8.0.0/24 counter masquerade');
    expect(out).toContain('hook postrouting');
    expect(out).toContain('delete table inet homeshield_vpn');
    expect(out).not.toContain('flush ruleset');
  });
});

describe('parseWgDump', () => {
  const dump = [
    'SRVPRIV\tSRVPUB\t51820\toff', // interface line (skipped)
    'PEER1\t(none)\t203.0.113.5:12345\t10.8.0.2/32\t1718200000\t1024\t2048\t25',
    'PEER2\t(none)\t(none)\t10.8.0.3/32\t0\t0\t0\toff', // never connected
  ].join('\n');

  it('parses peer handshake and transfer stats', () => {
    const peers = parseWgDump(dump);
    expect(peers).toHaveLength(2);
    expect(peers[0]).toMatchObject({
      public_key: 'PEER1',
      endpoint: '203.0.113.5:12345',
      rx_bytes: 1024,
      tx_bytes: 2048,
    });
    expect(peers[0].last_handshake).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
  });

  it('reports never-connected peers with a null handshake', () => {
    const peers = parseWgDump(dump);
    expect(peers[1].last_handshake).toBeNull();
    expect(peers[1].endpoint).toBe('');
  });

  it('handles empty output', () => {
    expect(parseWgDump('')).toEqual([]);
  });
});
