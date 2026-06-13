import { describe, it, expect } from 'vitest';
import { buildSwanctlConf, buildSwanctlSecrets, buildIpsecNatTable, buildWindowsInstaller } from './ipsec.mjs';

describe('buildSwanctlConf', () => {
  it('builds an IKEv2 EAP server config with the endpoint, pool and DNS', () => {
    const out = buildSwanctlConf({ endpoint: 'vpn.example.com', poolSubnet: '10.9.0.0/24', dns: '1.1.1.1' });
    expect(out).toContain('version = 2');
    expect(out).toContain('auth = eap-mschapv2');
    expect(out).toContain('id = vpn.example.com');
    expect(out).toContain('addrs = 10.9.0.0/24');
    expect(out).toContain('dns = 1.1.1.1');
    expect(out).toContain('certs = homeshield-server.pem');
  });

  it('defaults the traffic selector to full tunnel', () => {
    expect(buildSwanctlConf({ endpoint: 'x' })).toContain('local_ts = 0.0.0.0/0');
  });

  it('honors split-tunnel local subnets', () => {
    expect(buildSwanctlConf({ endpoint: 'x', localSubnets: '192.168.1.0/24' })).toContain('local_ts = 192.168.1.0/24');
  });
});

describe('buildSwanctlSecrets', () => {
  it('emits an EAP secret per user', () => {
    const out = buildSwanctlSecrets([{ username: 'alice', password: 'pw1' }, { username: 'bob', password: 'pw2' }]);
    expect(out).toContain('id = alice');
    expect(out).toContain('secret = "pw1"');
    expect(out).toContain('id = bob');
    expect(out).toContain('secret = "pw2"');
  });

  it('skips incomplete users and strips quotes from secrets', () => {
    const out = buildSwanctlSecrets([{ username: 'a', password: 'x"y' }, { username: '', password: 'z' }]);
    expect(out).toContain('secret = "xy"');
    expect(out).not.toContain('id = \n');
  });
});

describe('buildIpsecNatTable', () => {
  it('allows IKE/ESP in and masquerades the pool', () => {
    const out = buildIpsecNatTable('10.9.0.0/24');
    expect(out).toContain('udp dport { 500, 4500 } counter accept');
    expect(out).toContain('meta l4proto esp counter accept');
    expect(out).toContain('ip saddr 10.9.0.0/24 counter masquerade');
    expect(out).toContain('delete table inet homeshield_ipsec');
    expect(out).not.toContain('flush ruleset');
  });
});

describe('buildWindowsInstaller', () => {
  const out = buildWindowsInstaller({ name: 'HomeShield VPN', endpoint: 'vpn.example.com', caCertPem: '-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----', fullTunnel: false });

  it('embeds the CA (base64) and imports it to Trusted Root', () => {
    const b64 = Buffer.from('-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----', 'utf8').toString('base64');
    expect(out).toContain(b64);
    expect(out).toContain('Cert:\\LocalMachine\\Root');
  });

  it('creates an IKEv2 EAP connection to the endpoint', () => {
    expect(out).toContain('-TunnelType Ikev2');
    expect(out).toContain('-AuthenticationMethod Eap');
    expect(out).toContain('$Server  = "vpn.example.com"');
    expect(out).toContain('-SplitTunneling:$true'); // fullTunnel:false => split on
  });

  it('requires admin and strips injection characters from names', () => {
    const evil = buildWindowsInstaller({ name: 'x"; rm $y `z', endpoint: 'a"b', caCertPem: '' });
    expect(evil).toContain('#Requires -RunAsAdministrator');
    expect(evil).not.toContain('"; rm');
    expect(evil).not.toContain('`z');
  });
});
