import { describe, it, expect } from 'vitest';
import { compileNftables, compileWindowsFirewall, validatePolicies } from './nftables';
import type { FirewallPolicy } from './database.types';

function policy(overrides: Partial<FirewallPolicy> = {}): FirewallPolicy {
  return {
    id: 'test-id',
    name: 'Test Rule',
    description: 'test',
    enabled: true,
    action: 'allow',
    direction: 'inbound',
    src_ip: 'any',
    dst_ip: 'any',
    src_device: 'any',
    dst_device: 'any',
    src_port: 'any',
    dst_port: 'any',
    protocol: 'any',
    interface: 'any',
    schedule: 'always',
    tags: [],
    priority: 100,
    log_enabled: false,
    created_at: '',
    updated_at: '',
    ...overrides,
  };
}

describe('compileNftables', () => {
  it('never flushes the global ruleset, only the homeshield table', () => {
    const out = compileNftables([policy()]);
    expect(out).not.toContain('flush ruleset');
    expect(out).toContain('table inet homeshield\ndelete table inet homeshield');
  });

  it('prefixes ports with the protocol', () => {
    const out = compileNftables([policy({ protocol: 'tcp', dst_port: '443' })]);
    expect(out).toContain('tcp dport 443');
    // No bare dport without protocol prefix
    expect(out).not.toMatch(/(?<!tcp |udp )dport/);
  });

  it('emits protocol match when no ports are given', () => {
    const out = compileNftables([policy({ protocol: 'udp' })]);
    expect(out).toContain('meta l4proto udp');
  });

  it('does not emit ports for non-port protocols', () => {
    const out = compileNftables([policy({ protocol: 'icmp', dst_port: '443' })]);
    expect(out).not.toContain('dport');
    expect(out).toContain('meta l4proto { icmp, ipv6-icmp }');
  });

  it('uses tcp reset for rejecting tcp traffic', () => {
    const out = compileNftables([policy({ action: 'reject', protocol: 'tcp' })]);
    expect(out).toContain('reject with tcp reset');
  });

  it('uses icmpx unreachable for rejecting non-tcp traffic', () => {
    const out = compileNftables([policy({ action: 'reject', protocol: 'udp' })]);
    expect(out).toContain('reject with icmpx type port-unreachable');
  });

  it('uses ip6 selectors for IPv6 addresses', () => {
    const out = compileNftables([policy({ src_ip: 'fd00::1/64' })]);
    expect(out).toContain('ip6 saddr fd00::1/64');
  });

  it('uses ip selectors for IPv4 addresses', () => {
    const out = compileNftables([policy({ dst_ip: '192.168.1.0/24' })]);
    expect(out).toContain('ip daddr 192.168.1.0/24');
  });

  it('uses oif for outbound interface matches and iif for inbound', () => {
    const outbound = compileNftables([policy({ direction: 'outbound', interface: 'eth0' })]);
    expect(outbound).toContain('oif "eth0"');
    const inbound = compileNftables([policy({ direction: 'inbound', interface: 'eth0' })]);
    expect(inbound).toContain('iif "eth0"');
  });

  it('excludes disabled policies', () => {
    const out = compileNftables([policy({ enabled: false, name: 'Disabled Rule' })]);
    expect(out).not.toContain('Disabled Rule');
  });

  it('adds log prefix when logging is enabled', () => {
    const out = compileNftables([policy({ log_enabled: true, action: 'deny' })]);
    expect(out).toContain('log prefix "hs-deny: "');
  });
});

describe('compileWindowsFirewall', () => {
  it('only adds port parameters for tcp/udp', () => {
    const out = compileWindowsFirewall([policy({ protocol: 'any', dst_port: '443' })]);
    expect(out).not.toContain('-LocalPort');
    expect(out).not.toContain('-RemotePort');
  });

  it('maps inbound destination port to LocalPort', () => {
    const out = compileWindowsFirewall([policy({ protocol: 'tcp', dst_port: '3389', direction: 'inbound' })]);
    expect(out).toContain('-LocalPort "3389"');
  });

  it('maps outbound destination port/ip to Remote parameters', () => {
    const out = compileWindowsFirewall([
      policy({ protocol: 'tcp', dst_port: '443', dst_ip: '1.2.3.4', direction: 'outbound' }),
    ]);
    expect(out).toContain('-RemotePort "443"');
    expect(out).toContain('-RemoteAddress "1.2.3.4"');
  });

  it('skips log-only rules with a comment', () => {
    const out = compileWindowsFirewall([policy({ action: 'log-only', name: 'Watcher' })]);
    expect(out).not.toContain('New-NetFirewallRule');
    expect(out).toContain('# Skipped "Watcher"');
  });

  it('skips forward rules (host firewall has no forward chain)', () => {
    const out = compileWindowsFirewall([policy({ direction: 'forward', name: 'Transit' })]);
    expect(out).not.toContain('New-NetFirewallRule');
  });

  it('strips injection-prone characters from names and descriptions', () => {
    const out = compileWindowsFirewall([
      policy({ name: 'Evil"; Remove-Item C:\\ #', description: 'has `backticks` and $vars' }),
    ]);
    expect(out).not.toContain('"; Remove-Item');
    expect(out).not.toContain('$vars');
  });

  it('cleans up old rules without failing when none exist', () => {
    const out = compileWindowsFirewall([policy()]);
    expect(out).toContain('-ErrorAction SilentlyContinue');
  });
});

describe('device-ID matching', () => {
  const devices = [
    { id: 'dev-1', hostname: 'attiques-laptop', ip_address: '192.168.1.50' },
    { id: 'dev-2', hostname: 'no-ip-device', ip_address: null },
  ];

  it('resolves a source device to its IP in nftables', () => {
    const out = compileNftables([policy({ src_device: 'dev-1', protocol: 'tcp', dst_port: '443' })], devices);
    expect(out).toContain('ip saddr 192.168.1.50');
  });

  it('resolves a destination device to its IP', () => {
    const out = compileNftables([policy({ direction: 'outbound', dst_device: 'dev-1' })], devices);
    expect(out).toContain('ip daddr 192.168.1.50');
  });

  it('skips a rule whose device has no known IP (never matches everything)', () => {
    const out = compileNftables([policy({ name: 'NoIP', src_device: 'dev-2' })], devices);
    expect(out).toContain('# Skipped "NoIP": referenced device has no known IP yet');
    expect(out).not.toContain('ip saddr');
  });

  it('skips a rule referencing an unknown device', () => {
    const out = compileNftables([policy({ name: 'Gone', dst_device: 'dev-404' })], devices);
    expect(out).toContain('# Skipped "Gone"');
  });

  it('resolves device to RemoteAddress for inbound Windows rules', () => {
    const out = compileWindowsFirewall([policy({ src_device: 'dev-1', direction: 'inbound' })], devices);
    expect(out).toContain('-RemoteAddress "192.168.1.50"');
  });

  it('validates device references', () => {
    expect(validatePolicies([policy({ src_device: 'dev-1' })], devices)).toEqual([]);
    expect(validatePolicies([policy({ src_device: 'dev-404' })], devices)[0]).toMatch(/no longer enrolled/);
    expect(validatePolicies([policy({ dst_device: 'dev-2' })], devices)[0]).toMatch(/no known IP/);
  });
});

describe('validatePolicies', () => {
  it('accepts a valid policy', () => {
    expect(validatePolicies([policy({ protocol: 'tcp', dst_port: '443', src_ip: '10.0.0.0/8' })])).toEqual([]);
  });

  it('rejects ports without tcp/udp protocol', () => {
    const errors = validatePolicies([policy({ protocol: 'any', dst_port: '443' })]);
    expect(errors.some(e => e.includes('ports require protocol'))).toBe(true);
  });

  it('rejects invalid octets and prefixes', () => {
    expect(validatePolicies([policy({ src_ip: '999.1.1.1' })]).length).toBe(1);
    expect(validatePolicies([policy({ src_ip: '10.0.0.0/33' })]).length).toBe(1);
  });

  it('rejects invalid ports and accepts ranges', () => {
    expect(validatePolicies([policy({ protocol: 'tcp', dst_port: '70000' })]).length).toBe(1);
    expect(validatePolicies([policy({ protocol: 'tcp', dst_port: '8000-8080' })])).toEqual([]);
    expect(validatePolicies([policy({ protocol: 'tcp', dst_port: '8080-8000' })]).length).toBe(1);
  });

  it('accepts IPv6 with prefix', () => {
    expect(validatePolicies([policy({ src_ip: 'fd00::/8' })])).toEqual([]);
    expect(validatePolicies([policy({ src_ip: 'fd00::/200' })]).length).toBe(1);
  });
});
