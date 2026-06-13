import { describe, it, expect } from 'vitest';
import { buildThreatTable, splitByFamily } from './threats.mjs';

describe('splitByFamily', () => {
  it('separates IPv4/CIDR from IPv6', () => {
    const { v4, v6 } = splitByFamily(['1.2.3.4', '10.0.0.0/8', '2001:db8::1', 'fd00::/8', '']);
    expect(v4).toEqual(['1.2.3.4', '10.0.0.0/8']);
    expect(v6).toEqual(['2001:db8::1', 'fd00::/8']);
  });
});

describe('buildThreatTable', () => {
  it('returns null when there are no indicators', () => {
    expect(buildThreatTable([], [])).toBeNull();
  });

  it('builds interval sets and drop rules for IPv4', () => {
    const out = buildThreatTable(['1.2.3.4', '185.220.101.0/24'], []);
    expect(out).toContain('type ipv4_addr');
    expect(out).toContain('flags interval');
    expect(out).toContain('elements = { 1.2.3.4, 185.220.101.0/24 }');
    expect(out).toContain('ip saddr @threat4 counter drop');
    expect(out).toContain('ip daddr @threat4 counter drop');
  });

  it('runs before the policy filter and never flushes the global ruleset', () => {
    const out = buildThreatTable(['1.2.3.4'], []);
    expect(out).toContain('priority -10');
    expect(out).toContain('delete table inet homeshield_threats');
    expect(out).not.toContain('flush ruleset');
  });

  it('omits v6 rules when there are no v6 indicators', () => {
    const out = buildThreatTable(['1.2.3.4'], []);
    expect(out).not.toContain('@threat6');
    // empty set is still declared but carries no elements
    expect(out).toContain('set threat6');
    expect(out).not.toMatch(/threat6 \{[^}]*elements/s);
  });

  it('includes both families when present', () => {
    const out = buildThreatTable(['1.2.3.4'], ['2001:db8::/32']);
    expect(out).toContain('ip6 saddr @threat6 counter drop');
    expect(out).toContain('elements = { 2001:db8::/32 }');
  });
});
