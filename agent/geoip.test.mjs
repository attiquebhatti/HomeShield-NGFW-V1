import { describe, it, expect } from 'vitest';
import { parseZoneFile, buildGeoTable } from './geoip.mjs';

describe('parseZoneFile', () => {
  it('parses CIDR lines, ignoring comments and junk', () => {
    const text = [
      '# country zone',
      '1.2.3.0/24',
      '5.6.7.8',
      '2001:db8::/32',
      'not-a-cidr',
      '999.1.1.1/24',
      '',
    ].join('\n');
    expect(parseZoneFile(text)).toEqual(['1.2.3.0/24', '5.6.7.8', '2001:db8::/32']);
  });
});

describe('buildGeoTable', () => {
  it('returns null with no networks', () => {
    expect(buildGeoTable('block', [], [])).toBeNull();
  });

  it('block mode drops to/from the listed networks at priority -5', () => {
    const out = buildGeoTable('block', ['1.2.3.0/24'], []);
    expect(out).toContain('priority -5');
    expect(out).toContain('ip saddr @geo4 counter drop');
    expect(out).toContain('ip daddr @geo4 counter drop');
    expect(out).toContain('delete table inet homeshield_geo');
    expect(out).not.toContain('flush ruleset');
    // block mode does not whitelist private ranges
    expect(out).not.toContain('priv4');
  });

  it('allow mode accepts established, private and listed networks then drops the rest', () => {
    const out = buildGeoTable('allow', ['1.2.3.0/24'], []);
    expect(out).toContain('ct state established,related accept');
    expect(out).toContain('iif lo accept');
    expect(out).toContain('ip saddr @priv4 accept');
    expect(out).toContain('ip saddr @geo4 accept');
    expect(out).toContain('meta nfproto ipv4 counter drop');
    // allow mode only touches inbound
    expect(out).not.toContain('hook output');
  });

  it('includes IPv6 rules only when v6 networks are present', () => {
    const v4only = buildGeoTable('block', ['1.2.3.0/24'], []);
    expect(v4only).not.toContain('@geo6 counter');
    const both = buildGeoTable('block', ['1.2.3.0/24'], ['2001:db8::/32']);
    expect(both).toContain('ip6 saddr @geo6 counter drop');
  });
});
