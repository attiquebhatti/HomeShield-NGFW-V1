import { describe, it, expect } from 'vitest';
import { parseFeed, classifyIndicator } from './feeds.mjs';

describe('classifyIndicator', () => {
  it('classifies IPv4 addresses and CIDRs', () => {
    expect(classifyIndicator('192.168.1.1')).toEqual({ indicator_type: 'ip', value: '192.168.1.1' });
    expect(classifyIndicator('10.0.0.0/8')).toEqual({ indicator_type: 'cidr', value: '10.0.0.0/8' });
    expect(classifyIndicator('1.2.3.4/32')).toEqual({ indicator_type: 'ip', value: '1.2.3.4/32' });
  });

  it('rejects malformed IPs', () => {
    expect(classifyIndicator('999.1.1.1')).toBeNull();
    expect(classifyIndicator('10.0.0.0/40')).toBeNull();
  });

  it('classifies IPv6 and hashes and domains', () => {
    expect(classifyIndicator('2001:db8::1').indicator_type).toBe('ip');
    expect(classifyIndicator('fd00::/8').indicator_type).toBe('cidr');
    expect(classifyIndicator('d41d8cd98f00b204e9800998ecf8427e').indicator_type).toBe('hash');
    expect(classifyIndicator('evil.example.com').indicator_type).toBe('domain');
  });

  it('rejects junk', () => {
    expect(classifyIndicator('not-an-indicator!!')).toBeNull();
    expect(classifyIndicator('')).toBeNull();
  });
});

describe('parseFeed', () => {
  const sample = [
    '# Emerging Threats - compromised IPs',
    '; another comment style',
    '45.9.148.2',
    '185.220.101.0/24   // tor exit range',
    '45.9.148.2',            // duplicate
    '10.0.0.5, some description here',
    '',
    'garbage line that is not an indicator',
  ].join('\n');

  it('parses IP feeds, stripping comments and deduping', () => {
    const out = parseFeed(sample, 'ip');
    expect(out).toEqual([
      { indicator_type: 'ip', value: '45.9.148.2' },
      { indicator_type: 'cidr', value: '185.220.101.0/24' },
      { indicator_type: 'ip', value: '10.0.0.5' },
    ]);
  });

  it('filters by feed type', () => {
    const mixed = 'evil.example.com\n1.2.3.4\nd41d8cd98f00b204e9800998ecf8427e';
    expect(parseFeed(mixed, 'domain')).toEqual([{ indicator_type: 'domain', value: 'evil.example.com' }]);
    expect(parseFeed(mixed, 'ip')).toEqual([{ indicator_type: 'ip', value: '1.2.3.4' }]);
    expect(parseFeed(mixed, 'mixed')).toHaveLength(3);
  });

  it('honors the limit', () => {
    const many = Array.from({ length: 100 }, (_, i) => `10.0.0.${i}`).join('\n');
    expect(parseFeed(many, 'ip', 10)).toHaveLength(10);
  });

  it('handles empty and comment-only input', () => {
    expect(parseFeed('', 'ip')).toEqual([]);
    expect(parseFeed('# just a comment\n; and another', 'ip')).toEqual([]);
  });
});
