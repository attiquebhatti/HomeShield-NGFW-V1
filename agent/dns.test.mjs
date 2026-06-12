import { describe, it, expect } from 'vitest';
import { parseQuery, buildBlockResponse, createMatcher, sinkholeAddress } from './dns.mjs';

/** Builds a DNS query packet for the given name/qtype. */
function makeQuery(domain, qtype = 1, id = 0x1234) {
  const labels = domain.split('.');
  const qname = Buffer.concat([
    ...labels.map(l => Buffer.concat([Buffer.from([l.length]), Buffer.from(l, 'ascii')])),
    Buffer.from([0]),
  ]);
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header[2] = 0x01; // RD
  header.writeUInt16BE(1, 4); // QDCOUNT
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(qtype, 0);
  tail.writeUInt16BE(1, 2); // class IN
  return Buffer.concat([header, qname, tail]);
}

describe('parseQuery', () => {
  it('parses domain, id and qtype', () => {
    const parsed = parseQuery(makeQuery('Ads.Example.COM', 28, 0xbeef));
    expect(parsed).toMatchObject({
      id: 0xbeef,
      domain: 'ads.example.com',
      qtype: 28,
      qtypeName: 'AAAA',
    });
  });

  it('rejects malformed packets', () => {
    expect(parseQuery(Buffer.alloc(5))).toBeNull();
    expect(parseQuery(Buffer.from('not a dns packet at all'))).toBeNull();
    const truncated = makeQuery('example.com').subarray(0, 18);
    expect(parseQuery(truncated)).toBeNull();
  });
});

describe('buildBlockResponse', () => {
  it('answers A queries with 0.0.0.0', () => {
    const query = makeQuery('ads.example.com', 1, 0x4242);
    const parsed = parseQuery(query);
    const resp = buildBlockResponse(query, parsed);

    expect(resp.readUInt16BE(0)).toBe(0x4242);      // same id
    expect(resp[2] & 0x80).toBe(0x80);              // QR=1 (response)
    expect(resp[2] & 0x01).toBe(0x01);              // RD copied
    expect(resp[3] & 0x0f).toBe(0);                 // NOERROR
    expect(resp.readUInt16BE(6)).toBe(1);           // one answer
    expect(resp.subarray(resp.length - 4)).toEqual(Buffer.alloc(4)); // 0.0.0.0
  });

  it('answers AAAA queries with ::', () => {
    const query = makeQuery('ads.example.com', 28);
    const resp = buildBlockResponse(query, parseQuery(query));
    expect(resp.readUInt16BE(6)).toBe(1);
    expect(resp.subarray(resp.length - 16)).toEqual(Buffer.alloc(16));
  });

  it('answers other query types with NXDOMAIN', () => {
    const query = makeQuery('ads.example.com', 16); // TXT
    const resp = buildBlockResponse(query, parseQuery(query));
    expect(resp[3] & 0x0f).toBe(3); // NXDOMAIN
    expect(resp.readUInt16BE(6)).toBe(0); // no answers
  });

  it('reports sinkhole addresses for logging', () => {
    expect(sinkholeAddress(1)).toBe('0.0.0.0');
    expect(sinkholeAddress(28)).toBe('::');
    expect(sinkholeAddress(16)).toBe('');
  });
});

describe('createMatcher', () => {
  const match = createMatcher([
    { domain: 'doubleclick.net', list_type: 'blocklist', category: 'ads' },
    { domain: 'ads.example.com', list_type: 'blocklist', category: 'ads' },
    { domain: 'good.ads.example.com', list_type: 'allowlist', category: 'custom' },
  ]);

  it('blocks exact matches and subdomains', () => {
    expect(match('doubleclick.net').action).toBe('blocked');
    expect(match('stats.g.doubleclick.net')).toMatchObject({
      action: 'blocked',
      matched_list: 'doubleclick.net',
      category: 'ads',
    });
  });

  it('lets allowlist win over blocklist, including subdomains', () => {
    expect(match('ads.example.com').action).toBe('blocked');
    expect(match('good.ads.example.com').action).toBe('allowed');
    expect(match('cdn.good.ads.example.com').action).toBe('allowed');
  });

  it('allows unlisted domains with no matched_list', () => {
    expect(match('anthropic.com')).toEqual({ action: 'allowed', matched_list: null, category: null });
  });

  it('is case-insensitive and tolerant of trailing dots and wildcards', () => {
    expect(match('DoubleClick.NET.').action).toBe('blocked');
    const wild = createMatcher([{ domain: '*.tracker.io', list_type: 'blocklist', category: 'ads' }]);
    expect(wild.call ? wild('x.tracker.io').action : null).toBe('blocked');
    expect(wild('tracker.io').action).toBe('blocked');
  });
});
