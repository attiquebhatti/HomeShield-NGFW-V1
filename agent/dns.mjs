/**
 * DNS wire-format helpers and blocklist matching for the HomeShield agent's
 * DNS filtering proxy. Pure functions, no I/O — unit tested in dns.test.mjs.
 */

export const QTYPE_NAMES = {
  1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT',
  28: 'AAAA', 33: 'SRV', 64: 'SVCB', 65: 'HTTPS', 255: 'ANY',
};

/**
 * Parses the header and first question of a DNS query packet.
 * Returns { id, domain, qtype, qtypeName, questionEnd } or null if malformed.
 */
export function parseQuery(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 17) return null;

  const id = buf.readUInt16BE(0);
  const qdcount = buf.readUInt16BE(4);
  if (qdcount < 1) return null;

  const labels = [];
  let offset = 12;
  for (;;) {
    if (offset >= buf.length) return null;
    const len = buf[offset];
    if (len === 0) { offset++; break; }
    if (len > 63 || offset + 1 + len > buf.length) return null; // no compression in questions
    labels.push(buf.toString('ascii', offset + 1, offset + 1 + len));
    offset += 1 + len;
    if (labels.length > 127) return null;
  }
  if (offset + 4 > buf.length) return null;

  const qtype = buf.readUInt16BE(offset);
  return {
    id,
    domain: labels.join('.').toLowerCase(),
    qtype,
    qtypeName: QTYPE_NAMES[qtype] || String(qtype),
    questionEnd: offset + 4,
  };
}

/**
 * Builds a sinkhole response for a blocked query: A → 0.0.0.0, AAAA → ::,
 * anything else → NXDOMAIN. Echoes the question section of the original query.
 */
export function buildBlockResponse(queryBuf, parsed) {
  const question = queryBuf.subarray(12, parsed.questionEnd);
  const isA = parsed.qtype === 1;
  const isAAAA = parsed.qtype === 28;
  const sinkhole = isA || isAAAA;

  const header = Buffer.alloc(12);
  header.writeUInt16BE(parsed.id, 0);
  // QR=1, opcode copied as 0, RD copied from query, RA=1; rcode 0 or 3 (NXDOMAIN)
  header[2] = 0x80 | (queryBuf[2] & 0x01);
  header[3] = 0x80 | (sinkhole ? 0 : 3);
  header.writeUInt16BE(1, 4); // QDCOUNT
  header.writeUInt16BE(sinkhole ? 1 : 0, 6); // ANCOUNT

  if (!sinkhole) return Buffer.concat([header, question]);

  const rdata = isA ? Buffer.alloc(4) : Buffer.alloc(16); // 0.0.0.0 / ::
  const answer = Buffer.alloc(12);
  answer.writeUInt16BE(0xc00c, 0);          // name: pointer to question
  answer.writeUInt16BE(parsed.qtype, 2);    // type
  answer.writeUInt16BE(1, 4);               // class IN
  answer.writeUInt32BE(60, 6);              // TTL
  answer.writeUInt16BE(rdata.length, 10);   // RDLENGTH

  return Buffer.concat([header, question, answer, rdata]);
}

/** The sinkhole address a blocked query resolves to, for logging. */
export function sinkholeAddress(qtype) {
  if (qtype === 1) return '0.0.0.0';
  if (qtype === 28) return '::';
  return '';
}

/**
 * Builds a matcher from dns_entries rows. An entry matches its own domain and
 * all subdomains. Allowlist entries win over blocklist entries at any depth.
 *
 * Returns match(domain) → { action: 'allowed'|'blocked', matched_list, category }
 */
export function createMatcher(entries) {
  const allow = new Map();
  const block = new Map();
  for (const entry of entries) {
    const domain = String(entry.domain || '').toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
    if (!domain) continue;
    const target = entry.list_type === 'allowlist' ? allow : block;
    if (!target.has(domain)) target.set(domain, entry);
  }

  return function match(domain) {
    const name = String(domain || '').toLowerCase().replace(/\.$/, '');
    const labels = name.split('.');
    // Check the full name, then each parent suffix (sub.ads.example.com →
    // ads.example.com → example.com → com).
    for (let i = 0; i < labels.length; i++) {
      const suffix = labels.slice(i).join('.');
      const allowed = allow.get(suffix);
      if (allowed) {
        return { action: 'allowed', matched_list: allowed.domain, category: allowed.category || '' };
      }
    }
    for (let i = 0; i < labels.length; i++) {
      const suffix = labels.slice(i).join('.');
      const blocked = block.get(suffix);
      if (blocked) {
        return { action: 'blocked', matched_list: blocked.domain, category: blocked.category || '' };
      }
    }
    return { action: 'allowed', matched_list: null, category: null };
  };
}
