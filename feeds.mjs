/**
 * Threat-feed parsing for the HomeShield management server.
 *
 * Threat feeds are typically newline-delimited text: one IP, CIDR, domain or
 * hash per line, with comments (#, ;, //) and inline annotations. This module
 * turns raw feed text into normalized indicator records. Pure functions, no
 * I/O — unit tested in feeds.test.mjs.
 */

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const IPV4_CIDR = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/;
const HASH = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
const DOMAIN = /^(?=.{1,253}$)([a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

function validOctets(parts) {
  return parts.every(p => p >= 0 && p <= 255);
}

/** Classifies a single token, or returns null if it isn't a usable indicator. */
export function classifyIndicator(token) {
  const t = token.trim().replace(/\.$/, '');
  if (!t) return null;

  let m = t.match(IPV4_CIDR);
  if (m) {
    const octets = [m[1], m[2], m[3], m[4]].map(Number);
    const prefix = Number(m[5]);
    if (validOctets(octets) && prefix <= 32) {
      return { indicator_type: prefix === 32 ? 'ip' : 'cidr', value: t };
    }
    return null;
  }

  m = t.match(IPV4);
  if (m) {
    const octets = [m[1], m[2], m[3], m[4]].map(Number);
    return validOctets(octets) ? { indicator_type: 'ip', value: t } : null;
  }

  // IPv6 (loose): hex groups and colons, optional /prefix
  if (t.includes(':')) {
    const [addr, prefix] = t.split('/');
    if (/^[0-9a-fA-F:]+$/.test(addr) && addr.includes(':')) {
      if (prefix !== undefined && (!/^\d{1,3}$/.test(prefix) || Number(prefix) > 128)) return null;
      return { indicator_type: prefix !== undefined && Number(prefix) < 128 ? 'cidr' : 'ip', value: t };
    }
    return null;
  }

  if (HASH.test(t)) return { indicator_type: 'hash', value: t.toLowerCase() };
  if (DOMAIN.test(t)) return { indicator_type: 'domain', value: t.toLowerCase() };
  return null;
}

/** Strips a comment from a line and returns the remaining content. */
function stripComment(line) {
  let s = line;
  for (const marker of ['#', ';', '//']) {
    const idx = s.indexOf(marker);
    if (idx >= 0) s = s.slice(0, idx);
  }
  return s.trim();
}

/**
 * Parses raw feed text into deduplicated indicators.
 *
 * @param text     raw feed body
 * @param feedType 'ip' | 'domain' | 'hash' | 'mixed' — restricts which
 *                 indicator types are kept ('mixed' keeps all)
 * @param limit    max indicators to return (default 200000)
 */
export function parseFeed(text, feedType = 'mixed', limit = 200000) {
  const keep =
    feedType === 'ip' ? new Set(['ip', 'cidr'])
    : feedType === 'domain' ? new Set(['domain'])
    : feedType === 'hash' ? new Set(['hash'])
    : null; // mixed → keep everything

  const seen = new Set();
  const out = [];

  for (const rawLine of String(text).split(/\r?\n/)) {
    const line = stripComment(rawLine);
    if (!line) continue;

    // Take the first token that classifies; many feeds append descriptions
    // after the indicator (whitespace, comma or tab separated).
    for (const token of line.split(/[\s,]+/)) {
      const indicator = classifyIndicator(token);
      if (!indicator) continue;
      if (keep && !keep.has(indicator.indicator_type)) break;
      if (seen.has(indicator.value)) break;
      seen.add(indicator.value);
      out.push(indicator);
      break;
    }
    if (out.length >= limit) break;
  }

  return out;
}
