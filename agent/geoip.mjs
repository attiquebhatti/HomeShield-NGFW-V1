/**
 * GeoIP country filtering for the HomeShield agent.
 *
 * The agent downloads per-country aggregated CIDR zone files (one CIDR per
 * line, e.g. ipdeny.com's aggregated zones) and compiles them into an
 * nftables set. Two modes:
 *   - block: drop traffic to/from the listed countries
 *   - allow: only permit inbound from the listed countries (plus private
 *            ranges and established connections); drop the rest
 *
 * Pure functions — unit tested in geoip.test.mjs.
 */

// Private / reserved ranges that allow-mode must never drop (LAN, loopback,
// link-local, multicast), so enabling allow-mode can't cut off local access.
const PRIVATE_V4 = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4'];
const PRIVATE_V6 = ['::1/128', 'fe80::/10', 'fc00::/7', 'ff00::/8'];

const CIDR_V4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/;

/** Parses a country zone file into a list of valid CIDR/IP strings. */
export function parseZoneFile(text) {
  const out = [];
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.split('#')[0].trim();
    if (!line) continue;
    const m = line.match(CIDR_V4);
    if (m) {
      const octets = [m[1], m[2], m[3], m[4]].map(Number);
      const prefix = m[5] !== undefined ? Number(m[5]) : 32;
      if (octets.every(o => o <= 255) && prefix <= 32) out.push(line);
      continue;
    }
    // IPv6 (loose)
    const [addr, prefix] = line.split('/');
    if (/^[0-9a-fA-F:]+$/.test(addr) && addr.includes(':')) {
      if (prefix === undefined || (/^\d{1,3}$/.test(prefix) && Number(prefix) <= 128)) out.push(line);
    }
  }
  return out;
}

function setBlock(name, type, elements) {
  const lines = [`  set ${name} {`, `    type ${type}`, '    flags interval', '    auto-merge'];
  if (elements.length) lines.push(`    elements = { ${elements.join(', ')} }`);
  lines.push('  }');
  return lines;
}

/**
 * Builds the nftables GeoIP table. Returns null when there are no networks
 * (caller should remove the table).
 *
 * @param mode 'block' | 'allow'
 * @param v4   IPv4 CIDRs for the selected countries
 * @param v6   IPv6 CIDRs for the selected countries
 */
export function buildGeoTable(mode, v4 = [], v6 = []) {
  if (!v4.length && !v6.length) return null;
  const allow = mode === 'allow';

  const lines = [
    '#!/usr/sbin/nft -f',
    `# HomeShield NGFW - GeoIP ${allow ? 'allow' : 'block'}list`,
    `# Networks: ${v4.length} IPv4, ${v6.length} IPv6`,
    '',
    'table inet homeshield_geo',
    'delete table inet homeshield_geo',
    '',
    'table inet homeshield_geo {',
    ...setBlock('geo4', 'ipv4_addr', v4),
    ...setBlock('geo6', 'ipv6_addr', v6),
  ];

  if (allow) {
    // Allow-mode applies to inbound only: accept established, private ranges
    // and the listed countries; drop everything else.
    lines.push(
      ...setBlock('priv4', 'ipv4_addr', PRIVATE_V4),
      ...setBlock('priv6', 'ipv6_addr', PRIVATE_V6),
      '  chain input {',
      '    type filter hook input priority -5; policy accept;',
      '    ct state established,related accept',
      '    iif lo accept',
      '    ip saddr @priv4 accept',
      '    ip6 saddr @priv6 accept',
    );
    if (v4.length) lines.push('    ip saddr @geo4 accept', '    meta nfproto ipv4 counter drop');
    if (v6.length) lines.push('    ip6 saddr @geo6 accept', '    meta nfproto ipv6 counter drop');
    lines.push('  }', '}', '');
    return lines.join('\n');
  }

  // Block-mode: drop to/from the listed countries on input/output/forward.
  lines.push(
    '  chain input {',
    '    type filter hook input priority -5; policy accept;',
  );
  if (v4.length) lines.push('    ip saddr @geo4 counter drop');
  if (v6.length) lines.push('    ip6 saddr @geo6 counter drop');
  lines.push('  }', '  chain output {', '    type filter hook output priority -5; policy accept;');
  if (v4.length) lines.push('    ip daddr @geo4 counter drop');
  if (v6.length) lines.push('    ip6 daddr @geo6 counter drop');
  lines.push('  }', '  chain forward {', '    type filter hook forward priority -5; policy accept;');
  if (v4.length) lines.push('    ip saddr @geo4 counter drop', '    ip daddr @geo4 counter drop');
  if (v6.length) lines.push('    ip6 saddr @geo6 counter drop', '    ip6 daddr @geo6 counter drop');
  lines.push('  }', '}', '');
  return lines.join('\n');
}
