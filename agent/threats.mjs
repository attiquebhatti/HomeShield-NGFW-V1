/**
 * Compiles threat-intelligence indicators into an nftables blocking table for
 * the HomeShield agent. Pure, side-effect-free — unit tested in threats.test.mjs.
 *
 * The generated `homeshield_threats` table runs at priority -10, i.e. BEFORE
 * the homeshield policy filter (priority 0), so traffic to/from known-bad
 * addresses is dropped before any policy evaluation. It uses interval sets so
 * individual IPs and CIDR ranges coexist.
 */

/** Splits indicator values into IPv4 and IPv6 buckets (CIDRs included). */
export function splitByFamily(values) {
  const v4 = [];
  const v6 = [];
  for (const value of values) {
    const v = String(value).trim();
    if (!v) continue;
    if (v.includes(':')) v6.push(v);
    else v4.push(v);
  }
  return { v4, v6 };
}

function setBlock(name, type, elements) {
  const lines = [
    `  set ${name} {`,
    `    type ${type}`,
    '    flags interval',
    '    auto-merge',
  ];
  if (elements.length) {
    lines.push(`    elements = { ${elements.join(', ')} }`);
  }
  lines.push('  }');
  return lines;
}

/**
 * Builds the nftables threat-blocking table.
 * Returns null when there are no indicators (caller should remove the table).
 */
export function buildThreatTable(v4 = [], v6 = []) {
  if (!v4.length && !v6.length) return null;

  const lines = [
    '#!/usr/sbin/nft -f',
    '# HomeShield NGFW - Threat intelligence blocklist',
    `# Indicators: ${v4.length} IPv4, ${v6.length} IPv6`,
    '',
    'table inet homeshield_threats',
    'delete table inet homeshield_threats',
    '',
    'table inet homeshield_threats {',
    ...setBlock('threat4', 'ipv4_addr', v4),
    ...setBlock('threat6', 'ipv6_addr', v6),
    '',
    '  chain input {',
    '    type filter hook input priority -10; policy accept;',
  ];
  if (v4.length) lines.push('    ip saddr @threat4 counter drop');
  if (v6.length) lines.push('    ip6 saddr @threat6 counter drop');
  lines.push(
    '  }',
    '  chain output {',
    '    type filter hook output priority -10; policy accept;',
  );
  if (v4.length) lines.push('    ip daddr @threat4 counter drop');
  if (v6.length) lines.push('    ip6 daddr @threat6 counter drop');
  lines.push(
    '  }',
    '  chain forward {',
    '    type filter hook forward priority -10; policy accept;',
  );
  if (v4.length) lines.push('    ip saddr @threat4 counter drop', '    ip daddr @threat4 counter drop');
  if (v6.length) lines.push('    ip6 saddr @threat6 counter drop', '    ip6 daddr @threat6 counter drop');
  lines.push('  }', '}', '');

  return lines.join('\n');
}
