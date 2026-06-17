/**
 * HomeShield firewall policy compiler (pure ESM, no types).
 *
 * Single source of truth shared by the React UI (via the typed re-export in
 * nftables.ts) and the management server (server.js imports this directly to
 * compile the running config on demand for the Windows reconcile endpoint).
 *
 * Keep this dependency-free so both Vite and Node can import it unchanged.
 */

/**
 * Resolves a src_device / dst_device reference to a list of IPs.
 *   'any'          -> not device-constrained (ips: null, ok)
 *   '<device-id>'  -> that device's IP
 *   'tag:<name>'   -> every tagged device that has an IP (a group)
 *
 * `ok` is false when a device/group reference resolves to no usable IP, so the
 * caller skips the rule — a device-targeted rule must never silently match
 * everything.
 */
function resolveRef(ref, devices) {
  if (!ref || ref === 'any') return { ips: null, ok: true };
  if (ref.startsWith('tag:')) {
    const tag = ref.slice(4);
    const ips = devices.filter(d => (d.tags || []).includes(tag) && d.ip_address).map(d => String(d.ip_address));
    return { ips, ok: ips.length > 0 };
  }
  const dev = devices.find(d => d.id === ref);
  return { ips: dev?.ip_address ? [String(dev.ip_address)] : [], ok: !!dev?.ip_address };
}

/** Builds an nftables address match for one or more IPs (anonymous set if >1). */
function addrExpr(dir, ips) {
  const v4 = ips.filter(ip => !ip.includes(':'));
  const v6 = ips.filter(ip => ip.includes(':'));
  const fam = v4.length ? { p: 'ip', list: v4 } : { p: 'ip6', list: v6 };
  if (!fam.list.length) return '';
  return fam.list.length === 1
    ? `${fam.p} ${dir} ${fam.list[0]}`
    : `${fam.p} ${dir} { ${fam.list.join(', ')} }`;
}

/** L7 (App-ID / URL category) matches are enforced via DNS, not nftables/WFP. */
function isLayer7(rule) {
  return (!!rule.app_id && rule.app_id !== 'any') || (!!rule.url_category && rule.url_category !== 'any');
}

function emitNftRules(rules, devices) {
  const out = [];
  for (const rule of rules) {
    if (isLayer7(rule)) {
      out.push(`    # "${rule.name}": App-ID/URL match enforced via DNS filtering`);
      continue;
    }
    const s = resolveRef(rule.src_device, devices);
    const d = resolveRef(rule.dst_device, devices);
    if (!s.ok || !d.ok) {
      out.push(`    # Skipped "${rule.name}": device/group has no member with a known IP yet`);
      continue;
    }
    out.push(`    ${compileRule(rule, s.ips, d.ips)}  # ${rule.name}`);
  }
  return out;
}

/**
 * Compiles firewall policies into an nftables ruleset.
 *
 * Safety properties:
 * - Only touches `table inet homeshield` — never flushes the global ruleset.
 * - The whole script is applied atomically by `nft -f`.
 * - Device-ID matches are resolved against `devices` at compile time.
 */
export function compileNftables(policies, devices = []) {
  const enabled = policies
    .filter(p => p.enabled)
    .sort((a, b) => a.priority - b.priority);

  const lines = [
    '#!/usr/sbin/nft -f',
    '# HomeShield NGFW - Generated ruleset',
    `# Generated: ${new Date().toISOString()}`,
    `# Rules: ${enabled.length}`,
    '',
    '# Replace only the HomeShield table; leave the rest of the ruleset alone.',
    'table inet homeshield',
    'delete table inet homeshield',
    '',
    'table inet homeshield {',
    '',
    '  # Input chain - inbound traffic to this host',
    '  chain input {',
    '    type filter hook input priority 0; policy drop;',
    '    ct state established,related accept',
    '    iif lo accept',
    '    ct state invalid drop',
    '    # Essential ICMP/ICMPv6 (ping, path MTU, neighbor discovery)',
    '    meta l4proto { icmp, ipv6-icmp } accept',
    ...emitNftRules(enabled.filter(r => r.direction === 'inbound'), devices),
    '  }',
    '',
    '  # Output chain - outbound traffic from this host',
    '  chain output {',
    '    type filter hook output priority 0; policy accept;',
    ...emitNftRules(enabled.filter(r => r.direction === 'outbound'), devices),
    '  }',
    '',
    '  # Forward chain - transit traffic (gateway mode)',
    '  chain forward {',
    '    type filter hook forward priority 0; policy drop;',
    '    ct state established,related accept',
    '    ct state invalid drop',
    ...emitNftRules(enabled.filter(r => r.direction === 'forward'), devices),
    '  }',
    '',
    '  # NAT chain',
    '  chain postrouting {',
    '    type nat hook postrouting priority 100;',
    '  }',
    '',
    '}',
  ];

  return lines.join('\n');
}

function isIpv6(value) {
  return value.includes(':');
}

// srcIps / dstIps: resolved device/group IPs, or null when not device-constrained
// (in which case the rule's own src_ip / dst_ip is used).
function compileRule(rule, srcIps, dstIps) {
  const parts = [];

  if (rule.interface && rule.interface !== 'any') {
    const hook = rule.direction === 'outbound' ? 'oif' : 'iif';
    parts.push(`${hook} "${rule.interface}"`);
  }

  if (srcIps !== null) {
    const e = addrExpr('saddr', srcIps);
    if (e) parts.push(e);
  } else if (rule.src_ip && rule.src_ip !== 'any') {
    parts.push(`${isIpv6(rule.src_ip) ? 'ip6' : 'ip'} saddr ${rule.src_ip}`);
  }

  if (dstIps !== null) {
    const e = addrExpr('daddr', dstIps);
    if (e) parts.push(e);
  } else if (rule.dst_ip && rule.dst_ip !== 'any') {
    parts.push(`${isIpv6(rule.dst_ip) ? 'ip6' : 'ip'} daddr ${rule.dst_ip}`);
  }

  const hasPorts = rule.protocol === 'tcp' || rule.protocol === 'udp';

  if (hasPorts && rule.src_port && rule.src_port !== 'any') {
    parts.push(`${rule.protocol} sport ${rule.src_port}`);
  }

  if (hasPorts && rule.dst_port && rule.dst_port !== 'any') {
    parts.push(`${rule.protocol} dport ${rule.dst_port}`);
  }

  // Protocol match without ports (or icmp): match on the L4 protocol header.
  if (rule.protocol !== 'any' && !parts.some(p => p.startsWith(`${rule.protocol} `))) {
    if (rule.protocol === 'icmp') {
      parts.push('meta l4proto { icmp, ipv6-icmp }');
    } else {
      parts.push(`meta l4proto ${rule.protocol}`);
    }
  }

  if (rule.log_enabled) {
    parts.push(`log prefix "hs-${rule.action}: "`);
  }

  parts.push(actionToVerdict(rule));

  return parts.join(' ');
}

function actionToVerdict(rule) {
  switch (rule.action) {
    case 'allow': return 'counter accept';
    case 'deny': return 'counter drop';
    case 'reject':
      return rule.protocol === 'tcp'
        ? 'counter reject with tcp reset'
        : 'counter reject with icmpx type port-unreachable';
    case 'log-only': return 'counter';
    default: return 'counter drop';
  }
}

/**
 * Compiles firewall policies into a PowerShell script for Windows Firewall.
 *
 * Notes:
 * - Windows Firewall has no "reject" or "log-only" per-rule semantics:
 *   reject is mapped to Block; log-only rules are skipped with a comment.
 * - The agent runs *on* the device, so the rule already only affects that host;
 *   we do NOT pin -LocalAddress to the device IP (that would be IPv4-only and
 *   break on a DHCP change). Only the remote peer is constrained.
 * - Device-ID matches are resolved against `devices` at compile time.
 */
export function compileWindowsFirewall(policies, devices = []) {
  const enabled = policies
    .filter(p => p.enabled)
    .filter(p => p.direction !== 'forward')
    .sort((a, b) => a.priority - b.priority);

  const lines = [
    '# HomeShield NGFW - Windows Firewall Rules (PowerShell)',
    `# Generated: ${new Date().toISOString()}`,
    `# Rules: ${enabled.length}`,
    '',
    '# Remove existing HomeShield rules',
    'Get-NetFirewallRule -DisplayName "HomeShield-*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule',
    '',
  ];

  const winAddr = (ips, fallback) => {
    if (ips !== null) return ips.length ? ips.join(',') : null;
    return fallback && fallback !== 'any' ? fallback : null;
  };

  for (const rule of enabled) {
    if (rule.action === 'log-only') {
      lines.push(`# Skipped "${psEscape(rule.name)}": log-only rules are not supported by Windows Firewall`, '');
      continue;
    }
    if (isLayer7(rule)) {
      lines.push(`# "${psEscape(rule.name)}": App-ID/URL match enforced via DNS filtering`, '');
      continue;
    }
    const s = resolveRef(rule.src_device, devices);
    const d = resolveRef(rule.dst_device, devices);
    if (!s.ok || !d.ok) {
      lines.push(`# Skipped "${psEscape(rule.name)}": device/group has no member with a known IP yet`, '');
      continue;
    }

    const outbound = rule.direction === 'outbound';
    const dir = outbound ? 'Outbound' : 'Inbound';
    const action = rule.action === 'allow' ? 'Allow' : 'Block';
    const hasPorts = rule.protocol === 'tcp' || rule.protocol === 'udp';
    const proto = rule.protocol === 'any' ? 'Any' : rule.protocol.toUpperCase();

    let cmd = `New-NetFirewallRule -DisplayName "HomeShield-${psEscape(rule.name)}" \`\n`;
    cmd += `  -Direction ${dir} -Action ${action} -Protocol ${proto} \`\n`;

    // Only the remote peer is constrained (see note above — no -LocalAddress).
    const remoteIp = outbound ? winAddr(d.ips, rule.dst_ip) : winAddr(s.ips, rule.src_ip);
    if (remoteIp) cmd += `  -RemoteAddress "${remoteIp}" \`\n`;

    if (hasPorts) {
      const remotePort = outbound ? rule.dst_port : rule.src_port;
      const localPort = outbound ? rule.src_port : rule.dst_port;
      if (remotePort && remotePort !== 'any') cmd += `  -RemotePort "${remotePort}" \`\n`;
      if (localPort && localPort !== 'any') cmd += `  -LocalPort "${localPort}" \`\n`;
    }

    if (rule.interface && rule.interface !== 'any') cmd += `  -InterfaceAlias "${psEscape(rule.interface)}" \`\n`;

    cmd += `  -Description "HomeShield-managed: ${psEscape(rule.description)}"`;
    lines.push(cmd, '');
  }

  return lines.join('\n');
}

function psEscape(value) {
  return (value || '').replace(/[`"$]/g, '');
}

export function validatePolicies(policies, devices = []) {
  const errors = [];

  for (const p of policies) {
    if (!p.name.trim()) errors.push(`Rule ${p.id}: name is required`);
    if (!['allow', 'deny', 'reject', 'log-only'].includes(p.action)) {
      errors.push(`Rule "${p.name}": invalid action "${p.action}"`);
    }
    if (!['inbound', 'outbound', 'forward'].includes(p.direction)) {
      errors.push(`Rule "${p.name}": invalid direction "${p.direction}"`);
    }
    if (p.src_ip !== 'any' && !isValidIpOrCidr(p.src_ip)) {
      errors.push(`Rule "${p.name}": invalid source IP "${p.src_ip}"`);
    }
    if (p.dst_ip !== 'any' && !isValidIpOrCidr(p.dst_ip)) {
      errors.push(`Rule "${p.name}": invalid destination IP "${p.dst_ip}"`);
    }

    for (const [field, ref] of [['source', p.src_device], ['destination', p.dst_device]]) {
      if (!ref || ref === 'any') continue;
      if (ref.startsWith('tag:')) {
        const tag = ref.slice(4);
        const members = devices.filter(d => (d.tags || []).includes(tag));
        if (!members.length) errors.push(`Rule "${p.name}": ${field} group "${tag}" has no enrolled devices`);
        else if (!members.some(d => d.ip_address)) errors.push(`Rule "${p.name}": ${field} group "${tag}" has no member with a known IP yet`);
      } else {
        const dev = devices.find(d => d.id === ref);
        if (!dev) errors.push(`Rule "${p.name}": ${field} device is no longer enrolled`);
        else if (!dev.ip_address) errors.push(`Rule "${p.name}": ${field} device "${dev.hostname || ref}" has no known IP yet`);
      }
    }

    const hasPorts = (p.src_port && p.src_port !== 'any') || (p.dst_port && p.dst_port !== 'any');
    if (hasPorts && !['tcp', 'udp'].includes(p.protocol)) {
      errors.push(`Rule "${p.name}": ports require protocol tcp or udp`);
    }
    if (p.src_port !== 'any' && p.src_port && !isValidPort(p.src_port)) {
      errors.push(`Rule "${p.name}": invalid source port "${p.src_port}"`);
    }
    if (p.dst_port !== 'any' && p.dst_port && !isValidPort(p.dst_port)) {
      errors.push(`Rule "${p.name}": invalid destination port "${p.dst_port}"`);
    }
  }

  return errors;
}

function isValidPort(value) {
  const match = value.match(/^(\d{1,5})(?:-(\d{1,5}))?$/);
  if (!match) return false;
  const lo = parseInt(match[1], 10);
  const hi = match[2] ? parseInt(match[2], 10) : lo;
  return lo >= 1 && lo <= 65535 && hi >= 1 && hi <= 65535 && lo <= hi;
}

function isValidIpOrCidr(value) {
  const v4 = value.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/);
  if (v4) {
    const octets = [v4[1], v4[2], v4[3], v4[4]].map(o => parseInt(o, 10));
    if (octets.some(o => o > 255)) return false;
    if (v4[5] !== undefined && parseInt(v4[5], 10) > 32) return false;
    return true;
  }
  const v6 = value.match(/^([0-9a-fA-F:]+)(?:\/(\d{1,3}))?$/);
  if (v6 && v6[1].includes(':')) {
    if (v6[2] !== undefined && parseInt(v6[2], 10) > 128) return false;
    return true;
  }
  return false;
}
