import type { FirewallPolicy } from './database.types';

/**
 * Compiles firewall policies into an nftables ruleset.
 *
 * Safety properties:
 * - Only touches `table inet homeshield` — never flushes the global ruleset,
 *   so rules from Docker, libvirt, fail2ban etc. are preserved.
 * - The whole script is applied atomically by `nft -f`.
 */
export function compileNftables(policies: FirewallPolicy[]): string {
  const enabled = policies
    .filter(p => p.enabled)
    .sort((a, b) => a.priority - b.priority);

  const lines: string[] = [
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
  ];

  for (const rule of enabled.filter(r => r.direction === 'inbound')) {
    lines.push(`    ${compileRule(rule)}  # ${rule.name}`);
  }

  lines.push(
    '  }',
    '',
    '  # Output chain - outbound traffic from this host',
    '  chain output {',
    '    type filter hook output priority 0; policy accept;',
  );

  for (const rule of enabled.filter(r => r.direction === 'outbound')) {
    lines.push(`    ${compileRule(rule)}  # ${rule.name}`);
  }

  lines.push(
    '  }',
    '',
    '  # Forward chain - transit traffic (gateway mode)',
    '  chain forward {',
    '    type filter hook forward priority 0; policy drop;',
    '    ct state established,related accept',
    '    ct state invalid drop',
  );

  for (const rule of enabled.filter(r => r.direction === 'forward')) {
    lines.push(`    ${compileRule(rule)}  # ${rule.name}`);
  }

  lines.push(
    '  }',
    '',
    '  # NAT chain',
    '  chain postrouting {',
    '    type nat hook postrouting priority 100;',
    '  }',
    '',
    '}',
  );

  return lines.join('\n');
}

function isIpv6(value: string): boolean {
  return value.includes(':');
}

function compileRule(rule: FirewallPolicy): string {
  const parts: string[] = [];

  if (rule.interface && rule.interface !== 'any') {
    const hook = rule.direction === 'outbound' ? 'oif' : 'iif';
    parts.push(`${hook} "${rule.interface}"`);
  }

  if (rule.src_ip && rule.src_ip !== 'any') {
    parts.push(`${isIpv6(rule.src_ip) ? 'ip6' : 'ip'} saddr ${rule.src_ip}`);
  }

  if (rule.dst_ip && rule.dst_ip !== 'any') {
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

function actionToVerdict(rule: FirewallPolicy): string {
  switch (rule.action) {
    case 'allow': return 'counter accept';
    case 'deny': return 'counter drop';
    case 'reject':
      // TCP gets a clean RST; everything else an ICMP(v6)-agnostic unreachable.
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
 * - Port parameters are only valid for TCP/UDP, and remote vs local
 *   address/port mapping depends on rule direction.
 */
export function compileWindowsFirewall(policies: FirewallPolicy[]): string {
  const enabled = policies
    .filter(p => p.enabled)
    .filter(p => p.direction !== 'forward')
    .sort((a, b) => a.priority - b.priority);

  const lines: string[] = [
    '# HomeShield NGFW - Windows Firewall Rules (PowerShell)',
    `# Generated: ${new Date().toISOString()}`,
    `# Rules: ${enabled.length}`,
    '',
    '# Remove existing HomeShield rules',
    'Get-NetFirewallRule -DisplayName "HomeShield-*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule',
    '',
  ];

  for (const rule of enabled) {
    if (rule.action === 'log-only') {
      lines.push(`# Skipped "${psEscape(rule.name)}": log-only rules are not supported by Windows Firewall`, '');
      continue;
    }

    const outbound = rule.direction === 'outbound';
    const dir = outbound ? 'Outbound' : 'Inbound';
    const action = rule.action === 'allow' ? 'Allow' : 'Block';
    const hasPorts = rule.protocol === 'tcp' || rule.protocol === 'udp';
    const proto = rule.protocol === 'any' ? 'Any' : rule.protocol.toUpperCase();

    let cmd = `New-NetFirewallRule -DisplayName "HomeShield-${psEscape(rule.name)}" \`\n`;
    cmd += `  -Direction ${dir} -Action ${action} -Protocol ${proto} \`\n`;

    // Inbound: remote = source, local = destination. Outbound: remote = destination.
    const remoteIp = outbound ? rule.dst_ip : rule.src_ip;
    const localIp = outbound ? rule.src_ip : rule.dst_ip;
    if (remoteIp && remoteIp !== 'any') cmd += `  -RemoteAddress "${remoteIp}" \`\n`;
    if (localIp && localIp !== 'any') cmd += `  -LocalAddress "${localIp}" \`\n`;

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

function psEscape(value: string): string {
  return (value || '').replace(/[`"$]/g, '');
}

export function validatePolicies(policies: FirewallPolicy[]): string[] {
  const errors: string[] = [];

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

function isValidPort(value: string): boolean {
  // Single port (443) or range (8000-8080)
  const match = value.match(/^(\d{1,5})(?:-(\d{1,5}))?$/);
  if (!match) return false;
  const lo = parseInt(match[1], 10);
  const hi = match[2] ? parseInt(match[2], 10) : lo;
  return lo >= 1 && lo <= 65535 && hi >= 1 && hi <= 65535 && lo <= hi;
}

function isValidIpOrCidr(value: string): boolean {
  const v4 = value.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/);
  if (v4) {
    const octets = [v4[1], v4[2], v4[3], v4[4]].map(o => parseInt(o, 10));
    if (octets.some(o => o > 255)) return false;
    if (v4[5] !== undefined && parseInt(v4[5], 10) > 32) return false;
    return true;
  }
  // IPv6 (loose): hex groups with at least one colon, optional /prefix
  const v6 = value.match(/^([0-9a-fA-F:]+)(?:\/(\d{1,3}))?$/);
  if (v6 && v6[1].includes(':')) {
    if (v6[2] !== undefined && parseInt(v6[2], 10) > 128) return false;
    return true;
  }
  return false;
}
