import type { FirewallPolicy } from './database.types';

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
    'flush ruleset',
    '',
    'table inet homeshield {',
    '',
    '  # Input chain - inbound traffic to this host',
    '  chain input {',
    '    type filter hook input priority 0; policy drop;',
    '    ct state established,related accept',
    '    iif lo accept',
    '    ct state invalid drop',
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

function compileRule(rule: FirewallPolicy): string {
  const parts: string[] = [];

  if (rule.interface && rule.interface !== 'any') {
    const hook = rule.direction === 'inbound' ? 'iif' : 'oif';
    parts.push(`${hook} "${rule.interface}"`);
  }

  if (rule.protocol !== 'any') {
    parts.push(rule.protocol);
  }

  if (rule.src_ip && rule.src_ip !== 'any') {
    parts.push(`ip saddr ${rule.src_ip}`);
  }

  if (rule.dst_ip && rule.dst_ip !== 'any') {
    parts.push(`ip daddr ${rule.dst_ip}`);
  }

  if (rule.src_port && rule.src_port !== 'any' && rule.protocol !== 'icmp') {
    parts.push(`sport ${rule.src_port}`);
  }

  if (rule.dst_port && rule.dst_port !== 'any' && rule.protocol !== 'icmp') {
    parts.push(`dport ${rule.dst_port}`);
  }

  if (rule.log_enabled) {
    parts.push(`log prefix "hs-${rule.action}: "`);
  }

  parts.push(actionToVerdict(rule.action));

  if (parts.length === 1) return parts[0];
  return parts.join(' ');
}

function actionToVerdict(action: string): string {
  switch (action) {
    case 'allow': return 'counter accept';
    case 'deny': return 'counter drop';
    case 'reject': return 'counter reject with icmp port-unreachable';
    case 'log-only': return 'counter';
    default: return 'drop';
  }
}

export function compileWindowsFirewall(policies: FirewallPolicy[]): string {
  const enabled = policies
    .filter(p => p.enabled)
    .sort((a, b) => a.priority - b.priority);

  const lines: string[] = [
    '# HomeShield NGFW - Windows Firewall Rules (PowerShell)',
    `# Generated: ${new Date().toISOString()}`,
    `# Rules: ${enabled.length}`,
    '',
    '# Remove existing HomeShield rules',
    'Get-NetFirewallRule -DisplayName "HomeShield-*" | Remove-NetFirewallRule',
    '',
  ];

  for (const rule of enabled) {
    const dir = rule.direction === 'outbound' ? 'Outbound' : 'Inbound';
    const action = rule.action === 'allow' ? 'Allow' : 'Block';
    const proto = rule.protocol === 'any' ? 'Any' : rule.protocol.toUpperCase();

    let cmd = `New-NetFirewallRule -DisplayName "HomeShield-${rule.name.replace(/"/g, '')}" \`\n`;
    cmd += `  -Direction ${dir} -Action ${action} -Protocol ${proto} \`\n`;

    if (rule.src_ip !== 'any') cmd += `  -RemoteAddress "${rule.src_ip}" \`\n`;
    if (rule.dst_port !== 'any') cmd += `  -LocalPort "${rule.dst_port}" \`\n`;
    if (rule.interface !== 'any') cmd += `  -InterfaceAlias "${rule.interface}" \`\n`;

    cmd += `  -Description "HomeShield-managed: ${rule.description}"`;
    lines.push(cmd, '');
  }

  return lines.join('\n');
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
  }

  return errors;
}

function isValidIpOrCidr(value: string): boolean {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
  const ipv6 = /^[0-9a-fA-F:]+$/;
  return ipv4.test(value) || ipv6.test(value);
}
