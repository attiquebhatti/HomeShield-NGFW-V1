/**
 * Suricata IDS/IPS helpers for the HomeShield agent.
 *
 * IPS mode runs Suricata inline via NFQUEUE: the agent installs a separate
 * nftables table (`homeshield_ips`) whose chains hand packets to a netfilter
 * queue that Suricata reads, returning an accept/drop verdict per packet.
 * Suricata's alert log (eve.json) is tailed and ingested into ids_alerts in
 * both IDS and IPS modes.
 *
 * Pure, side-effect-free functions only — unit tested in ips.test.mjs.
 */

/** Suricata signature priority → our severity enum. 1 is most severe. */
function mapSeverity(sev) {
  switch (sev) {
    case 1: return 'high';
    case 2: return 'medium';
    case 3: return 'low';
    default: return 'low';
  }
}

/** Suricata alert.action → ids_alerts.action enum. */
function mapAction(action) {
  if (action === 'blocked') return 'drop';
  if (action === 'pass') return 'pass';
  return 'alert';
}

function toMysqlTimestamp(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString().slice(0, 19).replace('T', ' ');
}

/** Parses an eve.json line to an object, or null if it isn't JSON. */
export function parseEveLine(line) {
  const trimmed = String(line).trim();
  if (!trimmed || trimmed[0] !== '{') return null;
  try {
    return JSON.parse(trimmed);
  } catch {
    return null;
  }
}

/**
 * Parses one line of Suricata eve.json into an ids_alerts row.
 * Returns null for non-JSON lines and any event_type other than "alert".
 */
export function parseEveAlert(line) {
  const event = parseEveLine(line);
  return event ? mapAlertEvent(event) : null;
}

/** Maps a parsed eve "alert" event to an ids_alerts row, or null. */
export function mapAlertEvent(event) {
  if (!event || event.event_type !== 'alert' || !event.alert) return null;

  const a = event.alert;
  const payload = event.payload_printable || '';

  return {
    timestamp: toMysqlTimestamp(event.timestamp),
    severity: mapSeverity(a.severity),
    signature_id: a.signature_id ?? null,
    signature_name: a.signature || 'Unknown signature',
    category: a.category || '',
    src_ip: event.src_ip || null,
    dst_ip: event.dest_ip || null,
    src_port: event.src_port ?? null,
    dst_port: event.dest_port ?? null,
    protocol: event.proto ? String(event.proto).toLowerCase() : null,
    interface: event.in_iface || '',
    payload_preview: payload.slice(0, 500),
    action: mapAction(a.action),
  };
}

/**
 * Builds the nftables table that hands traffic to Suricata's NFQUEUE.
 *
 * Safety:
 * - `bypass` makes the queue fail-OPEN: if Suricata isn't listening, packets
 *   are accepted rather than dropped, so a Suricata crash never kills
 *   connectivity. Pass failOpen=false for fail-closed (stricter, riskier).
 * - Chain policy is accept; only Suricata's verdict drops packets.
 * - This is a separate table at priority 10, so it runs after (and never
 *   conflicts with) the `homeshield` filter table at priority 0. Replacing it
 *   is idempotent via the create/delete/create preamble.
 */
export function buildIpsTable(queueNum = 0, failOpen = true) {
  const q = Number.isInteger(queueNum) && queueNum >= 0 ? queueNum : 0;
  const verdict = `counter queue num ${q}${failOpen ? ' bypass' : ''}`;
  return [
    '#!/usr/sbin/nft -f',
    '# HomeShield NGFW - Suricata IPS NFQUEUE hook',
    `# Queue: ${q}  fail-${failOpen ? 'open' : 'closed'}`,
    '',
    'table inet homeshield_ips',
    'delete table inet homeshield_ips',
    '',
    'table inet homeshield_ips {',
    '  chain input {',
    '    type filter hook input priority 10; policy accept;',
    '    iif lo accept',
    `    ${verdict}`,
    '  }',
    '  chain output {',
    '    type filter hook output priority 10; policy accept;',
    '    oif lo accept',
    `    ${verdict}`,
    '  }',
    '  chain forward {',
    '    type filter hook forward priority 10; policy accept;',
    `    ${verdict}`,
    '  }',
    '}',
    '',
  ].join('\n');
}
