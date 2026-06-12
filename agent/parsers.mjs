/**
 * Pure parsing functions for the HomeShield agent.
 * Kept dependency-free and side-effect-free so they can be unit tested.
 */

const PROTO_NAMES = { 1: 'icmp', 6: 'tcp', 17: 'udp', 58: 'icmpv6' };

/**
 * Parses one kernel log line produced by an nftables `log prefix "hs-..."`
 * statement into a firewall_logs row, or returns null for non-HomeShield lines.
 *
 * Example input (journalctl -k -o short-iso):
 *   2026-06-12T22:10:01+0500 fw kernel: hs-deny: IN=eth0 OUT= MAC=... SRC=192.168.1.50
 *   DST=192.168.1.10 LEN=60 ... PROTO=TCP SPT=51514 DPT=22 WINDOW=64240 ...
 */
export function parseKernelLogLine(line) {
  const match = line.match(/hs-(allow|deny|reject|log-only):\s+(.*)$/);
  if (!match) return null;

  const action = match[1];
  const rest = match[2];

  const fields = {};
  for (const token of rest.split(/\s+/)) {
    const eq = token.indexOf('=');
    if (eq > 0) fields[token.slice(0, eq)] = token.slice(eq + 1);
  }

  const inIf = fields.IN || '';
  const outIf = fields.OUT || '';
  const direction = inIf && outIf ? 'forward' : inIf ? 'inbound' : 'outbound';

  // Timestamp from short-iso format at the start of the line, if present.
  const tsMatch = line.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4})/);

  return {
    timestamp: tsMatch ? new Date(tsMatch[1]).toISOString().slice(0, 19).replace('T', ' ') : null,
    action,
    direction,
    src_ip: fields.SRC || null,
    dst_ip: fields.DST || null,
    src_port: fields.SPT ? parseInt(fields.SPT, 10) : null,
    dst_port: fields.DPT ? parseInt(fields.DPT, 10) : null,
    protocol: fields.PROTO ? fields.PROTO.toLowerCase() : null,
    interface: inIf || outIf || null,
    bytes: fields.LEN ? parseInt(fields.LEN, 10) : 0,
    packets: 1,
    note: '',
  };
}

/**
 * Parses /proc/net/nf_conntrack into session rows.
 *
 * Line shapes (packets/bytes only appear when nf_conntrack_acct=1):
 *   ipv4 2 tcp 6 431999 ESTABLISHED src=A dst=B sport=1 dport=2 packets=N bytes=N
 *     src=B dst=A sport=2 dport=1 packets=N bytes=N [ASSURED] mark=0 use=1
 *   ipv4 2 udp 17 29 src=A dst=B sport=1 dport=2 [UNREPLIED] src=B dst=A ...
 */
export function parseConntrack(text) {
  const sessions = [];

  for (const line of text.split('\n')) {
    const tokens = line.trim().split(/\s+/);
    if (tokens.length < 6) continue;

    const protocol = tokens[2];
    if (!['tcp', 'udp', 'icmp', 'icmpv6'].includes(protocol)) continue;

    // For TCP the token after the timeout is the state; UDP/ICMP go straight
    // to key=value pairs.
    const firstKv = tokens.findIndex(t => t.includes('='));
    if (firstKv < 0) continue;
    const state = firstKv > 5 ? tokens[5] : protocol === 'udp' ? 'unreplied' : 'active';

    // Origin tuple = first src/dst/... group, reply tuple = second.
    const origin = {};
    const reply = {};
    let target = origin;
    for (const token of tokens.slice(firstKv)) {
      const eq = token.indexOf('=');
      if (eq <= 0) continue;
      const key = token.slice(0, eq);
      const value = token.slice(eq + 1);
      if (key === 'src' && target.src !== undefined) target = reply;
      if (target[key] === undefined) target[key] = value;
    }

    if (!origin.src || !origin.dst) continue;

    sessions.push({
      src_ip: origin.src,
      dst_ip: origin.dst,
      src_port: origin.sport ? parseInt(origin.sport, 10) : null,
      dst_port: origin.dport ? parseInt(origin.dport, 10) : null,
      protocol,
      state: state.toLowerCase(),
      bytes_out: origin.bytes ? parseInt(origin.bytes, 10) : 0,
      bytes_in: reply.bytes ? parseInt(reply.bytes, 10) : 0,
      packets_out: origin.packets ? parseInt(origin.packets, 10) : 0,
      packets_in: reply.packets ? parseInt(reply.packets, 10) : 0,
      interface: '',
      application: '',
    });
  }

  return sessions;
}

/**
 * Extracts the journal cursor from `journalctl --show-cursor` output and
 * returns { lines, cursor }. The cursor line looks like:
 *   -- cursor: s=abc123;i=42;...
 */
export function splitJournalOutput(output) {
  const lines = [];
  let cursor = null;
  for (const line of output.split('\n')) {
    const m = line.match(/^--\s*cursor:\s*(\S.*)$/);
    if (m) {
      cursor = m[1].trim();
    } else if (line.trim()) {
      lines.push(line);
    }
  }
  return { lines, cursor };
}
