import { describe, it, expect } from 'vitest';
import { parseEveAlert, buildIpsTable } from './ips.mjs';

const ALERT_LINE = JSON.stringify({
  timestamp: '2026-06-13T01:30:00.123456+0000',
  flow_id: 12345,
  in_iface: 'eth0',
  event_type: 'alert',
  src_ip: '45.9.148.2',
  src_port: 443,
  dest_ip: '192.168.1.20',
  dest_port: 51000,
  proto: 'TCP',
  alert: {
    action: 'blocked',
    gid: 1,
    signature_id: 2013028,
    rev: 5,
    signature: 'ET MALWARE Cobalt Strike Beacon Observed',
    category: 'A Network Trojan was Detected',
    severity: 1,
  },
  payload_printable: 'GET /malware HTTP/1.1\r\nHost: evil.example\r\n',
});

describe('parseEveAlert', () => {
  it('maps an inline-blocked alert to a drop row', () => {
    const row = parseEveAlert(ALERT_LINE);
    expect(row).toMatchObject({
      severity: 'high',
      signature_id: 2013028,
      signature_name: 'ET MALWARE Cobalt Strike Beacon Observed',
      category: 'A Network Trojan was Detected',
      src_ip: '45.9.148.2',
      dst_ip: '192.168.1.20',
      src_port: 443,
      dst_port: 51000,
      protocol: 'tcp',
      interface: 'eth0',
      action: 'drop',
    });
    expect(row.timestamp).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
    expect(row.payload_preview).toContain('GET /malware');
  });

  it('maps allowed alerts (IDS mode) to the alert action', () => {
    const row = parseEveAlert(ALERT_LINE.replace('"blocked"', '"allowed"'));
    expect(row.action).toBe('alert');
  });

  it('maps severities 1/2/3 to high/medium/low', () => {
    const sev = (n) => parseEveAlert(ALERT_LINE.replace('"severity":1', `"severity":${n}`)).severity;
    expect(sev(1)).toBe('high');
    expect(sev(2)).toBe('medium');
    expect(sev(3)).toBe('low');
  });

  it('truncates long payloads to 500 chars', () => {
    const big = JSON.parse(ALERT_LINE);
    big.payload_printable = 'x'.repeat(2000);
    expect(parseEveAlert(JSON.stringify(big)).payload_preview.length).toBe(500);
  });

  it('ignores non-alert events and non-JSON lines', () => {
    expect(parseEveAlert(JSON.stringify({ event_type: 'dns', dns: {} }))).toBeNull();
    expect(parseEveAlert(JSON.stringify({ event_type: 'stats' }))).toBeNull();
    expect(parseEveAlert('not json')).toBeNull();
    expect(parseEveAlert('')).toBeNull();
  });
});

describe('buildIpsTable', () => {
  it('builds a fail-open queue hook by default', () => {
    const out = buildIpsTable(0);
    expect(out).toContain('table inet homeshield_ips');
    expect(out).toContain('queue num 0 bypass');
    // idempotent replace, never flushes the global ruleset
    expect(out).toContain('delete table inet homeshield_ips');
    expect(out).not.toContain('flush ruleset');
    // runs after the filter table
    expect(out).toContain('priority 10');
  });

  it('omits bypass when fail-closed', () => {
    const out = buildIpsTable(2, false);
    expect(out).toContain('queue num 2');
    expect(out).not.toContain('bypass');
  });

  it('hooks input, output and forward, sparing loopback', () => {
    const out = buildIpsTable();
    expect(out).toContain('hook input');
    expect(out).toContain('hook output');
    expect(out).toContain('hook forward');
    expect(out).toContain('iif lo accept');
  });

  it('falls back to queue 0 for invalid queue numbers', () => {
    expect(buildIpsTable(-1)).toContain('queue num 0');
    expect(buildIpsTable('x')).toContain('queue num 0');
  });
});
