import { describe, it, expect } from 'vitest';
import { parseKernelLogLine, parseConntrack, splitJournalOutput } from './parsers.mjs';

describe('parseKernelLogLine', () => {
  const inboundDeny =
    '2026-06-12T22:10:01+0500 fw kernel: hs-deny: IN=eth0 OUT= ' +
    'MAC=aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:08:00 SRC=192.168.1.50 DST=192.168.1.10 ' +
    'LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=51514 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0';

  it('parses an inbound deny line', () => {
    const row = parseKernelLogLine(inboundDeny);
    expect(row).toMatchObject({
      action: 'deny',
      direction: 'inbound',
      src_ip: '192.168.1.50',
      dst_ip: '192.168.1.10',
      src_port: 51514,
      dst_port: 22,
      protocol: 'tcp',
      interface: 'eth0',
      bytes: 60,
    });
    expect(row.timestamp).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
  });

  it('classifies direction from IN/OUT fields', () => {
    const outbound = parseKernelLogLine('kernel: hs-allow: IN= OUT=eth0 SRC=10.0.0.1 DST=1.1.1.1 PROTO=UDP SPT=5353 DPT=53');
    expect(outbound.direction).toBe('outbound');
    expect(outbound.interface).toBe('eth0');

    const forward = parseKernelLogLine('kernel: hs-deny: IN=lan0 OUT=wan0 SRC=10.0.0.5 DST=8.8.8.8 PROTO=TCP SPT=1024 DPT=443');
    expect(forward.direction).toBe('forward');
  });

  it('handles ICMP lines without ports', () => {
    const row = parseKernelLogLine('kernel: hs-deny: IN=eth0 OUT= SRC=10.0.0.9 DST=10.0.0.1 PROTO=ICMP TYPE=8 CODE=0');
    expect(row.protocol).toBe('icmp');
    expect(row.src_port).toBeNull();
    expect(row.dst_port).toBeNull();
  });

  it('returns null for non-HomeShield lines', () => {
    expect(parseKernelLogLine('kernel: martian source 255.255.255.255')).toBeNull();
    expect(parseKernelLogLine('kernel: [UFW BLOCK] IN=eth0 SRC=1.2.3.4')).toBeNull();
  });
});

describe('parseConntrack', () => {
  it('parses a tcp entry with accounting', () => {
    const text =
      'ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.10 dst=142.250.74.36 sport=51514 dport=443 ' +
      'packets=12 bytes=2100 src=142.250.74.36 dst=192.168.1.10 sport=443 dport=51514 packets=10 bytes=8400 ' +
      '[ASSURED] mark=0 zone=0 use=2';
    const sessions = parseConntrack(text);
    expect(sessions).toHaveLength(1);
    expect(sessions[0]).toMatchObject({
      src_ip: '192.168.1.10',
      dst_ip: '142.250.74.36',
      src_port: 51514,
      dst_port: 443,
      protocol: 'tcp',
      state: 'established',
      bytes_out: 2100,
      bytes_in: 8400,
      packets_out: 12,
      packets_in: 10,
    });
  });

  it('parses a udp entry without a state token or accounting', () => {
    const text =
      'ipv4     2 udp      17 29 src=192.168.1.10 dst=192.168.1.1 sport=58234 dport=53 ' +
      '[UNREPLIED] src=192.168.1.1 dst=192.168.1.10 sport=53 dport=58234 mark=0 use=1';
    const sessions = parseConntrack(text);
    expect(sessions).toHaveLength(1);
    expect(sessions[0]).toMatchObject({
      protocol: 'udp',
      src_ip: '192.168.1.10',
      dst_port: 53,
      bytes_in: 0,
      bytes_out: 0,
    });
  });

  it('skips malformed lines', () => {
    expect(parseConntrack('garbage\n\nipv4 2')).toEqual([]);
  });
});

describe('splitJournalOutput', () => {
  it('separates log lines from the cursor', () => {
    const output = [
      'kernel: hs-deny: IN=eth0 OUT= SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP SPT=1 DPT=2',
      'kernel: unrelated line',
      '-- cursor: s=abc123;i=42;b=def',
      '',
    ].join('\n');
    const { lines, cursor } = splitJournalOutput(output);
    expect(lines).toHaveLength(2);
    expect(cursor).toBe('s=abc123;i=42;b=def');
  });

  it('returns null cursor when absent', () => {
    expect(splitJournalOutput('just a line').cursor).toBeNull();
  });
});
