#!/usr/bin/env node
/**
 * HomeShield NGFW — Linux enforcement agent
 *
 * Runs as root on the machine being protected. Polls the management API for
 * pending rule-apply jobs, applies them atomically with nftables, and
 * enforces the commit-confirm rollback timer: if the operator does not
 * confirm the new ruleset in the UI within the timer, the agent restores the
 * previous ruleset. It also reports interface inventory and system health.
 *
 * Requirements: Node 18+, nftables (`nft`), iproute2 (`ip`), root privileges.
 *
 * Configuration (environment variables):
 *   HOMESHIELD_API   Management API base URL   (default http://127.0.0.1:3000)
 *   AGENT_TOKEN      Shared secret, must match the server's AGENT_TOKEN (required)
 *   STATE_DIR        Where backups/rulesets are kept (default /var/lib/homeshield)
 *   POLL_SECONDS     Job poll interval          (default 5)
 *   TELEMETRY_SECONDS Telemetry interval        (default 60)
 *   DNS_PORT         DNS proxy listen port      (default 53)
 *   DNS_REFRESH_SECONDS  DNS/IPS config refresh (default 30)
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, writeFile, readFile, stat as statFile, open as openFile } from 'node:fs/promises';
import { join } from 'node:path';
import os from 'node:os';
import dgram from 'node:dgram';
import { parseKernelLogLine, parseConntrack, splitJournalOutput } from './parsers.mjs';
import { parseQuery, buildBlockResponse, createMatcher, sinkholeAddress } from './dns.mjs';
import { parseEveLine, mapAlertEvent, buildIpsTable } from './ips.mjs';
import { classifyApp, isIdentified, appFlowFromEvent } from './appid.mjs';
import { buildThreatTable, splitByFamily } from './threats.mjs';
import { buildServerConfig, buildVpnNatTable, parseWgDump } from './wg.mjs';
import { parseZoneFile, buildGeoTable } from './geoip.mjs';

const exec = promisify(execFile);

const API = (process.env.HOMESHIELD_API || 'http://127.0.0.1:3000').replace(/\/$/, '');
const TOKEN = process.env.AGENT_TOKEN || '';
const STATE_DIR = process.env.STATE_DIR || '/var/lib/homeshield';
const POLL_SECONDS = parseInt(process.env.POLL_SECONDS || '5', 10);
const TELEMETRY_SECONDS = parseInt(process.env.TELEMETRY_SECONDS || '60', 10);

if (!TOKEN) {
  console.error('AGENT_TOKEN is required');
  process.exit(1);
}

const log = (...args) => console.log(new Date().toISOString(), ...args);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function api(path, options = {}) {
  const res = await fetch(`${API}/api/agent${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'X-Agent-Token': TOKEN,
      ...options.headers,
    },
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(json.error || `HTTP ${res.status} on ${path}`);
  return json.data ?? json;
}

// ─── nftables operations ─────────────────────────────────────────────────

async function backupRuleset(jobId) {
  const { stdout } = await exec('nft', ['list', 'ruleset']);
  const file = join(STATE_DIR, `backup-${jobId}.nft`);
  await writeFile(file, stdout, 'utf8');
  return file;
}

async function applyRuleset(jobId, compiled) {
  const file = join(STATE_DIR, `apply-${jobId}.nft`);
  await writeFile(file, compiled, 'utf8');
  await exec('nft', ['-c', '-f', file]); // dry-run validation first
  await exec('nft', ['-f', file]);       // atomic apply
  return file;
}

async function restoreRuleset(backupFile) {
  const backup = await readFile(backupFile, 'utf8');
  // The backup is a full ruleset dump, so flush-then-load restores exactly
  // the pre-apply state (including non-HomeShield tables).
  const restoreFile = backupFile.replace('backup-', 'restore-');
  await writeFile(restoreFile, `flush ruleset\n${backup}`, 'utf8');
  await exec('nft', ['-f', restoreFile]);
}

// ─── Job handling ──────────────────────────────────────────────────────────

async function reportResult(jobId, status, errorMessage = '') {
  await api(`/job/${jobId}/result`, {
    method: 'POST',
    body: JSON.stringify({ status, error_message: errorMessage }),
  });
}

async function handleJob(job) {
  log(`Applying job ${job.id} (${job.rules_count} rules, rollback timer ${job.rollback_timer_seconds}s)`);

  let backupFile;
  try {
    backupFile = await backupRuleset(job.id);
  } catch (e) {
    log('Backup failed, refusing to apply:', e.message);
    await reportResult(job.id, 'failed', `backup failed: ${e.message}`);
    return;
  }

  try {
    await applyRuleset(job.id, job.compiled_output || '');
  } catch (e) {
    const msg = (e.stderr || e.message || '').trim();
    log('Apply failed:', msg);
    await reportResult(job.id, 'failed', msg.slice(0, 2000));
    return;
  }

  await reportResult(job.id, 'applied');
  log(`Job ${job.id} applied — waiting for confirmation`);

  // Commit-confirm: wait for the operator to confirm in the UI. If the timer
  // expires (e.g. the new rules locked them out), restore the old ruleset.
  const timerMs = (job.rollback_timer_seconds || 30) * 1000;
  const deadline = Date.now() + timerMs + 10_000; // grace for clock/poll skew

  while (Date.now() < deadline) {
    await sleep(2000);
    let status;
    try {
      status = (await api(`/job/${job.id}`)).status;
    } catch (e) {
      // API unreachable — keep waiting; the timeout below is the safety net.
      continue;
    }
    if (status === 'confirmed') {
      log(`Job ${job.id} confirmed — keeping new ruleset`);
      return;
    }
    if (status === 'rolled_back' || status === 'failed') break;
  }

  log(`Job ${job.id} not confirmed — restoring previous ruleset`);
  try {
    await restoreRuleset(backupFile);
    await reportResult(job.id, 'rolled_back');
    log(`Job ${job.id} rolled back successfully`);
  } catch (e) {
    log('ROLLBACK FAILED:', e.message);
    await reportResult(job.id, 'failed', `rollback failed: ${e.message}`).catch(() => {});
  }
}

// ─── Telemetry ─────────────────────────────────────────────────────────────

async function readStat(dev, stat) {
  try {
    return parseInt(await readFile(`/sys/class/net/${dev}/statistics/${stat}`, 'utf8'), 10) || 0;
  } catch {
    return 0;
  }
}

async function collectInterfaces() {
  const { stdout } = await exec('ip', ['-j', 'addr']);
  const links = JSON.parse(stdout);
  const interfaces = [];
  for (const link of links) {
    const v4 = (link.addr_info || []).find((a) => a.family === 'inet');
    interfaces.push({
      name: link.ifname,
      display_name: link.ifname,
      role: link.ifname === 'lo' ? 'unassigned' : 'unassigned',
      ip_address: v4 ? `${v4.local}` : '',
      netmask: v4 ? `/${v4.prefixlen}` : '',
      mac_address: link.address || '',
      mtu: link.mtu || 1500,
      status: link.operstate === 'UP' ? 'up' : link.operstate === 'DOWN' ? 'down' : 'unknown',
      rx_bytes: await readStat(link.ifname, 'rx_bytes'),
      tx_bytes: await readStat(link.ifname, 'tx_bytes'),
    });
  }
  return interfaces;
}

async function collectHealth() {
  const [l1, l5, l15] = os.loadavg();
  const total = os.totalmem();
  const free = os.freemem();
  let disk = { percent: 0, usedGb: 0, totalGb: 0 };
  try {
    const { stdout } = await exec('df', ['-k', '/']);
    const fields = stdout.trim().split('\n').pop().split(/\s+/);
    const totalKb = parseInt(fields[1], 10);
    const usedKb = parseInt(fields[2], 10);
    disk = {
      percent: totalKb ? (usedKb / totalKb) * 100 : 0,
      usedGb: usedKb / 1048576,
      totalGb: totalKb / 1048576,
    };
  } catch {}
  return {
    cpu_percent: Math.min(100, (l1 / os.cpus().length) * 100),
    ram_percent: ((total - free) / total) * 100,
    ram_used_mb: (total - free) / 1048576,
    ram_total_mb: total / 1048576,
    disk_percent: disk.percent,
    disk_used_gb: disk.usedGb,
    disk_total_gb: disk.totalGb,
    load_avg_1m: l1,
    load_avg_5m: l5,
    load_avg_15m: l15,
    services: { agent: 'running' },
  };
}

async function collectSessions() {
  try {
    const text = await readFile('/proc/net/nf_conntrack', 'utf8');
    // Cap to keep payloads and the sessions table bounded.
    return parseConntrack(text).slice(0, 500);
  } catch {
    // conntrack not available (module not loaded, or not running as root)
    return null;
  }
}

async function sendTelemetry() {
  const [interfaces, health, sessions] = await Promise.all([
    collectInterfaces(),
    collectHealth(),
    collectSessions(),
  ]);
  await api('/telemetry', {
    method: 'POST',
    body: JSON.stringify({ interfaces, health, sessions }),
  });
}

// ─── Firewall log ingestion ────────────────────────────────────────────────
// Rules compiled with logging enabled emit kernel log lines prefixed with
// "hs-<action>: ". We follow the kernel journal with a persisted cursor so
// no entries are lost across agent restarts.

const CURSOR_FILE = join(STATE_DIR, 'journal.cursor');
let journalCursor = null;
let journalAvailable = true;

async function loadCursor() {
  try {
    journalCursor = (await readFile(CURSOR_FILE, 'utf8')).trim() || null;
  } catch {
    journalCursor = null;
  }
}

async function collectFirewallLogs() {
  if (!journalAvailable) return;

  const args = ['-k', '--no-pager', '--show-cursor', '-o', 'short-iso'];
  if (journalCursor) {
    args.push('--after-cursor', journalCursor);
  } else {
    args.push('--since', '-2 minutes');
  }

  let stdout;
  try {
    ({ stdout } = await exec('journalctl', args, { maxBuffer: 16 * 1024 * 1024 }));
  } catch (e) {
    if (/ENOENT/.test(e.message)) {
      journalAvailable = false;
      log('journalctl not found — firewall log ingestion disabled');
      return;
    }
    throw e;
  }

  const { lines, cursor } = splitJournalOutput(stdout);
  const logs = lines.map(parseKernelLogLine).filter(Boolean);

  // Batch to keep request sizes sane under log floods.
  for (let i = 0; i < logs.length; i += 500) {
    await api('/firewall-logs', {
      method: 'POST',
      body: JSON.stringify({ logs: logs.slice(i, i + 500) }),
    });
  }
  if (logs.length) log(`Ingested ${logs.length} firewall log entries`);

  if (cursor) {
    journalCursor = cursor;
    await writeFile(CURSOR_FILE, cursor, 'utf8');
  }
}

// ─── DNS filtering proxy ───────────────────────────────────────────────────
// A UDP DNS proxy controlled by the dns_filtering_enabled system setting.
// Blocked domains are sinkholed (0.0.0.0 / :: / NXDOMAIN); everything else
// is forwarded to the upstream resolver. Query logs are batched to the API.

const DNS_PORT = parseInt(process.env.DNS_PORT || '53', 10);
const DNS_REFRESH_SECONDS = parseInt(process.env.DNS_REFRESH_SECONDS || '30', 10);

let dnsSocket = null;
let dnsMatcher = createMatcher([]);
let dnsUpstream = '1.1.1.1';
let dnsLogBuffer = [];

function pushDnsLog(entry) {
  dnsLogBuffer.push(entry);
  if (dnsLogBuffer.length > 5000) dnsLogBuffer = dnsLogBuffer.slice(-5000);
}

function forwardDnsQuery(msg, rinfo) {
  const upstreamSocket = dgram.createSocket('udp4');
  const timer = setTimeout(() => upstreamSocket.close(), 5000);
  upstreamSocket.on('message', (response) => {
    clearTimeout(timer);
    upstreamSocket.close();
    if (dnsSocket) dnsSocket.send(response, rinfo.port, rinfo.address);
  });
  upstreamSocket.on('error', () => {
    clearTimeout(timer);
    try { upstreamSocket.close(); } catch {}
  });
  upstreamSocket.send(msg, 53, dnsUpstream);
}

function handleDnsQuery(msg, rinfo) {
  const parsed = parseQuery(msg);
  if (!parsed) {
    forwardDnsQuery(msg, rinfo); // not something we understand — pass through
    return;
  }

  const verdict = dnsMatcher(parsed.domain);
  if (verdict.action === 'blocked') {
    dnsSocket.send(buildBlockResponse(msg, parsed), rinfo.port, rinfo.address);
  } else {
    forwardDnsQuery(msg, rinfo);
  }

  pushDnsLog({
    domain: parsed.domain,
    client_ip: rinfo.address,
    action: verdict.action,
    matched_list: verdict.matched_list,
    category: verdict.category,
    response_ip: verdict.action === 'blocked' ? sinkholeAddress(parsed.qtype) : '',
    query_type: parsed.qtypeName,
  });

  // Application identification from the resolved domain (standalone signal,
  // no Suricata required). Only record concrete apps to avoid log flooding.
  if (appidEnabled && verdict.action !== 'blocked') {
    const { application, category } = classifyApp(parsed.domain);
    if (isIdentified(application)) {
      pushAppFlow({
        client_ip: rinfo.address,
        application,
        category,
        hostname: parsed.domain,
        protocol: 'udp',
        app_proto: 'dns',
        source: 'dns',
        bytes: 0,
      });
    }
  }
}

function startDnsProxy() {
  if (dnsSocket) return;
  const socket = dgram.createSocket('udp4');
  socket.on('message', handleDnsQuery);
  socket.on('error', (e) => {
    log('DNS proxy error:', e.message);
    try { socket.close(); } catch {}
    if (dnsSocket === socket) dnsSocket = null;
  });
  socket.bind(DNS_PORT, () => log(`DNS filtering proxy listening on udp/${DNS_PORT} (upstream ${dnsUpstream})`));
  dnsSocket = socket;
}

function stopDnsProxy() {
  if (!dnsSocket) return;
  try { dnsSocket.close(); } catch {}
  dnsSocket = null;
  log('DNS filtering proxy stopped');
}

async function refreshDnsConfig() {
  const config = await api('/dns-config');
  dnsUpstream = config.upstream || '1.1.1.1';
  dnsMatcher = createMatcher(config.entries || []);
  appidEnabled = config.appid_enabled !== false;
  if (config.enabled && !dnsSocket) startDnsProxy();
  if (!config.enabled && dnsSocket) stopDnsProxy();
}

async function flushDnsLogs() {
  while (dnsLogBuffer.length) {
    const batch = dnsLogBuffer.slice(0, 500);
    await api('/dns-logs', { method: 'POST', body: JSON.stringify({ logs: batch }) });
    dnsLogBuffer = dnsLogBuffer.slice(batch.length);
  }
}

// ─── Application identification ────────────────────────────────────────────
// app_flows are produced from two sources: the DNS proxy above (domain-based)
// and Suricata eve.json tls/quic/http/flow events (SNI/host + protocol). Both
// feed one buffer, flushed in batches.

let appidEnabled = true;
let appFlowBuffer = [];

function pushAppFlow(flow) {
  appFlowBuffer.push(flow);
  if (appFlowBuffer.length > 5000) appFlowBuffer = appFlowBuffer.slice(-5000);
}

async function flushAppFlows() {
  while (appFlowBuffer.length) {
    const batch = appFlowBuffer.slice(0, 500);
    await api('/app-flows', { method: 'POST', body: JSON.stringify({ flows: batch }) });
    appFlowBuffer = appFlowBuffer.slice(batch.length);
  }
}

// ─── Suricata IDS/IPS ──────────────────────────────────────────────────────
// IPS mode: install an nftables NFQUEUE hook (homeshield_ips table) so
// Suricata can drop packets inline. The hook is fail-open (bypass), so if
// Suricata is down, traffic flows. Both modes tail eve.json into ids_alerts.

let ipsMode = 'off';          // 'off' | 'ids' | 'ips'
let ipsQueueNum = 0;
let prevIpsMode = 'off';
let evePath = '/var/log/suricata/eve.json';

async function applyIpsHook() {
  const file = join(STATE_DIR, 'ips-hook.nft');
  await writeFile(file, buildIpsTable(ipsQueueNum, true), 'utf8');
  await exec('nft', ['-f', file]);
}

async function removeIpsHook() {
  try {
    await exec('nft', ['delete', 'table', 'inet', 'homeshield_ips']);
  } catch {
    // table may not exist — nothing to remove
  }
}

async function refreshIpsConfig() {
  const config = await api('/ips-config');
  ipsMode = config.mode || 'off';
  ipsQueueNum = Number.isInteger(config.queue_num) ? config.queue_num : 0;
  evePath = config.eve_path || '/var/log/suricata/eve.json';

  if (ipsMode === 'ips') {
    // Re-assert every cycle so the hook self-heals after a ruleset rollback
    // (which flushes the global ruleset) restores it within one interval.
    await applyIpsHook();
  } else if (prevIpsMode === 'ips') {
    await removeIpsHook();
    log('IPS NFQUEUE hook removed');
  }

  if (ipsMode !== prevIpsMode) log(`Suricata mode: ${ipsMode}`);
  prevIpsMode = ipsMode;
}

// Incremental eve.json tail with a persisted byte offset. Handles log
// rotation/truncation by resetting to 0 when the file shrinks.
const EVE_OFFSET_FILE = join(STATE_DIR, 'eve.offset');
let eveOffset = 0;

async function loadEveOffset() {
  try {
    eveOffset = parseInt(await readFile(EVE_OFFSET_FILE, 'utf8'), 10) || 0;
  } catch {
    eveOffset = 0;
  }
}

async function readNewLines(path, fromOffset) {
  const handle = await openFile(path, 'r');
  try {
    const { size } = await handle.stat();
    let start = fromOffset;
    if (size < fromOffset) start = 0; // rotated or truncated
    if (size === start) return { lines: [], newOffset: size };

    const length = size - start;
    const buf = Buffer.alloc(length);
    await handle.read(buf, 0, length, start);

    // Only consume up to the last complete line; leave a partial line for next time.
    const lastNl = buf.lastIndexOf(0x0a);
    if (lastNl < 0) return { lines: [], newOffset: start };
    const text = buf.toString('utf8', 0, lastNl);
    return { lines: text.split('\n'), newOffset: start + lastNl + 1 };
  } finally {
    await handle.close();
  }
}

// Tails eve.json once and dispatches each event to alerts (ids_alerts) and/or
// application flows (app_flows), depending on event type and enabled features.
async function collectEveEvents() {
  if (ipsMode === 'off' && !appidEnabled) return;
  try {
    await statFile(evePath);
  } catch {
    return; // Suricata not writing eve.json (yet)
  }

  const { lines, newOffset } = await readNewLines(evePath, eveOffset);

  const alerts = [];
  for (const line of lines) {
    const event = parseEveLine(line);
    if (!event) continue;

    if (ipsMode !== 'off' && event.event_type === 'alert') {
      const row = mapAlertEvent(event);
      if (row) alerts.push(row);
    } else if (appidEnabled) {
      const flow = appFlowFromEvent(event);
      if (flow) pushAppFlow(flow);
    }
  }

  for (let i = 0; i < alerts.length; i += 500) {
    await api('/ids-alerts', {
      method: 'POST',
      body: JSON.stringify({ alerts: alerts.slice(i, i + 500) }),
    });
  }
  if (alerts.length) log(`Ingested ${alerts.length} IDS/IPS alerts`);

  if (newOffset !== eveOffset) {
    eveOffset = newOffset;
    await writeFile(EVE_OFFSET_FILE, String(eveOffset), 'utf8');
  }
}

// ─── Threat intelligence blocking ──────────────────────────────────────────
// Pulls active IP/CIDR indicators and compiles them into an nftables set that
// drops bad traffic before policy evaluation (priority -10). Re-asserted each
// cycle so it self-heals after a ruleset rollback flushes the global ruleset.

let threatTableActive = false;

async function removeThreatTable() {
  try {
    await exec('nft', ['delete', 'table', 'inet', 'homeshield_threats']);
  } catch {
    // not present
  }
}

async function refreshThreatSet() {
  const { values } = await api('/threat-set');
  const { v4, v6 } = splitByFamily(values || []);
  const script = buildThreatTable(v4, v6);

  if (!script) {
    if (threatTableActive) {
      await removeThreatTable();
      threatTableActive = false;
      log('Threat blocklist cleared');
    }
    return;
  }

  const file = join(STATE_DIR, 'threats.nft');
  await writeFile(file, script, 'utf8');
  await exec('nft', ['-f', file]);
  if (!threatTableActive) log(`Threat blocklist active: ${v4.length} IPv4, ${v6.length} IPv6`);
  threatTableActive = true;
}

// ─── GeoIP filtering ───────────────────────────────────────────────────────
// Downloads per-country CIDR zone files and compiles them into an nftables set
// (homeshield_geo). Zones are cached and only re-downloaded when the country
// selection changes or the cache goes stale; the table is re-applied only when
// the data or mode changes, or when it's missing (self-heal after a rollback).

const GEO_REFRESH_MS = (parseInt(process.env.GEO_REFRESH_HOURS || '12', 10)) * 3600 * 1000;
let geoCidrs = { v4: [], v6: [] };
let geoFetchKey = '';
let geoFetchedAt = 0;
let geoAppliedSig = '';
let geoTableActive = false;

async function fetchZone(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30000);
  try {
    const resp = await fetch(url, { signal: controller.signal, headers: { 'User-Agent': 'HomeShield-NGFW/1.0' } });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return parseZoneFile(await resp.text());
  } finally {
    clearTimeout(timer);
  }
}

async function fetchGeoCidrs(config) {
  const v4 = [];
  const v6 = [];
  for (const cc of config.countries) {
    const code = cc.toLowerCase();
    if (config.source_v4) {
      try { v4.push(...await fetchZone(config.source_v4.replace('{cc}', code))); }
      catch (e) { log(`GeoIP: ${cc} v4 fetch failed: ${e.message}`); }
    }
    if (config.source_v6) {
      try { v6.push(...await fetchZone(config.source_v6.replace('{cc}', code))); }
      catch { /* many countries have no v6 zone — ignore */ }
    }
  }
  return { v4, v6 };
}

async function geoTableExists() {
  try { await exec('nft', ['list', 'table', 'inet', 'homeshield_geo']); return true; }
  catch { return false; }
}

async function removeGeoTable() {
  try { await exec('nft', ['delete', 'table', 'inet', 'homeshield_geo']); } catch {}
  geoTableActive = false;
}

async function refreshGeoConfig() {
  const config = await api('/geoip-config');

  if (!config.enabled || !config.countries?.length) {
    if (geoTableActive) { await removeGeoTable(); log('GeoIP filtering disabled'); }
    geoAppliedSig = '';
    return;
  }

  const key = config.countries.map(c => c.toLowerCase()).sort().join(',');
  if (key !== geoFetchKey || Date.now() - geoFetchedAt > GEO_REFRESH_MS) {
    geoCidrs = await fetchGeoCidrs(config);
    geoFetchKey = key;
    geoFetchedAt = Date.now();
  }

  const sig = `${config.mode}|${key}|${geoFetchedAt}`;
  const tableMissing = !(await geoTableExists());
  if (sig === geoAppliedSig && !tableMissing) return; // unchanged and present

  const script = buildGeoTable(config.mode, geoCidrs.v4, geoCidrs.v6);
  if (!script) { await removeGeoTable(); geoAppliedSig = ''; return; }

  const file = join(STATE_DIR, 'geoip.nft');
  await writeFile(file, script, 'utf8');
  await exec('nft', ['-f', file]);
  geoAppliedSig = sig;
  geoTableActive = true;
  log(`GeoIP ${config.mode}list applied: ${config.countries.length} countries, ${geoCidrs.v4.length} v4 / ${geoCidrs.v6.length} v6 nets`);
}

// ─── WireGuard VPN ─────────────────────────────────────────────────────────
// Applies the WireGuard server config and a masquerade table so clients reach
// the internet. Uses `wg syncconf` for live peer updates when the interface is
// already up, falling back to `wg-quick up`. Reports peer telemetry.

let vpnUp = false;
let vpnInterface = 'wg0';

async function wgInterfaceExists(iface) {
  try {
    await exec('wg', ['show', iface]);
    return true;
  } catch {
    return false;
  }
}

async function applyVpn(config) {
  vpnInterface = config.interface || 'wg0';
  const confPath = `/etc/wireguard/${vpnInterface}.conf`;
  const serverConfig = buildServerConfig(config, config.peers || []);
  await writeFile(confPath, serverConfig, { mode: 0o600 });

  // Enable IPv4 forwarding for routing client traffic.
  await exec('sysctl', ['-w', 'net.ipv4.ip_forward=1']).catch(() => {});

  if (await wgInterfaceExists(vpnInterface)) {
    // Live-update peers without dropping the tunnel.
    const { stdout } = await exec('wg-quick', ['strip', vpnInterface]);
    const stripped = join(STATE_DIR, `${vpnInterface}.stripped.conf`);
    await writeFile(stripped, stdout, { mode: 0o600 });
    await exec('wg', ['syncconf', vpnInterface, stripped]);
  } else {
    await exec('wg-quick', ['up', vpnInterface]);
  }

  // Masquerade so VPN clients can reach the internet.
  const natFile = join(STATE_DIR, 'vpn-nat.nft');
  await writeFile(natFile, buildVpnNatTable(config.address), 'utf8');
  await exec('nft', ['-f', natFile]);

  if (!vpnUp) log(`WireGuard up on ${vpnInterface} (${(config.peers || []).length} peers)`);
  vpnUp = true;
}

async function teardownVpn() {
  try { await exec('wg-quick', ['down', vpnInterface]); } catch {}
  try { await exec('nft', ['delete', 'table', 'inet', 'homeshield_vpn']); } catch {}
  vpnUp = false;
  log('WireGuard down');
}

async function refreshVpn() {
  const config = await api('/vpn-config');
  if (config.enabled) {
    await applyVpn(config);
  } else if (vpnUp) {
    await teardownVpn();
  }
}

async function sendVpnTelemetry() {
  if (!vpnUp) return;
  let stdout;
  try {
    ({ stdout } = await exec('wg', ['show', vpnInterface, 'dump']));
  } catch {
    return; // interface not present
  }
  const peers = parseWgDump(stdout);
  if (peers.length) {
    await api('/vpn-telemetry', { method: 'POST', body: JSON.stringify({ peers }) });
  }
}

// ─── Main loop ─────────────────────────────────────────────────────────────

async function main() {
  await mkdir(STATE_DIR, { recursive: true });
  await loadCursor();
  await loadEveOffset();
  log(`HomeShield agent started — API ${API}, state dir ${STATE_DIR}`);

  let lastTelemetry = 0;
  let lastConfigRefresh = 0;

  for (;;) {
    try {
      const job = await api('/job?os=linux');
      if (job) await handleJob(job);
    } catch (e) {
      log('Poll error:', e.message);
    }

    try {
      await collectFirewallLogs();
    } catch (e) {
      log('Log ingestion error:', e.message);
    }

    try {
      await collectEveEvents();
    } catch (e) {
      log('eve.json ingestion error:', e.message);
    }

    if (Date.now() - lastConfigRefresh > DNS_REFRESH_SECONDS * 1000) {
      try {
        await refreshDnsConfig();
      } catch (e) {
        log('DNS config refresh error:', e.message);
      }
      try {
        await refreshIpsConfig();
      } catch (e) {
        log('IPS config refresh error:', e.message);
      }
      try {
        await refreshThreatSet();
      } catch (e) {
        log('Threat set refresh error:', e.message);
      }
      try {
        await refreshVpn();
      } catch (e) {
        log('VPN refresh error:', e.message);
      }
      try {
        await refreshGeoConfig();
      } catch (e) {
        log('GeoIP refresh error:', e.message);
      }
      lastConfigRefresh = Date.now();
    }

    try {
      await flushDnsLogs();
    } catch (e) {
      log('DNS log flush error:', e.message);
    }

    try {
      await flushAppFlows();
    } catch (e) {
      log('App flow flush error:', e.message);
    }

    if (Date.now() - lastTelemetry > TELEMETRY_SECONDS * 1000) {
      try {
        await sendTelemetry();
        lastTelemetry = Date.now();
      } catch (e) {
        log('Telemetry error:', e.message);
      }
      try {
        await sendVpnTelemetry();
      } catch (e) {
        log('VPN telemetry error:', e.message);
      }
    }

    await sleep(POLL_SECONDS * 1000);
  }
}

main().catch((e) => {
  console.error('Fatal:', e);
  process.exit(1);
});
