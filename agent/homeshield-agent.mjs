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
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import os from 'node:os';

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

async function sendTelemetry() {
  const [interfaces, health] = await Promise.all([collectInterfaces(), collectHealth()]);
  await api('/telemetry', {
    method: 'POST',
    body: JSON.stringify({ interfaces, health }),
  });
}

// ─── Main loop ─────────────────────────────────────────────────────────────

async function main() {
  await mkdir(STATE_DIR, { recursive: true });
  log(`HomeShield agent started — API ${API}, state dir ${STATE_DIR}`);

  let lastTelemetry = 0;

  for (;;) {
    try {
      const job = await api('/job?os=linux');
      if (job) await handleJob(job);
    } catch (e) {
      log('Poll error:', e.message);
    }

    if (Date.now() - lastTelemetry > TELEMETRY_SECONDS * 1000) {
      try {
        await sendTelemetry();
        lastTelemetry = Date.now();
      } catch (e) {
        log('Telemetry error:', e.message);
      }
    }

    await sleep(POLL_SECONDS * 1000);
  }
}

main().catch((e) => {
  console.error('Fatal:', e);
  process.exit(1);
});
