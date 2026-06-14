import express from 'express';
import mysql from 'mysql2/promise';
import { createHmac, randomUUID, randomBytes, timingSafeEqual } from 'crypto';
import { existsSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';
import QRCode from 'qrcode';
import { parseFeed } from './feeds.mjs';
import { generateKeyPair, derivePublicKey, generatePresharedKey, nextPeerAddress, buildClientConfig } from './wireguard.mjs';
import { buildEnvelope, readEnvelope, sha256 } from './backup.mjs';
import { generateSecret, verifyTOTP, otpauthURL } from './totp.mjs';
import { renderPrometheus, groupSamples } from './metrics.mjs';
import { buildWindowsInstaller } from './ipsec.mjs';
import { buildWindowsBootstrap, buildWindowsCmd } from './bootstrap.mjs';
import { verifyGoogleIdToken } from './google.mjs';

const { hash, compare } = bcrypt;
const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '10mb' }));

// ─── CORS ──────────────────────────────────────────────────────────────────
// The UI is served same-origin from dist/, so CORS is disabled by default.
// Set CORS_ORIGIN (e.g. http://localhost:5173) for the Vite dev server.

const CORS_ORIGIN = process.env.CORS_ORIGIN || '';
if (CORS_ORIGIN) {
  app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', CORS_ORIGIN);
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Agent-Token');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
  });
}

// ─── DB ────────────────────────────────────────────────────────────────────

let pool;
function getPool() {
  if (!pool) {
    pool = mysql.createPool({
      host: process.env.DB_HOST || 'localhost',
      database: process.env.DB_NAME,
      user: process.env.DB_USER,
      password: process.env.DB_PASS,
      waitForConnections: true,
      connectionLimit: 10,
      charset: 'utf8mb4',
    });
  }
  return pool;
}

async function query(sql, params = []) {
  const [rows] = await getPool().execute(sql, params);
  return rows;
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function now() {
  return new Date().toISOString().slice(0, 19).replace('T', ' ');
}

function castRow(row) {
  const result = { ...row };
  for (const [k, v] of Object.entries(result)) {
    if (v instanceof Date) result[k] = v.toISOString();
    if (typeof v === 'string' && (v.startsWith('{') || v.startsWith('['))) {
      try { result[k] = JSON.parse(v); } catch {}
    }
  }
  return result;
}

function castRows(rows) { return rows.map(castRow); }

// Log full details server-side, return a generic message to the client.
function serverError(res, context, e) {
  console.error(`${context}:`, e);
  res.status(500).json({ error: 'Internal server error' });
}

// ─── JWT ───────────────────────────────────────────────────────────────────

let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET === 'changeme') {
  JWT_SECRET = randomBytes(32).toString('hex');
  console.warn('WARNING: JWT_SECRET not set — generated an ephemeral secret.');
  console.warn('All sessions will be invalidated on restart. Set JWT_SECRET in the environment.');
}

function b64u(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function jwtSign(payload) {
  const header = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64u(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + 86400 * 7 }));
  const sig = b64u(createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest());
  return `${header}.${body}.${sig}`;
}

function jwtVerify(token) {
  try {
    const [header, body, sig] = token.split('.');
    const expected = b64u(createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest());
    const sigBuf = Buffer.from(sig, 'base64');
    const expBuf = Buffer.from(expected, 'base64');
    if (sigBuf.length !== expBuf.length) return null;
    if (!timingSafeEqual(sigBuf, expBuf)) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64').toString());
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || '';
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match) return res.status(401).json({ error: 'Missing authorization token' });
  const payload = jwtVerify(match[1]);
  if (!payload) return res.status(401).json({ error: 'Invalid or expired token' });
  req.user = payload;
  next();
}

// ─── Rate limiting (auth endpoints) ────────────────────────────────────────

const RATE_WINDOW_MS = 15 * 60 * 1000;
const RATE_MAX_ATTEMPTS = 10;
const rateBuckets = new Map(); // ip -> { count, windowStart }

function authRateLimit(req, res, next) {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const nowMs = Date.now();
  let bucket = rateBuckets.get(ip);
  if (!bucket || nowMs - bucket.windowStart > RATE_WINDOW_MS) {
    bucket = { count: 0, windowStart: nowMs };
    rateBuckets.set(ip, bucket);
  }
  bucket.count++;
  if (bucket.count > RATE_MAX_ATTEMPTS) {
    return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  }
  // Opportunistic cleanup of stale buckets
  if (rateBuckets.size > 10000) {
    for (const [k, v] of rateBuckets) {
      if (nowMs - v.windowStart > RATE_WINDOW_MS) rateBuckets.delete(k);
    }
  }
  next();
}

// ─── Auto-migrate ─────────────────────────────────────────────────────────

async function autoMigrate() {
  try {
    const [rows] = await getPool().query(
      `SELECT COUNT(*) AS cnt FROM information_schema.tables WHERE table_schema = ? AND table_name = 'admin_users'`,
      [process.env.DB_NAME]
    );
    if (rows[0].cnt > 0) {
      console.log('Tables already exist — skipping migration');
      return;
    }
    console.log('Tables not found — running auto-migration...');
    const { readFileSync } = await import('fs');
    const schemaPath = join(__dirname, 'api', 'schema.sql');
    const schema = readFileSync(schemaPath, 'utf-8');
    const statements = schema
      .split(';')
      .map(s => s.trim())
      .filter(s => s.length > 0);
    for (const stmt of statements) {
      await getPool().query(stmt);
    }
    console.log('Auto-migration complete — all tables created');
  } catch (e) {
    console.error('Auto-migration failed:', e.message);
  }
}

// ─── Public routes (no auth) ───────────────────────────────────────────────

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, ts: new Date().toISOString() });
});

// ─── Prometheus metrics ──────────────────────────────────────────────────────
// Scrape endpoint at /metrics. If METRICS_TOKEN is set it must be supplied via
// ?token= or an Authorization: Bearer header; otherwise the endpoint is open
// (intended for a trusted LAN / localhost Prometheus).

const METRICS_TOKEN = process.env.METRICS_TOKEN || '';

async function collectMetricFamilies() {
  const one = async (sql, params = []) => Number((await query(sql, params))[0]?.c || 0);

  const [
    policies, dnsEntries, fwEvents, dnsQueries, idsAlerts, idsUnack,
    indicators, feeds, appFlows, vpnPeers, sessions, users, health, interfaces,
  ] = await Promise.all([
    query("SELECT IF(enabled=1,'enabled','disabled') AS k, COUNT(*) AS count FROM firewall_policies GROUP BY k"),
    query('SELECT list_type AS k, COUNT(*) AS count FROM dns_entries GROUP BY list_type'),
    query("SELECT action AS k, COUNT(*) AS count FROM firewall_logs WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR) GROUP BY action"),
    query("SELECT action AS k, COUNT(*) AS count FROM dns_logs WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR) GROUP BY action"),
    query("SELECT severity AS k, COUNT(*) AS count FROM ids_alerts WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR) GROUP BY severity"),
    one('SELECT COUNT(*) AS c FROM ids_alerts WHERE acknowledged = 0'),
    query('SELECT indicator_type AS k, COUNT(*) AS count FROM threat_indicators GROUP BY indicator_type'),
    query("SELECT IF(enabled=1,'enabled','disabled') AS k, COUNT(*) AS count FROM threat_feeds GROUP BY k"),
    query("SELECT category AS k, COUNT(*) AS count FROM app_flows WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR) GROUP BY category"),
    query("SELECT IF(enabled=1,'enabled','disabled') AS k, COUNT(*) AS count FROM vpn_peers GROUP BY k"),
    one('SELECT COUNT(*) AS c FROM sessions'),
    query('SELECT role AS k, COUNT(*) AS count FROM admin_users GROUP BY role'),
    query('SELECT cpu_percent, ram_percent, disk_percent FROM system_health_snapshots ORDER BY recorded_at DESC LIMIT 1'),
    query('SELECT name, rx_bytes, tx_bytes FROM network_interfaces'),
  ]);

  const families = [
    { name: 'homeshield_up', help: 'Management server is up', type: 'gauge', samples: [{ value: 1 }] },
    { name: 'homeshield_firewall_policies', help: 'Firewall policies by status', type: 'gauge', samples: groupSamples(policies, 'status') },
    { name: 'homeshield_dns_list_entries', help: 'DNS list entries by type', type: 'gauge', samples: groupSamples(dnsEntries, 'list_type') },
    { name: 'homeshield_firewall_events_24h', help: 'Firewall log events in the last 24h by action', type: 'gauge', samples: groupSamples(fwEvents, 'action') },
    { name: 'homeshield_dns_queries_24h', help: 'DNS queries in the last 24h by action', type: 'gauge', samples: groupSamples(dnsQueries, 'action') },
    { name: 'homeshield_ids_alerts_24h', help: 'IDS/IPS alerts in the last 24h by severity', type: 'gauge', samples: groupSamples(idsAlerts, 'severity') },
    { name: 'homeshield_ids_alerts_unacknowledged', help: 'Unacknowledged IDS/IPS alerts', type: 'gauge', samples: [{ value: idsUnack }] },
    { name: 'homeshield_threat_indicators', help: 'Threat indicators by type', type: 'gauge', samples: groupSamples(indicators, 'indicator_type') },
    { name: 'homeshield_threat_feeds', help: 'Threat feeds by status', type: 'gauge', samples: groupSamples(feeds, 'status') },
    { name: 'homeshield_app_flows_24h', help: 'Identified application flows in the last 24h by category', type: 'gauge', samples: groupSamples(appFlows, 'category') },
    { name: 'homeshield_vpn_peers', help: 'WireGuard peers by status', type: 'gauge', samples: groupSamples(vpnPeers, 'status') },
    { name: 'homeshield_sessions', help: 'Tracked connection sessions', type: 'gauge', samples: [{ value: sessions }] },
    { name: 'homeshield_users', help: 'Admin users by role', type: 'gauge', samples: groupSamples(users, 'role') },
  ];

  if (health.length) {
    families.push(
      { name: 'homeshield_cpu_percent', help: 'Latest CPU usage percent', type: 'gauge', samples: [{ value: health[0].cpu_percent }] },
      { name: 'homeshield_ram_percent', help: 'Latest RAM usage percent', type: 'gauge', samples: [{ value: health[0].ram_percent }] },
      { name: 'homeshield_disk_percent', help: 'Latest disk usage percent', type: 'gauge', samples: [{ value: health[0].disk_percent }] },
    );
  }
  if (interfaces.length) {
    families.push(
      { name: 'homeshield_interface_rx_bytes', help: 'Interface received bytes', type: 'counter', samples: interfaces.map(i => ({ value: i.rx_bytes, labels: { interface: i.name } })) },
      { name: 'homeshield_interface_tx_bytes', help: 'Interface transmitted bytes', type: 'counter', samples: interfaces.map(i => ({ value: i.tx_bytes, labels: { interface: i.name } })) },
    );
  }
  return families;
}

app.get('/metrics', async (req, res) => {
  if (METRICS_TOKEN) {
    const provided = req.query.token || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (provided !== METRICS_TOKEN) return res.status(401).send('Unauthorized');
  }
  try {
    const text = renderPrometheus(await collectMetricFamilies());
    res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    res.send(text);
  } catch (e) {
    console.error('metrics error:', e.message);
    res.status(500).send('# metrics collection failed\n');
  }
});

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';

async function anyUsersExist() {
  return (await query('SELECT id FROM admin_users LIMIT 1')).length > 0;
}
async function openSignupEnabled() {
  const rows = await query("SELECT value FROM system_settings WHERE `key` = 'open_signup_enabled' LIMIT 1");
  return rows[0]?.value !== 'false'; // default enabled
}

// Public auth config so the login page can adapt (first-run vs sign-up,
// Google button, whether self-signup is allowed).
app.get('/api/auth/config', async (_req, res) => {
  try {
    const firstRun = !(await anyUsersExist());
    res.json({
      data: {
        first_run: firstRun,
        open_signup: firstRun || (await openSignupEnabled()),
        google_client_id: GOOGLE_CLIENT_ID || null,
      },
    });
  } catch (e) {
    serverError(res, 'auth config', e);
  }
});

// Signup. The first account (first-run) is an admin; every later self-signup
// is a viewer (read-only). Admins promote roles from the Users page. Later
// signups require open_signup_enabled.
app.post('/api/auth/signup', authRateLimit, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password || password.length < 12)
      return res.status(400).json({ error: 'Password must be at least 12 characters' });

    const firstRun = !(await anyUsersExist());
    if (!firstRun && !(await openSignupEnabled()))
      return res.status(403).json({ error: 'Self-signup is disabled. Ask an admin to create your account.' });

    const exists = await query('SELECT id FROM admin_users WHERE email = ? LIMIT 1', [email]);
    if (exists.length) return res.status(409).json({ error: 'An account with that email already exists. Please sign in.' });

    const role = firstRun ? 'admin' : 'viewer';
    await query(
      'INSERT INTO admin_users (id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)',
      [randomUUID(), email, await hash(password, 12), role, now()]
    );
    res.json({ message: firstRun ? 'Admin account created. Please sign in.' : 'Account created. Please sign in.', role });
  } catch (e) {
    serverError(res, 'signup', e);
  }
});

// Sign in / up with a Google ID token (Google Identity Services). New users
// are created as viewer (or admin on first run); existing users sign in.
app.post('/api/auth/google', authRateLimit, async (req, res) => {
  try {
    if (!GOOGLE_CLIENT_ID) return res.status(503).json({ error: 'Google sign-in is not configured on this server' });
    const { credential } = req.body || {};
    if (!credential) return res.status(400).json({ error: 'Missing Google credential' });

    let profile;
    try {
      profile = await verifyGoogleIdToken(credential, GOOGLE_CLIENT_ID);
    } catch (e) {
      return res.status(401).json({ error: `Google sign-in failed: ${e.message}` });
    }

    let rows = await query('SELECT id, email, role, mfa_secret, mfa_enabled FROM admin_users WHERE email = ? LIMIT 1', [profile.email]);
    if (!rows.length) {
      const firstRun = !(await anyUsersExist());
      if (!firstRun && !(await openSignupEnabled()))
        return res.status(403).json({ error: 'Self-signup is disabled. Ask an admin to create your account.' });
      const id = randomUUID();
      // Google users authenticate via Google; set an unusable random password.
      await query(
        'INSERT INTO admin_users (id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)',
        [id, profile.email, await hash(randomBytes(24).toString('hex'), 12), firstRun ? 'admin' : 'viewer', now()]
      );
      rows = await query('SELECT id, email, role, mfa_secret, mfa_enabled FROM admin_users WHERE id = ? LIMIT 1', [id]);
    }

    // Honour MFA if the account has it enabled (Google alone isn't enough).
    if (rows[0].mfa_enabled) {
      const { code } = req.body || {};
      if (!code) return res.status(401).json({ error: 'MFA code required', mfa_required: true });
      if (!verifyTOTP(rows[0].mfa_secret, code)) return res.status(401).json({ error: 'Invalid MFA code', mfa_required: true });
    }

    const user = { id: rows[0].id, email: rows[0].email, role: rows[0].role || 'viewer' };
    res.json({ token: jwtSign(user), user });
  } catch (e) {
    serverError(res, 'google auth', e);
  }
});

app.post('/api/auth/login', authRateLimit, async (req, res) => {
  try {
    const { email, password, code } = req.body || {};
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required' });

    const rows = await query(
      'SELECT id, email, password_hash, role, mfa_secret, mfa_enabled FROM admin_users WHERE email = ? LIMIT 1', [email]
    );
    if (!rows.length || !(await compare(password, rows[0].password_hash)))
      return res.status(401).json({ error: 'Invalid email or password' });

    if (rows[0].mfa_enabled) {
      if (!code) return res.status(401).json({ error: 'MFA code required', mfa_required: true });
      if (!verifyTOTP(rows[0].mfa_secret, code))
        return res.status(401).json({ error: 'Invalid MFA code', mfa_required: true });
    }

    const user = { id: rows[0].id, email: rows[0].email, role: rows[0].role || 'admin' };
    res.json({ token: jwtSign(user), user });
  } catch (e) {
    serverError(res, 'login', e);
  }
});

// ─── Protected routes (require auth) ──────────────────────────────────────

const api = express.Router();
api.use(authMiddleware);

// Role-based access control. Enforced server-side (the real boundary):
//   - viewer:   read-only (GET), plus their own account/MFA endpoints
//   - operator: full config, but no user management
//   - admin:    everything
function roleGuard(req, res, next) {
  const role = req.user.role || 'admin';
  if (req.path.startsWith('/users') && role !== 'admin') {
    return res.status(403).json({ error: 'Admin role required' });
  }
  if (role === 'viewer' && req.method !== 'GET' && !req.path.startsWith('/auth/')) {
    return res.status(403).json({ error: 'Read-only role' });
  }
  next();
}
api.use(roleGuard);

api.get('/auth/me', async (req, res) => {
  try {
    const rows = await query('SELECT id, email, role, mfa_enabled FROM admin_users WHERE id = ? LIMIT 1', [req.user.id]);
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    res.json({ user: { id: rows[0].id, email: rows[0].email, role: rows[0].role || 'admin', mfa_enabled: !!rows[0].mfa_enabled } });
  } catch (e) {
    serverError(res, 'auth me', e);
  }
});

// ─── MFA (self-service for the current user) ────────────────────────────────

// Begin enrollment: generate a secret (stored but not yet enabled) and return
// the otpauth URL + QR for the authenticator app.
api.post('/auth/mfa/setup', async (req, res) => {
  try {
    const secret = generateSecret();
    await query('UPDATE admin_users SET mfa_secret = ?, mfa_enabled = 0 WHERE id = ?', [secret, req.user.id]);
    const url = otpauthURL({ secret, label: req.user.email, issuer: 'HomeShield' });
    const qr = await QRCode.toDataURL(url, { margin: 1, width: 240 });
    res.json({ data: { secret, otpauth: url, qr } });
  } catch (e) {
    serverError(res, 'mfa setup', e);
  }
});

// Confirm enrollment by verifying a code against the pending secret.
api.post('/auth/mfa/enable', async (req, res) => {
  try {
    const { code } = req.body || {};
    const rows = await query('SELECT mfa_secret FROM admin_users WHERE id = ? LIMIT 1', [req.user.id]);
    if (!rows[0]?.mfa_secret) return res.status(400).json({ error: 'Run MFA setup first' });
    if (!verifyTOTP(rows[0].mfa_secret, code)) return res.status(400).json({ error: 'Invalid code' });
    await query('UPDATE admin_users SET mfa_enabled = 1 WHERE id = ?', [req.user.id]);
    res.json({ data: { mfa_enabled: true } });
  } catch (e) {
    serverError(res, 'mfa enable', e);
  }
});

// Disable MFA (requires a valid current code to prove possession).
api.post('/auth/mfa/disable', async (req, res) => {
  try {
    const { code } = req.body || {};
    const rows = await query('SELECT mfa_secret, mfa_enabled FROM admin_users WHERE id = ? LIMIT 1', [req.user.id]);
    if (!rows[0]?.mfa_enabled) return res.json({ data: { mfa_enabled: false } });
    if (!verifyTOTP(rows[0].mfa_secret, code)) return res.status(400).json({ error: 'Invalid code' });
    await query("UPDATE admin_users SET mfa_enabled = 0, mfa_secret = '' WHERE id = ?", [req.user.id]);
    res.json({ data: { mfa_enabled: false } });
  } catch (e) {
    serverError(res, 'mfa disable', e);
  }
});

// ─── User management (admin only — gated by roleGuard) ──────────────────────

const ROLES = ['admin', 'operator', 'viewer'];

api.get('/users', async (_req, res) => {
  try {
    const rows = await query('SELECT id, email, role, mfa_enabled, created_at FROM admin_users ORDER BY created_at ASC');
    res.json({ data: castRows(rows), count: rows.length });
  } catch (e) {
    serverError(res, 'users list', e);
  }
});

api.post('/users', async (req, res) => {
  try {
    const { email, password, role } = req.body || {};
    if (!email || !password || password.length < 12)
      return res.status(400).json({ error: 'Email and a 12+ character password are required' });
    if (!ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });
    const existing = await query('SELECT id FROM admin_users WHERE email = ? LIMIT 1', [email]);
    if (existing.length) return res.status(409).json({ error: 'A user with that email already exists' });

    const id = randomUUID();
    await query(
      'INSERT INTO admin_users (id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)',
      [id, email, await hash(password, 12), role, now()]
    );
    await query(
      'INSERT INTO audit_log (id, timestamp, actor, action, resource_type, resource_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [randomUUID(), now(), req.user.email, 'user_create', 'user', id, JSON.stringify({ email, role }), req.ip || '']
    );
    res.status(201).json({ data: { id, email, role } });
  } catch (e) {
    serverError(res, 'users create', e);
  }
});

api.patch('/users/:id', async (req, res) => {
  try {
    const { role, password } = req.body || {};
    const target = await query('SELECT id, role FROM admin_users WHERE id = ? LIMIT 1', [req.params.id]);
    if (!target.length) return res.status(404).json({ error: 'User not found' });

    // Guard against removing the last admin.
    if (role && role !== 'admin' && target[0].role === 'admin') {
      const admins = await query("SELECT COUNT(*) AS c FROM admin_users WHERE role = 'admin'");
      if (admins[0].c <= 1) return res.status(409).json({ error: 'Cannot demote the last admin' });
    }

    const sets = [];
    const params = [];
    if (role) {
      if (!ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });
      sets.push('role = ?'); params.push(role);
    }
    if (password) {
      if (password.length < 12) return res.status(400).json({ error: 'Password must be 12+ characters' });
      sets.push('password_hash = ?'); params.push(await hash(password, 12));
    }
    if (!sets.length) return res.status(400).json({ error: 'Nothing to update' });
    await query(`UPDATE admin_users SET ${sets.join(', ')} WHERE id = ?`, [...params, req.params.id]);
    res.json({ data: { id: req.params.id } });
  } catch (e) {
    serverError(res, 'users update', e);
  }
});

api.delete('/users/:id', async (req, res) => {
  try {
    if (req.params.id === req.user.id) return res.status(409).json({ error: 'You cannot delete your own account' });
    const target = await query('SELECT role FROM admin_users WHERE id = ? LIMIT 1', [req.params.id]);
    if (!target.length) return res.status(404).json({ error: 'User not found' });
    if (target[0].role === 'admin') {
      const admins = await query("SELECT COUNT(*) AS c FROM admin_users WHERE role = 'admin'");
      if (admins[0].c <= 1) return res.status(409).json({ error: 'Cannot delete the last admin' });
    }
    await query('DELETE FROM admin_users WHERE id = ?', [req.params.id]);
    await query(
      'INSERT INTO audit_log (id, timestamp, actor, action, resource_type, resource_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [randomUUID(), now(), req.user.email, 'user_delete', 'user', req.params.id, '{}', req.ip || '']
    );
    res.json({ success: true });
  } catch (e) {
    serverError(res, 'users delete', e);
  }
});

// ─── CRUD config ──────────────────────────────────────────────────────────

const TABLE_MAP = {
  'firewall-policies': 'firewall_policies',
  'firewall-logs': 'firewall_logs',
  'dns-entries': 'dns_entries',
  'dns-logs': 'dns_logs',
  'ids-alerts': 'ids_alerts',
  'threat-feeds': 'threat_feeds',
  'threat-indicators': 'threat_indicators',
  'network-interfaces': 'network_interfaces',
  'nat-rules': 'nat_rules',
  'audit-log': 'audit_log',
  'sessions': 'sessions',
  'backup-records': 'backup_records',
  'rule-apply-history': 'rule_apply_history',
  'system-health': 'system_health_snapshots',
  'app-flows': 'app_flows',
};

const ORDER_MAP = {
  'firewall-policies': { col: 'priority', dir: 'ASC' },
  'firewall-logs': { col: 'timestamp', dir: 'DESC' },
  'dns-entries': { col: 'created_at', dir: 'DESC' },
  'dns-logs': { col: 'timestamp', dir: 'DESC' },
  'ids-alerts': { col: 'timestamp', dir: 'DESC' },
  'threat-feeds': { col: 'created_at', dir: 'DESC' },
  'network-interfaces': { col: 'name', dir: 'ASC' },
  'nat-rules': { col: 'priority', dir: 'ASC' },
  'audit-log': { col: 'timestamp', dir: 'DESC' },
  'sessions': { col: 'last_seen', dir: 'DESC' },
  'backup-records': { col: 'created_at', dir: 'DESC' },
  'rule-apply-history': { col: 'applied_at', dir: 'DESC' },
  'system-health': { col: 'recorded_at', dir: 'DESC' },
  'app-flows': { col: 'timestamp', dir: 'DESC' },
};

const SEARCH_COLS = {
  'firewall-policies': ['name', 'src_ip', 'dst_ip'],
  'firewall-logs': ['src_ip', 'dst_ip', 'policy_name'],
  'dns-entries': ['domain'],
  'dns-logs': ['domain', 'client_ip'],
  'ids-alerts': ['signature_name', 'src_ip', 'dst_ip'],
  'audit-log': ['actor', 'action', 'resource_type'],
  'sessions': ['src_ip', 'dst_ip', 'application'],
  'app-flows': ['application', 'hostname', 'client_ip'],
};

const FILTER_COLS = {
  'firewall-policies': ['action', 'enabled'],
  'firewall-logs': ['action', 'protocol'],
  'dns-entries': ['list_type'],
  'ids-alerts': ['severity', 'acknowledged'],
  'dns-logs': ['action'],
  'app-flows': ['application', 'category', 'source'],
};

const BOOL_FIELDS = {
  'firewall-policies': ['enabled', 'log_enabled'],
  'dns-entries': ['enabled'],
  'ids-alerts': ['acknowledged'],
  'threat-feeds': ['enabled'],
  'nat-rules': ['enabled'],
  'backup-records': ['encrypted'],
};

// Mass-assignment protection: only these columns may be written per resource.
// A resource missing from UPDATABLE_COLS cannot be updated at all.

const INSERTABLE_COLS = {
  'firewall-policies': ['name', 'description', 'enabled', 'action', 'direction', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'interface', 'schedule', 'tags', 'priority', 'log_enabled', 'updated_at'],
  'firewall-logs': ['timestamp', 'action', 'direction', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'interface', 'policy_id', 'policy_name', 'bytes', 'packets', 'note'],
  'dns-entries': ['domain', 'list_type', 'category', 'source', 'enabled', 'note'],
  'dns-logs': ['timestamp', 'domain', 'client_ip', 'action', 'matched_list', 'category', 'response_ip', 'query_type'],
  'ids-alerts': ['timestamp', 'severity', 'signature_id', 'signature_name', 'category', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'interface', 'payload_preview', 'action', 'acknowledged'],
  'threat-feeds': ['name', 'description', 'url', 'feed_type', 'enabled', 'last_updated', 'last_status', 'indicator_count', 'refresh_interval_hours'],
  'threat-indicators': ['feed_id', 'indicator_type', 'value', 'severity', 'description', 'expires_at'],
  'network-interfaces': ['name', 'display_name', 'role', 'ip_address', 'netmask', 'mac_address', 'mtu', 'status', 'rx_bytes', 'tx_bytes', 'updated_at'],
  'nat-rules': ['name', 'description', 'enabled', 'nat_type', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'translate_to_ip', 'translate_to_port', 'interface', 'priority', 'updated_at'],
  'audit-log': ['timestamp', 'actor', 'action', 'resource_type', 'resource_id', 'details', 'ip_address'],
  'sessions': ['started_at', 'last_seen', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'state', 'interface', 'bytes_in', 'bytes_out', 'packets_in', 'packets_out', 'application', 'policy_id'],
  'backup-records': ['created_by', 'label', 'description', 'trigger_type', 'size_bytes', 'encrypted', 'payload', 'checksum'],
  'rule-apply-history': ['applied_by', 'mode', 'os_target', 'rules_count', 'status', 'rollback_timer_seconds', 'rules_snapshot', 'compiled_output'],
  'system-health': ['recorded_at', 'cpu_percent', 'ram_percent', 'ram_used_mb', 'ram_total_mb', 'disk_percent', 'disk_used_gb', 'disk_total_gb', 'load_avg_1m', 'load_avg_5m', 'load_avg_15m', 'services'],
  'app-flows': ['timestamp', 'client_ip', 'dest_ip', 'application', 'category', 'hostname', 'protocol', 'app_proto', 'source', 'bytes'],
};

const UPDATABLE_COLS = {
  'firewall-policies': ['name', 'description', 'enabled', 'action', 'direction', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'interface', 'schedule', 'tags', 'priority', 'log_enabled', 'updated_at'],
  'dns-entries': ['domain', 'list_type', 'category', 'source', 'enabled', 'note'],
  'ids-alerts': ['acknowledged'],
  'threat-feeds': ['name', 'description', 'url', 'feed_type', 'enabled', 'last_updated', 'last_status', 'indicator_count', 'refresh_interval_hours'],
  'network-interfaces': ['display_name', 'role', 'status', 'ip_address', 'netmask', 'mtu', 'rx_bytes', 'tx_bytes', 'updated_at'],
  'nat-rules': ['name', 'description', 'enabled', 'nat_type', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'translate_to_ip', 'translate_to_port', 'interface', 'priority', 'updated_at'],
  'sessions': ['last_seen', 'state', 'bytes_in', 'bytes_out', 'packets_in', 'packets_out', 'application'],
  'rule-apply-history': ['status', 'confirmed_at', 'rolled_back_at', 'error_message'],
};

// Append-only resources that must never be deleted via the API.
const NO_DELETE = new Set(['audit-log', 'rule-apply-history']);

function safeName(name) { return name.replace(/[^a-z0-9_]/gi, ''); }

function prepareFields(data, bools = [], allowed = null) {
  const out = {};
  for (const [k, v] of Object.entries(data)) {
    if (allowed && !allowed.includes(k)) continue;
    if (v !== null && typeof v === 'object') out[k] = JSON.stringify(v);
    else if (bools.includes(k)) out[k] = v ? 1 : 0;
    else out[k] = v;
  }
  return out;
}

// ─── CRUD handlers ─────────────────────────────────────────────────────────

async function listRows(resource, req, res) {
  const table = TABLE_MAP[resource];
  if (!table) return res.status(404).json({ error: 'Unknown resource' });

  const order = ORDER_MAP[resource] || { col: 'id', dir: 'ASC' };
  const pageSize = Math.min(parseInt(req.query.page_size) || 100, 1000);
  const page = parseInt(req.query.page) || 0;
  const offset = page * pageSize;

  const conditions = [];
  const params = [];

  for (const col of (FILTER_COLS[resource] || [])) {
    if (req.query[col] !== undefined) {
      conditions.push(`\`${safeName(col)}\` = ?`);
      params.push(req.query[col]);
    }
  }

  if (req.query.search) {
    const cols = SEARCH_COLS[resource] || [];
    if (cols.length) {
      conditions.push('(' + cols.map(c => `\`${safeName(c)}\` LIKE ?`).join(' OR ') + ')');
      for (const _ of cols) params.push(`%${req.query.search}%`);
    }
  }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  const orderClause = `ORDER BY \`${safeName(order.col)}\` ${order.dir}`;

  try {
    const [countRows] = await getPool().execute(`SELECT COUNT(*) as cnt FROM \`${table}\` ${where}`, params);
    const total = countRows[0]?.cnt || 0;
    const [rows] = await getPool().execute(
      `SELECT * FROM \`${table}\` ${where} ${orderClause} LIMIT ? OFFSET ?`,
      [...params, pageSize, offset]
    );
    res.json({ data: castRows(rows), count: Number(total) });
  } catch (e) {
    serverError(res, `listRows ${resource}`, e);
  }
}

async function getRow(resource, id, res) {
  const table = TABLE_MAP[resource];
  if (!table) return res.status(404).json({ error: 'Unknown resource' });
  try {
    const rows = await query(`SELECT * FROM \`${table}\` WHERE id = ? LIMIT 1`, [id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json({ data: castRow(rows[0]) });
  } catch (e) {
    serverError(res, `getRow ${resource}`, e);
  }
}

async function insertRow(resource, body, res) {
  const table = TABLE_MAP[resource];
  if (!table) return res.status(404).json({ error: 'Unknown resource' });
  const allowed = INSERTABLE_COLS[resource];
  if (!allowed) return res.status(403).json({ error: 'Resource is not writable' });
  const bools = BOOL_FIELDS[resource] || [];
  try {
    const data = prepareFields(body, bools, allowed);
    data.id = randomUUID();
    data.created_at = now();

    const cols = Object.keys(data).map(c => `\`${safeName(c)}\``).join(', ');
    const placeholders = Object.keys(data).map(() => '?').join(', ');
    await query(`INSERT INTO \`${table}\` (${cols}) VALUES (${placeholders})`, Object.values(data));

    const rows = await query(`SELECT * FROM \`${table}\` WHERE id = ? LIMIT 1`, [data.id]);
    res.status(201).json({ data: castRow(rows[0]) });
  } catch (e) {
    serverError(res, `insertRow ${resource}`, e);
  }
}

async function updateRow(resource, id, body, res) {
  const table = TABLE_MAP[resource];
  if (!table) return res.status(404).json({ error: 'Unknown resource' });
  const allowed = UPDATABLE_COLS[resource];
  if (!allowed) return res.status(403).json({ error: 'Resource is not updatable' });
  const bools = BOOL_FIELDS[resource] || [];
  try {
    const data = prepareFields(body, bools, allowed);
    if (!Object.keys(data).length) return res.status(400).json({ error: 'No updatable fields provided' });

    const sets = Object.keys(data).map(c => `\`${safeName(c)}\` = ?`).join(', ');
    await query(`UPDATE \`${table}\` SET ${sets} WHERE id = ?`, [...Object.values(data), id]);

    const rows = await query(`SELECT * FROM \`${table}\` WHERE id = ? LIMIT 1`, [id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json({ data: castRow(rows[0]) });
  } catch (e) {
    serverError(res, `updateRow ${resource}`, e);
  }
}

async function deleteRow(resource, id, res) {
  const table = TABLE_MAP[resource];
  if (!table) return res.status(404).json({ error: 'Unknown resource' });
  if (NO_DELETE.has(resource)) return res.status(403).json({ error: 'Resource is append-only' });
  try {
    await query(`DELETE FROM \`${table}\` WHERE id = ?`, [id]);
    res.json({ success: true });
  } catch (e) {
    serverError(res, `deleteRow ${resource}`, e);
  }
}

// ─── Register CRUD routes ──────────────────────────────────────────────────

const CRUD_RESOURCES = [
  'firewall-policies', 'firewall-logs', 'dns-entries', 'dns-logs', 'ids-alerts',
  'threat-feeds', 'threat-indicators', 'network-interfaces', 'nat-rules',
  'audit-log', 'sessions', 'backup-records', 'rule-apply-history', 'system-health',
  'app-flows',
];

// Special routes must be registered before the generic /:id routes.

api.post('/ids-alerts/acknowledge-many', async (req, res) => {
  try {
    const { ids } = req.body || {};
    if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ error: 'ids array required' });
    const placeholders = ids.map(() => '?').join(',');
    await query(`UPDATE ids_alerts SET acknowledged = 1 WHERE id IN (${placeholders})`, ids);
    res.json({ updated: ids.length });
  } catch (e) {
    serverError(res, 'acknowledge-many', e);
  }
});

// Refresh all enabled feeds now.
api.post('/threat-feeds/refresh-all', async (_req, res) => {
  try {
    const feeds = await query('SELECT * FROM threat_feeds WHERE enabled = 1');
    const results = [];
    for (const feed of feeds) results.push(await refreshOneFeed(feed));
    res.json({ refreshed: results.length, results });
  } catch (e) {
    serverError(res, 'refresh-all feeds', e);
  }
});

// Refresh a single feed now.
api.post('/threat-feeds/:id/refresh', async (req, res) => {
  try {
    const rows = await query('SELECT * FROM threat_feeds WHERE id = ? LIMIT 1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    const result = await refreshOneFeed(rows[0]);
    const updated = await query('SELECT * FROM threat_feeds WHERE id = ? LIMIT 1', [req.params.id]);
    res.json({ data: castRow(updated[0]), result });
  } catch (e) {
    serverError(res, 'refresh feed', e);
  }
});

// Deleting a feed also removes its indicators.
api.delete('/threat-feeds/:id', async (req, res) => {
  try {
    await query('DELETE FROM threat_indicators WHERE feed_id = ?', [req.params.id]);
    await query('DELETE FROM threat_feeds WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    serverError(res, 'delete feed', e);
  }
});

// ─── IPSec / IKEv2 VPN ─────────────────────────────────────────────────────

const IPSEC_FIELDS = ['enabled', 'endpoint', 'pool_subnet', 'dns', 'local_subnets'];

api.get('/ipsec-server', async (_req, res) => {
  try {
    const server = await getOrCreateIpsecServer();
    const { ca_cert, ...safe } = server;
    res.json({ data: castRow({ ...safe, ca_present: !!ca_cert }) });
  } catch (e) {
    serverError(res, 'ipsec-server get', e);
  }
});

api.put('/ipsec-server', async (req, res) => {
  try {
    await getOrCreateIpsecServer();
    const data = {};
    for (const f of IPSEC_FIELDS) {
      if (req.body[f] !== undefined) data[f] = f === 'enabled' ? (req.body[f] ? 1 : 0) : req.body[f];
    }
    if (Object.keys(data).length) {
      data.updated_at = now();
      const sets = Object.keys(data).map(c => `\`${safeName(c)}\` = ?`).join(', ');
      await query(`UPDATE ipsec_server SET ${sets}`, Object.values(data));
    }
    const server = await getOrCreateIpsecServer();
    const { ca_cert, ...safe } = server;
    res.json({ data: castRow({ ...safe, ca_present: !!ca_cert }) });
  } catch (e) {
    serverError(res, 'ipsec-server put', e);
  }
});

// VPN users (EAP credentials). Passwords are stored in cleartext because
// EAP-MSCHAPv2 requires the server to verify the password — keep the DB and
// backups (which can be passphrase-encrypted) protected accordingly.
api.get('/vpn-users', async (_req, res) => {
  try {
    const rows = await query('SELECT id, username, enabled, last_connected, created_at FROM vpn_users ORDER BY created_at ASC');
    res.json({ data: castRows(rows), count: rows.length });
  } catch (e) {
    serverError(res, 'vpn-users list', e);
  }
});

api.post('/vpn-users', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !/^[a-zA-Z0-9._@-]{1,100}$/.test(username))
      return res.status(400).json({ error: 'Invalid username' });
    if (!password || password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    const existing = await query('SELECT id FROM vpn_users WHERE username = ? LIMIT 1', [username]);
    if (existing.length) return res.status(409).json({ error: 'Username already exists' });
    const id = randomUUID();
    await query('INSERT INTO vpn_users (id, username, password, enabled, created_at) VALUES (?, ?, ?, 1, ?)',
      [id, username, password, now()]);
    res.status(201).json({ data: { id, username } });
  } catch (e) {
    serverError(res, 'vpn-users create', e);
  }
});

api.delete('/vpn-users/:id', async (req, res) => {
  try {
    await query('DELETE FROM vpn_users WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    serverError(res, 'vpn-users delete', e);
  }
});

// Windows IKEv2 client installer (PowerShell). Requires the CA to exist
// (generated by the agent once IPSec is enabled and applied).
api.get('/ipsec-client-script', async (_req, res) => {
  try {
    const server = await getOrCreateIpsecServer();
    if (!server.ca_cert) return res.status(409).json({ error: 'IPSec not ready yet — enable it and wait for the agent to provision the CA' });
    const script = buildWindowsInstaller({
      name: 'HomeShield VPN',
      endpoint: server.endpoint,
      caCertPem: server.ca_cert,
      fullTunnel: (server.local_subnets || '0.0.0.0/0').trim() === '0.0.0.0/0',
    });
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="homeshield-vpn-install.ps1"');
    res.send(script);
  } catch (e) {
    serverError(res, 'ipsec client script', e);
  }
});

// ─── Agent downloads ───────────────────────────────────────────────────────

// Self-contained Windows agent installer (embeds the agent script), with the
// API URL pre-filled from the request.
api.get('/agent-download/windows', (req, res) => {
  try {
    const scriptPath = join(__dirname, 'agent-windows', 'homeshield-agent.ps1');
    if (!existsSync(scriptPath)) return res.status(404).json({ error: 'Windows agent not bundled with this build' });
    const agentScript = readFileSync(scriptPath, 'utf8');
    const proto = String(req.headers['x-forwarded-proto'] || req.protocol || 'https').split(',')[0].trim();
    const host = req.get('host') || '';
    const bootstrap = buildWindowsBootstrap(agentScript, host ? `${proto}://${host}` : '');
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="homeshield-install.ps1"');
    res.send(bootstrap);
  } catch (e) {
    serverError(res, 'agent-download windows', e);
  }
});

// One-click, self-elevating .cmd installer with the token baked in.
// Admin-only because it embeds the agent token. Requires AGENT_TOKEN.
api.get('/agent-download/windows-cmd', (req, res) => {
  try {
    if ((req.user.role || 'admin') !== 'admin') return res.status(403).json({ error: 'Admin role required' });
    if (!effectiveAgentToken()) return res.status(409).json({ error: 'Generate an agent token first' });
    const scriptPath = join(__dirname, 'agent-windows', 'homeshield-agent.ps1');
    if (!existsSync(scriptPath)) return res.status(404).json({ error: 'Windows agent not bundled with this build' });
    const agentScript = readFileSync(scriptPath, 'utf8');
    const proto = String(req.headers['x-forwarded-proto'] || req.protocol || 'https').split(',')[0].trim();
    const host = req.get('host') || '';
    const cmd = buildWindowsCmd(agentScript, host ? `${proto}://${host}` : '', effectiveAgentToken());
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', 'attachment; filename="homeshield-install.cmd"');
    res.send(cmd);
  } catch (e) {
    serverError(res, 'agent-download windows-cmd', e);
  }
});

// Agent API status. The shared token is revealed to admins only so they can
// copy the install command; other roles get just the enabled flag.
api.get('/agent-status', (req, res) => {
  const isAdmin = (req.user.role || 'admin') === 'admin';
  const token = effectiveAgentToken();
  res.json({
    data: {
      agent_api_enabled: !!token,
      env_managed: agentTokenIsEnvManaged(),
      token: isAdmin ? token : undefined,
    },
  });
});

// Generate (or rotate) the agent token from the console. Admin-only. Disabled
// when AGENT_TOKEN is set via the environment (that takes precedence).
api.post('/agent-token/generate', async (req, res) => {
  try {
    if ((req.user.role || 'admin') !== 'admin') return res.status(403).json({ error: 'Admin role required' });
    if (agentTokenIsEnvManaged()) return res.status(409).json({ error: 'Agent token is managed by the AGENT_TOKEN environment variable' });
    const token = randomBytes(32).toString('hex');
    await query(
      "INSERT INTO server_secrets (`key`, value, updated_at) VALUES ('agent_token', ?, ?) ON DUPLICATE KEY UPDATE value = VALUES(value), updated_at = VALUES(updated_at)",
      [token, now()]
    );
    agentTokenCache = token;
    await query(
      'INSERT INTO audit_log (id, timestamp, actor, action, resource_type, resource_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [randomUUID(), now(), req.user.email, 'agent_token_rotate', 'agent', null, '{}', req.ip || '']
    );
    res.json({ data: { token } });
  } catch (e) {
    serverError(res, 'agent-token generate', e);
  }
});

// ─── Devices (inventory) ───────────────────────────────────────────────────

api.get('/devices', async (_req, res) => {
  try {
    const rows = await query(
      `SELECT id, hostname, os, os_version, agent_version, ip_address, tags, enrolled_at, last_seen,
              (last_seen >= DATE_SUB(NOW(), INTERVAL 2 MINUTE)) AS online
       FROM devices ORDER BY last_seen DESC`
    );
    res.json({ data: castRows(rows), count: rows.length });
  } catch (e) {
    serverError(res, 'devices list', e);
  }
});

api.delete('/devices/:id', async (req, res) => {
  try {
    await query('DELETE FROM devices WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    serverError(res, 'devices delete', e);
  }
});

// ─── WireGuard VPN ───────────────────────────────────────────────────────

const VPN_SERVER_FIELDS = ['interface', 'listen_port', 'address', 'endpoint', 'dns', 'enabled'];

// Server config (private key never leaves the server).
api.get('/vpn-server', async (_req, res) => {
  try {
    const server = await getOrCreateVpnServer();
    const { private_key, ...safe } = server;
    res.json({ data: castRow(safe) });
  } catch (e) {
    serverError(res, 'vpn-server get', e);
  }
});

api.put('/vpn-server', async (req, res) => {
  try {
    await getOrCreateVpnServer();
    const data = {};
    for (const f of VPN_SERVER_FIELDS) {
      if (req.body[f] !== undefined) data[f] = f === 'enabled' ? (req.body[f] ? 1 : 0) : req.body[f];
    }
    if (Object.keys(data).length) {
      data.updated_at = now();
      const sets = Object.keys(data).map(c => `\`${safeName(c)}\` = ?`).join(', ');
      await query(`UPDATE vpn_server SET ${sets}`, Object.values(data));
    }
    const server = await getOrCreateVpnServer();
    const { private_key, ...safe } = server;
    res.json({ data: castRow(safe) });
  } catch (e) {
    serverError(res, 'vpn-server put', e);
  }
});

// List peers (secrets omitted; fetch the full config via /config).
api.get('/vpn-peers', async (_req, res) => {
  try {
    const rows = await query(
      `SELECT id, name, public_key, address, allowed_ips, enabled, last_handshake, rx_bytes, tx_bytes, created_at
       FROM vpn_peers ORDER BY created_at ASC`
    );
    res.json({ data: castRows(rows), count: rows.length });
  } catch (e) {
    serverError(res, 'vpn-peers list', e);
  }
});

// Create a peer: generate its keypair, allocate the next tunnel address.
api.post('/vpn-peers', async (req, res) => {
  try {
    const name = (req.body?.name || '').trim();
    if (!name) return res.status(400).json({ error: 'Peer name is required' });

    const server = await getOrCreateVpnServer();
    const used = (await query('SELECT address FROM vpn_peers')).map(r => r.address);
    let address;
    try {
      address = nextPeerAddress(server.address, used);
    } catch (e) {
      return res.status(409).json({ error: e.message });
    }

    const { privateKey, publicKey } = generateKeyPair();
    const id = randomUUID();
    await query(
      `INSERT INTO vpn_peers (id, name, public_key, private_key, preshared_key, address, allowed_ips, enabled, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)`,
      [id, name, publicKey, privateKey, generatePresharedKey(), address,
       req.body.allowed_ips || '0.0.0.0/0', now()]
    );
    const rows = await query(
      `SELECT id, name, public_key, address, allowed_ips, enabled, last_handshake, rx_bytes, tx_bytes, created_at
       FROM vpn_peers WHERE id = ? LIMIT 1`, [id]
    );
    res.status(201).json({ data: castRow(rows[0]) });
  } catch (e) {
    serverError(res, 'vpn-peers create', e);
  }
});

api.patch('/vpn-peers/:id', async (req, res) => {
  try {
    const data = {};
    if (req.body.name !== undefined) data.name = req.body.name;
    if (req.body.allowed_ips !== undefined) data.allowed_ips = req.body.allowed_ips;
    if (req.body.enabled !== undefined) data.enabled = req.body.enabled ? 1 : 0;
    if (!Object.keys(data).length) return res.status(400).json({ error: 'No updatable fields' });
    const sets = Object.keys(data).map(c => `\`${safeName(c)}\` = ?`).join(', ');
    await query(`UPDATE vpn_peers SET ${sets} WHERE id = ?`, [...Object.values(data), req.params.id]);
    res.json({ success: true });
  } catch (e) {
    serverError(res, 'vpn-peers update', e);
  }
});

api.delete('/vpn-peers/:id', async (req, res) => {
  try {
    await query('DELETE FROM vpn_peers WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    serverError(res, 'vpn-peers delete', e);
  }
});

// Client config text + QR data URL for a peer.
api.get('/vpn-peers/:id/config', async (req, res) => {
  try {
    const server = await getOrCreateVpnServer();
    const rows = await query('SELECT * FROM vpn_peers WHERE id = ? LIMIT 1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    const config = buildClientConfig(server, rows[0]);
    const qr = await QRCode.toDataURL(config, { errorCorrectionLevel: 'M', margin: 1, width: 320 });
    res.json({ data: { config, qr } });
  } catch (e) {
    serverError(res, 'vpn-peers config', e);
  }
});

// ─── Backup & Restore ──────────────────────────────────────────────────────
// Config tables captured in a backup and their restorable columns. Order
// matters for restore (independent tables; full replace each).

const BACKUP_TABLES = {
  firewall_policies: ['id', 'name', 'description', 'enabled', 'action', 'direction', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'interface', 'schedule', 'tags', 'priority', 'log_enabled', 'created_at', 'updated_at'],
  nat_rules: ['id', 'name', 'description', 'enabled', 'nat_type', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'translate_to_ip', 'translate_to_port', 'interface', 'priority', 'created_at', 'updated_at'],
  dns_entries: ['id', 'domain', 'list_type', 'category', 'source', 'enabled', 'note', 'created_at'],
  threat_feeds: ['id', 'name', 'description', 'url', 'feed_type', 'enabled', 'last_updated', 'last_status', 'indicator_count', 'refresh_interval_hours', 'created_at'],
  vpn_server: ['id', 'interface', 'private_key', 'public_key', 'listen_port', 'address', 'endpoint', 'dns', 'enabled', 'created_at', 'updated_at'],
  vpn_peers: ['id', 'name', 'public_key', 'private_key', 'preshared_key', 'address', 'allowed_ips', 'enabled', 'last_handshake', 'rx_bytes', 'tx_bytes', 'created_at'],
  system_settings: ['key', 'value', 'description', 'updated_at'],
};

const JSON_BACKUP_COLS = new Set(['tags']);

async function gatherBackupConfig() {
  const config = {};
  for (const table of Object.keys(BACKUP_TABLES)) {
    config[table] = castRows(await query(`SELECT * FROM \`${table}\``));
  }
  return config;
}

// List backups (without the heavy payload column).
api.get('/backups', async (_req, res) => {
  try {
    const rows = await query(
      `SELECT id, created_at, created_by, label, description, trigger_type, size_bytes, encrypted, checksum
       FROM backup_records ORDER BY created_at DESC`
    );
    res.json({ data: castRows(rows), count: rows.length });
  } catch (e) {
    serverError(res, 'backups list', e);
  }
});

// Create a backup of the current configuration.
api.post('/backups', async (req, res) => {
  try {
    const { label, description, passphrase } = req.body || {};
    const config = await gatherBackupConfig();
    const envelope = buildEnvelope(config, { passphrase: passphrase || undefined });
    const id = randomUUID();
    const counts = Object.fromEntries(Object.entries(config).map(([k, v]) => [k, v.length]));
    await query(
      `INSERT INTO backup_records (id, created_at, created_by, label, description, trigger_type, size_bytes, encrypted, payload, checksum)
       VALUES (?, ?, ?, ?, ?, 'manual', ?, ?, ?, ?)`,
      [id, now(), req.user.email || 'admin', label || `Backup ${new Date().toISOString().slice(0, 10)}`,
       description || '', Buffer.byteLength(envelope), passphrase ? 1 : 0, envelope, sha256(envelope)]
    );
    await query(
      'INSERT INTO audit_log (id, timestamp, actor, action, resource_type, resource_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [randomUUID(), now(), req.user.email || 'admin', 'backup_create', 'backup', id, JSON.stringify(counts), req.ip || '']
    );
    const rows = await query(
      `SELECT id, created_at, created_by, label, description, trigger_type, size_bytes, encrypted, checksum
       FROM backup_records WHERE id = ? LIMIT 1`, [id]
    );
    res.status(201).json({ data: castRow(rows[0]) });
  } catch (e) {
    serverError(res, 'backup create', e);
  }
});

// Download a backup's envelope as a file.
api.get('/backups/:id/download', async (req, res) => {
  try {
    const rows = await query('SELECT label, payload FROM backup_records WHERE id = ? LIMIT 1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    const name = (rows[0].label || 'backup').replace(/[^a-z0-9]/gi, '_').slice(0, 40);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="homeshield-${name}.json"`);
    res.send(rows[0].payload);
  } catch (e) {
    serverError(res, 'backup download', e);
  }
});

// Restore configuration from a stored backup id or an uploaded payload.
api.post('/backups/restore', async (req, res) => {
  try {
    const { id, payload, passphrase } = req.body || {};
    let envelopeStr = payload;
    if (id) {
      const rows = await query('SELECT payload FROM backup_records WHERE id = ? LIMIT 1', [id]);
      if (!rows.length) return res.status(404).json({ error: 'Backup not found' });
      envelopeStr = rows[0].payload;
    }
    if (!envelopeStr) return res.status(400).json({ error: 'Provide a backup id or payload' });

    let config;
    try {
      config = readEnvelope(envelopeStr, passphrase);
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }

    const conn = await getPool().getConnection();
    const restored = {};
    try {
      await conn.beginTransaction();
      for (const [table, cols] of Object.entries(BACKUP_TABLES)) {
        const rows = config[table];
        if (!Array.isArray(rows)) continue;
        await conn.execute(`DELETE FROM \`${table}\``);
        for (const row of rows) {
          const data = {};
          for (const col of cols) {
            if (row[col] === undefined) continue;
            data[col] = JSON_BACKUP_COLS.has(col) && row[col] !== null && typeof row[col] === 'object'
              ? JSON.stringify(row[col])
              : row[col];
          }
          if (!Object.keys(data).length) continue;
          const names = Object.keys(data).map(c => `\`${safeName(c)}\``).join(', ');
          const placeholders = Object.keys(data).map(() => '?').join(', ');
          await conn.execute(`INSERT INTO \`${table}\` (${names}) VALUES (${placeholders})`, Object.values(data));
        }
        restored[table] = rows.length;
      }
      await conn.commit();
    } catch (e) {
      await conn.rollback();
      throw e;
    } finally {
      conn.release();
    }

    await query(
      'INSERT INTO audit_log (id, timestamp, actor, action, resource_type, resource_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [randomUUID(), now(), req.user.email || 'admin', 'backup_restore', 'backup', id || null, JSON.stringify(restored), req.ip || '']
    );
    res.json({ data: { restored } });
  } catch (e) {
    serverError(res, 'backup restore', e);
  }
});

api.delete('/backups/:id', async (req, res) => {
  try {
    await query('DELETE FROM backup_records WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    serverError(res, 'backup delete', e);
  }
});

// Aggregated application stats over a recent time window (default 24h).
api.get('/app-flows/stats', async (req, res) => {
  try {
    const hours = Math.min(Math.max(parseInt(req.query.hours, 10) || 24, 1), 720);
    const byApp = await query(
      `SELECT application, category,
              COUNT(*) AS flows,
              SUM(bytes) AS bytes,
              COUNT(DISTINCT client_ip) AS clients,
              MAX(timestamp) AS last_seen
       FROM app_flows
       WHERE timestamp >= DATE_SUB(NOW(), INTERVAL ? HOUR)
       GROUP BY application, category
       ORDER BY flows DESC
       LIMIT 100`,
      [hours]
    );
    const byCategory = await query(
      `SELECT category, COUNT(*) AS flows, SUM(bytes) AS bytes
       FROM app_flows
       WHERE timestamp >= DATE_SUB(NOW(), INTERVAL ? HOUR)
       GROUP BY category ORDER BY flows DESC`,
      [hours]
    );
    res.json({ data: { apps: castRows(byApp), categories: castRows(byCategory), hours } });
  } catch (e) {
    serverError(res, 'app-flows stats', e);
  }
});

for (const resource of CRUD_RESOURCES) {
  api.get(`/${resource}`, (req, res) => listRows(resource, req, res));
  api.get(`/${resource}/:id`, (req, res) => getRow(resource, req.params.id, res));
  api.post(`/${resource}`, (req, res) => insertRow(resource, req.body, res));
  api.patch(`/${resource}/:id`, (req, res) => updateRow(resource, req.params.id, req.body, res));
  api.put(`/${resource}/:id`, (req, res) => updateRow(resource, req.params.id, req.body, res));
  api.delete(`/${resource}/:id`, (req, res) => deleteRow(resource, req.params.id, res));
}

// ─── System settings ───────────────────────────────────────────────────────

api.get('/system-settings', async (_req, res) => {
  try {
    const rows = await query('SELECT * FROM system_settings');
    res.json({ data: castRows(rows) });
  } catch (e) {
    serverError(res, 'system-settings get', e);
  }
});

api.post('/system-settings', async (req, res) => {
  try {
    const items = Array.isArray(req.body?.items)
      ? req.body.items
      : Array.isArray(req.body)
      ? req.body
      : [req.body];

    for (const item of items) {
      if (!item.key) continue;
      await query(
        'INSERT INTO system_settings (`key`, value, description, updated_at) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE value = VALUES(value), description = VALUES(description), updated_at = VALUES(updated_at)',
        [item.key, item.value ?? '', item.description ?? '', now()]
      );
    }
    const rows = await query('SELECT * FROM system_settings');
    res.json({ data: castRows(rows) });
  } catch (e) {
    serverError(res, 'system-settings post', e);
  }
});

// ─── Agent API ─────────────────────────────────────────────────────────────
// Used by the enforcement agent (agent/homeshield-agent.mjs). Authenticated
// with a shared secret. The effective token is the AGENT_TOKEN env var if set
// (takes precedence), otherwise a token generated/stored in the DB and managed
// from the console. If neither is set, these endpoints are disabled.

const agent = express.Router();

agent.use((req, res, next) => {
  const expected = effectiveAgentToken();
  if (!expected) return res.status(503).json({ error: 'Agent API disabled — set or generate an agent token' });
  const token = req.headers['x-agent-token'] || '';
  const a = Buffer.from(String(token));
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return res.status(401).json({ error: 'Invalid agent token' });
  }
  next();
});

// Oldest pending apply job for this OS.
agent.get('/job', async (req, res) => {
  try {
    const os = req.query.os === 'windows' ? 'windows' : 'linux';
    const rows = await query(
      `SELECT id, mode, os_target, rules_count, rollback_timer_seconds, compiled_output
       FROM rule_apply_history WHERE status = 'pending' AND os_target = ?
       ORDER BY applied_at ASC LIMIT 1`,
      [os]
    );
    res.json({ data: rows.length ? castRow(rows[0]) : null });
  } catch (e) {
    serverError(res, 'agent job', e);
  }
});

// Agent polls this while waiting for the operator to confirm.
agent.get('/job/:id', async (req, res) => {
  try {
    const rows = await query(
      'SELECT id, status, rollback_timer_seconds FROM rule_apply_history WHERE id = ? LIMIT 1',
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json({ data: castRow(rows[0]) });
  } catch (e) {
    serverError(res, 'agent job status', e);
  }
});

// Agent reports the outcome of an apply or rollback.
agent.post('/job/:id/result', async (req, res) => {
  try {
    const { status, error_message } = req.body || {};
    if (!['applied', 'failed', 'rolled_back'].includes(status)) {
      return res.status(400).json({ error: 'status must be applied, failed or rolled_back' });
    }
    const sets = { status, error_message: error_message || '' };
    if (status === 'rolled_back') sets.rolled_back_at = now();
    const cols = Object.keys(sets).map(c => `\`${c}\` = ?`).join(', ');
    await query(`UPDATE rule_apply_history SET ${cols} WHERE id = ?`, [...Object.values(sets), req.params.id]);

    await query(
      'INSERT INTO audit_log (id, timestamp, actor, action, resource_type, resource_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [randomUUID(), now(), 'agent', `apply_${status}`, 'firewall_ruleset', req.params.id,
       JSON.stringify({ error_message: error_message || null }), req.ip || '']
    );
    res.json({ success: true });
  } catch (e) {
    serverError(res, 'agent job result', e);
  }
});

// Bulk firewall log ingestion from kernel log lines (max 500 per request).
agent.post('/firewall-logs', async (req, res) => {
  try {
    const logs = Array.isArray(req.body?.logs) ? req.body.logs.slice(0, 500) : [];
    if (!logs.length) return res.json({ inserted: 0 });

    const allowed = INSERTABLE_COLS['firewall-logs'];
    let inserted = 0;
    for (const entry of logs) {
      const data = prepareFields(entry, [], allowed);
      data.id = randomUUID();
      if (!data.timestamp) data.timestamp = now();
      const cols = Object.keys(data).map(c => `\`${safeName(c)}\``).join(', ');
      const placeholders = Object.keys(data).map(() => '?').join(', ');
      await query(`INSERT INTO firewall_logs (${cols}) VALUES (${placeholders})`, Object.values(data));
      inserted++;
    }
    res.json({ inserted });
  } catch (e) {
    serverError(res, 'agent firewall-logs', e);
  }
});

// DNS filtering config for the agent's proxy: enabled flag, upstream
// resolver, and all enabled block/allow entries.
agent.get('/dns-config', async (_req, res) => {
  try {
    const settings = await query(
      "SELECT `key`, value FROM system_settings WHERE `key` IN ('dns_filtering_enabled', 'dns_upstream', 'appid_enabled')"
    );
    const map = Object.fromEntries(settings.map(r => [r.key, r.value]));
    const entries = await query(
      'SELECT domain, list_type, category FROM dns_entries WHERE enabled = 1'
    );
    // Domain indicators from enabled threat feeds also become blocklist
    // entries. User allowlist entries in dns_entries still win (the matcher
    // gives allowlist precedence), so this can't override an explicit allow.
    const threatDomains = await query(
      `SELECT ti.value AS domain, 'blocklist' AS list_type,
              CONCAT('threat:', COALESCE(tf.name, 'feed')) AS category
       FROM threat_indicators ti
       JOIN threat_feeds tf ON tf.id = ti.feed_id
       WHERE tf.enabled = 1 AND ti.indicator_type = 'domain'
         AND (ti.expires_at IS NULL OR ti.expires_at > NOW())
       LIMIT 200000`
    );
    res.json({
      data: {
        enabled: map.dns_filtering_enabled === 'true',
        upstream: map.dns_upstream || '1.1.1.1',
        appid_enabled: map.appid_enabled !== 'false',
        entries: [...castRows(entries), ...castRows(threatDomains)],
      },
    });
  } catch (e) {
    serverError(res, 'agent dns-config', e);
  }
});

// Bulk DNS query log ingestion (max 500 per request).
agent.post('/dns-logs', async (req, res) => {
  try {
    const logs = Array.isArray(req.body?.logs) ? req.body.logs.slice(0, 500) : [];
    if (!logs.length) return res.json({ inserted: 0 });

    const allowed = INSERTABLE_COLS['dns-logs'];
    let inserted = 0;
    for (const entry of logs) {
      const data = prepareFields(entry, [], allowed);
      if (!data.domain || !['allowed', 'blocked'].includes(data.action)) continue;
      data.id = randomUUID();
      if (!data.timestamp) data.timestamp = now();
      const cols = Object.keys(data).map(c => `\`${safeName(c)}\``).join(', ');
      const placeholders = Object.keys(data).map(() => '?').join(', ');
      await query(`INSERT INTO dns_logs (${cols}) VALUES (${placeholders})`, Object.values(data));
      inserted++;
    }
    res.json({ inserted });
  } catch (e) {
    serverError(res, 'agent dns-logs', e);
  }
});

// Suricata IDS/IPS config for the agent: mode (off/ids/ips), NFQUEUE number
// and the eve.json path to tail.
agent.get('/ips-config', async (_req, res) => {
  try {
    const rows = await query(
      "SELECT `key`, value FROM system_settings WHERE `key` IN ('ips_mode', 'suricata_queue_num', 'suricata_eve_path')"
    );
    const map = Object.fromEntries(rows.map(r => [r.key, r.value]));
    const mode = ['off', 'ids', 'ips'].includes(map.ips_mode) ? map.ips_mode : 'off';
    res.json({
      data: {
        mode,
        queue_num: parseInt(map.suricata_queue_num, 10) || 0,
        eve_path: map.suricata_eve_path || '/var/log/suricata/eve.json',
      },
    });
  } catch (e) {
    serverError(res, 'agent ips-config', e);
  }
});

// Active threat-intel blocklist for the agent: IP/CIDR indicators from
// enabled feeds that haven't expired. The agent compiles these into an
// nftables set. Capped to keep the payload and ruleset bounded.
agent.get('/threat-set', async (_req, res) => {
  try {
    const rows = await query(
      `SELECT ti.value FROM threat_indicators ti
       JOIN threat_feeds tf ON tf.id = ti.feed_id
       WHERE tf.enabled = 1
         AND ti.indicator_type IN ('ip', 'cidr')
         AND (ti.expires_at IS NULL OR ti.expires_at > NOW())
       LIMIT 200000`
    );
    res.json({ data: { values: rows.map(r => r.value) } });
  } catch (e) {
    serverError(res, 'agent threat-set', e);
  }
});

// GeoIP filtering config for the agent: mode, country list and zone sources.
agent.get('/geoip-config', async (_req, res) => {
  try {
    const rows = await query(
      "SELECT `key`, value FROM system_settings WHERE `key` IN ('geoip_enabled', 'geoip_mode', 'geoip_countries', 'geoip_source_v4', 'geoip_source_v6')"
    );
    const map = Object.fromEntries(rows.map(r => [r.key, r.value]));
    const countries = (map.geoip_countries || '')
      .split(',').map(c => c.trim().toLowerCase()).filter(c => /^[a-z]{2}$/.test(c));
    res.json({
      data: {
        enabled: map.geoip_enabled === 'true',
        mode: map.geoip_mode === 'allow' ? 'allow' : 'block',
        countries,
        source_v4: map.geoip_source_v4 || 'https://www.ipdeny.com/ipblocks/data/aggregated/{cc}-aggregated.zone',
        source_v6: map.geoip_source_v6 || 'https://www.ipdeny.com/ipv6/ipaddresses/aggregated/{cc}-aggregated.zone',
      },
    });
  } catch (e) {
    serverError(res, 'agent geoip-config', e);
  }
});

// Device registration / heartbeat. Agents upsert their identity each cycle.
agent.post('/register', async (req, res) => {
  try {
    const { device_id, hostname, os, os_version, agent_version, ip_address } = req.body || {};
    if (!device_id) return res.status(400).json({ error: 'device_id required' });
    const osVal = ['windows', 'linux', 'macos'].includes(os) ? os : 'unknown';
    await query(
      `INSERT INTO devices (id, hostname, os, os_version, agent_version, ip_address, enrolled_at, last_seen)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE hostname = VALUES(hostname), os = VALUES(os),
         os_version = VALUES(os_version), agent_version = VALUES(agent_version),
         ip_address = VALUES(ip_address), last_seen = VALUES(last_seen)`,
      [device_id, hostname || '', osVal, os_version || '', agent_version || '', ip_address || '', now(), now()]
    );
    res.json({ success: true, device_id });
  } catch (e) {
    serverError(res, 'agent register', e);
  }
});

// IKEv2 client provisioning data for a Windows/macOS agent (the road-warrior
// side): endpoint + CA so the agent can create the native VPN connection.
agent.get('/vpn-client', async (_req, res) => {
  try {
    const server = await getOrCreateIpsecServer();
    res.json({
      data: {
        enabled: server.enabled === 1 && !!server.ca_cert,
        name: 'HomeShield VPN',
        endpoint: server.endpoint,
        ca_cert: server.ca_cert || '',
        full_tunnel: (server.local_subnets || '0.0.0.0/0').trim() === '0.0.0.0/0',
      },
    });
  } catch (e) {
    serverError(res, 'agent vpn-client', e);
  }
});

// IPSec/IKEv2 config for the agent: server settings + EAP users.
agent.get('/ipsec-config', async (_req, res) => {
  try {
    const server = await getOrCreateIpsecServer();
    const users = await query('SELECT username, password FROM vpn_users WHERE enabled = 1');
    res.json({
      data: {
        enabled: server.enabled === 1,
        endpoint: server.endpoint,
        pool_subnet: server.pool_subnet,
        dns: server.dns,
        local_subnets: server.local_subnets,
        ca_present: !!server.ca_cert,
        users: castRows(users),
      },
    });
  } catch (e) {
    serverError(res, 'agent ipsec-config', e);
  }
});

// Agent uploads the CA certificate it generated (so clients can be provisioned)
// and reports strongSwan status.
agent.post('/ipsec-ca', async (req, res) => {
  try {
    const { ca_cert, ca_fingerprint, status } = req.body || {};
    await getOrCreateIpsecServer();
    await query(
      'UPDATE ipsec_server SET ca_cert = ?, ca_fingerprint = ?, status = ?, updated_at = ?',
      [ca_cert || null, ca_fingerprint || '', status || 'active', now()]
    );
    res.json({ success: true });
  } catch (e) {
    serverError(res, 'agent ipsec-ca', e);
  }
});

// WireGuard config for the agent: server settings + enabled peers.
agent.get('/vpn-config', async (_req, res) => {
  try {
    const server = await getOrCreateVpnServer();
    const peers = await query(
      'SELECT public_key, preshared_key, address FROM vpn_peers WHERE enabled = 1'
    );
    res.json({
      data: {
        enabled: server.enabled === 1,
        interface: server.interface,
        private_key: server.private_key,
        listen_port: server.listen_port,
        address: server.address,
        peers: castRows(peers),
      },
    });
  } catch (e) {
    serverError(res, 'agent vpn-config', e);
  }
});

// Peer telemetry from `wg show dump`: handshake and transfer counters.
agent.post('/vpn-telemetry', async (req, res) => {
  try {
    const peers = Array.isArray(req.body?.peers) ? req.body.peers : [];
    for (const p of peers) {
      if (!p.public_key) continue;
      await query(
        'UPDATE vpn_peers SET last_handshake = ?, rx_bytes = ?, tx_bytes = ? WHERE public_key = ?',
        [p.last_handshake || null, p.rx_bytes || 0, p.tx_bytes || 0, p.public_key]
      );
    }
    res.json({ updated: peers.length });
  } catch (e) {
    serverError(res, 'agent vpn-telemetry', e);
  }
});

// Bulk application-flow ingestion (max 500 per request).
agent.post('/app-flows', async (req, res) => {
  try {
    const flows = Array.isArray(req.body?.flows) ? req.body.flows.slice(0, 500) : [];
    if (!flows.length) return res.json({ inserted: 0 });
    const allowed = INSERTABLE_COLS['app-flows'];
    let inserted = 0;
    for (const flow of flows) {
      const data = prepareFields(flow, [], allowed);
      if (!data.application) continue;
      data.id = randomUUID();
      if (!data.timestamp) data.timestamp = now();
      const cols = Object.keys(data).map(c => `\`${safeName(c)}\``).join(', ');
      const placeholders = Object.keys(data).map(() => '?').join(', ');
      await query(`INSERT INTO app_flows (${cols}) VALUES (${placeholders})`, Object.values(data));
      inserted++;
    }
    res.json({ inserted });
  } catch (e) {
    serverError(res, 'agent app-flows', e);
  }
});

// Bulk IDS/IPS alert ingestion from Suricata eve.json (max 500 per request).
agent.post('/ids-alerts', async (req, res) => {
  try {
    const alerts = Array.isArray(req.body?.alerts) ? req.body.alerts.slice(0, 500) : [];
    if (!alerts.length) return res.json({ inserted: 0 });

    const allowed = INSERTABLE_COLS['ids-alerts'];
    let inserted = 0;
    for (const entry of alerts) {
      const data = prepareFields(entry, [], allowed);
      if (!data.signature_name) continue;
      data.id = randomUUID();
      if (!data.timestamp) data.timestamp = now();
      const cols = Object.keys(data).map(c => `\`${safeName(c)}\``).join(', ');
      const placeholders = Object.keys(data).map(() => '?').join(', ');
      await query(`INSERT INTO ids_alerts (${cols}) VALUES (${placeholders})`, Object.values(data));
      inserted++;
    }
    res.json({ inserted });
  } catch (e) {
    serverError(res, 'agent ids-alerts', e);
  }
});

// Agent telemetry: replaces the interface inventory and live session list,
// and records a health snapshot.
agent.post('/telemetry', async (req, res) => {
  try {
    const { interfaces, health, sessions } = req.body || {};

    if (Array.isArray(interfaces)) {
      await query('DELETE FROM network_interfaces');
      for (const iface of interfaces) {
        const data = prepareFields(iface, [], INSERTABLE_COLS['network-interfaces']);
        data.id = randomUUID();
        data.updated_at = now();
        const cols = Object.keys(data).map(c => `\`${safeName(c)}\``).join(', ');
        const placeholders = Object.keys(data).map(() => '?').join(', ');
        await query(`INSERT INTO network_interfaces (${cols}) VALUES (${placeholders})`, Object.values(data));
      }
    }

    if (Array.isArray(sessions)) {
      await query('DELETE FROM sessions');
      const ts = now();
      for (const session of sessions.slice(0, 500)) {
        const data = prepareFields(session, [], INSERTABLE_COLS['sessions']);
        data.id = randomUUID();
        data.started_at = data.started_at || ts;
        data.last_seen = ts;
        const cols = Object.keys(data).map(c => `\`${safeName(c)}\``).join(', ');
        const placeholders = Object.keys(data).map(() => '?').join(', ');
        await query(`INSERT INTO sessions (${cols}) VALUES (${placeholders})`, Object.values(data));
      }
    }

    if (health && typeof health === 'object') {
      const data = prepareFields(health, [], INSERTABLE_COLS['system-health']);
      data.id = randomUUID();
      data.recorded_at = now();
      const cols = Object.keys(data).map(c => `\`${safeName(c)}\``).join(', ');
      const placeholders = Object.keys(data).map(() => '?').join(', ');
      await query(`INSERT INTO system_health_snapshots (${cols}) VALUES (${placeholders})`, Object.values(data));
    }

    res.json({ success: true });
  } catch (e) {
    serverError(res, 'agent telemetry', e);
  }
});

// Agent router must be mounted before the JWT-protected router so that
// /api/agent/* is matched here and never hits authMiddleware.
app.use('/api/agent', agent);
app.use('/api', api);

// ─── Serve React SPA ───────────────────────────────────────────────────────

const distDir = join(__dirname, 'dist');
if (existsSync(distDir)) {
  app.use(express.static(distDir));
  app.get('*', (_req, res) => res.sendFile(join(distDir, 'index.html')));
} else {
  console.warn('dist/ not found — frontend not available');
  app.get('*', (_req, res) => res.status(503).send('Run npm run build first'));
}

// Creates tables added after the initial schema on existing databases
// (auto-migrate only runs the full schema on first install). Idempotent.
async function ensureVpnTables() {
  try {
    await getPool().query(`CREATE TABLE IF NOT EXISTS vpn_server (
      id VARCHAR(36) PRIMARY KEY,
      interface VARCHAR(50) DEFAULT 'wg0',
      private_key VARCHAR(64) DEFAULT '',
      public_key VARCHAR(64) DEFAULT '',
      listen_port INT DEFAULT 51820,
      address VARCHAR(50) DEFAULT '10.8.0.1/24',
      endpoint VARCHAR(255) DEFAULT '',
      dns VARCHAR(100) DEFAULT '1.1.1.1',
      enabled TINYINT(1) DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    await getPool().query(`CREATE TABLE IF NOT EXISTS vpn_peers (
      id VARCHAR(36) PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      public_key VARCHAR(64) DEFAULT '',
      private_key VARCHAR(64) DEFAULT '',
      preshared_key VARCHAR(64) DEFAULT '',
      address VARCHAR(50) DEFAULT '',
      allowed_ips VARCHAR(255) DEFAULT '0.0.0.0/0',
      enabled TINYINT(1) DEFAULT 1,
      last_handshake DATETIME NULL,
      rx_bytes BIGINT DEFAULT 0,
      tx_bytes BIGINT DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_public_key (public_key)
    )`);
    await getPool().query(`CREATE TABLE IF NOT EXISTS app_flows (
      id VARCHAR(36) PRIMARY KEY,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      client_ip VARCHAR(50),
      dest_ip VARCHAR(50),
      application VARCHAR(100),
      category VARCHAR(50),
      hostname VARCHAR(255),
      protocol VARCHAR(20),
      app_proto VARCHAR(30),
      source VARCHAR(10),
      bytes BIGINT DEFAULT 0,
      INDEX idx_timestamp (timestamp),
      INDEX idx_application (application)
    )`);
    await getPool().query(`CREATE TABLE IF NOT EXISTS server_secrets (
      \`key\` VARCHAR(64) PRIMARY KEY,
      value TEXT,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    await getPool().query(`CREATE TABLE IF NOT EXISTS devices (
      id VARCHAR(36) PRIMARY KEY,
      hostname VARCHAR(255) DEFAULT '',
      os ENUM('windows','linux','macos','unknown') DEFAULT 'unknown',
      os_version VARCHAR(150) DEFAULT '',
      agent_version VARCHAR(50) DEFAULT '',
      ip_address VARCHAR(50) DEFAULT '',
      tags JSON,
      enrolled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_last_seen (last_seen),
      INDEX idx_os (os)
    )`);
    await getPool().query(`CREATE TABLE IF NOT EXISTS ipsec_server (
      id VARCHAR(36) PRIMARY KEY,
      enabled TINYINT(1) DEFAULT 0,
      endpoint VARCHAR(255) DEFAULT '',
      pool_subnet VARCHAR(50) DEFAULT '10.9.0.0/24',
      dns VARCHAR(100) DEFAULT '1.1.1.1',
      local_subnets VARCHAR(255) DEFAULT '0.0.0.0/0',
      ca_cert MEDIUMTEXT,
      ca_fingerprint VARCHAR(128) DEFAULT '',
      status VARCHAR(50) DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    await getPool().query(`CREATE TABLE IF NOT EXISTS vpn_users (
      id VARCHAR(36) PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      enabled TINYINT(1) DEFAULT 1,
      last_connected DATETIME NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
  } catch (e) {
    console.error('ensureVpnTables failed:', e.message);
  }
}

async function getOrCreateIpsecServer() {
  const rows = await query('SELECT * FROM ipsec_server LIMIT 1');
  if (rows.length) return rows[0];
  const id = randomUUID();
  await query('INSERT INTO ipsec_server (id, created_at, updated_at) VALUES (?, ?, ?)', [id, now(), now()]);
  return (await query('SELECT * FROM ipsec_server WHERE id = ? LIMIT 1', [id]))[0];
}

// Agent shared-secret. The AGENT_TOKEN env var wins if set; otherwise a token
// generated from the console and stored in server_secrets is used. Cached in
// memory so the per-request agent auth check stays fast.
let agentTokenCache = '';
function effectiveAgentToken() {
  return process.env.AGENT_TOKEN || agentTokenCache || '';
}
function agentTokenIsEnvManaged() {
  return !!process.env.AGENT_TOKEN;
}
async function loadAgentToken() {
  try {
    const rows = await query("SELECT value FROM server_secrets WHERE `key` = 'agent_token' LIMIT 1");
    agentTokenCache = rows[0]?.value || '';
  } catch (e) {
    console.error('loadAgentToken failed:', e.message);
  }
}

// Adds RBAC/MFA columns to admin_users on existing databases. Idempotent.
async function ensureUserColumns() {
  try {
    const [cols] = await getPool().query(
      'SELECT column_name FROM information_schema.columns WHERE table_schema = ? AND table_name = ?',
      [process.env.DB_NAME, 'admin_users']
    );
    const have = new Set(cols.map(c => c.column_name || c.COLUMN_NAME));
    if (!have.has('role')) {
      await getPool().query("ALTER TABLE admin_users ADD COLUMN role ENUM('admin','operator','viewer') NOT NULL DEFAULT 'admin'");
    }
    if (!have.has('mfa_secret')) {
      await getPool().query("ALTER TABLE admin_users ADD COLUMN mfa_secret VARCHAR(64) DEFAULT ''");
    }
    if (!have.has('mfa_enabled')) {
      await getPool().query('ALTER TABLE admin_users ADD COLUMN mfa_enabled TINYINT(1) DEFAULT 0');
    }
  } catch (e) {
    console.error('ensureUserColumns failed:', e.message);
  }
}

// Returns the single VPN server row, creating it (with a fresh keypair) on
// first access.
async function getOrCreateVpnServer() {
  const rows = await query('SELECT * FROM vpn_server LIMIT 1');
  if (rows.length) return rows[0];
  const { privateKey, publicKey } = generateKeyPair();
  const id = randomUUID();
  await query(
    'INSERT INTO vpn_server (id, private_key, public_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?)',
    [id, privateKey, publicKey, now(), now()]
  );
  const created = await query('SELECT * FROM vpn_server WHERE id = ? LIMIT 1', [id]);
  return created[0];
}

// Inserts any missing default settings on existing databases (auto-migrate
// only runs the full schema on first install).
async function ensureDefaultSettings() {
  const defaults = [
    ['dns_upstream', '1.1.1.1', 'Upstream DNS resolver for the filtering proxy'],
    ['suricata_queue_num', '0', 'NFQUEUE number Suricata reads in IPS mode'],
    ['suricata_eve_path', '/var/log/suricata/eve.json', 'Path to Suricata eve.json'],
    ['appid_enabled', 'true', 'Enable application identification (app_flows)'],
    ['geoip_enabled', 'false', 'Enable GeoIP country filtering'],
    ['geoip_mode', 'block', 'GeoIP mode: block (drop listed) or allow (only listed inbound)'],
    ['geoip_countries', '', 'Comma-separated ISO country codes for GeoIP filtering'],
    ['geoip_source_v4', 'https://www.ipdeny.com/ipblocks/data/aggregated/{cc}-aggregated.zone', 'IPv4 country zone URL template ({cc} = country code)'],
    ['geoip_source_v6', 'https://www.ipdeny.com/ipv6/ipaddresses/aggregated/{cc}-aggregated.zone', 'IPv6 country zone URL template'],
    ['open_signup_enabled', 'true', 'Allow self-signup (new users become viewers)'],
  ];
  try {
    for (const [key, value, description] of defaults) {
      await query(
        'INSERT IGNORE INTO system_settings (`key`, value, description, updated_at) VALUES (?, ?, ?, ?)',
        [key, value, description, now()]
      );
    }

    // Migrate the legacy ids_enabled boolean to the ips_mode tri-state.
    const existing = await query("SELECT value FROM system_settings WHERE `key` = 'ips_mode'");
    if (!existing.length) {
      const legacy = await query("SELECT value FROM system_settings WHERE `key` = 'ids_enabled'");
      const mode = legacy[0]?.value === 'true' ? 'ids' : 'off';
      await query(
        'INSERT IGNORE INTO system_settings (`key`, value, description, updated_at) VALUES (?, ?, ?, ?)',
        ['ips_mode', mode, 'Suricata mode: off, ids (detect), or ips (inline block)', now()]
      );
    }
  } catch (e) {
    console.error('ensureDefaultSettings failed:', e.message);
  }
}

// ─── Log retention ─────────────────────────────────────────────────────────
// Prunes high-volume tables per the log_retention_days system setting.
// Audit log and apply history are kept forever.

async function pruneOldLogs() {
  try {
    const rows = await query("SELECT value FROM system_settings WHERE `key` = 'log_retention_days'");
    const days = Math.max(1, parseInt(rows[0]?.value, 10) || 90);
    const tables = [
      ['firewall_logs', 'timestamp'],
      ['dns_logs', 'timestamp'],
      ['ids_alerts', 'timestamp'],
      ['app_flows', 'timestamp'],
      ['system_health_snapshots', 'recorded_at'],
    ];
    for (const [table, col] of tables) {
      const result = await getPool().execute(
        `DELETE FROM \`${table}\` WHERE \`${col}\` < DATE_SUB(NOW(), INTERVAL ? DAY)`,
        [days]
      );
      const affected = result[0]?.affectedRows || 0;
      if (affected) console.log(`Retention: pruned ${affected} rows from ${table} (>${days}d)`);
    }
  } catch (e) {
    console.error('Retention prune failed:', e.message);
  }
}

// ─── Threat feed refresh ────────────────────────────────────────────────────
// Downloads a feed, parses indicators, and atomically replaces the feed's
// stored indicators. Updates the feed's status/count/timestamp.

const FEED_MAX_BYTES = 16 * 1024 * 1024;

async function fetchFeedBody(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30000);
  try {
    const resp = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'HomeShield-NGFW/1.0' },
      redirect: 'follow',
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const text = await resp.text();
    if (text.length > FEED_MAX_BYTES) throw new Error('feed exceeds size limit');
    return text;
  } finally {
    clearTimeout(timer);
  }
}

async function refreshOneFeed(feed) {
  if (!feed.url) {
    await query("UPDATE threat_feeds SET last_status = 'error: no url', last_updated = ? WHERE id = ?", [now(), feed.id]);
    return { id: feed.id, status: 'error: no url', count: 0 };
  }
  try {
    const body = await fetchFeedBody(feed.url);
    const indicators = parseFeed(body, feed.feed_type);

    // Replace this feed's indicators atomically.
    const conn = await getPool().getConnection();
    try {
      await conn.beginTransaction();
      await conn.execute('DELETE FROM threat_indicators WHERE feed_id = ?', [feed.id]);
      const ts = now();
      for (let i = 0; i < indicators.length; i += 1000) {
        const chunk = indicators.slice(i, i + 1000);
        const placeholders = chunk.map(() => '(?, ?, ?, ?, ?)').join(', ');
        const values = [];
        for (const ind of chunk) {
          values.push(randomUUID(), feed.id, ind.indicator_type, ind.value, ts);
        }
        await conn.execute(
          `INSERT INTO threat_indicators (id, feed_id, indicator_type, value, created_at) VALUES ${placeholders}`,
          values
        );
      }
      await conn.commit();
    } catch (e) {
      await conn.rollback();
      throw e;
    } finally {
      conn.release();
    }

    await query(
      "UPDATE threat_feeds SET last_status = 'ok', last_updated = ?, indicator_count = ? WHERE id = ?",
      [now(), indicators.length, feed.id]
    );
    console.log(`Feed "${feed.name}": ${indicators.length} indicators`);
    return { id: feed.id, status: 'ok', count: indicators.length };
  } catch (e) {
    const status = `error: ${e.message}`.slice(0, 90);
    await query('UPDATE threat_feeds SET last_status = ?, last_updated = ? WHERE id = ?', [status, now(), feed.id]);
    console.error(`Feed "${feed.name}" refresh failed:`, e.message);
    return { id: feed.id, status, count: 0 };
  }
}

// Refreshes enabled feeds that are due based on refresh_interval_hours.
async function refreshDueFeeds() {
  try {
    const feeds = await query('SELECT * FROM threat_feeds WHERE enabled = 1');
    for (const feed of feeds) {
      const interval = Math.max(0, parseInt(feed.refresh_interval_hours, 10) || 0);
      const last = feed.last_updated ? new Date(feed.last_updated).getTime() : 0;
      const due = !last || Date.now() - last >= interval * 3600 * 1000;
      if (due) await refreshOneFeed(feed);
    }
  } catch (e) {
    console.error('refreshDueFeeds failed:', e.message);
  }
}

// ─── Start ─────────────────────────────────────────────────────────────────

autoMigrate().then(async () => {
  await ensureVpnTables();
  await ensureUserColumns();
  await ensureDefaultSettings();
  await loadAgentToken();
  pruneOldLogs();
  setInterval(pruneOldLogs, 24 * 60 * 60 * 1000);
  refreshDueFeeds();
  setInterval(refreshDueFeeds, 60 * 60 * 1000);
  app.listen(PORT, () => {
    console.log(`HomeShield running on port ${PORT}`);
    console.log(`DB: ${process.env.DB_HOST}/${process.env.DB_NAME}`);
    console.log(`dist/: ${existsSync(distDir) ? 'ready' : 'MISSING'}`);
    const tokenSrc = agentTokenIsEnvManaged() ? 'env' : (effectiveAgentToken() ? 'console-generated' : 'none');
    console.log(`Agent API: ${effectiveAgentToken() ? `enabled (${tokenSrc})` : 'disabled (generate a token in the console or set AGENT_TOKEN)'}`);
  });
});
