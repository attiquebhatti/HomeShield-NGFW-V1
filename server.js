import express from 'express';
import mysql from 'mysql2/promise';
import { createHmac, randomUUID, randomBytes, timingSafeEqual } from 'crypto';
import { existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';

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

// Signup is only open while no admin account exists (first-run setup).
app.post('/api/auth/signup', authRateLimit, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password || password.length < 12)
      return res.status(400).json({ error: 'Password must be at least 12 characters' });

    const existing = await query('SELECT id FROM admin_users LIMIT 1');
    if (existing.length > 0)
      return res.status(403).json({ error: 'Signup is disabled — an admin account already exists. Please sign in.' });

    const passwordHash = await hash(password, 12);
    await query(
      'INSERT INTO admin_users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)',
      [randomUUID(), email, passwordHash, now()]
    );
    res.json({ message: 'Account created. Please sign in.' });
  } catch (e) {
    serverError(res, 'signup', e);
  }
});

app.post('/api/auth/login', authRateLimit, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required' });

    const rows = await query('SELECT id, email, password_hash FROM admin_users WHERE email = ? LIMIT 1', [email]);
    if (!rows.length || !(await compare(password, rows[0].password_hash)))
      return res.status(401).json({ error: 'Invalid email or password' });

    const user = { id: rows[0].id, email: rows[0].email };
    res.json({ token: jwtSign(user), user });
  } catch (e) {
    serverError(res, 'login', e);
  }
});

// ─── Protected routes (require auth) ──────────────────────────────────────

const api = express.Router();
api.use(authMiddleware);

api.get('/auth/me', (req, res) => {
  res.json({ user: { id: req.user.id, email: req.user.email } });
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
};

const SEARCH_COLS = {
  'firewall-policies': ['name', 'src_ip', 'dst_ip'],
  'firewall-logs': ['src_ip', 'dst_ip', 'policy_name'],
  'dns-entries': ['domain'],
  'dns-logs': ['domain', 'client_ip'],
  'ids-alerts': ['signature_name', 'src_ip', 'dst_ip'],
  'audit-log': ['actor', 'action', 'resource_type'],
  'sessions': ['src_ip', 'dst_ip', 'application'],
};

const FILTER_COLS = {
  'firewall-policies': ['action', 'enabled'],
  'firewall-logs': ['action', 'protocol'],
  'dns-entries': ['list_type'],
  'ids-alerts': ['severity', 'acknowledged'],
  'dns-logs': ['action'],
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
// with a shared secret (AGENT_TOKEN env var) instead of a user JWT. If
// AGENT_TOKEN is not set, these endpoints are disabled.

const AGENT_TOKEN = process.env.AGENT_TOKEN || '';
const agent = express.Router();

agent.use((req, res, next) => {
  if (!AGENT_TOKEN) return res.status(503).json({ error: 'Agent API disabled — set AGENT_TOKEN' });
  const token = req.headers['x-agent-token'] || '';
  const a = Buffer.from(String(token));
  const b = Buffer.from(AGENT_TOKEN);
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
      "SELECT `key`, value FROM system_settings WHERE `key` IN ('dns_filtering_enabled', 'dns_upstream')"
    );
    const map = Object.fromEntries(settings.map(r => [r.key, r.value]));
    const entries = await query(
      'SELECT domain, list_type, category FROM dns_entries WHERE enabled = 1'
    );
    res.json({
      data: {
        enabled: map.dns_filtering_enabled === 'true',
        upstream: map.dns_upstream || '1.1.1.1',
        entries: castRows(entries),
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

// Inserts any missing default settings on existing databases (auto-migrate
// only runs the full schema on first install).
async function ensureDefaultSettings() {
  const defaults = [
    ['dns_upstream', '1.1.1.1', 'Upstream DNS resolver for the filtering proxy'],
  ];
  try {
    for (const [key, value, description] of defaults) {
      await query(
        'INSERT IGNORE INTO system_settings (`key`, value, description, updated_at) VALUES (?, ?, ?, ?)',
        [key, value, description, now()]
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

// ─── Start ─────────────────────────────────────────────────────────────────

autoMigrate().then(() => {
  ensureDefaultSettings();
  pruneOldLogs();
  setInterval(pruneOldLogs, 24 * 60 * 60 * 1000);
  app.listen(PORT, () => {
    console.log(`HomeShield running on port ${PORT}`);
    console.log(`DB: ${process.env.DB_HOST}/${process.env.DB_NAME}`);
    console.log(`dist/: ${existsSync(distDir) ? 'ready' : 'MISSING'}`);
    console.log(`Agent API: ${AGENT_TOKEN ? 'enabled' : 'disabled (set AGENT_TOKEN to enable)'}`);
  });
});
