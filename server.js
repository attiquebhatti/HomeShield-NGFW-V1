import express from 'express';
import mysql from 'mysql2/promise';
import { createHmac, randomUUID, timingSafeEqual } from 'crypto';
import { existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';

const { hash, compare } = bcrypt;
const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '10mb' }));

// CORS
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

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

// ─── JWT ───────────────────────────────────────────────────────────────────

const JWT_SECRET = process.env.JWT_SECRET || 'changeme';

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

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password || password.length < 12)
      return res.status(400).json({ error: 'Password must be at least 12 characters' });

    const existing = await query('SELECT id FROM admin_users WHERE email = ? LIMIT 1', [email]);
    if (existing.length > 0)
      return res.status(409).json({ error: 'An account already exists. Please sign in.' });

    const passwordHash = await hash(password, 12);
    await query(
      'INSERT INTO admin_users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)',
      [randomUUID(), email, passwordHash, now()]
    );
    res.json({ message: 'Account created. Please sign in.' });
  } catch (e) {
    console.error('signup error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
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
    console.error('login error:', e);
    res.status(500).json({ error: e.message });
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

function safeName(name) { return name.replace(/[^a-z0-9_]/gi, ''); }

function prepareFields(data, bools = []) {
  const out = {};
  for (const [k, v] of Object.entries(data)) {
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
    console.error(`listRows ${resource}:`, e.message);
    res.status(500).json({ error: e.message });
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
    res.status(500).json({ error: e.message });
  }
}

async function insertRow(resource, body, res) {
  const table = TABLE_MAP[resource];
  if (!table) return res.status(404).json({ error: 'Unknown resource' });
  const bools = BOOL_FIELDS[resource] || [];
  try {
    const data = prepareFields(body, bools);
    if (!data.id) data.id = randomUUID();
    if (!data.created_at) data.created_at = now();

    const cols = Object.keys(data).map(c => `\`${safeName(c)}\``).join(', ');
    const placeholders = Object.keys(data).map(() => '?').join(', ');
    await query(`INSERT INTO \`${table}\` (${cols}) VALUES (${placeholders})`, Object.values(data));

    const rows = await query(`SELECT * FROM \`${table}\` WHERE id = ? LIMIT 1`, [data.id]);
    res.status(201).json({ data: castRow(rows[0]) });
  } catch (e) {
    console.error(`insertRow ${resource}:`, e.message);
    res.status(500).json({ error: e.message });
  }
}

async function updateRow(resource, id, body, res) {
  const table = TABLE_MAP[resource];
  if (!table) return res.status(404).json({ error: 'Unknown resource' });
  const bools = BOOL_FIELDS[resource] || [];
  try {
    const data = prepareFields(body, bools);
    delete data.id;
    delete data.created_at;
    if (!Object.keys(data).length) return res.status(400).json({ error: 'No fields to update' });

    const sets = Object.keys(data).map(c => `\`${safeName(c)}\` = ?`).join(', ');
    await query(`UPDATE \`${table}\` SET ${sets} WHERE id = ?`, [...Object.values(data), id]);

    const rows = await query(`SELECT * FROM \`${table}\` WHERE id = ? LIMIT 1`, [id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json({ data: castRow(rows[0]) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

async function deleteRow(resource, id, res) {
  const table = TABLE_MAP[resource];
  if (!table) return res.status(404).json({ error: 'Unknown resource' });
  try {
    await query(`DELETE FROM \`${table}\` WHERE id = ?`, [id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

// ─── Register CRUD routes ──────────────────────────────────────────────────

const CRUD_RESOURCES = [
  'firewall-policies', 'firewall-logs', 'dns-entries', 'dns-logs', 'ids-alerts',
  'threat-feeds', 'threat-indicators', 'network-interfaces', 'nat-rules',
  'audit-log', 'sessions', 'backup-records', 'rule-apply-history', 'system-health',
];

for (const resource of CRUD_RESOURCES) {
  api.get(`/${resource}`, (req, res) => listRows(resource, req, res));
  api.get(`/${resource}/:id`, (req, res) => getRow(resource, req.params.id, res));
  api.post(`/${resource}`, (req, res) => insertRow(resource, req.body, res));
  api.patch(`/${resource}/:id`, (req, res) => updateRow(resource, req.params.id, req.body, res));
  api.put(`/${resource}/:id`, (req, res) => updateRow(resource, req.params.id, req.body, res));
  api.delete(`/${resource}/:id`, (req, res) => deleteRow(resource, req.params.id, res));
}

// ─── Special routes ────────────────────────────────────────────────────────

api.post('/ids-alerts/acknowledge-many', async (req, res) => {
  try {
    const { ids } = req.body || {};
    if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ error: 'ids array required' });
    const placeholders = ids.map(() => '?').join(',');
    await query(`UPDATE ids_alerts SET acknowledged = 1 WHERE id IN (${placeholders})`, ids);
    res.json({ updated: ids.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

api.get('/system-settings', async (_req, res) => {
  try {
    const rows = await query('SELECT * FROM system_settings');
    res.json({ data: castRows(rows) });
  } catch (e) {
    res.status(500).json({ error: e.message });
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
    res.status(500).json({ error: e.message });
  }
});

// Mount the protected router
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

// ─── Start ─────────────────────────────────────────────────────────────────

autoMigrate().then(() => {
  app.listen(PORT, () => {
    console.log(`HomeShield running on port ${PORT}`);
    console.log(`DB: ${process.env.DB_HOST}/${process.env.DB_NAME}`);
    console.log(`dist/: ${existsSync(distDir) ? 'ready' : 'MISSING'}`);
  });
});
