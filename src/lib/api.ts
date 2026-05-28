/**
 * MySQL REST API client — replaces @supabase/supabase-js
 * All calls go through the Express backend at /api/
 */

const API_BASE = (import.meta.env.VITE_API_URL || '/api').replace(/\/$/, '');

export const apiConfigured = true;

// ─── Token storage ─────────────────────────────────────────────────────────

const TOKEN_KEY = 'hs_token';

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

// ─── Core fetch ────────────────────────────────────────────────────────────

async function apiFetch<T = unknown>(
  path: string,
  options: RequestInit = {}
): Promise<{ data: T | null; error: string | null; count?: number }> {
  const token = getToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  try {
    const res = await fetch(`${API_BASE}/${path}`, { ...options, headers });
    const json = await res.json();

    if (!res.ok) {
      return { data: null, error: json.error || `HTTP ${res.status}` };
    }

    if (Array.isArray(json.data)) {
      return { data: json.data as T, error: null, count: json.count ?? json.data.length };
    }
    if (json.data !== undefined) {
      return { data: json.data as T, error: null };
    }
    return { data: json as T, error: null };
  } catch (e: unknown) {
    return { data: null, error: e instanceof Error ? e.message : 'Network error' };
  }
}

// ─── Auth ──────────────────────────────────────────────────────────────────

export const auth = {
  async signIn(email: string, password: string) {
    const res = await apiFetch<{ token: string; user: { id: string; email: string } }>(
      'auth/login',
      { method: 'POST', body: JSON.stringify({ email, password }) }
    );
    if (res.data?.token) setToken(res.data.token);
    return res;
  },

  async signUp(email: string, password: string) {
    return apiFetch('auth/signup', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  },

  async getUser(): Promise<{ id: string; email: string } | null> {
    if (!getToken()) return null;
    const res = await apiFetch<{ user: { id: string; email: string } }>('auth/me');
    return res.data?.user ?? null;
  },

  signOut() {
    clearToken();
  },
};

// ─── Query builder (mimics Supabase chained API) ───────────────────────────

type QueryParams = Record<string, string | number | boolean | undefined>;

interface QueryResult<T> {
  data: T[] | null;
  count: number;
  error: string | null;
}

interface SingleResult<T> {
  data: T | null;
  error: string | null;
}

class Query<T> {
  private resource: string;
  private params: QueryParams = {};
  private _limit?: number;
  private _order?: string;
  private _orderDir: 'asc' | 'desc' = 'asc';
  private _rangeFrom?: number;
  private _rangeTo?: number;
  private _countExact = false;

  constructor(resource: string) {
    this.resource = resource;
  }

  eq(col: string, val: string | number | boolean) {
    this.params[col] = val;
    return this;
  }

  in(_col: string, _vals: string[]) { return this; }

  ilike(col: string, pattern: string) {
    this.params['search'] = pattern.replace(/%/g, '');
    return this;
  }

  or(filter: string) {
    const match = filter.match(/ilike\.%([^%]+)%/);
    if (match) this.params['search'] = match[1];
    return this;
  }

  order(col: string, opts?: { ascending?: boolean }) {
    this._order = col;
    this._orderDir = opts?.ascending === false ? 'desc' : 'asc';
    return this;
  }

  limit(n: number) {
    this._limit = n;
    return this;
  }

  range(from: number, to: number) {
    this._rangeFrom = from;
    this._rangeTo = to;
    return this;
  }

  select(_cols: string, opts?: { count?: string }) {
    if (opts?.count === 'exact') this._countExact = true;
    return this;
  }

  private buildUrl(id?: string): string {
    const parts: string[] = [this.resource];
    if (id) parts.push(id);

    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(this.params)) {
      if (v !== undefined) qs.set(k, String(v));
    }
    if (this._order) qs.set('order_col', this._order);
    if (this._orderDir) qs.set('order_dir', this._orderDir);
    if (this._limit) {
      qs.set('page_size', String(this._limit));
    } else if (this._rangeFrom !== undefined && this._rangeTo !== undefined) {
      const size = this._rangeTo - this._rangeFrom + 1;
      const page = Math.floor(this._rangeFrom / size);
      qs.set('page', String(page));
      qs.set('page_size', String(size));
    }

    const qStr = qs.toString();
    return `${parts.join('/')}${qStr ? '?' + qStr : ''}`;
  }

  async then<TResult>(
    resolve: (value: QueryResult<T>) => TResult
  ): Promise<TResult> {
    const url = this.buildUrl();
    const res = await apiFetch<T[]>(url);
    return resolve({
      data: res.data ?? null,
      count: res.count ?? 0,
      error: res.error,
    });
  }

  async maybeSingle(): Promise<SingleResult<T>> {
    const result = await apiFetch<T[]>(this.buildUrl());
    const rows = result.data ?? [];
    return { data: rows[0] ?? null, error: result.error };
  }
}

// ─── Table client ─────────────────────────────────────────────────────────

class Table<T> {
  private resource: string;

  constructor(resource: string) {
    this.resource = resource;
  }

  select(_cols?: string, opts?: { count?: string }): Query<T> {
    const q = new Query<T>(this.resource);
    if (opts?.count === 'exact') q.select('*', opts);
    return q;
  }

  async insert(record: Partial<T> | Partial<T>[]): Promise<SingleResult<T>> {
    const body = Array.isArray(record) ? record[0] : record;
    return apiFetch<T>(this.resource, {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  update(fields: Partial<T>) {
    return {
      eq: async (col: string, val: string): Promise<SingleResult<T>> => {
        if (col !== 'id') return { data: null, error: 'Only id filtering supported for updates' };
        return apiFetch<T>(`${this.resource}/${val}`, {
          method: 'PATCH',
          body: JSON.stringify(fields),
        });
      },
      in: async (_col: string, vals: string[]): Promise<{ error: string | null }> => {
        if (this.resource === 'ids-alerts') {
          const r = await apiFetch(`${this.resource}/acknowledge-many`, {
            method: 'POST',
            body: JSON.stringify({ ids: vals }),
          });
          return { error: r.error };
        }
        return { error: null };
      },
    };
  }

  async upsert(
    records: Partial<T> | Partial<T>[],
    _opts?: { onConflict?: string }
  ): Promise<{ error: string | null }> {
    const items = Array.isArray(records) ? records : [records];
    if (this.resource === 'system-settings') {
      const r = await apiFetch(this.resource, {
        method: 'POST',
        body: JSON.stringify({ items }),
      });
      return { error: r.error };
    }
    for (const item of items) {
      await apiFetch<T>(this.resource, {
        method: 'POST',
        body: JSON.stringify(item),
      });
    }
    return { error: null };
  }

  delete() {
    return {
      eq: async (col: string, val: string): Promise<{ error: string | null }> => {
        if (col !== 'id') return { error: 'Only id filtering supported for deletes' };
        const r = await apiFetch(`${this.resource}/${val}`, { method: 'DELETE' });
        return { error: r.error };
      },
    };
  }
}

// ─── Resource name map ─────────────────────────────────────────────────────

const TABLE_MAP: Record<string, string> = {
  firewall_policies: 'firewall-policies',
  firewall_logs: 'firewall-logs',
  dns_entries: 'dns-entries',
  dns_logs: 'dns-logs',
  ids_alerts: 'ids-alerts',
  threat_feeds: 'threat-feeds',
  threat_indicators: 'threat-indicators',
  network_interfaces: 'network-interfaces',
  nat_rules: 'nat-rules',
  system_settings: 'system-settings',
  audit_log: 'audit-log',
  sessions: 'sessions',
  backup_records: 'backup-records',
  rule_apply_history: 'rule-apply-history',
  system_health_snapshots: 'system-health',
};

// ─── Main export ──────────────────────────────────────────────────────────

export const api = {
  from<T = Record<string, unknown>>(tableName: string): Table<T> {
    const resource = TABLE_MAP[tableName] ?? tableName.replace(/_/g, '-');
    return new Table<T>(resource);
  },
  auth,
};
