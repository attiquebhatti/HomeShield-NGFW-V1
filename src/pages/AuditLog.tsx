import { useEffect, useState, useCallback } from 'react';
import { RefreshCw, Search, ChevronLeft, ChevronRight } from 'lucide-react';
import { supabase } from '../lib/supabase';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import type { AuditEntry } from '../lib/database.types';

const PAGE_SIZE = 30;

const actionVariant: Record<string, 'success' | 'danger' | 'warning' | 'info' | 'neutral'> = {
  create: 'success',
  delete: 'danger',
  update: 'warning',
  apply: 'info',
  import: 'info',
  login: 'neutral',
  logout: 'neutral',
};

export function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [count, setCount] = useState(0);
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState('');

  const fetchEntries = useCallback(async () => {
    let query = supabase
      .from('audit_log')
      .select('*', { count: 'exact' })
      .order('timestamp', { ascending: false })
      .range(page * PAGE_SIZE, (page + 1) * PAGE_SIZE - 1);

    if (search) query = query.or(`actor.ilike.%${search}%,action.ilike.%${search}%,resource_type.ilike.%${search}%`);

    const { data, count: total } = await query;
    setEntries(data ?? []);
    setCount(total ?? 0);
    setLoading(false);
  }, [page, search]);

  useEffect(() => { setLoading(true); fetchEntries(); }, [fetchEntries]);

  const totalPages = Math.ceil(count / PAGE_SIZE);

  return (
    <div className="p-4 lg:p-6 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-text-primary">Audit Log</h1>
          <p className="text-sm text-text-muted mt-0.5">Immutable record of all configuration changes</p>
        </div>
        <Button variant="ghost" size="sm" onClick={fetchEntries}><RefreshCw className="w-3.5 h-3.5" /></Button>
      </div>

      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
        <input
          className="w-full bg-brand-panel border border-border-muted rounded-lg pl-9 pr-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-brand-gold/50 focus:ring-1 focus:ring-brand-gold/20 transition-all"
          placeholder="Search by actor, action, resource..."
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(0); }}
        />
      </div>

      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border-muted">
                <th className="px-4 py-3 text-left text-text-muted font-medium">Timestamp</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">Actor</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">Action</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">Resource</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">Details</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">IP</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={6} className="px-4 py-12 text-center text-text-muted">Loading...</td></tr>
              ) : entries.length === 0 ? (
                <tr><td colSpan={6} className="px-4 py-12 text-center text-text-muted">No audit entries found</td></tr>
              ) : entries.map(entry => (
                <tr key={entry.id} className="border-b border-border-muted/50 hover:bg-brand-slate/30 transition-colors">
                  <td className="px-4 py-2.5 text-text-muted whitespace-nowrap">{new Date(entry.timestamp).toLocaleString()}</td>
                  <td className="px-4 py-2.5 text-text-secondary font-medium">{entry.actor}</td>
                  <td className="px-4 py-2.5"><Badge variant={actionVariant[entry.action] ?? 'neutral'}>{entry.action}</Badge></td>
                  <td className="px-4 py-2.5 text-text-muted">{entry.resource_type}</td>
                  <td className="px-4 py-2.5 text-text-muted max-w-xs truncate font-mono">
                    {typeof entry.details === 'object' ? JSON.stringify(entry.details) : String(entry.details)}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-text-muted">{entry.ip_address || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="flex items-center justify-between px-4 py-3 border-t border-border-muted">
          <span className="text-xs text-text-muted">
            {count === 0 ? 'No results' : `${page * PAGE_SIZE + 1}–${Math.min((page + 1) * PAGE_SIZE, count)} of ${count.toLocaleString()}`}
          </span>
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" onClick={() => setPage(p => p - 1)} disabled={page === 0}><ChevronLeft className="w-4 h-4" /></Button>
            <span className="text-xs text-text-muted">Page {page + 1} / {totalPages || 1}</span>
            <Button variant="ghost" size="sm" onClick={() => setPage(p => p + 1)} disabled={page >= totalPages - 1}><ChevronRight className="w-4 h-4" /></Button>
          </div>
        </div>
      </Card>
    </div>
  );
}
