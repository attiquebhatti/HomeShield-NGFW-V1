import { useEffect, useState, useCallback } from 'react';
import { Search, RefreshCw, ArrowUpRight, ArrowDownLeft, ChevronLeft, ChevronRight } from 'lucide-react';
import { api } from '../lib/api';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import type { FirewallLog } from '../lib/database.types';

const PAGE_SIZE = 25;

function formatBytes(b: number) {
  if (!b) return '0 B';
  const k = 1024, sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(b) / Math.log(k));
  return `${parseFloat((b / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

function formatTime(ts: string) {
  return new Date(ts).toLocaleString();
}

const actionVariant: Record<string, 'success' | 'danger' | 'warning' | 'info'> = {
  allow: 'success',
  deny: 'danger',
  reject: 'danger',
  'log-only': 'info',
};

export function Logs() {
  const [logs, setLogs] = useState<FirewallLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [count, setCount] = useState(0);
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState('');
  const [filterAction, setFilterAction] = useState('all');
  const [filterProto, setFilterProto] = useState('all');
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchLogs = useCallback(async () => {
    let query = api
      .from<FirewallLog>('firewall_logs')
      .select('*', { count: 'exact' })
      .order('timestamp', { ascending: false })
      .range(page * PAGE_SIZE, (page + 1) * PAGE_SIZE - 1);

    if (filterAction !== 'all') query = query.eq('action', filterAction);
    if (filterProto !== 'all') query = query.eq('protocol', filterProto);
    if (search) query = query.or(`src_ip.ilike.%${search}%,dst_ip.ilike.%${search}%,policy_name.ilike.%${search}%`);

    const { data, count: total } = await query;
    setLogs(data ?? []);
    setCount(total ?? 0);
    setLoading(false);
  }, [page, filterAction, filterProto, search]);

  useEffect(() => { setLoading(true); fetchLogs(); }, [fetchLogs]);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(fetchLogs, 10000);
    return () => clearInterval(interval);
  }, [autoRefresh, fetchLogs]);

  const totalPages = Math.ceil(count / PAGE_SIZE);

  return (
    <div className="p-4 lg:p-6 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-text-primary">Traffic Logs</h1>
          <p className="text-sm text-text-muted mt-0.5">{count.toLocaleString()} total events</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant={autoRefresh ? 'success' : 'secondary'} size="sm" onClick={() => setAutoRefresh(!autoRefresh)}>
            <RefreshCw className={`w-3.5 h-3.5 ${autoRefresh ? 'animate-spin' : ''}`} />
            {autoRefresh ? 'Live' : 'Paused'}
          </Button>
          <Button variant="ghost" size="sm" onClick={fetchLogs}>
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </Button>
        </div>
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-48">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
          <input
            className="w-full bg-brand-panel border border-border-muted rounded-lg pl-9 pr-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-brand-gold/50 focus:ring-1 focus:ring-brand-gold/20 transition-all"
            placeholder="Filter by IP, rule name..."
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(0); }}
          />
        </div>
        <select className="bg-brand-panel border border-border-muted rounded-lg px-3 py-2 text-sm text-text-secondary focus:outline-none focus:border-brand-gold/50 focus:ring-1 focus:ring-brand-gold/20" value={filterAction} onChange={e => { setFilterAction(e.target.value); setPage(0); }}>
          <option value="all">All Actions</option>
          <option value="allow">Allow</option>
          <option value="deny">Deny</option>
          <option value="reject">Reject</option>
          <option value="log-only">Log Only</option>
        </select>
        <select className="bg-brand-panel border border-border-muted rounded-lg px-3 py-2 text-sm text-text-secondary focus:outline-none focus:border-brand-gold/50 focus:ring-1 focus:ring-brand-gold/20" value={filterProto} onChange={e => { setFilterProto(e.target.value); setPage(0); }}>
          <option value="all">All Protocols</option>
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
          <option value="icmp">ICMP</option>
        </select>
      </div>

      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border-muted">
                <th className="px-4 py-3 text-left text-text-muted font-medium">Timestamp</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">Action</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">Direction</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">Source</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">Destination</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">Proto</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">Interface</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">Rule</th>
                <th className="px-4 py-3 text-right text-text-muted font-medium">Bytes</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={9} className="px-4 py-12 text-center text-text-muted">Loading logs...</td></tr>
              ) : logs.length === 0 ? (
                <tr><td colSpan={9} className="px-4 py-12 text-center text-text-muted">No log entries found</td></tr>
              ) : logs.map(log => (
                <tr key={log.id} className="border-b border-border-muted/40 hover:bg-brand-slate/30 transition-colors">
                  <td className="px-4 py-2.5 text-text-muted whitespace-nowrap">{formatTime(log.timestamp)}</td>
                  <td className="px-4 py-2.5"><Badge variant={actionVariant[log.action] ?? 'neutral'}>{log.action}</Badge></td>
                  <td className="px-4 py-2.5">
                    {log.direction === 'inbound'
                      ? <span className="flex items-center gap-1 text-info"><ArrowDownLeft className="w-3 h-3" />in</span>
                      : log.direction === 'outbound'
                      ? <span className="flex items-center gap-1 text-warning"><ArrowUpRight className="w-3 h-3" />out</span>
                      : <span className="text-text-muted">{log.direction}</span>
                    }
                  </td>
                  <td className="px-4 py-2.5 font-mono text-text-secondary">{log.src_ip ?? '—'}{log.src_port ? `:${log.src_port}` : ''}</td>
                  <td className="px-4 py-2.5 font-mono text-text-secondary">{log.dst_ip ?? '—'}{log.dst_port ? `:${log.dst_port}` : ''}</td>
                  <td className="px-4 py-2.5 text-text-muted uppercase">{log.protocol ?? '—'}</td>
                  <td className="px-4 py-2.5 text-text-muted">{log.interface ?? '—'}</td>
                  <td className="px-4 py-2.5 text-text-muted max-w-32 truncate">{log.policy_name ?? '—'}</td>
                  <td className="px-4 py-2.5 text-right text-text-muted">{formatBytes(log.bytes)}</td>
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
