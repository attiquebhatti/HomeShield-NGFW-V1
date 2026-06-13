import { useEffect, useState } from 'react';
import { RefreshCw, Search, AppWindow } from 'lucide-react';
import { api } from '../lib/api';
import { Card, CardHeader, CardBody } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import type { AppFlow, AppStat } from '../lib/database.types';

const categoryVariant: Record<string, 'info' | 'warning' | 'success' | 'danger' | 'neutral'> = {
  streaming: 'info', social: 'warning', messaging: 'success', gaming: 'danger',
  conferencing: 'info', p2p: 'danger', cloud: 'neutral', web: 'neutral',
};

function fmtBytes(n: number) {
  if (!n) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
}

function timeAgo(ts: string) {
  const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return new Date(ts).toLocaleDateString();
}

const WINDOWS = [
  { label: '1h', hours: 1 },
  { label: '24h', hours: 24 },
  { label: '7d', hours: 168 },
];

export function Applications() {
  const [stats, setStats] = useState<AppStat[]>([]);
  const [categories, setCategories] = useState<{ category: string; flows: number; bytes: number }[]>([]);
  const [flows, setFlows] = useState<AppFlow[]>([]);
  const [hours, setHours] = useState(24);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);

  async function fetchData() {
    setLoading(true);
    const [s, f] = await Promise.all([
      api.get<{ apps: AppStat[]; categories: { category: string; flows: number; bytes: number }[] }>(`app-flows/stats?hours=${hours}`),
      api.get<AppFlow[]>('app-flows?page_size=100'),
    ]);
    setStats(s.data?.apps ?? []);
    setCategories(s.data?.categories ?? []);
    setFlows(f.data ?? []);
    setLoading(false);
  }

  useEffect(() => { fetchData(); /* eslint-disable-next-line */ }, [hours]);

  const maxFlows = Math.max(1, ...stats.map(s => s.flows));
  const filteredFlows = flows.filter(f =>
    !search || f.application.toLowerCase().includes(search.toLowerCase()) || f.hostname.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="p-4 lg:p-6 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-text-primary">Applications</h1>
          <p className="text-sm text-text-muted mt-0.5">
            {stats.length} applications identified · last {hours >= 24 ? `${hours / 24}d` : `${hours}h`}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex rounded-lg border border-border-muted overflow-hidden">
            {WINDOWS.map(w => (
              <button key={w.hours} onClick={() => setHours(w.hours)}
                className={`px-3 py-1.5 text-xs transition-colors ${hours === w.hours ? 'bg-brand-gold/15 text-brand-gold' : 'text-text-muted hover:bg-brand-slate'}`}>
                {w.label}
              </button>
            ))}
          </div>
          <Button variant="ghost" size="sm" onClick={fetchData}><RefreshCw className="w-3.5 h-3.5" /></Button>
        </div>
      </div>

      {/* Category summary */}
      {categories.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {categories.map(c => (
            <div key={c.category} className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-brand-panel border border-border-muted">
              <Badge variant={categoryVariant[c.category] ?? 'neutral'}>{c.category}</Badge>
              <span className="text-xs text-text-muted">{c.flows.toLocaleString()} flows</span>
            </div>
          ))}
        </div>
      )}

      {/* Top applications */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <AppWindow className="w-4 h-4 text-brand-gold" />
            <span className="font-semibold text-text-primary">Top Applications</span>
          </div>
        </CardHeader>
        <CardBody>
          {loading ? (
            <div className="py-8 text-center text-text-muted text-sm">Loading...</div>
          ) : stats.length === 0 ? (
            <div className="py-8 text-center text-text-muted text-sm">
              No application traffic identified yet. App-ID needs the agent running (DNS-based)
              and, for full SNI/protocol visibility, Suricata enabled.
            </div>
          ) : (
            <div className="space-y-2.5">
              {stats.slice(0, 25).map(s => (
                <div key={`${s.application}-${s.category}`} className="flex items-center gap-3">
                  <div className="w-40 flex-shrink-0 flex items-center gap-2 min-w-0">
                    <span className="text-sm text-text-primary font-medium truncate">{s.application}</span>
                  </div>
                  <div className="flex-1 h-5 bg-brand-panel-soft rounded overflow-hidden">
                    <div className="h-full bg-brand-gold/30 rounded flex items-center px-2"
                      style={{ width: `${Math.max(4, (s.flows / maxFlows) * 100)}%` }}>
                    </div>
                  </div>
                  <div className="w-16 text-right text-xs text-text-secondary flex-shrink-0">{s.flows.toLocaleString()}</div>
                  <div className="w-20 text-right text-xs text-text-muted flex-shrink-0">{fmtBytes(s.bytes)}</div>
                  <Badge variant={categoryVariant[s.category] ?? 'neutral'}>{s.category}</Badge>
                </div>
              ))}
            </div>
          )}
        </CardBody>
      </Card>

      {/* Recent flows */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <span className="font-semibold text-text-primary">Recent Flows</span>
            <div className="relative w-56">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-muted" />
              <input className="w-full bg-brand-panel border border-border-muted rounded-lg pl-9 pr-3 py-1.5 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:border-brand-gold/50"
                placeholder="App or hostname..." value={search} onChange={e => setSearch(e.target.value)} />
            </div>
          </div>
        </CardHeader>
        <CardBody>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border-muted text-text-muted">
                  <th className="px-3 py-2 text-left font-medium">Application</th>
                  <th className="px-3 py-2 text-left font-medium">Hostname / SNI</th>
                  <th className="px-3 py-2 text-left font-medium">Client</th>
                  <th className="px-3 py-2 text-left font-medium">Proto</th>
                  <th className="px-3 py-2 text-left font-medium">Source</th>
                  <th className="px-3 py-2 text-right font-medium">Bytes</th>
                  <th className="px-3 py-2 text-right font-medium">Time</th>
                </tr>
              </thead>
              <tbody>
                {filteredFlows.length === 0 ? (
                  <tr><td colSpan={7} className="px-3 py-8 text-center text-text-muted">No flows</td></tr>
                ) : filteredFlows.map(f => (
                  <tr key={f.id} className="border-b border-border-muted/50 hover:bg-brand-slate/30">
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-2">
                        <span className="text-text-primary font-medium">{f.application}</span>
                        <Badge variant={categoryVariant[f.category] ?? 'neutral'}>{f.category}</Badge>
                      </div>
                    </td>
                    <td className="px-3 py-2 font-mono text-text-secondary max-w-xs truncate">{f.hostname || '—'}</td>
                    <td className="px-3 py-2 font-mono text-text-muted">{f.client_ip ?? '—'}</td>
                    <td className="px-3 py-2 text-text-muted uppercase">{f.app_proto || f.protocol || '—'}</td>
                    <td className="px-3 py-2 text-text-muted">{f.source}</td>
                    <td className="px-3 py-2 text-right text-text-muted">{fmtBytes(f.bytes)}</td>
                    <td className="px-3 py-2 text-right text-text-muted whitespace-nowrap">{timeAgo(f.timestamp)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardBody>
      </Card>
    </div>
  );
}
