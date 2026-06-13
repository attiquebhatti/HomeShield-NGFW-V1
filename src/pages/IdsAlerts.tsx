import { useEffect, useState } from 'react';
import { CheckCheck, RefreshCw, Search } from 'lucide-react';
import { api } from '../lib/api';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import type { IdsAlert } from '../lib/database.types';

const severityVariant: Record<string, 'danger' | 'warning' | 'info' | 'neutral'> = {
  critical: 'danger',
  high: 'danger',
  medium: 'warning',
  low: 'info',
};

const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

const verdict: Record<string, { label: string; variant: 'danger' | 'warning' | 'neutral' }> = {
  drop: { label: 'blocked', variant: 'danger' },
  alert: { label: 'detected', variant: 'warning' },
  pass: { label: 'passed', variant: 'neutral' },
};

function timeAgo(ts: string) {
  const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return new Date(ts).toLocaleDateString();
}

export function IdsAlerts() {
  const [alerts, setAlerts] = useState<IdsAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [showAcked, setShowAcked] = useState(false);

  async function fetchAlerts() {
    const { data } = await api
      .from<IdsAlert>('ids_alerts')
      .select('*')
      .order('timestamp', { ascending: false })
      .limit(200);
    setAlerts(data ?? []);
    setLoading(false);
  }

  useEffect(() => { fetchAlerts(); }, []);

  async function acknowledge(id: string) {
    await api.from('ids_alerts').update({ acknowledged: true }).eq('id', id);
    fetchAlerts();
  }

  async function acknowledgeAll() {
    const ids = filtered.filter(a => !a.acknowledged).map(a => a.id);
    await api.from('ids_alerts').update({ acknowledged: true }).in('id', ids);
    fetchAlerts();
  }

  const filtered = alerts.filter(a => {
    if (!showAcked && a.acknowledged) return false;
    if (filterSeverity !== 'all' && a.severity !== filterSeverity) return false;
    if (search && !a.signature_name.toLowerCase().includes(search.toLowerCase()) &&
      !a.src_ip?.includes(search) && !a.dst_ip?.includes(search)) return false;
    return true;
  }).sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  const unacked = alerts.filter(a => !a.acknowledged).length;
  const blocked = alerts.filter(a => a.action === 'drop').length;

  return (
    <div className="p-4 lg:p-6 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-text-primary">IDS / IPS Alerts</h1>
          <p className="text-sm text-text-muted mt-0.5">
            {unacked} unacknowledged · {blocked} blocked · Suricata
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={fetchAlerts}><RefreshCw className="w-3.5 h-3.5" /></Button>
          {unacked > 0 && (
            <Button variant="secondary" size="sm" onClick={acknowledgeAll}>
              <CheckCheck className="w-3.5 h-3.5" /> Acknowledge All
            </Button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-4 gap-3">
        {(['critical', 'high', 'medium', 'low'] as const).map(sev => {
          const count = alerts.filter(a => a.severity === sev && !a.acknowledged).length;
          return (
            <button
              key={sev}
              onClick={() => setFilterSeverity(filterSeverity === sev ? 'all' : sev)}
              className={`p-3 rounded-xl border text-left transition-all ${
                filterSeverity === sev ? 'border-brand-gold/50 bg-brand-gold/10' : 'border-border-muted bg-brand-panel hover:border-border-active'
              }`}
            >
              <div className="text-lg font-bold text-text-primary">{count}</div>
              <div className="flex items-center gap-1.5 mt-0.5">
                <Badge variant={severityVariant[sev]}>{sev}</Badge>
              </div>
            </button>
          );
        })}
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-48">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
          <input
            className="w-full bg-brand-panel border border-border-muted rounded-lg pl-9 pr-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-brand-gold/50 focus:ring-1 focus:ring-brand-gold/20 transition-all"
            placeholder="Search signatures, IPs..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <label className="flex items-center gap-2 cursor-pointer text-sm text-text-muted">
          <input type="checkbox" className="w-4 h-4 accent-brand-gold" checked={showAcked} onChange={e => setShowAcked(e.target.checked)} />
          Show acknowledged
        </label>
      </div>

      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border-muted">
                <th className="px-4 py-3 text-left text-text-muted font-medium">Severity</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">Signature</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">Category</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">Source</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">Destination</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">Proto</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">Verdict</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">Time</th>
                <th className="px-4 py-3 text-right text-text-muted font-medium">Action</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={9} className="px-4 py-12 text-center text-text-muted">Loading alerts...</td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={9} className="px-4 py-12 text-center text-text-muted">No alerts found</td></tr>
              ) : filtered.map(alert => (
                <tr
                  key={alert.id}
                  className={`border-b border-border-muted/50 hover:bg-brand-slate/30 transition-colors ${alert.acknowledged ? 'opacity-40' : ''}`}
                >
                  <td className="px-4 py-3">
                    <Badge variant={severityVariant[alert.severity] ?? 'neutral'}>{alert.severity}</Badge>
                  </td>
                  <td className="px-4 py-3">
                    <div className="font-medium text-text-primary max-w-xs truncate">{alert.signature_name}</div>
                    {alert.signature_id && <div className="text-text-muted mt-0.5">SID: {alert.signature_id}</div>}
                  </td>
                  <td className="px-4 py-3 text-text-muted max-w-36 truncate">{alert.category || '—'}</td>
                  <td className="px-4 py-3 font-mono text-text-secondary">{alert.src_ip ?? '—'}:{alert.src_port ?? '—'}</td>
                  <td className="px-4 py-3 font-mono text-text-secondary">{alert.dst_ip ?? '—'}:{alert.dst_port ?? '—'}</td>
                  <td className="px-4 py-3 text-text-muted uppercase">{alert.protocol ?? '—'}</td>
                  <td className="px-4 py-3">
                    <Badge variant={verdict[alert.action]?.variant ?? 'neutral'}>
                      {verdict[alert.action]?.label ?? alert.action}
                    </Badge>
                  </td>
                  <td className="px-4 py-3 text-text-muted whitespace-nowrap">{timeAgo(alert.timestamp)}</td>
                  <td className="px-4 py-3 text-right">
                    {!alert.acknowledged && (
                      <button
                        onClick={() => acknowledge(alert.id)}
                        className="text-xs px-2 py-1 rounded-lg bg-brand-slate hover:bg-brand-steel text-text-secondary transition-colors"
                      >
                        Ack
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
