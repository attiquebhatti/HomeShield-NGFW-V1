import { useEffect, useState } from 'react';
import { RefreshCw, ArrowUpRight, ArrowDownLeft, Activity } from 'lucide-react';
import { api } from '../lib/api';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import type { Session } from '../lib/database.types';

function formatBytes(b: number) {
  if (!b) return '0 B';
  const k = 1024, s = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(b) / Math.log(k));
  return `${parseFloat((b / Math.pow(k, i)).toFixed(1))} ${s[i]}`;
}

function duration(started: string, last: string) {
  const ms = new Date(last).getTime() - new Date(started).getTime();
  if (ms < 1000) return '<1s';
  if (ms < 60000) return `${Math.floor(ms / 1000)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`;
}

export function Sessions() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  async function fetchSessions() {
    setLoading(true);
    const { data } = await api.from<Session>('sessions').select('*').order('last_seen', { ascending: false }).limit(100);
    setSessions(data ?? []);
    setLoading(false);
  }

  useEffect(() => { fetchSessions(); }, []);

  const filtered = sessions.filter(s =>
    !search || s.src_ip.includes(search) || s.dst_ip.includes(search) || s.application?.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="p-4 lg:p-6 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-text-primary">Sessions</h1>
          <p className="text-sm text-text-muted mt-0.5">{sessions.length} tracked connections</p>
        </div>
        <Button variant="ghost" size="sm" onClick={fetchSessions}><RefreshCw className="w-3.5 h-3.5" /> Refresh</Button>
      </div>

      <div className="relative">
        <Activity className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
        <input className="w-full bg-brand-panel border border-border-muted rounded-lg pl-9 pr-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-brand-gold/50 focus:ring-1 focus:ring-brand-gold/20 transition-all" placeholder="Filter by IP or application..." value={search} onChange={e => setSearch(e.target.value)} />
      </div>

      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border-muted">
                <th className="px-4 py-3 text-left text-text-muted font-medium">Source</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">Destination</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">Proto</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">App</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">State</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">Interface</th>
                <th className="px-4 py-3 text-left text-text-muted font-medium">Duration</th>
                <th className="px-4 py-3 text-right text-text-muted font-medium">In / Out</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={8} className="px-4 py-12 text-center text-text-muted">Loading sessions...</td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={8} className="px-4 py-12 text-center text-text-muted">No sessions found</td></tr>
              ) : filtered.map(sess => (
                <tr key={sess.id} className="border-b border-border-muted/40 hover:bg-brand-slate/30 transition-colors">
                  <td className="px-4 py-2.5 font-mono text-text-secondary">{sess.src_ip}:{sess.src_port ?? '—'}</td>
                  <td className="px-4 py-2.5 font-mono text-text-secondary">{sess.dst_ip}:{sess.dst_port ?? '—'}</td>
                  <td className="px-4 py-2.5 text-text-muted uppercase">{sess.protocol}</td>
                  <td className="px-4 py-2.5 text-text-muted">{sess.application || '—'}</td>
                  <td className="px-4 py-2.5">
                    <Badge variant={sess.state === 'established' ? 'success' : sess.state === 'time_wait' ? 'warning' : 'neutral'}>{sess.state}</Badge>
                  </td>
                  <td className="px-4 py-2.5 text-text-muted">{sess.interface || '—'}</td>
                  <td className="px-4 py-2.5 text-text-muted">{duration(sess.started_at, sess.last_seen)}</td>
                  <td className="px-4 py-2.5 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <span className="flex items-center gap-1 text-success"><ArrowDownLeft className="w-3 h-3" />{formatBytes(sess.bytes_in)}</span>
                      <span className="text-text-muted/60">/</span>
                      <span className="flex items-center gap-1 text-info"><ArrowUpRight className="w-3 h-3" />{formatBytes(sess.bytes_out)}</span>
                    </div>
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
