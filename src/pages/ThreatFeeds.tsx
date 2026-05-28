import { useEffect, useState } from 'react';
import { Plus, Trash2, Rss, ToggleRight, ToggleLeft, Clock } from 'lucide-react';
import { supabase } from '../lib/supabase';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Modal } from '../components/ui/Modal';
import { StatusDot } from '../components/ui/StatusDot';
import type { ThreatFeed } from '../lib/database.types';

function timeAgo(ts: string | null) {
  if (!ts) return 'never';
  const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

const empty: Omit<ThreatFeed, 'id' | 'created_at'> = {
  name: '',
  description: '',
  url: '',
  feed_type: 'ip',
  enabled: true,
  last_updated: null,
  last_status: 'pending',
  indicator_count: 0,
  refresh_interval_hours: 24,
};

export function ThreatFeeds() {
  const [feeds, setFeeds] = useState<ThreatFeed[]>([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [form, setForm] = useState<typeof empty>(empty);

  async function fetchFeeds() {
    const { data } = await supabase.from('threat_feeds').select('*').order('created_at', { ascending: false });
    setFeeds(data ?? []);
    setLoading(false);
  }

  useEffect(() => { fetchFeeds(); }, []);

  async function handleAdd() {
    if (!form.name.trim()) return;
    setSaving(true);
    await supabase.from('threat_feeds').insert(form);
    setSaving(false);
    setModalOpen(false);
    setForm(empty);
    fetchFeeds();
  }

  async function handleDelete(id: string) {
    await supabase.from('threat_feeds').delete().eq('id', id);
    setDeleteId(null);
    fetchFeeds();
  }

  async function toggle(feed: ThreatFeed) {
    await supabase.from('threat_feeds').update({ enabled: !feed.enabled }).eq('id', feed.id);
    fetchFeeds();
  }

  const totalIndicators = feeds.reduce((sum, f) => sum + f.indicator_count, 0);
  const cls = 'w-full bg-brand-panel border border-border-muted rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-brand-gold/50 focus:ring-1 focus:ring-brand-gold/20 transition-all';
  const lbl = 'block text-xs font-medium text-text-muted mb-1';

  return (
    <div className="p-4 lg:p-6 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-text-primary">Threat Feeds</h1>
          <p className="text-sm text-text-muted mt-0.5">
            {feeds.filter(f => f.enabled).length} active feeds · {totalIndicators.toLocaleString()} total indicators
          </p>
        </div>
        <Button variant="primary" onClick={() => setModalOpen(true)}><Plus className="w-4 h-4" /> Add Feed</Button>
      </div>

      <div className="grid grid-cols-1 gap-4">
        {loading ? (
          <div className="text-center py-12 text-text-muted">Loading feeds...</div>
        ) : feeds.length === 0 ? (
          <Card className="p-8 text-center text-text-muted">No threat feeds configured</Card>
        ) : feeds.map(feed => (
          <Card key={feed.id} className={!feed.enabled ? 'opacity-60' : ''}>
            <div className="p-5 flex items-start gap-4">
              <div className={`w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 ${feed.enabled ? 'bg-info/15' : 'bg-brand-slate/50'}`}>
                <Rss className={`w-5 h-5 ${feed.enabled ? 'text-info' : 'text-text-muted'}`} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-start justify-between gap-3 flex-wrap">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-text-primary">{feed.name}</span>
                      <Badge variant={feed.feed_type === 'ip' ? 'info' : feed.feed_type === 'domain' ? 'warning' : 'neutral'}>
                        {feed.feed_type}
                      </Badge>
                    </div>
                    {feed.description && <p className="text-xs text-text-muted mt-0.5">{feed.description}</p>}
                    {feed.url && <p className="text-xs text-text-muted/60 font-mono mt-1 truncate max-w-sm">{feed.url}</p>}
                  </div>
                  <div className="flex items-center gap-2">
                    <button onClick={() => toggle(feed)} className="flex items-center gap-1.5 text-xs">
                      {feed.enabled
                        ? <><ToggleRight className="w-5 h-5 text-success" /><span className="text-success">On</span></>
                        : <><ToggleLeft className="w-5 h-5 text-text-muted" /><span className="text-text-muted">Off</span></>
                      }
                    </button>
                    <button onClick={() => setDeleteId(feed.id)} className="p-1.5 rounded text-text-muted hover:text-danger hover:bg-danger/10 transition-colors">
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
                <div className="flex items-center gap-4 mt-3 flex-wrap">
                  <div className="flex items-center gap-1.5 text-xs text-text-muted">
                    <StatusDot status={feed.last_status === 'ok' ? 'ok' : feed.last_status === 'pending' ? 'pending' : 'error'} />
                    {feed.last_status}
                  </div>
                  <div className="flex items-center gap-1.5 text-xs text-text-muted">
                    <Clock className="w-3 h-3" />
                    Updated {timeAgo(feed.last_updated)}
                  </div>
                  <div className="flex items-center gap-1.5 text-xs text-text-muted">
                    <Rss className="w-3 h-3" />
                    {feed.indicator_count.toLocaleString()} indicators
                  </div>
                  {feed.refresh_interval_hours > 0 && (
                    <div className="text-xs text-text-muted/60">Refresh every {feed.refresh_interval_hours}h</div>
                  )}
                </div>
              </div>
            </div>
          </Card>
        ))}
      </div>

      <Modal open={modalOpen} onClose={() => setModalOpen(false)} title="Add Threat Feed" size="md">
        <div className="space-y-4">
          <div>
            <label className={lbl}>Feed Name *</label>
            <input className={cls} value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="e.g. Emerging Threats IPs" />
          </div>
          <div>
            <label className={lbl}>Description</label>
            <input className={cls} value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} placeholder="Optional description" />
          </div>
          <div>
            <label className={lbl}>Feed URL</label>
            <input className={cls} value={form.url} onChange={e => setForm({ ...form, url: e.target.value })} placeholder="https://..." />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className={lbl}>Feed Type</label>
              <select className={cls} value={form.feed_type} onChange={e => setForm({ ...form, feed_type: e.target.value as any })}>
                <option value="ip">IP addresses</option>
                <option value="domain">Domains</option>
                <option value="hash">File hashes</option>
                <option value="mixed">Mixed</option>
              </select>
            </div>
            <div>
              <label className={lbl}>Refresh Interval (hours)</label>
              <input type="number" className={cls} value={form.refresh_interval_hours} onChange={e => setForm({ ...form, refresh_interval_hours: Number(e.target.value) })} min={0} />
            </div>
          </div>
          <div className="flex justify-end gap-3 pt-2 border-t border-border-muted">
            <Button variant="ghost" onClick={() => setModalOpen(false)}>Cancel</Button>
            <Button variant="primary" onClick={handleAdd} loading={saving}>Add Feed</Button>
          </div>
        </div>
      </Modal>

      <Modal open={!!deleteId} onClose={() => setDeleteId(null)} title="Remove Feed" size="sm">
        <p className="text-sm text-text-secondary">Remove this threat feed and all its indicators?</p>
        <div className="flex justify-end gap-3 mt-6">
          <Button variant="ghost" onClick={() => setDeleteId(null)}>Cancel</Button>
          <Button variant="danger" onClick={() => deleteId && handleDelete(deleteId)}>Remove</Button>
        </div>
      </Modal>
    </div>
  );
}
