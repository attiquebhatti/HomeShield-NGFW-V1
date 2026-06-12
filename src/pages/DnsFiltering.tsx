import { useEffect, useState } from 'react';
import { Plus, Trash2, Search, Globe, ShieldOff, ShieldCheck, RefreshCw } from 'lucide-react';
import { api } from '../lib/api';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Modal } from '../components/ui/Modal';
import type { DnsEntry, DnsLog } from '../lib/database.types';

const categoryColors: Record<string, string> = {
  malware: 'text-danger',
  phishing: 'text-danger',
  ads: 'text-warning',
  custom: 'text-text-muted',
  tracking: 'text-warning',
};

export function DnsFiltering() {
  const [entries, setEntries] = useState<DnsEntry[]>([]);
  const [logs, setLogs] = useState<DnsLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'blocklist' | 'allowlist'>('all');
  const [saving, setSaving] = useState(false);
  const [form, setForm] = useState({ domain: '', list_type: 'blocklist' as 'blocklist' | 'allowlist', category: 'custom', note: '' });

  async function fetchData() {
    const [enRes, logRes] = await Promise.all([
      api.from<DnsEntry>('dns_entries').select('*').order('created_at', { ascending: false }),
      api.from<DnsLog>('dns_logs').select('*').order('timestamp', { ascending: false }).limit(20),
    ]);
    setEntries(enRes.data ?? []);
    setLogs(logRes.data ?? []);
    setLoading(false);
  }

  useEffect(() => { fetchData(); }, []);

  async function handleAdd() {
    if (!form.domain.trim()) return;
    setSaving(true);
    await api.from('dns_entries').insert({ ...form, source: 'manual', enabled: true });
    setSaving(false);
    setModalOpen(false);
    setForm({ domain: '', list_type: 'blocklist', category: 'custom', note: '' });
    fetchData();
  }

  async function handleDelete(id: string) {
    await api.from('dns_entries').delete().eq('id', id);
    setDeleteId(null);
    fetchData();
  }

  async function toggleEntry(entry: DnsEntry) {
    await api.from('dns_entries').update({ enabled: !entry.enabled }).eq('id', entry.id);
    fetchData();
  }

  const filtered = entries.filter(e => {
    const matchType = filterType === 'all' || e.list_type === filterType;
    const matchSearch = !search || e.domain.toLowerCase().includes(search.toLowerCase());
    return matchType && matchSearch;
  });

  const cls = 'w-full bg-brand-panel border border-border-muted rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-brand-gold/50 focus:ring-1 focus:ring-brand-gold/20 transition-all';

  return (
    <div className="p-4 lg:p-6 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-text-primary">DNS Filtering</h1>
          <p className="text-sm text-text-muted mt-0.5">{entries.filter(e => e.list_type === 'blocklist').length} blocked · {entries.filter(e => e.list_type === 'allowlist').length} allowed</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={fetchData}><RefreshCw className="w-3.5 h-3.5" /></Button>
          <Button variant="primary" onClick={() => setModalOpen(true)}><Plus className="w-4 h-4" /> Add Domain</Button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card className="p-5">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-danger/15 rounded-lg flex items-center justify-center"><ShieldOff className="w-5 h-5 text-danger" /></div>
            <div>
              <div className="text-2xl font-bold text-text-primary">{entries.filter(e => e.list_type === 'blocklist' && e.enabled).length}</div>
              <div className="text-xs text-text-muted">Active Blocklist</div>
            </div>
          </div>
        </Card>
        <Card className="p-5">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-success/15 rounded-lg flex items-center justify-center"><ShieldCheck className="w-5 h-5 text-success" /></div>
            <div>
              <div className="text-2xl font-bold text-text-primary">{entries.filter(e => e.list_type === 'allowlist' && e.enabled).length}</div>
              <div className="text-xs text-text-muted">Active Allowlist</div>
            </div>
          </div>
        </Card>
        <Card className="p-5">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-info/15 rounded-lg flex items-center justify-center"><Globe className="w-5 h-5 text-info" /></div>
            <div>
              <div className="text-2xl font-bold text-text-primary">{logs.filter(l => l.action === 'blocked').length}</div>
              <div className="text-xs text-text-muted">Blocked (recent)</div>
            </div>
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
              <input className="w-full bg-brand-panel border border-border-muted rounded-lg pl-9 pr-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-brand-gold/50 focus:ring-1 focus:ring-brand-gold/20 transition-all" placeholder="Search domains..." value={search} onChange={e => setSearch(e.target.value)} />
            </div>
            <select className="bg-brand-panel border border-border-muted rounded-lg px-3 py-2 text-sm text-text-secondary focus:outline-none focus:border-brand-gold/50" value={filterType} onChange={e => setFilterType(e.target.value as any)}>
              <option value="all">All</option>
              <option value="blocklist">Blocklist</option>
              <option value="allowlist">Allowlist</option>
            </select>
          </div>
          <Card>
            <div className="divide-y divide-border-muted max-h-96 overflow-y-auto">
              {loading ? (
                <div className="px-5 py-8 text-center text-text-muted text-sm">Loading...</div>
              ) : filtered.length === 0 ? (
                <div className="px-5 py-8 text-center text-text-muted text-sm">No entries found</div>
              ) : filtered.map(entry => (
                <div key={entry.id} className={`flex items-center justify-between px-4 py-3 hover:bg-brand-slate/30 transition-colors ${!entry.enabled ? 'opacity-50' : ''}`}>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-mono text-text-primary truncate">{entry.domain}</span>
                      <Badge variant={entry.list_type === 'blocklist' ? 'danger' : 'success'}>
                        {entry.list_type === 'blocklist' ? 'block' : 'allow'}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className={`text-xs ${categoryColors[entry.category] ?? 'text-text-muted'}`}>{entry.category}</span>
                      {entry.note && <span className="text-xs text-text-muted/60">· {entry.note}</span>}
                    </div>
                  </div>
                  <div className="flex items-center gap-1 ml-3 flex-shrink-0">
                    <button onClick={() => toggleEntry(entry)} className="p-1.5 rounded text-text-muted hover:text-text-secondary hover:bg-brand-steel transition-colors text-xs">
                      {entry.enabled ? 'Disable' : 'Enable'}
                    </button>
                    <button onClick={() => setDeleteId(entry.id)} className="p-1.5 rounded text-text-muted hover:text-danger hover:bg-danger/10 transition-colors">
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>

        <div className="space-y-3">
          <h2 className="text-sm font-semibold text-text-primary">Recent DNS Queries</h2>
          <Card>
            <div className="divide-y divide-border-muted max-h-96 overflow-y-auto">
              {logs.length === 0 ? (
                <div className="px-5 py-8 text-center text-text-muted text-sm">No DNS logs</div>
              ) : logs.map(log => (
                <div key={log.id} className="flex items-center justify-between px-4 py-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-text-primary truncate">{log.domain}</span>
                      <Badge variant={log.action === 'blocked' ? 'danger' : 'success'}>{log.action}</Badge>
                    </div>
                    <div className="text-xs text-text-muted mt-0.5">{log.client_ip} · {log.query_type}</div>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>

      <Modal open={modalOpen} onClose={() => setModalOpen(false)} title="Add Domain Entry" size="sm">
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-text-muted mb-1">Domain *</label>
            <input className={cls} value={form.domain} onChange={e => setForm({ ...form, domain: e.target.value })} placeholder="e.g. malware.example.com" />
          </div>
          <div>
            <label className="block text-xs font-medium text-text-muted mb-1">List Type</label>
            <select className={cls} value={form.list_type} onChange={e => setForm({ ...form, list_type: e.target.value as any })}>
              <option value="blocklist">Blocklist (deny)</option>
              <option value="allowlist">Allowlist (permit)</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-text-muted mb-1">Category</label>
            <select className={cls} value={form.category} onChange={e => setForm({ ...form, category: e.target.value })}>
              <option value="custom">Custom</option>
              <option value="malware">Malware</option>
              <option value="phishing">Phishing</option>
              <option value="ads">Ads / Trackers</option>
              <option value="adult">Adult Content</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-text-muted mb-1">Note</label>
            <input className={cls} value={form.note} onChange={e => setForm({ ...form, note: e.target.value })} placeholder="Optional note" />
          </div>
          <div className="flex justify-end gap-3 pt-2 border-t border-border-muted">
            <Button variant="ghost" onClick={() => setModalOpen(false)}>Cancel</Button>
            <Button variant="primary" onClick={handleAdd} loading={saving}>Add</Button>
          </div>
        </div>
      </Modal>

      <Modal open={!!deleteId} onClose={() => setDeleteId(null)} title="Remove Domain" size="sm">
        <p className="text-sm text-text-secondary">Remove this domain from the filter list?</p>
        <div className="flex justify-end gap-3 mt-6">
          <Button variant="ghost" onClick={() => setDeleteId(null)}>Cancel</Button>
          <Button variant="danger" onClick={() => deleteId && handleDelete(deleteId)}>Remove</Button>
        </div>
      </Modal>
    </div>
  );
}
