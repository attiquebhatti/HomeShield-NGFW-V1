import { useEffect, useState } from 'react';
import { Network, RefreshCw, ArrowDownLeft, ArrowUpRight, Pencil } from 'lucide-react';
import { api } from '../lib/api';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Modal } from '../components/ui/Modal';
import { StatusDot } from '../components/ui/StatusDot';
import type { NetworkInterface } from '../lib/database.types';

function formatBytes(b: number) {
  if (!b) return '0 B';
  const k = 1024, s = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(b) / Math.log(k));
  return `${parseFloat((b / Math.pow(k, i)).toFixed(2))} ${s[i]}`;
}

const roleVariant: Record<string, 'info' | 'success' | 'warning' | 'neutral'> = {
  wan: 'info',
  lan: 'success',
  dmz: 'warning',
  mgmt: 'warning',
  unassigned: 'neutral',
};

export function Interfaces() {
  const [ifaces, setIfaces] = useState<NetworkInterface[]>([]);
  const [loading, setLoading] = useState(true);
  const [editTarget, setEditTarget] = useState<NetworkInterface | null>(null);
  const [form, setForm] = useState({ role: 'unassigned' as NetworkInterface['role'], display_name: '' });
  const [saving, setSaving] = useState(false);

  async function fetchIfaces() {
    const { data } = await api.from('network_interfaces').select('*').order('name');
    setIfaces(data ?? []);
    setLoading(false);
  }

  useEffect(() => { fetchIfaces(); }, []);

  function openEdit(iface: NetworkInterface) {
    setEditTarget(iface);
    setForm({ role: iface.role, display_name: iface.display_name });
  }

  async function handleSave() {
    if (!editTarget) return;
    setSaving(true);
    await api.from('network_interfaces').update({ role: form.role, display_name: form.display_name, updated_at: new Date().toISOString() }).eq('id', editTarget.id);
    setSaving(false);
    setEditTarget(null);
    fetchIfaces();
  }

  const cls = 'w-full bg-brand-panel border border-border-muted rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-brand-gold/50 focus:ring-1 focus:ring-brand-gold/20 transition-all';
  const lbl = 'block text-xs font-medium text-text-muted mb-1';

  return (
    <div className="p-4 lg:p-6 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-text-primary">Network Interfaces</h1>
          <p className="text-sm text-text-muted mt-0.5">{ifaces.filter(i => i.status === 'up').length} interfaces up</p>
        </div>
        <Button variant="ghost" size="sm" onClick={fetchIfaces}><RefreshCw className="w-3.5 h-3.5" /> Refresh</Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {loading ? (
          <div className="col-span-3 text-center py-12 text-text-muted">Loading...</div>
        ) : ifaces.map(iface => (
          <Card key={iface.id}>
            <div className="p-5">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${iface.status === 'up' ? 'bg-success/15' : 'bg-brand-slate/50'}`}>
                    <Network className={`w-5 h-5 ${iface.status === 'up' ? 'text-success' : 'text-text-muted'}`} />
                  </div>
                  <div>
                    <div className="font-semibold text-text-primary">{iface.display_name || iface.name}</div>
                    <div className="text-xs text-text-muted font-mono">{iface.name}</div>
                  </div>
                </div>
                <button onClick={() => openEdit(iface)} className="p-1.5 rounded text-text-muted hover:text-text-secondary hover:bg-brand-steel transition-colors">
                  <Pencil className="w-3.5 h-3.5" />
                </button>
              </div>

              <div className="mt-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-text-muted">Status</span>
                  <div className="flex items-center gap-1.5">
                    <StatusDot status={iface.status} pulse={iface.status === 'up'} />
                    <span className="text-xs text-text-secondary">{iface.status}</span>
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-text-muted">Role</span>
                  <Badge variant={roleVariant[iface.role]}>{iface.role.toUpperCase()}</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-text-muted">IP Address</span>
                  <span className="text-xs text-text-secondary font-mono">{iface.ip_address || 'none'}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-text-muted">MAC</span>
                  <span className="text-xs text-text-muted font-mono">{iface.mac_address || '—'}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-text-muted">MTU</span>
                  <span className="text-xs text-text-muted">{iface.mtu}</span>
                </div>
              </div>

              <div className="mt-4 pt-4 border-t border-border-muted grid grid-cols-2 gap-3">
                <div className="flex items-center gap-2">
                  <ArrowDownLeft className="w-3.5 h-3.5 text-success flex-shrink-0" />
                  <div>
                    <div className="text-xs font-semibold text-text-primary">{formatBytes(iface.rx_bytes)}</div>
                    <div className="text-xs text-text-muted/60">RX</div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <ArrowUpRight className="w-3.5 h-3.5 text-info flex-shrink-0" />
                  <div>
                    <div className="text-xs font-semibold text-text-primary">{formatBytes(iface.tx_bytes)}</div>
                    <div className="text-xs text-text-muted/60">TX</div>
                  </div>
                </div>
              </div>
            </div>
          </Card>
        ))}
      </div>

      <Modal open={!!editTarget} onClose={() => setEditTarget(null)} title="Edit Interface" size="sm">
        <div className="space-y-4">
          <div>
            <label className={lbl}>Display Name</label>
            <input className={cls} value={form.display_name} onChange={e => setForm({ ...form, display_name: e.target.value })} placeholder="e.g. WAN (eth0)" />
          </div>
          <div>
            <label className={lbl}>Role</label>
            <select className={cls} value={form.role} onChange={e => setForm({ ...form, role: e.target.value as any })}>
              <option value="wan">WAN</option>
              <option value="lan">LAN</option>
              <option value="dmz">DMZ</option>
              <option value="mgmt">Management</option>
              <option value="unassigned">Unassigned</option>
            </select>
          </div>
          <div className="flex justify-end gap-3 pt-2 border-t border-border-muted">
            <Button variant="ghost" onClick={() => setEditTarget(null)}>Cancel</Button>
            <Button variant="primary" onClick={handleSave} loading={saving}>Save</Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
