import { useEffect, useState } from 'react';
import { Plus, Pencil, Trash2, ToggleRight, ToggleLeft } from 'lucide-react';
import { api } from '../lib/api';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Modal } from '../components/ui/Modal';
import type { NatRule } from '../lib/database.types';

const emptyRule: Omit<NatRule, 'id' | 'created_at' | 'updated_at'> = {
  name: '', description: '', enabled: true, nat_type: 'masquerade',
  src_ip: 'any', dst_ip: 'any', src_port: 'any', dst_port: 'any',
  protocol: 'tcp', translate_to_ip: '', translate_to_port: '', interface: 'any', priority: 100,
};

const typeVariant: Record<string, 'info' | 'warning' | 'success'> = { masquerade: 'info', dnat: 'warning', snat: 'success' };

function NatForm({ value, onChange, onSubmit, onCancel, loading, isEdit }: {
  value: typeof emptyRule; onChange: (v: typeof emptyRule) => void;
  onSubmit: () => void; onCancel: () => void; loading: boolean; isEdit: boolean;
}) {
  const set = (k: string, v: unknown) => onChange({ ...value, [k]: v });
  const cls = 'w-full bg-brand-panel border border-border-muted rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-brand-gold/50 focus:ring-1 focus:ring-brand-gold/20 transition-all';
  const lbl = 'block text-xs font-medium text-text-muted mb-1';
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div className="col-span-2"><label className={lbl}>Rule Name *</label><input className={cls} value={value.name} onChange={e => set('name', e.target.value)} placeholder="e.g. Port Forward HTTP" /></div>
        <div><label className={lbl}>NAT Type</label><select className={cls} value={value.nat_type} onChange={e => set('nat_type', e.target.value)}><option value="masquerade">Masquerade (outbound NAT)</option><option value="dnat">DNAT (port forward)</option><option value="snat">SNAT (source NAT)</option></select></div>
        <div><label className={lbl}>Protocol</label><select className={cls} value={value.protocol} onChange={e => set('protocol', e.target.value)}><option value="tcp">TCP</option><option value="udp">UDP</option><option value="any">Any</option></select></div>
        <div><label className={lbl}>Source IP</label><input className={cls} value={value.src_ip} onChange={e => set('src_ip', e.target.value)} placeholder="any" /></div>
        <div><label className={lbl}>Destination IP</label><input className={cls} value={value.dst_ip} onChange={e => set('dst_ip', e.target.value)} placeholder="any" /></div>
        <div><label className={lbl}>Destination Port</label><input className={cls} value={value.dst_port} onChange={e => set('dst_port', e.target.value)} placeholder="any or 80" /></div>
        <div><label className={lbl}>Interface</label><input className={cls} value={value.interface} onChange={e => set('interface', e.target.value)} placeholder="any or eth0" /></div>
        {value.nat_type !== 'masquerade' && <>
          <div><label className={lbl}>Translate To IP</label><input className={cls} value={value.translate_to_ip} onChange={e => set('translate_to_ip', e.target.value)} placeholder="192.168.1.100" /></div>
          <div><label className={lbl}>Translate To Port</label><input className={cls} value={value.translate_to_port} onChange={e => set('translate_to_port', e.target.value)} placeholder="8080" /></div>
        </>}
      </div>
      <label className="flex items-center gap-2 cursor-pointer"><input type="checkbox" className="w-4 h-4 accent-brand-gold" checked={value.enabled} onChange={e => set('enabled', e.target.checked)} /><span className="text-sm text-text-secondary">Enabled</span></label>
      <div className="flex justify-end gap-3 pt-2 border-t border-border-muted"><Button variant="ghost" onClick={onCancel}>Cancel</Button><Button variant="primary" onClick={onSubmit} loading={loading}>{isEdit ? 'Save' : 'Create'}</Button></div>
    </div>
  );
}

export function Nat() {
  const [rules, setRules] = useState<NatRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [editTarget, setEditTarget] = useState<NatRule | null>(null);
  const [form, setForm] = useState<typeof emptyRule>(emptyRule);

  async function fetchRules() { const { data } = await api.from<NatRule>('nat_rules').select('*').order('priority'); setRules(data ?? []); setLoading(false); }
  useEffect(() => { fetchRules(); }, []);

  function openCreate() { setEditTarget(null); setForm(emptyRule); setModalOpen(true); }
  function openEdit(r: NatRule) { setEditTarget(r); const { id, created_at, updated_at, ...rest } = r; setForm(rest); setModalOpen(true); }

  async function handleSubmit() {
    if (!form.name.trim()) return;
    setSaving(true);
    if (editTarget) { await api.from('nat_rules').update({ ...form, updated_at: new Date().toISOString() }).eq('id', editTarget.id); }
    else { await api.from('nat_rules').insert(form); }
    setSaving(false); setModalOpen(false); fetchRules();
  }

  async function handleDelete(id: string) { await api.from('nat_rules').delete().eq('id', id); setDeleteId(null); fetchRules(); }
  async function toggle(r: NatRule) { await api.from('nat_rules').update({ enabled: !r.enabled }).eq('id', r.id); fetchRules(); }

  return (
    <div className="p-4 lg:p-6 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div><h1 className="text-xl font-bold text-text-primary">NAT Rules</h1><p className="text-sm text-text-muted mt-0.5">Network Address Translation — masquerade, DNAT, SNAT</p></div>
        <Button variant="primary" onClick={openCreate}><Plus className="w-4 h-4" /> New Rule</Button>
      </div>
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-border-muted">
              <th className="px-4 py-3 text-left text-xs font-medium text-text-muted">Name</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-text-muted">Type</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-text-muted">Match</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-text-muted">Translate To</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-text-muted">Status</th>
              <th className="px-4 py-3 text-right text-xs font-medium text-text-muted">Actions</th>
            </tr></thead>
            <tbody>
              {loading ? (<tr><td colSpan={6} className="px-4 py-12 text-center text-text-muted">Loading...</td></tr>
              ) : rules.length === 0 ? (<tr><td colSpan={6} className="px-4 py-12 text-center text-text-muted">No NAT rules configured</td></tr>
              ) : rules.map(r => (
                <tr key={r.id} className={`border-b border-border-muted/50 hover:bg-brand-slate/30 transition-colors ${!r.enabled ? 'opacity-50' : ''}`}>
                  <td className="px-4 py-3"><div className="font-medium text-text-primary">{r.name}</div>{r.description && <div className="text-xs text-text-muted">{r.description}</div>}</td>
                  <td className="px-4 py-3"><Badge variant={typeVariant[r.nat_type]}>{r.nat_type.toUpperCase()}</Badge></td>
                  <td className="px-4 py-3 font-mono text-xs text-text-secondary">{r.src_ip}:{r.src_port} → {r.dst_ip}:{r.dst_port} ({r.protocol})</td>
                  <td className="px-4 py-3 font-mono text-xs text-text-muted">{r.nat_type === 'masquerade' ? <span className="text-text-muted">WAN IP</span> : `${r.translate_to_ip}:${r.translate_to_port}`}</td>
                  <td className="px-4 py-3"><button onClick={() => toggle(r)} className="flex items-center gap-1.5 text-xs">{r.enabled ? <><ToggleRight className="w-5 h-5 text-success" /><span className="text-success">On</span></> : <><ToggleLeft className="w-5 h-5 text-text-muted" /><span className="text-text-muted">Off</span></>}</button></td>
                  <td className="px-4 py-3 text-right"><div className="flex items-center justify-end gap-1"><button onClick={() => openEdit(r)} className="p-1.5 rounded-lg text-text-muted hover:text-text-primary hover:bg-brand-steel transition-colors"><Pencil className="w-3.5 h-3.5" /></button><button onClick={() => setDeleteId(r.id)} className="p-1.5 rounded-lg text-text-muted hover:text-danger hover:bg-danger/10 transition-colors"><Trash2 className="w-3.5 h-3.5" /></button></div></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <Modal open={modalOpen} onClose={() => setModalOpen(false)} title={editTarget ? 'Edit NAT Rule' : 'New NAT Rule'} size="lg">
        <NatForm value={form} onChange={setForm} onSubmit={handleSubmit} onCancel={() => setModalOpen(false)} loading={saving} isEdit={!!editTarget} />
      </Modal>
      <Modal open={!!deleteId} onClose={() => setDeleteId(null)} title="Delete NAT Rule" size="sm">
        <p className="text-sm text-text-secondary">Delete this NAT rule?</p>
        <div className="flex justify-end gap-3 mt-6"><Button variant="ghost" onClick={() => setDeleteId(null)}>Cancel</Button><Button variant="danger" onClick={() => deleteId && handleDelete(deleteId)}>Delete</Button></div>
      </Modal>
    </div>
  );
}
