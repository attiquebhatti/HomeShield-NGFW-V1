import { useEffect, useState, useRef } from 'react';
import {
  Plus, Pencil, Trash2, ToggleLeft, ToggleRight, Search,
  Play, RotateCcw, CheckCircle2, AlertTriangle, Code2, X,
  Terminal, Monitor, Server
} from 'lucide-react';
import { supabase } from '../lib/supabase';
import { Card, CardHeader } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Modal } from '../components/ui/Modal';
import { compileNftables, compileWindowsFirewall, validatePolicies } from '../lib/nftables';
import type { FirewallPolicy } from '../lib/database.types';

const actionVariant: Record<string, 'success' | 'danger' | 'warning' | 'info'> = {
  allow: 'success',
  deny: 'danger',
  reject: 'danger',
  'log-only': 'info',
};

const directionVariant: Record<string, 'info' | 'warning' | 'neutral'> = {
  inbound: 'info',
  outbound: 'warning',
  forward: 'neutral',
};

const emptyPolicy: Omit<FirewallPolicy, 'id' | 'created_at' | 'updated_at'> = {
  name: '',
  description: '',
  enabled: true,
  action: 'allow',
  direction: 'inbound',
  src_ip: 'any',
  dst_ip: 'any',
  src_port: 'any',
  dst_port: 'any',
  protocol: 'any',
  interface: 'any',
  schedule: 'always',
  tags: [],
  priority: 100,
  log_enabled: true,
};

type ApplyStatus = 'idle' | 'validating' | 'previewing' | 'applying' | 'confirming' | 'rolled_back' | 'confirmed';

interface ApplyState {
  status: ApplyStatus;
  validationErrors: string[];
  compiledOutput: string;
  osTarget: 'linux' | 'windows';
  countdown: number;
  applyId: string | null;
}

const ROLLBACK_SECONDS = 30;

function PolicyForm({
  value, onChange, onSubmit, onCancel, loading, isEdit,
}: {
  value: typeof emptyPolicy;
  onChange: (p: typeof emptyPolicy) => void;
  onSubmit: () => void;
  onCancel: () => void;
  loading: boolean;
  isEdit: boolean;
}) {
  const set = (key: string, val: unknown) => onChange({ ...value, [key]: val });
  const i = 'w-full bg-brand-panel border border-border-muted rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-brand-gold/50 focus:ring-1 focus:ring-brand-gold/20 transition-all';
  const l = 'block text-xs font-medium text-text-muted mb-1';

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div className="col-span-2">
          <label className={l}>Rule Name *</label>
          <input className={i} value={value.name} onChange={e => set('name', e.target.value)} placeholder="e.g. Allow HTTPS outbound" />
        </div>
        <div className="col-span-2">
          <label className={l}>Description</label>
          <input className={i} value={value.description} onChange={e => set('description', e.target.value)} placeholder="Optional description" />
        </div>
        <div>
          <label className={l}>Action *</label>
          <select className={i} value={value.action} onChange={e => set('action', e.target.value)}>
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
            <option value="reject">Reject</option>
            <option value="log-only">Log Only</option>
          </select>
        </div>
        <div>
          <label className={l}>Direction *</label>
          <select className={i} value={value.direction} onChange={e => set('direction', e.target.value)}>
            <option value="inbound">Inbound</option>
            <option value="outbound">Outbound</option>
            <option value="forward">Forward (gateway)</option>
          </select>
        </div>
        <div>
          <label className={l}>Source IP / CIDR</label>
          <input className={i} value={value.src_ip} onChange={e => set('src_ip', e.target.value)} placeholder="any or 192.168.1.0/24" />
        </div>
        <div>
          <label className={l}>Destination IP / CIDR</label>
          <input className={i} value={value.dst_ip} onChange={e => set('dst_ip', e.target.value)} placeholder="any" />
        </div>
        <div>
          <label className={l}>Source Port</label>
          <input className={i} value={value.src_port} onChange={e => set('src_port', e.target.value)} placeholder="any" />
        </div>
        <div>
          <label className={l}>Destination Port</label>
          <input className={i} value={value.dst_port} onChange={e => set('dst_port', e.target.value)} placeholder="any or 443 or 8000-8999" />
        </div>
        <div>
          <label className={l}>Protocol</label>
          <select className={i} value={value.protocol} onChange={e => set('protocol', e.target.value)}>
            <option value="any">Any</option>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
            <option value="icmp">ICMP</option>
          </select>
        </div>
        <div>
          <label className={l}>Interface</label>
          <input className={i} value={value.interface} onChange={e => set('interface', e.target.value)} placeholder="any or eth0" />
        </div>
        <div>
          <label className={l}>Priority (lower = first)</label>
          <input type="number" className={i} value={value.priority} onChange={e => set('priority', Number(e.target.value))} min={1} max={9999} />
        </div>
        <div>
          <label className={l}>Tags (comma-separated)</label>
          <input className={i} value={value.tags.join(', ')} onChange={e => set('tags', e.target.value.split(',').map((t: string) => t.trim()).filter(Boolean))} placeholder="web, security" />
        </div>
      </div>
      <div className="flex items-center gap-4 pt-1">
        <label className="flex items-center gap-2 cursor-pointer">
          <input type="checkbox" className="w-4 h-4 accent-brand-gold" checked={value.enabled} onChange={e => set('enabled', e.target.checked)} />
          <span className="text-sm text-text-secondary">Enabled</span>
        </label>
        <label className="flex items-center gap-2 cursor-pointer">
          <input type="checkbox" className="w-4 h-4 accent-brand-gold" checked={value.log_enabled} onChange={e => set('log_enabled', e.target.checked)} />
          <span className="text-sm text-text-secondary">Log matches</span>
        </label>
      </div>
      <div className="flex justify-end gap-3 pt-2 border-t border-border-muted">
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
        <Button variant="primary" onClick={onSubmit} loading={loading}>
          {isEdit ? 'Save Changes' : 'Create Policy'}
        </Button>
      </div>
    </div>
  );
}

function RollbackBanner({
  countdown, onConfirm, onRollback,
}: { countdown: number; onConfirm: () => void; onRollback: () => void }) {
  const pct = Math.round((countdown / ROLLBACK_SECONDS) * 100);
  return (
    <div className="fixed top-4 left-1/2 -translate-x-1/2 z-50 w-full max-w-lg px-4">
      <div className="bg-warning/10 border border-warning/40 rounded-xl p-4 shadow-2xl shadow-black/50 backdrop-blur-sm">
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-warning flex-shrink-0 mt-0.5" />
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between mb-1">
              <p className="text-sm font-semibold text-warning">Rules applied — confirm to keep</p>
              <span className="text-lg font-bold text-warning tabular-nums">{countdown}s</span>
            </div>
            <p className="text-xs text-warning/70 mb-3">
              If you don't confirm, the previous ruleset will be restored automatically.
            </p>
            <div className="h-1.5 bg-brand-main rounded-full overflow-hidden mb-3">
              <div
                className="h-full bg-warning rounded-full transition-all duration-1000"
                style={{ width: `${pct}%` }}
              />
            </div>
            <div className="flex gap-2">
              <button onClick={onConfirm} className="flex-1 flex items-center justify-center gap-1.5 bg-success hover:bg-success/90 text-white text-xs font-medium py-2 rounded-lg transition-colors">
                <CheckCircle2 className="w-3.5 h-3.5" /> Confirm &amp; Keep Rules
              </button>
              <button onClick={onRollback} className="flex-1 flex items-center justify-center gap-1.5 bg-danger/20 hover:bg-danger/30 text-danger border border-danger/40 text-xs font-medium py-2 rounded-lg transition-colors">
                <RotateCcw className="w-3.5 h-3.5" /> Roll Back Now
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export function Policies() {
  const [policies, setPolicies] = useState<FirewallPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [editTarget, setEditTarget] = useState<FirewallPolicy | null>(null);
  const [form, setForm] = useState<typeof emptyPolicy>(emptyPolicy);
  const [search, setSearch] = useState('');
  const [filterAction, setFilterAction] = useState('all');
  const [previewOpen, setPreviewOpen] = useState(false);

  const [applyState, setApplyState] = useState<ApplyState>({
    status: 'idle',
    validationErrors: [],
    compiledOutput: '',
    osTarget: 'linux',
    countdown: ROLLBACK_SECONDS,
    applyId: null,
  });

  const countdownRef = useRef<ReturnType<typeof setInterval> | null>(null);

  async function fetchPolicies() {
    const { data } = await supabase
      .from('firewall_policies')
      .select('*')
      .order('priority', { ascending: true });
    setPolicies(data ?? []);
    setLoading(false);
  }

  useEffect(() => { fetchPolicies(); }, []);
  useEffect(() => () => { if (countdownRef.current) clearInterval(countdownRef.current); }, []);

  function openCreate() {
    setEditTarget(null);
    setForm(emptyPolicy);
    setModalOpen(true);
  }

  function openEdit(policy: FirewallPolicy) {
    setEditTarget(policy);
    const { id, created_at, updated_at, ...rest } = policy;
    setForm(rest);
    setModalOpen(true);
  }

  async function handleSubmit() {
    if (!form.name.trim()) return;
    setSaving(true);
    if (editTarget) {
      await supabase.from('firewall_policies').update({ ...form, updated_at: new Date().toISOString() }).eq('id', editTarget.id);
    } else {
      await supabase.from('firewall_policies').insert(form);
    }
    setSaving(false);
    setModalOpen(false);
    fetchPolicies();
  }

  async function handleDelete(id: string) {
    await supabase.from('firewall_policies').delete().eq('id', id);
    setDeleteId(null);
    fetchPolicies();
  }

  async function toggleEnabled(policy: FirewallPolicy) {
    await supabase.from('firewall_policies').update({ enabled: !policy.enabled }).eq('id', policy.id);
    fetchPolicies();
  }

  async function handleApply(osTarget: 'linux' | 'windows') {
    setApplyState(s => ({ ...s, status: 'validating', osTarget, validationErrors: [] }));
    const errors = validatePolicies(policies.filter(p => p.enabled));
    if (errors.length > 0) {
      setApplyState(s => ({ ...s, status: 'idle', validationErrors: errors }));
      return;
    }
    const compiled = osTarget === 'linux'
      ? compileNftables(policies)
      : compileWindowsFirewall(policies);
    setApplyState(s => ({ ...s, status: 'previewing', compiledOutput: compiled }));
  }

  async function confirmApply() {
    const { osTarget, compiledOutput } = applyState;
    const { data: record } = await supabase.from('rule_apply_history').insert({
      applied_by: 'admin',
      mode: 'host',
      os_target: osTarget,
      rules_count: policies.filter(p => p.enabled).length,
      status: 'applied',
      rollback_timer_seconds: ROLLBACK_SECONDS,
      compiled_output: compiledOutput,
      rules_snapshot: policies,
    }).select().maybeSingle();

    await supabase.from('audit_log').insert({
      actor: 'admin',
      action: 'apply',
      resource_type: 'firewall_ruleset',
      details: { rules_count: policies.filter(p => p.enabled).length, os_target: osTarget, mode: 'atomic' },
      ip_address: '127.0.0.1',
    });

    const applyId = record?.id ?? null;
    let remaining = ROLLBACK_SECONDS;
    setApplyState(s => ({ ...s, status: 'confirming', countdown: remaining, applyId }));

    countdownRef.current = setInterval(() => {
      remaining--;
      if (remaining <= 0) {
        clearInterval(countdownRef.current!);
        triggerRollback(applyId);
      } else {
        setApplyState(s => ({ ...s, countdown: remaining }));
      }
    }, 1000);
  }

  async function handleUserConfirm() {
    if (countdownRef.current) clearInterval(countdownRef.current);
    const { applyId } = applyState;
    if (applyId) {
      await supabase.from('rule_apply_history')
        .update({ status: 'confirmed', confirmed_at: new Date().toISOString() })
        .eq('id', applyId);
    }
    setApplyState(s => ({ ...s, status: 'confirmed', countdown: 0 }));
    setTimeout(() => setApplyState(s => ({ ...s, status: 'idle' })), 3000);
  }

  async function triggerRollback(applyId: string | null) {
    if (applyId) {
      await supabase.from('rule_apply_history')
        .update({ status: 'rolled_back', rolled_back_at: new Date().toISOString() })
        .eq('id', applyId);
    }
    await supabase.from('audit_log').insert({
      actor: 'system',
      action: 'rollback',
      resource_type: 'firewall_ruleset',
      details: { reason: 'timer_expired', apply_id: applyId },
      ip_address: '127.0.0.1',
    });
    setApplyState(s => ({ ...s, status: 'rolled_back', countdown: 0 }));
    setTimeout(() => setApplyState(s => ({ ...s, status: 'idle' })), 5000);
  }

  const filtered = policies.filter(p => {
    const matchSearch = search === '' ||
      p.name.toLowerCase().includes(search.toLowerCase()) ||
      p.src_ip.includes(search) || p.dst_ip.includes(search) ||
      p.tags.some(t => t.includes(search));
    const matchAction = filterAction === 'all' || p.action === filterAction;
    return matchSearch && matchAction;
  });

  const enabledCount = policies.filter(p => p.enabled).length;
  const isConfirming = applyState.status === 'confirming';

  return (
    <>
      {isConfirming && (
        <RollbackBanner
          countdown={applyState.countdown}
          onConfirm={handleUserConfirm}
          onRollback={() => {
            if (countdownRef.current) clearInterval(countdownRef.current);
            triggerRollback(applyState.applyId);
          }}
        />
      )}

      <div className="p-4 lg:p-6 space-y-5">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div>
            <h1 className="text-xl font-bold text-text-primary">Firewall Policies</h1>
            <p className="text-sm text-text-muted mt-0.5">
              {policies.length} rules · {enabledCount} active · evaluated in priority order
            </p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <Button variant="ghost" size="sm" onClick={() => setPreviewOpen(true)}>
              <Code2 className="w-4 h-4" /> Preview
            </Button>
            <div className="flex items-center">
              <Button
                variant={applyState.status === 'confirmed' ? 'success' : 'primary'}
                onClick={() => handleApply('linux')}
                disabled={isConfirming || applyState.status === 'confirmed'}
                size="sm"
                className="rounded-r-none border-r-0"
              >
                <Server className="w-3.5 h-3.5" />
                {applyState.status === 'confirmed' ? 'Confirmed!' : 'Apply (Linux)'}
              </Button>
              <Button
                variant="secondary"
                onClick={() => handleApply('windows')}
                disabled={isConfirming}
                size="sm"
                className="rounded-l-none"
              >
                <Monitor className="w-3.5 h-3.5" />
                Windows
              </Button>
            </div>
            <Button variant="primary" onClick={openCreate} size="sm">
              <Plus className="w-4 h-4" /> New Policy
            </Button>
          </div>
        </div>

        {applyState.status === 'rolled_back' && (
          <div className="flex items-center gap-2 px-4 py-3 bg-danger/10 border border-danger/30 rounded-xl text-sm text-danger">
            <RotateCcw className="w-4 h-4 flex-shrink-0" />
            Rules rolled back to previous configuration.
          </div>
        )}
        {applyState.status === 'confirmed' && (
          <div className="flex items-center gap-2 px-4 py-3 bg-success/10 border border-success/30 rounded-xl text-sm text-success">
            <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
            Rules confirmed and applied successfully.
          </div>
        )}
        {applyState.validationErrors.length > 0 && (
          <div className="px-4 py-3 bg-danger/10 border border-danger/30 rounded-xl space-y-1">
            <div className="flex items-center gap-2 text-sm font-medium text-danger">
              <AlertTriangle className="w-4 h-4" /> Validation errors
            </div>
            {applyState.validationErrors.map((err, idx) => (
              <p key={idx} className="text-xs text-danger/80 ml-6">{err}</p>
            ))}
          </div>
        )}

        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative flex-1 min-w-48">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
            <input
              className="w-full bg-brand-panel border border-border-muted rounded-lg pl-9 pr-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-brand-gold/50 focus:ring-1 focus:ring-brand-gold/20 transition-all"
              placeholder="Search rules, IPs, tags..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>
          <select
            className="bg-brand-panel border border-border-muted rounded-lg px-3 py-2 text-sm text-text-secondary focus:outline-none focus:border-brand-gold/50 focus:ring-1 focus:ring-brand-gold/20 transition-all"
            value={filterAction}
            onChange={e => setFilterAction(e.target.value)}
          >
            <option value="all">All Actions</option>
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
            <option value="reject">Reject</option>
            <option value="log-only">Log Only</option>
          </select>
        </div>

        <Card>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border-muted">
                  <th className="px-4 py-3 text-left text-xs font-medium text-text-muted w-12">#</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-text-muted">Rule</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-text-muted">Action</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-text-muted">Direction</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-text-muted">Source</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-text-muted">Destination</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-text-muted">Proto</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-text-muted">Status</th>
                  <th className="px-4 py-3 text-right text-xs font-medium text-text-muted">Actions</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan={9} className="px-4 py-12 text-center text-text-muted">Loading policies...</td></tr>
                ) : filtered.length === 0 ? (
                  <tr><td colSpan={9} className="px-4 py-12 text-center text-text-muted">No policies found</td></tr>
                ) : filtered.map(policy => (
                  <tr
                    key={policy.id}
                    className={`border-b border-border-muted/50 hover:bg-brand-slate/30 transition-colors ${!policy.enabled ? 'opacity-50' : ''}`}
                  >
                    <td className="px-4 py-3 text-xs text-text-muted tabular-nums">{policy.priority}</td>
                    <td className="px-4 py-3">
                      <div className="font-medium text-text-primary">{policy.name}</div>
                      {policy.description && <div className="text-xs text-text-muted mt-0.5">{policy.description}</div>}
                      {policy.tags.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-1">
                          {policy.tags.map(tag => (
                            <span key={tag} className="text-xs px-1.5 py-0.5 bg-brand-slate text-text-muted rounded">{tag}</span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <Badge variant={actionVariant[policy.action] ?? 'neutral'}>{policy.action}</Badge>
                    </td>
                    <td className="px-4 py-3">
                      <Badge variant={directionVariant[policy.direction] ?? 'neutral'}>{policy.direction}</Badge>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-text-secondary">
                      <div>{policy.src_ip}</div>
                      {policy.src_port !== 'any' && <div className="text-text-muted">:{policy.src_port}</div>}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-text-secondary">
                      <div>{policy.dst_ip}</div>
                      {policy.dst_port !== 'any' && <div className="text-text-muted">:{policy.dst_port}</div>}
                    </td>
                    <td className="px-4 py-3 text-xs text-text-muted uppercase">{policy.protocol}</td>
                    <td className="px-4 py-3">
                      <button onClick={() => toggleEnabled(policy)} className="flex items-center gap-1.5 text-xs transition-colors">
                        {policy.enabled
                          ? <><ToggleRight className="w-5 h-5 text-success" /><span className="text-success">On</span></>
                          : <><ToggleLeft className="w-5 h-5 text-text-muted" /><span className="text-text-muted">Off</span></>
                        }
                      </button>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button onClick={() => openEdit(policy)} className="p-1.5 rounded-lg text-text-muted hover:text-text-primary hover:bg-brand-steel transition-colors">
                          <Pencil className="w-3.5 h-3.5" />
                        </button>
                        <button onClick={() => setDeleteId(policy.id)} className="p-1.5 rounded-lg text-text-muted hover:text-danger hover:bg-danger/10 transition-colors">
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        {previewOpen && (
          <div className="mt-4">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-text-muted" />
                    <span className="text-sm font-semibold text-text-primary">Compiled Ruleset Preview</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="flex bg-brand-main rounded-lg p-0.5 gap-0.5">
                      {(['linux', 'windows'] as const).map(os => (
                        <button
                          key={os}
                          onClick={() => setApplyState(s => ({ ...s, osTarget: os }))}
                          className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium transition-colors ${
                            applyState.osTarget === os ? 'bg-brand-slate text-text-primary' : 'text-text-muted hover:text-text-secondary'
                          }`}
                        >
                          {os === 'linux' ? <Server className="w-3 h-3" /> : <Monitor className="w-3 h-3" />}
                          {os === 'linux' ? 'nftables' : 'PowerShell'}
                        </button>
                      ))}
                    </div>
                    <button onClick={() => setPreviewOpen(false)} className="p-1.5 rounded text-text-muted hover:text-text-secondary">
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </CardHeader>
              <div className="bg-brand-main rounded-b-xl overflow-x-auto">
                <pre className="p-5 text-xs font-mono text-brand-gold/80 leading-relaxed whitespace-pre overflow-x-auto max-h-96">
                  {applyState.osTarget === 'linux'
                    ? compileNftables(policies)
                    : compileWindowsFirewall(policies)
                  }
                </pre>
              </div>
            </Card>
          </div>
        )}

        <Modal open={modalOpen} onClose={() => setModalOpen(false)} title={editTarget ? 'Edit Policy' : 'New Firewall Policy'} size="lg">
          <PolicyForm
            value={form}
            onChange={setForm}
            onSubmit={handleSubmit}
            onCancel={() => setModalOpen(false)}
            loading={saving}
            isEdit={!!editTarget}
          />
        </Modal>

        <Modal
          open={applyState.status === 'previewing'}
          onClose={() => setApplyState(s => ({ ...s, status: 'idle' }))}
          title={`Preview & Apply — ${applyState.osTarget === 'linux' ? 'nftables' : 'Windows Firewall'}`}
          size="xl"
        >
          <div className="space-y-4">
            <div className="flex items-start gap-3 px-4 py-3 bg-warning/10 border border-warning/30 rounded-xl">
              <AlertTriangle className="w-4 h-4 text-warning flex-shrink-0 mt-0.5" />
              <div className="text-xs text-warning">
                <p className="font-medium mb-0.5">Review before applying</p>
                <p>After applying, you have <strong>{ROLLBACK_SECONDS} seconds</strong> to confirm or rules will automatically roll back.</p>
              </div>
            </div>
            <div className="bg-brand-main rounded-xl overflow-x-auto border border-border-muted">
              <pre className="p-4 text-xs font-mono text-brand-gold/80 leading-relaxed max-h-80 overflow-y-auto whitespace-pre">
                {applyState.compiledOutput}
              </pre>
            </div>
            <div className="flex justify-between items-center pt-2 border-t border-border-muted">
              <div className="text-xs text-text-muted">
                {policies.filter(p => p.enabled).length} rules will be applied
              </div>
              <div className="flex gap-3">
                <Button variant="ghost" onClick={() => setApplyState(s => ({ ...s, status: 'idle' }))}>Cancel</Button>
                <Button variant="primary" onClick={confirmApply}>
                  <Play className="w-4 h-4" /> Apply Now
                </Button>
              </div>
            </div>
          </div>
        </Modal>

        <Modal open={!!deleteId} onClose={() => setDeleteId(null)} title="Delete Policy" size="sm">
          <p className="text-sm text-text-secondary">Delete this policy? This cannot be undone.</p>
          <div className="flex justify-end gap-3 mt-6">
            <Button variant="ghost" onClick={() => setDeleteId(null)}>Cancel</Button>
            <Button variant="danger" onClick={() => deleteId && handleDelete(deleteId)}>Delete</Button>
          </div>
        </Modal>
      </div>
    </>
  );
}
