import { useEffect, useState } from 'react';
import { RefreshCw, Trash2, Monitor, Server, Smartphone, HelpCircle, Download, Plus, AlertTriangle, Copy, Check, Tags } from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';
import { Card, CardHeader } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Modal } from '../components/ui/Modal';
import { StatusDot } from '../components/ui/StatusDot';

interface Device {
  id: string;
  hostname: string;
  os: 'windows' | 'linux' | 'macos' | 'unknown';
  os_version: string;
  agent_version: string;
  ip_address: string;
  tags: string[] | null;
  enrolled_at: string;
  last_seen: string;
  online: number | boolean;
}

const osIcon = { windows: Monitor, linux: Server, macos: Smartphone, unknown: HelpCircle };
const osVariant: Record<string, 'info' | 'warning' | 'neutral'> = { windows: 'info', linux: 'warning', macos: 'neutral', unknown: 'neutral' };

function timeAgo(ts: string) {
  const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export function Devices() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [tagsEdit, setTagsEdit] = useState<{ id: string; hostname: string; text: string } | null>(null);
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [installOpen, setInstallOpen] = useState(false);
  const [agentEnabled, setAgentEnabled] = useState(true);
  const [agentToken, setAgentToken] = useState('');
  const [envManaged, setEnvManaged] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [copied, setCopied] = useState(false);

  async function fetchDevices() {
    const { data } = await api.get<Device[]>('devices');
    setDevices(data ?? []);
    setLoading(false);
  }

  async function fetchAgentStatus() {
    const r = await api.get<{ agent_api_enabled: boolean; env_managed?: boolean; token?: string }>('agent-status');
    setAgentEnabled(r.data?.agent_api_enabled ?? true);
    setEnvManaged(r.data?.env_managed ?? false);
    setAgentToken(r.data?.token ?? '');
  }

  async function generateToken() {
    setGenerating(true);
    await api.post('agent-token/generate');
    await fetchAgentStatus();
    setGenerating(false);
  }

  useEffect(() => {
    fetchDevices();
    fetchAgentStatus();
    const t = setInterval(fetchDevices, 15000);
    return () => clearInterval(t);
  }, []);

  const installCmd = `powershell -ExecutionPolicy Bypass -File .\\homeshield-install.ps1 -Token "${agentToken || '<AGENT_TOKEN>'}"`;

  function copyCmd() {
    navigator.clipboard?.writeText(installCmd).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  async function removeDevice(id: string) {
    await api.del(`devices/${id}`);
    setDeleteId(null);
    fetchDevices();
  }

  async function saveTags() {
    if (!tagsEdit) return;
    const tags = tagsEdit.text.split(',').map(t => t.trim().toLowerCase()).filter(Boolean);
    await api.patch(`devices/${tagsEdit.id}`, { tags });
    setTagsEdit(null);
    fetchDevices();
  }

  const online = devices.filter(d => d.online).length;

  return (
    <div className="p-4 lg:p-6 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-text-primary">Devices</h1>
          <p className="text-sm text-text-muted mt-0.5">{devices.length} enrolled · {online} online</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={fetchDevices}><RefreshCw className="w-3.5 h-3.5" /></Button>
          <Button variant="primary" onClick={() => setInstallOpen(true)}><Plus className="w-4 h-4" /> Install Agent</Button>
        </div>
      </div>

      {!agentEnabled && (
        <div className="flex items-center justify-between gap-3 px-4 py-3 bg-warning/10 border border-warning/20 rounded-xl text-sm text-warning flex-wrap">
          <div className="flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
            <span>The agent API is disabled — no agent token is set, so agents can't enroll.</span>
          </div>
          {isAdmin && !envManaged && (
            <Button variant="secondary" size="sm" onClick={generateToken} loading={generating}>Generate Token</Button>
          )}
        </div>
      )}

      <Card>
        <CardHeader><span className="font-semibold text-text-primary">Enrolled Agents</span></CardHeader>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border-muted text-xs text-text-muted">
                <th className="px-4 py-3 text-left font-medium">Device</th>
                <th className="px-4 py-3 text-left font-medium">OS</th>
                <th className="px-4 py-3 text-left font-medium">IP</th>
                <th className="px-4 py-3 text-left font-medium">Groups</th>
                <th className="px-4 py-3 text-left font-medium">Agent</th>
                <th className="px-4 py-3 text-left font-medium">Last Seen</th>
                <th className="px-4 py-3 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={7} className="px-4 py-12 text-center text-text-muted">Loading...</td></tr>
              ) : devices.length === 0 ? (
                <tr><td colSpan={7} className="px-4 py-12 text-center text-text-muted">No devices enrolled yet. Install an agent and point it at this server.</td></tr>
              ) : devices.map(d => {
                const Icon = osIcon[d.os] ?? HelpCircle;
                return (
                  <tr key={d.id} className="border-b border-border-muted/50 hover:bg-brand-slate/30">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2.5">
                        <StatusDot status={d.online ? 'ok' : 'error'} />
                        <div>
                          <div className="text-text-primary font-medium">{d.hostname || 'unknown'}</div>
                          <div className="text-xs font-mono text-text-muted/60">{d.id.slice(0, 8)}…</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <Icon className="w-4 h-4 text-text-muted" />
                        <Badge variant={osVariant[d.os] ?? 'neutral'}>{d.os}</Badge>
                      </div>
                      {d.os_version && <div className="text-xs text-text-muted/60 mt-0.5 max-w-44 truncate">{d.os_version}</div>}
                    </td>
                    <td className="px-4 py-3 font-mono text-text-secondary">{d.ip_address || '—'}</td>
                    <td className="px-4 py-3">
                      <button onClick={() => setTagsEdit({ id: d.id, hostname: d.hostname, text: (d.tags || []).join(', ') })}
                        className="flex items-center gap-1 flex-wrap text-left group">
                        {(d.tags && d.tags.length)
                          ? d.tags.map(t => <Badge key={t} variant="info">{t}</Badge>)
                          : <span className="text-xs text-text-muted/50 group-hover:text-brand-gold">+ add</span>}
                      </button>
                    </td>
                    <td className="px-4 py-3 text-text-muted">{d.agent_version || '—'}</td>
                    <td className="px-4 py-3 text-text-muted">{timeAgo(d.last_seen)}</td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <button onClick={() => setTagsEdit({ id: d.id, hostname: d.hostname, text: (d.tags || []).join(', ') })} title="Edit groups"
                          className="p-1.5 rounded text-text-muted hover:text-brand-gold hover:bg-brand-gold/10 transition-colors">
                          <Tags className="w-3.5 h-3.5" />
                        </button>
                        <button onClick={() => setDeleteId(d.id)} title="Remove device"
                          className="p-1.5 rounded text-text-muted hover:text-danger hover:bg-danger/10 transition-colors">
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>

      <Modal open={installOpen} onClose={() => setInstallOpen(false)} title="Install an Agent" size="md">
        <div className="space-y-5">
          {/* Windows */}
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-sm font-semibold text-text-primary">
              <Monitor className="w-4 h-4 text-info" /> Windows
            </div>
            <p className="text-xs text-text-muted">
              Enrolls the device, enforces firewall policy, and sets up the IPSec VPN client.
            </p>
            {/* One-click .cmd (token + URL baked in, self-elevates) */}
            <Button variant="primary" disabled={!agentToken}
              title={agentToken ? 'One-click installer' : 'Set AGENT_TOKEN on the server first'}
              onClick={() => api.download('agent-download/windows-cmd', 'homeshield-install.cmd')}>
              <Download className="w-4 h-4" /> Download One-Click Installer (.cmd)
            </Button>
            <p className="text-xs text-text-muted/70">
              Double-click the downloaded file and approve the <strong>UAC</strong> prompt — no PowerShell or
              execution-policy steps. The server URL and token are baked in.
            </p>
            {agentToken ? (
              <div className="flex items-center gap-2 px-3 py-2 bg-success/10 border border-success/20 rounded-lg">
                <Check className="w-3.5 h-3.5 text-success flex-shrink-0" />
                <span className="text-xs text-success flex-1">
                  Agent token configured{envManaged ? ' (from server environment)' : ''} — enrollment is enabled.
                </span>
                {isAdmin && !envManaged && (
                  <button
                    onClick={() => { if (confirm('Rotate the agent token? Already-installed agents will stop connecting until reinstalled with the new token.')) generateToken(); }}
                    disabled={generating}
                    className="text-xs text-text-muted hover:text-text-primary underline disabled:opacity-50">
                    {generating ? 'Rotating…' : 'Rotate'}
                  </button>
                )}
              </div>
            ) : envManaged ? (
              <p className="text-xs text-warning">
                <code className="font-mono">AGENT_TOKEN</code> is managed by the server environment but appears empty —
                set it and restart the server.
              </p>
            ) : isAdmin ? (
              <div className="flex items-center gap-2 px-3 py-2 bg-warning/10 border border-warning/20 rounded-lg">
                <span className="text-xs text-warning flex-1">No agent token yet — generate one to enable enrollment and downloads.</span>
                <Button variant="primary" size="sm" onClick={generateToken} loading={generating}>Generate Token</Button>
              </div>
            ) : (
              <p className="text-xs text-warning">No agent token is set — ask an admin to generate one.</p>
            )}

            {/* Advanced: raw .ps1 + manual command */}
            <details className="text-xs text-text-muted/80 pt-1">
              <summary className="cursor-pointer">Advanced: PowerShell installer</summary>
              <div className="mt-2 space-y-2">
                <Button variant="secondary" size="sm" onClick={() => api.download('agent-download/windows', 'homeshield-install.ps1')}>
                  <Download className="w-3.5 h-3.5" /> Download .ps1
                </Button>
                <div>Run from an <strong>elevated</strong> PowerShell:</div>
                <div className="relative">
                  <code className="block px-3 py-2 pr-10 bg-brand-main rounded-lg font-mono text-success break-all">{installCmd}</code>
                  <button onClick={copyCmd} title="Copy"
                    className="absolute right-2 top-1/2 -translate-y-1/2 p-1.5 rounded text-text-muted hover:text-text-primary hover:bg-brand-slate transition-colors">
                    {copied ? <Check className="w-3.5 h-3.5 text-success" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            </details>
          </div>
        </div>
      </Modal>

      <Modal open={!!tagsEdit} onClose={() => setTagsEdit(null)} title={`Groups — ${tagsEdit?.hostname ?? ''}`} size="sm">
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-text-muted mb-1">Groups / tags (comma-separated)</label>
            <input className="w-full bg-brand-panel border border-border-muted rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-brand-gold/50"
              value={tagsEdit?.text ?? ''} autoFocus placeholder="iot, kids, corporate"
              onChange={e => setTagsEdit(t => t && { ...t, text: e.target.value })} />
            <p className="text-xs text-text-muted/60 mt-1">Lowercase letters, numbers, - and _. Policies can target a group as <code className="font-mono">tag:&lt;name&gt;</code> to match every device in it.</p>
          </div>
          <div className="flex justify-end gap-3">
            <Button variant="ghost" onClick={() => setTagsEdit(null)}>Cancel</Button>
            <Button variant="primary" onClick={saveTags}>Save Groups</Button>
          </div>
        </div>
      </Modal>

      <Modal open={!!deleteId} onClose={() => setDeleteId(null)} title="Remove Device" size="sm">
        <p className="text-sm text-text-secondary">Remove this device from the inventory? If its agent is still running it will re-enroll on the next heartbeat.</p>
        <div className="flex justify-end gap-3 mt-6">
          <Button variant="ghost" onClick={() => setDeleteId(null)}>Cancel</Button>
          <Button variant="danger" onClick={() => deleteId && removeDevice(deleteId)}>Remove</Button>
        </div>
      </Modal>
    </div>
  );
}
