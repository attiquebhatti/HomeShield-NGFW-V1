import { useEffect, useState } from 'react';
import { RefreshCw, Trash2, Monitor, Server, Smartphone, HelpCircle, Download, Plus, AlertTriangle, Copy, Check } from 'lucide-react';
import { api } from '../lib/api';
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
  const [installOpen, setInstallOpen] = useState(false);
  const [agentEnabled, setAgentEnabled] = useState(true);
  const [agentToken, setAgentToken] = useState('');
  const [copied, setCopied] = useState(false);

  async function fetchDevices() {
    const { data } = await api.get<Device[]>('devices');
    setDevices(data ?? []);
    setLoading(false);
  }

  useEffect(() => {
    fetchDevices();
    api.get<{ agent_api_enabled: boolean; token?: string }>('agent-status').then(r => {
      setAgentEnabled(r.data?.agent_api_enabled ?? true);
      setAgentToken(r.data?.token ?? '');
    });
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
        <div className="flex items-start gap-2 px-4 py-3 bg-warning/10 border border-warning/20 rounded-xl text-sm text-warning">
          <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
          <span>The agent API is disabled — set <code className="font-mono">AGENT_TOKEN</code> in the server environment and restart, or agents can't enroll.</span>
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
                <th className="px-4 py-3 text-left font-medium">Agent</th>
                <th className="px-4 py-3 text-left font-medium">Last Seen</th>
                <th className="px-4 py-3 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={6} className="px-4 py-12 text-center text-text-muted">Loading...</td></tr>
              ) : devices.length === 0 ? (
                <tr><td colSpan={6} className="px-4 py-12 text-center text-text-muted">No devices enrolled yet. Install an agent and point it at this server.</td></tr>
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
                    <td className="px-4 py-3 text-text-muted">{d.agent_version || '—'}</td>
                    <td className="px-4 py-3 text-text-muted">{timeAgo(d.last_seen)}</td>
                    <td className="px-4 py-3 text-right">
                      <button onClick={() => setDeleteId(d.id)} title="Remove device"
                        className="p-1.5 rounded text-text-muted hover:text-danger hover:bg-danger/10 transition-colors">
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
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
              Download the installer, then run it from an <strong>elevated</strong> PowerShell. It enrolls the
              device, enforces firewall policy, and sets up the IPSec VPN client.
            </p>
            <Button variant="primary" onClick={() => api.download('agent-download/windows', 'homeshield-install.ps1')}>
              <Download className="w-4 h-4" /> Download Windows Installer (.ps1)
            </Button>
            <div className="text-xs text-text-muted mt-1">
              Open PowerShell <strong>as Administrator</strong>, <code className="font-mono">cd</code> to the download
              folder, then run (the server URL and token are pre-filled):
            </div>
            <div className="relative">
              <code className="block px-3 py-2 pr-10 bg-brand-main rounded-lg text-xs font-mono text-success break-all">{installCmd}</code>
              <button onClick={copyCmd} title="Copy"
                className="absolute right-2 top-1/2 -translate-y-1/2 p-1.5 rounded text-text-muted hover:text-text-primary hover:bg-brand-slate transition-colors">
                {copied ? <Check className="w-3.5 h-3.5 text-success" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
            {agentToken
              ? <p className="text-xs text-text-muted/70">The <code className="font-mono">-ExecutionPolicy Bypass</code> clears the unsigned-script block on the downloaded file.</p>
              : <p className="text-xs text-warning">No <code className="font-mono">AGENT_TOKEN</code> is set on the server, so the command shows a placeholder. Set one in the server environment and restart first.</p>}
          </div>

          {/* Linux */}
          <div className="space-y-2 pt-3 border-t border-border-muted">
            <div className="flex items-center gap-2 text-sm font-semibold text-text-primary">
              <Server className="w-4 h-4 text-warning" /> Linux (gateway / host)
            </div>
            <p className="text-xs text-text-muted">
              Build and install the <code className="font-mono">.deb</code> on the Linux machine
              (<code className="font-mono">packaging/agent/build-deb.sh</code>), set
              <code className="font-mono"> /etc/homeshield/agent.env</code>, then
              <code className="font-mono"> systemctl enable --now homeshield-agent</code>. This host runs nftables
              enforcement and the IPSec/WireGuard VPN <em>server</em>. See <code className="font-mono">agent/README.md</code>.
            </p>
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
