import { useEffect, useState } from 'react';
import { RefreshCw, Trash2, Monitor, Server, Smartphone, HelpCircle } from 'lucide-react';
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

  async function fetchDevices() {
    const { data } = await api.get<Device[]>('devices');
    setDevices(data ?? []);
    setLoading(false);
  }

  useEffect(() => {
    fetchDevices();
    const t = setInterval(fetchDevices, 15000);
    return () => clearInterval(t);
  }, []);

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
        <Button variant="ghost" size="sm" onClick={fetchDevices}><RefreshCw className="w-3.5 h-3.5" /></Button>
      </div>

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
