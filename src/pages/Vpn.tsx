import { useEffect, useState } from 'react';
import { Plus, Trash2, Download, QrCode, ToggleRight, ToggleLeft, Save, Server, Users, ShieldCheck, KeyRound } from 'lucide-react';
import { api } from '../lib/api';
import { Card, CardHeader, CardBody } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Modal } from '../components/ui/Modal';
import { StatusDot } from '../components/ui/StatusDot';
import type { VpnServer, VpnPeer } from '../lib/database.types';

function timeAgo(ts: string | null) {
  if (!ts) return 'never';
  const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function fmtBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
}

const cls = 'w-full bg-brand-panel border border-border-muted rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-brand-gold/50 focus:ring-1 focus:ring-brand-gold/20 transition-all';
const lbl = 'block text-xs font-medium text-text-muted mb-1';

export function Vpn() {
  const [server, setServer] = useState<VpnServer | null>(null);
  const [peers, setPeers] = useState<VpnPeer[]>([]);
  const [loading, setLoading] = useState(true);
  const [savingServer, setSavingServer] = useState(false);
  const [addOpen, setAddOpen] = useState(false);
  const [newName, setNewName] = useState('');
  const [newAllowed, setNewAllowed] = useState('0.0.0.0/0');
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [configPeer, setConfigPeer] = useState<VpnPeer | null>(null);
  const [configData, setConfigData] = useState<{ config: string; qr: string } | null>(null);

  async function fetchAll() {
    const [s, p] = await Promise.all([
      api.get<VpnServer>('vpn-server'),
      api.get<VpnPeer[]>('vpn-peers'),
    ]);
    setServer(s.data ?? null);
    setPeers(p.data ?? []);
    setLoading(false);
  }

  useEffect(() => { fetchAll(); }, []);

  async function saveServer() {
    if (!server) return;
    setSavingServer(true);
    const { data } = await api.put<VpnServer>('vpn-server', {
      interface: server.interface,
      listen_port: Number(server.listen_port),
      address: server.address,
      endpoint: server.endpoint,
      dns: server.dns,
      enabled: server.enabled,
    });
    if (data) setServer(data);
    setSavingServer(false);
  }

  async function addPeer() {
    if (!newName.trim()) return;
    const { data } = await api.post<VpnPeer>('vpn-peers', { name: newName, allowed_ips: newAllowed });
    setAddOpen(false);
    setNewName('');
    setNewAllowed('0.0.0.0/0');
    await fetchAll();
    if (data) showConfig(data);
  }

  async function togglePeer(peer: VpnPeer) {
    await api.patch(`vpn-peers/${peer.id}`, { enabled: !peer.enabled });
    fetchAll();
  }

  async function removePeer(id: string) {
    await api.del(`vpn-peers/${id}`);
    setDeleteId(null);
    fetchAll();
  }

  async function showConfig(peer: VpnPeer) {
    setConfigPeer(peer);
    setConfigData(null);
    const { data } = await api.get<{ config: string; qr: string }>(`vpn-peers/${peer.id}/config`);
    setConfigData(data ?? null);
  }

  function downloadConfig() {
    if (!configData || !configPeer) return;
    const blob = new Blob([configData.config], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${configPeer.name.replace(/[^a-z0-9]/gi, '_')}.conf`;
    a.click();
    URL.revokeObjectURL(url);
  }

  if (loading) return <div className="p-6 text-text-muted">Loading VPN configuration...</div>;

  return (
    <div className="p-4 lg:p-6 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-text-primary">VPN</h1>
          <p className="text-sm text-text-muted mt-0.5">
            WireGuard · IPSec/IKEv2 · {peers.filter(p => p.enabled).length} WireGuard peers
          </p>
        </div>
        <Button variant="primary" onClick={() => setAddOpen(true)}><Plus className="w-4 h-4" /> Add Peer</Button>
      </div>

      <IpsecSection />

      {/* WireGuard server configuration */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-brand-gold" />
            <span className="font-semibold text-text-primary">WireGuard Server</span>
          </div>
        </CardHeader>
        <CardBody>
          {server && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                <div>
                  <label className={lbl}>Public Endpoint (host/IP clients connect to)</label>
                  <input className={cls} value={server.endpoint} placeholder="vpn.example.com or 203.0.113.5"
                    onChange={e => setServer({ ...server, endpoint: e.target.value })} />
                </div>
                <div>
                  <label className={lbl}>Listen Port</label>
                  <input type="number" className={cls} value={server.listen_port}
                    onChange={e => setServer({ ...server, listen_port: Number(e.target.value) })} />
                </div>
                <div>
                  <label className={lbl}>Interface</label>
                  <input className={cls} value={server.interface}
                    onChange={e => setServer({ ...server, interface: e.target.value })} />
                </div>
                <div>
                  <label className={lbl}>Tunnel Address / Subnet</label>
                  <input className={cls} value={server.address} placeholder="10.8.0.1/24"
                    onChange={e => setServer({ ...server, address: e.target.value })} />
                </div>
                <div>
                  <label className={lbl}>Client DNS</label>
                  <input className={cls} value={server.dns} placeholder="1.1.1.1"
                    onChange={e => setServer({ ...server, dns: e.target.value })} />
                </div>
                <div>
                  <label className={lbl}>Server Public Key</label>
                  <input className={`${cls} font-mono text-xs`} value={server.public_key} readOnly />
                </div>
              </div>
              <div className="flex items-center justify-between pt-2 border-t border-border-muted">
                <button onClick={() => setServer({ ...server, enabled: !server.enabled })} className="flex items-center gap-2 text-sm">
                  {server.enabled
                    ? <><ToggleRight className="w-6 h-6 text-success" /><span className="text-success font-medium">VPN Enabled</span></>
                    : <><ToggleLeft className="w-6 h-6 text-text-muted" /><span className="text-text-muted">VPN Disabled</span></>}
                </button>
                <Button variant="primary" onClick={saveServer} loading={savingServer}>
                  <Save className="w-4 h-4" /> Save & Apply
                </Button>
              </div>
              {server.enabled && !server.endpoint && (
                <p className="text-xs text-warning">Set a public endpoint so clients know where to connect.</p>
              )}
            </div>
          )}
        </CardBody>
      </Card>

      {/* Peers */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Users className="w-4 h-4 text-brand-gold" />
            <span className="font-semibold text-text-primary">Peers</span>
          </div>
        </CardHeader>
        <CardBody>
          {peers.length === 0 ? (
            <div className="text-center py-8 text-text-muted text-sm">No peers yet. Add one to generate a client config.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border-muted text-text-muted">
                    <th className="px-3 py-2 text-left font-medium">Name</th>
                    <th className="px-3 py-2 text-left font-medium">Tunnel IP</th>
                    <th className="px-3 py-2 text-left font-medium">Last Handshake</th>
                    <th className="px-3 py-2 text-left font-medium">Transfer</th>
                    <th className="px-3 py-2 text-right font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {peers.map(peer => (
                    <tr key={peer.id} className={`border-b border-border-muted/50 ${peer.enabled ? '' : 'opacity-40'}`}>
                      <td className="px-3 py-2.5">
                        <div className="flex items-center gap-2">
                          <StatusDot status={peer.last_handshake && Date.now() - new Date(peer.last_handshake).getTime() < 180000 ? 'ok' : 'pending'} />
                          <span className="font-medium text-text-primary">{peer.name}</span>
                        </div>
                      </td>
                      <td className="px-3 py-2.5 font-mono text-text-secondary">{peer.address}</td>
                      <td className="px-3 py-2.5 text-text-muted">{timeAgo(peer.last_handshake)}</td>
                      <td className="px-3 py-2.5 text-text-muted">↓{fmtBytes(peer.rx_bytes)} ↑{fmtBytes(peer.tx_bytes)}</td>
                      <td className="px-3 py-2.5">
                        <div className="flex items-center justify-end gap-1.5">
                          <button onClick={() => showConfig(peer)} title="Show config / QR"
                            className="p-1.5 rounded text-text-muted hover:text-brand-gold hover:bg-brand-gold/10 transition-colors">
                            <QrCode className="w-3.5 h-3.5" />
                          </button>
                          <button onClick={() => togglePeer(peer)} title={peer.enabled ? 'Disable' : 'Enable'}>
                            {peer.enabled ? <ToggleRight className="w-5 h-5 text-success" /> : <ToggleLeft className="w-5 h-5 text-text-muted" />}
                          </button>
                          <button onClick={() => setDeleteId(peer.id)}
                            className="p-1.5 rounded text-text-muted hover:text-danger hover:bg-danger/10 transition-colors">
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardBody>
      </Card>

      {/* Add peer modal */}
      <Modal open={addOpen} onClose={() => setAddOpen(false)} title="Add VPN Peer" size="md">
        <div className="space-y-4">
          <div>
            <label className={lbl}>Peer Name *</label>
            <input className={cls} value={newName} onChange={e => setNewName(e.target.value)} placeholder="e.g. Phone, Laptop" autoFocus />
          </div>
          <div>
            <label className={lbl}>Allowed IPs (what the client routes through the tunnel)</label>
            <input className={cls} value={newAllowed} onChange={e => setNewAllowed(e.target.value)} placeholder="0.0.0.0/0" />
            <p className="text-xs text-text-muted/60 mt-1">Use 0.0.0.0/0 for full tunnel, or a subnet like 10.8.0.0/24 for split tunnel.</p>
          </div>
          <div className="flex justify-end gap-3 pt-2 border-t border-border-muted">
            <Button variant="ghost" onClick={() => setAddOpen(false)}>Cancel</Button>
            <Button variant="primary" onClick={addPeer}>Create Peer</Button>
          </div>
        </div>
      </Modal>

      {/* Config / QR modal */}
      <Modal open={!!configPeer} onClose={() => { setConfigPeer(null); setConfigData(null); }} title={`Config — ${configPeer?.name ?? ''}`} size="md">
        {!configData ? (
          <div className="py-8 text-center text-text-muted text-sm">Generating config...</div>
        ) : (
          <div className="space-y-4">
            <div className="flex justify-center">
              <img src={configData.qr} alt="WireGuard QR" className="rounded-lg bg-white p-2 w-56 h-56" />
            </div>
            <p className="text-xs text-text-muted text-center">Scan with the WireGuard mobile app, or download the config below.</p>
            <pre className="bg-brand-panel-soft border border-border-muted rounded-lg p-3 text-xs text-text-secondary font-mono overflow-x-auto max-h-48">{configData.config}</pre>
            <div className="flex items-center gap-2 p-2 rounded-lg bg-warning/10 border border-warning/20">
              <QrCode className="w-4 h-4 text-warning flex-shrink-0" />
              <p className="text-xs text-warning">This config contains the peer's private key. Treat it as a secret — it is shown once per request.</p>
            </div>
            <div className="flex justify-end">
              <Button variant="primary" onClick={downloadConfig}><Download className="w-4 h-4" /> Download .conf</Button>
            </div>
          </div>
        )}
      </Modal>

      {/* Delete confirm */}
      <Modal open={!!deleteId} onClose={() => setDeleteId(null)} title="Remove Peer" size="sm">
        <p className="text-sm text-text-secondary">Remove this peer? Its config will stop working immediately.</p>
        <div className="flex justify-end gap-3 mt-6">
          <Button variant="ghost" onClick={() => setDeleteId(null)}>Cancel</Button>
          <Button variant="danger" onClick={() => deleteId && removePeer(deleteId)}>Remove</Button>
        </div>
      </Modal>
    </div>
  );
}

// ─── IPSec / IKEv2 (client-to-site, Windows) ────────────────────────────────

interface IpsecServer {
  enabled: boolean; endpoint: string; pool_subnet: string; dns: string;
  local_subnets: string; status: string; ca_present?: boolean;
}
interface VpnUser { id: string; username: string; enabled: boolean; last_connected: string | null; created_at: string; }

function IpsecSection() {
  const [cfg, setCfg] = useState<IpsecServer | null>(null);
  const [users, setUsers] = useState<VpnUser[]>([]);
  const [saving, setSaving] = useState(false);
  const [addUser, setAddUser] = useState(false);
  const [uname, setUname] = useState('');
  const [upass, setUpass] = useState('');
  const [err, setErr] = useState('');

  async function load() {
    const [s, u] = await Promise.all([
      api.get<IpsecServer>('ipsec-server'),
      api.get<VpnUser[]>('vpn-users'),
    ]);
    setCfg(s.data ?? null);
    setUsers(u.data ?? []);
  }
  useEffect(() => { load(); }, []);

  async function save() {
    if (!cfg) return;
    setSaving(true);
    const { data } = await api.put<IpsecServer>('ipsec-server', {
      enabled: cfg.enabled, endpoint: cfg.endpoint, pool_subnet: cfg.pool_subnet,
      dns: cfg.dns, local_subnets: cfg.local_subnets,
    });
    if (data) setCfg(data);
    setSaving(false);
  }

  async function createUser() {
    setErr('');
    const { error } = await api.post('vpn-users', { username: uname, password: upass });
    if (error) { setErr(error); return; }
    setAddUser(false); setUname(''); setUpass('');
    load();
  }

  async function delUser(id: string) {
    await api.del(`vpn-users/${id}`);
    load();
  }

  if (!cfg) return null;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-brand-gold" />
            <span className="font-semibold text-text-primary">IPSec / IKEv2 (Windows client-to-site)</span>
          </div>
          <div className="flex items-center gap-2">
            <StatusDot status={cfg.ca_present ? 'ok' : 'pending'} />
            <span className="text-xs text-text-muted">{cfg.ca_present ? 'CA provisioned' : 'awaiting agent'}</span>
          </div>
        </div>
      </CardHeader>
      <CardBody>
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <div>
              <label className={lbl}>Public Endpoint (FQDN/IP clients connect to)</label>
              <input className={cls} value={cfg.endpoint} placeholder="vpn.example.com"
                onChange={e => setCfg({ ...cfg, endpoint: e.target.value })} />
            </div>
            <div>
              <label className={lbl}>Client IP Pool</label>
              <input className={cls} value={cfg.pool_subnet} placeholder="10.9.0.0/24"
                onChange={e => setCfg({ ...cfg, pool_subnet: e.target.value })} />
            </div>
            <div>
              <label className={lbl}>Client DNS</label>
              <input className={cls} value={cfg.dns} placeholder="1.1.1.1"
                onChange={e => setCfg({ ...cfg, dns: e.target.value })} />
            </div>
            <div className="sm:col-span-2">
              <label className={lbl}>Routed subnets (0.0.0.0/0 = full tunnel)</label>
              <input className={cls} value={cfg.local_subnets} placeholder="0.0.0.0/0"
                onChange={e => setCfg({ ...cfg, local_subnets: e.target.value })} />
            </div>
          </div>

          <div className="flex items-center justify-between flex-wrap gap-3 pt-2 border-t border-border-muted">
            <button onClick={() => setCfg({ ...cfg, enabled: !cfg.enabled })} className="flex items-center gap-2 text-sm">
              {cfg.enabled
                ? <><ToggleRight className="w-6 h-6 text-success" /><span className="text-success font-medium">IPSec Enabled</span></>
                : <><ToggleLeft className="w-6 h-6 text-text-muted" /><span className="text-text-muted">IPSec Disabled</span></>}
            </button>
            <div className="flex items-center gap-2">
              <Button variant="secondary" disabled={!cfg.ca_present}
                title={cfg.ca_present ? 'Download the Windows installer' : 'Available once the agent provisions the CA'}
                onClick={() => api.download('ipsec-client-script', 'homeshield-vpn-install.ps1')}>
                <Download className="w-4 h-4" /> Windows Installer
              </Button>
              <Button variant="primary" onClick={save} loading={saving}><Save className="w-4 h-4" /> Save &amp; Apply</Button>
            </div>
          </div>

          {/* VPN users */}
          <div className="pt-2">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2 text-sm text-text-secondary"><Users className="w-4 h-4" /> VPN Users (EAP)</div>
              <Button variant="ghost" size="sm" onClick={() => { setAddUser(true); setErr(''); }}><Plus className="w-3.5 h-3.5" /> Add User</Button>
            </div>
            {users.length === 0 ? (
              <p className="text-xs text-text-muted">No VPN users yet. Add one, then connect from Windows with that username/password.</p>
            ) : (
              <div className="space-y-1.5">
                {users.map(u => (
                  <div key={u.id} className="flex items-center justify-between px-3 py-2 rounded-lg bg-brand-panel-soft border border-border-muted">
                    <div className="flex items-center gap-2 text-sm">
                      <KeyRound className="w-3.5 h-3.5 text-text-muted" />
                      <span className="text-text-primary font-medium">{u.username}</span>
                      <span className="text-xs text-text-muted">· last connected {timeAgo(u.last_connected)}</span>
                    </div>
                    <button onClick={() => delUser(u.id)} className="p-1.5 rounded text-text-muted hover:text-danger hover:bg-danger/10 transition-colors">
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <Modal open={addUser} onClose={() => setAddUser(false)} title="Add VPN User" size="sm">
          <div className="space-y-4">
            {err && <div className="text-xs text-danger">{err}</div>}
            <div>
              <label className={lbl}>Username</label>
              <input className={cls} value={uname} onChange={e => setUname(e.target.value)} placeholder="alice" autoFocus />
            </div>
            <div>
              <label className={lbl}>Password (min. 8 characters)</label>
              <input type="password" className={cls} value={upass} onChange={e => setUpass(e.target.value)} />
              <p className="text-xs text-text-muted/60 mt-1">Stored for EAP-MSCHAPv2 verification. Use the Backup encryption passphrase to protect exports.</p>
            </div>
            <div className="flex justify-end gap-3">
              <Button variant="ghost" onClick={() => setAddUser(false)}>Cancel</Button>
              <Button variant="primary" onClick={createUser}>Create</Button>
            </div>
          </div>
        </Modal>
      </CardBody>
    </Card>
  );
}
