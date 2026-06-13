import { useEffect, useRef, useState } from 'react';
import {
  Download, Upload, Trash2, Shield, CheckCircle2, AlertTriangle,
  Database, Lock, RefreshCw, FileJson, RotateCcw, Plus
} from 'lucide-react';
import { api } from '../lib/api';
import { Card, CardHeader, CardBody } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Modal } from '../components/ui/Modal';
import type { BackupRecord } from '../lib/database.types';

function timeAgo(ts: string) {
  const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function formatSize(bytes: number) {
  if (!bytes) return '—';
  const k = 1024;
  if (bytes < k) return `${bytes} B`;
  if (bytes < k * k) return `${(bytes / k).toFixed(1)} KB`;
  return `${(bytes / k / k).toFixed(1)} MB`;
}

const triggerVariant: Record<string, 'info' | 'neutral' | 'warning'> = {
  manual: 'info', auto: 'neutral', 'pre-apply': 'warning',
};

const cls = 'w-full bg-brand-panel border border-border-muted rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-brand-gold/50 focus:ring-1 focus:ring-brand-gold/20 transition-all';
const lbl = 'block text-xs font-medium text-text-muted mb-1';

export function Backup() {
  const [records, setRecords] = useState<BackupRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [banner, setBanner] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  // Create modal
  const [createOpen, setCreateOpen] = useState(false);
  const [label, setLabel] = useState('');
  const [description, setDescription] = useState('');
  const [createPass, setCreatePass] = useState('');

  // Restore modal (stored backup or uploaded file)
  const [restore, setRestore] = useState<{ id?: string; payload?: string; encrypted: boolean; name: string } | null>(null);
  const [restorePass, setRestorePass] = useState('');

  const [deleteId, setDeleteId] = useState<string | null>(null);

  async function fetchRecords() {
    const { data } = await api.get<BackupRecord[]>('backups');
    setRecords(data ?? []);
    setLoading(false);
  }

  useEffect(() => { fetchRecords(); }, []);

  function flash(kind: 'success' | 'error', text: string) {
    setBanner({ kind, text });
    setTimeout(() => setBanner(null), 6000);
  }

  async function createBackup() {
    setBusy(true);
    const { data, error } = await api.post<BackupRecord>('backups', {
      label, description, passphrase: createPass || undefined,
    });
    setBusy(false);
    if (error) { flash('error', error); return; }
    setCreateOpen(false);
    setLabel(''); setDescription(''); setCreatePass('');
    flash('success', 'Backup created.');
    fetchRecords();
    if (data?.id) api.download(`backups/${data.id}/download`);
  }

  async function runRestore() {
    if (!restore) return;
    setBusy(true);
    const { data, error } = await api.post<{ restored: Record<string, number> }>('backups/restore', {
      id: restore.id, payload: restore.payload, passphrase: restorePass || undefined,
    });
    setBusy(false);
    if (error) { flash('error', error); return; }
    const total = Object.values(data?.restored ?? {}).reduce((a, b) => a + b, 0);
    setRestore(null); setRestorePass('');
    flash('success', `Configuration restored (${total} records). The agent will re-apply within a cycle.`);
    fetchRecords();
  }

  async function onFilePicked(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    e.target.value = '';
    let encrypted = false;
    try { encrypted = JSON.parse(text)?.encrypted === true; } catch { /* validated server-side */ }
    setRestore({ payload: text, encrypted, name: file.name });
  }

  async function deleteRecord(id: string) {
    await api.del(`backups/${id}`);
    setDeleteId(null);
    fetchRecords();
  }

  return (
    <div className="p-4 lg:p-6 space-y-6">
      <input ref={fileInput} type="file" accept=".json,application/json" className="hidden" onChange={onFilePicked} />

      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-text-primary">Backup &amp; Restore</h1>
          <p className="text-sm text-text-muted mt-0.5">Capture and restore the full firewall configuration</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={fetchRecords}><RefreshCw className="w-3.5 h-3.5" /></Button>
          <Button variant="secondary" onClick={() => fileInput.current?.click()}>
            <Upload className="w-4 h-4" /> Import File
          </Button>
          <Button variant="primary" onClick={() => setCreateOpen(true)}>
            <Plus className="w-4 h-4" /> Create Backup
          </Button>
        </div>
      </div>

      {banner && (
        <div className={`flex items-center gap-2 px-4 py-3 rounded-xl text-sm border ${
          banner.kind === 'success' ? 'bg-success/10 border-success/20 text-success' : 'bg-danger/10 border-danger/20 text-danger'}`}>
          {banner.kind === 'success' ? <CheckCircle2 className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
          {banner.text}
        </div>
      )}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {[
          { label: 'Policies & NAT', icon: Shield, color: 'text-info bg-info/15' },
          { label: 'DNS & Threat Feeds', icon: Database, color: 'text-success bg-success/15' },
          { label: 'VPN (keys included)', icon: Lock, color: 'text-warning bg-warning/15' },
          { label: 'System Settings', icon: Lock, color: 'text-text-muted bg-brand-slate/50' },
        ].map(({ label, icon: Icon, color }) => (
          <div key={label} className="flex items-center gap-3 bg-brand-panel border border-border-muted rounded-xl p-4">
            <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${color}`}>
              <Icon className="w-4 h-4" />
            </div>
            <span className="text-xs text-text-secondary">{label}</span>
          </div>
        ))}
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <FileJson className="w-4 h-4 text-text-muted" />
            <span className="text-sm font-semibold text-text-primary">Backup History</span>
          </div>
        </CardHeader>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border-muted">
                <th className="px-4 py-3 text-left text-xs font-medium text-text-muted">Label</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-text-muted">Type</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-text-muted">Size</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-text-muted">Encrypted</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-text-muted">Created</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-text-muted">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={6} className="px-4 py-12 text-center text-text-muted">Loading...</td></tr>
              ) : records.length === 0 ? (
                <tr><td colSpan={6} className="px-4 py-12 text-center text-text-muted">No backups yet</td></tr>
              ) : records.map(rec => (
                <tr key={rec.id} className="border-b border-border-muted/50 hover:bg-brand-slate/30 transition-colors">
                  <td className="px-4 py-3">
                    <div className="font-medium text-text-primary">{rec.label || 'Untitled'}</div>
                    {rec.description && <div className="text-xs text-text-muted mt-0.5">{rec.description}</div>}
                    <div className="text-xs font-mono text-text-muted/60 mt-0.5">{rec.checksum?.slice(0, 28)}…</div>
                  </td>
                  <td className="px-4 py-3">
                    <Badge variant={triggerVariant[rec.trigger_type] ?? 'neutral'}>{rec.trigger_type}</Badge>
                  </td>
                  <td className="px-4 py-3 text-text-muted">{formatSize(rec.size_bytes)}</td>
                  <td className="px-4 py-3">
                    {rec.encrypted
                      ? <span className="flex items-center gap-1 text-xs text-success"><Lock className="w-3 h-3" /> Yes</span>
                      : <span className="text-xs text-text-muted">No</span>}
                  </td>
                  <td className="px-4 py-3 text-text-muted text-xs">
                    <div>{timeAgo(rec.created_at)}</div>
                    <div className="text-text-muted/60">{rec.created_by}</div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-1.5">
                      <button onClick={() => api.download(`backups/${rec.id}/download`)} title="Download"
                        className="p-1.5 rounded-lg text-text-muted hover:text-info hover:bg-info/10 transition-colors">
                        <Download className="w-3.5 h-3.5" />
                      </button>
                      <button onClick={() => { setRestore({ id: rec.id, encrypted: rec.encrypted, name: rec.label }); setRestorePass(''); }}
                        title="Restore" className="p-1.5 rounded-lg text-text-muted hover:text-warning hover:bg-warning/10 transition-colors">
                        <RotateCcw className="w-3.5 h-3.5" />
                      </button>
                      <button onClick={() => setDeleteId(rec.id)} title="Delete"
                        className="p-1.5 rounded-lg text-text-muted hover:text-danger hover:bg-danger/10 transition-colors">
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

      {/* Create */}
      <Modal open={createOpen} onClose={() => setCreateOpen(false)} title="Create Backup" size="md">
        <div className="space-y-4">
          <div>
            <label className={lbl}>Label</label>
            <input className={cls} value={label} onChange={e => setLabel(e.target.value)} placeholder={`Backup ${new Date().toLocaleDateString()}`} />
          </div>
          <div>
            <label className={lbl}>Description (optional)</label>
            <input className={cls} value={description} onChange={e => setDescription(e.target.value)} placeholder="e.g. before adding new policies" />
          </div>
          <div>
            <label className={lbl}>Encryption passphrase (optional)</label>
            <input type="password" className={cls} value={createPass} onChange={e => setCreatePass(e.target.value)} placeholder="Leave blank for an unencrypted backup" />
            <p className="text-xs text-text-muted/60 mt-1">Backups include VPN private keys. Set a passphrase (AES-256-GCM) to protect them — you'll need it to restore.</p>
          </div>
          <p className="text-xs text-text-muted">Captures firewall policies, NAT, DNS lists, threat feeds, VPN config and system settings. The file also downloads to your device.</p>
          <div className="flex justify-end gap-3 pt-2 border-t border-border-muted">
            <Button variant="ghost" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Button variant="primary" onClick={createBackup} loading={busy}><Download className="w-4 h-4" /> Create</Button>
          </div>
        </div>
      </Modal>

      {/* Restore */}
      <Modal open={!!restore} onClose={() => setRestore(null)} title="Restore Configuration" size="md">
        <div className="space-y-4">
          <div className="flex items-start gap-2 px-3 py-2.5 bg-warning/10 border border-warning/20 rounded-lg">
            <AlertTriangle className="w-4 h-4 text-warning flex-shrink-0 mt-0.5" />
            <p className="text-xs text-warning">
              This <strong>replaces</strong> all policies, NAT rules, DNS lists, threat feeds, VPN config and settings
              with the contents of <strong>{restore?.name}</strong>. Current configuration not in the backup will be removed.
            </p>
          </div>
          {restore?.encrypted && (
            <div>
              <label className={lbl}>Decryption passphrase</label>
              <input type="password" className={cls} value={restorePass} onChange={e => setRestorePass(e.target.value)} autoFocus />
            </div>
          )}
          <div className="flex justify-end gap-3 pt-2 border-t border-border-muted">
            <Button variant="ghost" onClick={() => setRestore(null)}>Cancel</Button>
            <Button variant="danger" onClick={runRestore} loading={busy}><RotateCcw className="w-4 h-4" /> Restore &amp; Replace</Button>
          </div>
        </div>
      </Modal>

      {/* Delete */}
      <Modal open={!!deleteId} onClose={() => setDeleteId(null)} title="Delete Backup" size="sm">
        <p className="text-sm text-text-secondary">Delete this backup record? Any file you already downloaded is unaffected.</p>
        <div className="flex justify-end gap-3 mt-6">
          <Button variant="ghost" onClick={() => setDeleteId(null)}>Cancel</Button>
          <Button variant="danger" onClick={() => deleteId && deleteRecord(deleteId)}>Delete</Button>
        </div>
      </Modal>
    </div>
  );
}
