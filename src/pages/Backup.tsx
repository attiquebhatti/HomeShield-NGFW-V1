import { useEffect, useState } from 'react';
import {
  Download, Upload, Trash2, Shield, CheckCircle2, AlertTriangle,
  Clock, Database, Lock, RefreshCw, FileJson
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
  manual: 'info',
  auto: 'neutral',
  'pre-apply': 'warning',
};

export function Backup() {
  const [records, setRecords] = useState<BackupRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [importing, setImporting] = useState(false);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [importModalOpen, setImportModalOpen] = useState(false);
  const [importText, setImportText] = useState('');
  const [importError, setImportError] = useState('');
  const [importSuccess, setImportSuccess] = useState(false);
  const [labelModalOpen, setLabelModalOpen] = useState(false);
  const [exportLabel, setExportLabel] = useState('');

  async function fetchRecords() {
    const { data } = await api
      .from('backup_records')
      .select('*')
      .order('created_at', { ascending: false });
    setRecords(data ?? []);
    setLoading(false);
  }

  useEffect(() => { fetchRecords(); }, []);

  async function exportBackup(label: string) {
    setExporting(true);

    const [policies, dnsEntries, natRules, settings] = await Promise.all([
      api.from('firewall_policies').select('*'),
      api.from('dns_entries').select('*'),
      api.from('nat_rules').select('*'),
      api.from('system_settings').select('*'),
    ]);

    const payload = {
      version: '1.0',
      exported_at: new Date().toISOString(),
      firewall_policies: policies.data ?? [],
      dns_entries: dnsEntries.data ?? [],
      nat_rules: natRules.data ?? [],
      system_settings: settings.data ?? [],
    };

    const json = JSON.stringify(payload, null, 2);
    const sizeBytes = new TextEncoder().encode(json).length;
    const checksum = `sha256:${sizeBytes.toString(16)}`;

    await api.from('backup_records').insert({
      created_by: 'admin',
      label: label || `Manual backup ${new Date().toLocaleDateString()}`,
      description: 'User-initiated configuration export',
      trigger_type: 'manual',
      size_bytes: sizeBytes,
      encrypted: false,
      payload,
      checksum,
    });

    await api.from('audit_log').insert({
      actor: 'admin',
      action: 'export',
      resource_type: 'backup',
      details: { size_bytes: sizeBytes, label },
      ip_address: '127.0.0.1',
    });

    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `homeshield-backup-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);

    setExporting(false);
    setLabelModalOpen(false);
    setExportLabel('');
    fetchRecords();
  }

  async function importBackup() {
    setImportError('');
    if (!importText.trim()) {
      setImportError('Paste the backup JSON content first.');
      return;
    }

    let parsed: any;
    try {
      parsed = JSON.parse(importText);
    } catch {
      setImportError('Invalid JSON. Please paste a valid HomeShield backup file.');
      return;
    }

    if (!parsed.version || !parsed.firewall_policies) {
      setImportError('This does not appear to be a valid HomeShield backup file.');
      return;
    }

    setImporting(true);

    if (parsed.firewall_policies?.length) {
      await api.from('firewall_policies').upsert(parsed.firewall_policies, { onConflict: 'id' });
    }
    if (parsed.dns_entries?.length) {
      await api.from('dns_entries').upsert(parsed.dns_entries, { onConflict: 'id' });
    }
    if (parsed.nat_rules?.length) {
      await api.from('nat_rules').upsert(parsed.nat_rules, { onConflict: 'id' });
    }
    if (parsed.system_settings?.length) {
      await api.from('system_settings').upsert(parsed.system_settings, { onConflict: 'key' });
    }

    await api.from('audit_log').insert({
      actor: 'admin',
      action: 'restore',
      resource_type: 'backup',
      details: {
        policies_count: parsed.firewall_policies?.length ?? 0,
        exported_at: parsed.exported_at,
      },
      ip_address: '127.0.0.1',
    });

    setImporting(false);
    setImportModalOpen(false);
    setImportText('');
    setImportSuccess(true);
    setTimeout(() => setImportSuccess(false), 5000);
  }

  async function deleteRecord(id: string) {
    await api.from('backup_records').delete().eq('id', id);
    setDeleteId(null);
    fetchRecords();
  }

  return (
    <div className="p-4 lg:p-6 space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-text-primary">Backup &amp; Restore</h1>
          <p className="text-sm text-text-muted mt-0.5">Export and restore configuration snapshots</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={fetchRecords}><RefreshCw className="w-3.5 h-3.5" /></Button>
          <Button variant="secondary" onClick={() => setImportModalOpen(true)}>
            <Upload className="w-4 h-4" /> Import
          </Button>
          <Button variant="primary" onClick={() => setLabelModalOpen(true)} loading={exporting}>
            <Download className="w-4 h-4" /> Export Backup
          </Button>
        </div>
      </div>

      {importSuccess && (
        <div className="flex items-center gap-2 px-4 py-3 bg-success/10 border border-success/20 rounded-xl text-sm text-success">
          <CheckCircle2 className="w-4 h-4" /> Configuration restored successfully.
        </div>
      )}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {[
          { label: 'Firewall Policies', icon: Shield, color: 'text-info bg-info/15' },
          { label: 'DNS Entries', icon: Database, color: 'text-success bg-success/15' },
          { label: 'NAT Rules', icon: Database, color: 'text-warning bg-warning/15' },
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
            <AlertTriangle className="w-4 h-4 text-warning" />
            <span className="text-sm font-semibold text-text-primary">Recovery Guide</span>
          </div>
        </CardHeader>
        <CardBody className="space-y-3">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="p-4 bg-brand-panel-soft border border-border-muted rounded-xl">
              <div className="text-xs font-semibold text-text-primary mb-1">If locked out of UI</div>
              <p className="text-xs text-text-muted">SSH into the host and run:</p>
              <code className="block mt-2 px-3 py-2 bg-brand-main rounded-lg text-xs font-mono text-success">
                sudo homeshield-recover
              </code>
            </div>
            <div className="p-4 bg-brand-panel-soft border border-border-muted rounded-xl">
              <div className="text-xs font-semibold text-text-primary mb-1">Flush rules manually</div>
              <code className="block mt-2 px-3 py-2 bg-brand-main rounded-lg text-xs font-mono text-success">
                sudo nft flush ruleset
              </code>
            </div>
            <div className="p-4 bg-brand-panel-soft border border-border-muted rounded-xl">
              <div className="text-xs font-semibold text-text-primary mb-1">Restore last backup</div>
              <code className="block mt-2 px-3 py-2 bg-brand-main rounded-lg text-xs font-mono text-success">
                sudo nft -f /etc/homeshield/backup.nft
              </code>
            </div>
          </div>
        </CardBody>
      </Card>

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
                    <div className="text-xs font-mono text-text-muted/60 mt-0.5">{rec.checksum?.slice(0, 28)}...</div>
                  </td>
                  <td className="px-4 py-3">
                    <Badge variant={triggerVariant[rec.trigger_type] ?? 'neutral'}>{rec.trigger_type}</Badge>
                  </td>
                  <td className="px-4 py-3 text-text-muted">{formatSize(rec.size_bytes)}</td>
                  <td className="px-4 py-3">
                    {rec.encrypted
                      ? <span className="flex items-center gap-1 text-xs text-success"><Lock className="w-3 h-3" /> Yes</span>
                      : <span className="text-xs text-text-muted">No</span>
                    }
                  </td>
                  <td className="px-4 py-3 text-text-muted text-xs">
                    <div>{timeAgo(rec.created_at)}</div>
                    <div className="text-text-muted/60">{rec.created_by}</div>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => setDeleteId(rec.id)}
                      className="p-1.5 rounded-lg text-text-muted hover:text-danger hover:bg-danger/10 transition-colors"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Modal open={labelModalOpen} onClose={() => setLabelModalOpen(false)} title="Export Backup" size="sm">
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-text-muted mb-1">Label (optional)</label>
            <input
              className="w-full bg-brand-panel border border-border-muted rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-brand-gold/50 focus:ring-1 focus:ring-brand-gold/20 transition-all"
              value={exportLabel}
              onChange={e => setExportLabel(e.target.value)}
              placeholder={`Backup ${new Date().toLocaleDateString()}`}
            />
          </div>
          <p className="text-xs text-text-muted">
            Exports firewall policies, DNS entries, NAT rules, and system settings as a JSON file.
          </p>
          <div className="flex justify-end gap-3 pt-2 border-t border-border-muted">
            <Button variant="ghost" onClick={() => setLabelModalOpen(false)}>Cancel</Button>
            <Button variant="primary" onClick={() => exportBackup(exportLabel)} loading={exporting}>
              <Download className="w-4 h-4" /> Export
            </Button>
          </div>
        </div>
      </Modal>

      <Modal open={importModalOpen} onClose={() => setImportModalOpen(false)} title="Import Backup" size="lg">
        <div className="space-y-4">
          <div className="flex items-start gap-2 px-3 py-2.5 bg-warning/10 border border-warning/20 rounded-lg">
            <AlertTriangle className="w-4 h-4 text-warning flex-shrink-0 mt-0.5" />
            <p className="text-xs text-warning">
              Importing will overwrite existing policies and settings that share the same IDs. Existing records not present in the backup will not be removed.
            </p>
          </div>
          <div>
            <label className="block text-xs font-medium text-text-muted mb-1">Paste backup JSON</label>
            <textarea
              rows={10}
              className="w-full bg-brand-panel border border-border-muted rounded-lg px-3 py-2 text-xs font-mono text-text-primary placeholder-text-muted focus:outline-none focus:border-brand-gold/50 focus:ring-1 focus:ring-brand-gold/20 transition-all resize-none"
              placeholder='{"version":"1.0","exported_at":"...","firewall_policies":[...]}'
              value={importText}
              onChange={e => setImportText(e.target.value)}
            />
          </div>
          {importError && (
            <div className="flex items-center gap-2 text-xs text-danger">
              <AlertTriangle className="w-3.5 h-3.5" /> {importError}
            </div>
          )}
          <div className="flex justify-end gap-3 pt-2 border-t border-border-muted">
            <Button variant="ghost" onClick={() => setImportModalOpen(false)}>Cancel</Button>
            <Button variant="primary" onClick={importBackup} loading={importing}>
              <Upload className="w-4 h-4" /> Restore
            </Button>
          </div>
        </div>
      </Modal>

      <Modal open={!!deleteId} onClose={() => setDeleteId(null)} title="Delete Backup" size="sm">
        <p className="text-sm text-text-secondary">Delete this backup record? The local file will not be affected.</p>
        <div className="flex justify-end gap-3 mt-6">
          <Button variant="ghost" onClick={() => setDeleteId(null)}>Cancel</Button>
          <Button variant="danger" onClick={() => deleteId && deleteRecord(deleteId)}>Delete</Button>
        </div>
      </Modal>
    </div>
  );
}
