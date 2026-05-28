import { useEffect, useState } from 'react';
import { Save, Shield, Server, Clock, Globe, AlertTriangle, RefreshCw } from 'lucide-react';
import { supabase } from '../lib/supabase';
import { Card, CardHeader, CardBody } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import type { SystemSetting } from '../lib/database.types';

type SettingsMap = Record<string, string>;

const groups = [
  {
    label: 'System',
    icon: Server,
    keys: ['system_name', 'deployment_mode', 'timezone'],
    fields: {
      system_name: { label: 'System Name', type: 'text', placeholder: 'HomeShield NGFW' },
      deployment_mode: { label: 'Deployment Mode', type: 'select', options: ['host', 'gateway'] },
      timezone: { label: 'Timezone', type: 'text', placeholder: 'UTC' },
    },
  },
  {
    label: 'Network',
    icon: Globe,
    keys: ['wan_interface', 'lan_interface'],
    fields: {
      wan_interface: { label: 'WAN Interface', type: 'text', placeholder: 'eth0' },
      lan_interface: { label: 'LAN Interface', type: 'text', placeholder: 'eth1' },
    },
  },
  {
    label: 'Security',
    icon: Shield,
    keys: ['rollback_timer_seconds', 'dns_filtering_enabled', 'ids_enabled'],
    fields: {
      rollback_timer_seconds: { label: 'Rollback Timer (seconds)', type: 'number', placeholder: '30' },
      dns_filtering_enabled: { label: 'DNS Filtering', type: 'boolean' },
      ids_enabled: { label: 'IDS Engine', type: 'boolean' },
    },
  },
  {
    label: 'Logging',
    icon: Clock,
    keys: ['log_retention_days', 'dashboard_refresh_seconds'],
    fields: {
      log_retention_days: { label: 'Log Retention (days)', type: 'number', placeholder: '90' },
      dashboard_refresh_seconds: { label: 'Dashboard Refresh (seconds)', type: 'number', placeholder: '10' },
    },
  },
];

type FieldDef = { label: string; type: string; placeholder?: string; options?: string[] };

function SettingField({
  fieldDef, value, onChange,
}: { fieldKey: string; fieldDef: FieldDef; value: string; onChange: (val: string) => void }) {
  const cls = 'bg-brand-panel border border-border-muted rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-brand-gold/50 focus:ring-1 focus:ring-brand-gold/20 transition-all';

  if (fieldDef.type === 'boolean') {
    return (
      <label className="flex items-center gap-3 cursor-pointer">
        <div
          onClick={() => onChange(value === 'true' ? 'false' : 'true')}
          className={`w-10 h-5 rounded-full transition-colors cursor-pointer relative ${value === 'true' ? 'bg-brand-gold' : 'bg-brand-slate'}`}
        >
          <div className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${value === 'true' ? 'translate-x-5' : 'translate-x-0.5'}`} />
        </div>
        <span className="text-sm text-text-secondary">{value === 'true' ? 'Enabled' : 'Disabled'}</span>
      </label>
    );
  }

  if (fieldDef.type === 'select' && fieldDef.options) {
    return (
      <select className={cls} value={value} onChange={e => onChange(e.target.value)}>
        {fieldDef.options.map(opt => <option key={opt} value={opt}>{opt}</option>)}
      </select>
    );
  }

  return (
    <input
      type={fieldDef.type === 'number' ? 'number' : 'text'}
      className={`${cls} w-full`}
      value={value}
      placeholder={fieldDef.placeholder}
      onChange={e => onChange(e.target.value)}
    />
  );
}

export function Settings() {
  const [settings, setSettings] = useState<SettingsMap>({});
  const [saved, setSaved] = useState<SettingsMap>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  async function fetchSettings() {
    const { data } = await supabase.from('system_settings').select('*');
    const map: SettingsMap = {};
    (data ?? []).forEach((s: SystemSetting) => { map[s.key] = s.value; });
    setSettings(map);
    setSaved(map);
    setLoading(false);
  }

  useEffect(() => { fetchSettings(); }, []);

  async function handleSave() {
    setSaving(true);
    const updates = Object.entries(settings).map(([key, value]) => ({ key, value, description: '', updated_at: new Date().toISOString() }));
    await supabase.from('system_settings').upsert(updates, { onConflict: 'key' });
    setSaved({ ...settings });
    setSaving(false);
    setSaveSuccess(true);
    setTimeout(() => setSaveSuccess(false), 3000);
  }

  const hasChanges = Object.keys(settings).some(k => settings[k] !== saved[k]);

  if (loading) {
    return <div className="flex items-center justify-center h-64 text-text-muted">Loading settings...</div>;
  }

  return (
    <div className="p-4 lg:p-6 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-text-primary">Settings</h1>
          <p className="text-sm text-text-muted mt-0.5">System configuration</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={fetchSettings}><RefreshCw className="w-3.5 h-3.5" /></Button>
          <Button variant="primary" onClick={handleSave} loading={saving} disabled={!hasChanges}>
            <Save className="w-4 h-4" />
            {saveSuccess ? 'Saved!' : 'Save Changes'}
          </Button>
        </div>
      </div>

      {hasChanges && (
        <div className="px-4 py-3 bg-warning/10 border border-warning/20 rounded-xl text-xs text-warning">
          You have unsaved changes.
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {groups.map(group => (
          <Card key={group.label}>
            <CardHeader>
              <div className="flex items-center gap-2">
                <group.icon className="w-4 h-4 text-text-muted" />
                <span className="text-sm font-semibold text-text-primary">{group.label}</span>
              </div>
            </CardHeader>
            <CardBody className="space-y-4">
              {group.keys.map(key => {
                const field = (group.fields as Record<string, FieldDef>)[key];
                if (!field) return null;
                return (
                  <div key={key}>
                    <label className="block text-xs font-medium text-text-muted mb-1">{field.label}</label>
                    <SettingField
                      fieldKey={key}
                      fieldDef={field}
                      value={settings[key] ?? ''}
                      onChange={val => setSettings(prev => ({ ...prev, [key]: val }))}
                    />
                  </div>
                );
              })}
            </CardBody>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-warning" />
            <span className="text-sm font-semibold text-text-primary">Recovery & Safety</span>
          </div>
        </CardHeader>
        <CardBody>
          <div className="space-y-4">
            <div className="p-4 bg-brand-panel-soft rounded-lg border border-border-muted space-y-2">
              <div className="text-sm font-medium text-text-primary">Auto-Rollback</div>
              <p className="text-xs text-text-muted">
                Every time firewall rules are applied, the previous ruleset is backed up. If the management UI becomes unreachable within the rollback timer window, rules revert automatically.
              </p>
              <div className="text-xs text-success">Rollback timer: {settings['rollback_timer_seconds'] ?? '30'} seconds</div>
            </div>
            <div className="p-4 bg-brand-panel-soft rounded-lg border border-border-muted space-y-2">
              <div className="text-sm font-medium text-text-primary">Recovery Mode</div>
              <p className="text-xs text-text-muted">
                If locked out, use the local console to run: <code className="px-1.5 py-0.5 bg-brand-slate rounded font-mono">homeshield-recover</code>
              </p>
              <p className="text-xs text-text-muted">
                This flushes all rules and restores the last known-good configuration.
              </p>
            </div>
            <div className="p-4 bg-brand-panel-soft rounded-lg border border-border-muted space-y-2">
              <div className="text-sm font-medium text-text-primary">Backup Configuration</div>
              <p className="text-xs text-text-muted">Export all policies, NAT rules, DNS entries, and system settings as a JSON backup.</p>
              <Button variant="secondary" size="sm">Export Backup</Button>
            </div>
          </div>
        </CardBody>
      </Card>
    </div>
  );
}
