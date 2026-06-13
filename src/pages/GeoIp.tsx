import { useEffect, useMemo, useState } from 'react';
import { Globe2, Save, Search, ToggleLeft, ToggleRight, ShieldBan, ShieldCheck } from 'lucide-react';
import { api } from '../lib/api';
import { Card, CardHeader, CardBody } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import type { SystemSetting } from '../lib/database.types';

// Common ISO 3166-1 alpha-2 countries for selection.
const COUNTRIES: [string, string][] = [
  ['ad', 'Andorra'], ['ae', 'United Arab Emirates'], ['af', 'Afghanistan'], ['ar', 'Argentina'],
  ['at', 'Austria'], ['au', 'Australia'], ['bd', 'Bangladesh'], ['be', 'Belgium'], ['bg', 'Bulgaria'],
  ['br', 'Brazil'], ['by', 'Belarus'], ['ca', 'Canada'], ['ch', 'Switzerland'], ['cl', 'Chile'],
  ['cn', 'China'], ['co', 'Colombia'], ['cz', 'Czechia'], ['de', 'Germany'], ['dk', 'Denmark'],
  ['eg', 'Egypt'], ['es', 'Spain'], ['fi', 'Finland'], ['fr', 'France'], ['gb', 'United Kingdom'],
  ['gr', 'Greece'], ['hk', 'Hong Kong'], ['hu', 'Hungary'], ['id', 'Indonesia'], ['ie', 'Ireland'],
  ['il', 'Israel'], ['in', 'India'], ['iq', 'Iraq'], ['ir', 'Iran'], ['it', 'Italy'], ['jp', 'Japan'],
  ['kp', 'North Korea'], ['kr', 'South Korea'], ['kz', 'Kazakhstan'], ['lt', 'Lithuania'],
  ['lv', 'Latvia'], ['mx', 'Mexico'], ['my', 'Malaysia'], ['ng', 'Nigeria'], ['nl', 'Netherlands'],
  ['no', 'Norway'], ['nz', 'New Zealand'], ['pe', 'Peru'], ['ph', 'Philippines'], ['pk', 'Pakistan'],
  ['pl', 'Poland'], ['pt', 'Portugal'], ['ro', 'Romania'], ['rs', 'Serbia'], ['ru', 'Russia'],
  ['sa', 'Saudi Arabia'], ['se', 'Sweden'], ['sg', 'Singapore'], ['th', 'Thailand'], ['tr', 'Turkey'],
  ['tw', 'Taiwan'], ['ua', 'Ukraine'], ['us', 'United States'], ['vn', 'Vietnam'], ['za', 'South Africa'],
];

export function GeoIp() {
  const [enabled, setEnabled] = useState(false);
  const [mode, setMode] = useState<'block' | 'allow'>('block');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    (async () => {
      const { data } = await api.get<SystemSetting[]>('system-settings');
      const map = Object.fromEntries((data ?? []).map(s => [s.key, s.value]));
      setEnabled(map.geoip_enabled === 'true');
      setMode(map.geoip_mode === 'allow' ? 'allow' : 'block');
      setSelected(new Set((map.geoip_countries || '').split(',').map((c: string) => c.trim().toLowerCase()).filter(Boolean)));
      setLoading(false);
    })();
  }, []);

  function toggleCountry(code: string) {
    setSelected(prev => {
      const next = new Set(prev);
      next.has(code) ? next.delete(code) : next.add(code);
      return next;
    });
  }

  async function save() {
    setSaving(true);
    await api.post('system-settings', {
      items: [
        { key: 'geoip_enabled', value: String(enabled) },
        { key: 'geoip_mode', value: mode },
        { key: 'geoip_countries', value: [...selected].join(',') },
      ],
    });
    setSaving(false);
    setSaved(true);
    setTimeout(() => setSaved(false), 4000);
  }

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return COUNTRIES.filter(([code, name]) => !q || name.toLowerCase().includes(q) || code.includes(q));
  }, [search]);

  if (loading) return <div className="p-6 text-text-muted">Loading GeoIP configuration...</div>;

  return (
    <div className="p-4 lg:p-6 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-text-primary">GeoIP Filtering</h1>
          <p className="text-sm text-text-muted mt-0.5">{selected.size} countries selected · {mode === 'block' ? 'block' : 'allow'} mode</p>
        </div>
        <div className="flex items-center gap-2">
          {saved && <span className="text-xs text-success">Saved — agent applies within a cycle</span>}
          <Button variant="primary" onClick={save} loading={saving}><Save className="w-4 h-4" /> Save &amp; Apply</Button>
        </div>
      </div>

      <Card>
        <CardBody>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <div>
              <div className="text-xs font-medium text-text-muted mb-2">Status</div>
              <button onClick={() => setEnabled(!enabled)} className="flex items-center gap-2 text-sm">
                {enabled
                  ? <><ToggleRight className="w-6 h-6 text-success" /><span className="text-success font-medium">GeoIP Filtering Enabled</span></>
                  : <><ToggleLeft className="w-6 h-6 text-text-muted" /><span className="text-text-muted">Disabled</span></>}
              </button>
            </div>
            <div>
              <div className="text-xs font-medium text-text-muted mb-2">Mode</div>
              <div className="flex gap-2">
                <button onClick={() => setMode('block')}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-sm transition-colors ${mode === 'block' ? 'border-danger/40 bg-danger/10 text-danger' : 'border-border-muted text-text-muted hover:bg-brand-slate'}`}>
                  <ShieldBan className="w-4 h-4" /> Block listed
                </button>
                <button onClick={() => setMode('allow')}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-sm transition-colors ${mode === 'allow' ? 'border-success/40 bg-success/10 text-success' : 'border-border-muted text-text-muted hover:bg-brand-slate'}`}>
                  <ShieldCheck className="w-4 h-4" /> Allow only listed
                </button>
              </div>
              <p className="text-xs text-text-muted/70 mt-2">
                {mode === 'block'
                  ? 'Drops traffic to and from the selected countries.'
                  : 'Allows inbound only from the selected countries (private ranges and established connections are always permitted).'}
              </p>
            </div>
          </div>
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div className="flex items-center gap-2">
              <Globe2 className="w-4 h-4 text-brand-gold" />
              <span className="font-semibold text-text-primary">Countries</span>
            </div>
            <div className="relative w-56">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-muted" />
              <input className="w-full bg-brand-panel border border-border-muted rounded-lg pl-9 pr-3 py-1.5 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:border-brand-gold/50"
                placeholder="Search countries..." value={search} onChange={e => setSearch(e.target.value)} />
            </div>
          </div>
        </CardHeader>
        <CardBody>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
            {filtered.map(([code, name]) => {
              const on = selected.has(code);
              return (
                <button key={code} onClick={() => toggleCountry(code)}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-sm text-left transition-colors ${on ? 'border-brand-gold/40 bg-brand-gold/10 text-text-primary' : 'border-border-muted text-text-muted hover:bg-brand-slate'}`}>
                  <span className={`w-2 h-2 rounded-full flex-shrink-0 ${on ? 'bg-brand-gold' : 'bg-border-strong'}`} />
                  <span className="uppercase text-xs font-mono text-text-muted/70 w-5 flex-shrink-0">{code}</span>
                  <span className="truncate">{name}</span>
                </button>
              );
            })}
          </div>
        </CardBody>
      </Card>

      <div className="flex items-start gap-2 px-3 py-2.5 bg-warning/10 border border-warning/20 rounded-lg">
        <Globe2 className="w-4 h-4 text-warning flex-shrink-0 mt-0.5" />
        <p className="text-xs text-warning">
          Country IP ranges are downloaded by the agent from public zone files and compiled into an nftables set
          at priority −5 (before policy). GeoIP is approximate — VPNs, CDNs and cloud IPs may not map to the
          expected country. In allow mode, double-check your own country is selected before saving.
        </p>
      </div>
    </div>
  );
}
