import { useEffect, useState, useCallback } from 'react';
import {
  Shield, AlertTriangle, Activity, TrendingUp,
  ArrowUpRight, ArrowDownLeft, Ban, CheckCircle2,
  Cpu, Server, Clock, Eye, RefreshCw, ChevronRight
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { api } from '../lib/api';
import { Card, CardHeader, CardBody } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { StatusDot } from '../components/ui/StatusDot';
import type {
  FirewallPolicy, FirewallLog, IdsAlert, NetworkInterface, Session,
  SystemHealthSnapshot, RuleApplyHistory
} from '../lib/database.types';

function formatBytes(bytes: number): string {
  if (!bytes) return '0 B';
  const k = 1024, sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

function timeAgo(ts: string): string {
  const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return new Date(ts).toLocaleDateString();
}

const severityVariant: Record<string, 'danger' | 'warning' | 'info' | 'neutral'> = {
  critical: 'danger', high: 'danger', medium: 'warning', low: 'info',
};

function Sparkline({ values, color = '#C9A227', height = 32 }: { values: number[]; color?: string; height?: number }) {
  if (values.length < 2) return null;
  const max = Math.max(...values, 1);
  const w = 120, h = height;
  const pts = values.map((v, i) => {
    const x = (i / (values.length - 1)) * w;
    const y = h - (v / max) * h;
    return `${x},${y}`;
  }).join(' ');
  const area = `0,${h} ${pts} ${w},${h}`;

  return (
    <svg width={w} height={h} className="overflow-visible">
      <defs>
        <linearGradient id={`sg-${color.replace('#', '')}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.25" />
          <stop offset="100%" stopColor={color} stopOpacity="0.02" />
        </linearGradient>
      </defs>
      <polygon points={area} fill={`url(#sg-${color.replace('#', '')})`} />
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function GaugeBar({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <span className="text-xs text-text-muted">{label}</span>
        <span className="text-xs font-semibold text-text-primary tabular-nums">{value.toFixed(1)}%</span>
      </div>
      <div className="h-1.5 bg-brand-slate rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ${color}`}
          style={{ width: `${Math.min(100, value)}%` }}
        />
      </div>
    </div>
  );
}

function ServicePill({ name, status }: { name: string; status: string }) {
  const running = status === 'running';
  return (
    <div className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium ${
      running ? 'bg-success/10 border-success/20 text-success' : 'bg-danger/10 border-danger/20 text-danger'
    }`}>
      <StatusDot status={running ? 'ok' : 'error'} pulse={running} />
      {name}
    </div>
  );
}

interface DashboardData {
  totalPolicies: number;
  activePolicies: number;
  totalAllowed: number;
  totalBlocked: number;
  activeAlerts: number;
  topSrcIps: { ip: string; count: number }[];
  topDstPorts: { port: number; count: number }[];
  cpuHistory: number[];
  ramHistory: number[];
}

const serviceLabels: Record<string, string> = {
  api: 'API Server',
  agent: 'Firewall Agent',
  dns_filter: 'DNS Filter',
  ids: 'IDS Engine',
};

export function Dashboard() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [recentLogs, setRecentLogs] = useState<FirewallLog[]>([]);
  const [recentAlerts, setRecentAlerts] = useState<IdsAlert[]>([]);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [health, setHealth] = useState<SystemHealthSnapshot | null>(null);
  const [applyHistory, setApplyHistory] = useState<RuleApplyHistory[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());

  const fetchAll = useCallback(async () => {
    const [
      policiesRes, logsRes, alertsRes, ifaceRes, sessRes, healthRes, historyRes
    ] = await Promise.all([
      api.from<Pick<FirewallPolicy, 'id' | 'enabled'>>('firewall_policies').select('id, enabled'),
      api.from<FirewallLog>('firewall_logs').select('*').order('timestamp', { ascending: false }).limit(50),
      api.from<IdsAlert>('ids_alerts').select('*').order('timestamp', { ascending: false }).limit(5),
      api.from<NetworkInterface>('network_interfaces').select('*'),
      api.from<Session>('sessions').select('*').order('last_seen', { ascending: false }).limit(5),
      api.from<SystemHealthSnapshot>('system_health_snapshots').select('*').order('recorded_at', { ascending: false }).limit(10),
      api.from<RuleApplyHistory>('rule_apply_history').select('*').order('applied_at', { ascending: false }).limit(5),
    ]);

    const policies = policiesRes.data ?? [];
    const logs = logsRes.data ?? [];
    const healthSnaps = (healthRes.data ?? []).reverse() as SystemHealthSnapshot[];

    const allowed = logs.filter(l => l.action === 'allow').length;
    const blocked = logs.filter(l => l.action === 'deny' || l.action === 'reject').length;
    const unackAlerts = (alertsRes.data ?? []).filter((a: IdsAlert) => !a.acknowledged).length;

    const ipCounts: Record<string, number> = {};
    const portCounts: Record<number, number> = {};
    logs.forEach(l => {
      if (l.src_ip) ipCounts[l.src_ip] = (ipCounts[l.src_ip] ?? 0) + 1;
      if (l.dst_port) portCounts[l.dst_port] = (portCounts[l.dst_port] ?? 0) + 1;
    });

    setData({
      totalPolicies: policies.length,
      activePolicies: policies.filter(p => p.enabled).length,
      totalAllowed: allowed,
      totalBlocked: blocked,
      activeAlerts: unackAlerts,
      topSrcIps: Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([ip, count]) => ({ ip, count })),
      topDstPorts: Object.entries(portCounts).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([port, count]) => ({ port: Number(port), count })),
      cpuHistory: healthSnaps.map(h => h.cpu_percent),
      ramHistory: healthSnaps.map(h => h.ram_percent),
    });
    setRecentLogs(logs.slice(0, 8));
    setRecentAlerts(alertsRes.data ?? []);
    setInterfaces(ifaceRes.data ?? []);
    setSessions(sessRes.data ?? []);
    setHealth(healthSnaps[healthSnaps.length - 1] ?? null);
    setApplyHistory(historyRes.data ?? []);
    setLastUpdated(new Date());
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 15000);
    return () => clearInterval(interval);
  }, [fetchAll]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex items-center gap-3 text-text-muted">
          <svg className="animate-spin w-5 h-5" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          Loading dashboard...
        </div>
      </div>
    );
  }

  const services = (health?.services ?? {}) as Record<string, string>;

  return (
    <div className="p-4 lg:p-6 space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-text-primary">Dashboard</h1>
          <p className="text-xs text-text-muted mt-0.5">Updated {timeAgo(lastUpdated.toISOString())}</p>
        </div>
        <div className="flex items-center gap-3">
          <button onClick={fetchAll} className="p-2 rounded-lg text-text-muted hover:text-text-primary hover:bg-brand-slate transition-colors">
            <RefreshCw className="w-4 h-4" />
          </button>
          <div className="flex items-center gap-2 px-3 py-1.5 bg-success/10 border border-success/20 rounded-lg">
            <StatusDot status="up" pulse />
            <span className="text-xs font-medium text-success">Firewall Active</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Active Policies', value: data?.activePolicies ?? 0, sub: `${data?.totalPolicies ?? 0} total`, icon: Shield, iconColor: 'text-brand-gold', bgColor: 'bg-brand-gold/10' },
          { label: 'Allowed (recent)', value: data?.totalAllowed ?? 0, sub: 'last 50 events', icon: CheckCircle2, iconColor: 'text-success', bgColor: 'bg-success/10' },
          { label: 'Blocked (recent)', value: data?.totalBlocked ?? 0, sub: 'last 50 events', icon: Ban, iconColor: 'text-danger', bgColor: 'bg-danger/10' },
          { label: 'IDS Alerts', value: data?.activeAlerts ?? 0, sub: 'unacknowledged', icon: AlertTriangle, iconColor: 'text-warning', bgColor: 'bg-warning/10' },
        ].map(({ label, value, sub, icon: Icon, iconColor, bgColor }) => (
          <Card key={label} className="p-5">
            <div className="flex items-start gap-3">
              <div className={`w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 ${bgColor}`}>
                <Icon className={`w-4 h-4 ${iconColor}`} />
              </div>
              <div>
                <div className="text-2xl font-bold text-text-primary tabular-nums">{value}</div>
                <div className="text-xs text-text-muted mt-0.5">{label}</div>
                <div className="text-xs text-text-muted/60 mt-0.5">{sub}</div>
              </div>
            </div>
          </Card>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-brand-gold" />
              <span className="text-sm font-semibold text-text-primary">System Health</span>
            </div>
          </CardHeader>
          <CardBody className="space-y-4">
            {health ? (
              <>
                <div className="space-y-3">
                  <GaugeBar label="CPU" value={health.cpu_percent} color="bg-brand-gold" />
                  <GaugeBar label="RAM" value={health.ram_percent} color="bg-success" />
                  <GaugeBar label="Disk" value={health.disk_percent} color="bg-warning" />
                </div>
                <div className="grid grid-cols-3 gap-2 pt-2 border-t border-border-muted text-center">
                  <div>
                    <div className="text-xs font-semibold text-text-primary">{health.load_avg_1m.toFixed(2)}</div>
                    <div className="text-xs text-text-muted">load 1m</div>
                  </div>
                  <div>
                    <div className="text-xs font-semibold text-text-primary">{health.load_avg_5m.toFixed(2)}</div>
                    <div className="text-xs text-text-muted">load 5m</div>
                  </div>
                  <div>
                    <div className="text-xs font-semibold text-text-primary">{health.disk_used_gb.toFixed(1)}GB</div>
                    <div className="text-xs text-text-muted">disk used</div>
                  </div>
                </div>
              </>
            ) : (
              <p className="text-xs text-text-muted">No health data available. Agent not connected.</p>
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-brand-gold" />
              <span className="text-sm font-semibold text-text-primary">Resource Trend</span>
            </div>
          </CardHeader>
          <CardBody className="space-y-4">
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-text-muted">CPU %</span>
                <span className="text-xs font-semibold text-brand-gold tabular-nums">{health?.cpu_percent.toFixed(1) ?? '—'}%</span>
              </div>
              <Sparkline values={data?.cpuHistory ?? []} color="#C9A227" height={36} />
            </div>
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-text-muted">RAM %</span>
                <span className="text-xs font-semibold text-success tabular-nums">{health?.ram_percent.toFixed(1) ?? '—'}%</span>
              </div>
              <Sparkline values={data?.ramHistory ?? []} color="#22C55E" height={36} />
            </div>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-brand-gold" />
              <span className="text-sm font-semibold text-text-primary">Services</span>
            </div>
          </CardHeader>
          <CardBody className="space-y-2">
            {Object.keys(serviceLabels).map(key => (
              <ServicePill key={key} name={serviceLabels[key]} status={services[key] ?? 'unknown'} />
            ))}
            {Object.keys(services).length === 0 && (
              <p className="text-xs text-text-muted">Agent not connected. Services status unavailable.</p>
            )}
          </CardBody>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <span className="text-sm font-semibold text-text-primary">Interfaces</span>
              <Link to="/interfaces" className="text-xs text-brand-gold hover:text-brand-gold-bright flex items-center gap-1">
                View <ChevronRight className="w-3 h-3" />
              </Link>
            </div>
          </CardHeader>
          <div className="divide-y divide-border-muted">
            {interfaces.map(iface => (
              <div key={iface.id} className="flex items-center justify-between px-5 py-3">
                <div className="flex items-center gap-3">
                  <StatusDot status={iface.status} pulse={iface.status === 'up'} />
                  <div>
                    <div className="text-sm font-medium text-text-primary">{iface.display_name || iface.name}</div>
                    <div className="text-xs text-text-muted font-mono">{iface.ip_address || 'no IP'}</div>
                  </div>
                </div>
                <Badge variant={iface.role === 'wan' ? 'info' : iface.role === 'lan' ? 'success' : 'neutral'}>
                  {iface.role.toUpperCase()}
                </Badge>
              </div>
            ))}
          </div>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-brand-gold" />
              <span className="text-sm font-semibold text-text-primary">Top Source IPs</span>
            </div>
          </CardHeader>
          <CardBody className="space-y-2.5">
            {(data?.topSrcIps ?? []).map(({ ip, count }) => {
              const pct = Math.min(100, Math.round((count / ((data?.topSrcIps[0]?.count) || 1)) * 100));
              return (
                <div key={ip}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-text-secondary font-mono">{ip}</span>
                    <span className="text-text-muted tabular-nums">{count}</span>
                  </div>
                  <div className="h-1 bg-brand-slate rounded-full overflow-hidden">
                    <div className="h-full bg-brand-gold rounded-full" style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
            {!data?.topSrcIps.length && <p className="text-xs text-text-muted">No traffic data</p>}
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-brand-gold" />
              <span className="text-sm font-semibold text-text-primary">Top Dest Ports</span>
            </div>
          </CardHeader>
          <CardBody className="space-y-2.5">
            {(data?.topDstPorts ?? []).map(({ port, count }) => {
              const pct = Math.min(100, Math.round((count / ((data?.topDstPorts[0]?.count) || 1)) * 100));
              const svc: Record<number, string> = { 443: 'HTTPS', 80: 'HTTP', 53: 'DNS', 22: 'SSH', 23: 'Telnet', 445: 'SMB', 4444: 'RAT?' };
              return (
                <div key={port}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-text-secondary font-mono">{port} <span className="text-text-muted">{svc[port] ?? ''}</span></span>
                    <span className="text-text-muted tabular-nums">{count}</span>
                  </div>
                  <div className="h-1 bg-brand-slate rounded-full overflow-hidden">
                    <div className="h-full bg-success rounded-full" style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
            {!data?.topDstPorts.length && <p className="text-xs text-text-muted">No traffic data</p>}
          </CardBody>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Eye className="w-4 h-4 text-brand-gold" />
                <span className="text-sm font-semibold text-text-primary">Recent Traffic</span>
              </div>
              <Link to="/logs" className="text-xs text-brand-gold hover:text-brand-gold-bright flex items-center gap-1">
                View all <ChevronRight className="w-3 h-3" />
              </Link>
            </div>
          </CardHeader>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border-muted">
                  <th className="text-left px-5 py-2.5 text-text-muted font-medium">Action</th>
                  <th className="text-left px-3 py-2.5 text-text-muted font-medium">Source</th>
                  <th className="text-left px-3 py-2.5 text-text-muted font-medium">Dest</th>
                  <th className="text-left px-3 py-2.5 text-text-muted font-medium">Proto</th>
                  <th className="text-right px-5 py-2.5 text-text-muted font-medium">Age</th>
                </tr>
              </thead>
              <tbody>
                {recentLogs.map(log => (
                  <tr key={log.id} className="border-b border-border-muted/50 hover:bg-brand-slate/30 transition-colors">
                    <td className="px-5 py-2.5">
                      <Badge variant={log.action === 'allow' ? 'success' : log.action === 'deny' ? 'danger' : 'warning'}>
                        {log.action}
                      </Badge>
                    </td>
                    <td className="px-3 py-2.5 font-mono text-text-secondary">{log.src_ip ?? '—'}</td>
                    <td className="px-3 py-2.5 font-mono text-text-secondary">
                      {log.dst_ip ?? '—'}:{log.dst_port ?? '—'}
                    </td>
                    <td className="px-3 py-2.5 text-text-muted uppercase">{log.protocol ?? '—'}</td>
                    <td className="px-5 py-2.5 text-right text-text-muted">{timeAgo(log.timestamp)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-brand-gold" />
                <span className="text-sm font-semibold text-text-primary">IDS Alerts</span>
              </div>
              <Link to="/ids" className="text-xs text-brand-gold hover:text-brand-gold-bright flex items-center gap-1">
                View all <ChevronRight className="w-3 h-3" />
              </Link>
            </div>
          </CardHeader>
          <div className="divide-y divide-border-muted">
            {recentAlerts.length === 0 ? (
              <div className="px-5 py-8 text-center text-text-muted text-sm">No recent alerts</div>
            ) : recentAlerts.map(alert => (
              <div
                key={alert.id}
                className={`px-5 py-3 flex items-start gap-3 hover:bg-brand-slate/30 transition-colors ${alert.acknowledged ? 'opacity-40' : ''}`}
              >
                <div className={`w-1.5 h-1.5 rounded-full mt-2 flex-shrink-0 ${
                  alert.severity === 'critical' ? 'bg-danger' :
                  alert.severity === 'high' ? 'bg-danger' :
                  alert.severity === 'medium' ? 'bg-warning' : 'bg-info'
                }`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-medium text-text-primary truncate">{alert.signature_name}</span>
                    <Badge variant={severityVariant[alert.severity] ?? 'neutral'}>{alert.severity}</Badge>
                  </div>
                  <div className="text-xs text-text-muted mt-0.5">
                    {alert.src_ip} → {alert.dst_ip}:{alert.dst_port} · {timeAgo(alert.timestamp)}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <span className="text-sm font-semibold text-text-primary">Active Sessions</span>
              <Link to="/sessions" className="text-xs text-brand-gold hover:text-brand-gold-bright flex items-center gap-1">
                View all <ChevronRight className="w-3 h-3" />
              </Link>
            </div>
          </CardHeader>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border-muted">
                  <th className="text-left px-4 py-2.5 text-text-muted font-medium">Source</th>
                  <th className="text-left px-3 py-2.5 text-text-muted font-medium">Destination</th>
                  <th className="text-left px-3 py-2.5 text-text-muted font-medium">State</th>
                  <th className="text-right px-4 py-2.5 text-text-muted font-medium">Traffic</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map(sess => (
                  <tr key={sess.id} className="border-b border-border-muted/50 hover:bg-brand-slate/30 transition-colors">
                    <td className="px-4 py-2.5 font-mono text-text-secondary">{sess.src_ip}:{sess.src_port}</td>
                    <td className="px-3 py-2.5 font-mono text-text-secondary">{sess.dst_ip}:{sess.dst_port}</td>
                    <td className="px-3 py-2.5">
                      <Badge variant={sess.state === 'established' ? 'success' : 'neutral'}>{sess.state}</Badge>
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <span className="flex items-center justify-end gap-1.5">
                        <ArrowDownLeft className="w-3 h-3 text-success" />
                        {formatBytes(sess.bytes_in)}
                        <span className="text-text-muted/40">/</span>
                        <ArrowUpRight className="w-3 h-3 text-info" />
                        {formatBytes(sess.bytes_out)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-brand-gold" />
                <span className="text-sm font-semibold text-text-primary">Apply History</span>
              </div>
              <Link to="/policies" className="text-xs text-brand-gold hover:text-brand-gold-bright flex items-center gap-1">
                Policies <ChevronRight className="w-3 h-3" />
              </Link>
            </div>
          </CardHeader>
          <div className="divide-y divide-border-muted">
            {applyHistory.length === 0 ? (
              <div className="px-5 py-8 text-center text-text-muted text-sm">No apply history</div>
            ) : applyHistory.map(h => (
              <div key={h.id} className="flex items-center justify-between px-5 py-3">
                <div>
                  <div className="flex items-center gap-2 text-xs">
                    <Badge variant={
                      h.status === 'confirmed' ? 'success' :
                      h.status === 'rolled_back' ? 'danger' :
                      h.status === 'applied' ? 'warning' : 'neutral'
                    }>
                      {h.status}
                    </Badge>
                    <span className="text-text-muted">{h.rules_count} rules</span>
                    <span className="text-text-muted/60 uppercase">{h.os_target}</span>
                  </div>
                  <div className="text-xs text-text-muted mt-0.5">{timeAgo(h.applied_at)} · {h.applied_by}</div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
