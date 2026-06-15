import { useState, useEffect } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import {
  Shield, LayoutDashboard, FileText, Globe, AlertTriangle,
  Network, Settings, ChevronLeft, ChevronRight,
  Activity, Map, Rss, BookOpen, Menu, Bell,
  HardDrive, LogOut, Lock, AppWindow, Globe2, UserCircle, UsersRound, MonitorSmartphone, GitCommit
} from 'lucide-react';
import { useAuth } from '../lib/auth';
import { api } from '../lib/api';

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/policies', label: 'Firewall Policies', icon: Shield },
  { to: '/logs', label: 'Traffic Logs', icon: FileText },
  { to: '/sessions', label: 'Sessions', icon: Activity },
  { to: '/nat', label: 'NAT Rules', icon: Map },
  { to: '/dns', label: 'DNS Filtering', icon: Globe },
  { to: '/ids', label: 'IDS / IPS', icon: AlertTriangle },
  { to: '/applications', label: 'Applications', icon: AppWindow },
  { to: '/threat-feeds', label: 'Threat Feeds', icon: Rss },
  { to: '/geoip', label: 'GeoIP Filtering', icon: Globe2 },
  { to: '/vpn', label: 'VPN', icon: Lock },
  { to: '/devices', label: 'Devices', icon: MonitorSmartphone },
  { to: '/interfaces', label: 'Interfaces', icon: Network },
  { to: '/audit', label: 'Audit Log', icon: BookOpen },
  { to: '/backup', label: 'Backup & Restore', icon: HardDrive },
  { to: '/users', label: 'Users & Access', icon: UsersRound, adminOnly: true },
  { to: '/account', label: 'Account', icon: UserCircle },
  { to: '/settings', label: 'Settings', icon: Settings },
];

export function Layout() {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const { user, signOut } = useAuth();
  const navigate = useNavigate();
  const visibleNav = navItems.filter(item => !item.adminOnly || user?.role === 'admin');
  const [pending, setPending] = useState(0);

  useEffect(() => {
    let active = true;
    const load = () => api.get<{ pending: number }>('config/status').then(r => { if (active) setPending(r.data?.pending ?? 0); }).catch(() => {});
    load();
    const t = setInterval(load, 15000);
    return () => { active = false; clearInterval(t); };
  }, []);

  async function handleSignOut() {
    await signOut();
    navigate('/login');
  }

  return (
    <div className="flex h-screen bg-brand-main text-text-secondary overflow-hidden">
      {mobileOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-20 lg:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      <aside
        className={`
          fixed lg:static inset-y-0 left-0 z-30
          flex flex-col bg-brand-sidebar border-r border-border-muted
          transition-all duration-300 ease-in-out
          ${collapsed ? 'w-16' : 'w-64'}
          ${mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
        `}
      >
        <div className={`flex items-center gap-3 px-4 py-5 border-b border-border-muted ${collapsed ? 'justify-center px-2' : ''}`}>
          <div className="flex-shrink-0 w-9 h-9 bg-brand-gold/15 border border-brand-gold/30 rounded-lg flex items-center justify-center">
            <Shield className="w-5 h-5 text-brand-gold" />
          </div>
          {!collapsed && (
            <div>
              <div className="text-sm font-bold text-text-primary leading-tight">HomeShield</div>
              <div className="text-[10px] text-brand-gold leading-tight tracking-wide uppercase">NGFW Console</div>
            </div>
          )}
        </div>

        <nav className="flex-1 py-3 overflow-y-auto overflow-x-hidden">
          {visibleNav.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              onClick={() => setMobileOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3 mx-2 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 group
                ${isActive
                  ? 'bg-brand-gold/10 text-brand-gold border-l-2 border-brand-gold ml-1'
                  : 'text-text-muted hover:bg-brand-slate hover:text-text-primary border-l-2 border-transparent ml-1'
                }
                ${collapsed ? 'justify-center px-2 ml-0 border-l-0' : ''}`
              }
              title={collapsed ? label : undefined}
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              {!collapsed && <span className="truncate">{label}</span>}
            </NavLink>
          ))}
        </nav>

        <div className="px-3 py-3 border-t border-border-muted">
          {!collapsed && (
            <div className="flex items-center gap-2 px-3 py-2 mb-2 rounded-lg bg-brand-slate/50">
              <span className="w-2 h-2 rounded-full bg-success animate-pulse" />
              <span className="text-[10px] text-text-muted uppercase tracking-wider">Protected</span>
            </div>
          )}
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="hidden lg:flex items-center justify-center w-full p-2 rounded-lg text-text-muted hover:text-text-primary hover:bg-brand-slate transition-colors"
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>
      </aside>

      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <header className="flex items-center justify-between px-4 lg:px-6 py-3.5 bg-brand-sidebar border-b border-border-muted flex-shrink-0">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileOpen(true)}
              className="lg:hidden p-2 rounded-lg text-text-muted hover:text-text-primary hover:bg-brand-slate"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-success/10 border border-success/20">
              <span className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
              <span className="text-xs text-success font-medium">Firewall Active</span>
            </div>
            {pending > 0 && (
              <button
                onClick={() => navigate('/policies')}
                title="Uncommitted policy changes — click to review and commit"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-brand-gold/15 border border-brand-gold/30 hover:bg-brand-gold/25 transition-colors"
              >
                <GitCommit className="w-3.5 h-3.5 text-brand-gold" />
                <span className="text-xs text-brand-gold font-medium">{pending} uncommitted</span>
              </button>
            )}
          </div>

          <div className="flex items-center gap-2">
            <button className="p-2 rounded-lg text-text-muted hover:text-text-primary hover:bg-brand-slate transition-colors relative">
              <Bell className="w-4 h-4" />
              <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 bg-danger rounded-full" />
            </button>

            <div className="relative">
              <button
                onClick={() => setUserMenuOpen(!userMenuOpen)}
                className="flex items-center gap-2 ml-2 pl-3 border-l border-border-muted hover:opacity-80 transition-opacity"
              >
                <div className="w-7 h-7 rounded-full bg-brand-gold/20 border border-brand-gold/30 flex items-center justify-center text-xs font-bold text-brand-gold">
                  {user?.email?.[0]?.toUpperCase() ?? 'A'}
                </div>
                <span className="text-sm text-text-secondary hidden sm:block max-w-24 truncate">
                  {user?.email?.split('@')[0] ?? 'admin'}
                </span>
              </button>

              {userMenuOpen && (
                <>
                  <div className="fixed inset-0 z-10" onClick={() => setUserMenuOpen(false)} />
                  <div className="absolute right-0 mt-2 w-52 bg-brand-panel border border-border-strong rounded-xl shadow-panel-lg z-20 py-1 overflow-hidden animate-fade-in">
                    <div className="px-4 py-3 border-b border-border-muted">
                      <div className="text-xs font-medium text-text-primary truncate">{user?.email}</div>
                      <div className="text-xs text-text-muted mt-0.5 capitalize">{user?.role ?? 'user'}</div>
                    </div>
                    <button
                      onClick={() => { setUserMenuOpen(false); navigate('/account'); }}
                      className="flex items-center gap-2.5 w-full px-4 py-2.5 text-sm text-text-secondary hover:bg-brand-slate hover:text-text-primary transition-colors"
                    >
                      <UserCircle className="w-3.5 h-3.5" /> Account &amp; Security
                    </button>
                    <button
                      onClick={() => { setUserMenuOpen(false); navigate('/settings'); }}
                      className="flex items-center gap-2.5 w-full px-4 py-2.5 text-sm text-text-secondary hover:bg-brand-slate hover:text-text-primary transition-colors"
                    >
                      <Settings className="w-3.5 h-3.5" /> Settings
                    </button>
                    <button
                      onClick={() => { setUserMenuOpen(false); handleSignOut(); }}
                      className="flex items-center gap-2.5 w-full px-4 py-2.5 text-sm text-danger hover:bg-danger/10 transition-colors"
                    >
                      <LogOut className="w-3.5 h-3.5" /> Sign Out
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto bg-brand-main">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
