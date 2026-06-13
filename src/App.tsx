import { Component, ReactNode } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AlertTriangle } from 'lucide-react';
import { AuthProvider, useAuth } from './lib/auth';
import { Layout } from './components/Layout';
import { Login } from './pages/Login';
import { Dashboard } from './pages/Dashboard';
import { Policies } from './pages/Policies';
import { Logs } from './pages/Logs';
import { Sessions } from './pages/Sessions';
import { Nat } from './pages/Nat';
import { DnsFiltering } from './pages/DnsFiltering';
import { IdsAlerts } from './pages/IdsAlerts';
import { Applications } from './pages/Applications';
import { ThreatFeeds } from './pages/ThreatFeeds';
import { GeoIp } from './pages/GeoIp';
import { Vpn } from './pages/Vpn';
import { Interfaces } from './pages/Interfaces';
import { AuditLog } from './pages/AuditLog';
import { Backup } from './pages/Backup';
import { Settings } from './pages/Settings';
import { Account } from './pages/Account';
import { Users } from './pages/Users';

class ErrorBoundary extends Component<{ children: ReactNode }, { hasError: boolean }> {
  constructor(props: { children: ReactNode }) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-brand-main flex items-center justify-center p-6">
          <div className="max-w-md w-full text-center space-y-6">
            <div className="w-16 h-16 bg-danger/15 border border-danger/25 rounded-2xl flex items-center justify-center mx-auto">
              <AlertTriangle className="w-8 h-8 text-danger" />
            </div>
            <h1 className="text-xl font-bold text-text-primary">Something went wrong</h1>
            <p className="text-sm text-text-muted">
              The application encountered an unexpected error. Please refresh the page or contact your administrator.
            </p>
            <button
              onClick={() => window.location.reload()}
              className="px-6 py-2.5 bg-brand-gold hover:bg-brand-gold-bright text-brand-main rounded-lg text-sm font-semibold transition-all"
            >
              Refresh Page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

function ProtectedLayout() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-brand-main flex items-center justify-center">
        <div className="flex items-center gap-3 text-text-muted">
          <svg className="animate-spin w-5 h-5" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          Loading...
        </div>
      </div>
    );
  }

  if (!user) return <Navigate to="/login" replace />;
  return <Layout />;
}

function AppRoutes() {
  const { user, loading } = useAuth();

  if (loading) return null;

  return (
    <Routes>
      <Route path="/login" element={user ? <Navigate to="/" replace /> : <Login />} />
      <Route path="/" element={<ProtectedLayout />}>
        <Route index element={<Dashboard />} />
        <Route path="policies" element={<Policies />} />
        <Route path="logs" element={<Logs />} />
        <Route path="sessions" element={<Sessions />} />
        <Route path="nat" element={<Nat />} />
        <Route path="dns" element={<DnsFiltering />} />
        <Route path="ids" element={<IdsAlerts />} />
        <Route path="applications" element={<Applications />} />
        <Route path="threat-feeds" element={<ThreatFeeds />} />
        <Route path="geoip" element={<GeoIp />} />
        <Route path="vpn" element={<Vpn />} />
        <Route path="interfaces" element={<Interfaces />} />
        <Route path="audit" element={<AuditLog />} />
        <Route path="backup" element={<Backup />} />
        <Route path="account" element={<Account />} />
        <Route path="users" element={<Users />} />
        <Route path="settings" element={<Settings />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </BrowserRouter>
    </ErrorBoundary>
  );
}
