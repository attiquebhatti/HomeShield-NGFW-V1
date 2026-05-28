import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
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
import { ThreatFeeds } from './pages/ThreatFeeds';
import { Interfaces } from './pages/Interfaces';
import { AuditLog } from './pages/AuditLog';
import { Backup } from './pages/Backup';
import { Settings } from './pages/Settings';

function ProtectedLayout() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center">
        <div className="flex items-center gap-3 text-gray-400">
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
        <Route path="threat-feeds" element={<ThreatFeeds />} />
        <Route path="interfaces" element={<Interfaces />} />
        <Route path="audit" element={<AuditLog />} />
        <Route path="backup" element={<Backup />} />
        <Route path="settings" element={<Settings />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  );
}
