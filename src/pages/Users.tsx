import { useEffect, useState } from 'react';
import { UserPlus, Trash2, ShieldCheck, KeyRound } from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';
import { Card, CardHeader } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Modal } from '../components/ui/Modal';

interface AdminUser {
  id: string;
  email: string;
  role: 'admin' | 'operator' | 'viewer';
  mfa_enabled: number | boolean;
  created_at: string;
}

const ROLES: AdminUser['role'][] = ['admin', 'operator', 'viewer'];
const roleHelp: Record<string, string> = {
  admin: 'Full access including user management',
  operator: 'Manage all firewall config, but not users',
  viewer: 'Read-only access',
};

const cls = 'w-full bg-brand-panel border border-border-muted rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-brand-gold/50 focus:ring-1 focus:ring-brand-gold/20 transition-all';
const lbl = 'block text-xs font-medium text-text-muted mb-1';

export function Users() {
  const { user: me } = useAuth();
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [addOpen, setAddOpen] = useState(false);
  const [form, setForm] = useState({ email: '', password: '', role: 'viewer' as AdminUser['role'] });
  const [resetId, setResetId] = useState<string | null>(null);
  const [resetPass, setResetPass] = useState('');
  const [deleteId, setDeleteId] = useState<string | null>(null);

  async function fetchUsers() {
    const { data } = await api.get<AdminUser[]>('users');
    setUsers(data ?? []);
    setLoading(false);
  }

  useEffect(() => { fetchUsers(); }, []);

  async function addUser() {
    setError('');
    const { error } = await api.post('users', form);
    if (error) { setError(error); return; }
    setAddOpen(false);
    setForm({ email: '', password: '', role: 'viewer' });
    fetchUsers();
  }

  async function changeRole(u: AdminUser, role: AdminUser['role']) {
    const { error } = await api.patch(`users/${u.id}`, { role });
    if (error) { setError(error); setTimeout(() => setError(''), 5000); }
    fetchUsers();
  }

  async function resetPassword() {
    if (!resetId) return;
    setError('');
    const { error } = await api.patch(`users/${resetId}`, { password: resetPass });
    if (error) { setError(error); return; }
    setResetId(null);
    setResetPass('');
  }

  async function removeUser(id: string) {
    const { error } = await api.del(`users/${id}`);
    if (error) { setError(error); setTimeout(() => setError(''), 5000); }
    setDeleteId(null);
    fetchUsers();
  }

  return (
    <div className="p-4 lg:p-6 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-text-primary">Users &amp; Access</h1>
          <p className="text-sm text-text-muted mt-0.5">{users.length} accounts · role-based access control</p>
        </div>
        <Button variant="primary" onClick={() => { setForm({ email: '', password: '', role: 'viewer' }); setError(''); setAddOpen(true); }}>
          <UserPlus className="w-4 h-4" /> Add User
        </Button>
      </div>

      {error && <div className="px-4 py-2.5 bg-danger/10 border border-danger/20 rounded-lg text-sm text-danger">{error}</div>}

      <Card>
        <CardHeader><span className="font-semibold text-text-primary">Accounts</span></CardHeader>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border-muted text-xs text-text-muted">
                <th className="px-4 py-3 text-left font-medium">Email</th>
                <th className="px-4 py-3 text-left font-medium">Role</th>
                <th className="px-4 py-3 text-left font-medium">MFA</th>
                <th className="px-4 py-3 text-left font-medium">Created</th>
                <th className="px-4 py-3 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={5} className="px-4 py-12 text-center text-text-muted">Loading...</td></tr>
              ) : users.map(u => (
                <tr key={u.id} className="border-b border-border-muted/50 hover:bg-brand-slate/30">
                  <td className="px-4 py-3">
                    <span className="text-text-primary font-medium">{u.email}</span>
                    {u.id === me?.id && <span className="ml-2 text-xs text-text-muted">(you)</span>}
                  </td>
                  <td className="px-4 py-3">
                    <select value={u.role} onChange={e => changeRole(u, e.target.value as AdminUser['role'])}
                      disabled={u.id === me?.id}
                      className="bg-brand-panel border border-border-muted rounded-lg px-2 py-1 text-xs text-text-primary disabled:opacity-50">
                      {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                    </select>
                  </td>
                  <td className="px-4 py-3">
                    {u.mfa_enabled
                      ? <span className="flex items-center gap-1 text-xs text-success"><ShieldCheck className="w-3.5 h-3.5" /> On</span>
                      : <span className="text-xs text-text-muted">Off</span>}
                  </td>
                  <td className="px-4 py-3 text-xs text-text-muted">{new Date(u.created_at).toLocaleDateString()}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-1.5">
                      <button onClick={() => { setResetId(u.id); setResetPass(''); setError(''); }} title="Reset password"
                        className="p-1.5 rounded text-text-muted hover:text-warning hover:bg-warning/10 transition-colors">
                        <KeyRound className="w-3.5 h-3.5" />
                      </button>
                      <button onClick={() => setDeleteId(u.id)} disabled={u.id === me?.id} title="Delete"
                        className="p-1.5 rounded text-text-muted hover:text-danger hover:bg-danger/10 transition-colors disabled:opacity-30 disabled:hover:bg-transparent">
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

      <Modal open={addOpen} onClose={() => setAddOpen(false)} title="Add User" size="md">
        <div className="space-y-4">
          {error && <div className="text-xs text-danger">{error}</div>}
          <div>
            <label className={lbl}>Email</label>
            <input className={cls} value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} placeholder="user@example.com" />
          </div>
          <div>
            <label className={lbl}>Password (min. 12 characters)</label>
            <input type="password" className={cls} value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} />
          </div>
          <div>
            <label className={lbl}>Role</label>
            <select className={cls} value={form.role} onChange={e => setForm({ ...form, role: e.target.value as AdminUser['role'] })}>
              {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
            </select>
            <p className="text-xs text-text-muted/60 mt-1">{roleHelp[form.role]}</p>
          </div>
          <div className="flex justify-end gap-3 pt-2 border-t border-border-muted">
            <Button variant="ghost" onClick={() => setAddOpen(false)}>Cancel</Button>
            <Button variant="primary" onClick={addUser}>Create User</Button>
          </div>
        </div>
      </Modal>

      <Modal open={!!resetId} onClose={() => setResetId(null)} title="Reset Password" size="sm">
        <div className="space-y-4">
          {error && <div className="text-xs text-danger">{error}</div>}
          <div>
            <label className={lbl}>New password (min. 12 characters)</label>
            <input type="password" className={cls} value={resetPass} onChange={e => setResetPass(e.target.value)} autoFocus />
          </div>
          <div className="flex justify-end gap-3">
            <Button variant="ghost" onClick={() => setResetId(null)}>Cancel</Button>
            <Button variant="primary" onClick={resetPassword}>Set Password</Button>
          </div>
        </div>
      </Modal>

      <Modal open={!!deleteId} onClose={() => setDeleteId(null)} title="Delete User" size="sm">
        <p className="text-sm text-text-secondary">Delete this user account? This cannot be undone.</p>
        <div className="flex justify-end gap-3 mt-6">
          <Button variant="ghost" onClick={() => setDeleteId(null)}>Cancel</Button>
          <Button variant="danger" onClick={() => deleteId && removeUser(deleteId)}>Delete</Button>
        </div>
      </Modal>
    </div>
  );
}
