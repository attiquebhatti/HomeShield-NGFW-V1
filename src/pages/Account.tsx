import { useState } from 'react';
import { ShieldCheck, ShieldAlert, Smartphone, KeyRound } from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';
import { Card, CardHeader, CardBody } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';

const roleVariant: Record<string, 'danger' | 'warning' | 'info'> = {
  admin: 'danger', operator: 'warning', viewer: 'info',
};

const cls = 'w-full bg-brand-panel border border-border-muted rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-brand-gold/50 focus:ring-1 focus:ring-brand-gold/20 transition-all';

export function Account() {
  const { user, refreshUser } = useAuth();
  const [setup, setSetup] = useState<{ qr: string; secret: string } | null>(null);
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [disarm, setDisarm] = useState(false);

  async function beginSetup() {
    setError('');
    setBusy(true);
    const { data, error } = await api.post<{ qr: string; secret: string; otpauth: string }>('auth/mfa/setup');
    setBusy(false);
    if (error) { setError(error); return; }
    setSetup({ qr: data!.qr, secret: data!.secret });
    setCode('');
  }

  async function confirmEnable() {
    setError('');
    setBusy(true);
    const { error } = await api.post('auth/mfa/enable', { code });
    setBusy(false);
    if (error) { setError(error); return; }
    setSetup(null);
    setCode('');
    await refreshUser();
  }

  async function disableMfa() {
    setError('');
    setBusy(true);
    const { error } = await api.post('auth/mfa/disable', { code });
    setBusy(false);
    if (error) { setError(error); return; }
    setDisarm(false);
    setCode('');
    await refreshUser();
  }

  return (
    <div className="p-4 lg:p-6 space-y-5 max-w-2xl">
      <div>
        <h1 className="text-xl font-bold text-text-primary">Account &amp; Security</h1>
        <p className="text-sm text-text-muted mt-0.5">Manage your sign-in and two-factor authentication</p>
      </div>

      <Card>
        <CardHeader><span className="font-semibold text-text-primary">Profile</span></CardHeader>
        <CardBody>
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm text-text-primary font-medium">{user?.email}</div>
              <div className="text-xs text-text-muted mt-0.5">Signed-in account</div>
            </div>
            <Badge variant={roleVariant[user?.role ?? 'viewer'] ?? 'info'}>{user?.role}</Badge>
          </div>
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            {user?.mfa_enabled
              ? <ShieldCheck className="w-4 h-4 text-success" />
              : <ShieldAlert className="w-4 h-4 text-warning" />}
            <span className="font-semibold text-text-primary">Two-Factor Authentication (TOTP)</span>
          </div>
        </CardHeader>
        <CardBody>
          {error && <div className="mb-4 text-xs text-danger">{error}</div>}

          {user?.mfa_enabled ? (
            <div className="space-y-4">
              <div className="flex items-center gap-2 text-sm text-success">
                <ShieldCheck className="w-4 h-4" /> MFA is enabled on this account.
              </div>
              {!disarm ? (
                <Button variant="danger" onClick={() => { setDisarm(true); setCode(''); setError(''); }}>Disable MFA</Button>
              ) : (
                <div className="space-y-3">
                  <label className="block text-xs font-medium text-text-muted">Enter a current code to disable</label>
                  <input className={cls} value={code} inputMode="numeric"
                    onChange={e => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))} placeholder="6-digit code" />
                  <div className="flex gap-2">
                    <Button variant="ghost" onClick={() => setDisarm(false)}>Cancel</Button>
                    <Button variant="danger" onClick={disableMfa} loading={busy}>Confirm Disable</Button>
                  </div>
                </div>
              )}
            </div>
          ) : !setup ? (
            <div className="space-y-3">
              <p className="text-sm text-text-muted">
                Protect your account with a time-based one-time password from an authenticator app
                (Google Authenticator, Authy, 1Password, etc.).
              </p>
              <Button variant="primary" onClick={beginSetup} loading={busy}>
                <Smartphone className="w-4 h-4" /> Set Up MFA
              </Button>
            </div>
          ) : (
            <div className="space-y-4">
              <p className="text-sm text-text-muted">1. Scan this QR code with your authenticator app:</p>
              <div className="flex justify-center">
                <img src={setup.qr} alt="MFA QR" className="rounded-lg bg-white p-2 w-44 h-44" />
              </div>
              <details className="text-xs text-text-muted">
                <summary className="cursor-pointer">Can't scan? Enter the secret manually</summary>
                <code className="block mt-2 px-3 py-2 bg-brand-panel-soft rounded font-mono break-all">{setup.secret}</code>
              </details>
              <div>
                <label className="block text-xs font-medium text-text-muted mb-1">2. Enter the 6-digit code to confirm</label>
                <div className="flex items-center gap-2">
                  <KeyRound className="w-4 h-4 text-text-muted" />
                  <input className={cls} value={code} inputMode="numeric" autoFocus
                    onChange={e => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))} placeholder="000000" />
                </div>
              </div>
              <div className="flex gap-2">
                <Button variant="ghost" onClick={() => setSetup(null)}>Cancel</Button>
                <Button variant="primary" onClick={confirmEnable} loading={busy}>Enable MFA</Button>
              </div>
            </div>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
