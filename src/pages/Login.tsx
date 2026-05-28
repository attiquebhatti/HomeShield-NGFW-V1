import { useState, FormEvent } from 'react';
import { Shield, Eye, EyeOff, AlertCircle, Lock } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { supabase } from '../lib/supabase';

export function Login() {
  const { signIn } = useAuth();
  const [mode, setMode] = useState<'login' | 'setup'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [setupDone, setSetupDone] = useState(false);

  async function handleLogin(e: FormEvent) {
    e.preventDefault();
    setError('');
    if (!email.trim() || !password.trim()) {
      setError('Email and password are required.');
      return;
    }
    setLoading(true);
    const { error: err } = await signIn(email, password);
    if (err) setError(err);
    setLoading(false);
  }

  async function handleSetup(e: FormEvent) {
    e.preventDefault();
    setError('');
    if (!email.trim() || password.length < 12) {
      setError('Password must be at least 12 characters.');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }
    setLoading(true);
    const { error: signUpErr } = await supabase.auth.signUp({ email, password });
    if (signUpErr) {
      setError(signUpErr.message);
      setLoading(false);
      return;
    }
    setSetupDone(true);
    setLoading(false);
  }

  const inputCls = 'w-full bg-brand-panel border border-border-muted rounded-lg px-4 py-3 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-brand-gold/50 focus:ring-1 focus:ring-brand-gold/20 transition-all pr-10';

  if (setupDone) {
    return (
      <div className="min-h-screen bg-brand-main flex items-center justify-center p-4">
        <div className="w-full max-w-md text-center space-y-4">
          <div className="w-16 h-16 bg-success/15 border border-success/25 rounded-2xl flex items-center justify-center mx-auto">
            <Shield className="w-8 h-8 text-success" />
          </div>
          <h2 className="text-xl font-bold text-text-primary">Admin account created</h2>
          <p className="text-sm text-text-muted">Check your email to confirm your account, then sign in.</p>
          <button onClick={() => { setMode('login'); setSetupDone(false); }} className="text-brand-gold hover:text-brand-gold-bright text-sm underline">
            Back to sign in
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-brand-main flex items-center justify-center p-4">
      <div className="w-full max-w-sm space-y-8">
        <div className="text-center">
          <div className="w-16 h-16 bg-brand-gold/15 border border-brand-gold/30 rounded-2xl flex items-center justify-center mx-auto mb-4 shadow-gold-md">
            <Shield className="w-8 h-8 text-brand-gold" />
          </div>
          <h1 className="text-2xl font-bold text-text-primary">HomeShield NGFW</h1>
          <p className="text-sm text-text-muted mt-1">Management Console</p>
        </div>

        <div className="bg-brand-panel border border-border-muted rounded-2xl p-8 shadow-panel-lg">
          <div className="flex gap-1 mb-6 bg-brand-slate p-1 rounded-lg">
            {(['login', 'setup'] as const).map(tab => (
              <button
                key={tab}
                onClick={() => { setMode(tab); setError(''); }}
                className={`flex-1 py-1.5 rounded-md text-xs font-medium transition-all ${
                  mode === tab ? 'bg-brand-panel-soft text-text-primary' : 'text-text-muted hover:text-text-secondary'
                }`}
              >
                {tab === 'login' ? 'Sign In' : 'First-Run Setup'}
              </button>
            ))}
          </div>

          <form onSubmit={mode === 'login' ? handleLogin : handleSetup} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-text-muted mb-1.5">Email</label>
              <input
                type="email"
                className={inputCls}
                placeholder="admin@example.com"
                value={email}
                onChange={e => setEmail(e.target.value)}
                autoComplete="username"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-text-muted mb-1.5">Password</label>
              <div className="relative">
                <input
                  type={showPass ? 'text' : 'password'}
                  className={inputCls}
                  placeholder={mode === 'setup' ? 'Min. 12 characters' : 'Enter password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                />
                <button type="button" onClick={() => setShowPass(!showPass)} className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary">
                  {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {mode === 'setup' && (
              <div>
                <label className="block text-xs font-medium text-text-muted mb-1.5">Confirm Password</label>
                <div className="relative">
                  <input
                    type={showPass ? 'text' : 'password'}
                    className={inputCls}
                    placeholder="Repeat password"
                    value={confirmPassword}
                    onChange={e => setConfirmPassword(e.target.value)}
                    autoComplete="new-password"
                  />
                </div>
              </div>
            )}

            {error && (
              <div className="flex items-start gap-2.5 px-3 py-2.5 bg-danger/10 border border-danger/25 rounded-lg">
                <AlertCircle className="w-4 h-4 text-danger flex-shrink-0 mt-0.5" />
                <p className="text-xs text-danger">{error}</p>
              </div>
            )}

            {mode === 'setup' && (
              <div className="px-3 py-2.5 bg-brand-gold/5 border border-brand-gold/20 rounded-lg space-y-1">
                <p className="text-xs text-brand-gold font-medium">Password requirements</p>
                <ul className="text-xs text-brand-gold/70 space-y-0.5 list-disc list-inside">
                  <li>At least 12 characters</li>
                  <li>Mix of letters and numbers recommended</li>
                  <li>Avoid common passwords</li>
                </ul>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 bg-brand-gold hover:bg-brand-gold-bright disabled:bg-brand-gold/50 text-brand-main py-3 rounded-lg text-sm font-semibold transition-all shadow-gold-sm hover:shadow-gold-md"
            >
              {loading ? (
                <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
              ) : <Lock className="w-4 h-4" />}
              {mode === 'login' ? 'Sign In' : 'Create Admin Account'}
            </button>
          </form>
        </div>

        <p className="text-center text-xs text-text-muted/60">
          HomeShield NGFW · Local Management Console · All traffic stays on your network
        </p>
      </div>
    </div>
  );
}
