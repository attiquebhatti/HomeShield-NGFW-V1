import { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { api, getToken } from './api';

interface AuthUser {
  id: string;
  email: string;
  role: 'admin' | 'operator' | 'viewer';
  mfa_enabled?: boolean;
}

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  signIn: (email: string, password: string, code?: string) => Promise<{ error: string | null; mfaRequired: boolean }>;
  refreshUser: () => Promise<void>;
  signOut: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!getToken()) {
      setLoading(false);
      return;
    }
    api.auth.getUser()
      .then(u => setUser(u))
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  async function signIn(email: string, password: string, code?: string): Promise<{ error: string | null; mfaRequired: boolean }> {
    const res = await api.auth.signIn(email, password, code);
    if (res.error) return { error: res.error, mfaRequired: res.mfaRequired };
    const u = await api.auth.getUser();
    setUser(u);
    return { error: null, mfaRequired: false };
  }

  async function refreshUser() {
    setUser(await api.auth.getUser());
  }

  function signOut() {
    api.auth.signOut();
    setUser(null);
  }

  return (
    <AuthContext.Provider value={{ user, loading, signIn, refreshUser, signOut }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
