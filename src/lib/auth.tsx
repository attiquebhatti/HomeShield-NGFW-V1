import { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { api, getToken } from './api';

interface AuthUser {
  id: string;
  email: string;
}

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  configured: boolean;
  signIn: (email: string, password: string) => Promise<{ error: string | null }>;
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

  async function signIn(email: string, password: string): Promise<{ error: string | null }> {
    const res = await api.auth.signIn(email, password);
    if (res.error) return { error: res.error };
    const u = (res.data as any)?.user ?? null;
    setUser(u);
    return { error: null };
  }

  function signOut() {
    api.auth.signOut();
    setUser(null);
  }

  return (
    <AuthContext.Provider value={{ user, loading, configured: true, signIn, signOut }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
