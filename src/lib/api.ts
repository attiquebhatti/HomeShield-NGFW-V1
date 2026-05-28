import { supabase } from './supabase';

export const apiConfigured = true;

// ─── Auth ──────────────────────────────────────────────────────────────────

export const auth = {
  async signIn(email: string, password: string) {
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    return { data, error: error?.message ?? null };
  },

  async signUp(email: string, password: string) {
    const { data, error } = await supabase.auth.signUp({ email, password });
    return { data, error: error?.message ?? null };
  },

  async getUser() {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return null;
    return { id: user.id, email: user.email ?? '' };
  },

  async signOut() {
    await supabase.auth.signOut();
  },
};

// ─── Main export — thin proxy over supabase.from() ────────────────────────

export const api = {
  from<T = Record<string, unknown>>(tableName: string) {
    return supabase.from<string, Record<string, unknown>>(tableName) as ReturnType<typeof supabase.from> & { _table: T };
  },
  auth,
};
