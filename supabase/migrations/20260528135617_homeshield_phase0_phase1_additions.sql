/*
  # HomeShield NGFW - Phase 0 & Phase 1 Additions

  ## Summary
  Adds tables required for authentication, backup/restore, rule apply history,
  and system health telemetry.

  ## New Tables

  ### 1. app_users
  Admin user accounts for the HomeShield console.
  Stores hashed credentials and role information.
  Note: In this UI-only implementation, Supabase Auth handles real auth;
  this table stores app-level profile/role data linked to auth.uid().

  ### 2. backup_records
  Records of configuration backups including metadata and optional
  encrypted payload reference.

  ### 3. rule_apply_history
  Audit trail for each firewall ruleset apply operation, including
  whether it was rolled back, how many rules were applied, and the
  serialized snapshot of rules at apply time.

  ### 4. system_health_snapshots
  Point-in-time snapshots of CPU, RAM, disk, and service health
  from the local agent. Used to populate health widgets on the dashboard.

  ## Security
  - RLS enabled on all new tables
  - Users can only read/write their own profile in app_users
  - backup_records and rule_apply_history are authenticated-only
*/

-- ============================================================
-- app_users
-- ============================================================
CREATE TABLE IF NOT EXISTS app_users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  auth_uid uuid UNIQUE,
  username text UNIQUE NOT NULL,
  display_name text DEFAULT '',
  role text DEFAULT 'admin' CHECK (role IN ('admin', 'viewer', 'operator')),
  mfa_enabled boolean DEFAULT false,
  last_login timestamptz,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE app_users ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can read own profile"
  ON app_users FOR SELECT
  TO authenticated
  USING (auth.uid() = auth_uid);

CREATE POLICY "Users can update own profile"
  ON app_users FOR UPDATE
  TO authenticated
  USING (auth.uid() = auth_uid)
  WITH CHECK (auth.uid() = auth_uid);

CREATE POLICY "Users can insert own profile"
  ON app_users FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = auth_uid);

-- ============================================================
-- backup_records
-- ============================================================
CREATE TABLE IF NOT EXISTS backup_records (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at timestamptz DEFAULT now(),
  created_by text DEFAULT 'admin',
  label text DEFAULT '',
  description text DEFAULT '',
  trigger_type text DEFAULT 'manual' CHECK (trigger_type IN ('manual', 'auto', 'pre-apply')),
  size_bytes integer DEFAULT 0,
  encrypted boolean DEFAULT false,
  payload jsonb DEFAULT '{}',
  checksum text DEFAULT ''
);

ALTER TABLE backup_records ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can read backup_records"
  ON backup_records FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Authenticated users can insert backup_records"
  ON backup_records FOR INSERT
  TO authenticated
  WITH CHECK (true);

CREATE POLICY "Authenticated users can delete backup_records"
  ON backup_records FOR DELETE
  TO authenticated
  USING (true);

CREATE INDEX IF NOT EXISTS idx_backup_records_created_at ON backup_records (created_at DESC);

-- ============================================================
-- rule_apply_history
-- ============================================================
CREATE TABLE IF NOT EXISTS rule_apply_history (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  applied_at timestamptz DEFAULT now(),
  applied_by text DEFAULT 'admin',
  mode text DEFAULT 'host' CHECK (mode IN ('host', 'gateway')),
  os_target text DEFAULT 'linux' CHECK (os_target IN ('linux', 'windows')),
  rules_count integer DEFAULT 0,
  status text DEFAULT 'pending' CHECK (status IN ('pending', 'applied', 'confirmed', 'rolled_back', 'failed')),
  rollback_timer_seconds integer DEFAULT 30,
  confirmed_at timestamptz,
  rolled_back_at timestamptz,
  error_message text DEFAULT '',
  rules_snapshot jsonb DEFAULT '[]',
  compiled_output text DEFAULT ''
);

ALTER TABLE rule_apply_history ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can read rule_apply_history"
  ON rule_apply_history FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Authenticated users can insert rule_apply_history"
  ON rule_apply_history FOR INSERT
  TO authenticated
  WITH CHECK (true);

CREATE POLICY "Authenticated users can update rule_apply_history"
  ON rule_apply_history FOR UPDATE
  TO authenticated
  USING (true)
  WITH CHECK (true);

CREATE INDEX IF NOT EXISTS idx_rule_apply_history_applied_at ON rule_apply_history (applied_at DESC);

-- ============================================================
-- system_health_snapshots
-- ============================================================
CREATE TABLE IF NOT EXISTS system_health_snapshots (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  recorded_at timestamptz DEFAULT now(),
  cpu_percent numeric DEFAULT 0,
  ram_percent numeric DEFAULT 0,
  ram_used_mb integer DEFAULT 0,
  ram_total_mb integer DEFAULT 0,
  disk_percent numeric DEFAULT 0,
  disk_used_gb numeric DEFAULT 0,
  disk_total_gb numeric DEFAULT 0,
  load_avg_1m numeric DEFAULT 0,
  load_avg_5m numeric DEFAULT 0,
  load_avg_15m numeric DEFAULT 0,
  services jsonb DEFAULT '{}'
);

ALTER TABLE system_health_snapshots ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can read system_health_snapshots"
  ON system_health_snapshots FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Authenticated users can insert system_health_snapshots"
  ON system_health_snapshots FOR INSERT
  TO authenticated
  WITH CHECK (true);

CREATE INDEX IF NOT EXISTS idx_system_health_snapshots_recorded_at ON system_health_snapshots (recorded_at DESC);

-- ============================================================
-- Seed system health snapshots (simulated data)
-- ============================================================
INSERT INTO system_health_snapshots (recorded_at, cpu_percent, ram_percent, ram_used_mb, ram_total_mb, disk_percent, disk_used_gb, disk_total_gb, load_avg_1m, load_avg_5m, load_avg_15m, services)
VALUES
  (now() - interval '50 seconds', 12.4, 34.2, 1392, 4096, 28.1, 56.2, 200.0, 0.45, 0.38, 0.31, '{"api":"running","agent":"running","dns_filter":"running","ids":"stopped"}'),
  (now() - interval '40 seconds', 14.1, 34.5, 1413, 4096, 28.1, 56.2, 200.0, 0.52, 0.40, 0.32, '{"api":"running","agent":"running","dns_filter":"running","ids":"stopped"}'),
  (now() - interval '30 seconds', 11.8, 34.8, 1426, 4096, 28.1, 56.3, 200.0, 0.41, 0.38, 0.31, '{"api":"running","agent":"running","dns_filter":"running","ids":"stopped"}'),
  (now() - interval '20 seconds', 18.3, 35.1, 1438, 4096, 28.1, 56.3, 200.0, 0.67, 0.44, 0.33, '{"api":"running","agent":"running","dns_filter":"running","ids":"stopped"}'),
  (now() - interval '10 seconds', 13.7, 35.0, 1434, 4096, 28.1, 56.3, 200.0, 0.49, 0.41, 0.32, '{"api":"running","agent":"running","dns_filter":"running","ids":"stopped"}'),
  (now(), 15.2, 35.3, 1447, 4096, 28.1, 56.3, 200.0, 0.55, 0.43, 0.33, '{"api":"running","agent":"running","dns_filter":"running","ids":"stopped"}')
ON CONFLICT DO NOTHING;

-- ============================================================
-- Seed a sample backup record
-- ============================================================
INSERT INTO backup_records (created_at, created_by, label, description, trigger_type, size_bytes, encrypted, checksum)
VALUES
  (now() - interval '2 hours', 'admin', 'Pre-update snapshot', 'Auto backup before rule apply', 'pre-apply', 24576, false, 'sha256:a3f1b2c4d5e6...'),
  (now() - interval '1 day', 'admin', 'Daily backup', 'Scheduled daily configuration backup', 'auto', 23040, false, 'sha256:b4c5d6e7f8a9...')
ON CONFLICT DO NOTHING;

-- ============================================================
-- Seed sample rule apply history
-- ============================================================
INSERT INTO rule_apply_history (applied_at, applied_by, mode, os_target, rules_count, status, rollback_timer_seconds, confirmed_at)
VALUES
  (now() - interval '1 hour', 'admin', 'gateway', 'linux', 8, 'confirmed', 30, now() - interval '59 minutes'),
  (now() - interval '3 hours', 'admin', 'host', 'linux', 5, 'confirmed', 30, now() - interval '179 minutes'),
  (now() - interval '1 day', 'admin', 'host', 'windows', 3, 'rolled_back', 30, null)
ON CONFLICT DO NOTHING;
