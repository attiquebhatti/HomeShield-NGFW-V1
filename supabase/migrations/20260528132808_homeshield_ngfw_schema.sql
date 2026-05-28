/*
  # HomeShield NGFW - Core Database Schema

  ## Summary
  This migration creates the complete database schema for HomeShield NGFW MVP.

  ## New Tables
  - firewall_policies: Firewall rules with full policy model
  - firewall_logs: Connection event logs
  - dns_entries: DNS blocklist/allowlist entries
  - dns_logs: DNS query event logs
  - ids_alerts: Suricata IDS alert records
  - threat_feeds: Threat intelligence feed sources
  - threat_indicators: Individual IOCs from threat feeds
  - network_interfaces: Detected network interfaces
  - nat_rules: NAT/port forwarding rules
  - system_settings: Key-value configuration store
  - audit_log: Immutable configuration change trail
  - sessions: Active/recent connection records

  ## Security
  - RLS enabled on all tables
  - Authenticated users can manage data
  - audit_log is insert-only (no update/delete)
*/

-- ============================================================
-- firewall_policies
-- ============================================================
CREATE TABLE IF NOT EXISTS firewall_policies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  description text DEFAULT '',
  enabled boolean DEFAULT true,
  action text NOT NULL CHECK (action IN ('allow', 'deny', 'reject', 'log-only')),
  direction text NOT NULL CHECK (direction IN ('inbound', 'outbound', 'forward')),
  src_ip text DEFAULT 'any',
  dst_ip text DEFAULT 'any',
  src_port text DEFAULT 'any',
  dst_port text DEFAULT 'any',
  protocol text DEFAULT 'any' CHECK (protocol IN ('tcp', 'udp', 'icmp', 'any')),
  interface text DEFAULT 'any',
  schedule text DEFAULT 'always',
  tags text[] DEFAULT '{}',
  priority integer DEFAULT 100,
  log_enabled boolean DEFAULT true,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

ALTER TABLE firewall_policies ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can read firewall_policies"
  ON firewall_policies FOR SELECT TO authenticated USING (true);

CREATE POLICY "Authenticated users can insert firewall_policies"
  ON firewall_policies FOR INSERT TO authenticated WITH CHECK (true);

CREATE POLICY "Authenticated users can update firewall_policies"
  ON firewall_policies FOR UPDATE TO authenticated USING (true) WITH CHECK (true);

CREATE POLICY "Authenticated users can delete firewall_policies"
  ON firewall_policies FOR DELETE TO authenticated USING (true);

CREATE INDEX IF NOT EXISTS idx_firewall_policies_priority ON firewall_policies (priority);
CREATE INDEX IF NOT EXISTS idx_firewall_policies_enabled ON firewall_policies (enabled);

-- ============================================================
-- firewall_logs
-- ============================================================
CREATE TABLE IF NOT EXISTS firewall_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  timestamp timestamptz DEFAULT now(),
  action text NOT NULL,
  direction text,
  src_ip text,
  dst_ip text,
  src_port integer,
  dst_port integer,
  protocol text,
  interface text,
  policy_id uuid REFERENCES firewall_policies(id) ON DELETE SET NULL,
  policy_name text,
  bytes bigint DEFAULT 0,
  packets bigint DEFAULT 0,
  note text DEFAULT ''
);

ALTER TABLE firewall_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can read firewall_logs"
  ON firewall_logs FOR SELECT TO authenticated USING (true);

CREATE POLICY "Authenticated users can insert firewall_logs"
  ON firewall_logs FOR INSERT TO authenticated WITH CHECK (true);

CREATE INDEX IF NOT EXISTS idx_firewall_logs_timestamp ON firewall_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_firewall_logs_src_ip ON firewall_logs (src_ip);
CREATE INDEX IF NOT EXISTS idx_firewall_logs_action ON firewall_logs (action);

-- ============================================================
-- dns_entries
-- ============================================================
CREATE TABLE IF NOT EXISTS dns_entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  domain text NOT NULL,
  list_type text NOT NULL CHECK (list_type IN ('blocklist', 'allowlist')),
  category text DEFAULT 'custom',
  source text DEFAULT 'manual',
  enabled boolean DEFAULT true,
  note text DEFAULT '',
  created_at timestamptz DEFAULT now()
);

ALTER TABLE dns_entries ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can read dns_entries"
  ON dns_entries FOR SELECT TO authenticated USING (true);

CREATE POLICY "Authenticated users can insert dns_entries"
  ON dns_entries FOR INSERT TO authenticated WITH CHECK (true);

CREATE POLICY "Authenticated users can update dns_entries"
  ON dns_entries FOR UPDATE TO authenticated USING (true) WITH CHECK (true);

CREATE POLICY "Authenticated users can delete dns_entries"
  ON dns_entries FOR DELETE TO authenticated USING (true);

CREATE INDEX IF NOT EXISTS idx_dns_entries_domain ON dns_entries (domain);
CREATE INDEX IF NOT EXISTS idx_dns_entries_list_type ON dns_entries (list_type);

-- ============================================================
-- dns_logs
-- ============================================================
CREATE TABLE IF NOT EXISTS dns_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  timestamp timestamptz DEFAULT now(),
  domain text NOT NULL,
  client_ip text,
  action text NOT NULL CHECK (action IN ('allowed', 'blocked')),
  matched_list text,
  category text,
  response_ip text,
  query_type text DEFAULT 'A'
);

ALTER TABLE dns_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can read dns_logs"
  ON dns_logs FOR SELECT TO authenticated USING (true);

CREATE POLICY "Authenticated users can insert dns_logs"
  ON dns_logs FOR INSERT TO authenticated WITH CHECK (true);

CREATE INDEX IF NOT EXISTS idx_dns_logs_timestamp ON dns_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_dns_logs_domain ON dns_logs (domain);
CREATE INDEX IF NOT EXISTS idx_dns_logs_action ON dns_logs (action);

-- ============================================================
-- ids_alerts
-- ============================================================
CREATE TABLE IF NOT EXISTS ids_alerts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  timestamp timestamptz DEFAULT now(),
  severity text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  signature_id bigint,
  signature_name text NOT NULL,
  category text DEFAULT '',
  src_ip text,
  dst_ip text,
  src_port integer,
  dst_port integer,
  protocol text,
  interface text,
  payload_preview text DEFAULT '',
  action text DEFAULT 'alert' CHECK (action IN ('alert', 'drop', 'pass')),
  acknowledged boolean DEFAULT false
);

ALTER TABLE ids_alerts ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can read ids_alerts"
  ON ids_alerts FOR SELECT TO authenticated USING (true);

CREATE POLICY "Authenticated users can insert ids_alerts"
  ON ids_alerts FOR INSERT TO authenticated WITH CHECK (true);

CREATE POLICY "Authenticated users can update ids_alerts"
  ON ids_alerts FOR UPDATE TO authenticated USING (true) WITH CHECK (true);

CREATE INDEX IF NOT EXISTS idx_ids_alerts_timestamp ON ids_alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ids_alerts_severity ON ids_alerts (severity);
CREATE INDEX IF NOT EXISTS idx_ids_alerts_acknowledged ON ids_alerts (acknowledged);

-- ============================================================
-- threat_feeds
-- ============================================================
CREATE TABLE IF NOT EXISTS threat_feeds (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  description text DEFAULT '',
  url text DEFAULT '',
  feed_type text DEFAULT 'ip' CHECK (feed_type IN ('ip', 'domain', 'hash', 'mixed')),
  enabled boolean DEFAULT true,
  last_updated timestamptz,
  last_status text DEFAULT 'pending',
  indicator_count integer DEFAULT 0,
  refresh_interval_hours integer DEFAULT 24,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE threat_feeds ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can read threat_feeds"
  ON threat_feeds FOR SELECT TO authenticated USING (true);

CREATE POLICY "Authenticated users can insert threat_feeds"
  ON threat_feeds FOR INSERT TO authenticated WITH CHECK (true);

CREATE POLICY "Authenticated users can update threat_feeds"
  ON threat_feeds FOR UPDATE TO authenticated USING (true) WITH CHECK (true);

CREATE POLICY "Authenticated users can delete threat_feeds"
  ON threat_feeds FOR DELETE TO authenticated USING (true);

-- ============================================================
-- threat_indicators
-- ============================================================
CREATE TABLE IF NOT EXISTS threat_indicators (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  feed_id uuid REFERENCES threat_feeds(id) ON DELETE CASCADE,
  indicator_type text NOT NULL CHECK (indicator_type IN ('ip', 'domain', 'hash', 'cidr')),
  value text NOT NULL,
  severity text DEFAULT 'medium',
  description text DEFAULT '',
  expires_at timestamptz,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE threat_indicators ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can read threat_indicators"
  ON threat_indicators FOR SELECT TO authenticated USING (true);

CREATE POLICY "Authenticated users can insert threat_indicators"
  ON threat_indicators FOR INSERT TO authenticated WITH CHECK (true);

CREATE POLICY "Authenticated users can delete threat_indicators"
  ON threat_indicators FOR DELETE TO authenticated USING (true);

CREATE INDEX IF NOT EXISTS idx_threat_indicators_value ON threat_indicators (value);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_type ON threat_indicators (indicator_type);

-- ============================================================
-- network_interfaces
-- ============================================================
CREATE TABLE IF NOT EXISTS network_interfaces (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  display_name text DEFAULT '',
  role text DEFAULT 'lan' CHECK (role IN ('wan', 'lan', 'dmz', 'mgmt', 'unassigned')),
  ip_address text DEFAULT '',
  netmask text DEFAULT '',
  mac_address text DEFAULT '',
  mtu integer DEFAULT 1500,
  status text DEFAULT 'unknown' CHECK (status IN ('up', 'down', 'unknown')),
  rx_bytes bigint DEFAULT 0,
  tx_bytes bigint DEFAULT 0,
  updated_at timestamptz DEFAULT now()
);

ALTER TABLE network_interfaces ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can read network_interfaces"
  ON network_interfaces FOR SELECT TO authenticated USING (true);

CREATE POLICY "Authenticated users can insert network_interfaces"
  ON network_interfaces FOR INSERT TO authenticated WITH CHECK (true);

CREATE POLICY "Authenticated users can update network_interfaces"
  ON network_interfaces FOR UPDATE TO authenticated USING (true) WITH CHECK (true);

-- ============================================================
-- nat_rules
-- ============================================================
CREATE TABLE IF NOT EXISTS nat_rules (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  description text DEFAULT '',
  enabled boolean DEFAULT true,
  nat_type text NOT NULL CHECK (nat_type IN ('masquerade', 'dnat', 'snat')),
  src_ip text DEFAULT 'any',
  dst_ip text DEFAULT 'any',
  src_port text DEFAULT 'any',
  dst_port text DEFAULT 'any',
  protocol text DEFAULT 'tcp' CHECK (protocol IN ('tcp', 'udp', 'any')),
  translate_to_ip text DEFAULT '',
  translate_to_port text DEFAULT '',
  interface text DEFAULT 'any',
  priority integer DEFAULT 100,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

ALTER TABLE nat_rules ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can read nat_rules"
  ON nat_rules FOR SELECT TO authenticated USING (true);

CREATE POLICY "Authenticated users can insert nat_rules"
  ON nat_rules FOR INSERT TO authenticated WITH CHECK (true);

CREATE POLICY "Authenticated users can update nat_rules"
  ON nat_rules FOR UPDATE TO authenticated USING (true) WITH CHECK (true);

CREATE POLICY "Authenticated users can delete nat_rules"
  ON nat_rules FOR DELETE TO authenticated USING (true);

-- ============================================================
-- system_settings
-- ============================================================
CREATE TABLE IF NOT EXISTS system_settings (
  key text PRIMARY KEY,
  value text NOT NULL DEFAULT '',
  description text DEFAULT '',
  updated_at timestamptz DEFAULT now()
);

ALTER TABLE system_settings ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can read system_settings"
  ON system_settings FOR SELECT TO authenticated USING (true);

CREATE POLICY "Authenticated users can insert system_settings"
  ON system_settings FOR INSERT TO authenticated WITH CHECK (true);

CREATE POLICY "Authenticated users can update system_settings"
  ON system_settings FOR UPDATE TO authenticated USING (true) WITH CHECK (true);

-- ============================================================
-- audit_log
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_log (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  timestamp timestamptz DEFAULT now(),
  actor text DEFAULT 'system',
  action text NOT NULL,
  resource_type text NOT NULL,
  resource_id text,
  details jsonb DEFAULT '{}',
  ip_address text DEFAULT ''
);

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can read audit_log"
  ON audit_log FOR SELECT TO authenticated USING (true);

CREATE POLICY "Authenticated users can insert audit_log"
  ON audit_log FOR INSERT TO authenticated WITH CHECK (true);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_resource_type ON audit_log (resource_type);

-- ============================================================
-- sessions
-- ============================================================
CREATE TABLE IF NOT EXISTS sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  started_at timestamptz DEFAULT now(),
  last_seen timestamptz DEFAULT now(),
  src_ip text NOT NULL,
  dst_ip text NOT NULL,
  src_port integer,
  dst_port integer,
  protocol text DEFAULT 'tcp',
  state text DEFAULT 'established',
  interface text DEFAULT '',
  bytes_in bigint DEFAULT 0,
  bytes_out bigint DEFAULT 0,
  packets_in bigint DEFAULT 0,
  packets_out bigint DEFAULT 0,
  application text DEFAULT '',
  policy_id uuid REFERENCES firewall_policies(id) ON DELETE SET NULL
);

ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can read sessions"
  ON sessions FOR SELECT TO authenticated USING (true);

CREATE POLICY "Authenticated users can insert sessions"
  ON sessions FOR INSERT TO authenticated WITH CHECK (true);

CREATE POLICY "Authenticated users can update sessions"
  ON sessions FOR UPDATE TO authenticated USING (true) WITH CHECK (true);

CREATE INDEX IF NOT EXISTS idx_sessions_last_seen ON sessions (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_src_ip ON sessions (src_ip);

-- ============================================================
-- Seed default system settings
-- ============================================================
INSERT INTO system_settings (key, value, description) VALUES
  ('system_name', 'HomeShield NGFW', 'Appliance display name'),
  ('deployment_mode', 'host', 'Deployment mode: host or gateway'),
  ('wan_interface', '', 'WAN network interface name'),
  ('lan_interface', '', 'LAN network interface name'),
  ('log_retention_days', '90', 'Days to retain firewall logs'),
  ('dns_filtering_enabled', 'false', 'Enable DNS filtering'),
  ('ids_enabled', 'false', 'Enable IDS/IPS engine'),
  ('rollback_timer_seconds', '30', 'Auto-rollback timer after rule apply'),
  ('timezone', 'UTC', 'System timezone'),
  ('dashboard_refresh_seconds', '10', 'Dashboard live refresh interval')
ON CONFLICT (key) DO NOTHING;

-- ============================================================
-- Seed sample network interfaces
-- ============================================================
INSERT INTO network_interfaces (name, display_name, role, ip_address, netmask, mac_address, status) VALUES
  ('eth0', 'WAN (eth0)', 'wan', '203.0.113.1', '255.255.255.0', 'aa:bb:cc:dd:ee:01', 'up'),
  ('eth1', 'LAN (eth1)', 'lan', '192.168.1.1', '255.255.255.0', 'aa:bb:cc:dd:ee:02', 'up'),
  ('lo', 'Loopback', 'unassigned', '127.0.0.1', '255.0.0.0', '00:00:00:00:00:00', 'up')
ON CONFLICT (name) DO NOTHING;

-- ============================================================
-- Seed sample firewall policies
-- ============================================================
INSERT INTO firewall_policies (name, description, enabled, action, direction, src_ip, dst_ip, src_port, dst_port, protocol, interface, priority, log_enabled, tags) VALUES
  ('Allow LAN to WAN', 'Permit all LAN outbound traffic', true, 'allow', 'forward', '192.168.1.0/24', 'any', 'any', 'any', 'any', 'eth1', 10, true, ARRAY['lan','outbound']),
  ('Block Telnet', 'Block insecure Telnet connections', true, 'deny', 'inbound', 'any', 'any', 'any', '23', 'tcp', 'any', 20, true, ARRAY['security','telnet']),
  ('Allow HTTPS', 'Permit HTTPS traffic', true, 'allow', 'outbound', 'any', 'any', 'any', '443', 'tcp', 'any', 30, false, ARRAY['web','https']),
  ('Allow HTTP', 'Permit HTTP traffic', true, 'allow', 'outbound', 'any', 'any', 'any', '80', 'tcp', 'any', 40, false, ARRAY['web','http']),
  ('Allow DNS', 'Permit DNS resolution', true, 'allow', 'outbound', 'any', 'any', 'any', '53', 'udp', 'any', 50, false, ARRAY['dns']),
  ('Block Bogon Networks', 'Deny traffic to reserved bogon space', true, 'deny', 'forward', 'any', '0.0.0.0/8', 'any', 'any', 'any', 'any', 60, true, ARRAY['security','bogons']),
  ('Allow ICMP', 'Permit ICMP ping', true, 'allow', 'inbound', 'any', 'any', 'any', 'any', 'icmp', 'any', 70, false, ARRAY['icmp']),
  ('Log SSH Attempts', 'Log all inbound SSH connection attempts', true, 'log-only', 'inbound', 'any', 'any', 'any', '22', 'tcp', 'eth0', 80, true, ARRAY['ssh','audit'])
ON CONFLICT DO NOTHING;

-- ============================================================
-- Seed sample DNS entries
-- ============================================================
INSERT INTO dns_entries (domain, list_type, category, source, enabled, note) VALUES
  ('malware-cdn.example.com', 'blocklist', 'malware', 'manual', true, 'Known malware distribution'),
  ('ads.tracker.io', 'blocklist', 'ads', 'manual', true, 'Ad tracker'),
  ('doubleclick.net', 'blocklist', 'ads', 'manual', true, 'Google ad network'),
  ('safe-update.myapp.com', 'allowlist', 'custom', 'manual', true, 'Trusted update server'),
  ('phishing-bank.fake', 'blocklist', 'phishing', 'manual', true, 'Phishing site')
ON CONFLICT DO NOTHING;

-- ============================================================
-- Seed sample IDS alerts
-- ============================================================
INSERT INTO ids_alerts (timestamp, severity, signature_id, signature_name, category, src_ip, dst_ip, src_port, dst_port, protocol, action, acknowledged) VALUES
  (now() - interval '5 minutes', 'high', 2001219, 'ET SCAN Potential SSH Scan', 'Attempted Information Leak', '203.0.113.50', '192.168.1.1', 54321, 22, 'tcp', 'alert', false),
  (now() - interval '12 minutes', 'medium', 2010935, 'ET MALWARE Known Malicious URL', 'A Network Trojan was Detected', '192.168.1.100', '198.51.100.20', 49876, 80, 'tcp', 'alert', false),
  (now() - interval '30 minutes', 'low', 2013028, 'ET INFO Suspicious User-Agent', 'Potentially Bad Traffic', '192.168.1.55', '203.0.113.80', 51234, 443, 'tcp', 'alert', true),
  (now() - interval '1 hour', 'critical', 2019401, 'ET EXPLOIT EternalBlue SMB RCE', 'Attempted Administrator Privilege Gain', '10.0.0.5', '192.168.1.200', 445, 445, 'tcp', 'alert', false),
  (now() - interval '2 hours', 'medium', 2008120, 'ET TROJAN Generic Backdoor C2', 'Trojan Activity', '192.168.1.77', '198.51.100.99', 52000, 4444, 'tcp', 'alert', false)
ON CONFLICT DO NOTHING;

-- ============================================================
-- Seed sample threat feeds
-- ============================================================
INSERT INTO threat_feeds (name, description, url, feed_type, enabled, last_updated, last_status, indicator_count, refresh_interval_hours) VALUES
  ('Emerging Threats IPs', 'Emerging Threats community IP blocklist', 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', 'ip', true, now() - interval '6 hours', 'ok', 4721, 24),
  ('Spamhaus DROP', 'Spamhaus Do Not Route or Peer list', 'https://www.spamhaus.org/drop/drop.txt', 'ip', true, now() - interval '1 day', 'ok', 892, 24),
  ('AbuseIPDB', 'AbuseIPDB community reported IPs', '', 'ip', false, null, 'pending', 0, 12),
  ('Custom IOC Import', 'Manually imported indicators of compromise', '', 'mixed', true, now() - interval '3 hours', 'ok', 47, 0)
ON CONFLICT DO NOTHING;

-- ============================================================
-- Seed sample firewall logs
-- ============================================================
INSERT INTO firewall_logs (timestamp, action, direction, src_ip, dst_ip, src_port, dst_port, protocol, interface, policy_name, bytes, packets) VALUES
  (now() - interval '1 minute', 'allow', 'outbound', '192.168.1.100', '8.8.8.8', 52341, 443, 'tcp', 'eth1', 'Allow HTTPS', 4096, 8),
  (now() - interval '2 minutes', 'deny', 'inbound', '203.0.113.50', '192.168.1.1', 54321, 23, 'tcp', 'eth0', 'Block Telnet', 0, 1),
  (now() - interval '3 minutes', 'allow', 'outbound', '192.168.1.55', '1.1.1.1', 49876, 53, 'udp', 'eth1', 'Allow DNS', 256, 2),
  (now() - interval '4 minutes', 'allow', 'outbound', '192.168.1.200', '172.217.0.1', 50012, 443, 'tcp', 'eth1', 'Allow HTTPS', 8192, 12),
  (now() - interval '5 minutes', 'deny', 'inbound', '198.51.100.1', '192.168.1.1', 12345, 22, 'tcp', 'eth0', 'Log SSH Attempts', 0, 3),
  (now() - interval '6 minutes', 'allow', 'forward', '192.168.1.10', '93.184.216.34', 55000, 80, 'tcp', 'eth1', 'Allow HTTP', 2048, 5),
  (now() - interval '7 minutes', 'deny', 'inbound', '10.0.0.5', '192.168.1.200', 445, 445, 'tcp', 'eth0', 'Block Bogon Networks', 0, 1),
  (now() - interval '8 minutes', 'allow', 'outbound', '192.168.1.30', '8.8.4.4', 48765, 53, 'udp', 'eth1', 'Allow DNS', 128, 1)
ON CONFLICT DO NOTHING;

-- ============================================================
-- Seed sample sessions
-- ============================================================
INSERT INTO sessions (started_at, last_seen, src_ip, dst_ip, src_port, dst_port, protocol, state, interface, bytes_in, bytes_out, application) VALUES
  (now() - interval '5 minutes', now(), '192.168.1.100', '142.250.80.46', 52341, 443, 'tcp', 'established', 'eth1', 45678, 12345, 'HTTPS'),
  (now() - interval '10 minutes', now() - interval '1 minute', '192.168.1.55', '1.1.1.1', 49876, 53, 'udp', 'established', 'eth1', 512, 256, 'DNS'),
  (now() - interval '2 minutes', now(), '192.168.1.200', '13.107.21.200', 50099, 443, 'tcp', 'established', 'eth1', 102400, 8192, 'HTTPS'),
  (now() - interval '15 minutes', now() - interval '30 seconds', '192.168.1.30', '151.101.1.69', 51200, 80, 'tcp', 'time_wait', 'eth1', 23456, 4567, 'HTTP'),
  (now() - interval '1 minute', now(), '192.168.1.10', '208.67.222.222', 48000, 53, 'udp', 'established', 'eth1', 256, 128, 'DNS')
ON CONFLICT DO NOTHING;

-- ============================================================
-- Seed sample audit log entries
-- ============================================================
INSERT INTO audit_log (timestamp, actor, action, resource_type, resource_id, details, ip_address) VALUES
  (now() - interval '1 hour', 'admin', 'create', 'firewall_policy', null, '{"name":"Block Telnet","action":"deny"}', '192.168.1.1'),
  (now() - interval '45 minutes', 'admin', 'update', 'system_settings', 'dns_filtering_enabled', '{"old":"false","new":"true"}', '192.168.1.1'),
  (now() - interval '30 minutes', 'admin', 'create', 'dns_entry', null, '{"domain":"malware-cdn.example.com","list_type":"blocklist"}', '192.168.1.1'),
  (now() - interval '15 minutes', 'admin', 'apply', 'firewall_ruleset', null, '{"rules_count":8,"mode":"atomic"}', '192.168.1.1'),
  (now() - interval '5 minutes', 'system', 'import', 'threat_feed', null, '{"feed":"Emerging Threats IPs","indicators":4721}', '127.0.0.1')
ON CONFLICT DO NOTHING;
