export type Json = string | number | boolean | null | { [key: string]: Json | undefined } | Json[];

export interface Database {
  public: {
    Tables: {
      firewall_policies: {
        Row: FirewallPolicy;
        Insert: Omit<FirewallPolicy, 'id' | 'created_at' | 'updated_at'>;
        Update: Partial<Omit<FirewallPolicy, 'id' | 'created_at'>>;
      };
      firewall_logs: {
        Row: FirewallLog;
        Insert: Omit<FirewallLog, 'id'>;
        Update: never;
      };
      dns_entries: {
        Row: DnsEntry;
        Insert: Omit<DnsEntry, 'id' | 'created_at'>;
        Update: Partial<Omit<DnsEntry, 'id' | 'created_at'>>;
      };
      dns_logs: {
        Row: DnsLog;
        Insert: Omit<DnsLog, 'id'>;
        Update: never;
      };
      ids_alerts: {
        Row: IdsAlert;
        Insert: Omit<IdsAlert, 'id'>;
        Update: Partial<Pick<IdsAlert, 'acknowledged'>>;
      };
      threat_feeds: {
        Row: ThreatFeed;
        Insert: Omit<ThreatFeed, 'id' | 'created_at'>;
        Update: Partial<Omit<ThreatFeed, 'id' | 'created_at'>>;
      };
      threat_indicators: {
        Row: ThreatIndicator;
        Insert: Omit<ThreatIndicator, 'id' | 'created_at'>;
        Update: never;
      };
      network_interfaces: {
        Row: NetworkInterface;
        Insert: Omit<NetworkInterface, 'id'>;
        Update: Partial<Omit<NetworkInterface, 'id'>>;
      };
      nat_rules: {
        Row: NatRule;
        Insert: Omit<NatRule, 'id' | 'created_at' | 'updated_at'>;
        Update: Partial<Omit<NatRule, 'id' | 'created_at'>>;
      };
      system_settings: {
        Row: SystemSetting;
        Insert: SystemSetting;
        Update: Partial<SystemSetting>;
      };
      audit_log: {
        Row: AuditEntry;
        Insert: Omit<AuditEntry, 'id'>;
        Update: never;
      };
      sessions: {
        Row: Session;
        Insert: Omit<Session, 'id'>;
        Update: Partial<Omit<Session, 'id'>>;
      };
      backup_records: {
        Row: BackupRecord;
        Insert: Omit<BackupRecord, 'id'>;
        Update: never;
      };
      rule_apply_history: {
        Row: RuleApplyHistory;
        Insert: Omit<RuleApplyHistory, 'id'>;
        Update: Partial<Omit<RuleApplyHistory, 'id'>>;
      };
      system_health_snapshots: {
        Row: SystemHealthSnapshot;
        Insert: Omit<SystemHealthSnapshot, 'id'>;
        Update: never;
      };
    };
  };
}

export interface FirewallPolicy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  action: 'allow' | 'deny' | 'reject' | 'log-only';
  direction: 'inbound' | 'outbound' | 'forward';
  src_ip: string;
  dst_ip: string;
  src_port: string;
  dst_port: string;
  protocol: 'tcp' | 'udp' | 'icmp' | 'any';
  interface: string;
  schedule: string;
  tags: string[];
  priority: number;
  log_enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface FirewallLog {
  id: string;
  timestamp: string;
  action: string;
  direction: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: string | null;
  interface: string | null;
  policy_id: string | null;
  policy_name: string | null;
  bytes: number;
  packets: number;
  note: string;
}

export interface DnsEntry {
  id: string;
  domain: string;
  list_type: 'blocklist' | 'allowlist';
  category: string;
  source: string;
  enabled: boolean;
  note: string;
  created_at: string;
}

export interface DnsLog {
  id: string;
  timestamp: string;
  domain: string;
  client_ip: string | null;
  action: 'allowed' | 'blocked';
  matched_list: string | null;
  category: string | null;
  response_ip: string | null;
  query_type: string;
}

export interface IdsAlert {
  id: string;
  timestamp: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  signature_id: number | null;
  signature_name: string;
  category: string;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: string | null;
  interface: string | null;
  payload_preview: string;
  action: 'alert' | 'drop' | 'pass';
  acknowledged: boolean;
}

export interface ThreatFeed {
  id: string;
  name: string;
  description: string;
  url: string;
  feed_type: 'ip' | 'domain' | 'hash' | 'mixed';
  enabled: boolean;
  last_updated: string | null;
  last_status: string;
  indicator_count: number;
  refresh_interval_hours: number;
  created_at: string;
}

export interface ThreatIndicator {
  id: string;
  feed_id: string | null;
  indicator_type: 'ip' | 'domain' | 'hash' | 'cidr';
  value: string;
  severity: string;
  description: string;
  expires_at: string | null;
  created_at: string;
}

export interface NetworkInterface {
  id: string;
  name: string;
  display_name: string;
  role: 'wan' | 'lan' | 'dmz' | 'mgmt' | 'unassigned';
  ip_address: string;
  netmask: string;
  mac_address: string;
  mtu: number;
  status: 'up' | 'down' | 'unknown';
  rx_bytes: number;
  tx_bytes: number;
  updated_at: string;
}

export interface NatRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  nat_type: 'masquerade' | 'dnat' | 'snat';
  src_ip: string;
  dst_ip: string;
  src_port: string;
  dst_port: string;
  protocol: 'tcp' | 'udp' | 'any';
  translate_to_ip: string;
  translate_to_port: string;
  interface: string;
  priority: number;
  created_at: string;
  updated_at: string;
}

export interface SystemSetting {
  key: string;
  value: string;
  description: string;
  updated_at: string;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  details: Json;
  ip_address: string;
}

export interface Session {
  id: string;
  started_at: string;
  last_seen: string;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  state: string;
  interface: string;
  bytes_in: number;
  bytes_out: number;
  packets_in: number;
  packets_out: number;
  application: string;
  policy_id: string | null;
}

export interface BackupRecord {
  id: string;
  created_at: string;
  created_by: string;
  label: string;
  description: string;
  trigger_type: 'manual' | 'auto' | 'pre-apply';
  size_bytes: number;
  encrypted: boolean;
  payload: Json;
  checksum: string;
}

export interface RuleApplyHistory {
  id: string;
  applied_at: string;
  applied_by: string;
  mode: 'host' | 'gateway';
  os_target: 'linux' | 'windows';
  rules_count: number;
  status: 'pending' | 'applied' | 'confirmed' | 'rolled_back' | 'failed';
  rollback_timer_seconds: number;
  confirmed_at: string | null;
  rolled_back_at: string | null;
  error_message: string;
  rules_snapshot: Json;
  compiled_output: string;
}

export interface SystemHealthSnapshot {
  id: string;
  recorded_at: string;
  cpu_percent: number;
  ram_percent: number;
  ram_used_mb: number;
  ram_total_mb: number;
  disk_percent: number;
  disk_used_gb: number;
  disk_total_gb: number;
  load_avg_1m: number;
  load_avg_5m: number;
  load_avg_15m: number;
  services: Json;
}
