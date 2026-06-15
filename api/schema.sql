-- HomeShield NGFW - MySQL Schema
-- Run this in Hostinger's phpMyAdmin to create all required tables.

CREATE TABLE IF NOT EXISTS admin_users (
  id VARCHAR(36) PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('admin','operator','viewer') NOT NULL DEFAULT 'admin',
  mfa_secret VARCHAR(64) DEFAULT '',
  mfa_enabled TINYINT(1) DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS firewall_policies (
  id VARCHAR(36) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT DEFAULT '',
  enabled TINYINT(1) DEFAULT 1,
  action ENUM('allow','deny','reject','log-only') NOT NULL DEFAULT 'allow',
  direction ENUM('inbound','outbound','forward') NOT NULL DEFAULT 'inbound',
  src_ip VARCHAR(100) DEFAULT 'any',
  dst_ip VARCHAR(100) DEFAULT 'any',
  src_device VARCHAR(36) DEFAULT 'any',
  dst_device VARCHAR(36) DEFAULT 'any',
  src_port VARCHAR(100) DEFAULT 'any',
  dst_port VARCHAR(100) DEFAULT 'any',
  protocol ENUM('tcp','udp','icmp','any') DEFAULT 'any',
  interface VARCHAR(50) DEFAULT 'any',
  schedule VARCHAR(100) DEFAULT 'always',
  tags JSON,
  priority INT DEFAULT 100,
  log_enabled TINYINT(1) DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS firewall_logs (
  id VARCHAR(36) PRIMARY KEY,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  action VARCHAR(20) NOT NULL,
  direction VARCHAR(20),
  src_ip VARCHAR(50),
  dst_ip VARCHAR(50),
  src_port INT,
  dst_port INT,
  protocol VARCHAR(10),
  interface VARCHAR(50),
  policy_id VARCHAR(36),
  policy_name VARCHAR(255),
  bytes BIGINT DEFAULT 0,
  packets INT DEFAULT 0,
  note TEXT DEFAULT '',
  INDEX idx_timestamp (timestamp),
  INDEX idx_action (action)
);

CREATE TABLE IF NOT EXISTS dns_entries (
  id VARCHAR(36) PRIMARY KEY,
  domain VARCHAR(255) NOT NULL,
  list_type ENUM('blocklist','allowlist') NOT NULL DEFAULT 'blocklist',
  category VARCHAR(100) DEFAULT 'custom',
  source VARCHAR(255) DEFAULT 'manual',
  enabled TINYINT(1) DEFAULT 1,
  note TEXT DEFAULT '',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_list_type (list_type)
);

CREATE TABLE IF NOT EXISTS dns_logs (
  id VARCHAR(36) PRIMARY KEY,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  domain VARCHAR(255) NOT NULL,
  client_ip VARCHAR(50),
  action ENUM('allowed','blocked') NOT NULL,
  matched_list VARCHAR(255),
  category VARCHAR(100),
  response_ip VARCHAR(50),
  query_type VARCHAR(20) DEFAULT 'A',
  INDEX idx_timestamp (timestamp)
);

CREATE TABLE IF NOT EXISTS ids_alerts (
  id VARCHAR(36) PRIMARY KEY,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  severity ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
  signature_id INT,
  signature_name VARCHAR(255) NOT NULL,
  category VARCHAR(100) DEFAULT '',
  src_ip VARCHAR(50),
  dst_ip VARCHAR(50),
  src_port INT,
  dst_port INT,
  protocol VARCHAR(20),
  interface VARCHAR(50),
  payload_preview TEXT DEFAULT '',
  action ENUM('alert','drop','pass') DEFAULT 'alert',
  acknowledged TINYINT(1) DEFAULT 0,
  INDEX idx_timestamp (timestamp),
  INDEX idx_severity (severity),
  INDEX idx_acknowledged (acknowledged)
);

CREATE TABLE IF NOT EXISTS threat_feeds (
  id VARCHAR(36) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT DEFAULT '',
  url TEXT DEFAULT '',
  feed_type ENUM('ip','domain','hash','mixed') DEFAULT 'ip',
  enabled TINYINT(1) DEFAULT 1,
  last_updated DATETIME,
  last_status VARCHAR(50) DEFAULT 'pending',
  indicator_count INT DEFAULT 0,
  refresh_interval_hours INT DEFAULT 24,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS threat_indicators (
  id VARCHAR(36) PRIMARY KEY,
  feed_id VARCHAR(36),
  indicator_type ENUM('ip','domain','hash','cidr') NOT NULL,
  value VARCHAR(500) NOT NULL,
  severity VARCHAR(50) DEFAULT 'medium',
  description TEXT DEFAULT '',
  expires_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_feed_id (feed_id),
  INDEX idx_value (value(191))
);

CREATE TABLE IF NOT EXISTS network_interfaces (
  id VARCHAR(36) PRIMARY KEY,
  name VARCHAR(50) NOT NULL,
  display_name VARCHAR(100) DEFAULT '',
  role ENUM('wan','lan','dmz','mgmt','unassigned') DEFAULT 'unassigned',
  ip_address VARCHAR(50) DEFAULT '',
  netmask VARCHAR(50) DEFAULT '',
  mac_address VARCHAR(20) DEFAULT '',
  mtu INT DEFAULT 1500,
  status ENUM('up','down','unknown') DEFAULT 'unknown',
  rx_bytes BIGINT DEFAULT 0,
  tx_bytes BIGINT DEFAULT 0,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS nat_rules (
  id VARCHAR(36) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT DEFAULT '',
  enabled TINYINT(1) DEFAULT 1,
  nat_type ENUM('masquerade','dnat','snat') NOT NULL DEFAULT 'masquerade',
  src_ip VARCHAR(100) DEFAULT 'any',
  dst_ip VARCHAR(100) DEFAULT 'any',
  src_port VARCHAR(100) DEFAULT 'any',
  dst_port VARCHAR(100) DEFAULT 'any',
  protocol ENUM('tcp','udp','any') DEFAULT 'tcp',
  translate_to_ip VARCHAR(100) DEFAULT '',
  translate_to_port VARCHAR(100) DEFAULT '',
  interface VARCHAR(50) DEFAULT 'any',
  priority INT DEFAULT 100,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS system_settings (
  `key` VARCHAR(100) PRIMARY KEY,
  value TEXT DEFAULT '',
  description TEXT DEFAULT '',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT IGNORE INTO system_settings (`key`, value, description) VALUES
  ('system_name', 'HomeShield NGFW', 'System display name'),
  ('deployment_mode', 'host', 'host or gateway'),
  ('timezone', 'UTC', 'System timezone'),
  ('wan_interface', 'eth0', 'WAN interface name'),
  ('lan_interface', 'eth1', 'LAN interface name'),
  ('rollback_timer_seconds', '30', 'Auto-rollback timer in seconds'),
  ('dns_filtering_enabled', 'false', 'Enable DNS filtering'),
  ('dns_upstream', '1.1.1.1', 'Upstream DNS resolver for the filtering proxy'),
  ('ips_mode', 'off', 'Suricata mode: off, ids (detect), or ips (inline block)'),
  ('suricata_queue_num', '0', 'NFQUEUE number Suricata reads in IPS mode'),
  ('suricata_eve_path', '/var/log/suricata/eve.json', 'Path to Suricata eve.json'),
  ('appid_enabled', 'true', 'Enable application identification (app_flows)'),
  ('geoip_enabled', 'false', 'Enable GeoIP country filtering'),
  ('geoip_mode', 'block', 'GeoIP mode: block (drop listed) or allow (only listed inbound)'),
  ('geoip_countries', '', 'Comma-separated ISO country codes for GeoIP filtering'),
  ('geoip_source_v4', 'https://www.ipdeny.com/ipblocks/data/aggregated/{cc}-aggregated.zone', 'IPv4 country zone URL template'),
  ('geoip_source_v6', 'https://www.ipdeny.com/ipv6/ipaddresses/aggregated/{cc}-aggregated.zone', 'IPv6 country zone URL template'),
  ('open_signup_enabled', 'true', 'Allow self-signup (new users become viewers)'),
  ('log_retention_days', '90', 'Log retention in days'),
  ('dashboard_refresh_seconds', '15', 'Dashboard auto-refresh interval');

CREATE TABLE IF NOT EXISTS audit_log (
  id VARCHAR(36) PRIMARY KEY,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  actor VARCHAR(255) DEFAULT '',
  action VARCHAR(100) NOT NULL,
  resource_type VARCHAR(100) DEFAULT '',
  resource_id VARCHAR(36),
  details JSON,
  ip_address VARCHAR(50) DEFAULT '',
  INDEX idx_timestamp (timestamp),
  INDEX idx_actor (actor),
  INDEX idx_action (action)
);

CREATE TABLE IF NOT EXISTS sessions (
  id VARCHAR(36) PRIMARY KEY,
  started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
  src_ip VARCHAR(50) NOT NULL DEFAULT '',
  dst_ip VARCHAR(50) NOT NULL DEFAULT '',
  src_port INT,
  dst_port INT,
  protocol VARCHAR(20) DEFAULT 'tcp',
  state VARCHAR(50) DEFAULT 'established',
  interface VARCHAR(50) DEFAULT '',
  bytes_in BIGINT DEFAULT 0,
  bytes_out BIGINT DEFAULT 0,
  packets_in INT DEFAULT 0,
  packets_out INT DEFAULT 0,
  application VARCHAR(100) DEFAULT '',
  policy_id VARCHAR(36),
  INDEX idx_last_seen (last_seen)
);

CREATE TABLE IF NOT EXISTS backup_records (
  id VARCHAR(36) PRIMARY KEY,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  created_by VARCHAR(255) DEFAULT 'admin',
  label VARCHAR(255) DEFAULT '',
  description TEXT DEFAULT '',
  trigger_type ENUM('manual','auto','pre-apply') DEFAULT 'manual',
  size_bytes BIGINT DEFAULT 0,
  encrypted TINYINT(1) DEFAULT 0,
  payload LONGTEXT,
  checksum VARCHAR(255) DEFAULT ''
);

CREATE TABLE IF NOT EXISTS rule_apply_history (
  id VARCHAR(36) PRIMARY KEY,
  applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  applied_by VARCHAR(255) DEFAULT 'admin',
  mode ENUM('host','gateway') DEFAULT 'host',
  os_target ENUM('linux','windows') DEFAULT 'linux',
  rules_count INT DEFAULT 0,
  status ENUM('pending','applied','confirmed','rolled_back','failed') DEFAULT 'pending',
  rollback_timer_seconds INT DEFAULT 30,
  confirmed_at DATETIME,
  rolled_back_at DATETIME,
  error_message TEXT DEFAULT '',
  rules_snapshot LONGTEXT,
  compiled_output LONGTEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS vpn_server (
  id VARCHAR(36) PRIMARY KEY,
  interface VARCHAR(50) DEFAULT 'wg0',
  private_key VARCHAR(64) DEFAULT '',
  public_key VARCHAR(64) DEFAULT '',
  listen_port INT DEFAULT 51820,
  address VARCHAR(50) DEFAULT '10.8.0.1/24',
  endpoint VARCHAR(255) DEFAULT '',
  dns VARCHAR(100) DEFAULT '1.1.1.1',
  enabled TINYINT(1) DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vpn_peers (
  id VARCHAR(36) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  public_key VARCHAR(64) DEFAULT '',
  private_key VARCHAR(64) DEFAULT '',
  preshared_key VARCHAR(64) DEFAULT '',
  address VARCHAR(50) DEFAULT '',
  allowed_ips VARCHAR(255) DEFAULT '0.0.0.0/0',
  enabled TINYINT(1) DEFAULT 1,
  last_handshake DATETIME NULL,
  rx_bytes BIGINT DEFAULT 0,
  tx_bytes BIGINT DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_public_key (public_key)
);

CREATE TABLE IF NOT EXISTS devices (
  id VARCHAR(36) PRIMARY KEY,
  hostname VARCHAR(255) DEFAULT '',
  os ENUM('windows','linux','macos','unknown') DEFAULT 'unknown',
  os_version VARCHAR(150) DEFAULT '',
  agent_version VARCHAR(50) DEFAULT '',
  ip_address VARCHAR(50) DEFAULT '',
  tags JSON,
  enrolled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_last_seen (last_seen),
  INDEX idx_os (os)
);

CREATE TABLE IF NOT EXISTS ipsec_server (
  id VARCHAR(36) PRIMARY KEY,
  enabled TINYINT(1) DEFAULT 0,
  endpoint VARCHAR(255) DEFAULT '',
  pool_subnet VARCHAR(50) DEFAULT '10.9.0.0/24',
  dns VARCHAR(100) DEFAULT '1.1.1.1',
  local_subnets VARCHAR(255) DEFAULT '0.0.0.0/0',
  ca_cert MEDIUMTEXT,
  ca_fingerprint VARCHAR(128) DEFAULT '',
  status VARCHAR(50) DEFAULT 'pending',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vpn_users (
  id VARCHAR(36) PRIMARY KEY,
  username VARCHAR(100) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  enabled TINYINT(1) DEFAULT 1,
  last_connected DATETIME NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS app_flows (
  id VARCHAR(36) PRIMARY KEY,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  client_ip VARCHAR(50),
  dest_ip VARCHAR(50),
  application VARCHAR(100),
  category VARCHAR(50),
  hostname VARCHAR(255),
  protocol VARCHAR(20),
  app_proto VARCHAR(30),
  source VARCHAR(10),
  bytes BIGINT DEFAULT 0,
  INDEX idx_timestamp (timestamp),
  INDEX idx_application (application)
);

CREATE TABLE IF NOT EXISTS system_health_snapshots (
  id VARCHAR(36) PRIMARY KEY,
  recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  cpu_percent FLOAT DEFAULT 0,
  ram_percent FLOAT DEFAULT 0,
  ram_used_mb FLOAT DEFAULT 0,
  ram_total_mb FLOAT DEFAULT 0,
  disk_percent FLOAT DEFAULT 0,
  disk_used_gb FLOAT DEFAULT 0,
  disk_total_gb FLOAT DEFAULT 0,
  load_avg_1m FLOAT DEFAULT 0,
  load_avg_5m FLOAT DEFAULT 0,
  load_avg_15m FLOAT DEFAULT 0,
  services JSON,
  INDEX idx_recorded_at (recorded_at)
);
