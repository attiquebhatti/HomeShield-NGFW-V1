/**
 * Application identification for the HomeShield agent.
 *
 * Classifies traffic into applications using two signals:
 *   1. Hostnames — from DNS queries (our proxy) or TLS/QUIC SNI / HTTP Host
 *      (Suricata eve.json). Matched against a domain-suffix signature table.
 *   2. Layer-7 protocol — from Suricata's app-layer detection (app_proto),
 *      used as a fallback when no hostname is available (e.g. BitTorrent, SSH).
 *
 * Pure, side-effect-free — unit tested in appid.test.mjs.
 */

// domain suffix → [application, category]. Order doesn't matter; the longest
// matching suffix wins.
const DOMAIN_SIGNATURES = [
  // Streaming
  ['youtube.com', 'YouTube', 'streaming'], ['googlevideo.com', 'YouTube', 'streaming'], ['ytimg.com', 'YouTube', 'streaming'],
  ['netflix.com', 'Netflix', 'streaming'], ['nflxvideo.net', 'Netflix', 'streaming'], ['nflximg.net', 'Netflix', 'streaming'],
  ['twitch.tv', 'Twitch', 'streaming'], ['ttvnw.net', 'Twitch', 'streaming'],
  ['disneyplus.com', 'Disney+', 'streaming'], ['dssott.com', 'Disney+', 'streaming'],
  ['spotify.com', 'Spotify', 'streaming'], ['scdn.co', 'Spotify', 'streaming'],
  ['primevideo.com', 'Prime Video', 'streaming'], ['hulu.com', 'Hulu', 'streaming'],
  // Conferencing
  ['zoom.us', 'Zoom', 'conferencing'],
  ['teams.microsoft.com', 'Microsoft Teams', 'conferencing'], ['teams.live.com', 'Microsoft Teams', 'conferencing'],
  ['meet.google.com', 'Google Meet', 'conferencing'], ['webex.com', 'Webex', 'conferencing'],
  // Messaging / social
  ['discord.com', 'Discord', 'messaging'], ['discord.gg', 'Discord', 'messaging'], ['discordapp.com', 'Discord', 'messaging'], ['discord.media', 'Discord', 'messaging'],
  ['telegram.org', 'Telegram', 'messaging'], ['t.me', 'Telegram', 'messaging'], ['telegram.me', 'Telegram', 'messaging'],
  ['whatsapp.com', 'WhatsApp', 'messaging'], ['whatsapp.net', 'WhatsApp', 'messaging'],
  ['signal.org', 'Signal', 'messaging'], ['slack.com', 'Slack', 'messaging'],
  ['facebook.com', 'Facebook', 'social'], ['fbcdn.net', 'Facebook', 'social'], ['messenger.com', 'Facebook', 'social'],
  ['instagram.com', 'Instagram', 'social'], ['cdninstagram.com', 'Instagram', 'social'],
  ['twitter.com', 'X (Twitter)', 'social'], ['x.com', 'X (Twitter)', 'social'], ['twimg.com', 'X (Twitter)', 'social'],
  ['tiktok.com', 'TikTok', 'social'], ['tiktokcdn.com', 'TikTok', 'social'],
  ['reddit.com', 'Reddit', 'social'], ['redd.it', 'Reddit', 'social'],
  ['linkedin.com', 'LinkedIn', 'social'], ['snapchat.com', 'Snapchat', 'social'], ['pinterest.com', 'Pinterest', 'social'],
  // Gaming
  ['steampowered.com', 'Steam', 'gaming'], ['steamcommunity.com', 'Steam', 'gaming'], ['steamserver.net', 'Steam', 'gaming'],
  ['epicgames.com', 'Epic Games', 'gaming'], ['riotgames.com', 'Riot Games', 'gaming'],
  ['battle.net', 'Blizzard', 'gaming'], ['blizzard.com', 'Blizzard', 'gaming'],
  ['xboxlive.com', 'Xbox Live', 'gaming'], ['playstation.net', 'PlayStation', 'gaming'],
  ['nintendo.net', 'Nintendo', 'gaming'], ['roblox.com', 'Roblox', 'gaming'],
  ['minecraft.net', 'Minecraft', 'gaming'], ['mojang.com', 'Minecraft', 'gaming'],
  // Cloud / web / dev
  ['icloud.com', 'Apple', 'cloud'], ['mzstatic.com', 'Apple', 'cloud'], ['apple.com', 'Apple', 'cloud'],
  ['googleapis.com', 'Google', 'cloud'], ['gstatic.com', 'Google', 'cloud'], ['google.com', 'Google', 'web'],
  ['windowsupdate.com', 'Windows Update', 'cloud'], ['office.com', 'Microsoft 365', 'cloud'], ['live.com', 'Microsoft', 'cloud'],
  ['amazonaws.com', 'Amazon AWS', 'cloud'], ['amazon.com', 'Amazon', 'web'],
  ['github.com', 'GitHub', 'dev'], ['githubusercontent.com', 'GitHub', 'dev'],
  ['dropbox.com', 'Dropbox', 'cloud'], ['cloudflare.com', 'Cloudflare', 'cloud'],
];

// app_proto (Suricata) → [application, category], used when no hostname matches.
const PROTO_SIGNATURES = {
  bittorrent: ['BitTorrent', 'p2p'],
  ssh: ['SSH', 'remote'],
  rdp: ['RDP', 'remote'],
  ftp: ['FTP', 'file-transfer'],
  smtp: ['Email (SMTP)', 'email'],
  imap: ['Email (IMAP)', 'email'],
  pop3: ['Email (POP3)', 'email'],
  dns: ['DNS', 'network'],
  ntp: ['NTP', 'network'],
  dhcp: ['DHCP', 'network'],
  snmp: ['SNMP', 'network'],
  quic: ['Web (QUIC)', 'web'],
  tls: ['Web (TLS)', 'web'],
  http: ['Web (HTTP)', 'web'],
  krb5: ['Kerberos', 'network'],
  smb: ['SMB', 'file-transfer'],
};

// Generic web protocols: only used to label a flow when no hostname is known.
// When a hostname IS present but unmatched, we prefer the more informative
// "Other" (with the hostname shown) over a generic "Web (TLS)".
const WEB_PROTOS = new Set(['tls', 'http', 'quic']);

function normHost(host) {
  return String(host || '').toLowerCase().replace(/\.$/, '').trim();
}

/**
 * Classifies a flow by hostname and/or layer-7 protocol.
 * Returns { application, category }.
 *   - hostname matches a signature → that app
 *   - specific non-web protocol (bittorrent, ssh, ...) → that app
 *   - hostname present but unmatched → { application: 'Other', category: 'web' }
 *   - generic web protocol with no hostname → { application: 'Web (TLS)', ... }
 *   - nothing usable → { application: 'Unknown', category: 'other' }
 */
export function classifyApp(hostname, appProto) {
  const host = normHost(hostname);
  if (host) {
    let best = null;
    for (const [suffix, app, category] of DOMAIN_SIGNATURES) {
      if (host === suffix || host.endsWith(`.${suffix}`)) {
        if (!best || suffix.length > best.suffix.length) best = { suffix, app, category };
      }
    }
    if (best) return { application: best.app, category: best.category };
  }

  const proto = String(appProto || '').toLowerCase();
  // Specific (non-web) protocols are meaningful on their own.
  if (PROTO_SIGNATURES[proto] && !WEB_PROTOS.has(proto)) {
    const [app, category] = PROTO_SIGNATURES[proto];
    return { application: app, category };
  }

  // A known but unmatched hostname is more useful than a generic web label.
  if (host) return { application: 'Other', category: 'web' };

  if (PROTO_SIGNATURES[proto]) {
    const [app, category] = PROTO_SIGNATURES[proto];
    return { application: app, category };
  }
  return { application: 'Unknown', category: 'other' };
}

/** True when classification yielded a concrete application (not a fallback). */
export function isIdentified(application) {
  return application !== 'Other' && application !== 'Unknown';
}

/**
 * Maps a parsed Suricata eve.json event to an app_flow row, or null.
 *
 * De-duplication: TLS/QUIC/HTTP connections are recorded from their own
 * events (which carry the hostname). `flow` events are only used for OTHER
 * protocols (so we capture e.g. BitTorrent byte counts without double-counting
 * web traffic).
 */
export function appFlowFromEvent(event) {
  if (!event || typeof event !== 'object') return null;

  let hostname = null;
  let appProto = null;
  let bytes = 0;
  let source = event.event_type;
  let protocol = (event.proto ? String(event.proto).toLowerCase() : null);

  switch (event.event_type) {
    case 'tls':
      hostname = event.tls?.sni || null;
      appProto = 'tls';
      protocol = protocol || 'tcp';
      break;
    case 'quic':
      hostname = event.quic?.sni || null;
      appProto = 'quic';
      protocol = protocol || 'udp';
      break;
    case 'http':
      hostname = event.http?.hostname || null;
      appProto = 'http';
      protocol = protocol || 'tcp';
      break;
    case 'flow': {
      const ap = String(event.app_proto || '').toLowerCase();
      if (['tls', 'http', 'quic'].includes(ap)) return null; // covered above
      appProto = ap;
      bytes = (event.flow?.bytes_toserver || 0) + (event.flow?.bytes_toclient || 0);
      break;
    }
    default:
      return null;
  }

  const { application, category } = classifyApp(hostname, appProto);
  if (application === 'Unknown') return null; // not worth recording

  return {
    timestamp: event.timestamp ? new Date(event.timestamp).toISOString().slice(0, 19).replace('T', ' ') : null,
    client_ip: event.src_ip || null,
    dest_ip: event.dest_ip || null,
    application,
    category,
    hostname: hostname || '',
    protocol: protocol || '',
    app_proto: appProto || '',
    source,
    bytes,
  };
}
