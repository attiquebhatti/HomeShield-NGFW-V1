/**
 * Application / URL-category signature catalog for HomeShield security policies.
 *
 * Maps applications and content categories to the domains that identify them,
 * so a policy that matches an App-ID or URL category can be enforced at the DNS
 * layer (sinkhole the domains on deny, allowlist them on allow).
 *
 * These are publicly-known applications mapped to their domains by us, grouped
 * with a Palo-Alto-style category taxonomy and a 1-5 risk rating. We do NOT
 * import Palo Alto's proprietary App-ID database — Applipedia does not publish
 * the domain signatures our DNS enforcement needs, and that catalog is licensed.
 *
 * NOTE: the agent keeps its own smaller copy (agent/appid.mjs) for on-box flow
 * classification; this module is the server-side source for policy authoring
 * and DNS enforcement.
 */

// { name, category, risk (1=low .. 5=high), domains: [identifying domain suffixes] }
const APPS = [
  // ── Streaming (video/audio) ───────────────────────────────────────────────
  { name: 'YouTube', category: 'streaming', risk: 3, domains: ['youtube.com', 'googlevideo.com', 'ytimg.com', 'youtu.be'] },
  { name: 'Netflix', category: 'streaming', risk: 2, domains: ['netflix.com', 'nflxvideo.net', 'nflximg.net'] },
  { name: 'Twitch', category: 'streaming', risk: 3, domains: ['twitch.tv', 'ttvnw.net'] },
  { name: 'Disney+', category: 'streaming', risk: 2, domains: ['disneyplus.com', 'dssott.com'] },
  { name: 'Prime Video', category: 'streaming', risk: 2, domains: ['primevideo.com'] },
  { name: 'Hulu', category: 'streaming', risk: 2, domains: ['hulu.com'] },
  { name: 'Max (HBO)', category: 'streaming', risk: 2, domains: ['max.com', 'hbomax.com'] },
  { name: 'Vimeo', category: 'streaming', risk: 2, domains: ['vimeo.com'] },
  { name: 'Dailymotion', category: 'streaming', risk: 3, domains: ['dailymotion.com'] },
  { name: 'Spotify', category: 'streaming', risk: 2, domains: ['spotify.com', 'scdn.co'] },
  { name: 'Apple Music', category: 'streaming', risk: 2, domains: ['music.apple.com'] },
  { name: 'SoundCloud', category: 'streaming', risk: 2, domains: ['soundcloud.com', 'sndcdn.com'] },
  { name: 'Pandora', category: 'streaming', risk: 2, domains: ['pandora.com'] },
  { name: 'Deezer', category: 'streaming', risk: 2, domains: ['deezer.com'] },
  { name: 'Tidal', category: 'streaming', risk: 2, domains: ['tidal.com'] },

  // ── Social networking ─────────────────────────────────────────────────────
  { name: 'Facebook', category: 'social', risk: 3, domains: ['facebook.com', 'fbcdn.net', 'fb.com'] },
  { name: 'Instagram', category: 'social', risk: 3, domains: ['instagram.com', 'cdninstagram.com'] },
  { name: 'X (Twitter)', category: 'social', risk: 3, domains: ['twitter.com', 'x.com', 'twimg.com'] },
  { name: 'TikTok', category: 'social', risk: 4, domains: ['tiktok.com', 'tiktokcdn.com', 'byteoversea.com'] },
  { name: 'Reddit', category: 'social', risk: 3, domains: ['reddit.com', 'redd.it', 'redditmedia.com'] },
  { name: 'LinkedIn', category: 'social', risk: 2, domains: ['linkedin.com', 'licdn.com'] },
  { name: 'Snapchat', category: 'social', risk: 3, domains: ['snapchat.com', 'sc-cdn.net'] },
  { name: 'Pinterest', category: 'social', risk: 2, domains: ['pinterest.com', 'pinimg.com'] },
  { name: 'Tumblr', category: 'social', risk: 3, domains: ['tumblr.com'] },
  { name: 'Quora', category: 'social', risk: 2, domains: ['quora.com'] },
  { name: 'VK', category: 'social', risk: 3, domains: ['vk.com'] },

  // ── Messaging ─────────────────────────────────────────────────────────────
  { name: 'WhatsApp', category: 'messaging', risk: 3, domains: ['whatsapp.com', 'whatsapp.net'] },
  { name: 'Telegram', category: 'messaging', risk: 4, domains: ['telegram.org', 't.me', 'telegram.me'] },
  { name: 'Signal', category: 'messaging', risk: 3, domains: ['signal.org'] },
  { name: 'Discord', category: 'messaging', risk: 3, domains: ['discord.com', 'discord.gg', 'discordapp.com', 'discord.media'] },
  { name: 'Slack', category: 'messaging', risk: 2, domains: ['slack.com'] },
  { name: 'WeChat', category: 'messaging', risk: 4, domains: ['wechat.com', 'weixin.qq.com'] },
  { name: 'Facebook Messenger', category: 'messaging', risk: 3, domains: ['messenger.com'] },
  { name: 'Skype', category: 'messaging', risk: 2, domains: ['skype.com'] },
  { name: 'Viber', category: 'messaging', risk: 3, domains: ['viber.com'] },
  { name: 'Line', category: 'messaging', risk: 3, domains: ['line.me'] },

  // ── Conferencing ──────────────────────────────────────────────────────────
  { name: 'Zoom', category: 'conferencing', risk: 2, domains: ['zoom.us'] },
  { name: 'Microsoft Teams', category: 'conferencing', risk: 2, domains: ['teams.microsoft.com', 'teams.live.com'] },
  { name: 'Google Meet', category: 'conferencing', risk: 2, domains: ['meet.google.com'] },
  { name: 'Cisco Webex', category: 'conferencing', risk: 2, domains: ['webex.com'] },
  { name: 'GoTo Meeting', category: 'conferencing', risk: 2, domains: ['gotomeeting.com', 'goto.com'] },

  // ── Email ─────────────────────────────────────────────────────────────────
  { name: 'Gmail', category: 'email', risk: 2, domains: ['mail.google.com'] },
  { name: 'Outlook', category: 'email', risk: 2, domains: ['outlook.com', 'outlook.live.com'] },
  { name: 'Yahoo Mail', category: 'email', risk: 2, domains: ['mail.yahoo.com', 'yahoo.com'] },
  { name: 'Proton Mail', category: 'email', risk: 3, domains: ['proton.me', 'protonmail.com'] },
  { name: 'Zoho Mail', category: 'email', risk: 2, domains: ['zoho.com'] },

  // ── Gaming ────────────────────────────────────────────────────────────────
  { name: 'Steam', category: 'gaming', risk: 2, domains: ['steampowered.com', 'steamcommunity.com', 'steamcontent.com'] },
  { name: 'Epic Games', category: 'gaming', risk: 2, domains: ['epicgames.com', 'fortnite.com'] },
  { name: 'Riot Games', category: 'gaming', risk: 2, domains: ['riotgames.com'] },
  { name: 'Blizzard', category: 'gaming', risk: 2, domains: ['battle.net', 'blizzard.com'] },
  { name: 'Xbox Live', category: 'gaming', risk: 2, domains: ['xboxlive.com', 'xbox.com'] },
  { name: 'PlayStation Network', category: 'gaming', risk: 2, domains: ['playstation.net', 'playstation.com'] },
  { name: 'Nintendo', category: 'gaming', risk: 2, domains: ['nintendo.net', 'nintendo.com'] },
  { name: 'Roblox', category: 'gaming', risk: 3, domains: ['roblox.com'] },
  { name: 'Minecraft', category: 'gaming', risk: 2, domains: ['minecraft.net', 'mojang.com'] },
  { name: 'Electronic Arts', category: 'gaming', risk: 2, domains: ['ea.com'] },

  // ── File sharing / cloud storage ──────────────────────────────────────────
  { name: 'Dropbox', category: 'file-sharing', risk: 3, domains: ['dropbox.com', 'dropboxusercontent.com'] },
  { name: 'Google Drive', category: 'file-sharing', risk: 2, domains: ['drive.google.com', 'docs.google.com'] },
  { name: 'OneDrive', category: 'file-sharing', risk: 2, domains: ['onedrive.live.com', '1drv.com'] },
  { name: 'iCloud', category: 'file-sharing', risk: 2, domains: ['icloud.com'] },
  { name: 'Box', category: 'file-sharing', risk: 2, domains: ['box.com'] },
  { name: 'MEGA', category: 'file-sharing', risk: 4, domains: ['mega.nz', 'mega.io'] },
  { name: 'WeTransfer', category: 'file-sharing', risk: 3, domains: ['wetransfer.com'] },
  { name: 'MediaFire', category: 'file-sharing', risk: 3, domains: ['mediafire.com'] },
  { name: 'BitTorrent', category: 'file-sharing', risk: 4, domains: ['thepiratebay.org', '1337x.to', 'rarbg.to', 'torrentz2.eu'] },

  // ── VPN / proxy / anonymizer ──────────────────────────────────────────────
  { name: 'NordVPN', category: 'vpn-proxy', risk: 4, domains: ['nordvpn.com'] },
  { name: 'ExpressVPN', category: 'vpn-proxy', risk: 4, domains: ['expressvpn.com'] },
  { name: 'Proton VPN', category: 'vpn-proxy', risk: 4, domains: ['protonvpn.com'] },
  { name: 'Surfshark', category: 'vpn-proxy', risk: 4, domains: ['surfshark.com'] },
  { name: 'Tor', category: 'vpn-proxy', risk: 5, domains: ['torproject.org'] },
  { name: 'Psiphon', category: 'vpn-proxy', risk: 5, domains: ['psiphon3.com', 'psiphon.ca'] },
  { name: 'Ultrasurf', category: 'vpn-proxy', risk: 5, domains: ['ultrasurf.us'] },
  { name: 'Hola VPN', category: 'vpn-proxy', risk: 5, domains: ['hola.org'] },

  // ── Remote access ─────────────────────────────────────────────────────────
  { name: 'TeamViewer', category: 'remote-access', risk: 4, domains: ['teamviewer.com'] },
  { name: 'AnyDesk', category: 'remote-access', risk: 4, domains: ['anydesk.com'] },
  { name: 'Chrome Remote Desktop', category: 'remote-access', risk: 3, domains: ['remotedesktop.google.com'] },
  { name: 'LogMeIn', category: 'remote-access', risk: 3, domains: ['logmein.com'] },
  { name: 'Splashtop', category: 'remote-access', risk: 3, domains: ['splashtop.com'] },

  // ── AI / LLM services ─────────────────────────────────────────────────────
  { name: 'ChatGPT (OpenAI)', category: 'ai', risk: 3, domains: ['openai.com', 'chatgpt.com', 'oaistatic.com'] },
  { name: 'Claude (Anthropic)', category: 'ai', risk: 2, domains: ['claude.ai', 'anthropic.com'] },
  { name: 'Google Gemini', category: 'ai', risk: 2, domains: ['gemini.google.com'] },
  { name: 'Perplexity', category: 'ai', risk: 2, domains: ['perplexity.ai'] },
  { name: 'Microsoft Copilot', category: 'ai', risk: 2, domains: ['copilot.microsoft.com'] },

  // ── Developer / SaaS / business ───────────────────────────────────────────
  { name: 'GitHub', category: 'dev', risk: 2, domains: ['github.com', 'githubusercontent.com'] },
  { name: 'GitLab', category: 'dev', risk: 2, domains: ['gitlab.com'] },
  { name: 'Bitbucket', category: 'dev', risk: 2, domains: ['bitbucket.org'] },
  { name: 'Atlassian (Jira/Confluence)', category: 'dev', risk: 2, domains: ['atlassian.com', 'atlassian.net'] },
  { name: 'Docker Hub', category: 'dev', risk: 2, domains: ['docker.com', 'docker.io'] },
  { name: 'npm', category: 'dev', risk: 2, domains: ['npmjs.com'] },
  { name: 'Notion', category: 'cloud', risk: 2, domains: ['notion.so'] },
  { name: 'Trello', category: 'cloud', risk: 2, domains: ['trello.com'] },
  { name: 'Asana', category: 'cloud', risk: 2, domains: ['asana.com'] },
  { name: 'Salesforce', category: 'cloud', risk: 2, domains: ['salesforce.com', 'force.com'] },
  { name: 'HubSpot', category: 'cloud', risk: 2, domains: ['hubspot.com'] },
  { name: 'Zendesk', category: 'cloud', risk: 2, domains: ['zendesk.com'] },
  { name: 'ServiceNow', category: 'cloud', risk: 2, domains: ['servicenow.com', 'service-now.com'] },
  { name: 'Okta', category: 'cloud', risk: 2, domains: ['okta.com'] },
  { name: 'Microsoft 365', category: 'cloud', risk: 2, domains: ['office.com', 'office365.com', 'microsoftonline.com', 'sharepoint.com'] },
  { name: 'Google Workspace', category: 'cloud', risk: 2, domains: ['workspace.google.com', 'googleapis.com', 'gstatic.com'] },
  { name: 'Adobe Creative Cloud', category: 'cloud', risk: 2, domains: ['adobe.com', 'adobe.io'] },
  { name: 'Amazon Web Services', category: 'cloud', risk: 2, domains: ['amazonaws.com', 'aws.amazon.com'] },
  { name: 'Microsoft Azure', category: 'cloud', risk: 2, domains: ['azure.com', 'windows.net', 'azureedge.net'] },
  { name: 'Google Cloud', category: 'cloud', risk: 2, domains: ['cloud.google.com'] },

  // ── Shopping / finance ────────────────────────────────────────────────────
  { name: 'Amazon', category: 'shopping', risk: 2, domains: ['amazon.com'] },
  { name: 'eBay', category: 'shopping', risk: 2, domains: ['ebay.com'] },
  { name: 'AliExpress', category: 'shopping', risk: 3, domains: ['aliexpress.com', 'alibaba.com'] },
  { name: 'PayPal', category: 'shopping', risk: 2, domains: ['paypal.com'] },
  { name: 'Stripe', category: 'shopping', risk: 2, domains: ['stripe.com'] },
  { name: 'Shopify', category: 'shopping', risk: 2, domains: ['shopify.com'] },

  // ── General web / infrastructure ──────────────────────────────────────────
  { name: 'Google Search', category: 'web', risk: 1, domains: ['google.com'] },
  { name: 'Bing', category: 'web', risk: 1, domains: ['bing.com'] },
  { name: 'DuckDuckGo', category: 'web', risk: 1, domains: ['duckduckgo.com'] },
  { name: 'Wikipedia', category: 'web', risk: 1, domains: ['wikipedia.org', 'wikimedia.org'] },
  { name: 'Apple', category: 'web', risk: 1, domains: ['apple.com', 'mzstatic.com'] },
  { name: 'Windows Update', category: 'infrastructure', risk: 1, domains: ['windowsupdate.com'] },
  { name: 'Cloudflare', category: 'infrastructure', risk: 1, domains: ['cloudflare.com'] },
  { name: 'Akamai', category: 'infrastructure', risk: 1, domains: ['akamai.com', 'akamaihd.net'] },
];

/** Distinct content categories, sorted (URL-filtering category dropdown). */
export function listCategories() {
  return [...new Set(APPS.map(a => a.category))].sort();
}

/** Application catalog for the policy editor: { name, category, risk }, by name. */
export function listApplications() {
  return APPS
    .map(({ name, category, risk }) => ({ name, category, risk }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

/** Domains that identify an application. */
export function appDomains(application) {
  const app = APPS.find(a => a.name === application);
  return app ? app.domains.slice() : [];
}

/** Domains belonging to a content/URL category. */
export function categoryDomains(category) {
  return APPS.filter(a => a.category === category).flatMap(a => a.domains);
}
