/**
 * Application / URL-category signature catalog for HomeShield security policies.
 *
 * Maps applications and content categories to the domains that identify them,
 * so a policy that matches an App-ID or URL category can be enforced at the DNS
 * layer (sinkhole the domains on deny, allowlist them on allow). Used by the
 * management server. Pure data + helpers — unit tested in appsignatures.test.mjs.
 *
 * NOTE: the agent keeps its own copy of these signatures (agent/appid.mjs) for
 * on-box classification; this module is the server-side source for policy
 * authoring and DNS enforcement.
 */

// [domain suffix, application, category]
const SIGNATURES = [
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
  ['windowsupdate.com', 'Windows Update', 'cloud'], ['office.com', 'Microsoft 365', 'cloud'],
  ['amazonaws.com', 'Amazon AWS', 'cloud'], ['github.com', 'GitHub', 'dev'], ['githubusercontent.com', 'GitHub', 'dev'],
  ['dropbox.com', 'Dropbox', 'cloud'],
];

/** Sorted list of distinct application names (for the policy editor dropdown). */
export function listApplications() {
  return [...new Set(SIGNATURES.map(s => s[1]))].sort();
}

/** Sorted list of distinct content categories. */
export function listCategories() {
  return [...new Set(SIGNATURES.map(s => s[2]))].sort();
}

/** Domains that identify an application. */
export function appDomains(application) {
  return SIGNATURES.filter(s => s[1] === application).map(s => s[0]);
}

/** Domains in a content/URL category. */
export function categoryDomains(category) {
  return SIGNATURES.filter(s => s[2] === category).map(s => s[0]);
}
