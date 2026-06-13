import { describe, it, expect } from 'vitest';
import { classifyApp, isIdentified, appFlowFromEvent } from './appid.mjs';

describe('classifyApp', () => {
  it('identifies apps by domain and subdomain', () => {
    expect(classifyApp('www.youtube.com').application).toBe('YouTube');
    expect(classifyApp('r4---sn-abc.googlevideo.com').application).toBe('YouTube');
    expect(classifyApp('netflix.com')).toEqual({ application: 'Netflix', category: 'streaming' });
    expect(classifyApp('gateway.discord.gg').application).toBe('Discord');
    expect(classifyApp('media.steampowered.com').application).toBe('Steam');
  });

  it('prefers the longest matching suffix', () => {
    // teams.microsoft.com should win over a hypothetical microsoft.com entry
    expect(classifyApp('api.teams.microsoft.com').application).toBe('Microsoft Teams');
  });

  it('is case-insensitive and tolerant of trailing dots', () => {
    expect(classifyApp('WWW.NETFLIX.COM.').application).toBe('Netflix');
  });

  it('falls back to layer-7 protocol when no host matches', () => {
    expect(classifyApp(null, 'bittorrent')).toEqual({ application: 'BitTorrent', category: 'p2p' });
    expect(classifyApp(null, 'ssh').application).toBe('SSH');
    expect(classifyApp('', 'quic').application).toBe('Web (QUIC)');
  });

  it('returns Other for an unknown host, Unknown for nothing usable', () => {
    expect(classifyApp('some-random-host.example').application).toBe('Other');
    expect(classifyApp(null, null).application).toBe('Unknown');
    expect(classifyApp(null, 'failed').application).toBe('Unknown');
  });

  it('isIdentified distinguishes concrete apps from fallbacks', () => {
    expect(isIdentified('YouTube')).toBe(true);
    expect(isIdentified('Other')).toBe(false);
    expect(isIdentified('Unknown')).toBe(false);
  });
});

describe('appFlowFromEvent', () => {
  it('maps a TLS event with SNI to an app flow', () => {
    const flow = appFlowFromEvent({
      event_type: 'tls', timestamp: '2026-06-13T10:00:00.000000+0000',
      src_ip: '192.168.1.20', dest_ip: '142.250.1.1', proto: 'TCP',
      tls: { sni: 'www.youtube.com', version: 'TLS 1.3' },
    });
    expect(flow).toMatchObject({
      client_ip: '192.168.1.20', application: 'YouTube', category: 'streaming',
      hostname: 'www.youtube.com', app_proto: 'tls', source: 'tls',
    });
    expect(flow.timestamp).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
  });

  it('maps a QUIC event with SNI', () => {
    const flow = appFlowFromEvent({ event_type: 'quic', src_ip: '10.0.0.2', quic: { sni: 'netflix.com' } });
    expect(flow).toMatchObject({ application: 'Netflix', source: 'quic', app_proto: 'quic' });
  });

  it('maps an HTTP event by Host header', () => {
    const flow = appFlowFromEvent({ event_type: 'http', src_ip: '10.0.0.3', http: { hostname: 'cdn.discordapp.com' } });
    expect(flow.application).toBe('Discord');
  });

  it('uses flow events for non-web protocols with byte counts', () => {
    const flow = appFlowFromEvent({
      event_type: 'flow', src_ip: '10.0.0.4', app_proto: 'bittorrent',
      flow: { bytes_toserver: 1000, bytes_toclient: 5000 },
    });
    expect(flow).toMatchObject({ application: 'BitTorrent', source: 'flow', bytes: 6000 });
  });

  it('ignores flow events for web protocols (counted via tls/http/quic)', () => {
    expect(appFlowFromEvent({ event_type: 'flow', app_proto: 'tls', flow: {} })).toBeNull();
    expect(appFlowFromEvent({ event_type: 'flow', app_proto: 'http', flow: {} })).toBeNull();
  });

  it('ignores unrelated events and unclassifiable flows', () => {
    expect(appFlowFromEvent({ event_type: 'alert' })).toBeNull();
    expect(appFlowFromEvent({ event_type: 'stats' })).toBeNull();
    expect(appFlowFromEvent({ event_type: 'flow', app_proto: 'failed', flow: {} })).toBeNull();
  });

  it('records a TLS connection with an unmatched SNI as Other', () => {
    const flow = appFlowFromEvent({ event_type: 'tls', src_ip: '10.0.0.5', tls: { sni: 'intranet.local' } });
    expect(flow.application).toBe('Other');
    expect(flow.hostname).toBe('intranet.local');
  });
});
