import { describe, it, expect } from 'vitest';
import { buildWindowsBootstrap } from './bootstrap.mjs';

describe('buildWindowsBootstrap', () => {
  const agent = 'Write-Host "I am the agent"';
  const out = buildWindowsBootstrap(agent, 'https://shield.example.com');

  it('embeds the agent script as base64', () => {
    expect(out).toContain(Buffer.from(agent, 'utf8').toString('base64'));
    expect(out).toContain('[Convert]::FromBase64String($agentB64)');
  });

  it('pre-fills the API URL and requires a token + admin', () => {
    expect(out).toContain('$Api = "https://shield.example.com"');
    expect(out).toContain('[Parameter(Mandatory = $true)][string]$Token');
    expect(out).toContain('#Requires -RunAsAdministrator');
  });

  it('registers the SYSTEM scheduled task', () => {
    expect(out).toContain('Register-ScheduledTask -TaskName "HomeShieldAgent"');
    expect(out).toContain('New-ScheduledTaskPrincipal -UserId "SYSTEM"');
  });

  it('sanitises the API URL to avoid script injection', () => {
    const evil = buildWindowsBootstrap(agent, 'https://x"; rm -rf / #`$(bad)');
    expect(evil).not.toContain('"; rm');
    expect(evil).not.toContain('$(bad)');
  });

  it('handles an empty default API', () => {
    expect(buildWindowsBootstrap(agent, '')).toContain('$Api = ""');
  });
});
