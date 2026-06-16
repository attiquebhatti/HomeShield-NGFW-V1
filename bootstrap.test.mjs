import { describe, it, expect } from 'vitest';
import { buildWindowsBootstrap, buildWindowsCmd } from './bootstrap.mjs';

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

  it('embeds the optional status script when provided', () => {
    const status = 'Write-Host "status"';
    const withStatus = buildWindowsBootstrap(agent, 'https://x', status);
    expect(withStatus).toContain(Buffer.from(status, 'utf8').toString('base64'));
    expect(withStatus).toContain('homeshield-status.ps1');
    // and omits it when not provided
    expect(out).not.toContain('homeshield-status.ps1');
  });
});

describe('buildWindowsCmd', () => {
  const agent = 'Write-Host "agent body"';
  const out = buildWindowsCmd(agent, 'https://shield.example.com', 'secrettoken');

  it('is a self-elevating batch file', () => {
    expect(out.startsWith('@echo off')).toBe(true);
    expect(out).toContain('net session >nul 2>&1');
    expect(out).toContain('Start-Process -Verb RunAs');
    expect(out).toContain('exit /b');
  });

  it('bakes in the API and token and embeds the agent', () => {
    expect(out).toContain("$Api = 'https://shield.example.com'");
    expect(out).toContain("$Token = 'secrettoken'");
    expect(out).toContain(Buffer.from(agent, 'utf8').toString('base64'));
  });

  it('runs the payload after the marker via LastIndexOf (not the marker in the command)', () => {
    expect(out).toContain("$c.LastIndexOf('#PSPAYLOAD#')");
    // the literal marker line appears exactly once as a delimiter (plus once inside the command)
    const markerLines = out.split('\r\n').filter(l => l === '#PSPAYLOAD#');
    expect(markerLines.length).toBe(1);
    expect(out).toContain('Register-ScheduledTask -TaskName "HomeShieldAgent"');
  });

  it('uses CRLF line endings and escapes single quotes', () => {
    expect(out).toContain('\r\n');
    expect(buildWindowsCmd(agent, "a'b", "t'k")).toContain("$Token = 't''k'");
  });

  it('embeds the optional status script when provided', () => {
    const status = 'Write-Host "status"';
    const withStatus = buildWindowsCmd(agent, 'https://x', 'tok', status);
    expect(withStatus).toContain(Buffer.from(status, 'utf8').toString('base64'));
    expect(withStatus).toContain('$statusB64');
    // the base file still hints at the status command, but only writes it when bundled
    expect(out).not.toContain('$statusB64');
  });
});
