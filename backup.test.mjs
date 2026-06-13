import { describe, it, expect } from 'vitest';
import {
  sha256, encryptPayload, decryptPayload, buildEnvelope, readEnvelope,
} from './backup.mjs';

describe('sha256', () => {
  it('produces a stable prefixed digest', () => {
    expect(sha256('hello')).toBe('sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  });
});

describe('encrypt/decrypt', () => {
  it('round-trips a payload with the right passphrase', () => {
    const cipher = encryptPayload('secret config', 'hunter2');
    expect(decryptPayload(cipher, 'hunter2')).toBe('secret config');
  });

  it('fails with the wrong passphrase', () => {
    const cipher = encryptPayload('secret config', 'hunter2');
    expect(() => decryptPayload(cipher, 'wrong')).toThrow(/wrong passphrase|Decryption failed/i);
  });

  it('uses a fresh salt/iv each time', () => {
    const a = encryptPayload('x', 'p');
    const b = encryptPayload('x', 'p');
    expect(a.salt).not.toBe(b.salt);
    expect(a.iv).not.toBe(b.iv);
  });
});

describe('envelope', () => {
  const config = { firewall_policies: [{ id: '1', name: 'Allow SSH' }], system_settings: [{ key: 'x', value: 'y' }] };

  it('round-trips an unencrypted envelope', () => {
    const env = buildEnvelope(config);
    const parsed = JSON.parse(env);
    expect(parsed.homeshield_backup).toBe(true);
    expect(parsed.encrypted).toBe(false);
    expect(readEnvelope(env)).toEqual(config);
  });

  it('round-trips an encrypted envelope', () => {
    const env = buildEnvelope(config, { passphrase: 'pw' });
    const parsed = JSON.parse(env);
    expect(parsed.encrypted).toBe(true);
    expect(parsed.data).toBeUndefined();
    expect(parsed.cipher).toBeDefined();
    expect(readEnvelope(env, 'pw')).toEqual(config);
  });

  it('requires a passphrase for encrypted backups', () => {
    const env = buildEnvelope(config, { passphrase: 'pw' });
    expect(() => readEnvelope(env)).toThrow(/passphrase is required/i);
  });

  it('rejects non-HomeShield files', () => {
    expect(() => readEnvelope('{"foo":1}')).toThrow(/Not a HomeShield backup/);
    expect(() => readEnvelope('not json')).toThrow(/not valid JSON/);
  });

  it('rejects backups from a newer version', () => {
    const future = JSON.stringify({ homeshield_backup: true, version: 999, encrypted: false, data: {} });
    expect(() => readEnvelope(future)).toThrow(/newer than supported/);
  });
});
