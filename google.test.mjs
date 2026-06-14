import { describe, it, expect } from 'vitest';
import { decodeJwt, verifyGoogleClaims } from './google.mjs';

function makeToken(payload) {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${b64({ alg: 'RS256', kid: 'k1' })}.${b64(payload)}.${Buffer.from('sig').toString('base64url')}`;
}

const CLIENT = '123.apps.googleusercontent.com';
const base = {
  iss: 'https://accounts.google.com', aud: CLIENT, exp: 2000000000,
  email: 'User@Example.com', email_verified: true, name: 'User', sub: '42',
};

describe('decodeJwt', () => {
  it('splits header/payload/signature', () => {
    const { header, payload } = decodeJwt(makeToken(base));
    expect(header).toMatchObject({ alg: 'RS256', kid: 'k1' });
    expect(payload.aud).toBe(CLIENT);
  });

  it('rejects malformed tokens', () => {
    expect(() => decodeJwt('a.b')).toThrow(/Malformed/);
  });
});

describe('verifyGoogleClaims', () => {
  const now = 1700000000;

  it('accepts a valid payload and normalizes the email', () => {
    expect(verifyGoogleClaims(base, CLIENT, now)).toEqual({ email: 'user@example.com', name: 'User', sub: '42' });
  });

  it('accepts both Google issuer forms', () => {
    expect(verifyGoogleClaims({ ...base, iss: 'accounts.google.com' }, CLIENT, now).email).toBe('user@example.com');
  });

  it('rejects a wrong audience', () => {
    expect(() => verifyGoogleClaims({ ...base, aud: 'other' }, CLIENT, now)).toThrow(/audience/);
  });

  it('rejects an untrusted issuer', () => {
    expect(() => verifyGoogleClaims({ ...base, iss: 'evil.com' }, CLIENT, now)).toThrow(/issuer/);
  });

  it('rejects expired tokens', () => {
    expect(() => verifyGoogleClaims({ ...base, exp: now - 1 }, CLIENT, now)).toThrow(/expired/);
  });

  it('rejects unverified emails', () => {
    expect(() => verifyGoogleClaims({ ...base, email_verified: false }, CLIENT, now)).toThrow(/not verified/);
  });

  it('rejects a missing client id', () => {
    expect(() => verifyGoogleClaims(base, '', now)).toThrow(/audience/);
  });
});
