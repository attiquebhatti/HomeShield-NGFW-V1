import { describe, it, expect } from 'vitest';
import { base32Encode, base32Decode, generateSecret, totp, verifyTOTP, otpauthURL } from './totp.mjs';

// RFC 6238 test secret: ASCII "12345678901234567890" (SHA-1).
const RFC_SECRET = base32Encode(Buffer.from('12345678901234567890'));

describe('base32', () => {
  it('round-trips bytes', () => {
    const buf = Buffer.from('Hello, World!');
    expect(base32Decode(base32Encode(buf))).toEqual(buf);
  });

  it('encodes the RFC secret correctly', () => {
    expect(RFC_SECRET).toBe('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
  });

  it('ignores spaces, padding and case on decode', () => {
    expect(base32Decode('gezd gnbv').equals(base32Decode('GEZDGNBV'))).toBe(true);
  });
});

describe('totp (RFC 6238 vectors)', () => {
  // Each vector: unix seconds → expected 6-digit code (truncated from the
  // RFC's 8-digit SHA-1 values).
  const vectors = [
    [59, '287082'],
    [1111111109, '081804'],
    [1111111111, '050471'],
    [1234567890, '005924'],
    [2000000000, '279037'],
  ];

  for (const [seconds, code] of vectors) {
    it(`produces ${code} at t=${seconds}`, () => {
      expect(totp(RFC_SECRET, { time: seconds * 1000 })).toBe(code);
    });
  }
});

describe('verifyTOTP', () => {
  it('accepts the current code', () => {
    const now = Date.now();
    expect(verifyTOTP(RFC_SECRET, totp(RFC_SECRET, { time: now }), { time: now })).toBe(true);
  });

  it('accepts a code within the drift window', () => {
    const now = 1111111111 * 1000;
    const prev = totp(RFC_SECRET, { time: now - 30000 });
    expect(verifyTOTP(RFC_SECRET, prev, { time: now, window: 1 })).toBe(true);
  });

  it('rejects a code outside the window', () => {
    const now = 1111111111 * 1000;
    const old = totp(RFC_SECRET, { time: now - 120000 });
    expect(verifyTOTP(RFC_SECRET, old, { time: now, window: 1 })).toBe(false);
  });

  it('rejects malformed tokens', () => {
    expect(verifyTOTP(RFC_SECRET, '12', {})).toBe(false);
    expect(verifyTOTP(RFC_SECRET, 'abcdef', {})).toBe(false);
    expect(verifyTOTP(RFC_SECRET, '', {})).toBe(false);
  });
});

describe('generateSecret / otpauthURL', () => {
  it('generates a usable base32 secret', () => {
    const s = generateSecret();
    expect(s).toMatch(/^[A-Z2-7]+$/);
    expect(base32Decode(s)).toHaveLength(20);
  });

  it('builds an otpauth URL with the secret and issuer', () => {
    const url = otpauthURL({ secret: 'ABC234', label: 'admin@example.com', issuer: 'HomeShield' });
    expect(url).toContain('otpauth://totp/HomeShield:admin%40example.com');
    expect(url).toContain('secret=ABC234');
    expect(url).toContain('issuer=HomeShield');
  });
});
