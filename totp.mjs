/**
 * TOTP (RFC 6238) implementation for HomeShield MFA. Dependency-free, using
 * Node's crypto for HMAC-SHA1. Pure functions — unit tested against the RFC
 * test vectors in totp.test.mjs.
 */

import crypto from 'node:crypto';

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Encodes a Buffer to RFC 4648 base32 (no padding). */
export function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/** Decodes an RFC 4648 base32 string to a Buffer (ignores spaces/padding/case). */
export function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** Generates a new base32 TOTP secret (default 20 random bytes = 160 bits). */
export function generateSecret(bytes = 20) {
  return base32Encode(crypto.randomBytes(bytes));
}

/** Computes an HOTP value for a counter (RFC 4226). */
export function hotp(secretBytes, counter, digits = 6) {
  const buf = Buffer.alloc(8);
  // Write the 64-bit counter big-endian.
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', secretBytes).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return (bin % 10 ** digits).toString().padStart(digits, '0');
}

/** Computes the current TOTP code for a base32 secret. */
export function totp(secretBase32, { time = Date.now(), step = 30, digits = 6 } = {}) {
  const counter = Math.floor(time / 1000 / step);
  return hotp(base32Decode(secretBase32), counter, digits);
}

/**
 * Verifies a submitted TOTP token, allowing ±window steps of clock drift.
 * Uses a constant-time compare per candidate.
 */
export function verifyTOTP(secretBase32, token, { time = Date.now(), step = 30, digits = 6, window = 1 } = {}) {
  const cleaned = String(token || '').replace(/\D/g, '');
  if (cleaned.length !== digits) return false;
  const secret = base32Decode(secretBase32);
  const base = Math.floor(time / 1000 / step);
  for (let w = -window; w <= window; w++) {
    const candidate = hotp(secret, base + w, digits);
    const a = Buffer.from(candidate);
    const b = Buffer.from(cleaned);
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) return true;
  }
  return false;
}

/** Builds an otpauth:// URL for QR provisioning (Google Authenticator etc.). */
export function otpauthURL({ secret, label, issuer = 'HomeShield' }) {
  const enc = encodeURIComponent;
  const acct = `${enc(issuer)}:${enc(label)}`;
  return `otpauth://totp/${acct}?secret=${secret}&issuer=${enc(issuer)}&algorithm=SHA1&digits=6&period=30`;
}
