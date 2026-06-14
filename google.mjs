/**
 * Google Sign-In (Identity Services) ID-token verification for HomeShield.
 *
 * The browser obtains a Google ID token (an RS256 JWT) and posts it to the
 * server. We verify the signature against Google's JWKS and validate the
 * claims. No external dependency — Node's crypto can build a public key from a
 * JWK and verify RS256. The pure claim checks are unit tested in google.test.mjs.
 */

import crypto from 'node:crypto';

const JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
const ISSUERS = new Set(['accounts.google.com', 'https://accounts.google.com']);

let jwksCache = { keys: [], fetchedAt: 0 };

/** Splits a JWT into header/payload/signature without verifying. */
export function decodeJwt(token) {
  const parts = String(token).split('.');
  if (parts.length !== 3) throw new Error('Malformed token');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  return { header, payload, signingInput: `${parts[0]}.${parts[1]}`, signature: Buffer.from(parts[2], 'base64url') };
}

/**
 * Validates the standard claims of a Google ID token payload.
 * @returns { email, name, sub } on success; throws otherwise.
 */
export function verifyGoogleClaims(payload, clientId, nowSec = Math.floor(Date.now() / 1000)) {
  if (!payload || typeof payload !== 'object') throw new Error('Invalid token payload');
  if (!ISSUERS.has(payload.iss)) throw new Error('Untrusted token issuer');
  if (!clientId || payload.aud !== clientId) throw new Error('Token audience mismatch');
  if (typeof payload.exp !== 'number' || payload.exp <= nowSec) throw new Error('Token expired');
  if (payload.email_verified === false) throw new Error('Google email not verified');
  if (!payload.email) throw new Error('Token has no email');
  return { email: String(payload.email).toLowerCase(), name: payload.name || '', sub: payload.sub || '' };
}

async function getJwks() {
  if (jwksCache.keys.length && Date.now() - jwksCache.fetchedAt < 3600_000) return jwksCache.keys;
  const res = await fetch(JWKS_URL);
  if (!res.ok) throw new Error(`JWKS fetch failed: HTTP ${res.status}`);
  const json = await res.json();
  jwksCache = { keys: json.keys || [], fetchedAt: Date.now() };
  return jwksCache.keys;
}

/** Verifies a Google ID token's signature and claims. Returns { email, name }. */
export async function verifyGoogleIdToken(token, clientId) {
  const { header, payload, signingInput, signature } = decodeJwt(token);
  if (header.alg !== 'RS256') throw new Error('Unexpected token algorithm');
  const keys = await getJwks();
  const jwk = keys.find(k => k.kid === header.kid);
  if (!jwk) throw new Error('Token signing key not found');
  const pubKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const ok = crypto.verify('RSA-SHA256', Buffer.from(signingInput), pubKey, signature);
  if (!ok) throw new Error('Token signature verification failed');
  return verifyGoogleClaims(payload, clientId);
}
