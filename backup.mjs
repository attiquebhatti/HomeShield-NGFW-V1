/**
 * Backup serialization and optional passphrase encryption for HomeShield.
 *
 * A backup is a JSON "envelope" describing the captured configuration. When a
 * passphrase is supplied the config payload is encrypted with AES-256-GCM
 * using a scrypt-derived key, so backups containing secrets (VPN keys, etc.)
 * can be stored and exported safely. Pure helpers — unit tested in
 * backup.test.mjs.
 */

import crypto from 'node:crypto';

export const BACKUP_VERSION = 1;

export function sha256(text) {
  return 'sha256:' + crypto.createHash('sha256').update(text).digest('hex');
}

/** Encrypts a plaintext string with a passphrase. Returns a cipher envelope. */
export function encryptPayload(plaintext, passphrase) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(passphrase, salt, 32);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    alg: 'aes-256-gcm',
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ct: ct.toString('base64'),
  };
}

/** Decrypts a cipher envelope. Throws if the passphrase is wrong (auth fail). */
export function decryptPayload(cipher, passphrase) {
  const salt = Buffer.from(cipher.salt, 'base64');
  const iv = Buffer.from(cipher.iv, 'base64');
  const tag = Buffer.from(cipher.tag, 'base64');
  const key = crypto.scryptSync(passphrase, salt, 32);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(Buffer.from(cipher.ct, 'base64')), decipher.final()]).toString('utf8');
  } catch {
    throw new Error('Decryption failed — wrong passphrase or corrupt backup');
  }
}

/**
 * Builds a backup envelope (as a JSON string) from a config object.
 * If passphrase is provided, the config is encrypted.
 */
export function buildEnvelope(config, { passphrase, createdAt } = {}) {
  const plaintext = JSON.stringify(config);
  const envelope = {
    homeshield_backup: true,
    version: BACKUP_VERSION,
    created_at: createdAt || new Date().toISOString(),
    encrypted: Boolean(passphrase),
  };
  if (passphrase) envelope.cipher = encryptPayload(plaintext, passphrase);
  else envelope.data = config;
  return JSON.stringify(envelope);
}

/**
 * Parses and validates a backup envelope string, returning the config object.
 * @throws on malformed envelopes or missing/incorrect passphrase.
 */
export function readEnvelope(envelopeStr, passphrase) {
  let env;
  try {
    env = typeof envelopeStr === 'string' ? JSON.parse(envelopeStr) : envelopeStr;
  } catch {
    throw new Error('Invalid backup file — not valid JSON');
  }
  if (!env || env.homeshield_backup !== true) {
    throw new Error('Not a HomeShield backup file');
  }
  if (env.version > BACKUP_VERSION) {
    throw new Error(`Backup version ${env.version} is newer than supported (${BACKUP_VERSION})`);
  }
  if (env.encrypted) {
    if (!passphrase) throw new Error('This backup is encrypted — a passphrase is required');
    return JSON.parse(decryptPayload(env.cipher, passphrase));
  }
  return env.data;
}
