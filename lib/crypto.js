import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  createHmac,
  timingSafeEqual,
} from 'crypto';
import { readFile, writeFile } from 'fs/promises';
import { basename } from 'path';
import argon2 from 'argon2';

// ─── Constants ───────────────────────────────────────────────────────
const ALGORITHM = 'aes-256-gcm';         // AES-256 in GCM mode (AEAD)
const IV_LENGTH = 12;                     // 96-bit IV (NIST recommended for GCM)
const SALT_LENGTH = 32;                   // 256-bit salt
const TAG_LENGTH = 16;                    // 128-bit GCM auth tag
const KEY_LENGTH = 32;                    // 256-bit key
const HMAC_LENGTH = 32;                   // 256-bit HMAC-SHA256
const MAGIC = Buffer.from('ENCPING2');    // format identifier (shared by v2/v3)
const FORMAT_VERSION = 3;

// Argon2id parameters (OWASP recommended — memory-hard, GPU-resistant)
const ARGON2_OPTIONS = {
  type: argon2.argon2id,   // hybrid: side-channel + GPU resistance
  memoryCost: 65536,       // 64 MB memory
  timeCost: 4,             // 4 iterations
  parallelism: 2,          // 2 threads
  hashLength: KEY_LENGTH,  // 256-bit output
};

// ─── Key Derivation ──────────────────────────────────────────────────

/**
 * Derive a 256-bit encryption key using Argon2id.
 * This is the same KDF recommended by OWASP for password-based encryption.
 */
async function deriveKey(password, salt) {
  const hash = await argon2.hash(password, {
    ...ARGON2_OPTIONS,
    salt,
    raw: true, // return raw Buffer instead of encoded string
  });
  return hash;
}

/**
 * Derive a separate HMAC key from the same password + a different domain.
 * This ensures encrypt key and HMAC key are independent.
 */
async function deriveHmacKey(password, salt) {
  const hmacSalt = Buffer.concat([salt, Buffer.from('hmac-key-domain')]);
  return deriveKey(password, hmacSalt);
}

// ─── Encryption ──────────────────────────────────────────────────────

/**
 * Encrypt a file with AES-256-GCM + Argon2id KDF + HMAC integrity.
 *
 * File format (v3 — encrypted metadata):
 *   [8B  magic "ENCPING2"]
 *   [1B  format version = 3]
 *   [32B Argon2id salt]
 *   [12B beacon IV]
 *   [16B beacon GCM auth tag]
 *   [4B  encrypted beacon length]
 *   [NB  encrypted beacon JSON (includes originalFile)]
 *   [12B content IV]
 *   [16B content GCM auth tag]
 *   [**  content ciphertext]
 *   [32B HMAC-SHA256 over everything above]
 */
export async function encryptFile(inputPath, outputPath, password, beaconData) {
  const plaintext = await readFile(inputPath);
  const originalName = basename(inputPath);

  // Ensure originalFile is in beacon data
  beaconData.originalFile = beaconData.originalFile || originalName;

  // Generate cryptographic random values
  const salt = randomBytes(SALT_LENGTH);
  const beaconIv = randomBytes(IV_LENGTH);
  const contentIv = randomBytes(IV_LENGTH);

  // Derive keys using Argon2id
  const encKey = await deriveKey(password, salt);
  const hmacKey = await deriveHmacKey(password, salt);

  // Encrypt beacon JSON with AES-256-GCM
  const beaconJson = JSON.stringify(beaconData);
  const beaconPlain = Buffer.from(beaconJson, 'utf8');
  const beaconCipher = createCipheriv(ALGORITHM, encKey, beaconIv);
  const encryptedBeacon = Buffer.concat([beaconCipher.update(beaconPlain), beaconCipher.final()]);
  const beaconTag = beaconCipher.getAuthTag();

  // Encrypt file content with AES-256-GCM (different IV)
  const contentCipher = createCipheriv(ALGORITHM, encKey, contentIv);
  const encryptedContent = Buffer.concat([contentCipher.update(plaintext), contentCipher.final()]);
  const contentTag = contentCipher.getAuthTag();

  // Beacon length
  const beaconLenBuf = Buffer.alloc(4);
  beaconLenBuf.writeUInt32BE(encryptedBeacon.length);

  // Version byte
  const versionBuf = Buffer.alloc(1);
  versionBuf.writeUInt8(FORMAT_VERSION);

  // Assemble everything except HMAC
  const payload = Buffer.concat([
    MAGIC,
    versionBuf,
    salt,
    beaconIv,
    beaconTag,
    beaconLenBuf,
    encryptedBeacon,
    contentIv,
    contentTag,
    encryptedContent,
  ]);

  // Compute HMAC-SHA256 over the entire payload for tamper detection
  const hmac = createHmac('sha256', hmacKey).update(payload).digest();

  // Final output = payload + HMAC
  const output = Buffer.concat([payload, hmac]);

  await writeFile(outputPath, output);

  // Wipe keys from memory
  encKey.fill(0);
  hmacKey.fill(0);

  return {
    beaconId: beaconData.id,
    originalFile: originalName,
    outputFile: outputPath,
    encryptedSize: output.length,
  };
}

// ─── Decryption ──────────────────────────────────────────────────────

/**
 * Decrypt a file in memory, verify integrity, and return the result.
 * IMPORTANT: The decrypted content is held in memory only.
 * Call commitDecryption() to write it to disk after the ping succeeds.
 * If the ping fails (offline), call destroyDecryption() to wipe it.
 */
export async function decryptFile(inputPath, password) {
  const data = await readFile(inputPath);

  // ── Verify magic ──
  let offset = 0;
  const magic = data.subarray(offset, offset + 8);
  offset += 8;

  if (magic.equals(Buffer.from('ENCPING1'))) {
    throw new Error(
      'This file uses the v1 format. Please re-encrypt with the latest version.'
    );
  }
  if (!magic.equals(MAGIC)) {
    throw new Error('Invalid file format — not an encrypted file.');
  }

  // ── Version ──
  const version = data.readUInt8(offset);
  offset += 1;

  if (version === 2) return decryptV2(data, offset, password);
  if (version === 3) return decryptV3(data, offset, password);
  throw new Error(`Unsupported format version: ${version}`);
}

/** Decrypt v2 format (plaintext beacon, separate filename field) */
async function decryptV2(data, offset, password) {
  const storedHmac = data.subarray(data.length - HMAC_LENGTH);
  const payload = data.subarray(0, data.length - HMAC_LENGTH);

  const beaconLen = payload.readUInt32BE(offset); offset += 4;
  const beaconData = JSON.parse(payload.subarray(offset, offset + beaconLen).toString('utf8'));
  offset += beaconLen;

  const salt = payload.subarray(offset, offset + SALT_LENGTH); offset += SALT_LENGTH;
  const iv = payload.subarray(offset, offset + IV_LENGTH); offset += IV_LENGTH;
  const tag = payload.subarray(offset, offset + TAG_LENGTH); offset += TAG_LENGTH;

  const nameLen = payload.readUInt32BE(offset); offset += 4;
  const originalName = payload.subarray(offset, offset + nameLen).toString('utf8');
  offset += nameLen;

  const ciphertext = payload.subarray(offset);

  const encKey = await deriveKey(password, salt);
  const hmacKey = await deriveHmacKey(password, salt);

  const computedHmac = createHmac('sha256', hmacKey).update(payload).digest();
  if (!timingSafeEqual(computedHmac, storedHmac)) {
    encKey.fill(0); hmacKey.fill(0);
    throw new Error('HMAC verification failed — file has been tampered with or wrong password.');
  }

  const decipher = createDecipheriv(ALGORITHM, encKey, iv);
  decipher.setAuthTag(tag);

  let decrypted;
  try {
    decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    encKey.fill(0); hmacKey.fill(0);
    throw new Error('Decryption failed — wrong password or corrupted file.');
  }

  encKey.fill(0); hmacKey.fill(0);
  return makeHandle(beaconData, originalName, decrypted);
}

/** Decrypt v3 format (encrypted beacon, no separate filename) */
async function decryptV3(data, offset, password) {
  const storedHmac = data.subarray(data.length - HMAC_LENGTH);
  const payload = data.subarray(0, data.length - HMAC_LENGTH);

  // Salt comes first in v3 so we can derive keys before reading beacon
  const salt = payload.subarray(offset, offset + SALT_LENGTH); offset += SALT_LENGTH;

  const encKey = await deriveKey(password, salt);
  const hmacKey = await deriveHmacKey(password, salt);

  // Verify HMAC before any decryption
  const computedHmac = createHmac('sha256', hmacKey).update(payload).digest();
  if (!timingSafeEqual(computedHmac, storedHmac)) {
    encKey.fill(0); hmacKey.fill(0);
    throw new Error('HMAC verification failed — file has been tampered with or wrong password.');
  }

  // Decrypt beacon
  const beaconIv = payload.subarray(offset, offset + IV_LENGTH); offset += IV_LENGTH;
  const beaconTag = payload.subarray(offset, offset + TAG_LENGTH); offset += TAG_LENGTH;
  const beaconLen = payload.readUInt32BE(offset); offset += 4;
  const encryptedBeacon = payload.subarray(offset, offset + beaconLen); offset += beaconLen;

  let beaconData;
  try {
    const beaconDecipher = createDecipheriv(ALGORITHM, encKey, beaconIv);
    beaconDecipher.setAuthTag(beaconTag);
    const beaconPlain = Buffer.concat([beaconDecipher.update(encryptedBeacon), beaconDecipher.final()]);
    beaconData = JSON.parse(beaconPlain.toString('utf8'));
  } catch {
    encKey.fill(0); hmacKey.fill(0);
    throw new Error('Decryption failed — wrong password or corrupted file.');
  }

  // Decrypt content
  const contentIv = payload.subarray(offset, offset + IV_LENGTH); offset += IV_LENGTH;
  const contentTag = payload.subarray(offset, offset + TAG_LENGTH); offset += TAG_LENGTH;
  const ciphertext = payload.subarray(offset);

  let decrypted;
  try {
    const decipher = createDecipheriv(ALGORITHM, encKey, contentIv);
    decipher.setAuthTag(contentTag);
    decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    encKey.fill(0); hmacKey.fill(0);
    throw new Error('Decryption failed — wrong password or corrupted file.');
  }

  encKey.fill(0); hmacKey.fill(0);
  const originalName = beaconData.originalFile || 'decrypted';
  return makeHandle(beaconData, originalName, decrypted);
}

/** Build the decryption handle returned to callers */
function makeHandle(beaconData, originalName, decrypted) {
  return {
    beaconData,
    originalName,
    decryptedSize: decrypted.length,

    /** Write decrypted content to disk. Call only after ping succeeds. */
    async commitToDisk(outputPath) {
      const finalOutput = outputPath || originalName;
      await writeFile(finalOutput, decrypted);
      return finalOutput;
    },

    /** Wipe decrypted content from memory without ever writing to disk. */
    destroy() {
      decrypted.fill(0);
    },
  };
}

/**
 * Inspect encrypted file metadata.
 * v2: reads plaintext beacon (no password needed).
 * v3: requires password to decrypt beacon.
 */
export async function inspectFile(data, password = null) {
  const magic = data.subarray(0, 8).toString();
  if (magic !== 'ENCPING2' && magic !== 'ENCPING1') {
    throw new Error('Not a valid encrypted file');
  }

  let offset = 8;
  const version = magic === 'ENCPING2' ? data.readUInt8(offset) : 1;
  if (version >= 2) offset += 1;

  if (version <= 2) {
    // v1/v2: plaintext beacon
    const beaconLen = data.readUInt32BE(offset); offset += 4;
    const beacon = JSON.parse(data.subarray(offset, offset + beaconLen).toString('utf8'));
    return {
      format: `v${version}`, cipher: 'AES-256-GCM',
      kdf: version >= 2 ? 'Argon2id (64MB, 4 iter)' : 'SHA-256',
      integrity: version >= 2 ? 'HMAC-SHA256 + GCM' : 'GCM only',
      beaconId: beacon.id, originalFile: beacon.originalFile,
      linkedRepo: beacon.repo, encryptedAt: beacon.timestamp,
      canary: beacon.canary || false, canaryDomain: beacon.dnsCanaryHost || null,
      fileSize: data.length,
    };
  }

  // v3: encrypted beacon — password required
  if (!password) {
    return {
      format: 'v3', cipher: 'AES-256-GCM',
      kdf: 'Argon2id (64MB, 4 iter)', integrity: 'HMAC-SHA256 + GCM',
      encrypted: true, fileSize: data.length,
      message: 'Password required to view metadata',
    };
  }

  const salt = data.subarray(offset, offset + SALT_LENGTH); offset += SALT_LENGTH;
  const encKey = await deriveKey(password, salt);

  const beaconIv = data.subarray(offset, offset + IV_LENGTH); offset += IV_LENGTH;
  const beaconTag = data.subarray(offset, offset + TAG_LENGTH); offset += TAG_LENGTH;
  const beaconLen = data.readUInt32BE(offset); offset += 4;
  const encryptedBeacon = data.subarray(offset, offset + beaconLen);

  let beacon;
  try {
    const decipher = createDecipheriv(ALGORITHM, encKey, beaconIv);
    decipher.setAuthTag(beaconTag);
    const plain = Buffer.concat([decipher.update(encryptedBeacon), decipher.final()]);
    beacon = JSON.parse(plain.toString('utf8'));
  } catch {
    encKey.fill(0);
    throw new Error('Wrong password — cannot decrypt metadata');
  }

  encKey.fill(0);
  return {
    format: 'v3', cipher: 'AES-256-GCM',
    kdf: 'Argon2id (64MB, 4 iter)', integrity: 'HMAC-SHA256 + GCM',
    beaconId: beacon.id, originalFile: beacon.originalFile,
    linkedRepo: beacon.repo, encryptedAt: beacon.timestamp,
    canary: beacon.canary || false, canaryDomain: beacon.dnsCanaryHost || null,
    fileSize: data.length,
  };
}
