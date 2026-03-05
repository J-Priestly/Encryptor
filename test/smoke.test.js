import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, readFile, unlink, mkdir, rm } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';
import { randomUUID } from 'crypto';
import { encryptFile, decryptFile, inspectFile } from '../lib/crypto.js';

const TMP = join(tmpdir(), `encryptor-test-${randomUUID()}`);
const INPUT = join(TMP, 'test.txt');
const ENCRYPTED = join(TMP, 'test.txt.enc');
const PASSWORD = 'test-password-123';
const CONTENT = 'Hello, this is a test file for encryption.';

await mkdir(TMP, { recursive: true });
await writeFile(INPUT, CONTENT);

const beacon = { id: randomUUID(), originalFile: 'test.txt', repo: 'test/repo', timestamp: new Date().toISOString(), canary: false };

describe('encryptor', () => {
  after(async () => {
    await rm(TMP, { recursive: true, force: true }).catch(() => {});
  });

  it('encrypts a file', async () => {
    const result = await encryptFile(INPUT, ENCRYPTED, PASSWORD, beacon);
    assert.ok(result.beaconId, 'should return beacon ID');
    assert.ok(result.encryptedSize > 0, 'encrypted size should be positive');
  });

  it('produces a valid v3 file', async () => {
    const data = await readFile(ENCRYPTED);
    assert.equal(data.subarray(0, 8).toString(), 'ENCPING2');
    assert.equal(data.readUInt8(8), 3, 'format version should be 3');
  });

  it('decrypts back to original content', async () => {
    const handle = await decryptFile(ENCRYPTED, PASSWORD);
    const output = join(TMP, 'decrypted.txt');
    await handle.commitToDisk(output);
    const result = await readFile(output, 'utf8');
    assert.equal(result, CONTENT);
    await unlink(output).catch(() => {});
  });

  it('rejects wrong password on decrypt', async () => {
    await assert.rejects(
      () => decryptFile(ENCRYPTED, 'wrong-password'),
      { message: /HMAC verification failed|wrong password/i }
    );
  });

  it('inspect without password returns encrypted flag', async () => {
    const data = await readFile(ENCRYPTED);
    const info = await inspectFile(data);
    assert.equal(info.format, 'v3');
    assert.equal(info.encrypted, true);
    assert.ok(info.fileSize > 0);
  });

  it('inspect with password returns full metadata', async () => {
    const data = await readFile(ENCRYPTED);
    const info = await inspectFile(data, PASSWORD);
    assert.equal(info.format, 'v3');
    assert.equal(info.originalFile, 'test.txt');
    assert.ok(info.beaconId);
    assert.equal(info.linkedRepo, 'test/repo');
  });

  it('inspect rejects wrong password', async () => {
    const data = await readFile(ENCRYPTED);
    await assert.rejects(
      () => inspectFile(data, 'wrong'),
      { message: /wrong password/i }
    );
  });
});
