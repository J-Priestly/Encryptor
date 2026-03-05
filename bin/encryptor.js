#!/usr/bin/env node
import { program } from 'commander';
import { randomUUID } from 'crypto';
import { resolve } from 'path';
import { config } from 'dotenv';
import { writeFile } from 'fs/promises';
import { encryptFile, decryptFile, inspectFile } from '../lib/crypto.js';
import { sendPing } from '../lib/ping.js';
import { wrapFileWithCanary } from '../lib/wrapper.js';
import { startCanaryServer } from '../lib/canary.js';

config();

function ghConfig() {
  return { githubToken: process.env.GITHUB_TOKEN, githubRepo: process.env.GITHUB_REPO, pingMode: process.env.PING_MODE || 'issue' };
}

program.name('encryptor').description('File encryption with tracking beacons and decryption notifications').version('2.0.0');

// ─── Encrypt ─────────────────────────────────────────────────────────
program.command('encrypt').description('Encrypt a file and embed a tracking beacon')
  .argument('<file>', 'File to encrypt')
  .option('-o, --output <path>', 'Output path')
  .option('-p, --password <password>', 'Encryption password')
  .option('--beacon-id <id>', 'Custom beacon ID')
  .option('--canary', 'Wrap file in HTML with DNS canary')
  .option('--canary-domain <domain>', 'DNS canary domain')
  .option('--canary-http <url>', 'HTTP canary server URL')
  .action(async (file, opts) => {
    const inputPath = resolve(file);
    const password = opts.password || process.env.ENCRYPT_PASSWORD;
    if (!password) { console.error('Error: Password required (-p or ENCRYPT_PASSWORD)'); process.exit(1); }

    const gh = ghConfig();
    const beaconId = opts.beaconId || randomUUID();
    const beaconData = { id: beaconId, originalFile: file, repo: gh.githubRepo || 'not-configured', timestamp: new Date().toISOString(), canary: !!opts.canary };

    try {
      let fileToEncrypt = inputPath;
      let canaryInfo = null;

      if (opts.canary) {
        const domain = opts.canaryDomain || process.env.CANARY_DOMAIN;
        if (!domain) { console.error('Error: --canary requires --canary-domain or CANARY_DOMAIN'); process.exit(1); }
        const wrapped = await wrapFileWithCanary(inputPath, beaconId, { canaryDomain: domain, canaryHttpUrl: opts.canaryHttp || process.env.CANARY_HTTP_URL });
        const tempPath = inputPath + '.canary.html';
        await writeFile(tempPath, wrapped.html);
        fileToEncrypt = tempPath;
        canaryInfo = wrapped;
        beaconData.canaryDomain = domain;
        beaconData.dnsCanaryHost = wrapped.dnsCanaryHost;
      }

      const outputPath = opts.output ? resolve(opts.output) : `${inputPath}.enc`;
      const result = await encryptFile(fileToEncrypt, outputPath, password, beaconData);

      if (canaryInfo) { const { unlink } = await import('fs/promises'); await unlink(fileToEncrypt).catch(() => {}); }

      console.log('\n  Encryption Complete');
      console.log(`  Beacon ID:  ${result.beaconId}`);
      console.log(`  Output:     ${result.outputFile}`);
      console.log(`  Size:       ${result.encryptedSize} bytes`);
      console.log(`  Algorithm:  AES-256-GCM + Argon2id KDF`);
      if (canaryInfo) console.log(`  Canary:     ${canaryInfo.dnsCanaryHost}`);
      console.log('');
    } catch (err) { console.error(`Error: ${err.message}`); process.exit(1); }
  });

// ─── Decrypt ─────────────────────────────────────────────────────────
program.command('decrypt').description('Decrypt a file and send a ping to GitHub')
  .argument('<file>', 'Encrypted file')
  .option('-o, --output <path>', 'Output path')
  .option('-p, --password <password>', 'Password')
  .option('--no-ping', 'Skip GitHub ping')
  .option('--allow-offline', 'Allow decryption if ping fails')
  .action(async (file, opts) => {
    const inputPath = resolve(file);
    const password = opts.password || process.env.ENCRYPT_PASSWORD;
    if (!password) { console.error('Error: Password required'); process.exit(1); }
    const killSwitch = opts.ping !== false && !opts.allowOffline;

    let handle;
    try {
      handle = await decryptFile(inputPath, password);
      console.log(`\n  Beacon: ${handle.beaconData.id}  |  ${handle.decryptedSize} bytes`);

      if (opts.ping !== false) {
        console.log('  Sending ping...');
        try { await sendPing(handle.beaconData, ghConfig()); console.log('  Ping sent.'); }
        catch (e) {
          if (killSwitch) { console.error(`\n  KILL SWITCH — ${e.message}\n  Content destroyed.`); handle.destroy(); process.exit(1); }
          console.error(`  Ping failed: ${e.message}`);
        }
      }

      const out = await handle.commitToDisk(opts.output ? resolve(opts.output) : null);
      console.log(`  Output: ${out}\n`);
    } catch (err) { if (handle) handle.destroy(); console.error(`Error: ${err.message}`); process.exit(1); }
  });

// ─── Inspect ─────────────────────────────────────────────────────────
program.command('inspect').description('Inspect encrypted file metadata')
  .argument('<file>')
  .option('-p, --password <password>', 'Password (required for v3 files)')
  .action(async (file, opts) => {
    const { readFile } = await import('fs/promises');
    const data = await readFile(resolve(file));

    try {
      const info = await inspectFile(data, opts.password || null);
      if (info.encrypted && !opts.password) {
        console.log(`\n  Format:     v3  |  AES-256-GCM  |  Argon2id`);
        console.log(`  Metadata:   Encrypted (password required with -p)`);
        console.log(`  Size:       ${data.length} bytes\n`);
        return;
      }
      console.log(`\n  Format:     ${info.format}  |  ${info.cipher}  |  ${info.kdf}`);
      console.log(`  Beacon:     ${info.beaconId}`);
      console.log(`  File:       ${info.originalFile}`);
      console.log(`  Repo:       ${info.linkedRepo}`);
      console.log(`  Encrypted:  ${info.encryptedAt}`);
      if (info.canary) console.log(`  Canary:     ${info.canaryDomain || 'Enabled'}`);
      console.log(`  Size:       ${info.fileSize} bytes\n`);
    } catch (err) { console.error(`Error: ${err.message}`); process.exit(1); }
  });

// ─── Serve (canary) ──────────────────────────────────────────────────
program.command('serve').description('Start DNS + HTTP canary server')
  .option('--dns-port <port>', 'DNS port', '53')
  .option('--http-port <port>', 'HTTP port', '8053')
  .option('--domain <domain>', 'Canary domain')
  .option('--response-ip <ip>', 'Response IP', '127.0.0.1')
  .action((opts) => {
    const domain = opts.domain || process.env.CANARY_DOMAIN;
    if (!domain) { console.error('Error: --domain or CANARY_DOMAIN required'); process.exit(1); }
    startCanaryServer({ canaryDomain: domain, responseIp: opts.responseIp, dnsPort: parseInt(opts.dnsPort), httpPort: parseInt(opts.httpPort), githubToken: process.env.GITHUB_TOKEN, githubRepo: process.env.GITHUB_REPO });
  });

// ─── Web UI ──────────────────────────────────────────────────────────
program.command('web').description('Start the web dashboard')
  .option('--port <port>', 'HTTP port', '3000')
  .action(async (opts) => {
    const { startWebServer } = await import('../server/index.js');
    startWebServer(parseInt(opts.port));
  });

program.parse();
