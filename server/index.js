import { createServer } from 'http';
import { readFile, writeFile, unlink, mkdir, rm } from 'fs/promises';
import { resolve, dirname, join, extname } from 'path';
import { fileURLToPath } from 'url';
import { tmpdir } from 'os';
import { randomUUID } from 'crypto';
import { collectBody, parseMultipart } from './multipart.js';
import { encryptFile, decryptFile, inspectFile } from '../lib/crypto.js';
import { sendPing } from '../lib/ping.js';
import { wrapFileWithCanary } from '../lib/wrapper.js';
import { startCanaryServer } from '../lib/canary.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, '..', 'public');

// ─── State ───────────────────────────────────────────────────────────
let canaryInstance = null;
let canaryHitCount = 0;
let canaryConfig = {};
const sseClients = new Set();

function broadcastCanaryHit(data) {
  canaryHitCount++;
  const msg = `data: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) client.write(msg);
}

// ─── Helpers ─────────────────────────────────────────────────────────
function tempPath(ext = '') { return join(tmpdir(), `ep-${randomUUID()}${ext}`); }

async function cleanup(...paths) {
  for (const p of paths) if (p) await unlink(p).catch(() => {});
}

function json(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function error(res, status, message) { json(res, status, { error: message }); }

async function jsonBody(req) {
  return JSON.parse((await collectBody(req)).toString('utf8'));
}

// ─── Settings ────────────────────────────────────────────────────────
const ENV_PATH = resolve(process.cwd(), '.env');
const KEYS = ['GITHUB_TOKEN', 'GITHUB_REPO', 'PING_MODE', 'CANARY_DOMAIN', 'CANARY_HTTP_URL', 'FEATURE_GITHUB', 'FEATURE_CANARY'];

async function readSettings() {
  const text = await readFile(ENV_PATH, 'utf8').catch(() => '');
  const s = {};
  for (const line of text.split('\n')) {
    const m = line.match(/^([A-Z_]+)=(.*)$/);
    if (m) s[m[1]] = m[2];
  }
  return s;
}

async function writeSettings(settings) {
  const lines = KEYS.filter(k => settings[k] !== undefined && settings[k] !== '').map(k => `${k}=${settings[k]}`);
  await writeFile(ENV_PATH, lines.join('\n') + '\n');
  for (const k of KEYS) if (settings[k] !== undefined) process.env[k] = settings[k];
}

// ─── Feature Flags ──────────────────────────────────────────────────
function featureEnabled(name) {
  const val = process.env[`FEATURE_${name.toUpperCase()}`];
  return val === undefined || val === '' || val === 'true';  // enabled by default
}

// ─── Static Serving ──────────────────────────────────────────────────
const MIME = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };

async function serveStatic(res, filePath) {
  try {
    const data = await readFile(filePath);
    res.writeHead(200, { 'Content-Type': MIME[extname(filePath)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    res.end(data);
  } catch {
    res.writeHead(404);
    res.end('Not found');
  }
}

// ─── Route: Encrypt ──────────────────────────────────────────────────
async function handleEncrypt(req, res) {
  const body = await collectBody(req);
  const { fields, files } = parseMultipart(req.headers['content-type'], body);
  if (!files.file) return error(res, 400, 'No file uploaded');
  if (!fields.password) return error(res, 400, 'Password required');

  const tempDir = join(tmpdir(), `ep-${randomUUID()}`);
  await mkdir(tempDir, { recursive: true });
  const inputPath = join(tempDir, files.file.filename);
  const beaconId = randomUUID();
  let fileToEncrypt = inputPath;
  let tempCanaryPath = null;

  try {
    await writeFile(inputPath, files.file.data);

    if (fields.canary === 'true' && featureEnabled('canary')) {
      const domain = fields.canaryDomain || process.env.CANARY_DOMAIN;
      const httpUrl = fields.canaryHttpUrl || process.env.CANARY_HTTP_URL;
      if (!domain) return error(res, 400, 'Canary domain required');
      const wrapped = await wrapFileWithCanary(inputPath, beaconId, { canaryDomain: domain, canaryHttpUrl: httpUrl });
      tempCanaryPath = inputPath + '.canary.html';
      await writeFile(tempCanaryPath, wrapped.html);
      fileToEncrypt = tempCanaryPath;
    }

    const outputPath = tempPath('.enc');
    const beaconData = { id: beaconId, originalFile: files.file.filename, repo: process.env.GITHUB_REPO || 'not-configured', timestamp: new Date().toISOString(), canary: fields.canary === 'true' };
    await encryptFile(fileToEncrypt, outputPath, fields.password, beaconData);
    const encrypted = await readFile(outputPath);

    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${files.file.filename}.enc"`,
      'X-Beacon-Id': beaconId,
      'X-Original-File': files.file.filename,
      'X-Encrypted-Size': String(encrypted.length),
      'Access-Control-Expose-Headers': 'X-Beacon-Id, X-Original-File, X-Encrypted-Size',
    });
    res.end(encrypted);
    await cleanup(inputPath, outputPath, tempCanaryPath);
    await rm(tempDir, { recursive: true, force: true }).catch(() => {});
  } catch (err) {
    await cleanup(inputPath, tempCanaryPath);
    await rm(tempDir, { recursive: true, force: true }).catch(() => {});
    error(res, 500, err.message);
  }
}

// ─── Route: Decrypt ──────────────────────────────────────────────────
async function handleDecrypt(req, res) {
  const body = await collectBody(req);
  const { fields, files } = parseMultipart(req.headers['content-type'], body);
  if (!files.file) return error(res, 400, 'No file uploaded');
  if (!fields.password) return error(res, 400, 'Password required');

  const inputPath = tempPath('.enc');
  let handle = null;

  try {
    await writeFile(inputPath, files.file.data);
    handle = await decryptFile(inputPath, fields.password);

    let pingStatus = 'skipped';
    if (fields.ping !== 'false' && featureEnabled('github')) {
      try {
        await sendPing(handle.beaconData, { githubToken: process.env.GITHUB_TOKEN, githubRepo: process.env.GITHUB_REPO, pingMode: process.env.PING_MODE || 'issue' });
        pingStatus = 'sent';
      } catch (pingErr) {
        if (fields.allowOffline !== 'true') {
          handle.destroy();
          await cleanup(inputPath);
          return error(res, 403, `Kill switch: ${pingErr.message}`);
        }
        pingStatus = 'failed';
      }
    }

    const outputPath = tempPath();
    await handle.commitToDisk(outputPath);
    const decrypted = await readFile(outputPath);
    const originalName = handle.beaconData.originalFile || handle.originalName;

    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${originalName}"`,
      'X-Beacon-Id': handle.beaconData.id,
      'X-Ping-Status': pingStatus,
      'X-Original-Name': originalName,
      'Access-Control-Expose-Headers': 'X-Beacon-Id, X-Ping-Status, X-Original-Name',
    });
    res.end(decrypted);
    await cleanup(inputPath, outputPath);
  } catch (err) {
    if (handle) handle.destroy();
    await cleanup(inputPath);
    error(res, 400, err.message);
  }
}

// ─── Route: Inspect ──────────────────────────────────────────────────
async function handleInspect(req, res) {
  const body = await collectBody(req);
  const { fields, files } = parseMultipart(req.headers['content-type'], body);
  if (!files.file) return error(res, 400, 'No file uploaded');

  try {
    const info = await inspectFile(files.file.data, fields.password || null);
    json(res, 200, info);
  } catch (err) {
    error(res, 400, err.message);
  }
}

// ─── Router ──────────────────────────────────────────────────────────
async function handleRequest(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const path = url.pathname;

  try {
    // Static
    if (req.method === 'GET') {
      if (path === '/' || path === '/index.html') return serveStatic(res, join(PUBLIC_DIR, 'index.html'));
      if (path.startsWith('/css/') || path.startsWith('/js/')) return serveStatic(res, join(PUBLIC_DIR, path.slice(1)));
    }

    // API
    if (req.method === 'POST' && path === '/api/encrypt') return handleEncrypt(req, res);
    if (req.method === 'POST' && path === '/api/decrypt') return handleDecrypt(req, res);
    if (req.method === 'POST' && path === '/api/inspect') return handleInspect(req, res);

    if (req.method === 'POST' && path === '/api/canary/start') {
      if (!featureEnabled('canary')) return error(res, 403, 'Canary feature is disabled');
      if (canaryInstance) return error(res, 409, 'Canary server already running');
      const cfg = await jsonBody(req);
      const domain = cfg.domain || process.env.CANARY_DOMAIN;
      if (!domain) return error(res, 400, 'Canary domain required');
      const dnsPort = cfg.dnsPort || 5353;
      const httpPort = cfg.httpPort || 8054;
      canaryHitCount = 0;
      canaryConfig = { dnsPort, httpPort, domain };
      canaryInstance = startCanaryServer({ canaryDomain: domain, responseIp: cfg.responseIp || '127.0.0.1', dnsPort, httpPort, githubToken: process.env.GITHUB_TOKEN, githubRepo: process.env.GITHUB_REPO, onBeacon: broadcastCanaryHit });
      return json(res, 200, { status: 'running', dnsPort, httpPort, domain });
    }

    if (req.method === 'POST' && path === '/api/canary/stop') {
      if (!canaryInstance) return error(res, 409, 'Not running');
      canaryInstance.dns.close(); canaryInstance.http.close(); canaryInstance = null;
      return json(res, 200, { status: 'stopped' });
    }

    if (req.method === 'GET' && path === '/api/canary/status')
      return json(res, 200, { running: !!canaryInstance, hitCount: canaryHitCount, ...canaryConfig });

    if (req.method === 'GET' && path === '/api/canary/events') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
      res.write(':\n\n');
      sseClients.add(res);
      req.on('close', () => sseClients.delete(res));
      return;
    }

    if (req.method === 'GET' && path === '/api/settings') {
      const s = await readSettings();
      return json(res, 200, {
        githubToken: s.GITHUB_TOKEN ? '****' + s.GITHUB_TOKEN.slice(-4) : '',
        githubRepo: s.GITHUB_REPO || '', pingMode: s.PING_MODE || 'issue',
        canaryDomain: s.CANARY_DOMAIN || '', canaryHttpUrl: s.CANARY_HTTP_URL || '',
        featureGithub: s.FEATURE_GITHUB !== 'false',
        featureCanary: s.FEATURE_CANARY !== 'false',
      });
    }

    if (req.method === 'PUT' && path === '/api/settings') {
      const d = await jsonBody(req);
      const cur = await readSettings();
      const u = { ...cur };
      if (d.githubToken && !d.githubToken.startsWith('****')) u.GITHUB_TOKEN = d.githubToken;
      if (d.githubRepo !== undefined) u.GITHUB_REPO = d.githubRepo;
      if (d.pingMode !== undefined) u.PING_MODE = d.pingMode;
      if (d.canaryDomain !== undefined) u.CANARY_DOMAIN = d.canaryDomain;
      if (d.canaryHttpUrl !== undefined) u.CANARY_HTTP_URL = d.canaryHttpUrl;
      if (d.featureGithub !== undefined) u.FEATURE_GITHUB = String(d.featureGithub);
      if (d.featureCanary !== undefined) u.FEATURE_CANARY = String(d.featureCanary);
      await writeSettings(u);
      return json(res, 200, { saved: true });
    }

    res.writeHead(404); res.end('Not found');
  } catch (err) {
    console.error(`[server] ${err.message}`);
    error(res, 500, err.message);
  }
}

export function startWebServer(port = 3000) {
  const server = createServer(handleRequest);
  server.listen(port, '127.0.0.1', () => {
    console.log(`\n  encryptor dashboard → http://localhost:${port}\n`);
  });
  return server;
}
