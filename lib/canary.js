import { createSocket } from 'dgram';
import { createServer } from 'http';
import { hostname, userInfo, platform, arch } from 'os';

/**
 * DNS Canary Server
 *
 * Runs two services:
 *   1. UDP DNS server (port 53) — catches DNS lookups for beacon subdomains
 *   2. HTTP server (configurable port) — catches tracking pixel requests as fallback
 *
 * When a beacon is detected, it sends a ping to GitHub.
 *
 * DNS flow:
 *   File opened → browser/app resolves {beacon-id}.{canary-domain} →
 *   DNS query hits this server → logged + GitHub ping
 *
 * HTTP flow (fallback):
 *   File opened in browser → <img> loads https://{canary-host}/b/{beacon-id} →
 *   HTTP request hits this server → logged + GitHub ping
 */

// ─── DNS Packet Parsing ─────────────────────────────────────────────

function parseDnsQuery(buf) {
  // Transaction ID
  const id = buf.readUInt16BE(0);

  // Skip flags (2 bytes), QDCOUNT (2 bytes)
  const qdcount = buf.readUInt16BE(4);
  if (qdcount === 0) return null;

  // Parse the question section (first question only)
  let offset = 12;
  const labels = [];
  while (offset < buf.length) {
    const len = buf[offset];
    if (len === 0) { offset++; break; }
    offset++;
    labels.push(buf.subarray(offset, offset + len).toString('ascii'));
    offset += len;
  }

  const qtype = buf.readUInt16BE(offset);
  const qclass = buf.readUInt16BE(offset + 2);

  return {
    id,
    name: labels.join('.'),
    labels,
    qtype,
    qclass,
  };
}

function buildDnsResponse(query, ip) {
  // Build a minimal DNS response pointing to our IP
  const nameParts = query.name.split('.');
  const nameBuffer = [];
  for (const part of nameParts) {
    nameBuffer.push(Buffer.from([part.length]));
    nameBuffer.push(Buffer.from(part, 'ascii'));
  }
  nameBuffer.push(Buffer.from([0])); // null terminator
  const nameBuf = Buffer.concat(nameBuffer);

  // Header
  const header = Buffer.alloc(12);
  header.writeUInt16BE(query.id, 0);       // Transaction ID
  header.writeUInt16BE(0x8180, 2);         // Flags: response, authoritative, no error
  header.writeUInt16BE(1, 4);              // QDCOUNT
  header.writeUInt16BE(1, 6);              // ANCOUNT
  header.writeUInt16BE(0, 8);              // NSCOUNT
  header.writeUInt16BE(0, 10);             // ARCOUNT

  // Question section (echo back)
  const question = Buffer.concat([
    nameBuf,
    Buffer.from([0, 1]),   // QTYPE A
    Buffer.from([0, 1]),   // QCLASS IN
  ]);

  // Answer section
  const ipParts = ip.split('.').map(Number);
  const answer = Buffer.concat([
    nameBuf,
    Buffer.from([0, 1]),               // TYPE A
    Buffer.from([0, 1]),               // CLASS IN
    Buffer.from([0, 0, 0, 60]),        // TTL 60 seconds
    Buffer.from([0, 4]),               // RDLENGTH
    Buffer.from(ipParts),              // RDATA (IP address)
  ]);

  return Buffer.concat([header, question, answer]);
}

// ─── Beacon Detection ────────────────────────────────────────────────

function extractBeaconId(name, canaryDomain) {
  // e.g. "a8f3e2.canary.example.com" → "a8f3e2"
  const suffix = `.${canaryDomain}`;
  if (name.endsWith(suffix)) {
    return name.slice(0, name.length - suffix.length);
  }
  // Also handle without trailing dot
  if (name.endsWith(suffix + '.')) {
    return name.slice(0, name.length - suffix.length - 1);
  }
  return null;
}

// ─── GitHub Ping (reuses logic from ping.js) ────────────────────────

async function sendGithubPing(beaconId, source, githubToken, githubRepo, remoteInfo) {
  if (!githubToken || !githubRepo) return;

  const title = `[Canary Ping] ${beaconId} — ${new Date().toISOString()}`;
  const body = [
    `## DNS Canary Triggered`,
    ``,
    `| Field | Value |`,
    `|-------|-------|`,
    `| **Beacon ID** | \`${beaconId}\` |`,
    `| **Source** | ${source} |`,
    `| **Remote IP** | ${remoteInfo.address || 'unknown'} |`,
    `| **Remote Port** | ${remoteInfo.port || 'unknown'} |`,
    `| **Server Host** | ${hostname()} |`,
    `| **Detected At** | ${new Date().toISOString()} |`,
    ``,
    `> This issue was automatically created by the **encrypt-ping canary server** ` +
    `when a DNS/HTTP canary was triggered — indicating the encrypted file was ` +
    `decrypted and opened.`,
  ].join('\n');

  try {
    const res = await fetch(`https://api.github.com/repos/${githubRepo}/issues`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${githubToken}`,
        Accept: 'application/vnd.github+json',
        'Content-Type': 'application/json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
      body: JSON.stringify({ title, body, labels: ['canary-ping'] }),
    });
    if (res.ok) {
      const issue = await res.json();
      console.log(`  [github] Issue created: ${issue.html_url}`);
    } else {
      console.error(`  [github] Failed (${res.status}): ${await res.text()}`);
    }
  } catch (err) {
    console.error(`  [github] Error: ${err.message}`);
  }
}

// ─── Servers ─────────────────────────────────────────────────────────

/**
 * Start the canary server (DNS + HTTP).
 */
export function startCanaryServer(config) {
  const {
    canaryDomain,
    responseIp = '127.0.0.1',
    dnsPort = 53,
    httpPort = 8053,
    githubToken,
    githubRepo,
    onBeacon,
  } = config;

  const seen = new Set(); // deduplicate rapid repeats

  function handleBeacon(beaconId, source, remoteInfo) {
    const key = `${beaconId}-${source}-${remoteInfo.address}`;
    const now = Date.now();

    // Deduplicate: ignore same beacon from same IP within 60 seconds
    if (seen.has(key)) return;
    seen.add(key);
    setTimeout(() => seen.delete(key), 60_000);

    console.log(`\n  [CANARY HIT] Beacon: ${beaconId}`);
    console.log(`    Source:    ${source}`);
    console.log(`    Remote:    ${remoteInfo.address}:${remoteInfo.port}`);
    console.log(`    Time:      ${new Date().toISOString()}`);

    sendGithubPing(beaconId, source, githubToken, githubRepo, remoteInfo);

    if (onBeacon) {
      onBeacon({ beaconId, source, remoteIp: remoteInfo.address, remotePort: remoteInfo.port, time: new Date().toISOString() });
    }
  }

  // ── DNS Server ──
  const dns = createSocket('udp4');

  dns.on('message', (msg, rinfo) => {
    const query = parseDnsQuery(msg);
    if (!query) return;

    const beaconId = extractBeaconId(query.name, canaryDomain);
    if (beaconId) {
      handleBeacon(beaconId, `DNS lookup: ${query.name}`, rinfo);
    }

    // Always respond (so the lookup completes and triggers the canary)
    const response = buildDnsResponse(query, responseIp);
    dns.send(response, rinfo.port, rinfo.address);
  });

  dns.on('error', (err) => {
    if (err.code === 'EACCES') {
      console.error(`[dns] Port ${dnsPort} requires admin/root. Try: sudo or use --dns-port 5353`);
    } else {
      console.error(`[dns] Error: ${err.message}`);
    }
  });

  dns.bind(dnsPort, () => {
    console.log(`[dns] Canary DNS server listening on UDP :${dnsPort}`);
    console.log(`[dns] Watching for *.${canaryDomain}`);
  });

  // ── HTTP Server (fallback tracking pixel) ──
  const PIXEL = Buffer.from(
    'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7',
    'base64'
  ); // 1x1 transparent GIF

  const http = createServer((req, res) => {
    // CORS headers so it works from any origin
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cache-Control', 'no-store');

    // Route: /b/{beaconId}
    const match = req.url?.match(/^\/b\/([a-zA-Z0-9_-]+)/);
    if (match) {
      const beaconId = match[1];
      const remoteInfo = {
        address: req.socket.remoteAddress,
        port: req.socket.remotePort,
      };
      handleBeacon(beaconId, `HTTP pixel: ${req.url}`, remoteInfo);

      res.writeHead(200, { 'Content-Type': 'image/gif', 'Content-Length': PIXEL.length });
      res.end(PIXEL);
      return;
    }

    // Health check
    if (req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('canary-server ok');
      return;
    }

    res.writeHead(404);
    res.end();
  });

  http.listen(httpPort, () => {
    console.log(`[http] Canary HTTP server listening on :${httpPort}`);
    console.log(`[http] Tracking pixel at http://YOUR_IP:${httpPort}/b/{beaconId}`);
  });

  return { dns, http };
}
