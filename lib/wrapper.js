import { readFile } from 'fs/promises';
import { basename, extname } from 'path';

/**
 * Wrap a file in an HTML canary container.
 *
 * The HTML page includes multiple canary triggers:
 *   1. DNS canary — resolves a unique subdomain via <link> prefetch
 *   2. HTTP pixel — loads a 1x1 tracking pixel from the canary HTTP server
 *   3. Fetch beacon — sends a navigator.sendBeacon() call
 *
 * The original file is embedded as a base64 data blob and auto-downloaded
 * when the HTML is opened. The user sees their file; the canary fires silently.
 *
 * This works regardless of what tool decrypted the .enc file — as long as
 * the person opens the resulting HTML in any browser.
 */
export async function wrapFileWithCanary(filePath, beaconId, canaryConfig) {
  const {
    canaryDomain,        // e.g. "canary.example.com"
    canaryHttpUrl,       // e.g. "http://YOUR_SERVER:8053"
  } = canaryConfig;

  const fileData = await readFile(filePath);
  const fileName = basename(filePath);
  const ext = extname(fileName).toLowerCase();
  const base64Data = fileData.toString('base64');
  const mimeType = getMimeType(ext);

  // Build canary triggers
  const dnsCanaryHost = `${beaconId}.${canaryDomain}`;
  const httpPixelUrl = canaryHttpUrl
    ? `${canaryHttpUrl.replace(/\/$/, '')}/b/${beaconId}`
    : null;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(fileName)}</title>

<!-- DNS canary: forces DNS resolution of the beacon subdomain -->
<link rel="dns-prefetch" href="//${dnsCanaryHost}">
<link rel="preconnect" href="//${dnsCanaryHost}">

<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #0a0a0a; color: #e0e0e0;
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh; padding: 2rem;
  }
  .container {
    background: #1a1a1a; border-radius: 12px; padding: 2.5rem;
    max-width: 500px; width: 100%; text-align: center;
    box-shadow: 0 4px 24px rgba(0,0,0,0.5);
  }
  h1 { font-size: 1.3rem; margin-bottom: 0.5rem; color: #fff; }
  p { font-size: 0.9rem; color: #888; margin-bottom: 1.5rem; }
  .btn {
    display: inline-block; padding: 0.75rem 2rem;
    background: #2563eb; color: #fff; border: none; border-radius: 8px;
    font-size: 1rem; cursor: pointer; text-decoration: none;
    transition: background 0.2s;
  }
  .btn:hover { background: #1d4ed8; }
  .info { font-size: 0.75rem; color: #555; margin-top: 1.5rem; }
</style>
</head>
<body>

<div class="container">
  <h1>${escapeHtml(fileName)}</h1>
  <p>Your file is ready. Click below to save it.</p>
  <a id="dl" class="btn">Save File</a>
  <div class="info">Secured with encrypt-ping</div>
</div>

${httpPixelUrl ? `<!-- HTTP canary pixel -->\n<img src="${escapeHtml(httpPixelUrl)}" width="1" height="1" style="position:absolute;left:-9999px" alt="">` : ''}

<script>
(function(){
  // Canary triggers (run immediately when HTML is opened)

  // 1. DNS canary — fetch forces DNS resolution even if prefetch is blocked
  try { fetch('//' + ${JSON.stringify(dnsCanaryHost)} + '/ping', {mode:'no-cors'}).catch(function(){}); } catch(e){}

  // 2. HTTP canary — sendBeacon as backup
  ${httpPixelUrl ? `try { navigator.sendBeacon(${JSON.stringify(httpPixelUrl)}); } catch(e){}` : ''}

  // 3. Auto-download the original file
  var data = ${JSON.stringify(base64Data)};
  var mime = ${JSON.stringify(mimeType)};
  var name = ${JSON.stringify(fileName)};

  function b64toBlob(b64, type) {
    var bin = atob(b64);
    var arr = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return new Blob([arr], {type: type});
  }

  var blob = b64toBlob(data, mime);
  var url = URL.createObjectURL(blob);

  var link = document.getElementById('dl');
  link.href = url;
  link.download = name;
})();
</script>

</body>
</html>`;

  return {
    html,
    wrappedFileName: fileName + '.html',
    originalFileName: fileName,
    beaconId,
    dnsCanaryHost,
    httpPixelUrl,
  };
}

function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function getMimeType(ext) {
  const types = {
    '.txt': 'text/plain',
    '.pdf': 'application/pdf',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.mp4': 'video/mp4',
    '.mp3': 'audio/mpeg',
    '.zip': 'application/zip',
    '.doc': 'application/msword',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.xls': 'application/vnd.ms-excel',
    '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    '.ppt': 'application/vnd.ms-powerpoint',
    '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    '.json': 'application/json',
    '.xml': 'application/xml',
    '.csv': 'text/csv',
    '.html': 'text/html',
    '.js': 'text/javascript',
    '.css': 'text/css',
  };
  return types[ext] || 'application/octet-stream';
}
