/* ─── Feature State ───────────────────────────────────────────────── */
const features = { github: true, canary: true };

function applyFeatureState() {
  // Sidebar: show/hide canary nav
  const canaryNav = document.querySelector('[data-page="canary"]');
  if (canaryNav) canaryNav.style.display = features.canary ? '' : 'none';

  // Encrypt page: show/hide canary toggle
  const encCanaryRow = document.getElementById('enc-canary-row');
  if (encCanaryRow) encCanaryRow.style.display = features.canary ? '' : 'none';
  if (!features.canary) { const cb = document.getElementById('enc-canary'); if (cb) cb.checked = false; }

  // Decrypt page: show/hide GitHub ping toggles
  const decPingRow = document.getElementById('dec-ping-row');
  const decOfflineRow = document.getElementById('dec-offline-row');
  if (decPingRow) decPingRow.style.display = features.github ? '' : 'none';
  if (decOfflineRow) decOfflineRow.style.display = features.github ? '' : 'none';
  if (!features.github) { const cb = document.getElementById('dec-ping'); if (cb) cb.checked = false; }

  // Settings page: dim cards when feature is off
  const ghCard = document.getElementById('settings-github-card');
  const canaryCard = document.getElementById('settings-canary-card');
  if (ghCard) ghCard.style.opacity = features.github ? '1' : '0.4';
  if (canaryCard) canaryCard.style.opacity = features.canary ? '1' : '0.4';

  // If on canary page and feature just got disabled, redirect
  if (!features.canary && location.hash === '#canary') {
    location.hash = '#encrypt';
  }
}

/* ─── Router ──────────────────────────────────────────────────────── */
function navigate(page) {
  // Block navigation to canary page if feature is disabled
  if (page === 'canary' && !features.canary) page = 'encrypt';

  document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));
  document.querySelectorAll('.nav-link').forEach(n => n.classList.remove('active'));
  const el = document.getElementById('page-' + page);
  if (el) el.classList.remove('hidden');
  const nav = document.querySelector(`[data-page="${page}"]`);
  if (nav) nav.classList.add('active');
  applyFeatureState();
}
window.addEventListener('hashchange', () => navigate(location.hash.slice(1) || 'encrypt'));
navigate(location.hash.slice(1) || 'encrypt');

/* ─── Utilities ───────────────────────────────────────────────────── */
const $ = id => document.getElementById(id);
const files = {};

function formatSize(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  return (b / 1048576).toFixed(1) + ' MB';
}

function setLoading(btn, on) {
  btn.classList.toggle('loading', on);
  if (on) btn.disabled = true;
}

function showToast(id, html) {
  const el = $(id);
  el.hidden = false;
  const body = el.querySelector('.toast-body');
  if (body && html) body.innerHTML = html;
}

function showError(id, msg) {
  const el = $(id);
  el.hidden = false;
  el.querySelector('.toast-body').textContent = msg;
}

function hideEl(...ids) { ids.forEach(id => $(id).hidden = true); }

function download(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement('a'), { href: url, download: name });
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

/* ─── Drop Zone ───────────────────────────────────────────────────── */
function setupDrop(zoneId, infoId, key, onFile) {
  const zone = $(zoneId), info = $(infoId), input = zone.querySelector('input[type="file"]');

  function handle(file) {
    files[key] = file;
    info.textContent = `${file.name}  (${formatSize(file.size)})`;
    zone.classList.add('has-file');
    if (onFile) onFile(file);
  }

  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => { e.preventDefault(); zone.classList.remove('drag-over'); if (e.dataTransfer.files[0]) handle(e.dataTransfer.files[0]); });
  zone.addEventListener('click', () => input.click());
  input.addEventListener('change', () => { if (input.files[0]) handle(input.files[0]); });
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  ENCRYPT                                                           */
/* ═══════════════════════════════════════════════════════════════════ */
setupDrop('encrypt-drop', 'encrypt-file-info', 'encrypt', () => updateEncBtn());

const encPass = $('enc-password'), encBtn = $('encrypt-btn');
encPass.addEventListener('input', updateEncBtn);
function updateEncBtn() { encBtn.disabled = !files.encrypt || !encPass.value; }

encBtn.addEventListener('click', async () => {
  hideEl('encrypt-result', 'encrypt-error');
  setLoading(encBtn, true);

  const fd = new FormData();
  fd.append('file', files.encrypt);
  fd.append('password', encPass.value);
  fd.append('canary', (features.canary && $('enc-canary').checked) ? 'true' : 'false');

  try {
    const res = await fetch('/api/encrypt', { method: 'POST', body: fd });
    if (!res.ok) throw new Error((await res.json()).error);

    const blob = await res.blob();
    const beaconId = res.headers.get('X-Beacon-Id');
    const origFile = res.headers.get('X-Original-File');
    const size = res.headers.get('X-Encrypted-Size');

    download(blob, origFile + '.enc');
    showToast('encrypt-result',
      `Beacon: ${beaconId}<br>File: ${origFile}<br>Size: ${formatSize(+size)}<br>Cipher: AES-256-GCM + Argon2id`
    );
  } catch (e) { showError('encrypt-error', e.message); }
  finally { setLoading(encBtn, false); updateEncBtn(); }
});

/* ═══════════════════════════════════════════════════════════════════ */
/*  DECRYPT                                                           */
/* ═══════════════════════════════════════════════════════════════════ */
setupDrop('decrypt-drop', 'decrypt-file-info', 'decrypt', () => updateDecBtn());

const decPass = $('dec-password'), decBtn = $('decrypt-btn');
decPass.addEventListener('input', updateDecBtn);
function updateDecBtn() { decBtn.disabled = !files.decrypt || !decPass.value; }

decBtn.addEventListener('click', async () => {
  hideEl('decrypt-result', 'decrypt-error');
  setLoading(decBtn, true);

  const fd = new FormData();
  fd.append('file', files.decrypt);
  fd.append('password', decPass.value);
  fd.append('ping', (features.github && $('dec-ping').checked) ? 'true' : 'false');
  fd.append('allowOffline', $('dec-allow-offline').checked ? 'true' : 'false');

  try {
    const res = await fetch('/api/decrypt', { method: 'POST', body: fd });
    if (!res.ok) throw new Error((await res.json()).error);

    const blob = await res.blob();
    const beaconId = res.headers.get('X-Beacon-Id');
    const pingStatus = res.headers.get('X-Ping-Status');
    const origName = res.headers.get('X-Original-Name');

    download(blob, origName || 'decrypted');
    const labels = { sent: 'Sent', skipped: 'Skipped', failed: 'Failed (offline)' };
    showToast('decrypt-result',
      `Beacon: ${beaconId}<br>File: ${origName}<br>Ping: ${labels[pingStatus] || pingStatus}`
    );
  } catch (e) { showError('decrypt-error', e.message); }
  finally { setLoading(decBtn, false); updateDecBtn(); }
});

/* ═══════════════════════════════════════════════════════════════════ */
/*  INSPECT                                                           */
/* ═══════════════════════════════════════════════════════════════════ */
setupDrop('inspect-drop', 'inspect-file-info', 'inspect', () => updateInspectBtn());

const inspectPass = $('inspect-password'), inspectBtn = $('inspect-btn');
inspectPass.addEventListener('input', updateInspectBtn);
function updateInspectBtn() { inspectBtn.disabled = !files.inspect; }

inspectBtn.addEventListener('click', async () => {
  hideEl('inspect-result', 'inspect-error');
  setLoading(inspectBtn, true);

  const fd = new FormData();
  fd.append('file', files.inspect);
  if (inspectPass.value) fd.append('password', inspectPass.value);

  try {
    const res = await fetch('/api/inspect', { method: 'POST', body: fd });
    if (!res.ok) throw new Error((await res.json()).error);

    const d = await res.json();
    const tbl = $('inspect-table');
    tbl.innerHTML = '';

    if (d.encrypted && !d.beaconId) {
      // v3 without password — show limited info
      const rows = [
        ['Format', d.format], ['Cipher', d.cipher], ['KDF', d.kdf], ['Integrity', d.integrity],
        ['Metadata', 'Encrypted — enter password to view'], ['Size', formatSize(d.fileSize)],
      ];
      for (const [k, v] of rows) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${k}</td><td>${v}</td>`;
        tbl.appendChild(tr);
      }
    } else {
      const rows = [
        ['Format', d.format], ['Cipher', d.cipher], ['KDF', d.kdf], ['Integrity', d.integrity],
        ['Beacon ID', d.beaconId], ['Original File', d.originalFile], ['Linked Repo', d.linkedRepo],
        ['Encrypted At', d.encryptedAt], ['Canary', d.canary ? 'Enabled' : 'Disabled'], ['Size', formatSize(d.fileSize)],
      ];
      if (d.canaryDomain) rows.push(['Canary Domain', d.canaryDomain]);

      for (const [k, v] of rows) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${k}</td><td>${v}</td>`;
        tbl.appendChild(tr);
      }
    }
    $('inspect-result').hidden = false;
  } catch (e) { showError('inspect-error', e.message); }
  finally { setLoading(inspectBtn, false); updateInspectBtn(); }
});

/* ═══════════════════════════════════════════════════════════════════ */
/*  CANARY                                                            */
/* ═══════════════════════════════════════════════════════════════════ */
const startBtn = $('canary-start-btn'), stopBtn = $('canary-stop-btn');
const canaryDot = $('canary-dot'), canaryText = $('canary-status-text'), hitBadge = $('canary-hit-count');
const canaryLog = $('canary-log');
let sse = null;

function setCanaryState(running) {
  canaryDot.classList.toggle('running', running);
  canaryText.textContent = running ? 'Online' : 'Offline';
  $('canary-pill').style.borderColor = running ? 'rgba(34,197,94,0.3)' : '';
  startBtn.disabled = running;
  stopBtn.disabled = !running;
}

function addHit(hit) {
  const empty = canaryLog.querySelector('.terminal-empty');
  if (empty) empty.remove();
  const el = document.createElement('div');
  el.className = 'log-entry';
  el.innerHTML = `<span class="log-time">${hit.time}</span> <span class="log-beacon">${hit.beaconId}</span> <span class="log-source">${hit.source}</span> <span class="log-ip">${hit.remoteIp}</span>`;
  canaryLog.appendChild(el);
  canaryLog.scrollTop = canaryLog.scrollHeight;
  const count = canaryLog.querySelectorAll('.log-entry').length;
  hitBadge.textContent = count + ' hit' + (count !== 1 ? 's' : '');
}

startBtn.addEventListener('click', async () => {
  hideEl('canary-error');
  setLoading(startBtn, true);
  try {
    const res = await fetch('/api/canary/start', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        domain: $('canary-domain').value,
        dnsPort: +$('canary-dns-port').value || 5353,
        httpPort: +$('canary-http-port').value || 8054,
      }),
    });
    if (!res.ok) throw new Error((await res.json()).error);
    setCanaryState(true);
    sse = new EventSource('/api/canary/events');
    sse.onmessage = e => addHit(JSON.parse(e.data));
  } catch (e) { showError('canary-error', e.message); }
  finally { setLoading(startBtn, false); if (!canaryDot.classList.contains('running')) startBtn.disabled = false; }
});

stopBtn.addEventListener('click', async () => {
  await fetch('/api/canary/stop', { method: 'POST' }).catch(() => {});
  setCanaryState(false);
  if (sse) { sse.close(); sse = null; }
});

// Restore canary state on load
(async () => {
  try {
    const { running, domain, dnsPort, httpPort, hitCount } = await (await fetch('/api/canary/status')).json();
    if (running) {
      setCanaryState(true);
      if (domain) $('canary-domain').value = domain;
      if (dnsPort) $('canary-dns-port').value = dnsPort;
      if (httpPort) $('canary-http-port').value = httpPort;
      hitBadge.textContent = (hitCount || 0) + ' hits';
      sse = new EventSource('/api/canary/events');
      sse.onmessage = e => addHit(JSON.parse(e.data));
    }
  } catch {}
})();

/* ═══════════════════════════════════════════════════════════════════ */
/*  SETTINGS                                                          */
/* ═══════════════════════════════════════════════════════════════════ */
const saveBtn = $('settings-save-btn');
const featureGithubToggle = $('set-feature-github');
const featureCanaryToggle = $('set-feature-canary');

// Live preview: toggling feature switches updates UI immediately
featureGithubToggle.addEventListener('change', () => {
  features.github = featureGithubToggle.checked;
  applyFeatureState();
});
featureCanaryToggle.addEventListener('change', () => {
  features.canary = featureCanaryToggle.checked;
  applyFeatureState();
});

// Load settings on startup
(async () => {
  try {
    const d = await (await fetch('/api/settings')).json();
    $('set-token').value = d.githubToken || '';
    $('set-repo').value = d.githubRepo || '';
    $('set-ping-mode').value = d.pingMode || 'issue';
    $('set-canary-domain').value = d.canaryDomain || '';
    $('set-canary-http').value = d.canaryHttpUrl || '';
    if (d.canaryDomain && !$('canary-domain').value) $('canary-domain').value = d.canaryDomain;

    // Apply feature flags
    features.github = d.featureGithub !== false;
    features.canary = d.featureCanary !== false;
    featureGithubToggle.checked = features.github;
    featureCanaryToggle.checked = features.canary;
    applyFeatureState();
  } catch {}
})();

saveBtn.addEventListener('click', async () => {
  hideEl('settings-result', 'settings-error');
  setLoading(saveBtn, true);
  try {
    const res = await fetch('/api/settings', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        githubToken: $('set-token').value, githubRepo: $('set-repo').value,
        pingMode: $('set-ping-mode').value, canaryDomain: $('set-canary-domain').value,
        canaryHttpUrl: $('set-canary-http').value,
        featureGithub: featureGithubToggle.checked,
        featureCanary: featureCanaryToggle.checked,
      }),
    });
    if (!res.ok) throw new Error((await res.json()).error);
    showToast('settings-result');
    setTimeout(() => $('settings-result').hidden = true, 3000);
  } catch (e) { showError('settings-error', e.message); }
  finally { setLoading(saveBtn, false); }
});
