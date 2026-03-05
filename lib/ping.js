import { hostname, userInfo, platform, arch } from 'os';

/**
 * Send a decryption ping to GitHub.
 *
 * Two modes:
 *   1. "issue"    — creates a GitHub issue on the linked repo
 *   2. "dispatch" — fires a repository_dispatch event (for GitHub Actions)
 *
 * Requires a GitHub Personal Access Token with `repo` scope.
 */
export async function sendPing(beaconData, config) {
  const { githubToken, githubRepo, pingMode = 'issue' } = config;

  if (!githubToken || !githubRepo) {
    throw new Error(
      'Missing GITHUB_TOKEN or GITHUB_REPO — cannot verify decryption authorization.'
    );
  }

  const environment = {
    hostname: hostname(),
    user: userInfo().username,
    platform: `${platform()} ${arch()}`,
    timestamp: new Date().toISOString(),
  };

  if (pingMode === 'dispatch') {
    return sendDispatch(beaconData, environment, githubToken, githubRepo);
  }
  return sendIssue(beaconData, environment, githubToken, githubRepo);
}

/**
 * Create a GitHub issue as a decryption notification.
 */
async function sendIssue(beaconData, env, token, repo) {
  const url = `https://api.github.com/repos/${repo}/issues`;

  const title = `[Decrypt Ping] ${beaconData.id} — ${env.timestamp}`;
  const body = [
    `## Decryption Event Detected`,
    ``,
    `| Field | Value |`,
    `|-------|-------|`,
    `| **Beacon ID** | \`${beaconData.id}\` |`,
    `| **Original File** | \`${beaconData.originalFile || 'unknown'}\` |`,
    `| **Encrypted At** | ${beaconData.timestamp || 'unknown'} |`,
    `| **Decrypted At** | ${env.timestamp} |`,
    `| **Host** | ${env.hostname} |`,
    `| **User** | ${env.user} |`,
    `| **Platform** | ${env.platform} |`,
    ``,
    `> This issue was automatically created by **encrypt-ping** when a tracked encrypted file was decrypted.`,
  ].join('\n');

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'Content-Type': 'application/json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
    body: JSON.stringify({
      title,
      body,
      labels: ['decrypt-ping'],
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`GitHub issue creation failed (${res.status}): ${err}`);
  }

  const issue = await res.json();
  console.log(`[ping] GitHub issue created: ${issue.html_url}`);
  return issue;
}

/**
 * Fire a repository_dispatch event so GitHub Actions can react.
 */
async function sendDispatch(beaconData, env, token, repo) {
  const url = `https://api.github.com/repos/${repo}/dispatches`;

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'Content-Type': 'application/json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
    body: JSON.stringify({
      event_type: 'decrypt-ping',
      client_payload: {
        beacon: beaconData,
        environment: env,
      },
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`GitHub dispatch failed (${res.status}): ${err}`);
  }

  console.log(`[ping] Repository dispatch event sent to ${repo}`);
  return { dispatched: true, repo };
}
