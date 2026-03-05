# Encryptor

File encryption with tracking beacons, decryption notifications, and DNS canary tracking.

## Features

- **AES-256-GCM Encryption** — Authenticated encryption with Argon2id key derivation (64 MB, 4 iterations)
- **Tracking Beacons** — Each encrypted file embeds a unique beacon ID for traceability
- **GitHub Notifications** — Automatically creates a GitHub issue or fires a repository dispatch event when a file is decrypted
- **Kill Switch** — Decrypted content is held in memory only; if the ping fails and offline mode is disabled, the content is wiped without ever touching disk
- **DNS Canary** — Wraps files in HTML with DNS prefetch, fetch beacon, and HTTP pixel triggers that fire when the file is opened
- **Canary Server** — Built-in DNS + HTTP server that detects canary hits in real time
- **Web Dashboard** — Browser-based UI for encrypting, decrypting, inspecting files, managing the canary server, and configuring settings
- **Feature Toggles** — Enable or disable GitHub integration and DNS canary independently from the settings page

## Quick Start

```bash
# Install dependencies
npm install

# Configure environment (optional)
cp .env.example .env
# Edit .env with your GitHub token, repo, and canary domain

# Start the web dashboard
npm start
# Opens at http://localhost:3000
```

## CLI Usage

```bash
# Encrypt a file
npx encryptor encrypt secret.pdf -p "strong-password"

# Encrypt with DNS canary
npx encryptor encrypt secret.pdf -p "password" --canary --canary-domain canary.example.com

# Decrypt a file (sends GitHub ping)
npx encryptor decrypt secret.pdf.enc -p "strong-password"

# Decrypt without ping
npx encryptor decrypt secret.pdf.enc -p "password" --no-ping

# Decrypt with offline fallback (disables kill switch)
npx encryptor decrypt secret.pdf.enc -p "password" --allow-offline

# Inspect encrypted file metadata (v3 requires password)
npx encryptor inspect secret.pdf.enc -p "strong-password"

# Start canary server
npx encryptor serve --domain canary.example.com --dns-port 53 --http-port 8053

# Start web dashboard on custom port
npx encryptor web --port 8080
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GITHUB_TOKEN` | GitHub Personal Access Token with `repo` scope | — |
| `GITHUB_REPO` | Target repository in `owner/repo` format | — |
| `PING_MODE` | Notification mode: `issue` or `dispatch` | `issue` |
| `CANARY_DOMAIN` | DNS canary domain | — |
| `CANARY_HTTP_URL` | HTTP canary server URL | — |
| `ENCRYPT_PASSWORD` | Default encryption password (CLI only) | — |
| `FEATURE_GITHUB` | Enable GitHub integration (`true`/`false`) | `true` |
| `FEATURE_CANARY` | Enable DNS canary system (`true`/`false`) | `true` |

## Web Dashboard API

| Method | Route | Description |
|--------|-------|-------------|
| `POST` | `/api/encrypt` | Upload and encrypt a file |
| `POST` | `/api/decrypt` | Upload and decrypt a `.enc` file |
| `POST` | `/api/inspect` | Inspect encrypted file metadata |
| `POST` | `/api/canary/start` | Start the DNS + HTTP canary server |
| `POST` | `/api/canary/stop` | Stop the canary server |
| `GET` | `/api/canary/status` | Get canary server status |
| `GET` | `/api/canary/events` | SSE stream of live canary hits |
| `GET` | `/api/settings` | Get current configuration |
| `PUT` | `/api/settings` | Update configuration |

## File Format (v3 — Encrypted Metadata)

All metadata (beacon ID, filename, timestamp, repo) is encrypted and cannot be read without the password.

```
[8B  magic "ENCPING2"]
[1B  format version = 3]
[32B Argon2id salt]
[12B beacon IV]
[16B beacon GCM auth tag]
[4B  encrypted beacon length]
[NB  encrypted beacon JSON]
[12B content IV]
[16B content GCM auth tag]
[**  content ciphertext]
[32B HMAC-SHA256]
```

v2 files (plaintext metadata) are still supported for decryption and inspection.

## Security

| Component | Detail |
|-----------|--------|
| Cipher | AES-256-GCM (AEAD) |
| KDF | Argon2id — 64 MB memory, 4 iterations, 2 threads |
| IV | 96-bit random (NIST recommended for GCM) |
| Salt | 256-bit random |
| Integrity | HMAC-SHA256 over full payload + GCM auth tag |
| Key Separation | Encryption key and HMAC key derived independently via domain separation |
| Memory Safety | Keys and decrypted content wiped from memory after use |

## Project Structure

```
bin/encryptor.js        CLI entry point
lib/crypto.js           AES-256-GCM + Argon2id encryption/decryption
lib/ping.js             GitHub issue/dispatch notifications
lib/wrapper.js          HTML canary wrapper
lib/canary.js           DNS + HTTP canary server
server/index.js         HTTP server and API routes
server/multipart.js     Multipart form parser
public/index.html       Web dashboard SPA
public/css/main.css     Dashboard styles
public/js/app.js        Dashboard client-side logic
```

## License

MIT
