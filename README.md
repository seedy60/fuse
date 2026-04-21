# Fuse

File uploading with security and encryption.

## Introduction

Fuse is a Node.js web service for private and secure file sharing.

Your browser encrypts the file before upload. The server stores encrypted bytes only. The decryption key is kept in the URL fragment (`#...`), so it is not sent to the server.

You can set files to expire, limit downloads, and add an optional password.

## Features

### Browser-side encryption

- Files are encrypted in the browser with the Web Crypto API using AES-256-GCM.
- The encryption key is placed in the URL fragment (`#...`), which is not sent to the server.
- The server never stores decrypted file content.

### Link expiration and download controls

- Set expiry after a number of days.
- Set expiry on a specific date.
- Set an optional maximum download count.
- Expired or fully consumed fuses are removed automatically.

### Access protection

- Add an optional password per upload.
- Password metadata is hashed on the server with Argon2id.
- Optional first-download claim code blocks initial download unless the code is provided.
- Claim codes are hashed with Argon2id.
- Every upload returns a one-time owner revoke token that can instantly blow the fuse.
- Revoke tokens are stored as HMAC-SHA-256 hashes using a server-side pepper.

### Configurable deployment

- Runtime settings are configured with environment variables.

## Installation

### Install Node.js

Node.js v24 (Krypton) is the current LTS line as of April 2026.

#### Linux

Debian or Ubuntu (distribution repository):

```bash
sudo apt update
sudo apt install -y nodejs npm
```

Debian or Ubuntu (NodeSource 24.x):

```bash
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
sudo apt install -y nodejs
```

Fedora or RHEL (distribution repository):

```bash
sudo dnf install -y nodejs npm
```

Fedora or RHEL (NodeSource 24.x):

```bash
curl -fsSL https://rpm.nodesource.com/setup_24.x | sudo bash -
sudo dnf install -y nodejs
```

Arch Linux:

```bash
sudo pacman -S --needed nodejs npm
```

Any Linux distribution with nvm:

```bash
curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.4/install.sh | bash
source ~/.nvm/nvm.sh
nvm install --lts
nvm alias default 'lts/*'
```

#### Windows

Install with winget:

```powershell
winget install --id OpenJS.NodeJS.LTS -e
```

Install with Chocolatey:

```powershell
choco install nodejs-lts -y
```

You can also download and run the official LTS MSI installer from nodejs.org.

#### Verify installation

```bash
node -v
npm -v
npx -v
node -p "process.release.lts"
```

Distribution repositories can lag behind the active LTS release. For the newest LTS on Linux, prefer NodeSource or nvm. Use one installation method per machine to avoid mixed PATH or package-manager conflicts.

### From source

1. Clone this repository and move into the project directory.

```bash
git clone https://github.com/seedy60/fuse.git
cd fuse
```

2. Install dependencies.

```bash
npm install
```

3. Create your local environment file.

```bash
cp .env.example .env
```

If you are using Windows PowerShell, use:

```powershell
Copy-Item .env.example .env
```

4. Edit `.env` for your deployment.
5. Start the server.

```bash
npm start
```

6. Open the site in your browser at `http://localhost:3000` unless you changed `FUSE_PORT`.

## Configuration

All runtime settings are read from `.env`.

The following table lists each Fuse environment variable, its default value, and what it controls.

| Variable | Default | Description |
| --- | --- | --- |
| `FUSE_PORT` | `3000` | Port used by the Node.js server |
| `FUSE_MAX_FILE_SIZE` | `524288000` | Maximum upload size in bytes (500 MB default) |
| `FUSE_BASE_URL` | `http://localhost:3000` | Base URL used to build share links |
| `FUSE_SSL_CERT` | empty | Path to TLS certificate file to enable HTTPS |
| `FUSE_SSL_KEY` | empty | Path to TLS private key file to enable HTTPS |
| `FUSE_UPLOAD_DIR` | `./uploads` | Directory where encrypted upload blobs are stored |
| `FUSE_CLEANUP_INTERVAL` | `10` | Minutes between cleanup checks for expired/consumed fuses |
| `FUSE_REQUIRE_CLAIM_CODE` | `true` | Enables claim code by default for new uploads |
| `FUSE_TOKEN_PEPPER` | `change-me-to-a-long-random-secret` | Secret key used for HMAC hashing of owner revoke tokens |
| `FUSE_CLAIM_MAX_ATTEMPTS` | `5` | Number of bad claim code attempts allowed per IP and fuse in the time window |
| `FUSE_CLAIM_WINDOW_MINUTES` | `15` | Sliding window for claim attempt counting |
| `FUSE_CLAIM_BLOCK_MINUTES` | `30` | Temporary block time after too many failed claim attempts |

`FUSE_BASE_URL` is normalized by the server before links are generated. This removes escaped slash or backslash formatting artifacts and trailing slashes.

## Usage

### Upload a file

1. Open Fuse in your browser.
2. Select a file (or drag and drop one into the upload area).
3. Choose fuse options:
   - Expiry mode (none, days, or specific date)
   - Optional download limit
   - Optional password
	- Optional first-download claim code requirement
4. Start the upload.
5. Save the owner revoke token.
6. Share URL, decryption key, claim code, and password separately.

### Download a file

1. Open the share link in a browser.
2. If required, enter the first-download claim code.
3. If prompted, enter the password provided by the sender.
4. Start the download.
5. The browser downloads encrypted data, decrypts it locally using the URL fragment key, and saves the original file.

### Emergency revoke from browser

If you need to immediately disable a shared fuse:

1. Open the emergency revoke URL in any browser.
2. If needed, paste the owner revoke token.
3. Click Blow fuse now.

The revoke page route is:

`/revoke/:id`

Fuse also provides a full emergency revoke URL in the share result screen, including the token in the URL fragment so it is not sent to the server in HTTP requests.

## Accessibility

- The page includes a skip link to jump directly to main content.
- Error feedback is announced through alert regions for form and download errors.
- Status updates are announced with live regions during key actions such as encrypting, uploading, download progress, decryption, and copy-to-clipboard feedback.
- Focus is moved intentionally after major view changes:
	- After upload completes, focus moves to the "Share link ready" heading.
	- After choosing "Share another file", focus moves back to the upload heading.
	- On password-protected downloads, focus moves to the password field.
	- On downloads without a password, focus moves to the download button.
- Keyboard interaction uses standard browser behavior for all controls, and pressing Enter in the download password field starts the download.

## HTTPS Notes

1. Provide both `FUSE_SSL_CERT` and `FUSE_SSL_KEY` in `.env`.
2. Set `FUSE_BASE_URL` to an `https://` URL that matches how users access Fuse.
3. Restart the server after configuration changes.

Example:

```dotenv
FUSE_SSL_CERT=./certs/server.crt
FUSE_SSL_KEY=./certs/server.key
FUSE_BASE_URL=https://files.example.com
```

If either TLS variable is missing, Fuse starts in HTTP mode.

## Development Commands

The following table lists the available npm scripts for this project.

| Command | Purpose |
| --- | --- |
| `npm start` | Run the server normally (`node server.js`) |
| `npm run dev` | Run the server in watch mode (`node --watch server.js`) |

## License

MIT
