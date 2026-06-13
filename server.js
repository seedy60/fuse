require("dotenv").config();

const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const https = require("https");
const http = require("http");
const crypto = require("crypto");
const argon2 = require("argon2");
const { nanoid } = require("nanoid");
const db = require("./db");

const PORT = parseInt(process.env.FUSE_PORT, 10) || 3000;
const MAX_FILE_SIZE = parseInt(process.env.FUSE_MAX_FILE_SIZE, 10) || 524288000;
const BASE_URL = (process.env.FUSE_BASE_URL || `http://localhost:${PORT}`)
  .replace(/\\(?=\/)/g, "")
  .replace(/\/+$/, "");
const INSTANCE_NAME = process.env.FUSE_INSTANCE_NAME || "Fuse";
const BASE_PATH = normalizeBasePath(process.env.FUSE_BASE_PATH);
const UPLOAD_DIR = process.env.FUSE_UPLOAD_DIR || path.join(__dirname, "uploads");
const CHUNK_UPLOAD_DIR = path.join(UPLOAD_DIR, ".chunks");
const CLEANUP_INTERVAL = (parseInt(process.env.FUSE_CLEANUP_INTERVAL, 10) || 10) * 60 * 1000;
const REQUIRE_CLAIM_CODE_DEFAULT = String(process.env.FUSE_REQUIRE_CLAIM_CODE || "true").toLowerCase() !== "false";
const TOKEN_PEPPER = process.env.FUSE_TOKEN_PEPPER || "";
const CLAIM_MAX_ATTEMPTS = parseInt(process.env.FUSE_CLAIM_MAX_ATTEMPTS, 10) || 5;
const CLAIM_WINDOW_MS = (parseInt(process.env.FUSE_CLAIM_WINDOW_MINUTES, 10) || 15) * 60 * 1000;
const CLAIM_BLOCK_MS = (parseInt(process.env.FUSE_CLAIM_BLOCK_MINUTES, 10) || 30) * 60 * 1000;
const SSL_CERT = process.env.FUSE_SSL_CERT;
const SSL_KEY = process.env.FUSE_SSL_KEY;
// The v2 chunked format adds a 17-byte header + a 16-byte GCM tag per chunk.
// Allow a generous fixed overhead (far above the worst case even at MAX_FILE_SIZE)
// so large multi-chunk uploads are never rejected just for their framing bytes.
const ENCRYPTED_FILE_OVERHEAD_BYTES = 1024 * 1024;
const UPLOAD_TIMEOUT_MINUTES = parseNonNegativeInteger(process.env.FUSE_UPLOAD_TIMEOUT_MINUTES, 60);
const UPLOAD_TIMEOUT_MS = UPLOAD_TIMEOUT_MINUTES === 0 ? 0 : UPLOAD_TIMEOUT_MINUTES * 60 * 1000;
const UPLOAD_CHUNK_SIZE_BYTES = parseNonNegativeInteger(process.env.FUSE_UPLOAD_CHUNK_SIZE_BYTES, 33554432) || 33554432;
const UPLOAD_CHUNK_PARSER_LIMIT_BYTES = UPLOAD_CHUNK_SIZE_BYTES + 1048576;
const CHUNK_UPLOAD_TTL_HOURS = parseNonNegativeInteger(process.env.FUSE_CHUNK_UPLOAD_TTL_HOURS, 24) || 24;
const CHUNK_UPLOAD_TTL_MS = CHUNK_UPLOAD_TTL_HOURS * 60 * 60 * 1000;

// --- Account system configuration ---
// Dedicated secrets, kept separate from the owner-token pepper and given their
// own domains. These constants are consumed by later phases (crypto helpers,
// endpoints, rate limiting); declared here so all config lives in one place.
const ACCOUNT_PEPPER = process.env.FUSE_ACCOUNT_PEPPER || "";
const SESSION_SECRET_FROM_ENV = Boolean(process.env.FUSE_SESSION_SECRET);
const SESSION_SECRET = process.env.FUSE_SESSION_SECRET || crypto.randomBytes(32).toString("hex");
// Account numbers are saved, not memorized, so there is no reason to stay at
// Mullvad's 16 digits. Default to 20 (~2^66); floor at 16 to keep the keyspace
// large even if an operator lowers it.
const ACCOUNT_NUMBER_DIGITS = Math.max(16, parseNonNegativeInteger(process.env.FUSE_ACCOUNT_NUMBER_DIGITS, 20) || 20);
const ACCOUNT_SESSION_TTL_MS = (parseNonNegativeInteger(process.env.FUSE_ACCOUNT_SESSION_TTL_MINUTES, 30) || 30) * 60 * 1000;
// "Remember me" duration. 0 disables the option; the client hides the checkbox.
const ACCOUNT_REMEMBER_DAYS = parseNonNegativeInteger(process.env.FUSE_ACCOUNT_REMEMBER_DAYS, 30);
const ACCOUNT_REMEMBER_MS = ACCOUNT_REMEMBER_DAYS * 24 * 60 * 60 * 1000;
// Per-IP login triage only. It is the cheap first filter, not the security
// boundary: the real wall is the keyspace, server-side argon2, and a global
// concurrency cap added in a later phase.
const ACCOUNT_LOGIN_MAX_ATTEMPTS = parseNonNegativeInteger(process.env.FUSE_ACCOUNT_LOGIN_MAX_ATTEMPTS, 10) || 10;
const ACCOUNT_LOGIN_WINDOW_MS = (parseNonNegativeInteger(process.env.FUSE_ACCOUNT_LOGIN_WINDOW_MINUTES, 15) || 15) * 60 * 1000;
const ACCOUNT_LOGIN_BLOCK_MS = (parseNonNegativeInteger(process.env.FUSE_ACCOUNT_LOGIN_BLOCK_MINUTES, 30) || 30) * 60 * 1000;
const ACCOUNT_LOGIN_MAX_CONCURRENT = parseNonNegativeInteger(process.env.FUSE_ACCOUNT_LOGIN_MAX_CONCURRENT, 4) || 4;
const ACCOUNT_LOGIN_MAX_QUEUE = parseNonNegativeInteger(process.env.FUSE_ACCOUNT_LOGIN_MAX_QUEUE, 20) || 20;
const TRUST_PROXY = parseTrustProxy(process.env.FUSE_TRUST_PROXY);

for (const dir of [UPLOAD_DIR, CHUNK_UPLOAD_DIR]) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

const app = express();
// Behind a reverse proxy this must be set so req.ip is the real client address
// (used by the claim-code and account-login limiters). Default false trusts only
// the direct socket. Do NOT set this to "true" blindly — that trusts a spoofable
// X-Forwarded-For; use the hop count or your proxy's address instead.
app.set("trust proxy", TRUST_PROXY);

// Support mounting under a sub-path (FUSE_BASE_PATH, e.g. "/fuse"): strip the
// prefix from the request URL so the routes below match at the root. Works
// whether a reverse proxy forwards the prefix or strips it — the client always
// addresses the prefixed paths via the <base> tag injected into each page.
if (BASE_PATH) {
  app.use(function (req, res, next) {
    if (req.url === BASE_PATH || req.url.startsWith(BASE_PATH + "/") || req.url.startsWith(BASE_PATH + "?")) {
      req.url = req.url.slice(BASE_PATH.length) || "/";
      if (req.url[0] !== "/") req.url = "/" + req.url;
    }
    next();
  });
}

app.use(express.json());
// Always revalidate static assets so a redeploy's updated client code is picked
// up on the next load instead of a stale cached copy — a stale app.js/crypto.js
// silently breaks decryption when the on-the-wire format has changed.
app.use(express.static(path.join(__dirname, "public"), {
  index: false,
  setHeaders: function (res) {
    res.setHeader("Cache-Control", "no-cache");
  },
}));

const upload = multer({
  dest: UPLOAD_DIR,
  limits: { fileSize: MAX_FILE_SIZE + ENCRYPTED_FILE_OVERHEAD_BYTES },
});

const chunkUpload = multer({
  dest: UPLOAD_DIR,
  limits: { fileSize: UPLOAD_CHUNK_PARSER_LIMIT_BYTES },
});

const claimAttemptState = new Map();

const argon2ClaimOptions = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

if (!TOKEN_PEPPER) {
  console.warn("FUSE_TOKEN_PEPPER is not set. Set it in .env for stronger token hashing.");
}

if (!ACCOUNT_PEPPER) {
  console.warn("FUSE_ACCOUNT_PEPPER is not set. Set it in .env for stronger account-number hashing.");
}

if (!SESSION_SECRET_FROM_ENV) {
  console.warn("FUSE_SESSION_SECRET is not set. Using a random secret; account sessions will not survive a restart.");
}

function parseNonNegativeInteger(value, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

// Express "trust proxy" setting. Accepts a hop count, true/false, or an
// IP/subnet/list (or "loopback"). Default false: trust only the direct socket.
function parseTrustProxy(value) {
  if (value === undefined || value === null || value === "") return false;
  const normalized = String(value).trim();
  if (normalized.toLowerCase() === "true") return true;
  if (normalized.toLowerCase() === "false") return false;
  if (/^\d+$/.test(normalized)) return Number(normalized);
  return normalized;
}

// Sub-path mount point. "" or "/" -> "" (root); "fuse" or "/fuse/" -> "/fuse"
// (leading slash, no trailing slash).
function normalizeBasePath(value) {
  const trimmed = String(value || "").trim().replace(/\/+$/, "");
  if (!trimmed) return "";
  return trimmed.startsWith("/") ? trimmed : "/" + trimmed;
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return "unknown size";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`;
  return `${(bytes / 1073741824).toFixed(2)} GB`;
}

function httpError(status, message) {
  const err = new Error(message);
  err.status = status;
  err.publicMessage = message;
  return err;
}

function hashSecret(secret) {
  return crypto.createHash("sha256").update(secret, "utf8").digest("hex");
}

function hashOwnerToken(secret) {
  return crypto.createHmac("sha256", TOKEN_PEPPER).update(secret, "utf8").digest("hex");
}

function safeHashEquals(leftHash, rightHash) {
  if (!leftHash || !rightHash) return false;
  const left = Buffer.from(leftHash, "utf8");
  const right = Buffer.from(rightHash, "utf8");
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function generateOwnerToken() {
  return crypto.randomBytes(24).toString("hex");
}

function generateClaimCode() {
  return crypto.randomBytes(8).toString("hex").toUpperCase();
}

function getClaimAttemptKey(fuseId, req) {
  const ip = req.ip || req.socket?.remoteAddress || "unknown";
  return `${fuseId}:${ip}`;
}

function isClaimBlocked(fuseId, req) {
  const key = getClaimAttemptKey(fuseId, req);
  const state = claimAttemptState.get(key);
  if (!state) return false;

  const now = Date.now();
  if (state.blockedUntil && now < state.blockedUntil) {
    return true;
  }
  if (state.blockedUntil && now >= state.blockedUntil) {
    claimAttemptState.delete(key);
    return false;
  }
  return false;
}

function registerClaimFailure(fuseId, req) {
  const key = getClaimAttemptKey(fuseId, req);
  const now = Date.now();
  let state = claimAttemptState.get(key);

  if (!state || now > state.windowEndsAt) {
    state = {
      count: 0,
      windowEndsAt: now + CLAIM_WINDOW_MS,
      blockedUntil: 0,
    };
  }

  state.count += 1;
  if (state.count >= CLAIM_MAX_ATTEMPTS) {
    state.blockedUntil = now + CLAIM_BLOCK_MS;
  }

  claimAttemptState.set(key, state);
}

function resetClaimFailures(fuseId, req) {
  const key = getClaimAttemptKey(fuseId, req);
  claimAttemptState.delete(key);
}

// Per-IP account-login limiter. This is cheap triage only; it shares the
// reverse-proxy caveat of the claim limiter (fixed in a later phase) and is not
// the real brute-force wall (keyspace + argon2 + a global cap are).
const loginAttemptState = new Map();

function getLoginAttemptKey(req) {
  return req.ip || req.socket?.remoteAddress || "unknown";
}

function isLoginBlocked(req) {
  const state = loginAttemptState.get(getLoginAttemptKey(req));
  if (!state) return false;
  const now = Date.now();
  if (state.blockedUntil && now < state.blockedUntil) return true;
  if (state.blockedUntil && now >= state.blockedUntil) {
    loginAttemptState.delete(getLoginAttemptKey(req));
  }
  return false;
}

function registerLoginFailure(req) {
  const key = getLoginAttemptKey(req);
  const now = Date.now();
  let state = loginAttemptState.get(key);
  if (!state || now > state.windowEndsAt) {
    state = { count: 0, windowEndsAt: now + ACCOUNT_LOGIN_WINDOW_MS, blockedUntil: 0 };
  }
  state.count += 1;
  if (state.count >= ACCOUNT_LOGIN_MAX_ATTEMPTS) {
    state.blockedUntil = now + ACCOUNT_LOGIN_BLOCK_MS;
  }
  loginAttemptState.set(key, state);
}

function resetLoginFailures(req) {
  loginAttemptState.delete(getLoginAttemptKey(req));
}

async function verifyClaimCode(claimCode, storedHash) {
  if (!storedHash) return false;
  if (storedHash.startsWith("$argon2")) {
    return argon2.verify(storedHash, claimCode);
  }
  // Backward compatibility for old rows that used SHA-256.
  return safeHashEquals(hashSecret(claimCode), storedHash);
}

// --- Account helpers ---
// Accounts are zero-knowledge: the browser generates the account number and
// derives a login authenticator from it (PBKDF2 + HKDF, in /crypto.js). The
// server only ever sees the authenticator, never the number, so the helpers
// below operate on the authenticator as the credential.

// Rejects anything that is not a well-formed authenticator before any HMAC or
// argon2 work. The authenticator is a 256-bit value, base64url-encoded (43 chars).
function normalizeAuthenticator(input) {
  const value = String(input || "").trim();
  return /^[A-Za-z0-9_-]{43}$/.test(value) ? value : null;
}

// Deterministic, peppered, domain-separated lookup key for O(1) login. An
// argon2 hash can't be looked up (random salt), so this indexes the row; the
// pepper stops a leaked DB from being scanned with a precomputed table.
function hashAccountLookup(accountNumber) {
  return crypto.createHmac("sha256", ACCOUNT_PEPPER).update("account:" + accountNumber, "utf8").digest("hex");
}

function hashAccountNumber(accountNumber) {
  return argon2.hash(accountNumber, argon2ClaimOptions);
}

async function verifyAccountNumberHash(accountNumber, verifyHash) {
  try {
    return await argon2.verify(verifyHash, accountNumber);
  } catch (_) {
    return false;
  }
}

// Precomputed once so that a login for a non-existent account still pays the
// full argon2 cost; otherwise response timing would reveal which numbers exist.
const decoyVerifyHashPromise = argon2.hash(crypto.randomBytes(32).toString("hex"), argon2ClaimOptions);
// Mark handled so an (unexpected) startup failure isn't a fatal unhandled
// rejection; real awaiters below still observe the error and fail closed.
decoyVerifyHashPromise.catch(() => {});

// Always runs argon2 whether or not the account exists (constant existence).
async function verifyAccountConstantTime(accountNumber, account) {
  const hashToCheck = account ? account.verify_hash : await decoyVerifyHashPromise;
  const matches = await verifyAccountNumberHash(accountNumber, hashToCheck);
  return Boolean(account) && matches;
}

// --- Account sessions (stateless, HMAC-signed, carried in the Authorization header) ---

function signSessionPayload(payloadB64) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(payloadB64, "utf8").digest("base64url");
}

function issueSessionToken(accountId, ttlMs) {
  const expiresAt = Date.now() + (ttlMs || ACCOUNT_SESSION_TTL_MS);
  const payloadB64 = Buffer.from(`${accountId}.${expiresAt}`, "utf8").toString("base64url");
  return { token: `${payloadB64}.${signSessionPayload(payloadB64)}`, expiresAt };
}

function verifySessionToken(token) {
  if (typeof token !== "string" || !token) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;

  const expectedSig = Buffer.from(signSessionPayload(parts[0]));
  const providedSig = Buffer.from(parts[1]);
  if (providedSig.length !== expectedSig.length || !crypto.timingSafeEqual(providedSig, expectedSig)) {
    return null;
  }

  const payload = Buffer.from(parts[0], "base64url").toString("utf8");
  const sep = payload.lastIndexOf(".");
  if (sep === -1) return null;

  const accountId = payload.slice(0, sep);
  const expiresAt = Number(payload.slice(sep + 1));
  if (!accountId || !Number.isFinite(expiresAt) || Date.now() > expiresAt) {
    return null;
  }
  return { accountId, expiresAt };
}

function getSessionFromRequest(req) {
  const match = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || "");
  return match ? verifySessionToken(match[1].trim()) : null;
}

function requireAccount(req, res, next) {
  const session = getSessionFromRequest(req);
  if (!session) {
    return res.status(401).json({ error: "Account session is invalid or expired.", needsLogin: true });
  }
  req.accountId = session.accountId;
  next();
}

function parseBoolean(value, defaultValue) {
  if (typeof value === "boolean") return value;
  if (typeof value !== "string") return defaultValue;
  const normalized = value.trim().toLowerCase();
  if (normalized === "true" || normalized === "1" || normalized === "yes" || normalized === "on") return true;
  if (normalized === "false" || normalized === "0" || normalized === "no" || normalized === "off") return false;
  return defaultValue;
}

function parseUploadInteger(value) {
  const stringValue = String(value ?? "").trim();
  if (!/^\d+$/.test(stringValue)) return null;
  const parsed = Number(stringValue);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function normalizeOriginalName(value) {
  const parts = String(value || "file").split(/[\\/]/);
  const name = parts[parts.length - 1].trim();
  return (name || "file").slice(0, 255);
}

function removeFileAtPath(filePath) {
  if (filePath && fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
  }
}

function removeUploadedFile(file) {
  removeFileAtPath(file && file.path);
}

function cleanupReceivedFiles(req) {
  removeUploadedFile(req.file);
  if (!req.files) return;

  if (Array.isArray(req.files)) {
    for (const file of req.files) {
      removeUploadedFile(file);
    }
    return;
  }

  for (const files of Object.values(req.files)) {
    for (const file of files) {
      removeUploadedFile(file);
    }
  }
}

function getChunkUploadDir(uploadId) {
  if (!/^[A-Za-z0-9_-]{16,64}$/.test(uploadId || "")) return null;
  return path.join(CHUNK_UPLOAD_DIR, uploadId);
}

function getChunkFilePath(uploadDir, chunkIndex) {
  return path.join(uploadDir, `${chunkIndex}.part`);
}

function removeChunkUploadDir(uploadDir) {
  if (!uploadDir) return;

  const basePath = path.resolve(CHUNK_UPLOAD_DIR);
  const resolvedPath = path.resolve(uploadDir);
  if (resolvedPath === basePath || !resolvedPath.startsWith(basePath + path.sep)) {
    return;
  }

  fs.rmSync(resolvedPath, { recursive: true, force: true });
}

function validateEncryptedUploadSize(size) {
  if (!Number.isSafeInteger(size) || size <= 0) {
    throw httpError(400, "Upload size is invalid.");
  }
  if (size > MAX_FILE_SIZE + ENCRYPTED_FILE_OVERHEAD_BYTES) {
    throw httpError(413, `File is larger than the ${formatBytes(MAX_FILE_SIZE)} limit.`);
  }
}

function logUploadStart(req, res, next) {
  const contentLength = Number(req.headers["content-length"]);
  const sizeLabel = Number.isFinite(contentLength) ? formatBytes(contentLength) : "unknown size";

  console.log(`Upload request started: ${sizeLabel}`);
  req.once("aborted", () => {
    console.warn(`Upload request aborted before completion: ${sizeLabel}`);
  });

  next();
}

function receiveUpload(req, res, next) {
  upload.single("file")(req, res, function (err) {
    if (!err) return next();

    cleanupReceivedFiles(req);

    if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
      console.warn(`Upload rejected: file is larger than ${formatBytes(MAX_FILE_SIZE)}.`);
      return res.status(413).json({
        error: `File is larger than the ${formatBytes(MAX_FILE_SIZE)} limit.`,
      });
    }

    if (err instanceof multer.MulterError) {
      console.warn("Upload rejected by multipart parser:", err.message);
      return res.status(400).json({ error: "Upload could not be parsed." });
    }

    console.error("Upload receive error:", err);
    return res.status(500).json({ error: "Upload failed while receiving the file." });
  });
}

function receiveUploadChunk(req, res, next) {
  chunkUpload.single("file")(req, res, function (err) {
    if (!err) return next();

    cleanupReceivedFiles(req);

    if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
      console.warn(`Upload chunk rejected: chunk is larger than ${formatBytes(UPLOAD_CHUNK_SIZE_BYTES)}.`);
      return res.status(413).json({
        error: `Upload chunk is larger than the ${formatBytes(UPLOAD_CHUNK_SIZE_BYTES)} chunk limit.`,
      });
    }

    if (err instanceof multer.MulterError) {
      console.warn("Upload chunk rejected by multipart parser:", err.message);
      return res.status(400).json({ error: "Upload chunk could not be parsed." });
    }

    console.error("Upload chunk receive error:", err);
    return res.status(500).json({ error: "Upload failed while receiving a chunk." });
  });
}

async function appendChunkToStream(sourcePath, writeStream) {
  await new Promise((resolve, reject) => {
    const readStream = fs.createReadStream(sourcePath);
    const handleWriteError = (err) => {
      readStream.destroy();
      reject(err);
    };
    readStream.on("error", reject);
    writeStream.once("error", handleWriteError);
    readStream.on("end", () => {
      writeStream.off("error", handleWriteError);
      resolve();
    });
    readStream.pipe(writeStream, { end: false });
  });
}

async function assembleChunks(uploadDir, totalChunks, finalPath) {
  const writeStream = fs.createWriteStream(finalPath, { flags: "wx" });
  try {
    for (let index = 0; index < totalChunks; index += 1) {
      await appendChunkToStream(getChunkFilePath(uploadDir, index), writeStream);
    }
  } finally {
    await new Promise((resolve) => writeStream.end(resolve));
  }
}

async function createFuseRecord(options) {
  const { id = nanoid(16), originalName, finalPath, size, body } = options;
  validateEncryptedUploadSize(size);

  let passwordHash = null;
  if (body.password && body.password.length > 0) {
    passwordHash = await argon2.hash(body.password, {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 1,
    });
  }

  let expiresAt = null;
  if (body.expiresAt) {
    expiresAt = body.expiresAt;
  }

  let maxDownloads = null;
  if (body.maxDownloads && parseInt(body.maxDownloads, 10) > 0) {
    maxDownloads = parseInt(body.maxDownloads, 10);
  }

  const ownerToken = generateOwnerToken();
  const ownerTokenHash = hashOwnerToken(ownerToken);

  const claimRequired = parseBoolean(body.claimRequired, REQUIRE_CLAIM_CODE_DEFAULT);
  const claimCode = claimRequired ? generateClaimCode() : null;
  const claimCodeHash = claimCode
    ? await argon2.hash(claimCode, argon2ClaimOptions)
    : null;

  db.insert.run({
    id,
    originalName,
    filePath: finalPath,
    size,
    passwordHash,
    maxDownloads,
    expiresAt,
    ownerTokenHash,
    claimCodeHash,
    claimRequired: claimRequired ? 1 : 0,
    claimed: claimRequired ? 0 : 1,
  });

  return {
    id,
    url: `${BASE_URL}/d/${id}`,
    ownerToken,
    claimCode,
    claimRequired,
  };
}

// Links a freshly-stored fuse to the uploader's account when they are logged in.
// No/invalid token, or an account deleted since the token was issued, leaves the
// fuse anonymous (account_id NULL) — accounts are strictly optional.
function associateFuseWithAccount(req, fuseId) {
  const session = getSessionFromRequest(req);
  if (session && db.getAccountById.get(session.accountId)) {
    db.setFuseAccount.run(session.accountId, fuseId);
  }
}

function isFuseUnavailable(fuse) {
  if (!fuse) {
    return { unavailable: true, status: 404, error: "Share link not found." };
  }
  if (fuse.blown) {
    return { unavailable: true, status: 410, error: "This share link has expired." };
  }
  if (fuse.expires_at && new Date(fuse.expires_at + "Z") <= new Date()) {
    cleanupFuse(fuse);
    return { unavailable: true, status: 410, error: "This share link has expired." };
  }
  if (fuse.max_downloads && fuse.download_count >= fuse.max_downloads) {
    cleanupFuse(fuse);
    return { unavailable: true, status: 410, error: "This share link has reached its download limit." };
  }
  return { unavailable: false };
}

// --- API Routes ---

app.get("/api/config", (req, res) => {
  res.json({
    instanceName: INSTANCE_NAME,
    maxFileSize: MAX_FILE_SIZE,
    uploadChunkSize: UPLOAD_CHUNK_SIZE_BYTES,
    requireClaimCodeDefault: REQUIRE_CLAIM_CODE_DEFAULT,
    accountNumberDigits: ACCOUNT_NUMBER_DIGITS,
    rememberDays: ACCOUNT_REMEMBER_DAYS,
  });
});

app.post("/api/upload/start", (req, res) => {
  try {
    const totalSize = parseUploadInteger(req.body.totalSize);
    validateEncryptedUploadSize(totalSize);

    const uploadId = nanoid(24);
    const uploadDir = getChunkUploadDir(uploadId);
    fs.mkdirSync(uploadDir, { recursive: true });
    fs.writeFileSync(
      path.join(uploadDir, "state.json"),
      JSON.stringify({
        createdAt: new Date().toISOString(),
        totalSize,
      }),
    );

    console.log(`Chunked upload started: ${uploadId} (${formatBytes(totalSize)})`);
    res.json({
      uploadId,
      chunkSize: UPLOAD_CHUNK_SIZE_BYTES,
    });
  } catch (err) {
    const status = err.status || 500;
    console.error("Chunked upload start error:", err);
    res.status(status).json({ error: err.publicMessage || "Upload could not be started." });
  }
});

app.post("/api/upload/chunk", logUploadStart, receiveUploadChunk, (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No chunk provided." });
    }

    const uploadId = String(req.body.uploadId || "");
    const uploadDir = getChunkUploadDir(uploadId);
    if (!uploadDir || !fs.existsSync(uploadDir)) {
      cleanupReceivedFiles(req);
      return res.status(404).json({ error: "Chunked upload session not found." });
    }

    const chunkIndex = parseUploadInteger(req.body.chunkIndex);
    const totalChunks = parseUploadInteger(req.body.totalChunks);
    const totalSize = parseUploadInteger(req.body.totalSize);
    validateEncryptedUploadSize(totalSize);

    if (!Number.isSafeInteger(totalChunks) || totalChunks < 1) {
      cleanupReceivedFiles(req);
      return res.status(400).json({ error: "Total chunk count is invalid." });
    }
    if (!Number.isSafeInteger(chunkIndex) || chunkIndex < 0 || chunkIndex >= totalChunks) {
      cleanupReceivedFiles(req);
      return res.status(400).json({ error: "Chunk index is invalid." });
    }

    const chunkPath = getChunkFilePath(uploadDir, chunkIndex);
    removeFileAtPath(chunkPath);
    fs.renameSync(req.file.path, chunkPath);

    res.json({ ok: true });
  } catch (err) {
    console.error("Chunked upload chunk error:", err);
    cleanupReceivedFiles(req);
    res.status(err.status || 500).json({ error: err.publicMessage || "Upload chunk failed." });
  }
});

app.post("/api/upload/complete", async (req, res) => {
  const uploadId = String(req.body.uploadId || "");
  const uploadDir = getChunkUploadDir(uploadId);
  let finalPath = null;

  try {
    if (!uploadDir || !fs.existsSync(uploadDir)) {
      return res.status(404).json({ error: "Chunked upload session not found." });
    }

    const totalChunks = parseUploadInteger(req.body.totalChunks);
    const totalSize = parseUploadInteger(req.body.totalSize);
    validateEncryptedUploadSize(totalSize);

    if (!Number.isSafeInteger(totalChunks) || totalChunks < 1) {
      return res.status(400).json({ error: "Total chunk count is invalid." });
    }

    let receivedSize = 0;
    for (let index = 0; index < totalChunks; index += 1) {
      const chunkPath = getChunkFilePath(uploadDir, index);
      if (!fs.existsSync(chunkPath)) {
        return res.status(400).json({ error: "Upload is missing one or more chunks." });
      }
      receivedSize += fs.statSync(chunkPath).size;
    }

    if (receivedSize !== totalSize) {
      return res.status(400).json({ error: "Uploaded chunks do not match the expected size." });
    }

    const id = nanoid(16);
    finalPath = path.join(UPLOAD_DIR, id);
    await assembleChunks(uploadDir, totalChunks, finalPath);

    const assembledSize = fs.statSync(finalPath).size;
    if (assembledSize !== totalSize) {
      throw httpError(400, "Assembled upload does not match the expected size.");
    }

    const result = await createFuseRecord({
      id,
      originalName: normalizeOriginalName(req.body.originalName),
      finalPath,
      size: assembledSize,
      body: req.body,
    });
    associateFuseWithAccount(req, result.id);

    removeChunkUploadDir(uploadDir);
    res.json(result);
    console.log(`Chunked upload stored: ${result.id} (${formatBytes(assembledSize)})`);
  } catch (err) {
    console.error("Chunked upload complete error:", err);
    removeFileAtPath(finalPath);
    res.status(err.status || 500).json({ error: err.publicMessage || "Upload could not be completed." });
  }
});

app.post("/api/upload", logUploadStart, receiveUpload, async (req, res) => {
  let finalPath = null;

  try {
    if (!req.file) {
      return res.status(400).json({ error: "No file provided." });
    }

    const id = nanoid(16);
    const { originalname, path: tmpPath, size } = req.file;
    console.log(`Upload received: ${originalname} (${formatBytes(size)})`);

    finalPath = path.join(UPLOAD_DIR, id);
    fs.renameSync(tmpPath, finalPath);

    const result = await createFuseRecord({
      id,
      originalName: normalizeOriginalName(originalname),
      finalPath,
      size,
      body: req.body,
    });
    associateFuseWithAccount(req, result.id);

    res.json(result);
    console.log(`Upload stored: ${result.id} (${formatBytes(size)})`);
  } catch (err) {
    console.error("Upload error:", err);
    cleanupReceivedFiles(req);
    removeFileAtPath(finalPath);
    res.status(err.status || 500).json({ error: err.publicMessage || "Upload failed." });
  }
});

app.get("/api/fuse/:id", (req, res) => {
  const fuse = db.getById.get(req.params.id);
  const availability = isFuseUnavailable(fuse);
  if (availability.unavailable) {
    return res.status(availability.status).json({ error: availability.error });
  }

  res.json({
    id: fuse.id,
    originalName: fuse.original_name,
    size: fuse.size,
    hasPassword: !!fuse.password_hash,
    maxDownloads: fuse.max_downloads,
    downloadCount: fuse.download_count,
    expiresAt: fuse.expires_at,
    createdAt: fuse.created_at,
    claimRequired: !!fuse.claim_required,
    claimed: !!fuse.claimed,
  });
});

app.post("/api/fuse/:id/revoke", (req, res) => {
  const fuse = db.getById.get(req.params.id);
  const availability = isFuseUnavailable(fuse);
  if (availability.unavailable && availability.status !== 410) {
    return res.status(availability.status).json({ error: availability.error });
  }
  if (!fuse) {
    return res.status(404).json({ error: "Share link not found." });
  }

  const ownerToken = (req.body && req.body.ownerToken) || "";
  if (!ownerToken) {
    return res.status(401).json({ error: "Owner token required." });
  }
  if (!fuse.owner_token_hash || !safeHashEquals(hashOwnerToken(ownerToken), fuse.owner_token_hash)) {
    return res.status(403).json({ error: "Owner token is invalid." });
  }

  cleanupFuse(fuse);
  return res.json({ ok: true, message: "Fuse blown." });
});

app.post("/api/fuse/:id/download", express.json(), async (req, res) => {
  const fuse = db.getById.get(req.params.id);
  const availability = isFuseUnavailable(fuse);
  if (availability.unavailable) {
    return res.status(availability.status).json({ error: availability.error });
  }

  if (fuse.claim_required && !fuse.claimed) {
    if (isClaimBlocked(fuse.id, req)) {
      return res.status(429).json({
        error: "Too many incorrect claim code attempts. Please try again later.",
        needsClaimCode: true,
      });
    }

    const claimCode = (req.body && req.body.claimCode ? String(req.body.claimCode) : "").trim().toUpperCase();
    if (!claimCode) {
      return res.status(423).json({
        error: "Claim code required before first download.",
        needsClaimCode: true,
      });
    }

    const validClaimCode = await verifyClaimCode(claimCode, fuse.claim_code_hash);
    if (!validClaimCode) {
      registerClaimFailure(fuse.id, req);
      return res.status(403).json({
        error: "Claim code is incorrect.",
        needsClaimCode: true,
      });
    }

    resetClaimFailures(fuse.id, req);
    db.markClaimed.run(fuse.id);
  }

  if (fuse.password_hash) {
    const { password } = req.body || {};
    if (!password) {
      return res.status(401).json({ error: "Password required.", needsPassword: true });
    }
    const valid = await argon2.verify(fuse.password_hash, password);
    if (!valid) {
      return res.status(403).json({ error: "The password is incorrect. Please try again." });
    }
  }

  db.incrementDownloads.run(fuse.id);

  const updatedFuse = db.getById.get(fuse.id);
  const shouldBlowAfterSend = !!(updatedFuse.max_downloads && updatedFuse.download_count >= updatedFuse.max_downloads);

  if (!fs.existsSync(fuse.file_path)) {
    if (shouldBlowAfterSend) {
      cleanupFuse(updatedFuse);
    }
    return res.status(410).json({ error: "The file is no longer available." });
  }

  res.setHeader("Content-Disposition", `attachment; filename="${encodeURIComponent(fuse.original_name)}"`);
  res.setHeader("Content-Type", "application/octet-stream");
  res.setHeader("Content-Length", fuse.size);

  const stream = fs.createReadStream(fuse.file_path);

  stream.on("error", (error) => {
    console.error("Download stream error:", error);
    if (!res.headersSent) {
      return res.status(500).json({ error: "Download failed." });
    }
    res.destroy(error);
  });

  if (shouldBlowAfterSend) {
    res.on("finish", () => {
      const latest = db.getById.get(fuse.id);
      if (latest && !latest.blown && latest.max_downloads && latest.download_count >= latest.max_downloads) {
        cleanupFuse(latest);
      }
    });
  }

  stream.pipe(res);
});

// --- Account API Routes ---

// Bounded-concurrency gate. `release()` hands a held slot directly to the next
// waiter, so `active` never exceeds maxActive; once the queue is full, acquire()
// returns null and the caller is shed with a 503.
function createConcurrencyLimiter(maxActive, maxQueue) {
  let active = 0;
  const queue = [];
  return {
    acquire() {
      if (active < maxActive) {
        active += 1;
        return Promise.resolve();
      }
      if (queue.length >= maxQueue) {
        return null;
      }
      return new Promise((resolve) => { queue.push(resolve); });
    },
    release() {
      const next = queue.shift();
      if (next) {
        next();
      } else {
        active -= 1;
      }
    },
  };
}

// Caps concurrent account-number argon2 work server-wide. Being independent of
// source IP, this is the real brute-force ceiling: rotating through VPNs/proxies
// cannot raise the total guess rate past what one server can hash. The per-IP
// limiter is just cheap triage in front of it. This is the deliberate primary
// anti-abuse mechanism: no CAPTCHA or proof-of-work — those are inaccessible to
// many users, and redundant given this cap plus the ~2^66 account-number keyspace.
const argon2Slots = createConcurrencyLimiter(ACCOUNT_LOGIN_MAX_CONCURRENT, ACCOUNT_LOGIN_MAX_QUEUE);

function limitArgon2Concurrency(req, res, next) {
  const slot = argon2Slots.acquire();
  if (!slot) {
    return res.status(503).json({ error: "The server is busy. Please try again in a moment." });
  }
  let released = false;
  const release = function () {
    if (released) return;
    released = true;
    argon2Slots.release();
  };
  res.on("finish", release);
  res.on("close", release);
  slot.then(next);
}

app.post("/api/account/create", limitArgon2Concurrency, async (req, res) => {
  const authenticator = normalizeAuthenticator(req.body && req.body.authenticator);
  if (!authenticator) {
    return res.status(400).json({ error: "A valid account authenticator is required." });
  }
  try {
    const id = nanoid(16);
    const verifyHash = await hashAccountNumber(authenticator);
    db.insertAccount.run({ id, lookupHash: hashAccountLookup(authenticator), verifyHash });

    const remember = Boolean(req.body && req.body.remember) && ACCOUNT_REMEMBER_MS > 0;
    const { token, expiresAt } = issueSessionToken(id, remember ? ACCOUNT_REMEMBER_MS : ACCOUNT_SESSION_TTL_MS);
    console.log(`Account created: ${id}`);
    // No account number is sent or stored. The client generated it and derived
    // this authenticator from it; the server never sees the number itself.
    res.json({ sessionToken: token, expiresAt });
  } catch (err) {
    // A UNIQUE violation means the same number was generated twice (astronomically
    // unlikely); the client can retry with a fresh number.
    console.error("Account create error:", err);
    res.status(500).json({ error: "Could not create account. Please try again." });
  }
});

app.post("/api/account/login", limitArgon2Concurrency, async (req, res) => {
  if (isLoginBlocked(req)) {
    return res.status(429).json({ error: "Too many login attempts. Please try again later." });
  }

  const authenticator = normalizeAuthenticator(req.body && req.body.authenticator);
  if (!authenticator) {
    registerLoginFailure(req);
    return res.status(400).json({ error: "A valid account authenticator is required." });
  }

  // Look up by deterministic HMAC, then verify. verifyAccountConstantTime always
  // runs argon2 (against a decoy when the row is missing), so a wrong credential
  // and a non-existent one are indistinguishable by timing or response.
  const account = db.getAccountByLookup.get(hashAccountLookup(authenticator));
  const valid = await verifyAccountConstantTime(authenticator, account);
  if (!valid) {
    registerLoginFailure(req);
    return res.status(403).json({ error: "Account number is incorrect." });
  }

  resetLoginFailures(req);
  const remember = Boolean(req.body && req.body.remember) && ACCOUNT_REMEMBER_MS > 0;
  const { token, expiresAt } = issueSessionToken(account.id, remember ? ACCOUNT_REMEMBER_MS : ACCOUNT_SESSION_TTL_MS);
  res.json({ sessionToken: token, expiresAt });
});

app.get("/api/account/fuses", requireAccount, (req, res) => {
  const fuses = [];
  for (const fuse of db.getActiveFusesByAccount.all(req.accountId)) {
    // Reuse the download availability check; it also purges expired/over-limit
    // fuses, which is exactly the "expired fuses auto-removed" behaviour we want.
    if (isFuseUnavailable(fuse).unavailable) continue;
    fuses.push({
      id: fuse.id,
      originalName: fuse.original_name,
      size: fuse.size,
      maxDownloads: fuse.max_downloads,
      downloadCount: fuse.download_count,
      expiresAt: fuse.expires_at,
      createdAt: fuse.created_at,
      claimRequired: !!fuse.claim_required,
      claimed: !!fuse.claimed,
      vaultBlob: fuse.vault_blob || null,
    });
  }
  res.json({ fuses });
});

app.post("/api/account/fuses/:id/blow", requireAccount, (req, res) => {
  const fuse = db.getFuseByIdAndAccount.get(req.params.id, req.accountId);
  if (!fuse) {
    return res.status(404).json({ error: "Fuse not found for this account." });
  }
  if (!fuse.blown) {
    cleanupFuse(fuse);
  }
  res.json({ ok: true, message: "Fuse blown." });
});

app.post("/api/account/vault", requireAccount, (req, res) => {
  const fuseId = req.body && req.body.fuseId;
  const blob = req.body && req.body.blob;
  // The blob is opaque client-encrypted ciphertext; the server only checks it is
  // a small string it can store, never reads it.
  if (typeof fuseId !== "string" || typeof blob !== "string" || !blob || blob.length > 8192) {
    return res.status(400).json({ error: "Invalid vault entry." });
  }
  if (!db.getFuseByIdAndAccount.get(fuseId, req.accountId)) {
    return res.status(404).json({ error: "Fuse not found for this account." });
  }
  db.setFuseVault.run(blob, fuseId, req.accountId);
  res.json({ ok: true });
});

app.post("/api/account/delete", requireAccount, async (req, res) => {
  const account = db.getAccountById.get(req.accountId);
  if (!account) {
    return res.status(404).json({ error: "Account not found." });
  }

  // Re-authenticate with the account number (the client sends the authenticator
  // derived from it): an irreversible, destructive action must not be possible
  // with only a borrowed/stolen session token.
  const authenticator = normalizeAuthenticator(req.body && req.body.authenticator);
  if (!authenticator) {
    return res.status(400).json({ error: "Re-enter your account number to confirm deletion." });
  }
  if (!(await verifyAccountConstantTime(authenticator, account))) {
    return res.status(403).json({ error: "Account number is incorrect." });
  }

  // Crypto-shred: unlink ciphertext files (best-effort), then remove the fuse
  // rows and the account. Only one-way hashes were ever stored, so deleting the
  // rows is the wipe; residual bytes are useless ciphertext.
  const fuses = db.getFusesByAccount.all(req.accountId);
  for (const fuse of fuses) {
    try {
      removeFileAtPath(fuse.file_path);
    } catch (err) {
      console.warn(`Account delete: could not remove file for fuse ${fuse.id}: ${err.message}`);
    }
  }
  db.deleteFusesByAccount.run(req.accountId);
  db.deleteAccount.run(req.accountId);

  console.log(`Account deleted: ${req.accountId} (${fuses.length} fuses removed)`);
  res.json({ ok: true, message: "Account and all fuses deleted." });
});

// Serves an HTML page with a <base> tag injected so the page's relative asset
// and API paths resolve correctly whether Fuse is mounted at the root ("/") or
// a sub-path ("/fuse/"). The <base> is path-only, so it works on any host.
function sendHtml(res, filename) {
  res.setHeader("Cache-Control", "no-cache");
  fs.readFile(path.join(__dirname, "public", filename), "utf8", (err, html) => {
    if (err) {
      console.error(`Failed to read ${filename}:`, err);
      return res.status(500).send("Page unavailable.");
    }
    res.type("html").send(html.replace("<head>", `<head>\n  <base href="${BASE_PATH}/">`));
  });
}

app.get("/", (req, res) => sendHtml(res, "index.html"));

app.get("/d/:id", (req, res) => sendHtml(res, "index.html"));

app.get("/revoke/:id", (req, res) => sendHtml(res, "revoke.html"));

app.get("/account", (req, res) => sendHtml(res, "account.html"));

// --- Cleanup ---

function cleanupFuse(fuse) {
  db.blowFuse.run(fuse.id);
  if (fs.existsSync(fuse.file_path)) {
    fs.unlinkSync(fuse.file_path);
  }
}

function runCleanup() {
  const expired = db.getExpired.all();
  for (const fuse of expired) {
    console.log(`Blowing fuse: ${fuse.id} (${fuse.original_name})`);
    cleanupFuse(fuse);
  }
  cleanupExpiredChunkUploads();
}

function cleanupExpiredChunkUploads() {
  if (!fs.existsSync(CHUNK_UPLOAD_DIR)) return;

  const now = Date.now();
  const entries = fs.readdirSync(CHUNK_UPLOAD_DIR, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;

    const uploadDir = path.join(CHUNK_UPLOAD_DIR, entry.name);
    const ageMs = now - fs.statSync(uploadDir).mtimeMs;
    if (ageMs > CHUNK_UPLOAD_TTL_MS) {
      console.log(`Removing incomplete chunked upload: ${entry.name}`);
      removeChunkUploadDir(uploadDir);
    }
  }
}

// --- Start Server ---

let server;
if (SSL_CERT && SSL_KEY) {
  const sslOptions = {
    cert: fs.readFileSync(SSL_CERT),
    key: fs.readFileSync(SSL_KEY),
  };
  server = https.createServer(sslOptions, app);
} else {
  server = http.createServer(app);
}

server.requestTimeout = UPLOAD_TIMEOUT_MS;

// Only bind the port and start the cleanup timer when run directly. Importing
// this file (e.g. from a test) exposes the helpers below without side effects.
if (require.main === module) {
  setInterval(runCleanup, CLEANUP_INTERVAL);
  server.listen(PORT, () => {
    const protocol = SSL_CERT && SSL_KEY ? "https" : "http";
    console.log(`${INSTANCE_NAME} is running at ${protocol}://localhost:${PORT}`);
    console.log(`Max file size: ${(MAX_FILE_SIZE / 1024 / 1024).toFixed(0)} MB`);
    console.log(`Upload request timeout: ${UPLOAD_TIMEOUT_MINUTES === 0 ? "disabled" : `${UPLOAD_TIMEOUT_MINUTES} minutes`}`);
    runCleanup();
  });
}

module.exports = {
  app,
  parseTrustProxy,
  normalizeAuthenticator,
  hashAccountLookup,
  hashAccountNumber,
  verifyAccountNumberHash,
  verifyAccountConstantTime,
  signSessionPayload,
  issueSessionToken,
  verifySessionToken,
  getSessionFromRequest,
  requireAccount,
};
