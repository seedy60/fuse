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
const ENCRYPTED_FILE_OVERHEAD_BYTES = 28; // 12-byte IV + 16-byte AES-GCM auth tag.
const UPLOAD_TIMEOUT_MINUTES = parseNonNegativeInteger(process.env.FUSE_UPLOAD_TIMEOUT_MINUTES, 60);
const UPLOAD_TIMEOUT_MS = UPLOAD_TIMEOUT_MINUTES === 0 ? 0 : UPLOAD_TIMEOUT_MINUTES * 60 * 1000;
const UPLOAD_CHUNK_SIZE_BYTES = parseNonNegativeInteger(process.env.FUSE_UPLOAD_CHUNK_SIZE_BYTES, 33554432) || 33554432;
const UPLOAD_CHUNK_PARSER_LIMIT_BYTES = UPLOAD_CHUNK_SIZE_BYTES + 1048576;
const CHUNK_UPLOAD_TTL_HOURS = parseNonNegativeInteger(process.env.FUSE_CHUNK_UPLOAD_TTL_HOURS, 24) || 24;
const CHUNK_UPLOAD_TTL_MS = CHUNK_UPLOAD_TTL_HOURS * 60 * 60 * 1000;

for (const dir of [UPLOAD_DIR, CHUNK_UPLOAD_DIR]) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

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

function parseNonNegativeInteger(value, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
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

async function verifyClaimCode(claimCode, storedHash) {
  if (!storedHash) return false;
  if (storedHash.startsWith("$argon2")) {
    return argon2.verify(storedHash, claimCode);
  }
  // Backward compatibility for old rows that used SHA-256.
  return safeHashEquals(hashSecret(claimCode), storedHash);
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
    maxFileSize: MAX_FILE_SIZE,
    uploadChunkSize: UPLOAD_CHUNK_SIZE_BYTES,
    requireClaimCodeDefault: REQUIRE_CLAIM_CODE_DEFAULT,
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

app.get("/d/:id", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/revoke/:id", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "revoke.html"));
});

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

setInterval(runCleanup, CLEANUP_INTERVAL);

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

server.listen(PORT, () => {
  const protocol = SSL_CERT && SSL_KEY ? "https" : "http";
  console.log(`Fuse is running at ${protocol}://localhost:${PORT}`);
  console.log(`Max file size: ${(MAX_FILE_SIZE / 1024 / 1024).toFixed(0)} MB`);
  console.log(`Upload request timeout: ${UPLOAD_TIMEOUT_MINUTES === 0 ? "disabled" : `${UPLOAD_TIMEOUT_MINUTES} minutes`}`);
  runCleanup();
});
