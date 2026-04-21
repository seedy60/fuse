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
const CLEANUP_INTERVAL = (parseInt(process.env.FUSE_CLEANUP_INTERVAL, 10) || 10) * 60 * 1000;
const REQUIRE_CLAIM_CODE_DEFAULT = String(process.env.FUSE_REQUIRE_CLAIM_CODE || "true").toLowerCase() !== "false";
const TOKEN_PEPPER = process.env.FUSE_TOKEN_PEPPER || "";
const CLAIM_MAX_ATTEMPTS = parseInt(process.env.FUSE_CLAIM_MAX_ATTEMPTS, 10) || 5;
const CLAIM_WINDOW_MS = (parseInt(process.env.FUSE_CLAIM_WINDOW_MINUTES, 10) || 15) * 60 * 1000;
const CLAIM_BLOCK_MS = (parseInt(process.env.FUSE_CLAIM_BLOCK_MINUTES, 10) || 30) * 60 * 1000;
const SSL_CERT = process.env.FUSE_SSL_CERT;
const SSL_KEY = process.env.FUSE_SSL_KEY;

if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const upload = multer({
  dest: UPLOAD_DIR,
  limits: { fileSize: MAX_FILE_SIZE },
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
    requireClaimCodeDefault: REQUIRE_CLAIM_CODE_DEFAULT,
  });
});

app.post("/api/upload", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No file provided." });
    }

    const id = nanoid(16);
    const { originalname, path: tmpPath, size } = req.file;

    const finalPath = path.join(UPLOAD_DIR, id);
    fs.renameSync(tmpPath, finalPath);

    let passwordHash = null;
    if (req.body.password && req.body.password.length > 0) {
      passwordHash = await argon2.hash(req.body.password, {
        type: argon2.argon2id,
        memoryCost: 65536,
        timeCost: 3,
        parallelism: 1,
      });
    }

    let expiresAt = null;
    if (req.body.expiresAt) {
      expiresAt = req.body.expiresAt;
    }

    let maxDownloads = null;
    if (req.body.maxDownloads && parseInt(req.body.maxDownloads, 10) > 0) {
      maxDownloads = parseInt(req.body.maxDownloads, 10);
    }

    const ownerToken = generateOwnerToken();
    const ownerTokenHash = hashOwnerToken(ownerToken);

    const claimRequired = parseBoolean(req.body.claimRequired, REQUIRE_CLAIM_CODE_DEFAULT);
    const claimCode = claimRequired ? generateClaimCode() : null;
    const claimCodeHash = claimCode
      ? await argon2.hash(claimCode, argon2ClaimOptions)
      : null;

    db.insert.run({
      id,
      originalName: originalname,
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

    res.json({
      id,
      url: `${BASE_URL}/d/${id}`,
      ownerToken,
      claimCode,
      claimRequired,
    });
  } catch (err) {
    console.error("Upload error:", err);
    if (req.file && req.file.path && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ error: "Upload failed." });
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
  if (updatedFuse.max_downloads && updatedFuse.download_count >= updatedFuse.max_downloads) {
    cleanupFuse(updatedFuse);
  }

  if (!fs.existsSync(fuse.file_path)) {
    return res.status(410).json({ error: "The file is no longer available." });
  }

  res.setHeader("Content-Disposition", `attachment; filename="${encodeURIComponent(fuse.original_name)}"`);
  res.setHeader("Content-Type", "application/octet-stream");
  res.setHeader("Content-Length", fuse.size);

  const stream = fs.createReadStream(fuse.file_path);
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

server.listen(PORT, () => {
  const protocol = SSL_CERT && SSL_KEY ? "https" : "http";
  console.log(`Fuse is running at ${protocol}://localhost:${PORT}`);
  console.log(`Max file size: ${(MAX_FILE_SIZE / 1024 / 1024).toFixed(0)} MB`);
  runCleanup();
});
