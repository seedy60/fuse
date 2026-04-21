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

// --- API Routes ---

app.get("/api/config", (req, res) => {
  res.json({
    maxFileSize: MAX_FILE_SIZE,
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

    db.insert.run({
      id,
      originalName: originalname,
      filePath: finalPath,
      size,
      passwordHash,
      maxDownloads,
      expiresAt,
    });

    res.json({
      id,
      url: `${BASE_URL}/d/${id}`,
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
  if (!fuse) {
    return res.status(404).json({ error: "Share link not found." });
  }

  if (fuse.blown) {
    return res.status(410).json({ error: "This share link has expired." });
  }

  if (fuse.expires_at && new Date(fuse.expires_at + "Z") <= new Date()) {
    cleanupFuse(fuse);
    return res.status(410).json({ error: "This share link has expired." });
  }

  if (fuse.max_downloads && fuse.download_count >= fuse.max_downloads) {
    cleanupFuse(fuse);
    return res.status(410).json({ error: "This share link has reached its download limit." });
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
  });
});

app.post("/api/fuse/:id/download", express.json(), async (req, res) => {
  const fuse = db.getById.get(req.params.id);
  if (!fuse) {
    return res.status(404).json({ error: "Share link not found." });
  }

  if (fuse.blown) {
    return res.status(410).json({ error: "This share link has expired." });
  }

  if (fuse.expires_at && new Date(fuse.expires_at + "Z") <= new Date()) {
    cleanupFuse(fuse);
    return res.status(410).json({ error: "This share link has expired." });
  }

  if (fuse.max_downloads && fuse.download_count >= fuse.max_downloads) {
    cleanupFuse(fuse);
    return res.status(410).json({ error: "This share link has reached its download limit." });
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
