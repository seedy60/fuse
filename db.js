const Database = require("better-sqlite3");
const path = require("path");

const db = new Database(path.join(__dirname, "fuse.db"));

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS fuses (
    id            TEXT PRIMARY KEY,
    original_name TEXT NOT NULL,
    file_path     TEXT NOT NULL,
    size          INTEGER NOT NULL,
    password_hash TEXT,
    max_downloads INTEGER,
    download_count INTEGER NOT NULL DEFAULT 0,
    expires_at    TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    blown         INTEGER NOT NULL DEFAULT 0
  )
`);

const insert = db.prepare(`
  INSERT INTO fuses (id, original_name, file_path, size, password_hash, max_downloads, expires_at)
  VALUES (@id, @originalName, @filePath, @size, @passwordHash, @maxDownloads, @expiresAt)
`);

const getById = db.prepare("SELECT * FROM fuses WHERE id = ?");

const incrementDownloads = db.prepare(`
  UPDATE fuses SET download_count = download_count + 1 WHERE id = ?
`);

const blowFuse = db.prepare("UPDATE fuses SET blown = 1 WHERE id = ?");

const getExpired = db.prepare(`
  SELECT * FROM fuses
  WHERE blown = 0
    AND (
      (expires_at IS NOT NULL AND datetime(expires_at) <= datetime('now'))
      OR (max_downloads IS NOT NULL AND download_count >= max_downloads)
    )
`);

const getAll = db.prepare("SELECT * FROM fuses WHERE blown = 0");

module.exports = {
  db,
  insert,
  getById,
  incrementDownloads,
  blowFuse,
  getExpired,
  getAll,
};
