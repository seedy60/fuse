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
    blown         INTEGER NOT NULL DEFAULT 0,
    owner_token_hash TEXT,
    claim_code_hash TEXT,
    claim_required INTEGER NOT NULL DEFAULT 1,
    claimed       INTEGER NOT NULL DEFAULT 0,
    claimed_at    TEXT
  )
`);

function ensureColumn(columnName, definition) {
  const columns = db.prepare("PRAGMA table_info(fuses)").all();
  const exists = columns.some(function (col) {
    return col.name === columnName;
  });
  if (!exists) {
    db.exec(`ALTER TABLE fuses ADD COLUMN ${definition}`);
  }
}

ensureColumn("owner_token_hash", "owner_token_hash TEXT");
ensureColumn("claim_code_hash", "claim_code_hash TEXT");
ensureColumn("claim_required", "claim_required INTEGER NOT NULL DEFAULT 1");
ensureColumn("claimed", "claimed INTEGER NOT NULL DEFAULT 0");
ensureColumn("claimed_at", "claimed_at TEXT");

const insert = db.prepare(`
  INSERT INTO fuses (
    id,
    original_name,
    file_path,
    size,
    password_hash,
    max_downloads,
    expires_at,
    owner_token_hash,
    claim_code_hash,
    claim_required,
    claimed
  )
  VALUES (
    @id,
    @originalName,
    @filePath,
    @size,
    @passwordHash,
    @maxDownloads,
    @expiresAt,
    @ownerTokenHash,
    @claimCodeHash,
    @claimRequired,
    @claimed
  )
`);

const getById = db.prepare("SELECT * FROM fuses WHERE id = ?");

const incrementDownloads = db.prepare(`
  UPDATE fuses SET download_count = download_count + 1 WHERE id = ?
`);

const blowFuse = db.prepare("UPDATE fuses SET blown = 1 WHERE id = ?");

const markClaimed = db.prepare(`
  UPDATE fuses
  SET claimed = 1, claimed_at = datetime('now'), claim_code_hash = NULL
  WHERE id = ?
`);

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
  markClaimed,
  getExpired,
  getAll,
};
