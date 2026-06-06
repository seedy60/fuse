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

// Optional, privacy-first accounts. A fuse may belong to an account (account_id)
// or stay anonymous (NULL). Accounts store only one-way values: a peppered HMAC
// for O(1) login lookup and an argon2id hash for verification. The 16/20-digit
// account number itself is never stored.
ensureColumn("account_id", "account_id TEXT");
// Tier 2: a client-encrypted vault entry ({key, ownerToken, name, url}) the
// server stores but cannot read. NULL for anonymous or pre-Tier-2 fuses.
ensureColumn("vault_blob", "vault_blob TEXT");

db.exec(`
  CREATE TABLE IF NOT EXISTS accounts (
    id          TEXT PRIMARY KEY,
    lookup_hash TEXT NOT NULL UNIQUE,
    verify_hash TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  )
`);

db.exec("CREATE INDEX IF NOT EXISTS idx_fuses_account ON fuses(account_id)");

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

// --- Accounts ---

const insertAccount = db.prepare(`
  INSERT INTO accounts (id, lookup_hash, verify_hash)
  VALUES (@id, @lookupHash, @verifyHash)
`);

const getAccountByLookup = db.prepare("SELECT * FROM accounts WHERE lookup_hash = ?");

const getAccountById = db.prepare("SELECT * FROM accounts WHERE id = ?");

const deleteAccount = db.prepare("DELETE FROM accounts WHERE id = ?");

// Associates an already-stored fuse with an account. Kept separate from `insert`
// so the anonymous upload path is untouched.
const setFuseAccount = db.prepare("UPDATE fuses SET account_id = ? WHERE id = ?");

// Stores a client-encrypted vault entry, scoped to the owning account.
const setFuseVault = db.prepare("UPDATE fuses SET vault_blob = ? WHERE id = ? AND account_id = ?");

// Live fuses for the dashboard (newest first). Expired-but-not-yet-purged rows
// are filtered by the server using the same availability check downloads use.
const getActiveFusesByAccount = db.prepare(`
  SELECT * FROM fuses
  WHERE account_id = ? AND blown = 0
  ORDER BY created_at DESC
`);

// Every fuse for an account, used when wiping the account (unlink files first).
const getFusesByAccount = db.prepare("SELECT * FROM fuses WHERE account_id = ?");

const getFuseByIdAndAccount = db.prepare("SELECT * FROM fuses WHERE id = ? AND account_id = ?");

const deleteFusesByAccount = db.prepare("DELETE FROM fuses WHERE account_id = ?");

module.exports = {
  db,
  insert,
  getById,
  incrementDownloads,
  blowFuse,
  markClaimed,
  getExpired,
  getAll,
  insertAccount,
  getAccountByLookup,
  getAccountById,
  deleteAccount,
  setFuseAccount,
  setFuseVault,
  getActiveFusesByAccount,
  getFusesByAccount,
  getFuseByIdAndAccount,
  deleteFusesByAccount,
};
