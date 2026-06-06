// Fuse client-side cryptography. Shared between the browser (loaded as a plain
// <script>, exposes window.FuseCrypto) and Node (require, for unit tests).
//
// Format v2 — chunked AEAD (STREAM construction). The whole file is never held
// in one buffer; each chunk is encrypted independently with AES-256-GCM:
//
//   header(17): "FUSE"(4) | version=2(1) | chunkSize:u32be(4) | noncePrefix(8)
//   per chunk i: ciphertext ‖ tag(16)   (ciphertext length == plaintext length)
//     IV  = noncePrefix(8) ‖ uint32be(i)         unique per chunk (key is per-file)
//     AAD = uint32be(i) ‖ finalFlag(1)           binds order + finality
//
// Reordering, truncation, or extension all flip the index/final the decryptor
// feeds as AAD, so the GCM tag fails. Legacy v1 blobs (iv(12) ‖ ciphertext‖tag,
// no header) are still decryptable via decryptLegacyBlob for existing links.
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("crypto").webcrypto || globalThis.crypto);
  } else {
    root.FuseCrypto = factory(root.crypto);
  }
})(typeof self !== "undefined" ? self : this, function (webcrypto) {
  "use strict";

  const subtle = webcrypto.subtle;

  const MAGIC = [0x46, 0x55, 0x53, 0x45]; // "FUSE"
  const VERSION = 2;
  const HEADER_SIZE = 17; // 4 magic + 1 version + 4 chunkSize + 8 noncePrefix
  const NONCE_PREFIX_BYTES = 8;
  const TAG_BYTES = 16;
  const DEFAULT_CHUNK_SIZE = 16 * 1024 * 1024; // 16 MiB plaintext per chunk

  // --- base64url (used only for the small raw key) ---

  function bufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function base64UrlToBuffer(base64Url) {
    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  // --- keys ---

  function generateKey() {
    return subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  }

  async function exportKey(key) {
    return bufferToBase64Url(await subtle.exportKey("raw", key));
  }

  function importKey(base64Url) {
    return subtle.importKey("raw", base64UrlToBuffer(base64Url), { name: "AES-GCM" }, false, ["decrypt"]);
  }

  function randomNoncePrefix() {
    const prefix = new Uint8Array(NONCE_PREFIX_BYTES);
    webcrypto.getRandomValues(prefix);
    return prefix;
  }

  // --- v2 framing ---

  function uint32be(n) {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, n >>> 0, false);
    return out;
  }

  function buildHeader(chunkSize, noncePrefix) {
    const header = new Uint8Array(HEADER_SIZE);
    header.set(MAGIC, 0);
    header[4] = VERSION;
    header.set(uint32be(chunkSize), 5);
    header.set(noncePrefix, 9);
    return header;
  }

  function isV2(bytes) {
    return bytes.length >= 5 &&
      bytes[0] === MAGIC[0] && bytes[1] === MAGIC[1] &&
      bytes[2] === MAGIC[2] && bytes[3] === MAGIC[3] &&
      bytes[4] === VERSION;
  }

  function parseHeader(bytes) {
    if (!isV2(bytes) || bytes.length < HEADER_SIZE) return null;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return {
      version: VERSION,
      chunkSize: view.getUint32(5, false),
      noncePrefix: bytes.slice(9, 17),
      headerSize: HEADER_SIZE,
    };
  }

  function chunkIv(noncePrefix, index) {
    const iv = new Uint8Array(12);
    iv.set(noncePrefix, 0);
    iv.set(uint32be(index), NONCE_PREFIX_BYTES);
    return iv;
  }

  function chunkAad(index, isFinal) {
    const aad = new Uint8Array(5);
    aad.set(uint32be(index), 0);
    aad[4] = isFinal ? 1 : 0;
    return aad;
  }

  // Returns a Uint8Array record (ciphertext ‖ tag).
  async function encryptChunk(key, noncePrefix, index, isFinal, plaintext) {
    const result = await subtle.encrypt(
      { name: "AES-GCM", iv: chunkIv(noncePrefix, index), additionalData: chunkAad(index, isFinal), tagLength: 128 },
      key,
      plaintext,
    );
    return new Uint8Array(result);
  }

  // Returns a Uint8Array of plaintext, or throws if authentication fails.
  async function decryptChunk(key, noncePrefix, index, isFinal, record) {
    const result = await subtle.decrypt(
      { name: "AES-GCM", iv: chunkIv(noncePrefix, index), additionalData: chunkAad(index, isFinal), tagLength: 128 },
      key,
      record,
    );
    return new Uint8Array(result);
  }

  // Legacy v1: iv(12) ‖ ciphertext‖tag, no AAD. For links created before v2.
  async function decryptLegacyBlob(combinedBuffer, key) {
    const combined = new Uint8Array(combinedBuffer);
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    const result = await subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
    return new Uint8Array(result);
  }

  // --- Streaming decryption (download side) ---

  // Pulls exactly n bytes off the front of a queue of Uint8Arrays, copying only
  // those n bytes (never the whole pending buffer), so framing a multi-GB stream
  // stays linear rather than quadratic. Caller guarantees n <= bytes queued.
  function pullBytes(queue, n) {
    const out = new Uint8Array(n);
    let offset = 0;
    while (offset < n) {
      const first = queue[0];
      const need = n - offset;
      if (first.length <= need) {
        out.set(first, offset);
        offset += first.length;
        queue.shift();
      } else {
        out.set(first.subarray(0, need), offset);
        queue[0] = first.subarray(need);
        offset += need;
      }
    }
    return out;
  }

  function peekBytes(queue, n) {
    let available = 0;
    for (let i = 0; i < queue.length; i += 1) available += queue[i].length;
    const want = Math.min(n, available);
    const out = new Uint8Array(want);
    let offset = 0;
    for (let i = 0; i < queue.length && offset < want; i += 1) {
      const take = Math.min(queue[i].length, want - offset);
      out.set(queue[i].subarray(0, take), offset);
      offset += take;
    }
    return out;
  }

  async function decryptV2Whole(bytes, key) {
    const header = parseHeader(bytes);
    const recordSize = header.chunkSize + TAG_BYTES;
    const parts = [];
    let offset = header.headerSize;
    let index = 0;
    while (offset < bytes.length) {
      const len = Math.min(recordSize, bytes.length - offset);
      const isFinal = offset + len >= bytes.length;
      parts.push(await decryptChunk(key, header.noncePrefix, index, isFinal, bytes.slice(offset, offset + len)));
      offset += len;
      index += 1;
    }
    return new Blob(parts);
  }

  // Decrypts a fully-buffered blob — for the no-stream fallback, and for legacy
  // v1 which must be read whole anyway.
  async function decryptBufferToBlob(bytesLike, keyString) {
    const key = await importKey(keyString);
    const bytes = bytesLike instanceof Uint8Array ? bytesLike : new Uint8Array(bytesLike);
    if (isV2(bytes)) return decryptV2Whole(bytes, key);
    return new Blob([await decryptLegacyBlob(bytes, key)]);
  }

  // Streams an encrypted response body and decrypts it chunk-by-chunk into a
  // Blob, so the whole file is never held as one ArrayBuffer (~2 GiB cap). The
  // record still buffered at end-of-stream is the final one — that is how exact
  // size-multiples are disambiguated. onProgress(received, total) reports the
  // encrypted bytes pulled so far. Auto-detects v2 vs legacy v1.
  // Streams an encrypted response body and decrypts it chunk-by-chunk, invoking
  // onChunk(plaintextUint8Array) for each — so the consumer can write straight to
  // disk (no in-memory blob, no ~2 GiB cap) or accumulate. onChunk may be async.
  // The record still buffered at end-of-stream is the final one (handles exact
  // size-multiples). onProgress(received, total) reports encrypted bytes pulled.
  async function decryptStream(stream, keyString, onProgress, total, onChunk) {
    const key = await importKey(keyString);
    const reader = stream.getReader();
    const queue = [];
    let queuedLen = 0;
    let received = 0;
    total = total || 0;

    async function readMore() {
      const next = await reader.read();
      if (next.done) return false;
      const bytes = next.value instanceof Uint8Array ? next.value : new Uint8Array(next.value);
      queue.push(bytes);
      queuedLen += bytes.length;
      received += bytes.length;
      if (onProgress) onProgress(received, total);
      return true;
    }

    while (queuedLen < HEADER_SIZE) {
      if (!(await readMore())) break;
    }
    const head = peekBytes(queue, HEADER_SIZE);
    const header = isV2(head) ? parseHeader(head) : null;

    if (!header) {
      while (await readMore()) { /* drain legacy body */ }
      await onChunk(await decryptLegacyBlob(pullBytes(queue, queuedLen), key));
      return;
    }

    pullBytes(queue, header.headerSize);
    queuedLen -= header.headerSize;
    const recordSize = header.chunkSize + TAG_BYTES;
    let index = 0;

    // While strictly more than one record is buffered, the leading record is
    // certainly not the last, so decrypt it as non-final.
    async function drainNonFinal() {
      while (queuedLen > recordSize) {
        await onChunk(await decryptChunk(key, header.noncePrefix, index, false, pullBytes(queue, recordSize)));
        queuedLen -= recordSize;
        index += 1;
      }
    }

    await drainNonFinal();
    while (await readMore()) {
      await drainNonFinal();
    }
    await onChunk(await decryptChunk(key, header.noncePrefix, index, true, pullBytes(queue, queuedLen)));
  }

  async function decryptStreamToBlob(stream, keyString, onProgress, total) {
    const parts = [];
    await decryptStream(stream, keyString, onProgress, total, function (chunk) { parts.push(chunk); });
    return new Blob(parts);
  }

  // --- Accounts: key derivation + vault (Tier 2, zero-knowledge) ---

  const PBKDF2_ITERATIONS = 600000;
  const ACCOUNT_NUMBER_DIGITS = 20;
  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  // Client-side account number (CSPRNG, rejection sampling — no modulo bias).
  // Generated in the browser so the server never sees it.
  function generateAccountNumber(digits) {
    const want = digits || ACCOUNT_NUMBER_DIGITS;
    let number = "";
    while (number.length < want) {
      const bytes = new Uint8Array(want);
      webcrypto.getRandomValues(bytes);
      for (let i = 0; i < bytes.length && number.length < want; i += 1) {
        if (bytes[i] < 250) number += String(bytes[i] % 10);
      }
    }
    return number;
  }

  function importVaultKey(base64Url) {
    return subtle.importKey("raw", base64UrlToBuffer(base64Url), { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
  }

  // From the account number, derive (entirely in the browser) the login
  // authenticator sent to the server and the vault key that never leaves it.
  // PBKDF2 slows any offline attack on a captured authenticator; HKDF with
  // distinct info strings keeps the two outputs cryptographically independent.
  async function deriveAccountKeys(accountNumber) {
    const salt = new Uint8Array(await subtle.digest("SHA-256", textEncoder.encode("fuse-account-kdf-v1:" + accountNumber)));
    const pbkdf2Key = await subtle.importKey("raw", textEncoder.encode(accountNumber), "PBKDF2", false, ["deriveBits"]);
    const masterBits = await subtle.deriveBits({ name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, pbkdf2Key, 256);
    const master = await subtle.importKey("raw", masterBits, "HKDF", false, ["deriveBits"]);

    const emptySalt = new Uint8Array(0);
    const authBits = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: emptySalt, info: textEncoder.encode("fuse-account-auth-v1") }, master, 256);
    const vaultBits = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: emptySalt, info: textEncoder.encode("fuse-account-vault-v1") }, master, 256);

    const vaultKeyB64 = bufferToBase64Url(vaultBits);
    return { authenticator: bufferToBase64Url(authBits), vaultKey: await importVaultKey(vaultKeyB64), vaultKeyB64 };
  }

  // A vault entry seals a fuse's secrets (key, owner token, name, url) under the
  // vault key: AES-GCM with a per-entry IV, returned as base64url(iv ‖ ct‖tag).
  async function encryptVaultEntry(vaultKey, plaintextString) {
    const iv = new Uint8Array(12);
    webcrypto.getRandomValues(iv);
    const ct = await subtle.encrypt({ name: "AES-GCM", iv }, vaultKey, textEncoder.encode(plaintextString));
    const out = new Uint8Array(iv.length + ct.byteLength);
    out.set(iv, 0);
    out.set(new Uint8Array(ct), iv.length);
    return bufferToBase64Url(out);
  }

  async function decryptVaultEntry(vaultKey, base64Url) {
    const bytes = new Uint8Array(base64UrlToBuffer(base64Url));
    const pt = await subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(0, 12) }, vaultKey, bytes.slice(12));
    return textDecoder.decode(pt);
  }

  return {
    MAGIC, VERSION, HEADER_SIZE, NONCE_PREFIX_BYTES, TAG_BYTES, DEFAULT_CHUNK_SIZE,
    bufferToBase64Url, base64UrlToBuffer,
    generateKey, exportKey, importKey, randomNoncePrefix,
    uint32be, buildHeader, isV2, parseHeader, chunkIv, chunkAad,
    encryptChunk, decryptChunk, decryptLegacyBlob,
    decryptBufferToBlob, decryptStream, decryptStreamToBlob,
    generateAccountNumber, deriveAccountKeys, importVaultKey,
    encryptVaultEntry, decryptVaultEntry,
  };
});
