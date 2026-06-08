(function () {
  "use strict";

  // --- Elements ---
  const uploadView = document.getElementById("upload-view");
  const resultView = document.getElementById("result-view");
  const downloadView = document.getElementById("download-view");

  const uploadForm = document.getElementById("upload-form");
  const dropZone = document.getElementById("drop-zone");
  const fileInput = document.getElementById("file-input");
  const maxSizeDisplay = document.getElementById("max-size-display");
  const fileSelected = document.getElementById("file-selected");
  const selectedFileName = document.getElementById("selected-file-name");
  const selectedFileSize = document.getElementById("selected-file-size");
  const uploadBtn = document.getElementById("upload-btn");
  const uploadBtnText = document.getElementById("upload-btn-text");

  const expireMode = document.getElementById("expire-mode");
  const expireDaysGroup = document.getElementById("expire-days-group");
  const expireDateGroup = document.getElementById("expire-date-group");
  const expireDays = document.getElementById("expire-days");
  const expireDaysError = document.getElementById("expire-days-error");
  const expireDate = document.getElementById("expire-date");
  const expireDateError = document.getElementById("expire-date-error");
  const maxDownloads = document.getElementById("max-downloads");
  const maxDownloadsError = document.getElementById("max-downloads-error");
  const passwordField = document.getElementById("password");
  const claimRequiredField = document.getElementById("claim-required");

  const progressArea = document.getElementById("progress-area");
  const progressFill = document.getElementById("progress-fill");
  const progressText = document.getElementById("progress-text");
  const formError = document.getElementById("form-error");
  const uploadStatus = document.getElementById("upload-status");
  const accountIndicator = document.getElementById("account-indicator");
  const accountOptionalNotice = document.getElementById("account-optional-notice");

  const shareLink = document.getElementById("share-link");
  const shareKey = document.getElementById("share-key");
  const claimCodeBox = document.getElementById("claim-code-box");
  const claimCodeField = document.getElementById("claim-code");
  const passwordBox = document.getElementById("password-box");
  const sharePassword = document.getElementById("share-password");
  const ownerTokenField = document.getElementById("owner-token");
  const revokeLinkField = document.getElementById("revoke-link");
  const copyFullBtn = document.getElementById("copy-full-btn");
  const copyLinkBtn = document.getElementById("copy-link-btn");
  const copyKeyBtn = document.getElementById("copy-key-btn");
  const copyClaimBtn = document.getElementById("copy-claim-btn");
  const copyPasswordBtn = document.getElementById("copy-password-btn");
  const copyOwnerBtn = document.getElementById("copy-owner-btn");
  const copyRevokeLinkBtn = document.getElementById("copy-revoke-link-btn");
  const blowFuseBtn = document.getElementById("blow-fuse-btn");
  const copyStatus = document.getElementById("copy-status");
  const resultHeading = document.getElementById("result-heading");
  const fuseDetails = document.getElementById("fuse-details");
  const newUploadBtn = document.getElementById("new-upload-btn");
  const uploadHeading = document.getElementById("upload-heading");

  const downloadInfo = document.getElementById("download-info");
  const downloadStatus = document.getElementById("download-status");
  const passwordPrompt = document.getElementById("password-prompt");
  const downloadPassword = document.getElementById("download-password");
  const claimPrompt = document.getElementById("claim-prompt");
  const downloadClaimCode = document.getElementById("download-claim-code");
  const downloadActionRow = document.getElementById("download-action-row");
  const downloadSubmitBtn = document.getElementById("download-submit-btn");
  const downloadNoPassword = document.getElementById("download-no-password");
  const downloadDirectBtn = document.getElementById("download-direct-btn");
  const downloadProgress = document.getElementById("download-progress");
  const downloadProgressFill = document.getElementById("download-progress-fill");
  const downloadProgressText = document.getElementById("download-progress-text");
  const downloadError = document.getElementById("download-error");
  const downloadHeading = document.getElementById("download-heading");

  function instanceName() {
    return (window.FuseBranding && window.FuseBranding.name) || "Fuse";
  }

  function baseTitle() {
    return instanceName() + " \u2014 Secure File Transfer";
  }
  const DEFAULT_UPLOAD_CHUNK_SIZE = 33554432;
  const ACCOUNT_SESSION_KEY = "fuseAccountSession";
  // Above this size, stream the download straight to disk (File System Access)
  // to dodge the browser's ~2 GiB blob-download limit. Smaller files use the
  // seamless anchor download — no save dialog, no file-access prompt.
  const STREAM_TO_DISK_THRESHOLD = 1610612736; // 1.5 GiB

  let selectedFile = null;
  let configuredMaxFileSize = null;
  let configuredUploadChunkSize = DEFAULT_UPLOAD_CHUNK_SIZE;
  let currentOwnerToken = "";
  let currentFuseId = "";
  let currentDownloadState = {
    fuseId: "",
    keyString: "",
    originalName: "",
    size: 0,
    requiresPassword: false,
    requiresClaim: false,
  };

  // --- Utility ---

  function formatSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + " MB";
    return (bytes / 1073741824).toFixed(2) + " GB";
  }

  function updateMaxSizeDisplay(bytes) {
    if (!maxSizeDisplay || !Number.isFinite(bytes) || bytes <= 0) return;
    maxSizeDisplay.textContent = formatSize(bytes);
  }

  async function loadConfig() {
    try {
      const response = await fetch("/api/config", { method: "GET" });
      if (!response.ok) return;
      const config = await response.json();
      if (Number.isFinite(config.maxFileSize) && config.maxFileSize > 0) {
        configuredMaxFileSize = config.maxFileSize;
        updateMaxSizeDisplay(configuredMaxFileSize);
      }
      if (Number.isFinite(config.uploadChunkSize) && config.uploadChunkSize > 0) {
        configuredUploadChunkSize = Math.floor(config.uploadChunkSize);
      }
      if (typeof config.requireClaimCodeDefault === "boolean") {
        claimRequiredField.checked = config.requireClaimCodeDefault;
      }
    } catch (_) {
      // Keep fallback text when config is unavailable.
    }
  }

  function toLocalDateInputValue(date) {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, "0");
    const day = String(date.getDate()).padStart(2, "0");
    return year + "-" + month + "-" + day;
  }

  function showView(view) {
    uploadView.hidden = true;
    resultView.hidden = true;
    downloadView.hidden = true;
    view.hidden = false;
  }

  function getDescribedByIds(field) {
    const value = field.getAttribute("aria-describedby") || "";
    return value.split(/\s+/).filter(Boolean);
  }

  function addDescribedById(field, id) {
    const ids = getDescribedByIds(field);
    if (ids.indexOf(id) === -1) {
      ids.push(id);
      field.setAttribute("aria-describedby", ids.join(" "));
    }
  }

  function removeDescribedById(field, id) {
    const ids = getDescribedByIds(field).filter(function (currentId) {
      return currentId !== id;
    });
    if (ids.length) {
      field.setAttribute("aria-describedby", ids.join(" "));
    } else {
      field.removeAttribute("aria-describedby");
    }
  }

  function setFieldError(field, errorElement, message) {
    field.setAttribute("aria-invalid", "true");
    if (errorElement && errorElement.id) {
      addDescribedById(field, errorElement.id);
      errorElement.textContent = message;
      errorElement.hidden = false;
    }
  }

  function clearFieldError(field, errorElement) {
    field.removeAttribute("aria-invalid");
    if (errorElement && errorElement.id) {
      removeDescribedById(field, errorElement.id);
      errorElement.textContent = "";
      errorElement.hidden = true;
    }
  }

  // --- Expiry Mode Toggle ---

  function setExpireDateError(message) {
    setFieldError(expireDate, expireDateError, message);
  }

  function clearExpireDateError() {
    clearFieldError(expireDate, expireDateError);
  }

  function announceUploadStatus(message) {
    if (!uploadStatus) return;
    if (uploadStatus.textContent === message) {
      uploadStatus.textContent = "";
      window.setTimeout(function () {
        uploadStatus.textContent = message;
      }, 30);
      return;
    }
    uploadStatus.textContent = message;
  }

  function announceStatus(statusEl, message) {
    if (!statusEl) return;
    if (statusEl.textContent === message) {
      statusEl.textContent = "";
      window.setTimeout(function () {
        statusEl.textContent = message;
      }, 30);
      return;
    }
    statusEl.textContent = message;
  }

  expireMode.addEventListener("change", function () {
    const mode = expireMode.value;
    expireDaysGroup.hidden = mode !== "days";
    expireDateGroup.hidden = mode !== "date";
    if (mode !== "date") {
      clearExpireDateError();
    }
  });

  expireDate.addEventListener("input", function () {
    clearExpireDateError();
  });

  downloadPassword.addEventListener("input", function () {
    downloadPassword.removeAttribute("aria-invalid");
  });

  // --- Drop Zone ---
  // The drop zone is a <label for="file-input">, so clicking/Enter/Space on it
  // is handled natively via the associated input. We only need drag-drop wiring.

  dropZone.addEventListener("dragover", function (e) {
    e.preventDefault();
    dropZone.classList.add("dragover");
  });

  dropZone.addEventListener("dragleave", function () {
    dropZone.classList.remove("dragover");
  });

  dropZone.addEventListener("drop", function (e) {
    e.preventDefault();
    dropZone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) {
      selectFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener("change", function () {
    if (fileInput.files.length > 0) {
      selectFile(fileInput.files[0]);
    }
  });

  function selectFile(file) {
    formError.textContent = "";

    if (configuredMaxFileSize && file.size > configuredMaxFileSize) {
      clearSelectedFile();
      fileInput.value = "";
      showFormError("File is too large. Maximum file size is " + formatSize(configuredMaxFileSize) + ".");
      fileInput.focus();
      return;
    }

    selectedFile = file;
    selectedFileName.textContent = file.name;
    selectedFileSize.textContent = formatSize(file.size);
    fileSelected.hidden = false;
    uploadBtn.disabled = false;
    uploadBtnText.textContent = "Encrypt & Upload";
  }

  function clearSelectedFile() {
    selectedFile = null;
    selectedFileName.textContent = "";
    selectedFileSize.textContent = "";
    fileSelected.hidden = true;
    uploadBtn.disabled = true;
    uploadBtnText.textContent = "Select a file first";
  }

  // --- Upload ---

  uploadForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    formError.textContent = "";
    clearFieldError(expireDays, expireDaysError);
    clearFieldError(maxDownloads, maxDownloadsError);
    clearExpireDateError();

    if (!selectedFile) {
      showFormError("Please choose a file to share.");
      fileInput.focus();
      return;
    }

    const mode = expireMode.value;
    let firstInvalidField = null;
    let firstErrorMessage = "";

    function markInvalid(field, errorElement, message) {
      setFieldError(field, errorElement, message);
      if (!firstInvalidField) {
        firstInvalidField = field;
        firstErrorMessage = message;
      }
    }

    let daysValue = null;
    if (mode === "days") {
      const rawDays = expireDays.value.trim();
      if (!/^\d+$/.test(rawDays)) {
        markInvalid(expireDays, expireDaysError, "Enter whole days between 1 and 365.");
      } else {
        const parsedDays = Number(rawDays);
        if (parsedDays < 1 || parsedDays > 365) {
          markInvalid(expireDays, expireDaysError, "Days until expiry must be between 1 and 365.");
        } else {
          daysValue = parsedDays;
        }
      }
    }

    const rawMaxDownloads = maxDownloads.value.trim();
    let maxDownloadsValue = null;
    if (!/^\d+$/.test(rawMaxDownloads)) {
      markInvalid(maxDownloads, maxDownloadsError, "Download limit must be a whole number 0 or greater.");
    } else {
      const parsedMaxDownloads = Number(rawMaxDownloads);
      if (parsedMaxDownloads < 0) {
        markInvalid(maxDownloads, maxDownloadsError, "Download limit must be a whole number 0 or greater.");
      } else {
        maxDownloadsValue = parsedMaxDownloads;
      }
    }

    // Validate expiry date if that mode is selected.
    if (mode === "date") {
      const todayStr = toLocalDateInputValue(new Date());
      if (!expireDate.value) {
        markInvalid(expireDate, expireDateError, "Please choose an expiry date.");
      }
      if (expireDate.value && expireDate.value < todayStr) {
        markInvalid(expireDate, expireDateError, "Expiry date must be today or later.");
      }
    }

    if (firstInvalidField) {
      showFormError(firstErrorMessage || "Please correct the highlighted fields.");
      firstInvalidField.focus();
      return;
    }

    uploadBtn.disabled = true;
    showProgressArea(true);
    announceUploadStatus("Encrypting file in your browser.");
    setProgress(progressFill, 10, "Encrypting file in your browser");

    try {
      // 1. Generate a per-file key. It lives only in the share-link fragment.
      const key = await FuseCrypto.generateKey();
      const keyString = await FuseCrypto.exportKey(key);

      // 2. Build upload metadata (independent of encryption).
      let expiresAt = null;
      if (mode === "days") {
        const d = new Date();
        d.setDate(d.getDate() + daysValue);
        expiresAt = d.toISOString().slice(0, 19).replace("T", " ");
      } else if (mode === "date") {
        expiresAt = new Date(expireDate.value + "T23:59:59").toISOString().slice(0, 19).replace("T", " ");
      }

      const uploadOptions = {
        expiresAt,
        maxDownloads: maxDownloadsValue > 0 ? String(maxDownloadsValue) : "",
        password: passwordField.value || "",
        claimRequired: claimRequiredField.checked ? "true" : "false",
      };

      // 3. Encrypt and upload chunk-by-chunk so the whole file is never buffered.
      const result = await encryptAndUpload(selectedFile, key, selectedFile.name, uploadOptions);
      announceUploadStatus("Upload complete. Generating your share link.");
      setProgress(progressFill, 100, "Upload complete");
      showResult(result, keyString);
      await storeVaultEntry(result, keyString);
    } catch (err) {
      const message = err && err.message
        ? err.message
        : "The browser could not read or encrypt this file.";
      showFormError("Upload failed: " + message);
      announceUploadStatus("Upload failed: " + message);
      setProgress(progressFill, 0, "");
      showProgressArea(false);
      uploadBtn.disabled = false;
      uploadBtn.focus();
    }
  });

  function appendUploadOptions(formData, uploadOptions) {
    if (uploadOptions.expiresAt) {
      formData.append("expiresAt", uploadOptions.expiresAt);
    }
    if (uploadOptions.maxDownloads) {
      formData.append("maxDownloads", uploadOptions.maxDownloads);
    }
    if (uploadOptions.password) {
      formData.append("password", uploadOptions.password);
    }
    formData.append("claimRequired", uploadOptions.claimRequired);
  }

  // Reads the optional account session shared with the account page (account.js,
  // same sessionStorage key). When present, uploads are attributed to the
  // account; absent or expired, the upload proceeds anonymously.
  // The account session lives in sessionStorage (tab-only) or localStorage
  // ("remember me"); read whichever is present and unexpired.
  function readAccountSession() {
    const stores = [sessionStorage, localStorage];
    for (let i = 0; i < stores.length; i += 1) {
      try {
        const raw = stores[i].getItem(ACCOUNT_SESSION_KEY);
        if (!raw) continue;
        const session = JSON.parse(raw);
        if (session && session.token && !(session.expiresAt && Date.now() > session.expiresAt)) {
          return session;
        }
      } catch (_) {
        // ignore and try the next store
      }
    }
    return null;
  }

  function getAccountToken() {
    const session = readAccountSession();
    return session ? session.token : "";
  }

  function getAccountVaultKey() {
    const session = readAccountSession();
    return session ? (session.vaultKey || "") : "";
  }

  // When logged in with a vault key, store an encrypted vault entry so the new
  // fuse appears on the dashboard with a recoverable link. Best-effort and
  // non-fatal — the share itself already works regardless.
  async function storeVaultEntry(result, keyString) {
    const token = getAccountToken();
    const vaultKeyB64 = getAccountVaultKey();
    if (!token || !vaultKeyB64) return;
    try {
      const vaultKey = await FuseCrypto.importVaultKey(vaultKeyB64);
      const blob = await FuseCrypto.encryptVaultEntry(vaultKey, JSON.stringify({
        key: keyString,
        ownerToken: result.ownerToken || "",
        name: selectedFile.name,
        url: result.url,
      }));
      await fetch("/api/account/vault", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
        body: JSON.stringify({ fuseId: result.id, blob }),
      });
    } catch (_) {
      // Non-fatal.
    }
  }

  function sendUploadRequest(method, url, body, options) {
    const requestOptions = options || {};

    return new Promise(function (resolve, reject) {
      const xhr = new XMLHttpRequest();
      xhr.open(method, url);

      if (requestOptions.headers) {
        Object.keys(requestOptions.headers).forEach(function (header) {
          xhr.setRequestHeader(header, requestOptions.headers[header]);
        });
      }

      const accountToken = getAccountToken();
      if (accountToken) {
        xhr.setRequestHeader("Authorization", "Bearer " + accountToken);
      }

      if (requestOptions.onUploadProgress) {
        xhr.upload.addEventListener("progress", function (evt) {
          if (evt.lengthComputable) {
            requestOptions.onUploadProgress(evt.loaded, evt.total);
          }
        });
      }

      xhr.addEventListener("load", function () {
        let result = null;
        try {
          result = xhr.responseText ? JSON.parse(xhr.responseText) : null;
        } catch (_) {
          result = null;
        }

        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(result);
          return;
        }

        reject(new Error((result && result.error) || "Upload failed."));
      });

      xhr.addEventListener("error", function () {
        reject(new Error("the connection closed before the server finished receiving the file."));
      });

      xhr.addEventListener("abort", function () {
        reject(new Error("upload cancelled before it finished."));
      });

      xhr.addEventListener("timeout", function () {
        reject(new Error("the server took too long to receive the file."));
      });

      xhr.send(body);
    });
  }

  // Plaintext chunk size: bounded by our memory budget and the server's
  // per-request limit (so each encrypted record fits one /api/upload/chunk POST).
  function uploadChunkPlaintextSize() {
    return Math.max(1, Math.min(FuseCrypto.DEFAULT_CHUNK_SIZE, configuredUploadChunkSize));
  }

  async function encryptAndUpload(file, key, originalName, uploadOptions) {
    const chunkSize = uploadChunkPlaintextSize();
    const noncePrefix = FuseCrypto.randomNoncePrefix();
    const header = FuseCrypto.buildHeader(chunkSize, noncePrefix);
    const numChunks = Math.max(1, Math.ceil(file.size / chunkSize));
    const encryptedTotal = header.length + file.size + numChunks * FuseCrypto.TAG_BYTES;

    if (encryptedTotal <= configuredUploadChunkSize) {
      return encryptAndUploadSingle(file, key, originalName, uploadOptions, header, noncePrefix, chunkSize, numChunks);
    }
    return encryptAndUploadChunked(file, key, originalName, uploadOptions, header, noncePrefix, chunkSize, numChunks, encryptedTotal);
  }

  // Reads one plaintext slice and returns its encrypted record (ciphertext+tag).
  // Only one slice is in memory at a time, so total file size never matters.
  async function encryptChunkAt(file, key, noncePrefix, index, chunkSize, numChunks) {
    const start = index * chunkSize;
    const slice = file.slice(start, Math.min(file.size, start + chunkSize));
    const plaintext = new Uint8Array(await slice.arrayBuffer());
    return FuseCrypto.encryptChunk(key, noncePrefix, index, index === numChunks - 1, plaintext);
  }

  async function encryptAndUploadSingle(file, key, originalName, uploadOptions, header, noncePrefix, chunkSize, numChunks) {
    const parts = [header];
    for (let index = 0; index < numChunks; index += 1) {
      parts.push(await encryptChunkAt(file, key, noncePrefix, index, chunkSize, numChunks));
      setProgress(progressFill, 10 + ((index + 1) / numChunks) * 40, "Encrypting file in your browser");
    }
    announceUploadStatus("Uploading encrypted file.");
    const blob = new Blob(parts, { type: "application/octet-stream" });
    return uploadEncryptedBlobSingle(blob, originalName, uploadOptions);
  }

  async function uploadEncryptedBlobSingle(blob, originalName, uploadOptions) {
    const formData = new FormData();
    formData.append("file", blob, originalName);
    appendUploadOptions(formData, uploadOptions);

    return sendUploadRequest("POST", "/api/upload", formData, {
      onUploadProgress: function (loaded, total) {
        const pct = 50 + (loaded / total) * 45;
        setProgress(progressFill, pct, "Uploading encrypted file");
      },
    });
  }

  async function encryptAndUploadChunked(file, key, originalName, uploadOptions, header, noncePrefix, chunkSize, numChunks, encryptedTotal) {
    announceUploadStatus("Uploading encrypted file.");
    setProgress(progressFill, 10, "Encrypting & uploading");

    const started = await sendUploadRequest(
      "POST",
      "/api/upload/start",
      JSON.stringify({ totalSize: encryptedTotal }),
      { headers: { "Content-Type": "application/json" } },
    );
    const uploadId = started && started.uploadId;
    if (!uploadId) {
      throw new Error("the server could not start a chunked upload.");
    }

    for (let index = 0; index < numChunks; index += 1) {
      const record = await encryptChunkAt(file, key, noncePrefix, index, chunkSize, numChunks);
      // The v2 header rides along with the first chunk so the assembled file
      // starts with it.
      const filePart = index === 0 ? new Blob([header, record]) : new Blob([record]);

      const formData = new FormData();
      formData.append("uploadId", uploadId);
      formData.append("chunkIndex", String(index));
      formData.append("totalChunks", String(numChunks));
      formData.append("totalSize", String(encryptedTotal));
      formData.append("file", filePart, originalName + ".part");

      await sendUploadRequest("POST", "/api/upload/chunk", formData, {
        onUploadProgress: function (loaded, total) {
          const within = total > 0 ? Math.min(loaded, total) / total : 0;
          const pct = 10 + ((index + within) / numChunks) * 85;
          setProgress(progressFill, pct, "Encrypting & uploading (" + (index + 1) + " of " + numChunks + ")");
        },
      });
    }

    setProgress(progressFill, 96, "Finalizing encrypted file");

    const completePayload = Object.assign({}, uploadOptions, {
      uploadId,
      originalName,
      totalSize: encryptedTotal,
      totalChunks: numChunks,
    });

    return sendUploadRequest(
      "POST",
      "/api/upload/complete",
      JSON.stringify(completePayload),
      { headers: { "Content-Type": "application/json" } },
    );
  }

  function showFormError(msg) {
    formError.textContent = msg;
  }

  function showProgressArea(show) {
    if (show) {
      progressArea.classList.remove("is-idle");
    } else {
      progressArea.classList.add("is-idle");
      progressText.textContent = "";
      announceUploadStatus("");
    }
  }

  function showDownloadProgressArea(show) {
    if (show) {
      downloadProgress.classList.remove("is-idle");
    } else {
      downloadProgress.classList.add("is-idle");
      downloadProgressText.textContent = "";
    }
  }

  function setProgress(el, pct, label) {
    const clamped = Math.min(100, Math.max(0, pct));
    el.style.width = clamped + "%";
    const bar = el.closest(".progress-bar");
    const rounded = Math.round(clamped);
    bar.setAttribute("aria-valuenow", rounded);
    if (typeof label === "string") {
      if (label) {
        bar.setAttribute("aria-valuetext", rounded + " percent \u2014 " + label);
      } else {
        bar.removeAttribute("aria-valuetext");
      }
      // Mirror the label visually in the accompanying <p>.
      if (el === progressFill) {
        progressText.textContent = label ? label + "\u2026" : "";
      } else if (el === downloadProgressFill) {
        downloadProgressText.textContent = label ? label + "\u2026" : "";
      }
    }
  }

  function showResult(result, keyString) {
    currentFuseId = result.id;
    currentOwnerToken = result.ownerToken || "";

    shareLink.value = result.url;
    shareKey.value = keyString;
    ownerTokenField.value = currentOwnerToken;
    const revokeBaseUrl = result.url.replace(/\/d\/[^/]+$/, "/revoke/" + encodeURIComponent(result.id));
    revokeLinkField.value = revokeBaseUrl + "#" + currentOwnerToken;

    claimCodeBox.hidden = !result.claimRequired;
    claimCodeField.value = result.claimCode || "";

    passwordBox.hidden = !passwordField.value;
    sharePassword.value = passwordField.value || "";

    fuseDetails.innerHTML = "";
    addDetail("File", selectedFile.name);
    addDetail("Size", formatSize(selectedFile.size));
    if (expireMode.value !== "none") {
      addDetail("Expires", expireMode.value === "days" ? expireDays.value + " days" : expireDate.value);
    }
    if (parseInt(maxDownloads.value, 10) > 0) {
      addDetail("Download limit", maxDownloads.value);
    }
    addDetail("Password", passwordField.value ? "Yes" : "No");
    addDetail("Claim code", result.claimRequired ? "Required on first download" : "Not required");

    showView(resultView);
    document.title = "Share link ready \u2014 " + instanceName();
    // Focus the heading first so screen readers announce the new view; sighted
    // users can still Tab into the link field immediately.
    resultHeading.focus();
  }

  function addDetail(label, value) {
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value;
    fuseDetails.appendChild(dt);
    fuseDetails.appendChild(dd);
  }

  // --- Copy Link ---

  let copyResetTimeout = null;
  let copyClearTimeout = null;

  function announceCopy(msg) {
    announceStatus(copyStatus, msg);
    if (copyClearTimeout) clearTimeout(copyClearTimeout);
    copyClearTimeout = setTimeout(function () {
      if (copyStatus.textContent === msg) copyStatus.textContent = "";
    }, 5000);
  }

  function scheduleLabelReset(button, originalLabel) {
    if (copyResetTimeout) clearTimeout(copyResetTimeout);
    copyResetTimeout = setTimeout(function () {
      button.textContent = originalLabel;
    }, 1800);
  }

  function copyValue(input, button, label, successMessage) {
    if (!input || !button) return;
    if (!navigator.clipboard) {
      input.focus();
      input.select();
      announceCopy("Clipboard not available. Value selected for manual copy.");
      return;
    }

    navigator.clipboard.writeText(input.value).then(function () {
      button.textContent = "Copied";
      announceCopy(successMessage);
      scheduleLabelReset(button, label);
    }).catch(function () {
      input.focus();
      input.select();
      announceCopy("Copy failed. Value selected for manual copy.");
    });
  }

  copyLinkBtn.addEventListener("click", function () {
    copyValue(shareLink, copyLinkBtn, "Copy URL", "Share URL copied.");
  });

  copyFullBtn.addEventListener("click", function () {
    const fullLink = shareLink.value + "#" + shareKey.value;
    if (!navigator.clipboard) {
      shareLink.focus();
      shareLink.select();
      announceCopy("Clipboard not available. Share URL selected for manual copy.");
      return;
    }
    navigator.clipboard.writeText(fullLink).then(function () {
      copyFullBtn.textContent = "Copied";
      announceCopy("Full link copied.");
      scheduleLabelReset(copyFullBtn, "Copy full link");
    }).catch(function () {
      shareLink.focus();
      shareLink.select();
      announceCopy("Copy failed. Share URL selected for manual copy.");
    });
  });

  copyKeyBtn.addEventListener("click", function () {
    copyValue(shareKey, copyKeyBtn, "Copy key", "Decryption key copied.");
  });

  copyClaimBtn.addEventListener("click", function () {
    copyValue(claimCodeField, copyClaimBtn, "Copy code", "Claim code copied.");
  });

  copyPasswordBtn.addEventListener("click", function () {
    copyValue(sharePassword, copyPasswordBtn, "Copy password", "Password copied.");
  });

  copyOwnerBtn.addEventListener("click", function () {
    copyValue(ownerTokenField, copyOwnerBtn, "Copy token", "Owner revoke token copied.");
  });

  copyRevokeLinkBtn.addEventListener("click", function () {
    copyValue(revokeLinkField, copyRevokeLinkBtn, "Copy revoke URL", "Emergency revoke URL copied.");
  });

  blowFuseBtn.addEventListener("click", async function () {
    if (!currentFuseId || !currentOwnerToken) {
      announceCopy("No active fuse available to revoke.");
      return;
    }

    const confirmed = window.confirm("Blow this fuse now? This cannot be undone.");
    if (!confirmed) return;

    blowFuseBtn.disabled = true;
    try {
      const response = await fetch("/api/fuse/" + encodeURIComponent(currentFuseId) + "/revoke", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ownerToken: currentOwnerToken }),
      });
      if (!response.ok) {
        const err = await response.json().catch(function () { return {}; });
        announceCopy(err.error || "Unable to blow fuse.");
        blowFuseBtn.disabled = false;
        return;
      }
      announceCopy("Fuse blown. Downloads are now blocked.");
      blowFuseBtn.textContent = "Fuse blown";
    } catch (error) {
      announceCopy("Unable to blow fuse due to a network error.");
      blowFuseBtn.disabled = false;
    }
  });

  // --- New Upload ---

  newUploadBtn.addEventListener("click", function () {
    clearSelectedFile();
    currentFuseId = "";
    currentOwnerToken = "";
    uploadForm.reset();
    claimCodeBox.hidden = true;
    passwordBox.hidden = true;
    shareLink.value = "";
    shareKey.value = "";
    claimCodeField.value = "";
    sharePassword.value = "";
    ownerTokenField.value = "";
    revokeLinkField.value = "";
    blowFuseBtn.disabled = false;
    blowFuseBtn.textContent = "Blow fuse now";
    showProgressArea(false);
    setProgress(progressFill, 0, "");
    formError.textContent = "";
    document.title = baseTitle();
    showView(uploadView);
    uploadHeading.setAttribute("tabindex", "-1");
    uploadHeading.focus();
  });

  // --- Download Flow ---

  async function initDownload() {
    const match = window.location.pathname.match(/^\/d\/(.+)$/);
    if (!match) return;

    const fuseId = match[1];
    const keyString = window.location.hash.slice(1);

    currentDownloadState.fuseId = fuseId;
    currentDownloadState.keyString = keyString;
    currentDownloadState.requiresPassword = false;
    currentDownloadState.requiresClaim = false;

    document.title = "Download file \u2014 " + instanceName();
    showView(downloadView);
    downloadHeading.focus();

    if (!keyString) {
      showDownloadError("Missing decryption key. The link may be incomplete.", true);
      return;
    }

    try {
      announceStatus(downloadStatus, "Loading file information.");
      const resp = await fetch("/api/fuse/" + encodeURIComponent(fuseId));
      if (!resp.ok) {
        const err = await resp.json().catch(function () { return {}; });
        showDownloadError(err.error || "File not found or has expired.", true);
        return;
      }

      const info = await resp.json();
      downloadInfo.innerHTML = "";

      const dl = document.createElement("dl");
      dl.className = "fuse-details";

      function addDl(label, value) {
        const dt = document.createElement("dt");
        dt.textContent = label;
        const dd = document.createElement("dd");
        dd.textContent = value;
        dl.appendChild(dt);
        dl.appendChild(dd);
      }

      addDl("File", info.originalName);
      addDl("Size", formatSize(info.size));
      if (info.expiresAt) addDl("Expires", new Date(info.expiresAt + "Z").toLocaleString());
      if (info.maxDownloads) addDl("Download limit", info.downloadCount + " / " + info.maxDownloads);
      if (info.claimRequired) addDl("Claim", info.claimed ? "Already claimed" : "Claim code required for first download");

      downloadInfo.appendChild(dl);
      document.title = "Download " + info.originalName + " \u2014 " + instanceName();
      // The fetch can take a noticeable time. The heading was already rendered
      // on view switch, so announce the metadata now that it is visible.
      downloadStatus.textContent = "File ready: " + info.originalName + ", " + formatSize(info.size) + ".";

      currentDownloadState.originalName = info.originalName || "";
      currentDownloadState.size = Number(info.size) || 0;
      currentDownloadState.requiresPassword = !!info.hasPassword;
      currentDownloadState.requiresClaim = !!info.claimRequired && !info.claimed;

      passwordPrompt.hidden = !currentDownloadState.requiresPassword;
      claimPrompt.hidden = !currentDownloadState.requiresClaim;
      downloadActionRow.hidden = false;
      downloadNoPassword.hidden = true;

      if (currentDownloadState.requiresClaim) {
        downloadClaimCode.focus();
      } else if (currentDownloadState.requiresPassword) {
        downloadPassword.focus();
      } else {
        downloadSubmitBtn.focus();
      }
    } catch (err) {
      showDownloadError("Could not load file information: " + err.message, true);
    }
  }

  async function performDownload() {
    const fuseId = currentDownloadState.fuseId;
    const keyString = currentDownloadState.keyString;
    const password = currentDownloadState.requiresPassword ? downloadPassword.value : null;
    const claimCode = currentDownloadState.requiresClaim ? downloadClaimCode.value : null;

    downloadError.textContent = "";
    downloadClaimCode.removeAttribute("aria-invalid");
    if (downloadSubmitBtn) downloadSubmitBtn.disabled = true;
    if (downloadDirectBtn) downloadDirectBtn.disabled = true;

    function reenable() {
      if (downloadSubmitBtn) downloadSubmitBtn.disabled = false;
      if (downloadDirectBtn) downloadDirectBtn.disabled = false;
    }

    // Only for large files: choose the destination now — while the click's user
    // activation is fresh — and stream to disk, dodging the ~2 GiB blob-download
    // limit. Cancelling aborts before any download starts. Smaller files skip the
    // picker entirely and download seamlessly.
    let fileHandle = null;
    if (window.showSaveFilePicker && currentDownloadState.size > STREAM_TO_DISK_THRESHOLD) {
      try {
        fileHandle = await window.showSaveFilePicker({ suggestedName: currentDownloadState.originalName || "download" });
      } catch (err) {
        if (err && err.name === "AbortError") {
          reenable();
          return;
        }
        fileHandle = null;
      }
    }

    showDownloadProgressArea(true);
    announceStatus(downloadStatus, "Download started.");
    setProgress(downloadProgressFill, 10, "Downloading encrypted file");

    try {
      const payload = {};
      if (password) payload.password = password;
      if (claimCode) payload.claimCode = String(claimCode).trim().toUpperCase();

      const resp = await fetch("/api/fuse/" + encodeURIComponent(fuseId) + "/download", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!resp.ok) {
        const err = await resp.json().catch(function () { return {}; });
        const isAuthFailure = err.needsPassword || resp.status === 401;
        if (err.needsClaimCode) {
          showDownloadError(err.error || "Claim code required.");
          announceStatus(downloadStatus, "Download failed: claim code required.");
          downloadClaimCode.setAttribute("aria-invalid", "true");
          downloadClaimCode.focus();
        } else if (err.needsPassword) {
          showDownloadError("Password required. Please enter the password and try again.");
          announceStatus(downloadStatus, "Download failed: password required.");
        } else {
          showDownloadError(err.error || "Download failed.");
          announceStatus(downloadStatus, "Download failed.");
        }
        showDownloadProgressArea(false);
        reenable();
        if (isAuthFailure && downloadPassword && !passwordPrompt.hidden) {
          downloadPassword.setAttribute("aria-invalid", "true");
          downloadPassword.focus();
        }
        return;
      }

      // Stream and decrypt chunk-by-chunk so the whole file is never held as one
      // ArrayBuffer (which caps near 2 GiB). Auto-detects v2 vs legacy v1.
      announceStatus(downloadStatus, "Downloading and decrypting.");
      let lastShownPercent = -1;
      const onProgress = function (loaded, total) {
        if (!total) return;
        const percent = Math.round(10 + (loaded / total) * 80);
        if (percent !== lastShownPercent) {
          lastShownPercent = percent;
          setProgress(downloadProgressFill, percent, "Downloading and decrypting");
        }
      };

      const contentLength = Number(resp.headers.get("Content-Length")) || 0;

      // Preferred path: stream decrypted chunks straight to disk. With no in-memory
      // blob, files larger than the browser's ~2 GiB blob-download limit work.
      if (fileHandle && resp.body && typeof resp.body.getReader === "function") {
        const writable = await fileHandle.createWritable();
        try {
          await FuseCrypto.decryptStream(resp.body, keyString, onProgress, contentLength, function (chunk) {
            return writable.write(chunk);
          });
          await writable.close();
        } catch (err) {
          try { await writable.abort(); } catch (_) {}
          throw err;
        }
        setProgress(downloadProgressFill, 100, "Download complete");
        announceStatus(downloadStatus, "Download complete. File decrypted successfully.");
        return;
      }

      // Fallback: assemble a Blob and use an anchor download (works under ~2 GiB).
      let blob;
      if (resp.body && typeof resp.body.getReader === "function") {
        blob = await FuseCrypto.decryptStreamToBlob(resp.body, keyString, onProgress, contentLength);
      } else {
        const all = new Uint8Array(await resp.arrayBuffer());
        onProgress(all.length, contentLength || all.length);
        blob = await FuseCrypto.decryptBufferToBlob(all, keyString);
      }

      setProgress(downloadProgressFill, 95, "Preparing file");
      announceStatus(downloadStatus, "Preparing file.");

      // Extract filename from Content-Disposition header
      const disposition = resp.headers.get("Content-Disposition") || "";
      let filename = currentDownloadState.originalName || "download";
      const filenameMatch = disposition.match(/filename="?([^";\n]+)"?/);
      if (filenameMatch) {
        try {
          filename = decodeURIComponent(filenameMatch[1]);
        } catch (_) {
          filename = filenameMatch[1];
        }
      }

      // Trigger download
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setProgress(downloadProgressFill, 100, "Download complete");
      announceStatus(downloadStatus, "Download complete. File decrypted successfully.");
    } catch (err) {
      // Surface the cause in the page's alert region so it is announced to
      // screen readers, rather than only in the browser console (which they
      // cannot reach). The error name distinguishes the common causes.
      const name = (err && err.name) || "";
      let message;
      if (name === "OperationError") {
        message = "Decryption failed: the key in the link may be wrong or incomplete, or the file may be corrupted.";
      } else if (name === "QuotaExceededError") {
        message = "Could not save the file: your device is out of storage space.";
      } else {
        message = "The download did not finish" + (name ? " (" + name + ")" : "") + " — it may have been interrupted. Please try again.";
      }
      showDownloadError(message);
      announceStatus(downloadStatus, "Download failed.");
      showDownloadProgressArea(false);
      reenable();
    }
  }

  downloadSubmitBtn.addEventListener("click", function () {
    performDownload();
  });

  downloadDirectBtn.addEventListener("click", function () {
    performDownload();
  });

  downloadPassword.addEventListener("keydown", function (e) {
    if (e.key === "Enter") {
      e.preventDefault();
      performDownload();
    }
  });

  downloadClaimCode.addEventListener("keydown", function (e) {
    if (e.key === "Enter") {
      e.preventDefault();
      performDownload();
    }
  });

  function showDownloadError(msg, shouldFocusAlert) {
    downloadError.textContent = msg;
    if (shouldFocusAlert) {
      if (!downloadError.hasAttribute("tabindex")) {
        downloadError.setAttribute("tabindex", "-1");
      }
      downloadError.focus();
    }
  }

  // --- Init ---

  const isDownloadPage = window.location.pathname.startsWith("/d/");
  if (isDownloadPage) {
    initDownload();
  } else {
    showView(uploadView);
    loadConfig();
    const loggedIn = !!getAccountToken();
    if (accountIndicator) accountIndicator.hidden = !loggedIn;
    if (accountOptionalNotice) accountOptionalNotice.hidden = loggedIn;
  }

  // Set min date for date picker to today
  const today = toLocalDateInputValue(new Date());
  expireDate.setAttribute("min", today);
})();
