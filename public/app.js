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
  const expireDate = document.getElementById("expire-date");
  const expireDateError = document.getElementById("expire-date-error");
  const maxDownloads = document.getElementById("max-downloads");
  const passwordField = document.getElementById("password");

  const progressArea = document.getElementById("progress-area");
  const progressFill = document.getElementById("progress-fill");
  const progressText = document.getElementById("progress-text");
  const formError = document.getElementById("form-error");
  const uploadStatus = document.getElementById("upload-status");

  const shareLink = document.getElementById("share-link");
  const copyBtn = document.getElementById("copy-btn");
  const copyStatus = document.getElementById("copy-status");
  const resultHeading = document.getElementById("result-heading");
  const fuseDetails = document.getElementById("fuse-details");
  const newUploadBtn = document.getElementById("new-upload-btn");
  const uploadHeading = document.getElementById("upload-heading");

  const downloadInfo = document.getElementById("download-info");
  const downloadStatus = document.getElementById("download-status");
  const passwordPrompt = document.getElementById("password-prompt");
  const downloadPassword = document.getElementById("download-password");
  const downloadSubmitBtn = document.getElementById("download-submit-btn");
  const downloadNoPassword = document.getElementById("download-no-password");
  const downloadDirectBtn = document.getElementById("download-direct-btn");
  const downloadProgress = document.getElementById("download-progress");
  const downloadProgressFill = document.getElementById("download-progress-fill");
  const downloadProgressText = document.getElementById("download-progress-text");
  const downloadError = document.getElementById("download-error");

  const BASE_TITLE = "Fuse \u2014 Secure File Transfer";

  let selectedFile = null;

  // --- Crypto Helpers (Web Crypto API, AES-256-GCM) ---

  async function generateKey() {
    return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  }

  async function exportKey(key) {
    const raw = await crypto.subtle.exportKey("raw", key);
    return bufferToBase64Url(raw);
  }

  async function importKey(base64Url) {
    const raw = base64UrlToBuffer(base64Url);
    return crypto.subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  }

  async function encryptFile(file, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = await file.arrayBuffer();
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
    // Prepend IV to ciphertext so we can extract it on decrypt
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encrypted), iv.length);
    return combined;
  }

  async function decryptData(combinedBuffer, key) {
    const combined = new Uint8Array(combinedBuffer);
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    return crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  }

  function bufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function base64UrlToBuffer(base64Url) {
    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

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
      updateMaxSizeDisplay(config.maxFileSize);
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

  // --- Expiry Mode Toggle ---

  function setExpireDateError(message) {
    expireDate.setAttribute("aria-invalid", "true");
    expireDate.setAttribute("aria-describedby", "expire-date-error");
    expireDateError.textContent = message;
    expireDateError.hidden = false;
  }

  function clearExpireDateError() {
    expireDate.removeAttribute("aria-invalid");
    expireDate.removeAttribute("aria-describedby");
    expireDateError.textContent = "";
    expireDateError.hidden = true;
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
    selectedFile = file;
    selectedFileName.textContent = file.name;
    selectedFileSize.textContent = formatSize(file.size);
    fileSelected.hidden = false;
    uploadBtn.disabled = false;
    uploadBtnText.textContent = "Encrypt & Upload";
  }

  // --- Upload ---

  uploadForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    formError.textContent = "";
    if (!selectedFile) {
      showFormError("Please choose a file to share.");
      fileInput.focus();
      return;
    }

    // Validate expiry date if that mode is selected.
    const mode = expireMode.value;
    if (mode === "date") {
      const todayStr = toLocalDateInputValue(new Date());
      if (!expireDate.value) {
        showFormError("Please choose an expiry date.");
        setExpireDateError("Please choose an expiry date.");
        expireDate.focus();
        return;
      }
      if (expireDate.value < todayStr) {
        showFormError("Expiry date must be today or later.");
        setExpireDateError("Expiry date must be today or later.");
        expireDate.focus();
        return;
      }
      clearExpireDateError();
    }

    uploadBtn.disabled = true;
    showProgressArea(true);
    announceUploadStatus("Encrypting file in your browser.");
    setProgress(progressFill, 10, "Encrypting file in your browser");

    try {
      // 1. Generate encryption key
      const key = await generateKey();
      const keyString = await exportKey(key);

      // 2. Encrypt file client-side
      setProgress(progressFill, 20, "Encrypting file in your browser");
      const encryptedData = await encryptFile(selectedFile, key);
      announceUploadStatus("Uploading encrypted file.");
      setProgress(progressFill, 50, "Uploading encrypted file");

      // 3. Build form data
      const blob = new Blob([encryptedData], { type: "application/octet-stream" });
      const formData = new FormData();
      formData.append("file", blob, selectedFile.name);

      // Compute expiry
      let expiresAt = null;
      if (mode === "days") {
        const days = parseInt(expireDays.value, 10) || 7;
        const d = new Date();
        d.setDate(d.getDate() + days);
        expiresAt = d.toISOString().slice(0, 19).replace("T", " ");
      } else if (mode === "date") {
        expiresAt = new Date(expireDate.value + "T23:59:59").toISOString().slice(0, 19).replace("T", " ");
      }

      if (expiresAt) {
        formData.append("expiresAt", expiresAt);
      }

      const dl = parseInt(maxDownloads.value, 10);
      if (dl > 0) {
        formData.append("maxDownloads", String(dl));
      }

      if (passwordField.value) {
        formData.append("password", passwordField.value);
      }

      // 4. Upload
      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/upload");

      xhr.upload.addEventListener("progress", function (evt) {
        if (evt.lengthComputable) {
          const pct = 50 + (evt.loaded / evt.total) * 45;
          setProgress(progressFill, pct, "Uploading encrypted file");
        }
      });

      xhr.addEventListener("load", function () {
        if (xhr.status >= 200 && xhr.status < 300) {
          announceUploadStatus("Upload complete. Generating your share link.");
          setProgress(progressFill, 100, "Upload complete");
          const result = JSON.parse(xhr.responseText);
          showResult(result, keyString);
        } else {
          let message = "Upload failed.";
          try {
            const err = JSON.parse(xhr.responseText);
            if (err && err.error) message = "Upload failed: " + err.error;
          } catch (_) { /* ignore */ }
          showFormError(message);
          announceUploadStatus(message);
          setProgress(progressFill, 0, "");
          showProgressArea(false);
          uploadBtn.disabled = false;
          uploadBtn.focus();
        }
      });

      xhr.addEventListener("error", function () {
        showFormError("Upload failed: network error. Please check your connection and try again.");
        announceUploadStatus("Upload failed due to a network error.");
        setProgress(progressFill, 0, "");
        showProgressArea(false);
        uploadBtn.disabled = false;
        uploadBtn.focus();
      });

      xhr.send(formData);
    } catch (err) {
      showFormError("Error: " + err.message);
      announceUploadStatus("Upload failed: " + err.message);
      setProgress(progressFill, 0, "");
      showProgressArea(false);
      uploadBtn.disabled = false;
      uploadBtn.focus();
    }
  });

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
    const fullUrl = result.url + "#" + keyString;
    shareLink.value = fullUrl;

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

    showView(resultView);
    document.title = "Share link ready \u2014 Fuse";
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

  copyBtn.addEventListener("click", function () {
    function announce(msg) {
      // Clear+reset when needed so identical messages still get announced.
      announceStatus(copyStatus, msg);
      if (copyClearTimeout) clearTimeout(copyClearTimeout);
      copyClearTimeout = setTimeout(function () {
        if (copyStatus.textContent === msg) copyStatus.textContent = "";
      }, 5000);
    }
    function scheduleLabelReset() {
      if (copyResetTimeout) clearTimeout(copyResetTimeout);
      copyResetTimeout = setTimeout(function () { copyBtn.textContent = "Copy"; }, 2000);
    }

    if (!navigator.clipboard) {
      shareLink.focus();
      shareLink.select();
      announce("Clipboard not available. Share link is selected \u2014 press Ctrl or Command plus C to copy.");
      return;
    }

    navigator.clipboard.writeText(shareLink.value).then(function () {
      copyBtn.textContent = "Copied";
      announce("Share link copied to clipboard.");
      scheduleLabelReset();
    }).catch(function () {
      shareLink.focus();
      shareLink.select();
      announce("Copy failed. Share link is selected \u2014 press Ctrl or Command plus C to copy.");
    });
  });

  // --- New Upload ---

  newUploadBtn.addEventListener("click", function () {
    selectedFile = null;
    uploadForm.reset();
    fileSelected.hidden = true;
    uploadBtn.disabled = true;
    uploadBtnText.textContent = "Select a file first";
    showProgressArea(false);
    setProgress(progressFill, 0, "");
    formError.textContent = "";
    document.title = BASE_TITLE;
    showView(uploadView);
    uploadHeading.setAttribute("tabindex", "-1");
    uploadHeading.focus();
  });

  // --- Download Flow ---

  let downloadHandlersAttached = false;

  async function initDownload() {
    const match = window.location.pathname.match(/^\/d\/(.+)$/);
    if (!match) return;

    const fuseId = match[1];
    const keyString = window.location.hash.slice(1);

    document.title = "Download file \u2014 Fuse";
    showView(downloadView);

    if (!keyString) {
      showDownloadError("Missing decryption key. The link may be incomplete.");
      return;
    }

    try {
      announceStatus(downloadStatus, "Loading file information.");
      const resp = await fetch("/api/fuse/" + encodeURIComponent(fuseId));
      if (!resp.ok) {
        const err = await resp.json().catch(function () { return {}; });
        showDownloadError(err.error || "File not found or has expired.");
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

      downloadInfo.appendChild(dl);
      document.title = "Download " + info.originalName + " \u2014 Fuse";
      // The fetch can take a noticeable time. The heading was already rendered
      // on view switch, so announce the metadata now that it is visible.
      downloadStatus.textContent = "File ready: " + info.originalName + ", " + formatSize(info.size) + ".";

      if (info.hasPassword) {
        passwordPrompt.hidden = false;
        downloadPassword.focus();

        if (!downloadHandlersAttached) {
          downloadSubmitBtn.addEventListener("click", function () {
            performDownload(fuseId, keyString, downloadPassword.value);
          });
          downloadPassword.addEventListener("keydown", function (e) {
            if (e.key === "Enter") {
              e.preventDefault();
              performDownload(fuseId, keyString, downloadPassword.value);
            }
          });
          downloadHandlersAttached = true;
        }
      } else {
        downloadNoPassword.hidden = false;
        downloadDirectBtn.focus();
        if (!downloadHandlersAttached) {
          downloadDirectBtn.addEventListener("click", function () {
            performDownload(fuseId, keyString, null);
          });
          downloadHandlersAttached = true;
        }
      }
    } catch (err) {
      showDownloadError("Could not load file information: " + err.message);
    }
  }

  async function performDownload(fuseId, keyString, password) {
    downloadError.textContent = "";
    if (downloadSubmitBtn) downloadSubmitBtn.disabled = true;
    if (downloadDirectBtn) downloadDirectBtn.disabled = true;
    showDownloadProgressArea(true);
    announceStatus(downloadStatus, "Download started.");
    setProgress(downloadProgressFill, 10, "Downloading encrypted file");

    try {
      const body = password ? JSON.stringify({ password }) : "{}";
      const resp = await fetch("/api/fuse/" + encodeURIComponent(fuseId) + "/download", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
      });

      if (!resp.ok) {
        const err = await resp.json().catch(function () { return {}; });
        const isAuthFailure = err.needsPassword || resp.status === 401 || resp.status === 403;
        if (err.needsPassword) {
          showDownloadError("Password required. Please enter the password and try again.");
          announceStatus(downloadStatus, "Download failed: password required.");
        } else {
          showDownloadError(err.error || "Download failed.");
          announceStatus(downloadStatus, "Download failed.");
        }
        showDownloadProgressArea(false);
        if (downloadSubmitBtn) downloadSubmitBtn.disabled = false;
        if (downloadDirectBtn) downloadDirectBtn.disabled = false;
        if (isAuthFailure && downloadPassword && !passwordPrompt.hidden) {
          downloadPassword.setAttribute("aria-invalid", "true");
          downloadPassword.focus();
        }
        return;
      }

      setProgress(downloadProgressFill, 50, "Decrypting file in your browser");
        announceStatus(downloadStatus, "Decrypting file.");

      const encryptedBuffer = await resp.arrayBuffer();
      setProgress(downloadProgressFill, 70, "Decrypting file in your browser");

      const key = await importKey(keyString);
      const decrypted = await decryptData(encryptedBuffer, key);
      setProgress(downloadProgressFill, 90, "Preparing file");
      announceStatus(downloadStatus, "Preparing file.");

      // Extract filename from Content-Disposition header
      const disposition = resp.headers.get("Content-Disposition") || "";
      let filename = "download";
      const filenameMatch = disposition.match(/filename="?([^";\n]+)"?/);
      if (filenameMatch) {
        filename = decodeURIComponent(filenameMatch[1]);
      }

      // Trigger download
      const blob = new Blob([decrypted]);
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
      showDownloadError("Decryption failed. The link may be invalid or corrupted.");
      announceStatus(downloadStatus, "Download failed.");
      showDownloadProgressArea(false);
      if (downloadSubmitBtn) downloadSubmitBtn.disabled = false;
      if (downloadDirectBtn) downloadDirectBtn.disabled = false;
    }
  }

  function showDownloadError(msg) {
    // role="alert" announces the message automatically; no need to steal focus.
    downloadError.textContent = msg;
  }

  // --- Init ---

  const isDownloadPage = window.location.pathname.startsWith("/d/");
  if (isDownloadPage) {
    initDownload();
  } else {
    showView(uploadView);
    loadConfig();
  }

  // Set min date for date picker to today
  const today = toLocalDateInputValue(new Date());
  expireDate.setAttribute("min", today);
})();
