(function () {
  "use strict";

  // Shared with the upload page (app.js, Phase 6) so an upload made while the
  // dashboard tab is open is attributed to the account. sessionStorage clears on
  // tab close, which suits a shared machine.
  const SESSION_KEY = "fuseAccountSession";

  // --- Elements ---
  const gateView = document.getElementById("gate-view");
  const createdView = document.getElementById("created-view");
  const dashboardView = document.getElementById("dashboard-view");

  const gateHeading = document.getElementById("gate-heading");
  const createBtn = document.getElementById("create-btn");
  const createError = document.getElementById("create-error");
  const loginForm = document.getElementById("login-form");
  const loginNumber = document.getElementById("login-number");
  const loginBtn = document.getElementById("login-btn");
  const loginError = document.getElementById("login-error");
  const gateStatus = document.getElementById("gate-status");
  const rememberMe = document.getElementById("remember-me");
  const rememberRow = document.getElementById("remember-row");

  const createdHeading = document.getElementById("created-heading");
  const newNumberField = document.getElementById("new-number");
  const copyNumberBtn = document.getElementById("copy-number-btn");
  const downloadNumberBtn = document.getElementById("download-number-btn");
  const printNumberBtn = document.getElementById("print-number-btn");
  const confirmForm = document.getElementById("confirm-form");
  const confirmNumber = document.getElementById("confirm-number");
  const confirmError = document.getElementById("confirm-error");
  const createdStatus = document.getElementById("created-status");

  const dashboardHeading = document.getElementById("dashboard-heading");
  const refreshBtn = document.getElementById("refresh-btn");
  const logoutBtn = document.getElementById("logout-btn");
  const fuseList = document.getElementById("fuse-list");
  const deleteToggleBtn = document.getElementById("delete-toggle-btn");
  const deleteForm = document.getElementById("delete-form");
  const deleteNumber = document.getElementById("delete-number");
  const deleteConfirmBtn = document.getElementById("delete-confirm-btn");
  const deleteCancelBtn = document.getElementById("delete-cancel-btn");
  const deleteError = document.getElementById("delete-error");
  const dashboardStatus = document.getElementById("dashboard-status");

  // Held only in memory between account creation and the save-confirmation step;
  // never persisted, matching the server which never stores it either.
  let pendingNumber = "";
  // How many digits to generate; refreshed from /api/config (server-advertised).
  let accountNumberDigits = 20;
  let rememberDays = 30;

  // --- Helpers ---

  function normalizeDigits(value) {
    return String(value || "").replace(/\D/g, "");
  }

  function formatNumber(digits) {
    return digits.replace(/(\d{4})(?=\d)/g, "$1 ");
  }

  function formatSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + " MB";
    return (bytes / 1073741824).toFixed(2) + " GB";
  }

  function announce(el, message) {
    if (!el) return;
    if (el.textContent === message) {
      el.textContent = "";
      window.setTimeout(function () { el.textContent = message; }, 30);
    } else {
      el.textContent = message;
    }
  }

  function setError(el, message) {
    if (el) el.textContent = message || "";
  }

  function showView(view) {
    [gateView, createdView, dashboardView].forEach(function (v) {
      v.hidden = v !== view;
    });
  }

  // --- Session ---

  function readSessionFrom(store) {
    try {
      const raw = store.getItem(SESSION_KEY);
      if (!raw) return null;
      const session = JSON.parse(raw);
      if (!session || !session.token || (session.expiresAt && Date.now() > session.expiresAt)) {
        store.removeItem(SESSION_KEY);
        return null;
      }
      return session;
    } catch (_) {
      return null;
    }
  }

  function loadSession() {
    // A "remember me" session lives in localStorage; a tab-only one in sessionStorage.
    return readSessionFrom(sessionStorage) || readSessionFrom(localStorage);
  }

  function saveSession(token, expiresAt, vaultKey, remember) {
    const data = JSON.stringify({ token: token, expiresAt: expiresAt, vaultKey: vaultKey || "" });
    if (remember) {
      localStorage.setItem(SESSION_KEY, data);
      sessionStorage.removeItem(SESSION_KEY);
    } else {
      sessionStorage.setItem(SESSION_KEY, data);
      localStorage.removeItem(SESSION_KEY);
    }
  }

  function clearSession() {
    sessionStorage.removeItem(SESSION_KEY);
    localStorage.removeItem(SESSION_KEY);
  }

  function authHeaders() {
    const session = loadSession();
    return session ? { Authorization: "Bearer " + session.token } : {};
  }

  // Imports the vault key stashed at login so the dashboard can decrypt stored
  // share secrets. Null when not logged in or no vault key is present.
  async function getVaultKey() {
    const session = loadSession();
    if (!session || !session.vaultKey) return null;
    try {
      return await FuseCrypto.importVaultKey(session.vaultKey);
    } catch (_) {
      return null;
    }
  }

  async function loadAccountConfig() {
    try {
      const resp = await fetch("/api/config");
      if (resp.ok) {
        const cfg = await resp.json();
        if (Number.isFinite(cfg.accountNumberDigits) && cfg.accountNumberDigits >= 16) {
          accountNumberDigits = cfg.accountNumberDigits;
        }
        if (Number.isFinite(cfg.rememberDays)) {
          rememberDays = cfg.rememberDays;
        }
      }
    } catch (_) {
      // Keep the defaults when config is unavailable.
    }
    // Reflect the server-configured values in the UI.
    document.querySelectorAll("[data-account-digits]").forEach(function (el) {
      el.textContent = String(accountNumberDigits);
    });
    document.querySelectorAll("[data-remember-days]").forEach(function (el) {
      el.textContent = String(rememberDays);
    });
    if (rememberRow) rememberRow.hidden = !(rememberDays > 0);
  }

  // --- View transitions ---

  function showGate(message) {
    showView(gateView);
    loginNumber.value = "";
    loginNumber.removeAttribute("aria-invalid");
    setError(loginError, "");
    setError(createError, "");
    createBtn.disabled = false;
    loginBtn.disabled = false;
    if (message) announce(gateStatus, message);
    gateHeading.focus();
  }

  function goToDashboard() {
    deleteForm.hidden = true;
    deleteNumber.value = "";
    setError(deleteError, "");
    deleteConfirmBtn.disabled = false;
    showView(dashboardView);
    dashboardHeading.focus();
    loadFuses();
  }

  // --- Create ---

  createBtn.addEventListener("click", async function () {
    setError(createError, "");
    createBtn.disabled = true;
    announce(gateStatus, "Creating your account. This can take a moment.");
    try {
      const remember = !!(rememberMe && rememberMe.checked);
      // The number is generated and the keys derived here; only the authenticator
      // is sent. The server never sees the number or the vault key.
      const number = FuseCrypto.generateAccountNumber(accountNumberDigits);
      const keys = await FuseCrypto.deriveAccountKeys(number);
      const resp = await fetch("/api/account/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ authenticator: keys.authenticator, remember: remember }),
      });
      const data = await resp.json().catch(function () { return {}; });
      if (!resp.ok) throw new Error(data.error || "Could not create account.");

      pendingNumber = number;
      saveSession(data.sessionToken, data.expiresAt, keys.vaultKeyB64, remember);
      newNumberField.value = formatNumber(number);
      showView(createdView);
      createdHeading.focus();
    } catch (err) {
      setError(createError, err.message);
      createBtn.disabled = false;
    }
  });

  copyNumberBtn.addEventListener("click", function () {
    if (!navigator.clipboard) {
      newNumberField.focus();
      newNumberField.select();
      announce(createdStatus, "Clipboard unavailable. The number is selected for manual copy.");
      return;
    }
    navigator.clipboard.writeText(pendingNumber).then(function () {
      copyNumberBtn.textContent = "Copied";
      announce(createdStatus, "Account number copied.");
      window.setTimeout(function () { copyNumberBtn.textContent = "Copy"; }, 1800);
    }).catch(function () {
      newNumberField.focus();
      newNumberField.select();
      announce(createdStatus, "Copy failed. The number is selected for manual copy.");
    });
  });

  downloadNumberBtn.addEventListener("click", function () {
    const brand = (window.FuseBranding && window.FuseBranding.name) || "Fuse";
    const text = brand + " account number\n\n" + formatNumber(pendingNumber) +
      "\n\nDigits only: " + pendingNumber +
      "\n\nThis is the ONLY way to access your " + brand + " account.\n" +
      "We cannot reset it, email it, or look it up. Keep it somewhere safe and private.\n";
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "fuse-account-number.txt";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    announce(createdStatus, "Recovery sheet downloaded.");
  });

  printNumberBtn.addEventListener("click", function () {
    window.print();
  });

  confirmNumber.addEventListener("input", function () {
    confirmNumber.removeAttribute("aria-invalid");
    setError(confirmError, "");
  });

  confirmForm.addEventListener("submit", function (e) {
    e.preventDefault();
    setError(confirmError, "");
    if (normalizeDigits(confirmNumber.value) !== pendingNumber) {
      setError(confirmError, "That does not match. Check the number you saved and try again.");
      confirmNumber.setAttribute("aria-invalid", "true");
      confirmNumber.focus();
      return;
    }
    pendingNumber = "";
    confirmNumber.value = "";
    newNumberField.value = "";
    goToDashboard();
  });

  // --- Login ---

  loginNumber.addEventListener("input", function () {
    loginNumber.removeAttribute("aria-invalid");
    setError(loginError, "");
  });

  loginForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    setError(loginError, "");
    const number = normalizeDigits(loginNumber.value);
    if (!number) {
      setError(loginError, "Enter your account number.");
      loginNumber.focus();
      return;
    }
    loginBtn.disabled = true;
    announce(gateStatus, "Logging in. This can take a moment.");
    try {
      const remember = !!(rememberMe && rememberMe.checked);
      const keys = await FuseCrypto.deriveAccountKeys(number);
      const resp = await fetch("/api/account/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ authenticator: keys.authenticator, remember: remember }),
      });
      const data = await resp.json().catch(function () { return {}; });
      if (!resp.ok) throw new Error(data.error || "Login failed.");
      saveSession(data.sessionToken, data.expiresAt, keys.vaultKeyB64, remember);
      loginNumber.value = "";
      goToDashboard();
    } catch (err) {
      setError(loginError, err.message);
      loginNumber.setAttribute("aria-invalid", "true");
      loginNumber.focus();
      loginBtn.disabled = false;
    }
  });

  // --- Dashboard ---

  async function loadFuses() {
    announce(dashboardStatus, "Loading your fuses.");
    let data;
    try {
      const resp = await fetch("/api/account/fuses", { headers: authHeaders() });
      if (resp.status === 401) {
        clearSession();
        showGate("Your session expired. Please log in again.");
        return;
      }
      data = await resp.json().catch(function () { return {}; });
      if (!resp.ok) throw new Error(data.error || "Could not load your fuses.");
    } catch (err) {
      fuseList.innerHTML = "";
      const p = document.createElement("p");
      p.className = "field-error";
      p.setAttribute("role", "alert");
      p.textContent = err.message;
      fuseList.appendChild(p);
      return;
    }

    const fuses = data.fuses || [];
    // Decrypt any stored vault entries locally so we can rebuild full share
    // links. The key never left the browser, so only this session can read them.
    const vaultKey = await getVaultKey();
    if (vaultKey) {
      for (const fuse of fuses) {
        if (!fuse.vaultBlob) continue;
        try {
          fuse.secrets = JSON.parse(await FuseCrypto.decryptVaultEntry(vaultKey, fuse.vaultBlob));
        } catch (_) {
          fuse.secrets = null;
        }
      }
    }
    renderFuses(fuses);
  }

  function buildMeta(fuse) {
    const parts = [formatSize(fuse.size)];
    if (fuse.maxDownloads) {
      parts.push(fuse.downloadCount + " / " + fuse.maxDownloads + " downloads");
    } else {
      parts.push(fuse.downloadCount + (fuse.downloadCount === 1 ? " download" : " downloads"));
    }
    if (fuse.expiresAt) {
      parts.push("expires " + new Date(fuse.expiresAt + "Z").toLocaleString());
    }
    if (fuse.claimRequired) {
      parts.push(fuse.claimed ? "claimed" : "claim code required");
    }
    return parts.join(" · ");
  }

  function copyShareLink(fuse, btn) {
    const link = fuse.secrets.url + "#" + fuse.secrets.key;
    if (!navigator.clipboard) {
      window.prompt("Copy this share link:", link);
      return;
    }
    navigator.clipboard.writeText(link).then(function () {
      btn.textContent = "Copied";
      announce(dashboardStatus, "Share link copied for " + fuse.originalName + ".");
      window.setTimeout(function () { btn.textContent = "Copy link"; }, 1800);
    }).catch(function () {
      window.prompt("Copy this share link:", link);
    });
  }

  function renderFuseItem(fuse) {
    const item = document.createElement("div");
    item.className = "fuse-item";

    const main = document.createElement("div");
    main.className = "fuse-item-main";

    const name = document.createElement("p");
    name.className = "fuse-item-name";
    name.textContent = fuse.originalName;
    main.appendChild(name);

    const meta = document.createElement("p");
    meta.className = "fuse-item-meta";
    meta.textContent = buildMeta(fuse);
    main.appendChild(meta);

    item.appendChild(main);

    const actions = document.createElement("div");
    actions.className = "fuse-item-actions";

    // Present only when this session holds the vault key and an entry exists.
    if (fuse.secrets && fuse.secrets.url && fuse.secrets.key) {
      const copyBtn = document.createElement("button");
      copyBtn.type = "button";
      copyBtn.className = "secondary";
      copyBtn.textContent = "Copy link";
      copyBtn.setAttribute("aria-label", "Copy share link for " + fuse.originalName);
      copyBtn.addEventListener("click", function () { copyShareLink(fuse, copyBtn); });
      actions.appendChild(copyBtn);
    }

    const blowBtn = document.createElement("button");
    blowBtn.type = "button";
    blowBtn.className = "danger";
    blowBtn.textContent = "Blow";
    blowBtn.setAttribute("aria-label", "Blow fuse for " + fuse.originalName);
    blowBtn.addEventListener("click", function () { blowFuse(fuse, blowBtn); });
    actions.appendChild(blowBtn);

    item.appendChild(actions);
    return item;
  }

  function renderFuses(fuses) {
    fuseList.innerHTML = "";
    if (!fuses.length) {
      const p = document.createElement("p");
      p.className = "fuse-empty";
      p.textContent = "No active fuses. Files you upload while logged in will appear here.";
      fuseList.appendChild(p);
      announce(dashboardStatus, "You have no active fuses.");
      return;
    }
    fuses.forEach(function (fuse) {
      fuseList.appendChild(renderFuseItem(fuse));
    });
    announce(dashboardStatus, fuses.length === 1 ? "1 active fuse." : fuses.length + " active fuses.");
  }

  async function blowFuse(fuse, btn) {
    if (!window.confirm("Blow the fuse for \"" + fuse.originalName + "\"? This cannot be undone.")) {
      return;
    }
    btn.disabled = true;
    try {
      const resp = await fetch("/api/account/fuses/" + encodeURIComponent(fuse.id) + "/blow", {
        method: "POST",
        headers: authHeaders(),
      });
      if (resp.status === 401) {
        clearSession();
        showGate("Your session expired. Please log in again.");
        return;
      }
      if (!resp.ok) {
        const data = await resp.json().catch(function () { return {}; });
        throw new Error(data.error || "Could not blow fuse.");
      }
      announce(dashboardStatus, "Fuse blown for " + fuse.originalName + ".");
      loadFuses();
    } catch (err) {
      btn.disabled = false;
      announce(dashboardStatus, err.message);
    }
  }

  refreshBtn.addEventListener("click", function () { loadFuses(); });

  logoutBtn.addEventListener("click", function () {
    clearSession();
    showGate("You are logged out.");
  });

  // --- Delete account ---

  deleteToggleBtn.addEventListener("click", function () {
    deleteForm.hidden = false;
    deleteNumber.focus();
  });

  deleteCancelBtn.addEventListener("click", function () {
    deleteForm.hidden = true;
    deleteNumber.value = "";
    setError(deleteError, "");
    deleteToggleBtn.focus();
  });

  deleteNumber.addEventListener("input", function () {
    deleteNumber.removeAttribute("aria-invalid");
    setError(deleteError, "");
  });

  deleteForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    setError(deleteError, "");
    const number = normalizeDigits(deleteNumber.value);
    if (!number) {
      setError(deleteError, "Re-enter your account number to confirm.");
      deleteNumber.focus();
      return;
    }
    if (!window.confirm("Permanently delete your account and blow all your fuses? This cannot be undone.")) {
      return;
    }
    deleteConfirmBtn.disabled = true;
    try {
      const keys = await FuseCrypto.deriveAccountKeys(number);
      const resp = await fetch("/api/account/delete", {
        method: "POST",
        headers: Object.assign({ "Content-Type": "application/json" }, authHeaders()),
        body: JSON.stringify({ authenticator: keys.authenticator }),
      });
      const data = await resp.json().catch(function () { return {}; });
      if (resp.status === 401) {
        clearSession();
        showGate("Your session expired. Please log in again.");
        return;
      }
      if (!resp.ok) throw new Error(data.error || "Could not delete account.");
      clearSession();
      deleteForm.hidden = true;
      deleteNumber.value = "";
      showGate("Your account and all its fuses have been deleted.");
    } catch (err) {
      deleteConfirmBtn.disabled = false;
      setError(deleteError, err.message);
      deleteNumber.setAttribute("aria-invalid", "true");
    }
  });

  // --- Init ---

  loadAccountConfig();
  if (loadSession()) {
    goToDashboard();
  } else {
    showView(gateView);
    gateHeading.focus();
  }
})();
