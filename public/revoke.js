(function () {
  "use strict";

  const fuseIdField = document.getElementById("fuse-id");
  const ownerTokenField = document.getElementById("owner-token");
  const revokeForm = document.getElementById("revoke-form");
  const revokeBtn = document.getElementById("revoke-btn");
  const revokeError = document.getElementById("revoke-error");
  const revokeSuccess = document.getElementById("revoke-success");
  const revokeHeading = document.getElementById("revoke-heading");

  const match = window.location.pathname.match(/^\/revoke\/(.+)$/);
  let fuseId = "";
  if (match) {
    try {
      fuseId = decodeURIComponent(match[1]);
    } catch (_) {
      fuseId = "";
    }
  }

  fuseIdField.value = fuseId;
  revokeHeading.focus();

  if (!fuseId) {
    revokeError.textContent = "Invalid revoke URL. Missing or malformed fuse ID.";
    revokeBtn.disabled = true;
  }

  const hashToken = window.location.hash ? window.location.hash.slice(1) : "";
  if (hashToken) {
    ownerTokenField.value = hashToken;
  }

  revokeForm.addEventListener("submit", async function (event) {
    event.preventDefault();
    revokeError.textContent = "";
    revokeSuccess.textContent = "";

    const token = ownerTokenField.value.trim();
    if (!fuseId) {
      revokeError.textContent = "Invalid revoke URL. Missing fuse ID.";
      return;
    }

    if (!token) {
      revokeError.textContent = "Owner token is required.";
      ownerTokenField.focus();
      return;
    }

    revokeBtn.disabled = true;
    try {
      const response = await fetch("/api/fuse/" + encodeURIComponent(fuseId) + "/revoke", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ ownerToken: token }),
      });

      const payload = await response.json().catch(function () {
        return {};
      });

      if (!response.ok) {
        revokeError.textContent = payload.error || "Failed to blow fuse.";
        revokeBtn.disabled = false;
        return;
      }

      revokeSuccess.textContent = "Fuse blown successfully. Downloads are now blocked.";
      revokeBtn.textContent = "Fuse blown";
    } catch (_) {
      revokeError.textContent = "Network error while revoking fuse.";
      revokeBtn.disabled = false;
    }
  });
})();
