// Applies the operator-configured instance name (FUSE_INSTANCE_NAME) to the page
// chrome. The name comes from /api/config; until it loads, the static "Fuse"
// fallback in the markup is shown. Loaded before each page's own script so
// window.FuseBranding is available synchronously to it.
(function () {
  "use strict";

  var DEFAULT = "Fuse";

  // A <base href> (used for sub-path deploys) makes a fragment-only link like
  // the skip link resolve against the base, not the current page. Re-anchor it
  // to the current URL so "Skip to main content" still jumps within this page.
  var skip = document.querySelector("a.skip-link");
  if (skip) {
    var frag = skip.getAttribute("href");
    if (frag && frag.charAt(0) === "#") {
      skip.setAttribute("href", window.location.pathname + window.location.search + frag);
    }
  }

  function apply(name) {
    var instance = name || DEFAULT;

    var nodes = document.querySelectorAll("[data-instance-name]");
    for (var i = 0; i < nodes.length; i++) {
      nodes[i].textContent = instance;
      var label = nodes[i].getAttribute("aria-label");
      if (label && label.indexOf(DEFAULT) !== -1) {
        nodes[i].setAttribute("aria-label", label.split(DEFAULT).join(instance));
      }
    }

    // Fix up the static document title (dynamic titles read FuseBranding.name).
    if (instance !== DEFAULT && document.title.indexOf(DEFAULT) !== -1) {
      document.title = document.title.split(DEFAULT).join(instance);
    }

    window.FuseBranding.name = instance;
  }

  var resolveReady;
  window.FuseBranding = {
    name: DEFAULT,
    ready: new Promise(function (resolve) { resolveReady = resolve; }),
    apply: apply,
  };

  fetch("api/config")
    .then(function (resp) { return resp.ok ? resp.json() : {}; })
    .then(function (cfg) { apply(cfg && cfg.instanceName); })
    .catch(function () { apply(DEFAULT); })
    .then(function () { resolveReady(window.FuseBranding.name); });
})();
