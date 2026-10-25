// Column chooser: remembers hidden columns per list in this browser only.
(function () {
  "use strict";
  function storeKey(table) { return "openkca.hidden." + table; }
  function load(table) {
    try { return JSON.parse(localStorage.getItem(storeKey(table)) || "[]"); } catch (e) { return []; }
  }
  function save(table, cols) {
    try { localStorage.setItem(storeKey(table), JSON.stringify(cols)); } catch (e) { /* storage unavailable */ }
  }
  function apply(menu) {
    var tableId = menu.getAttribute("data-table");
    var table = document.getElementById(tableId);
    if (!table) { return; }
    var hidden = load(tableId);
    menu.querySelectorAll("input[data-col]").forEach(function (box) {
      var col = box.getAttribute("data-col");
      var isHidden = hidden.indexOf(col) >= 0;
      box.checked = !isHidden;
      table.classList.toggle("hide-" + col, isHidden);
      box.addEventListener("change", function () {
        var now = load(tableId).filter(function (c) { return c !== col; });
        if (!box.checked) { now.push(col); }
        save(tableId, now);
        table.classList.toggle("hide-" + col, !box.checked);
      });
    });
  }
  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".colmenu[data-table]").forEach(apply);
  });
})();

// Copy buttons: data-copy names the element whose text is copied.
(function () {
  "use strict";
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest ? ev.target.closest("button[data-copy]") : null;
    if (!btn) { return; }
    var src = document.getElementById(btn.getAttribute("data-copy"));
    if (!src) { return; }
    var text = src.value !== undefined ? src.value : src.textContent;
    var done = function () {
      var label = btn.textContent;
      btn.textContent = btn.getAttribute("data-copied") || label;
      setTimeout(function () { btn.textContent = label; }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { src.select(); });
    } else if (src.select) {
      src.select();
    }
  });
})();

// Key picker filter: shows the key types whose label contains the text.
(function () {
  "use strict";
  function setup(picker) {
    var input = picker.querySelector("input[data-keyfilter]");
    if (!input) { return; }
    input.closest("label").hidden = false;
    var fams = picker.querySelectorAll("details.keyfam");
    var wasOpen = [];
    fams.forEach(function (d, i) { wasOpen[i] = d.open; });
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase();
      fams.forEach(function (d, i) {
        var any = false;
        d.querySelectorAll(".keychip").forEach(function (chip) {
          var hit = q === "" || chip.textContent.toLowerCase().indexOf(q) >= 0;
          chip.hidden = !hit;
          any = any || hit;
        });
        d.hidden = !any;
        d.open = q === "" ? wasOpen[i] : any;
      });
    });
  }
  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-keypick]").forEach(setup);
  });
  document.addEventListener("htmx:afterSwap", function (ev) {
    ev.target.querySelectorAll("[data-keypick]").forEach(setup);
  });
})();

// Security keys and passkeys (WebAuthn): logging in, re-confirming and
// adding one. Buttons and forms carry data-webauthn="login|confirm|register"
// with data-db and data-csrf; the server answers with JSON.
(function () {
  "use strict";
  if (!window.PublicKeyCredential || !navigator.credentials) { return; }

  function toBuf(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) { s += "="; }
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
    return out.buffer;
  }
  function toB64(buf) {
    var bytes = new Uint8Array(buf), bin = "";
    for (var i = 0; i < bytes.length; i++) { bin += String.fromCharCode(bytes[i]); }
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function prfIn(prf) {
    if (!prf) { return prf; }
    var out = {};
    if (prf.eval) { out.eval = { first: toBuf(prf.eval.first) }; }
    if (prf.evalByCredential) {
      out.evalByCredential = {};
      Object.keys(prf.evalByCredential).forEach(function (k) {
        out.evalByCredential[k] = { first: toBuf(prf.evalByCredential[k].first) };
      });
    }
    return out;
  }
  function creationOptions(o) {
    var pk = o.publicKey;
    pk.challenge = toBuf(pk.challenge);
    pk.user.id = toBuf(pk.user.id);
    (pk.excludeCredentials || []).forEach(function (c) { c.id = toBuf(c.id); });
    if (pk.extensions && pk.extensions.prf) { pk.extensions.prf = prfIn(pk.extensions.prf); }
    return { publicKey: pk };
  }
  function requestOptions(o) {
    var pk = o.publicKey;
    pk.challenge = toBuf(pk.challenge);
    (pk.allowCredentials || []).forEach(function (c) { c.id = toBuf(c.id); });
    if (pk.extensions && pk.extensions.prf) { pk.extensions.prf = prfIn(pk.extensions.prf); }
    return { publicKey: pk };
  }
  function extOut(cred) {
    var ext = cred.getClientExtensionResults ? cred.getClientExtensionResults() : {};
    var out = {};
    if (ext.prf) {
      out.prf = {};
      if (ext.prf.enabled !== undefined) { out.prf.enabled = ext.prf.enabled; }
      if (ext.prf.results && ext.prf.results.first) { out.prf.results = { first: toB64(ext.prf.results.first) }; }
    }
    return out;
  }
  function attestationJSON(c) {
    var r = c.response;
    return {
      id: c.id, rawId: toB64(c.rawId), type: c.type, authenticatorAttachment: c.authenticatorAttachment || undefined,
      response: {
        clientDataJSON: toB64(r.clientDataJSON), attestationObject: toB64(r.attestationObject),
        transports: r.getTransports ? r.getTransports() : []
      },
      clientExtensionResults: extOut(c)
    };
  }
  function assertionJSON(c) {
    var r = c.response;
    return {
      id: c.id, rawId: toB64(c.rawId), type: c.type, authenticatorAttachment: c.authenticatorAttachment || undefined,
      response: {
        clientDataJSON: toB64(r.clientDataJSON), authenticatorData: toB64(r.authenticatorData),
        signature: toB64(r.signature), userHandle: r.userHandle ? toB64(r.userHandle) : undefined
      },
      clientExtensionResults: extOut(c)
    };
  }
  function post(url, csrf, body, json) {
    var headers = { "X-CSRF-Token": csrf };
    if (json) { headers["Content-Type"] = "application/json"; }
    return fetch(url, { method: "POST", headers: headers, body: body, credentials: "same-origin" })
      .then(function (res) {
        return res.json().catch(function () { return {}; }).then(function (data) {
          if (!res.ok) { throw new Error(data.error || ""); }
          return data;
        });
      });
  }
  function errorBox(el) {
    var scope = el.closest("li, section, .card") || document;
    return scope.querySelector("[data-webauthn-error]");
  }
  function showError(el, err) {
    var box = errorBox(el);
    if (!box) { return; }
    var msg;
    if (err && (err.name === "NotAllowedError" || err.name === "AbortError")) {
      msg = box.getAttribute("data-cancelled");
    } else if (err && err.name === "Error" && err.message) {
      msg = err.message; // the server's message
    } else {
      msg = box.getAttribute("data-failed");
    }
    box.textContent = msg;
    box.hidden = false;
  }
  function clearError(el) {
    var box = errorBox(el);
    if (box) { box.hidden = true; box.textContent = ""; }
  }
  function busy(el, on) {
    if (el.tagName === "BUTTON") {
      el.disabled = on;
      return;
    }
    el.querySelectorAll("button").forEach(function (b) { b.disabled = on; });
    var st = el.querySelector("[data-webauthn-status]");
    if (st) { st.hidden = !on; }
  }

  // Login and re-confirmation: one assertion with the database's keys.
  function assert(btn, purpose) {
    var db = encodeURIComponent(btn.getAttribute("data-db")), csrf = btn.getAttribute("data-csrf");
    var base = "/db/" + db + "/webauthn/" + purpose + "/";
    clearError(btn);
    busy(btn, true);
    post(base + "begin", csrf, null, false)
      .then(function (opts) { return navigator.credentials.get(requestOptions(opts)); })
      .then(function (cred) { return post(base + "finish", csrf, JSON.stringify(assertionJSON(cred)), true); })
      .then(function (data) { window.location.assign(data.redirect); })
      .catch(function (err) { busy(btn, false); showError(btn, err); });
  }

  // Registration: create, then (if the key did not evaluate the PRF while
  // creating) one assertion for the new credential.
  function register(form) {
    var db = encodeURIComponent(form.getAttribute("data-db")), csrf = form.getAttribute("data-csrf");
    var base = "/db/" + db + "/webauthn/register/";
    var fields = new URLSearchParams(new FormData(form));
    clearError(form);
    busy(form, true);
    post(base + "begin", csrf, fields, false)
      .then(function (opts) { return navigator.credentials.create(creationOptions(opts)); })
      .then(function (cred) { return post(base + "finish", csrf, JSON.stringify(attestationJSON(cred)), true); })
      .then(function (data) {
        if (!data.assert) { return data; }
        return navigator.credentials.get(requestOptions(data.assert)).then(function (cred) {
          return post(base + "prf", csrf, JSON.stringify(assertionJSON(cred)), true);
        });
      })
      .then(function (data) { window.location.assign(data.redirect); })
      .catch(function (err) { busy(form, false); showError(form, err); });
  }

  function setup(root) {
    root.querySelectorAll("button[data-webauthn]").forEach(function (btn) {
      btn.hidden = false;
      btn.addEventListener("click", function () { assert(btn, btn.getAttribute("data-webauthn")); });
    });
    root.querySelectorAll("form[data-webauthn=register]").forEach(function (form) {
      form.addEventListener("submit", function (ev) { ev.preventDefault(); register(form); });
    });
  }
  document.addEventListener("DOMContentLoaded", function () { setup(document); });
})();

// Registration form without WebAuthn support in this browser.
(function () {
  "use strict";
  document.addEventListener("DOMContentLoaded", function () {
    if (window.PublicKeyCredential && navigator.credentials) { return; }
    document.querySelectorAll("form[data-webauthn=register]").forEach(function (form) {
      form.querySelectorAll("button").forEach(function (b) { b.disabled = true; });
      var note = form.querySelector("[data-webauthn-unsupported]");
      if (note) { note.hidden = false; }
    });
  });
})();

// Backup code: download as a text file, print.
(function () {
  "use strict";
  document.addEventListener("click", function (ev) {
    var t = ev.target.closest ? ev.target.closest("button[data-download], button[data-print]") : null;
    if (!t) { return; }
    if (t.hasAttribute("data-print")) { window.print(); return; }
    var src = document.getElementById(t.getAttribute("data-download"));
    if (!src) { return; }
    var url = URL.createObjectURL(new Blob([src.textContent + "\n"], { type: "text/plain" }));
    var a = document.createElement("a");
    a.href = url;
    a.download = t.getAttribute("data-filename") || "backup-code.txt";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  });
})();
