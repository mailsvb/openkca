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
