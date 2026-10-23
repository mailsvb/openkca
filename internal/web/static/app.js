// Column chooser: remembers hidden columns per list in this browser only.
(function () {
  "use strict";
  function storeKey(table) { return "go-ca.hidden." + table; }
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
