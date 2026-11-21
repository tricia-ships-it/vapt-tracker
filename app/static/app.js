/* app.js — interaction layer for Argus.
   Dependency-free, offline. Adds motion and keyboard-driven navigation without
   touching the server contract: count-up stats, scroll reveal, toasts, a
   command palette (Cmd/Ctrl-K) and shortcuts. Honors reduced-motion. */
(function () {
  "use strict";
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---------- toast API: window.toast(msg, {type,title,timeout}) ---------- */
  function ensureToastWrap() {
    var w = document.querySelector(".toast-wrap");
    if (!w) { w = document.createElement("div"); w.className = "toast-wrap"; document.body.appendChild(w); }
    return w;
  }
  window.toast = function (msg, opts) {
    opts = opts || {};
    var w = ensureToastWrap();
    var el = document.createElement("div");
    el.className = "toast " + (opts.type || "");
    el.innerHTML = '<span class="t-dot"></span><div>' +
      (opts.title ? '<div class="t-title">' + esc(opts.title) + "</div>" : "") +
      '<div class="t-msg">' + esc(msg) + "</div></div>";
    w.appendChild(el);
    var life = opts.timeout || 3600;
    setTimeout(function () { el.classList.add("leaving"); setTimeout(function () { el.remove(); }, 300); }, life);
  };
  function esc(s) { var d = document.createElement("div"); d.textContent = s == null ? "" : s; return d.innerHTML; }

  /* ---------- count-up for stat / kpi numbers ---------- */
  function countUp(el) {
    var target = parseFloat(el.getAttribute("data-count"));
    if (isNaN(target)) { target = parseFloat((el.textContent || "").replace(/[^\d.-]/g, "")); }
    if (isNaN(target)) return;
    var suffix = el.getAttribute("data-suffix") || "";
    if (reduce || target === 0) { el.textContent = target + suffix; return; }
    var dur = 650, start = performance.now(), isFloat = target % 1 !== 0;
    function step(now) {
      var p = Math.min(1, (now - start) / dur);
      var e = 1 - Math.pow(1 - p, 3); // easeOutCubic
      var v = target * e;
      el.textContent = (isFloat ? v.toFixed(1) : Math.round(v)) + suffix;
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  /* ---------- scroll reveal ---------- */
  function setupReveal() {
    var items = document.querySelectorAll(".reveal, .reveal-stagger");
    if (!("IntersectionObserver" in window) || reduce) {
      items.forEach(function (n) { n.classList.add("in"); });
      return;
    }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting) {
          var el = en.target;
          // stagger children
          if (el.classList.contains("reveal-stagger")) {
            Array.prototype.forEach.call(el.children, function (c, i) {
              c.style.transitionDelay = Math.min(i * 45, 400) + "ms";
            });
          }
          el.classList.add("in");
          io.unobserve(el);
        }
      });
    }, { threshold: 0.08, rootMargin: "0px 0px -40px 0px" });
    items.forEach(function (n) { io.observe(n); });
  }

  /* ---------- severity row classes + status-change flash on findings table ---------- */
  function tagSeverityRows() {
    document.querySelectorAll("table.grid tbody tr").forEach(function (tr) {
      var pill = tr.querySelector(".risk");
      if (!pill) return;
      var sev = (pill.className.match(/risk\s+(\w+)/) || [])[1];
      if (sev) tr.classList.add("sev-" + sev);
    });
    // when a status <select> changes, flash the row (server call handled elsewhere)
    document.querySelectorAll("select.statussel").forEach(function (sel) {
      sel.addEventListener("change", function () {
        var tr = sel.closest("tr");
        if (tr) { tr.classList.remove("flash"); void tr.offsetWidth; tr.classList.add("flash"); }
      });
    });
  }

  /* ---------- command palette ---------- */
  var CMDK = null;
  function buildCommands() {
    var url = function (p) { return (window.__ROUTES && window.__ROUTES[p]) || p; };
    var cmds = [
      { ic: "◆", label: "Dashboard", sub: "g d", href: url("dashboard") },
      { ic: "≡", label: "All findings", sub: "g f", href: url("index") },
      { ic: "▦", label: "Asset register (inventory)", sub: "", href: url("inventory") },
      { ic: "☷", label: "Asset risk view", sub: "", href: url("assets") },
      { ic: "⇄", label: "Compare scans", sub: "", href: url("diff") },
      { ic: "✓", label: "Compliance coverage", sub: "", href: url("compliance") },
      { ic: "⚠", label: "Threat intelligence", sub: "", href: url("threatintel") },
      { ic: "✉", label: "Phishing awareness", sub: "", href: url("phishing") },
      { ic: "⌁", label: "Activity feed", sub: "g a", href: url("activity") },
    ];
    if (window.__ROUTES && window.__ROUTES.settings)
      cmds.push({ ic: "⚙", label: "Settings", sub: "", href: url("settings") });
    if (window.__CAN_SCAN) {
      cmds.push({ ic: "+", label: "Add finding", sub: "n", href: url("finding_new") });
      cmds.push({ ic: "⊹", label: "Run a scan", sub: "", href: url("scan_page") });
      cmds.push({ ic: "↥", label: "Import scan results", sub: "", href: url("import_scan") });
      cmds.push({ ic: "☖", label: "Asset owners", sub: "", href: url("owners") });
    }
    if (window.__IS_ADMIN) cmds.push({ ic: "✦", label: "Manage users", sub: "", href: url("users") });
    cmds.push({ ic: "◐", label: "Toggle light / dark theme", sub: "t", action: toggleTheme });
    return cmds;
  }
  function toggleTheme() {
    var btn = document.getElementById("themeToggle");
    if (btn) btn.click();
  }
  function openCmdk() {
    if (!CMDK) return;
    CMDK.overlay.classList.add("open");
    CMDK.input.value = ""; renderCmdk(""); CMDK.input.focus();
  }
  function closeCmdk() { if (CMDK) CMDK.overlay.classList.remove("open"); }
  function renderCmdk(q) {
    q = (q || "").toLowerCase().trim();
    var list = CMDK.commands.filter(function (c) { return !q || c.label.toLowerCase().indexOf(q) >= 0; });
    CMDK.filtered = list; CMDK.sel = 0;
    if (!list.length) { CMDK.listEl.innerHTML = '<div class="cmdk-empty">No matches</div>'; return; }
    CMDK.listEl.innerHTML = list.map(function (c, i) {
      return '<div class="cmdk-item' + (i === 0 ? " active" : "") + '" data-i="' + i + '">' +
        '<span class="k-ic">' + c.ic + "</span><span>" + esc(c.label) + "</span>" +
        (c.sub ? '<span class="k-sub">' + esc(c.sub) + "</span>" : "") + "</div>";
    }).join("");
    Array.prototype.forEach.call(CMDK.listEl.children, function (row) {
      row.addEventListener("click", function () { runCmd(CMDK.filtered[+row.getAttribute("data-i")]); });
    });
  }
  function moveSel(d) {
    var rows = CMDK.listEl.querySelectorAll(".cmdk-item");
    if (!rows.length) return;
    CMDK.sel = (CMDK.sel + d + rows.length) % rows.length;
    rows.forEach(function (r, i) { r.classList.toggle("active", i === CMDK.sel); });
    rows[CMDK.sel].scrollIntoView({ block: "nearest" });
  }
  function runCmd(c) {
    if (!c) return;
    closeCmdk();
    if (c.action) c.action();
    else if (c.href) window.location.href = c.href;
  }
  function setupCmdk() {
    var overlay = document.createElement("div");
    overlay.className = "cmdk-overlay";
    overlay.innerHTML =
      '<div class="cmdk" role="dialog" aria-label="Command palette">' +
      '<input class="cmdk-input" placeholder="Jump to… (type a page or action)" aria-label="Command">' +
      '<div class="cmdk-list"></div>' +
      '<div class="cmdk-hint"><span><kbd>↑</kbd><kbd>↓</kbd> navigate</span><span><kbd>↵</kbd> open</span><span><kbd>esc</kbd> close</span></div>' +
      "</div>";
    document.body.appendChild(overlay);
    CMDK = {
      overlay: overlay,
      input: overlay.querySelector(".cmdk-input"),
      listEl: overlay.querySelector(".cmdk-list"),
      commands: buildCommands(), filtered: [], sel: 0,
    };
    CMDK.input.addEventListener("input", function () { renderCmdk(CMDK.input.value); });
    CMDK.input.addEventListener("keydown", function (e) {
      if (e.key === "ArrowDown") { e.preventDefault(); moveSel(1); }
      else if (e.key === "ArrowUp") { e.preventDefault(); moveSel(-1); }
      else if (e.key === "Enter") { e.preventDefault(); runCmd(CMDK.filtered[CMDK.sel]); }
      else if (e.key === "Escape") { closeCmdk(); }
    });
    overlay.addEventListener("click", function (e) { if (e.target === overlay) closeCmdk(); });
  }

  /* ---------- global shortcuts ---------- */
  function setupShortcuts() {
    var lastG = 0;
    document.addEventListener("keydown", function (e) {
      var t = e.target, typing = t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable);
      // Cmd/Ctrl-K opens palette anywhere
      if ((e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K")) { e.preventDefault(); openCmdk(); return; }
      if (typing) return;
      var now = Date.now(), go = now - lastG < 650;
      if (e.key === "g") { lastG = now; return; }
      var R = window.__ROUTES || {};
      if (go && e.key === "d") { window.location.href = R.dashboard || "/dashboard"; }
      else if (go && e.key === "f") { window.location.href = R.index || "/"; }
      else if (go && e.key === "a") { window.location.href = R.activity || "/activity"; }
      else if (e.key === "/") {
        var s = document.querySelector('.toolbar input[type=text], input[type=search]');
        if (s) { e.preventDefault(); s.focus(); }
      } else if (e.key === "n" && window.__CAN_SCAN && R.finding_new) { window.location.href = R.finding_new; }
      else if (e.key === "?") { window.toast("g d · g f · g a to navigate, / to search, n new finding, ⌘K palette", { title: "Shortcuts", timeout: 5000 }); }
    });
  }

  /* ---------- wire up ---------- */
  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-count], .count").forEach(countUp);
    setupReveal();
    tagSeverityRows();
    setupCmdk();
    setupShortcuts();
    var chip = document.getElementById("cmdkChip");
    if (chip) chip.addEventListener("click", openCmdk);
    window.openCmdk = openCmdk;
  });

  /* re-run enhancements on dynamically rendered content (e.g. the dashboard) */
  window.vaptEnhance = function (root) {
    root = root || document;
    root.querySelectorAll("[data-count], .count").forEach(countUp);
    tagSeverityRows();
  };
})();
