/* Sakullla plugin UI kit — theme resolution and small shared behaviours.
   No framework, no external requests. Exposes window.NREUI.
   The script is loaded synchronously in <head> so the theme is applied
   before the first paint. */
(function (global) {
  "use strict";

  var HOST_THEMES = ["fresh-green", "sakura-day", "sakura-night", "neko-dark", "business"];
  var DARK_THEMES = { "sakura-night": true, "neko-dark": true, "dark": true };
  var LEGACY_THEMES = {
    sakura: "sakura-day",
    midnight: "sakura-night",
    cyberpunk: "sakura-day",
    "sakura-night": "sakura-night",
    "neko-dark": "neko-dark"
  };
  var STORAGE_KEY = "theme";
  var root = document.documentElement;
  var media = null;
  var listenersBound = false;

  function isHostTheme(value) {
    return HOST_THEMES.indexOf(value) !== -1;
  }

  function safeGet(key) {
    if (!key) return null;
    try {
      return global.localStorage.getItem(key);
    } catch (_error) {
      return null;
    }
  }

  function safeSet(key, value) {
    if (!key) return;
    try {
      global.localStorage.setItem(key, value);
    } catch (_error) {
      /* Storage can be unavailable in privacy modes. */
    }
  }

  function prefersDark() {
    try {
      return Boolean(global.matchMedia && global.matchMedia("(prefers-color-scheme: dark)").matches);
    } catch (_error) {
      return false;
    }
  }

  function normalizeHostTheme(raw, dark) {
    var value = String(raw || "").trim();
    if (LEGACY_THEMES[value]) value = LEGACY_THEMES[value];
    if (isHostTheme(value)) return value;
    if (value === "light" || value === "dark") return value;
    return dark ? "dark" : "light";
  }

  function normalizeStandaloneTheme(raw, dark) {
    var value = String(raw || "").trim();
    if (LEGACY_THEMES[value]) value = LEGACY_THEMES[value];
    if (value === "light" || value === "dark") return value;
    if (isHostTheme(value)) return DARK_THEMES[value] ? "dark" : "light";
    return dark ? "dark" : "light";
  }

  function themeFamily(theme) {
    return DARK_THEMES[theme] ? "dark" : "light";
  }

  function mode() {
    return root.getAttribute("data-theme-mode") === "host" ? "host" : "standalone";
  }

  function standaloneKey() {
    return root.getAttribute("data-theme-key") || "";
  }

  function resolveTheme(options) {
    options = options || {};
    var host = options.mode === "host";
    var dark = typeof options.dark === "boolean" ? options.dark : prefersDark();
    var theme = host
      ? normalizeHostTheme(options.raw, dark)
      : normalizeStandaloneTheme(options.raw, dark);
    return { theme: theme, family: themeFamily(theme) };
  }

  function applyTheme(theme) {
    var family = themeFamily(theme);
    root.setAttribute("data-theme", theme);
    root.setAttribute("data-theme-family", family);
  }

  function currentRaw() {
    return mode() === "host" ? safeGet(STORAGE_KEY) : safeGet(standaloneKey());
  }

  function applyFromStorage() {
    var raw = currentRaw();
    var resolved = resolveTheme({ mode: mode(), raw: raw, dark: prefersDark() });
    applyTheme(resolved.theme);
    syncToggles(resolved.family);
    return resolved;
  }

  function setTheme(theme, options) {
    options = options || {};
    var value = String(theme || "").trim();
    if (value !== "light" && value !== "dark") return false;
    if (mode() === "host" && !options.allowHost) return false;
    applyTheme(value);
    if (standaloneKey()) safeSet(standaloneKey(), value);
    syncToggles(themeFamily(value));
    return true;
  }

  function toggleTheme() {
    var next = root.getAttribute("data-theme-family") === "dark" ? "light" : "dark";
    return setTheme(next);
  }

  function syncToggles(family) {
    var nodes = document.querySelectorAll("[data-ui-theme-toggle]");
    for (var i = 0; i < nodes.length; i += 1) {
      var node = nodes[i];
      node.setAttribute("aria-pressed", family === "dark" ? "true" : "false");
      if (!node.getAttribute("aria-label") && !node.getAttribute("title")) {
        node.setAttribute("aria-label", family === "dark" ? "切换到浅色主题" : "切换到深色主题");
      }
    }
  }

  function bindThemeListeners() {
    if (listenersBound) return;
    listenersBound = true;

    global.addEventListener("storage", function (event) {
      var key = mode() === "host" ? STORAGE_KEY : standaloneKey();
      if (!key) return;
      if (event.key === key || event.key === null) applyFromStorage();
    });

    try {
      media = global.matchMedia("(prefers-color-scheme: dark)");
      var onChange = function () {
        if (mode() === "host" && currentRaw()) return;
        if (mode() === "standalone" && standaloneKey() && currentRaw()) return;
        applyFromStorage();
      };
      if (media.addEventListener) media.addEventListener("change", onChange);
      else if (media.addListener) media.addListener(onChange);
    } catch (_error) {
      media = null;
    }

    document.addEventListener("click", function (event) {
      var toggle = event.target.closest ? event.target.closest("[data-ui-theme-toggle]") : null;
      if (!toggle) return;
      event.preventDefault();
      toggleTheme();
    });
  }

  function focusable(container) {
    return container.querySelectorAll(
      'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
    );
  }

  function openDialog(target) {
    var dialog = typeof target === "string" ? document.querySelector(target) : target;
    if (!dialog || !dialog.showModal) return null;
    dialog._uiTrigger = document.activeElement;
    if (!dialog.open) dialog.showModal();
    var nodes = focusable(dialog);
    if (nodes.length) nodes[0].focus();
    return dialog;
  }

  function closeDialog(target) {
    var dialog = typeof target === "string" ? document.querySelector(target) : target;
    if (!dialog || !dialog.close) return;
    if (dialog.open) dialog.close();
    if (dialog._uiTrigger && dialog._uiTrigger.focus) dialog._uiTrigger.focus();
  }

  function initDialogs() {
    var dialogs = document.querySelectorAll("dialog[data-ui-dialog]");
    for (var i = 0; i < dialogs.length; i += 1) {
      (function (dialog) {
        if (dialog._uiBound) return;
        dialog._uiBound = true;
        dialog.addEventListener("close", function () {
          if (dialog._uiTrigger && dialog._uiTrigger.focus) dialog._uiTrigger.focus();
        });
        dialog.addEventListener("click", function (event) {
          if (event.target === dialog) closeDialog(dialog);
        });
      })(dialogs[i]);
    }
  }

  function initTabs(scope) {
    var rootNode = scope || document;
    var lists = rootNode.querySelectorAll('[role="tablist"][data-ui-tabs]');
    for (var i = 0; i < lists.length; i += 1) {
      (function (list) {
        if (list._uiTabBound) return;
        list._uiTabBound = true;
        var tabs = Array.prototype.slice.call(list.querySelectorAll('[role="tab"]'));
        if (!tabs.length) return;
        function activate(index) {
          var tab = tabs[(index + tabs.length) % tabs.length];
          if (!tab) return;
          tabs.forEach(function (item) {
            item.setAttribute("tabindex", item === tab ? "0" : "-1");
          });
          tab.focus();
          tab.click();
        }
        tabs.forEach(function (tab, index) {
          tab.setAttribute("tabindex", tab.getAttribute("aria-selected") === "true" ? "0" : "-1");
          tab.addEventListener("keydown", function (event) {
            if (event.key === "ArrowRight" || event.key === "ArrowDown") {
              event.preventDefault();
              activate(index + 1);
            } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
              event.preventDefault();
              activate(index - 1);
            } else if (event.key === "Home") {
              event.preventDefault();
              activate(0);
            } else if (event.key === "End") {
              event.preventDefault();
              activate(tabs.length - 1);
            }
          });
        });
      })(lists[i]);
    }
  }

  function toast(message, tone) {
    if (!message) return null;
    var region = document.querySelector(".ui-toast-region");
    if (!region) {
      region = document.createElement("div");
      region.className = "ui-toast-region";
      region.setAttribute("role", "status");
      region.setAttribute("aria-live", "polite");
      document.body.appendChild(region);
    }
    var node = document.createElement("div");
    node.className = "ui-toast" + (tone ? " ui-toast--" + tone : "");
    node.textContent = String(message);
    region.appendChild(node);
    global.setTimeout(function () {
      node.remove();
    }, 4500);
    return node;
  }

  function copyText(text) {
    var value = String(text || "");
    if (!value) return Promise.resolve(false);
    if (global.navigator && global.navigator.clipboard && global.navigator.clipboard.writeText) {
      return global.navigator.clipboard.writeText(value).then(
        function () { return true; },
        function () { return fallbackCopy(value); }
      );
    }
    return Promise.resolve(fallbackCopy(value));
  }

  function fallbackCopy(value) {
    try {
      var area = document.createElement("textarea");
      area.value = value;
      area.className = "ui-sr-only";
      document.body.appendChild(area);
      area.focus();
      area.select();
      var ok = document.execCommand("copy");
      area.remove();
      return Boolean(ok);
    } catch (_error) {
      return false;
    }
  }

  function setBusy(button, busy) {
    if (!button) return;
    if (busy) {
      button.setAttribute("aria-busy", "true");
      button.disabled = true;
    } else {
      button.removeAttribute("aria-busy");
      button.disabled = false;
    }
  }

  function fieldError(input, message) {
    if (!input) return;
    var field = input.closest(".ui-field") || input.parentElement;
    if (!field) return;
    var error = field.querySelector(".ui-error-text");
    if (!error) {
      error = document.createElement("p");
      error.className = "ui-error-text";
      error.setAttribute("role", "alert");
      field.appendChild(error);
    }
    if (!error.id) error.id = "ui-error-" + Math.random().toString(36).slice(2, 10);
    error.textContent = String(message || "");
    input.setAttribute("aria-invalid", "true");
    input.setAttribute("aria-describedby", error.id);
  }

  function clearFieldError(input) {
    if (!input) return;
    var field = input.closest(".ui-field") || input.parentElement;
    if (!field) return;
    var error = field.querySelector(".ui-error-text");
    if (error) error.textContent = "";
    input.removeAttribute("aria-invalid");
    input.removeAttribute("aria-describedby");
  }

  function confirmAction(options) {
    options = options || {};
    if (!document.body || !global.HTMLDialogElement) return Promise.resolve(global.confirm(options.message || "确认执行？"));
    return new Promise(function (resolve) {
      var dialog = document.createElement("dialog");
      dialog.className = "ui-dialog";
      dialog.setAttribute("data-ui-dialog", "");
      var title = options.title || "确认操作";
      var message = options.message || "";
      var confirmLabel = options.confirmLabel || "确认";
      var danger = options.tone === "danger";
      dialog.innerHTML =
        '<div class="ui-dialog__head"><div><h2 class="ui-dialog__title"></h2>' +
        '<p class="ui-dialog__desc"></p></div></div>' +
        '<div class="ui-dialog__footer"><button type="button" class="ui-btn ui-btn--secondary" data-ui-cancel>取消</button>' +
        '<button type="button" class="ui-btn ' + (danger ? "ui-btn--danger" : "") + '" data-ui-confirm></button></div>';
      dialog.querySelector(".ui-dialog__title").textContent = title;
      dialog.querySelector(".ui-dialog__desc").textContent = message;
      dialog.querySelector("[data-ui-confirm]").textContent = confirmLabel;
      document.body.appendChild(dialog);
      function finish(value) {
        if (dialog.open) dialog.close();
        dialog.remove();
        resolve(Boolean(value));
      }
      dialog.querySelector("[data-ui-cancel]").addEventListener("click", function () { finish(false); });
      dialog.querySelector("[data-ui-confirm]").addEventListener("click", function () { finish(true); });
      dialog.addEventListener("cancel", function (event) {
        event.preventDefault();
        finish(false);
      });
      dialog.addEventListener("click", function (event) {
        if (event.target === dialog) finish(false);
      });
      openDialog(dialog);
    });
  }

  function init() {
    bindThemeListeners();
    applyFromStorage();
    initDialogs();
    initTabs(document);
  }

  global.NREUI = {
    HOST_THEMES: HOST_THEMES.slice(),
    mode: mode,
    resolveTheme: resolveTheme,
    applyTheme: applyTheme,
    applyFromStorage: applyFromStorage,
    setTheme: setTheme,
    toggleTheme: toggleTheme,
    openDialog: openDialog,
    closeDialog: closeDialog,
    initDialogs: initDialogs,
    initTabs: initTabs,
    toast: toast,
    copyText: copyText,
    setBusy: setBusy,
    fieldError: fieldError,
    clearFieldError: clearFieldError,
    confirm: confirmAction
  };

  /* Apply immediately, before stylesheets paint. */
  applyFromStorage();

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})(window);
