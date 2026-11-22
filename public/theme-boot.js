/* Synchronous pre-paint theme cache boot loader (CSP script-src 'self' compliant) */
(function () {
  try {
    var raw = localStorage.getItem("heyjournal_active_theme_cache_v1");
    if (!raw) return;
    var cached = JSON.parse(raw);
    if (!cached || typeof cached !== "object") return;
    if (cached.themeId && /^[a-z0-9][a-z0-9_-]*$/.test(cached.themeId)) {
      document.documentElement.setAttribute("data-theme-id", cached.themeId);
    }
    if (cached.mode === "light" || cached.mode === "dark") {
      document.documentElement.setAttribute("data-theme", cached.mode);
    }
    if (cached.accent && /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/.test(cached.accent)) {
      document.documentElement.style.setProperty("--accent", cached.accent);
    }
    if (cached.metaColor) {
      var meta = document.querySelector('meta[name="theme-color"]');
      if (meta) meta.setAttribute("content", cached.metaColor);
    }
    if (
      cached.stylesheetUrl &&
      /^\/themes\/[a-zA-Z0-9._\/-]+\.css$/.test(cached.stylesheetUrl) &&
      cached.stylesheetUrl.indexOf("..") === -1
    ) {
      var link = document.createElement("link");
      link.id = "activeThemeStylesheet";
      link.rel = "stylesheet";
      link.href = cached.stylesheetUrl + "?v=2";
      document.head.appendChild(link);
    }
  } catch (e) {}
})();
