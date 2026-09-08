export const UI_ASSETS = [
  "index.html", "app.js", "style.css", "companion.js",
  "companion-idle.webp", "companion-blink.webp", "companion-wink.webp",
];

export const assetContentType = name => name.endsWith(".js") ? "text/javascript; charset=utf-8"
  : name.endsWith(".css") ? "text/css; charset=utf-8"
    : name.endsWith(".webp") ? "image/webp" : "text/html; charset=utf-8";

// The theme fixture may embed the page; image/script restrictions match the plugin.
export const FIXTURE_ASSET_CSP = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; img-src 'self' blob:";
