// File-share login and directory pages with a fixed in-memory listing.
// The shared runner owns the browser, viewport, and gallery.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const moduleRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");
const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8" };
const password = "shared-secret";
const files = [
  { name: "notes", dir: true },
  { name: "readme.txt", dir: false, size: 1280, size_text: "1.3 KB", size_exact: "1280" },
  { name: "photos", dir: true },
  { name: "archive.zip", dir: false, size: 2400000, size_text: "2.3 MB", size_exact: "2400000" },
];

const cookieValue = (request, name) => {
  const jar = String(request.headers.cookie || "");
  for (const part of jar.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    if (part.slice(0, index).trim() === name) return decodeURIComponent(part.slice(index + 1).trim());
  }
  return "";
};

const authorized = (request) => {
  const header = String(request.headers.authorization || "");
  if (!header.startsWith("Basic ")) return false;
  try {
    const decoded = Buffer.from(header.slice(6), "base64").toString("utf8");
    const split = decoded.indexOf(":");
    return split > 0 && decoded.slice(split + 1) === password;
  } catch {
    return false;
  }
};

export const id = "webdav";
export const themeMode = "standalone";
export const themeKey = "webdav.theme";

export const scenes = [
  {
    name: "login",
    title: "登录",
    run: async (ui) => {
      await ui.waitFor("#login-form");
      await ui.waitFor("#login-username");
    },
  },
  {
    name: "files",
    title: "目录内容",
    run: async (ui) => {
      const origin = await ui.evaluate("location.origin");
      await ui.open(`${origin}/?view=files`);
      await ui.waitFor("#listing tr");
      await ui.waitFor("#dav-url");
    },
  },
  {
    name: "empty",
    title: "空目录",
    run: async (ui) => {
      const origin = await ui.evaluate("location.origin");
      await ui.open(`${origin}/?view=empty`);
      await ui.waitFor("#empty");
      await ui.waitFor("#manager-view");
    },
  },
];

export async function startPreview({ root = moduleRoot } = {}) {
  const base = join(root, "plugins/webdav/static");
  const server = createServer(async (request, response) => {
    const url = new URL(request.url, "http://127.0.0.1");
    const json = (status, body) => {
      response.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
      response.end(JSON.stringify(body));
    };
    try {
      if (url.pathname === "/favicon.ico") {
        response.writeHead(204);
        return response.end();
      }
      if (url.pathname === "/api/list") {
        if (!authorized(request)) return json(401, { error: "口令不正确" });
        const view = cookieValue(request, "webdav_view");
        const path = url.searchParams.get("path") || "/";
        const entries = view === "empty" || path !== "/" ? [] : files;
        return json(200, { path, entries });
      }
      const relative = url.pathname === "/" ? "index.html" : url.pathname.startsWith("/static/") ? decodeURIComponent(url.pathname.slice("/static/".length)) : "";
      if (!relative) return json(404, { error: "not found" });
      const file = normalize(join(base, relative));
      if (!file.startsWith(base + sep) && file !== base) return json(403, { error: "forbidden" });
      let body = await readFile(file).catch(() => null);
      if (!body) {
        response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
        return response.end("404 page not found\n");
      }
      const view = relative === "index.html" ? (url.searchParams.get("view") || "login") : "";
      if (relative === "index.html") {
        const boot = view === "login"
          ? "sessionStorage.removeItem('webdav.username');sessionStorage.removeItem('webdav.password');"
          : "sessionStorage.setItem('webdav.username','alice');sessionStorage.setItem('webdav.password','shared-secret');";
        body = Buffer.from(body.toString("utf8").replace(
          "<script src=\"/static/app.js\" defer></script>",
          `<script>${boot}</script>\n  <script src="/static/app.js" defer></script>`,
        ));
      }
      const extension = file.slice(file.lastIndexOf("."));
      response.writeHead(200, {
        "Content-Type": types[extension] || "application/octet-stream",
        "Cache-Control": "no-store",
        ...(relative === "index.html" ? { "Set-Cookie": `webdav_view=${encodeURIComponent(view)}; Path=/; SameSite=Lax` } : {}),
      });
      response.end(body);
    } catch (error) {
      json(500, { error: error.message });
    }
  });
  await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  return {
    url: `http://127.0.0.1:${server.address().port}/`,
    close: async () => {
      server.closeAllConnections?.();
      await new Promise((resolveClose) => server.close(resolveClose));
    },
  };
}
