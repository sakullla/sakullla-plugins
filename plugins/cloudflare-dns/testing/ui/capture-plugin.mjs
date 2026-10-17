// Cloudflare DNS mapping page and a deterministic in-memory catalog.
// The shared runner owns the browser, viewport, and gallery.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const moduleRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");
const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8" };

const saved = [
  { suffix: "example.com", provider: "cloudflare", configured: true, updated_at: 12 },
  { suffix: "shop.example.com", provider: "aliyun", configured: true, updated_at: 9 },
  { suffix: "cn.example.com", provider: "dnspod-cn", configured: true, updated_at: 4 },
  { suffix: "dns.example.com", provider: "tencent-dns", configured: false, updated_at: 2 },
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

const serve = async (root) => {
  const staticRoot = join(root, "plugins/cloudflare-dns/ui");
  const server = createServer(async (request, response) => {
    const url = new URL(request.url, "http://127.0.0.1");
    const json = (status, body, headers = {}) => {
      response.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers });
      response.end(JSON.stringify(body));
    };
    try {
      if (url.pathname === "/favicon.ico") {
        response.writeHead(204);
        return response.end();
      }
      if (url.pathname === "/api/mappings") {
        const fixture = cookieValue(request, "cf_fixture");
        const mappings = fixture === "empty" ? [] : saved;
        return json(200, {
          mappings,
          access: { can_read: true, can_write: true, can_rotate: true },
        });
      }
      const relative = url.pathname === "/" ? "index.html" : decodeURIComponent(url.pathname.slice(1));
      const file = normalize(join(staticRoot, relative));
      if (!file.startsWith(staticRoot + sep) && file !== staticRoot) return json(403, { error: "forbidden" });
      const body = await readFile(file).catch(() => null);
      if (!body) {
        response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
        return response.end("404 page not found\n");
      }
      const fixture = relative === "index.html" ? (url.searchParams.get("fixture") || "mappings") : "";
      response.writeHead(200, {
        "Content-Type": types[file.slice(file.lastIndexOf("."))] || "application/octet-stream",
        "Cache-Control": "no-store",
        ...(relative === "index.html" ? { "Set-Cookie": `cf_fixture=${encodeURIComponent(fixture)}; Path=/; SameSite=Lax` } : {}),
      });
      response.end(body);
    } catch (error) {
      json(500, { error: error.message });
    }
  });
  await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  const origin = `http://127.0.0.1:${server.address().port}`;
  return {
    origin,
    close: async () => {
      server.closeAllConnections?.();
      await new Promise((resolveClose) => server.close(resolveClose));
    },
  };
};

const reopen = async (ui, origin, search) => {
  await ui.open(`${origin}/${search}`);
};

export const id = "cloudflare-dns";

export const scenes = [
  {
    name: "mappings",
    title: "已保存映射",
    run: async (ui) => {
      await ui.waitFor("#mapping-list table");
      await ui.waitFor("#mapping-create");
    },
  },
  {
    name: "empty",
    title: "还没有映射",
    run: async (ui) => {
      const origin = await ui.evaluate("location.origin");
      await reopen(ui, origin, "?fixture=empty");
      await ui.waitFor("#mapping-empty");
      await ui.waitFor("#mapping-create");
    },
  },
];

export async function startPreview({ root = moduleRoot } = {}) {
  const preview = await serve(root);
  return { url: `${preview.origin}/`, close: () => preview.close() };
}
