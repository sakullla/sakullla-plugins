// Reverse L4 mapping list and create form with a fixed node catalog.
// The shared runner owns the browser, viewport, and gallery.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const moduleRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");
const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8" };

const agents = [
  { id: "edge-hk", name: "香港入口", online: true, status: "online", last_seen_at: "2026-10-17T08:00:00Z", last_seen_ip: "192.0.2.10" },
  { id: "home", name: "家庭出口", online: true, status: "online", last_seen_at: "2026-10-17T08:05:00Z", last_seen_ip: "192.0.2.20" },
];

const listeners = [
  { id: 7, name: "香港中继", agent_name: "香港入口", agent_id: "edge-hk", enabled: true, public_addr: "192.0.2.10:7000" },
  { id: 8, name: "家庭中继", agent_name: "家庭出口", agent_id: "home", enabled: true, public_addr: "192.0.2.20:7000" },
];

const saved = [
  {
    id: "map-web",
    name: "内网 Web",
    entry_agent_id: "edge-hk",
    exit_agent_id: "home",
    protocol: "tcp",
    listen_host: "0.0.0.0",
    listen_port: 8443,
    backend_host: "127.0.0.1",
    backend_port: 9443,
    relay_chain: [7],
    enabled: true,
    channel_state: "online",
  },
  {
    id: "map-dns",
    name: "内网 DNS",
    entry_agent_id: "edge-hk",
    exit_agent_id: "home",
    protocol: "udp",
    listen_host: "0.0.0.0",
    listen_port: 5353,
    backend_host: "10.0.0.8",
    backend_port: 53,
    relay_chain: [],
    enabled: false,
    channel_state: "offline",
    last_error: "出口节点暂时离线",
  },
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

export const id = "reverse-l4";

export const scenes = [
  {
    name: "mappings",
    title: "映射列表",
    run: async (ui) => {
      await ui.waitFor("#map-list .map-card");
      await ui.waitFor("#create-toggle");
    },
  },
  {
    name: "create",
    title: "新建映射",
    run: async (ui) => {
      await ui.waitFor("#create-toggle");
      await ui.click("#create-toggle");
      await ui.waitFor("#mapping-form");
      await ui.waitFor("#relay-add");
    },
  },
  {
    name: "empty",
    title: "还没有映射",
    run: async (ui) => {
      const origin = await ui.evaluate("location.origin");
      await ui.open(`${origin}/?fixture=empty`);
      await ui.waitFor("#map-empty");
      await ui.waitFor("#create-toggle");
    },
  },
];

export async function startPreview({ root = moduleRoot } = {}) {
  const staticRoot = join(root, "plugins/reverse-l4/assets/ui");
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
      if (url.pathname === "/panel-api/agents") return json(200, { agents });
      if (url.pathname === "/panel-api/relay-listeners") return json(200, { listeners });
      if (url.pathname === "/api/mappings" && request.method === "GET") {
        const mappings = cookieValue(request, "l4_fixture") === "empty" ? [] : saved;
        return json(200, { mappings, access: { can_read: true, can_write: true } });
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
      const extension = file.slice(file.lastIndexOf("."));
      response.writeHead(200, {
        "Content-Type": types[extension] || "application/octet-stream",
        "Cache-Control": "no-store",
        ...(relative === "index.html" ? { "Set-Cookie": `l4_fixture=${encodeURIComponent(fixture)}; Path=/; SameSite=Lax` } : {}),
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
