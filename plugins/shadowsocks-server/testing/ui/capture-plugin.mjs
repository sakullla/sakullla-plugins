// Shadowsocks listens and dataset routing over a fixed node fixture.
// The shared runner owns the browser, viewport, and gallery.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const moduleRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");
const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8" };

const agents = [
  { id: "edge", name: "香港边缘", online: true, status: "online", last_seen_at: "2026-10-17T08:00:00Z", ddns_domain: "ss.example.test" },
];

const execution = {
  agent_id: "edge",
  online: true,
  ready: true,
  share_host: "ss.example.test",
  share_host_source: "ddns",
};

const listens = [
  {
    id: "listen-8388",
    agent_id: "edge",
    port: 8388,
    method: "2022-blake3-aes-128-gcm",
    family: "2022",
    bound: true,
    host_port: "ss.example.test:8388",
    users: [
      {
        id: "acct-alice",
        name: "alice",
        family: "2022",
        method: "2022-blake3-aes-128-gcm",
        enabled: true,
        share_available: true,
        uri: "ss://example@ss.example.test:8388",
        host_port: "ss.example.test:8388",
      },
      {
        id: "acct-bob",
        name: "bob",
        family: "2022",
        method: "2022-blake3-aes-128-gcm",
        enabled: false,
        share_available: false,
        reason: "停用后无法导入",
      },
    ],
  },
  {
    id: "listen-9443",
    agent_id: "edge",
    port: 9443,
    method: "aes-256-gcm",
    family: "classic",
    bound: false,
    host_port: "ss.example.test:9443",
    users: [
      {
        id: "acct-guest",
        name: "guest",
        family: "classic",
        method: "aes-256-gcm",
        enabled: true,
        share_available: false,
        reason: "监听尚未绑定",
      },
    ],
  },
];

const routing = {
  default_action: "direct",
  upstreams: [
    {
      id: "exit-tokyo",
      host: "tokyo.example.test",
      port: 443,
      method: "2022-blake3-aes-128-gcm",
      secret_ref: "secret/tokyo",
      secret_version: "v3",
      enabled: true,
      tcp: true,
      udp: true,
    },
  ],
  rules: [
    {
      id: "ai-proxy",
      source_id: "geosite",
      classification: { kind: "domain", name: "category-ai" },
      action: "upstream",
      upstream_id: "exit-tokyo",
    },
    {
      id: "cn-direct",
      source_id: "geoip",
      classification: { kind: "country", name: "cn" },
      action: "direct",
    },
  ],
};

const routeStatus = [
  { rule_id: "ai-proxy", source_id: "geosite", classification: "category-ai", action: "upstream", exit: "exit-tokyo", domain_source: "dataset" },
  { rule_id: "cn-direct", source_id: "geoip", classification: "cn", action: "direct", exit: "direct", domain_source: "none" },
];

export const id = "shadowsocks-server";

export const scenes = [
  {
    name: "listens",
    title: "监听与账号",
    run: async (ui) => {
      await ui.waitFor("#listen-list .listen-card");
      await ui.waitFor("#share-host");
    },
  },
  {
    name: "routing",
    title: "数据集分流",
    run: async (ui) => {
      await ui.waitFor("#tab-btn-routing");
      await ui.click("#tab-btn-routing");
      await ui.waitFor("#routing-panel .route-item-card");
      await ui.waitFor("#route-default-action");
    },
  },
];

export async function startPreview({ root = moduleRoot } = {}) {
  const staticRoot = join(root, "plugins/shadowsocks-server/assets/ui");
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
      if (url.pathname === "/panel-api/agents") return json(200, { agents });
      if (url.pathname === "/panel-api/plugins/shadowsocks-server") return json(200, { instances: [{ targets: ["edge"] }] });
      if (url.pathname === "/api/execution") return json(200, { ready: true, execution, access: { can_read: true, can_write: true } });
      if (url.pathname === "/api/listens") return json(200, { ready: true, listens, access: { can_read: true, can_write: true } });
      if (url.pathname === "/api/routing") return json(200, { ready: true, routing, route_status: routeStatus, access: { can_read: true, can_write: true } });
      const relative = url.pathname === "/" ? "index.html" : decodeURIComponent(url.pathname.slice(1));
      const file = normalize(join(staticRoot, relative));
      if (!file.startsWith(staticRoot + sep) && file !== staticRoot) return json(403, { error: "forbidden" });
      const body = await readFile(file).catch(() => null);
      if (!body) {
        response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
        return response.end("404 page not found\n");
      }
      const extension = file.slice(file.lastIndexOf("."));
      response.writeHead(200, { "Content-Type": types[extension] || "application/octet-stream", "Cache-Control": "no-store" });
      response.end(body);
    } catch (error) {
      json(500, { error: error.message });
    }
  });
  await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  return {
    url: `http://127.0.0.1:${server.address().port}/?agent_id=edge`,
    close: async () => {
      server.closeAllConnections?.();
      await new Promise((resolveClose) => server.close(resolveClose));
    },
  };
}
