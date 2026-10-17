// Same-origin preview server for the accelerator-sources UI. It serves the
// embedded web/static assets with the production security headers and answers
// the catalog / offline APIs from deterministic fixtures, so captures never
// depend on Docker Hub or the network.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize, sep } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml" };

const day = 24 * 3600 * 1000;
const stamp = (daysAgo) => new Date(Date.UTC(2026, 9, 17) - daysAgo * day).toISOString();

const repositories = [
  { repo_name: "nginx", short_description: "Official build of Nginx.", star_count: 21034, pull_count: 12_400_000_000, is_official: true },
  { repo_name: "nginxinc/nginx-unprivileged", short_description: "Unprivileged NGINX Dockerfiles", star_count: 186, pull_count: 1_020_000_000, is_official: false },
  { repo_name: "bitnami/nginx", short_description: "Bitnami container image for NGINX", star_count: 197, pull_count: 640_000_000, is_official: false },
  { repo_name: "nginx/nginx-ingress", short_description: "NGINX and NGINX Plus Ingress Controllers for Kubernetes", star_count: 98, pull_count: 1_000_000_000, is_official: false },
  { repo_name: "nginx/unit", short_description: "This repository is retired, use the Docker official images.", star_count: 64, pull_count: 18_000_000, is_official: false },
  { repo_name: "linuxserver/nginx", short_description: "An Nginx container, brought to you by LinuxServer.io.", star_count: 212, pull_count: 96_000_000, is_official: false },
  { repo_name: "redis", short_description: "Redis is the world's fastest data platform for caching, vector search, and NoSQL databases.", star_count: 13140, pull_count: 8_100_000_000, is_official: true },
  { repo_name: "alpine", short_description: "A minimal Docker image based on Alpine Linux with a complete package index and only 5 MB in size!", star_count: 11380, pull_count: 9_300_000_000, is_official: true },
];

const tagNames = ["latest", "stable", "mainline", "alpine", "alpine-slim", "1.27", "1.27.3", "1.27.3-alpine", "1.27-alpine", "1.26", "1.26.2", "1.26-alpine", "stable-alpine", "mainline-alpine", "bookworm", "perl", "otel", "1.25", "1.25.5", "1.24"];
const images = [{ architecture: "amd64", os: "linux" }, { architecture: "arm64", os: "linux", variant: "v8" }, { architecture: "arm", os: "linux", variant: "v7" }];

const tagsFor = (image, page, size) => {
  const all = tagNames.map((name, index) => ({ name, full_size: 18_000_000 + index * 1_350_000, last_updated: stamp(index * 3 + 1), tag_status: "active", images }));
  const start = (page - 1) * size;
  return { count: all.length, next: start + size < all.length ? `page=${page + 1}` : null, previous: null, results: all.slice(start, start + size) };
};

export async function startMockServer({ root, port = 0, latency = 0, csp }) {
  const staticRoot = join(root, "plugins/accelerator-sources/web/static");
  const requests = [];
  const held = new Set();
  const plans = new Map();
  const broken = (list) => list.some((item) => /^fail|(^|\/)fail/.test(item));
  const server = createServer(async (request, response) => {
    const url = new URL(request.url, "http://mock.local");
    const path = url.pathname;
    requests.push({ method: request.method, path, query: Object.fromEntries(url.searchParams) });
    const json = (status, body) => {
      response.writeHead(status, { "Content-Type": "application/json" });
      response.end(JSON.stringify(body));
    };
    try {
      if (path.startsWith("/api/")) {
        if (latency) await delay(latency);
        const query = url.searchParams.get("q") || url.searchParams.get("image") || "";
        if (query.startsWith("hold")) {
          // Keep the request pending so captures can show loading states.
          held.add(response);
          response.on("close", () => held.delete(response));
          return;
        }
        if (query.startsWith("fail") && (path === "/api/search" || path === "/api/tags")) return json(502, { error: "catalog upstream failed" });
      }
      if (path === "/api/search") {
        const term = (url.searchParams.get("q") || "").trim().toLowerCase();
        if (!term) return json(400, { error: "search query is required" });
        const page = Number(url.searchParams.get("page") || 1);
        const size = Number(url.searchParams.get("page_size") || 25);
        const matches = term === "none" ? [] : repositories.filter((item) => item.repo_name.includes(term) || term.length < 3);
        const results = (matches.length ? matches : term === "none" ? [] : repositories).map((item) => ({ ...item, repo_owner: "", is_automated: false }));
        const start = (page - 1) * size;
        return json(200, { count: results.length, next: start + size < results.length ? "next" : null, previous: null, results: results.slice(start, start + size) });
      }
      if (path === "/api/tags") {
        const image = (url.searchParams.get("image") || "").trim();
        if (!image || /[@:]/.test(image)) return json(400, { error: "valid Docker Hub image is required" });
        if (image === "empty/none") return json(200, { count: 0, next: null, results: [] });
        const page = Number(url.searchParams.get("page") || 1);
        const size = Number(url.searchParams.get("page_size") || 25);
        return json(200, tagsFor(image, page, size));
      }
      if (path === "/api/offline/prepare") {
        if (request.method !== "POST") return json(405, { error: "offline prepare requires POST" });
        let raw = "";
        for await (const chunk of request) raw += chunk;
        const body = JSON.parse(raw || "{}");
        const list = Array.isArray(body.images) ? body.images : [];
        if (list.length === 0 || list.length > 16) return json(400, { error: "offline request requires 1-16 images" });
        // Like the real handler, prepare only records the plan; resolution
        // (and therefore failure) happens on HEAD/GET of the download URL.
        const token = (plans.size + 1).toString(16).padStart(48, "0");
        plans.set(token, list);
        return json(200, { download_url: `/api/offline/${token}`, expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString() });
      }
      if (path.startsWith("/api/offline")) {
        const token = path.slice("/api/offline/".length);
        const list = path === "/api/offline" ? url.searchParams.getAll("image") : plans.get(token);
        if (!list) return json(404, { error: "download token not found" });
        if (broken(list)) return json(502, { error: "unable to resolve image manifest" });
        if (request.method === "GET" && token) plans.delete(token);
        response.writeHead(200, { "Content-Type": "application/x-tar", "Content-Disposition": 'attachment; filename="images.tar"' });
        return response.end(request.method === "HEAD" ? undefined : Buffer.alloc(1024));
      }
      const relative = path === "/" ? "index.html" : decodeURIComponent(path.slice(1));
      const file = normalize(join(staticRoot, relative));
      if (!file.startsWith(staticRoot + sep)) return json(403, { error: "forbidden" });
      const body = await readFile(file).catch(() => null);
      if (!body) {
        response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
        return response.end("404 page not found\n");
      }
      response.writeHead(200, {
        "Content-Type": types[extname(file)] || "application/octet-stream",
        "Cache-Control": "no-store",
        "Content-Security-Policy": csp,
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
      });
      response.end(body);
    } catch (error) {
      json(500, { error: error.message });
    }
  });
  await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
  return {
    url: `http://127.0.0.1:${server.address().port}/`,
    requests,
    close: async () => {
      for (const response of held) response.destroy();
      server.closeAllConnections?.();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

// readProductionCSP keeps the preview header in lockstep with web/handler.go so
// inline styles or scripts that production would block also fail here.
export async function readProductionCSP(root) {
  const source = await readFile(join(root, "plugins/accelerator-sources/web/handler.go"), "utf8");
  const match = source.match(/"Content-Security-Policy",\s*"([^"]+)"/);
  if (!match) throw new Error("无法从 web/handler.go 读取 Content-Security-Policy");
  return match[1];
}
