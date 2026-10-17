// Web firewall overview, events, rules, and scope over a fixed node fixture.
// The shared runner owns the browser, viewport, and gallery.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const moduleRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");
const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8" };

const agents = [
  { id: "edge", name: "香港边缘", online: true, status: "online", last_seen_at: "2026-10-17T08:00:00Z" },
];

const entries = [
  { rule_ref: "1", frontend_url: "https://media.example.test", backend: "http://192.0.2.10:8000", enabled: true, attached: true, mode: "deny" },
  { rule_ref: "2", frontend_url: "https://api.example.test", backend: "http://192.0.2.10:8001", enabled: true, attached: true, mode: "observe" },
  { rule_ref: "3", frontend_url: "https://files.example.test", backend: "http://192.0.2.10:8002", enabled: true, attached: false, mode: "observe" },
  { rule_ref: "4", frontend_url: "https://admin.example.test", backend: "http://192.0.2.10:8003", enabled: true, attached: true, mode: "deny" },
];

const events = [
  { id: "event-1", site: "media.example.test", rule_id: "managed-sqli-union", reason: "rule_matched", disposition: "deny", digest: "a19b8b6b57c2f90a" },
  { id: "event-2", site: "api.example.test", rule_id: "managed-xss-script", reason: "rule_matched", disposition: "observe", digest: "b27c91aa10de4412" },
  { id: "event-3", site: "files.example.test", rule_id: "managed-path-traversal", reason: "body_window_skipped", disposition: "observe", digest: "c38d02bb21ef5523" },
  { id: "event-4", site: "admin.example.test", rule_id: "managed-sqli-schema", reason: "rule_matched", disposition: "deny", digest: "d49e13cc32fa6634" },
];

const modeOf = (event) => (event.disposition === "deny" ? "deny" : event.reason !== "rule_matched" ? "skip" : "observe");

const paginate = (items, page = 1) => {
  const total = items.length;
  const size = 10;
  const current = Math.min(Number(page) || 1, Math.max(1, Math.ceil(total / size) || 1));
  return { items: items.slice((current - 1) * size, current * size), page: current, page_size: size, total };
};

const readManaged = async (root) => {
  const text = await readFile(join(root, "plugins/waf/rules/managed.rules"), "utf8");
  return text.split(/\r?\n/).filter((line) => line && !line.startsWith("#")).map((line) => {
    const [id, target, needle] = line.split("|");
    return { id, target: String(target || "").toLowerCase(), needle };
  });
};

export const id = "waf";

export const scenes = [
  {
    name: "overview",
    title: "防护概览",
    run: async (ui) => {
      await ui.waitFor("#view-overview #stat-deny");
      await ui.waitFor("#protection-title");
    },
  },
  {
    name: "events",
    title: "安全事件",
    run: async (ui) => {
      await ui.waitFor("#tab-events");
      await ui.click("#tab-events");
      await ui.waitFor("#event-list tr");
    },
  },
  {
    name: "event-detail",
    title: "事件详情",
    run: async (ui) => {
      await ui.waitFor("#tab-events");
      await ui.click("#tab-events");
      await ui.waitFor("#event-list tr button");
      await ui.click("#event-list tr button");
      await ui.waitFor("#event-dialog[open]");
    },
  },
  {
    name: "rules",
    title: "检测规则",
    run: async (ui) => {
      await ui.waitFor("#tab-rules");
      await ui.click("#tab-rules");
      await ui.waitFor("#managed-list .managed-group");
    },
  },
  {
    name: "scope",
    title: "入口范围",
    run: async (ui) => {
      await ui.waitFor("#tab-scope");
      await ui.click("#tab-scope");
      await ui.waitFor("#entry-list li");
    },
  },
];

export async function startPreview({ root = moduleRoot } = {}) {
  const staticRoot = join(root, "plugins/waf/assets/ui");
  const managed = await readManaged(root);
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
      if (url.pathname === "/panel-api/plugins/waf") return json(200, { instances: [{ targets: ["edge"] }] });
      if (url.pathname === "/api/state") {
        const filtered = entries.filter((entry) => {
          const mode = entry.attached ? entry.mode : "skip";
          const wanted = url.searchParams.get("entry_mode");
          const query = (url.searchParams.get("entry_query") || "").toLowerCase();
          return (!wanted || mode === wanted) && JSON.stringify(entry).toLowerCase().includes(query);
        });
        const page = paginate(filtered, url.searchParams.get("entry_page") || 1);
        const filteredEvents = events.filter((event) => {
          const wanted = url.searchParams.get("event_mode");
          const query = (url.searchParams.get("event_query") || "").toLowerCase();
          return (!wanted || modeOf(event) === wanted) && JSON.stringify(event).toLowerCase().includes(query);
        });
        const eventPage = paginate(filteredEvents, url.searchParams.get("event_page") || 1);
        return json(200, {
          ready: true,
          events_available: true,
          error: "",
          events: eventPage.items,
          events_page: eventPage,
          recent_events: events.slice(0, 4),
          event_summary: { deny: 2, observe: 1, skip: 1 },
          entries: page.items,
          entries_page: page,
          managed_rules: managed,
          custom_rules: [],
          exclusions: [],
          coverage: { total: entries.length, deny: 2, observe: 1, unprotected: 1, disabled: 0 },
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
