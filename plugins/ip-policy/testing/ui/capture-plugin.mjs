// IP policy workspace with fixed nodes, rules, datasets, and recent events.
// The shared runner owns the browser, viewport, and gallery.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const moduleRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");
const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8" };
const digest = "sha256:" + "a".repeat(64);

const agents = [
  { id: "node-a", name: "香港节点", status: "online", last_seen_at: "2026-10-17T08:00:00Z", last_seen_ip: "192.0.2.10" },
  { id: "node-b", name: "洛杉矶节点", status: "offline", last_seen_at: "2026-10-16T08:00:00Z" },
];

const provinces = [
  { name: "北京市", classification: "cn-11" },
  { name: "广东省", classification: "cn-44" },
  { name: "广西壮族自治区", classification: "cn-45" },
];

const config = {
  schema: "sakullla.ip-policy/v1",
  default_action: "deny",
  datasets: [
    {
      id: "geo",
      source_id: "province-source",
      name: "中国省份",
      classifications: [
        { id: "beijing", kind: "region", name: "cn-11" },
        { id: "guangdong", kind: "region", name: "cn-44" },
        { id: "guangxi", kind: "region", name: "cn-45" },
      ],
    },
  ],
  province_whitelist: [{ dataset_id: "geo", classification_id: "beijing" }],
  rules: [
    { id: "rule-lab", action: "deny", selector: { type: "cidr", value: "192.0.2.0/24" } },
    { id: "rule-beijing", action: "allow", selector: { type: "classification", dataset_id: "geo", classification_id: "beijing" } },
  ],
};

const entries = [
  { entry: { node_id: "node-a", kind: "http-rule", id: "1", token: "entry-token-000000000001" } },
  { entry: { node_id: "node-a", kind: "tcp-rule", id: "2", token: "entry-token-000000000002" } },
  { entry: { node_id: "node-b", kind: "udp-rule", id: "3", token: "entry-token-000000000003" } },
];

const entryRules = [
  { id: "entry-rule-1", action: "deny", selector: { type: "ip", value: "198.51.100.8" } },
];

const version = {
  index_bytes: 1048576,
  digest,
  revision: "2026 年 10 月",
  source_id: "province-source",
  license_url: "https://example.test/license",
  coverage: { ipv4: "full", ipv6: "partial" },
};

const sources = [
  {
    source: {
      id: "province-source",
      name: "中国省份数据库",
      format: "geo-mmdb",
      url: "https://example.test/data.mmdb",
      license_url: "https://example.test/license",
    },
    current_digest: digest,
  },
];

const policy = {
  desired: {
    settings: { default_mode: "observe" },
    version: { revision: 7, instance_version: 2 },
  },
};

const stateFor = (url) => {
  const token = url.searchParams.get("entry_token");
  const node = url.searchParams.get("node_id") || "node-a";
  const selected = entries.find((item) => item.entry.token === token);
  return {
    ready: true,
    config,
    policy,
    access: { can_read: true, can_write: true },
    entries,
    entry: selected
      ? {
          ...policy,
          node: { phase: "active", applied: { settings: { default_mode: "observe", entry_mode: "enforce" }, version: { revision: 7 } }, generation: "trusted-generation" },
        }
      : undefined,
    entry_overlay: { schema: "sakullla.ip-policy-overlay/v1", rules: entryRules },
    provinces,
    issues: [],
    events: [0, 1, 2, 3].map((index) => ({
      code: "ip.rule_match",
      disposition: index % 2 === 0 ? "deny" : "observe",
      reason: "rule_matched",
      created_at: `2026-10-17T0${index}:15:00Z`,
      context: { node_id: node, entry_id: "1", source_address: `192.0.2.${index + 8}`, rule_id: index % 2 === 0 ? "rule-lab" : "entry-rule-1" },
    })),
    datasets: config.datasets.map((definition) => ({
      definition,
      versions: [version],
      status: { phase: "active", applied: digest },
      classifications: [],
    })),
    bindings: config.datasets.map((definition) => ({
      source_id: definition.source_id,
      desired: { spec: { version_digest: digest } },
    })),
  };
};

export const id = "ip-policy";
export const themeMode = "host";

export const scenes = [
  {
    name: "global",
    title: "全局策略",
    run: async (ui) => {
      await ui.waitFor("#rules tr");
      await ui.waitFor("#provinces label");
      await ui.waitFor("#desired-mode");
      await ui.waitFor(".ip-status-strip");
    },
  },
  {
    name: "entry",
    title: "入口策略",
    run: async (ui) => {
      await ui.waitFor("#workspace");
      await ui.click('[data-tab="entry"]');
      await ui.waitFor("#entry-select");
      await ui.evaluate(`(async () => {
        const end = Date.now() + 8000;
        const ready = () => document.querySelector('#entry-select option[value="entry-token-000000000001"]');
        while (Date.now() < end) {
          if (ready()) return;
          await new Promise((resolve) => setTimeout(resolve, 40));
        }
        throw new Error("入口选项未出现");
      })()`);
      await ui.fill("#entry-select", "entry-token-000000000001");
      await ui.evaluate(`(async () => {
        const end = Date.now() + 8000;
        while (Date.now() < end) {
          if ((document.querySelector("#entry-hint")?.textContent || "").includes("仅作用于")) return;
          await new Promise((resolve) => setTimeout(resolve, 40));
        }
        throw new Error("入口未选中");
      })()`);
      await ui.waitFor("#entry-rules tr");
    },
  },
  {
    name: "data",
    title: "数据源",
    run: async (ui) => {
      await ui.waitFor("#workspace");
      await ui.click('[data-tab="data"]');
      await ui.waitFor("#source-select");
      await ui.evaluate(`(async () => {
        const end = Date.now() + 8000;
        while (Date.now() < end) {
          if (document.querySelector('#source-select option[value="province-source"]')) return;
          await new Promise((resolve) => setTimeout(resolve, 40));
        }
        throw new Error("数据源选项未出现");
      })()`);
      await ui.fill("#source-select", "province-source");
      await ui.waitFor("#catalog-classes label");
      await ui.waitFor("#datasets .dataset-card");
    },
  },
  {
    name: "events",
    title: "诊断事件",
    run: async (ui) => {
      await ui.waitFor("#workspace");
      await ui.click('[data-tab="events"]');
      await ui.waitFor("#events tr");
    },
  },
];

export async function startPreview({ root = moduleRoot } = {}) {
  const staticRoot = join(root, "plugins/ip-policy/assets/ui");
  const server = createServer(async (request, response) => {
    const url = new URL(request.url, "http://127.0.0.1");
    const json = (status, body) => {
      response.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
      response.end(status === 204 ? undefined : JSON.stringify(body));
    };
    try {
      if (url.pathname === "/favicon.ico") {
        response.writeHead(204);
        return response.end();
      }
      if (url.pathname === "/panel-api/agents") return json(200, { agents });
      if (url.pathname === "/panel-api/plugins/ip-policy") {
        return json(200, { instances: [{ targets: ["node-a", "node-b"] }], agent_statuses: [], package: { runtime: {} } });
      }
      if (url.pathname.endsWith("/l4-rules")) {
        return json(200, {
          rules: [
            { id: 2, protocol: "tcp", name: "游戏入口", listen_host: "0.0.0.0", listen_port: 25565 },
            { id: 3, protocol: "udp", name: "DNS 服务", listen_host: "0.0.0.0", listen_port: 5353 },
          ],
        });
      }
      if (/^\/panel-api\/agents\/[^/]+\/rules$/.test(url.pathname)) {
        return json(200, { rules: [{ id: 1, frontend_url: "https://media.example.test" }] });
      }
      if (url.pathname === "/api/state") return json(200, stateFor(url));
      if (url.pathname === "/panel-api/datasets") return json(200, { sources });
      if (url.pathname.endsWith("/catalog")) {
        if (!url.searchParams.get("version_digest")) return json(200, { versions: [version] });
        return json(200, {
          classifications: provinces.map((province) => ({
            classification: { kind: "region", name: province.classification },
            display_name: province.name,
            coverage: { ipv4: "full", ipv6: province.classification === "cn-11" ? "none" : "partial" },
          })),
          next_cursor: "",
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
    url: `http://127.0.0.1:${server.address().port}/?agent_id=node-a`,
    close: async () => {
      server.closeAllConnections?.();
      await new Promise((resolveClose) => server.close(resolveClose));
    },
  };
}
