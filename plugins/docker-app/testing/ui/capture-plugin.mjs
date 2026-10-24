// Docker app inventory and detail sections over the existing in-memory fixtures.
// The shared runner owns the browser, viewport, and gallery.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { UI_ASSETS, assetContentType } from "./assets.mjs";
import { createOperationsState, handleOperationsRequest } from "./fixtures/operations.mjs";
import { createResourcesState, handleResourcesRequest } from "./fixtures/resources.mjs";
import { agents, engineFor } from "./fixtures/workspace.mjs";

const moduleRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");

const openDetail = async (ui, section) => {
  await ui.waitFor("#app-list .app-card");
  await ui.click("#app-list .app-card");
  await ui.waitFor("#detail-overview .overview-stats");
  if (section && section !== "overview") await ui.click(`#detail-nav [data-section="${section}"]`);
};

export const id = "docker-app";

export const scenes = [
  {
    name: "apps",
    title: "应用列表",
    run: async (ui) => {
      await ui.waitFor("#app-list .app-card");
      await ui.waitFor("#deploy-toggle");
    },
  },
  {
    name: "deploy",
    title: "部署应用",
    run: async (ui) => {
      await ui.waitFor("#app-list .app-card");
      await ui.waitFor("#deploy-toggle");
      await ui.click("#deploy-toggle");
      await ui.waitFor("#create-form");
    },
  },
  {
    name: "detail",
    title: "应用概览",
    run: async (ui) => {
      await openDetail(ui, "overview");
    },
  },
  {
    name: "compose",
    title: "Compose",
    run: async (ui) => {
      await openDetail(ui, "compose");
      await ui.waitFor("#compose-form textarea");
    },
  },
  {
    name: "files",
    title: "工作区文件",
    run: async (ui) => {
      await openDetail(ui, "files");
      await ui.waitFor("#files-list li");
    },
  },
  {
    name: "logs",
    title: "服务日志",
    run: async (ui) => {
      await openDetail(ui, "logs");
      await ui.waitFor("#logs-view .log-line");
    },
  },
  {
    name: "http",
    title: "HTTP 入口",
    run: async (ui) => {
      await openDetail(ui, "http");
      await ui.waitFor("#detail-http .http-rule-main");
    },
  },
  {
    name: "backup",
    title: "备份",
    run: async (ui) => {
      await openDetail(ui, "backup");
      await ui.waitFor("#backup-run-form");
      await ui.waitFor(".backup-list tbody tr");
    },
  },
];

export async function startPreview({ root = moduleRoot } = {}) {
  const assets = new URL("../../assets/ui/", import.meta.url);
  const operations = createOperationsState();
  const resources = createResourcesState();
  const server = createServer(async (request, response) => {
    const json = (value, status = 200) => {
      response.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
      response.end(JSON.stringify(value));
    };
    try {
      const url = new URL(request.url, "http://127.0.0.1");
      if (url.pathname === "/favicon.ico") {
        response.writeHead(204);
        return response.end();
      }
      if (url.pathname === "/" || url.pathname === "/index.html") {
        operations.reset();
        resources.reset();
      }
      if (url.pathname === "/panel-api/agents") return json({ agents });
      if (url.pathname === "/panel-api/plugins/docker-app") return json({ instances: [{ targets: ["node-a", "node-b"] }] });
      if (url.pathname === "/api/engine") return json({ engine: engineFor(url.searchParams.get("agent_id")) });
      resources.apps = operations.apps;
      const record = {};
      if (/\/(files|logs|http-rule|http-rule-delete)$/.test(url.pathname) && await handleResourcesRequest({ url, request, json, state: resources, record })) return;
      if (await handleOperationsRequest({ url, request, json, state: operations, record })) return;
      const name = url.pathname === "/" ? "index.html" : decodeURIComponent(url.pathname.slice(1));
      if (!UI_ASSETS.includes(name) || request.method !== "GET") return json({ error: "Not found" }, 404);
      const body = await readFile(new URL(name, assets));
      response.writeHead(200, { "Content-Type": assetContentType(name), "Cache-Control": "no-store" });
      response.end(body);
    } catch (error) {
      json({ error: error.message }, 500);
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
