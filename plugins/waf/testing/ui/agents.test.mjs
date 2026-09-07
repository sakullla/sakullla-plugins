import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { createContext, runInContext } from "node:vm";

const script = await readFile(
  new URL("../../assets/ui/app.js", import.meta.url),
  "utf8",
);
const agents = [
  { id: "local", name: "本机", is_local: true, mode: "local", online: true },
  { id: "remote", name: "远程", online: false },
  { id: "uninstalled", name: "未安装", online: true },
];

async function load({ instances = [], requested = "", status = 200 } = {}) {
  const requests = [];
  const context = createContext({
    URLSearchParams,
    document: {
      querySelector: () => null,
      querySelectorAll: () => [],
      documentElement: { getAttribute: () => "light", setAttribute() {} },
    },
    window: { location: { search: `?agent_id=${requested}` } },
    fetch: async (path) => {
      requests.push(path);
      const isPlugin = path === "/panel-api/plugins/waf";
      const code = isPlugin ? status : 200;
      return {
        ok: code === 200,
        status: code,
        json: async () => (isPlugin ? { instances } : { agents }),
      };
    },
  });
  // Run the real page logic without automatically starting the UI.
  runInContext(script.replace(/start\(\);\s*$/, ""), context);
  await runInContext("loadAgents()", context);
  const result = JSON.parse(
    runInContext(
      "JSON.stringify({ ids: agentsCache.map(agent => agent.id), selected: selectedAgentID })",
      context,
    ),
  );
  return { ...result, requests };
}

test("only installed targets are selectable, including local and offline nodes", async () => {
  const result = await load({
    instances: [{ targets: ["local", "remote"] }],
    requested: "local",
  });
  assert.deepEqual(result.ids, ["local", "remote"]);
  assert.equal(result.selected, "local");
  assert.deepEqual(result.requests.sort(), [
    "/panel-api/agents",
    "/panel-api/plugins/waf",
  ]);
});

test("an uninstalled URL target cannot bypass deployment filtering", async () => {
  const result = await load({
    instances: [{ targets: ["local", "remote"] }],
    requested: "uninstalled",
  });
  assert.equal(result.selected, "");
});

test("a single installed node is selected after filtering", async () => {
  const result = await load({
    instances: [{ targets: ["local"] }],
    requested: "uninstalled",
  });
  assert.deepEqual(result.ids, ["local"]);
  assert.equal(result.selected, "local");
});

test("missing or malformed instances never expose all host nodes", async () => {
  for (const instances of [[], null, {}, [null, {}, { targets: null }]]) {
    const result = await load({ instances, requested: "local" });
    assert.deepEqual(result.ids, []);
    assert.equal(result.selected, "");
  }
});

test("targets from multiple instances are merged without duplicates or unknown nodes", async () => {
  const result = await load({
    instances: [
      { targets: ["local", "remote"] },
      { targets: ["local", "unknown", null, ""] },
    ],
  });
  assert.deepEqual(result.ids, ["local", "remote"]);
});

test("deployment lookup errors propagate instead of falling back to all nodes", async () => {
  for (const status of [403, 503]) {
    await assert.rejects(load({ status }), (error) => error.status === status);
  }
});
