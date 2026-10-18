import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile, mkdir, mkdtemp, writeFile, rm } from "node:fs/promises";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { createHash } from "node:crypto";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");
const assets = join(root, "plugins/ip-policy/assets/ui");
const output = join(root, "dist/ip-policy-ui");
const digest = "sha256:" + "a".repeat(64);
const configDefault = () => ({
  schema: "sakullla.ip-policy/v1",
  default_action: "allow",
  datasets: [],
  province_whitelist: [],
  rules: [],
});
let config = configDefault(),
  failBinding = false,
  failImport = false,
  entryRules = [],
  received = [],
  stateDelay = 0,
  writeDelay = 0,
  failState = false,
  deniedState = false;
const provinces = [
  { name: "北京市", classification: "cn-11" },
  { name: "广东省", classification: "cn-44" },
  { name: "广西壮族自治区", classification: "cn-45" },
];
const agents = [
  {
    id: "node-a",
    name: "香港节点",
    status: "online",
    last_seen_at: "2026-09-07T12:00:00Z",
    last_seen_ip: "192.0.2.1",
  },
  {
    id: "node-b",
    name: "洛杉矶节点",
    status: "offline",
    last_seen_at: "2026-09-06T12:00:00Z",
  },
  { id: "foreign-node", name: "不属于本插件的节点", status: "online" },
];
const entries = [
  {
    entry: {
      node_id: "node-a",
      kind: "http-rule",
      id: "1",
      token: "entry-token-000000000001",
    },
  },
  {
    entry: {
      node_id: "node-a",
      kind: "tcp-rule",
      id: "2",
      token: "entry-token-000000000002",
    },
  },
  {
    entry: {
      node_id: "node-b",
      kind: "udp-rule",
      id: "3",
      token: "entry-token-000000000003",
    },
  },
];
const version = {
  index_bytes: 1048576,
  digest,
  revision: "2026 年 9 月",
  source_id: "province-source",
  license_url: "https://example.test/license",
  coverage: { ipv4: "full", ipv6: "partial" },
};
let sources = [
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
const calls = [];
const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://localhost"),
      path = url.pathname;
    const json = (body, status = 200) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
    };
    let body = {};
    if (req.method === "POST" || req.method === "PUT") {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      if (path.endsWith("/uploads")) {
        const bytes = Buffer.concat(chunks);
        return json({
          artifact_digest:
            "sha256:" + createHash("sha256").update(bytes).digest("hex"),
        });
      }
      body = JSON.parse(Buffer.concat(chunks).toString() || "{}");
      received.push({ path, body });
    }
    calls.push({ path, query: Object.fromEntries(url.searchParams) });
    if (path === "/panel-api/agents") return json({ agents });
    if (path === "/panel-api/plugins/ip-policy")
      return json({
        instances: [{ targets: ["node-a", "node-b"] }],
        agent_statuses: [],
        package: { runtime: {} },
      });
    if (path.endsWith("/l4-rules"))
      return json({
        rules: [
          {
            id: 2,
            protocol: "tcp",
            name: "游戏入口",
            listen_host: "0.0.0.0",
            listen_port: 25565,
          },
          {
            id: 3,
            protocol: "udp",
            name: "DNS 服务",
            listen_host: "0.0.0.0",
            listen_port: 5353,
          },
        ],
      });
    if (path.match(/^\/panel-api\/agents\/[^/]+\/rules$/))
      return json({
        rules: [{ id: 1, frontend_url: "https://media.example.test" }],
      });
    if (path.endsWith("/api/state")) {
      if (failState) {
        res.destroy();
        return;
      }
      if (deniedState) return json({ error: "没有访问权限" }, 403);
      const token = url.searchParams.get("entry_token"),
        selected = entries.find((e) => e.entry.token === token);
      const policy = {
        desired: {
          settings: { default_mode: "observe" },
          version: { revision: 7, instance_version: 2 },
        },
      };
      const data = {
        ready: true,
        config,
        policy,
        access: { can_read: true, can_write: true },
        entries,
        entry: selected
          ? {
              ...policy,
              node: {
                phase: "active",
                applied: policy.desired,
                generation: "trusted-generation",
              },
            }
          : undefined,
        entry_overlay: {
          schema: "sakullla.ip-policy-overlay/v1",
          rules: entryRules,
        },
        provinces,
        issues: [],
        events: Array.from({ length: 12 }, (_, i) => ({
          code: "ip.rule_match",
          disposition: "deny",
          reason: "rule_matched",
          context: {
            node_id: url.searchParams.get("node_id"),
            entry_id: "1",
            source_address: "192.0.2." + i,
          },
        })),
        datasets: config.datasets.map((d) => ({
          definition: d,
          versions: [version],
          status: { phase: "active", applied: digest },
          classifications: [],
        })),
        bindings: config.datasets.map((d) => ({
          source_id: d.source_id,
          desired: { spec: { version_digest: digest } },
        })),
      };
      if (stateDelay) await delay(stateDelay);
      return json(data);
    }
    if (path === "/panel-api/datasets") return json({ sources });
    if (req.method === "PUT" && path.startsWith("/panel-api/datasets/")) {
      sources.push({ source: body.source, retrieval: body.retrieval });
      return json({ stored: true });
    }
    if (path === "/panel-api/datasets/control" && body.action === "import")
      return failImport
        ? json({ error: "文件格式无法识别" }, 400)
        : json({ stored: true });
    if (
      path === "/panel-api/datasets/control" &&
      body.action === "delete-source" &&
      body.source_id.startsWith("source-")
    ) {
      sources = sources.filter((s) => s.source.id !== body.source_id);
      return json({ stored: true });
    }
    if (path === "/panel-api/datasets/control")
      return json(
        { message: "dataset resource is referenced or retained" },
        409,
      );
    if (path.endsWith("/catalog")) {
      if (!url.searchParams.get("version_digest"))
        return json({ versions: [version] });
      return json({
        classifications: provinces.map((p) => ({
          classification: { kind: "region", name: p.classification },
          display_name: p.name,
          coverage: {
            ipv4: "full",
            ipv6: p.classification === "cn-11" ? "none" : "partial",
          },
        })),
        next_cursor: "",
      });
    }
    if (path.endsWith("/api/binding")) {
      if (failBinding) return json({ error: "版本校验失败，原配置保留" }, 409);
      if (writeDelay) await delay(writeDelay);
      config = body.binding.config;
      return json({ stored: true });
    }
    if (path.endsWith("/api/config")) {
      if (writeDelay) await delay(writeDelay);
      config = body.config;
      return json({ stored: true });
    }
    if (path.endsWith("/api/entry-rules")) {
      if (writeDelay) await delay(writeDelay);
      entryRules = body.rules;
      return json({ stored: true });
    }
    if (path.endsWith("/api/entry-mode")) {
      if (writeDelay) await delay(writeDelay);
      if (body.reset) entryRules = [];
      return json({ stored: true });
    }
    if (path.endsWith("/api/dataset")) {
      if (body.dataset.source) sources.push({ source: body.dataset.source });
      return json({ stored: true });
    }
    const requested = path.split("/").pop() || "index.html";
    const file = ["app.js", "style.css", "ui-kit.js", "ui-kit.css", "index.html"].includes(requested)
      ? requested
      : "index.html";
    res.writeHead(200, {
      "Content-Type": file.endsWith(".js")
        ? "text/javascript"
        : file.endsWith(".css")
          ? "text/css"
          : "text/html",
    });
    res.end(await readFile(join(assets, file)));
  } catch (e) {
    res.writeHead(500);
    res.end(JSON.stringify({ error: e.message }));
  }
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const url =
  "http://127.0.0.1:" + server.address().port + "/panel-api/plugins/ip-policy/";
if (process.argv.includes("--serve")) {
  console.log(url);
  await new Promise(() => {});
}
const temp = await mkdtemp(join(tmpdir(), "ip-policy-ui-"));
let browser, socket;
const checks = [];
const until = async (fn, label, ms = 12000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return;
    await delay(50);
  }
  throw new Error("Timed out: " + label);
};
try {
  const executable =
    process.env.NRE_UI_BROWSER ||
    "C:/Program Files/Google/Chrome/Application/chrome.exe";
  browser = spawn(
    executable,
    [
      "--headless=new",
      "--no-sandbox",
      "--disable-gpu",
      "--remote-debugging-port=0",
      "--user-data-dir=" + temp,
      "about:blank",
    ],
    { windowsHide: true, stdio: "ignore" },
  );
  let port;
  await until(async () => {
    try {
      port = (await readFile(join(temp, "DevToolsActivePort"), "utf8")).split(
        "\n",
      )[0];
      return !!port;
    } catch {
      return false;
    }
  }, "browser startup");
  const page = await (
    await fetch(
      "http://127.0.0.1:" + port + "/json/new?" + encodeURIComponent(url),
      { method: "PUT" },
    )
  ).json();
  socket = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });
  let next = 0;
  const pending = new Map(),
    errors = [];
  socket.addEventListener("message", ({ data }) => {
    const m = JSON.parse(data);
    if (m.id) {
      const p = pending.get(m.id);
      if (p) {
        pending.delete(m.id);
        m.error
          ? p.reject(new Error(JSON.stringify(m.error)))
          : p.resolve(m.result);
      }
    }
    if (m.method === "Runtime.exceptionThrown")
      errors.push(m.params.exceptionDetails);
  });
  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const id = ++next;
      pending.set(id, { resolve, reject });
      socket.send(JSON.stringify({ id, method, params }));
    });
  const evaluate = async (expression) => {
    const r = await send("Runtime.evaluate", {
      expression,
      awaitPromise: true,
      returnByValue: true,
    });
    if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails));
    return r.result.value;
  };
  const click = (selector) =>
    evaluate(
      "(()=>{const n=document.querySelector(" +
        JSON.stringify(selector) +
        ');if(!n||n.matches(":disabled")||!n.getClientRects().length)throw new Error("unreachable control: "+' +
        JSON.stringify(selector) +
        ");n.click();})()",
    );
  const fill = (selector, value) =>
    evaluate(
      "(()=>{const n=document.querySelector(" +
        JSON.stringify(selector) +
        ");n.value=" +
        JSON.stringify(value) +
        ';n.dispatchEvent(new Event("input",{bubbles:true}));n.dispatchEvent(new Event("change",{bubbles:true}));})()',
    );
  const visible = (selector) =>
    evaluate(
      "!!document.querySelector(" +
        JSON.stringify(selector) +
        ")?.getClientRects().length",
    );
  const body = () => evaluate("document.body.innerText");
  const check = async (name, fn) => {
    await fn();
    checks.push({ name, status: "passed" });
    console.log("PASS " + name);
  };
  const chooseNode = async (id) => {
    await click("#node-trigger");
    await click('[data-node="' + id + '"]');
    await until(
      async () => !(await body()).includes("正在读取策略状态"),
      "node loaded",
    );
  };
  await send("Runtime.enable");
  await send("Page.enable");
  await until(async () => await visible("#workspace"), "workspace");
  await check(
    "host themes follow localStorage and dark details use data-theme-family",
    async () => {
      await evaluate('localStorage.setItem("theme", "neko-dark")');
      await send("Page.reload", { ignoreCache: true });
      await until(
        async () =>
          (await evaluate('document.documentElement.getAttribute("data-theme")')) ===
          "neko-dark",
        "dark host theme",
      );
      assert.equal(
        await evaluate('document.documentElement.getAttribute("data-theme-family")'),
        "dark",
      );
      assert.match(
        await evaluate(
          'getComputedStyle(document.querySelector(".ip-status-strip")).backgroundImage',
        ),
        /gradient/,
      );
      await evaluate('localStorage.setItem("theme", "light")');
      await send("Page.reload", { ignoreCache: true });
      await until(
        async () =>
          (await evaluate('document.documentElement.getAttribute("data-theme-family")')) ===
          "light",
        "light host theme",
      );
      assert.equal(
        await evaluate(
          'getComputedStyle(document.querySelector(".ip-status-strip")).backgroundImage',
        ),
        "none",
      );
      await until(async () => await visible("#workspace"), "workspace after theme reload");
    },
  );
  await check(
    "node picker restricts membership and supports name/status filters",
    async () => {
      await click("#node-trigger");
      assert.equal(
        await evaluate('document.querySelectorAll("[data-node]").length'),
        2,
      );
      assert.equal((await body()).includes("不属于本插件的节点"), false);
      await click('[data-online="online"]');
      assert.equal(
        await evaluate('document.querySelectorAll("[data-node]").length'),
        1,
      );
      await click('[data-online=""]');
      await fill("#node-search", "香港");
      assert.equal(
        await evaluate('document.querySelectorAll("[data-node]").length'),
        1,
      );
      await click('[data-node="node-a"]');
      await until(
        async () => !(await body()).includes("正在读取策略状态"),
        "node loaded",
      );
    },
  );
  await check(
    "390 touch targets reach 44px in the node picker and sort field",
    async () => {
      await send("Emulation.setDeviceMetricsOverride", {
        width: 390,
        height: 900,
        deviceScaleFactor: 1,
        mobile: false,
      });
      await click("#node-trigger");
      const sizes = await evaluate(`(() => {
        const heights = (selector) =>
          [...document.querySelectorAll(selector)].map((node) =>
            Math.round(node.getBoundingClientRect().height),
          );
        return {
          rows: heights("#node-options button"),
          filters: heights("#node-filters button"),
          sort: heights("#node-sort"),
        };
      })()`);
      assert.ok(sizes.rows.length > 0, "node options rendered");
      for (const [name, values] of Object.entries(sizes)) {
        assert.ok(values.length > 0, name + " rendered");
        for (const height of values)
          assert.ok(height >= 44, name + " target is " + height + "px");
      }
      await click("#node-trigger");
      await send("Emulation.setDeviceMetricsOverride", {
        width: 1440,
        height: 1000,
        deviceScaleFactor: 1,
        mobile: false,
      });
    },
  );
  await check("entry labels show domains and ports, not raw IDs", async () => {
    await click('[data-tab="entry"]');
    const options = await evaluate(
      'document.querySelector("#entry-select").innerText',
    );
    assert.match(options, /media\.example\.test/);
    assert.match(options, /25565/);
    assert.equal(options.includes("node-a"), false);
    assert.equal(options.includes("DNS 服务"), false);
    assert.equal(await visible("#entry-empty"), true);
    assert.match(
      await evaluate('document.querySelector("#entry-empty-title").textContent'),
      /尚未选择入口/,
    );
    assert.equal(await visible("#entry-controls"), false);
    await fill("#entry-select", "entry-token-000000000001");
    await until(
      async () =>
        !(await evaluate('document.querySelector("#entry-controls").disabled')),
      "entry loaded",
    );
  });
  await check(
    "global draft survives node changes and entry inspection",
    async () => {
      await click('[data-tab="global"]');
      await fill('#rule-form [name="value"]', "192.0.2.8");
      await click("#rule-form button");
      assert.match(
        await evaluate('document.querySelector("#rules").innerText'),
        /192\.0\.2\.8/,
      );
      await chooseNode("node-b");
      await chooseNode("node-a");
      assert.match(
        await evaluate('document.querySelector("#rules").innerText'),
        /192\.0\.2\.8/,
      );
      assert.match(
        await evaluate('document.querySelector("#draft-status").innerText'),
        /未保存/,
      );
    },
  );
  await check(
    "geographic selector hides IP fields and requires real catalog choices",
    async () => {
      await fill('#rule-form [name="type"]', "classification");
      assert.equal(await visible("#rule-form [data-value-field]"), false);
      assert.equal(await visible("#rule-form [data-class-field]"), true);
      assert.equal(await visible("#province-empty"), true);
      await click("#setup-provinces");
      await fill("#source-select", "province-source");
      await until(
        async () =>
          await evaluate(
            'document.querySelectorAll("#catalog-classes input").length===3',
          ),
        "classifications loaded",
      );
    },
  );
  await check(
    "failed binding keeps the draft and successful binding enables provinces",
    async () => {
      await click("#select-province-classes");
      failBinding = true;
      await click("#bind");
      await until(
        async () => (await body()).includes("版本校验失败"),
        "binding error",
      );
      assert.equal(config.datasets.length, 0);
      assert.equal(
        await evaluate(
          'document.querySelector("#draft-status").innerText.includes("未保存")',
        ),
        true,
      );
      failBinding = false;
      await click("#bind");
      await until(() => config.datasets.length === 1, "binding saved");
      await until(
        async () =>
          !(await evaluate('document.querySelector("#bind").disabled')),
        "binding complete",
      );
      assert.deepEqual(
        received.filter((r) => r.path.endsWith("/api/binding")).at(-1).body
          .binding.node_ids,
        ["node-a"],
      );
      assert.equal(config.rules.length, 1);
      await click('[data-tab="global"]');
      assert.equal(await visible("#province-empty"), false);
      assert.equal(
        await evaluate(
          'document.querySelectorAll("#provinces input:not(:disabled)").length',
        ),
        3,
      );
      await fill("#province-search", "北京");
      assert.equal(
        await evaluate(
          '[...document.querySelectorAll("#provinces label")].filter((label) => !label.hidden).length',
        ),
        1,
      );
      await fill("#province-search", "");
      assert.equal(
        await evaluate(
          '[...document.querySelectorAll("#provinces label")].filter((label) => !label.hidden).length',
        ),
        3,
      );
      await click("#province-all");
      await click("#save");
      await until(
        () => config.province_whitelist.length === 3,
        "province save",
      );
      await until(
        async () =>
          !(await evaluate('document.querySelector("#save").disabled')),
        "save complete",
      );
    },
  );
  await check(
    "entry writes retain opaque authority and automatic rule IDs",
    async () => {
      await click('[data-tab="entry"]');
      await fill("#entry-select", "entry-token-000000000001");
      await until(
        async () =>
          !(await evaluate(
            'document.querySelector("#entry-controls").disabled',
          )),
        "entry ready",
      );
      await fill('#entry-rule-form [name="value"]', "198.51.100.3");
      await click("#entry-rule-form button");
      await until(() => entryRules.length === 1, "entry saved");
      await until(
        async () =>
          !(await evaluate(
            'document.querySelector("[data-tab=events]").disabled',
          )),
        "entry save complete",
      );
      const request = received
        .filter((r) => r.path.endsWith("/api/entry-rules"))
        .at(-1).body;
      assert.equal(request.entry.token, "entry-token-000000000001");
      assert.match(request.rules[0].id, /^rule-[a-f0-9]+$/);
      assert.equal(config.rules.length, 1);
    },
  );
  await check(
    "entry rule deletion confirms impact, shows progress and reports the result",
    async () => {
      writeDelay = 400;
      await click("#entry-rules [data-remove]");
      assert.equal(await visible("#confirm-dialog"), true);
      assert.match(
        await evaluate('document.querySelector("#confirm-message").textContent'),
        /无法撤销/,
      );
      assert.equal(entryRules.length, 1);
      await click("#confirm-ok");
      await until(
        async () =>
          (await evaluate(
            'document.querySelector("#entry-rules [data-remove]")?.textContent',
          )) === "正在删除…",
        "delete in progress",
      );
      assert.equal(
        await evaluate(
          'document.querySelector("#entry-rules [data-remove]").getAttribute("aria-busy")',
        ),
        "true",
      );
      assert.match(
        await evaluate('document.querySelector("#status").textContent'),
        /正在删除入口规则/,
      );
      await until(() => entryRules.length === 0, "entry rule deleted");
      await until(
        async () =>
          (await evaluate('document.querySelector("#status").textContent')) ===
          "已删除入口规则",
        "delete result",
      );
      assert.equal(
        await evaluate('document.querySelector("#entry-rules [data-remove]")'),
        null,
      );
      writeDelay = 0;
    },
  );
  await check(
    "diagnostics reuse recent plugin results without custom audit endpoints",
    async () => {
      await click('[data-tab="events"]');
      await until(
        async () => (await body()).includes("第 1 / 2 页"),
        "event page",
      );
      await click("#events-next");
      await until(
        async () => (await body()).includes("第 2 / 2 页"),
        "next page",
      );
      assert.equal(
        await evaluate('document.querySelectorAll("#events tr").length'),
        2,
      );
      assert.equal(
        calls.some((c) => c.path.includes("audit-events")),
        false,
      );
      const q = calls.filter((c) => c.path.endsWith("/api/state")).at(-1).query;
      assert.equal(q.node_id, "node-a");
      assert.match(await body(), /不代表完整历史/);
    },
  );
  await mkdir(output, { recursive: true });
  await check(
    "file import computes integrity automatically and keeps storage bounded",
    async () => {
      await click('[data-tab="data"]');
      await click("#add-source");
      const file = join(temp, "networks.txt");
      const bytes = "192.0.2.0/24\n";
      await writeFile(file, bytes);
      const dom = await send("DOM.getDocument");
      const input = await send("DOM.querySelector", {
        nodeId: dom.root.nodeId,
        selector: '#source-form [name="file"]',
      });
      await send("DOM.setFileInputFiles", {
        nodeId: input.nodeId,
        files: [file],
      });
      await fill('#source-form [name="name"]', "我的网段数据");
      await fill(
        '#source-form [name="license_url"]',
        "https://example.test/license",
      );
      await click('#source-form button[type="submit"]');
      await until(
        async () =>
          !(await evaluate('document.querySelector("#source-dialog").open')),
        "source saved",
      );
      const request = received.find((r) =>
        r.path.startsWith("/panel-api/datasets/source-"),
      );
      assert.equal(request.body.source.refresh_interval_seconds, 0);
      assert.equal(request.body.retrieval.allow_private, false);
      const imported = received.find((r) => r.body.action === "import").body;
      assert.equal(
        imported.candidate.expected_digest,
        "sha256:" + createHash("sha256").update(bytes).digest("hex"),
      );
      assert.equal(
        imported.candidate.expected_digest,
        imported.candidate.artifact_digest,
      );
      assert.equal(
        await evaluate('!!document.querySelector("[name=checksum_url]")'),
        false,
      );
      await until(
        async () =>
          !(await evaluate(
            'document.querySelector("[data-tab=data]").disabled',
          )),
        "source operation complete",
      );
      await fill("#source-select", "province-source");
      await until(
        async () =>
          await evaluate(
            'document.querySelectorAll("#catalog-classes input").length===3',
          ),
        "catalog restored",
      );
      await click("#delete-version");
      await click("#confirm-ok");
      await until(
        async () => (await body()).includes("仍被使用或用于回退"),
        "referenced version protected",
      );
      assert.equal(config.datasets.length, 1);
      assert.deepEqual(await evaluate('Object.keys(localStorage).filter((k) => k !== "theme")'), []);
      await until(
        async () =>
          !(await evaluate(
            'document.querySelector("[data-tab=data]").disabled',
          )),
        "delete request complete",
      );
    },
  );
  await check(
    "oversized files are rejected before creating or uploading data",
    async () => {
      await click("#add-source");
      const count = received.length;
      await evaluate(
        '(()=>{const transfer=new DataTransfer();transfer.items.add(new File([new Uint8Array(128*1024*1024+1)],"too-large.mmdb"));const input=document.querySelector("#source-form [name=file]");input.files=transfer.files;input.dispatchEvent(new Event("change"));})()',
      );
      await click('#source-form button[type="submit"]');
      assert.match(
        await evaluate('document.querySelector("#source-error").textContent'),
        /128 MiB/,
      );
      assert.equal(received.length, count);
      await click("#source-close");
      await evaluate('document.querySelector("#source-form").reset()');
    },
  );
  await check(
    "failed imports remove newly created unreferenced sources",
    async () => {
      const count = sources.length;
      failImport = true;
      await click("#add-source");
      const file = join(temp, "invalid.mmdb");
      await writeFile(file, "invalid data");
      const dom = await send("DOM.getDocument"),
        input = await send("DOM.querySelector", {
          nodeId: dom.root.nodeId,
          selector: '#source-form [name="file"]',
        });
      await send("DOM.setFileInputFiles", {
        nodeId: input.nodeId,
        files: [file],
      });
      await click('#source-form button[type="submit"]');
      await until(
        async () => (await body()).includes("文件格式无法识别"),
        "import rejected",
      );
      assert.equal(sources.length, count);
      assert.equal(config.datasets.length, 1);
      assert.ok(
        received.some(
          (r) =>
            r.body.action === "delete-source" &&
            r.body.source_id.startsWith("source-"),
        ),
      );
      await until(
        async () =>
          !(await evaluate('document.querySelector("#source-close").disabled')),
        "import cleanup complete",
      );
      await click("#source-close");
      failImport = false;
    },
  );
  await click("#load");
  await until(
    async () =>
      (await evaluate('document.querySelector("#status").textContent')) ===
      "状态已更新",
    "clean final preview state",
  );
  await check("sticky save bar and unsaved indicator stay observable", async () => {
    await click('[data-tab="global"]');
    assert.equal(
      await evaluate('getComputedStyle(document.querySelector("#save-bar")).position'),
      "sticky",
    );
    await fill('#rule-form [name="type"]', "ip");
    await fill('#rule-form [name="value"]', "203.0.113.9");
    await click("#rule-form button");
    assert.equal(
      await evaluate('document.querySelector("#dirty-badge").hidden'),
      false,
    );
    assert.match(
      await evaluate('document.querySelector("#draft-status").textContent'),
      /未保存/,
    );
    writeDelay = 400;
    await click("#save");
    assert.equal(
      await evaluate('document.querySelector("#save").textContent'),
      "正在保存…",
    );
    assert.equal(
      await evaluate('document.querySelector("#save").getAttribute("aria-busy")'),
      "true",
    );
    assert.match(
      await evaluate('document.querySelector("#status").textContent'),
      /正在保存全局配置/,
    );
    await until(
      () => config.rules.some((rule) => rule.selector.value === "203.0.113.9"),
      "draft rule saved",
    );
    await until(
      async () => await evaluate('!!document.querySelector(".ui-toast")'),
      "save toast",
    );
    await until(
      async () => await evaluate('document.querySelector("#dirty-badge").hidden'),
      "dirty cleared",
    );
    await until(
      async () => !(await evaluate('document.querySelector("#save").disabled')),
      "save settled",
    );
    assert.equal(
      await evaluate('document.querySelector("#save").hasAttribute("aria-busy")'),
      false,
    );
    assert.equal(
      await evaluate('document.querySelector("#save").textContent'),
      "保存配置",
    );
    writeDelay = 0;
  });
  await check(
    "refresh and permission failures explain the next step without losing preset copy",
    async () => {
      const loadPreset = (
        await evaluate('document.querySelector("#load-error-desc").textContent')
      ).trim();
      failState = true;
      await click("#load");
      await until(async () => await visible("#load-error"), "refresh error shown");
      assert.match(
        await evaluate('document.querySelector("#status").textContent'),
        /网络连接失败/,
      );
      const detail = await evaluate(
        'document.querySelector("#load-error-detail").textContent',
      );
      assert.match(detail, /网络连接失败/);
      assert.match(detail, /上次读取的数据/);
      assert.equal(
        (
          await evaluate(
            'document.querySelector("#load-error-desc").textContent',
          )
        ).trim(),
        loadPreset,
      );
      assert.equal(await visible("#rules"), true);
      failState = false;
      await click("#load");
      await until(
        async () => !(await visible("#load-error")),
        "refresh recovered",
      );

      const deniedPreset = (
        await evaluate('document.querySelector("#denied-desc").textContent')
      ).trim();
      deniedState = true;
      await click("#load");
      await until(async () => await visible("#denied-state"), "denied shown");
      assert.equal(
        (
          await evaluate('document.querySelector("#denied-desc").textContent')
        ).trim(),
        deniedPreset,
      );
      assert.match(deniedPreset, /联系管理员/);
      assert.match(
        await evaluate('document.querySelector("#status").textContent'),
        /权限/,
      );
      deniedState = false;
      await click("#load");
      await until(
        async () => !(await visible("#denied-state")),
        "denied recovered",
      );
    },
  );
  await check("390 rule table keeps match source readable", async () => {
    await send("Emulation.setDeviceMetricsOverride", {
      width: 390,
      height: 1000,
      deviceScaleFactor: 1,
      mobile: false,
    });
    await click('[data-tab="global"]');
    assert.equal(
      await evaluate(
        'getComputedStyle(document.querySelector("#global-rules th.ip-type-col")).display',
      ),
      "none",
    );
    assert.equal(
      await evaluate(
        'getComputedStyle(document.querySelector("#global-rules .ip-rule-type-inline")).display',
      ),
      "block",
    );
    const sourceWidth = await evaluate(
      'Math.round(document.querySelector("#global-rules tbody tr td").getBoundingClientRect().width)',
    );
    assert.ok(sourceWidth >= 110, "match source column is " + sourceWidth + "px");
    await send("Emulation.setDeviceMetricsOverride", {
      width: 1440,
      height: 1000,
      deviceScaleFactor: 1,
      mobile: false,
    });
  });
  for (const width of [1440, 768, 390]) {
    await send("Emulation.setDeviceMetricsOverride", {
      width,
      height: 1000,
      deviceScaleFactor: 1,
      mobile: false,
    });
    for (const tab of ["global", "entry", "data", "events"]) {
      await click('[data-tab="' + tab + '"]');
      await delay(120);
      assert.ok(
        await evaluate(
          "document.documentElement.scrollWidth<=window.innerWidth",
        ),
        "no horizontal overflow at " + width + "/" + tab,
      );
      const capture = await send("Page.captureScreenshot", {
        format: "png",
        captureBeyondViewport: true,
      });
      await writeFile(
        join(output, tab + "-" + width + ".png"),
        Buffer.from(capture.data, "base64"),
      );
    }
  }
  assert.equal(errors.length, 0, "browser runtime errors");
  await send("Emulation.setDeviceMetricsOverride", {
    width: 1440,
    height: 1000,
    deviceScaleFactor: 1,
    mobile: false,
  });
  await click('[data-tab="data"]');
  await click("#add-source");
  const importCapture = await send("Page.captureScreenshot", { format: "png" });
  await writeFile(
    join(output, "import-dialog.png"),
    Buffer.from(importCapture.data, "base64"),
  );
  await click("#source-close");
  await writeFile(
    join(output, "report.json"),
    JSON.stringify({ status: "passed", checks, screenshots: 13 }, null, 2),
  );
  console.log(
    "UI verification passed: " + checks.length + " checks, 13 screenshots",
  );
} catch (error) {
  console.error(error);
  process.exitCode = 1;
} finally {
  socket?.close();
  browser?.kill();
  server.close();
  await delay(200);
  await rm(temp, {
    recursive: true,
    force: true,
    maxRetries: 5,
    retryDelay: 200,
  }).catch(() => {});
}
