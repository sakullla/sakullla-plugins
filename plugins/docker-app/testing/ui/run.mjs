import { UI_ASSETS, assetContentType, FIXTURE_ASSET_CSP } from "./assets.mjs";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { access, readFile, mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { createHash } from "node:crypto";
import { agents, makeApp, longApp, engineFor } from "./fixtures/workspace.mjs";
import { runCompose } from "./compose.mjs";
import { runOperations } from "./operations.mjs";
import { runResources } from "./resources.mjs";
import { runExperience } from "./experience.mjs";
import { runAll } from "./all.mjs";
import { runHost } from "./host.mjs";
import { runCompanion } from "./companion.mjs";
import { createResourcesState, handleResourcesRequest } from "./fixtures/resources.mjs";
import { createOperationsState, handleOperationsRequest } from "./fixtures/operations.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "../../../..");
const assets = resolve(here, "../../assets/ui");
const suite = process.argv[process.argv.indexOf("--suite") + 1];
if (!["workspace", "compose", "operations", "resources", "experience", "all", "host", "companion"].includes(suite)) throw new Error(`Suite ${suite || "<missing>"} is not implemented; no tests were run.`);

if (suite === "all") {
  try { await runAll({runner:fileURLToPath(import.meta.url),repo,assets}); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
  process.exit(process.exitCode || 0);
}

async function eventually(check, description, timeout = 10000) {
  const until = Date.now() + timeout;
  do {
    if (await check()) return;
    await delay(40);
  } while (Date.now() < until);
  throw new Error(`Timed out: ${description}`);
}

async function findBrowser() {
  const candidates = [process.env.NRE_UI_BROWSER,
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    "/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"].filter(Boolean);
  for (const candidate of candidates) {
    try { await access(candidate); return candidate; } catch { /* Try next actual executable. */ }
  }
  throw new Error("No browser found. Set NRE_UI_BROWSER to a Chromium/Chrome/Edge executable. Nothing was verified.");
}

class Page {
  constructor(socket) {
    this.socket = socket; this.id = 0; this.pending = new Map(); this.errors = []; this.navigations = 0; this.javascriptDialogs = [];
    socket.addEventListener("message", ({ data }) => {
      const message = JSON.parse(data);
      const pending = this.pending.get(message.id);
      if (pending) {
        this.pending.delete(message.id);
        clearTimeout(pending.timer);
        if (message.error) pending.reject(new Error(JSON.stringify(message.error)));
        else pending.resolve(message.result);
      }
      if (message.method === "Runtime.exceptionThrown") this.errors.push(message.params.exceptionDetails.text);
      if (message.method === "Page.frameNavigated" && !message.params.frame.parentId) this.navigations += 1;
      if (message.method === "Page.javascriptDialogOpening") {
        this.javascriptDialogs.push(message.params.type);
        if (message.params.type === "beforeunload") this.send("Page.handleJavaScriptDialog", {accept:true});
      }
    });
  }
  send(method, params = {}, sessionId) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 15000);
      this.pending.set(id, { resolve, reject, timer });
      this.socket.send(JSON.stringify({ id, method, params, ...(sessionId ? {sessionId} : {}) }));
    });
  }
  async evaluate(expression) {
    const result = await this.send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  }
  async click(selector) {
    const point = await this.evaluate(`(() => {
      const node = document.querySelector(${JSON.stringify(selector)});
      if (!node || node.disabled || !node.getClientRects().length) throw new Error('Unreachable control: ' + ${JSON.stringify(selector)});
      node.scrollIntoView({block:'center'});
      const r = node.getBoundingClientRect();
      const hit = document.elementFromPoint(r.x+r.width/2,r.y+r.height/2);
      if (hit && !node.contains(hit)) throw new Error('Covered control: ' + ${JSON.stringify(selector)} + ' by ' + hit.tagName + '#' + hit.id + '.' + hit.className);
      return {x:r.x+r.width/2, y:r.y+r.height/2};
    })()`);
    await this.send("Input.dispatchMouseEvent", { type: "mousePressed", button: "left", clickCount: 1, ...point });
    await this.send("Input.dispatchMouseEvent", { type: "mouseReleased", button: "left", clickCount: 1, ...point });
  }
  async key(key, {shift = false, ctrl = false, meta = false} = {}) {
    const code = key === " " ? "Space" : key === "s" || key === "S" ? "KeyS" : key;
    const keyCode = {Escape:27,Enter:13,Tab:9,ArrowDown:40,ArrowUp:38," ":32,s:83,S:83}[key] || 0;
    const modifiers = (ctrl ? 2 : 0) | (meta ? 4 : 0) | (shift ? 8 : 0);
    await this.send("Input.dispatchKeyEvent", {type:"keyDown",key,code,windowsVirtualKeyCode:keyCode,modifiers});
    await this.send("Input.dispatchKeyEvent", {type:"keyUp",key,code,windowsVirtualKeyCode:keyCode,modifiers});
  }
  visible(selector) { return this.evaluate(`!!document.querySelector(${JSON.stringify(selector)})?.getClientRects().length`); }
  waitVisible(selector) { return eventually(() => this.visible(selector), `visible ${selector}`); }
  async selectAgent(id) {
    await this.click(".agent-search-select__trigger");
    const name = agents.find((agent) => agent.id === id)?.name;
    // Locate the rendered option by its user-visible name; no application internals.
    const index = await this.evaluate(`Array.from(document.querySelectorAll('.agent-search-select__option')).findIndex(n => n.querySelector('.agent-search-select__option-name')?.textContent === ${JSON.stringify(name)})`);
    assert.ok(index >= 0, `node option ${id}`);
    await this.click(`.agent-search-select__option:nth-child(${index + 1})`);
  }
}

if (suite === "companion") {
  try {await runCompanion({Page,eventually,findBrowser,repo});}
  catch(error) {console.error(error);process.exitCode=1;}
  process.exit(process.exitCode || 0);
}

if (suite === "host") {
  try { await runHost({Page,eventually,findBrowser,repo,assets}); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
  process.exit(process.exitCode || 0);
}

const requests = [];
const operationsState = createOperationsState();
const resourcesState = createResourcesState();
const composeState = { previewError: "", saveError: "", listError: false, risk: false, previewCount: 0, saveCount: 0, lastSave: null, file: "original\n", fileError: false, fileListError: false };
const gates = new Map();
let apps = [makeApp("alpha"), makeApp("beta"), longApp, makeApp("bravo", "node-b")];
const appSummary = ({compose: _compose, env: _env, ...summary}) => summary;
const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url, "http://fixture.invalid");
    const record = { method: request.method, path: url.pathname, agent: url.searchParams.get("agent_id") };
    requests.push(record);
    const gate = gates.get(url.pathname + url.search);
    if (gate) { gate.seen = true; await gate.promise; }
    const json = (payload, status = 200) => { response.writeHead(status, { "Content-Type": "application/json" }); response.end(JSON.stringify(payload)); };
    if (url.pathname === "/panel-api/agents") return json({ agents });
    if (url.pathname === "/panel-api/plugins/docker-app") return json({ instances: [{ targets: agents.map((a) => a.id) }] });
    if (url.pathname === "/api/engine") {
      const id = record.agent;
      return id === "denied" ? json({ error: "无权访问" }, 403) : json({ engine: engineFor(id) });
    }
    if (suite === "resources" && await handleResourcesRequest({url, request, json, state:resourcesState, record})) return;
    if (suite === "operations" && await handleOperationsRequest({url, request, json, state:operationsState, record})) return;
    if (suite === "compose" && request.method === "POST") {
      let raw = "";
      for await (const chunk of request) raw += chunk;
      const body = raw ? JSON.parse(raw) : {};
      if (url.pathname === "/api/apps/preview") {
        composeState.previewCount += 1;
        if (composeState.previewError || !body.compose?.includes("services:")) return json({error: composeState.previewError || "Compose YAML 无效，请检查服务配置。"}, 422);
        return json({preview:{digest:"fixture-digest", items:composeState.risk ? [{kind:"privileged",target:"web"}] : []}});
      }
      if (url.pathname === "/api/apps") {
        composeState.saveCount += 1;
        composeState.lastSave = body;
        if (composeState.saveError) return json({error:composeState.saveError}, 422);
        if (body.compose.includes("REQUIRED_VALUE") && !body.env.includes("REQUIRED_VALUE=")) return json({error:"缺少必需环境变量，请填写 .env。"}, 422);
        const existing = apps.find((item) => item.id === body.id);
        const app = makeApp(body.id, body.agent_id, {
          compose:body.compose, env:body.env || existing?.env || "", auto_update:body.auto_update,
        });
        apps = [...apps.filter((item) => item.id !== body.id), app];
        return json({apps:[appSummary(app)]});
      }
      if (url.pathname.endsWith("/files")) {
        record.action = body.action;
        if (body.action === "list") return stateFileList();
        function stateFileList() {
          if (composeState.fileListError) return json({error:"目录读取失败。"},500);
          return json({path:".",entries:[{name:"config.txt",path:"config.txt",dir:false,size:composeState.file.length}]});
        }
        if (body.action === "read") return json({content:composeState.file});
        if (composeState.fileError) return json({error:"文件保存失败。"},500);
        if (body.action === "write") { composeState.file = body.content; return json({accepted:true}); }
      }
    }
    if (url.pathname === "/api/apps") {
      if (suite === "compose" && composeState.listError) return json({error:"列表读取失败。"}, 500);
      return json({ apps: apps.filter((app) => app.agent_id === record.agent).map(appSummary) });
    }
    if (url.pathname === "/api/disk-cleanup") return json({ cleanup: { steps: [] } });
    if (request.method === "POST" && url.pathname === "/api/apps/alpha/delete") {
      apps = apps.filter((app) => app.id !== "alpha");
      return json({ accepted: true });
    }
    if (request.method === "POST" && url.pathname === "/api/apps/beta/delete") return json({ error: "应用删除失败，请重试。" }, 500);
    if (/^\/api\/apps\/[^/]+$/.test(url.pathname)) {
      if (suite === "compose" && composeState.detailError) return json({error:"详情读取失败。"}, 500);
      const app = apps.find((app) => app.id === decodeURIComponent(url.pathname.split("/").pop()));
      return json({ app }, app ? 200 : 404);
    }
    if (request.method !== "GET") return json({ error: "Unexpected mutation in workspace suite" }, 500);
    if (url.pathname === "/theme-frame.html" || url.pathname === "/theme-writer.html") {
      response.writeHead(200,{"Content-Type":"text/html"});
      response.end(url.pathname === "/theme-frame.html" ? '<!doctype html><html data-theme="sakura-night"><body style="margin:0"><iframe title="Theme fixture" src="/?agent_id=node-a" style="width:100%;height:100vh;border:0"></iframe></body></html>' : '<!doctype html><title>Host theme fixture</title>');
      return;
    }
    const name = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
    if (!UI_ASSETS.includes(name)) { response.writeHead(404); response.end(); return; }
    response.writeHead(200, { "Content-Type": assetContentType(name), "Content-Security-Policy": FIXTURE_ASSET_CSP });
    response.end(await readFile(join(assets, name)));
  } catch (error) { response.writeHead(500); response.end(String(error)); }
});

function hold(path) {
  const gate = { seen: false };
  gate.promise = new Promise((resolve) => { gate.release = () => { gates.delete(path); resolve(); }; });
  gate.detach = () => gates.delete(path);
  gates.set(path, gate);
  return gate;
}

const evidence = { kind: "fixture-browser", suite, results: [], started_at: new Date().toISOString() };
const output = resolve(repo, `dist/docker-app-ui-validation/${suite}.json`);
let browser, profile, page;
try {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const executable = await findBrowser();
  profile = await mkdtemp(join(tmpdir(), "nre-ui-browser-"));
  browser = spawn(executable, ["--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--remote-debugging-port=0", `--user-data-dir=${profile}`, "about:blank"], { stdio: "ignore", windowsHide: true });
  browser.on("error", (error) => { evidence.browser_error = error.message; });
  let port;
  await eventually(async () => { try { port = (await readFile(join(profile, "DevToolsActivePort"), "utf8")).split("\n")[0]; return !!port; } catch { return false; } }, "browser debugging port");
  const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  const socket = new WebSocket(targets.find((target) => target.type === "page").webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.addEventListener("open", resolve, { once: true }); socket.addEventListener("error", reject, { once: true }); });
  page = new Page(socket);
  await page.send("Runtime.enable"); await page.send("Page.enable");
  await page.send("Network.enable"); await page.send("Network.setCacheDisabled", { cacheDisabled: true });
  await page.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false });
  const test = async (name, run) => { await run(); evidence.results.push({ name, status: "passed" }); console.log(`PASS ${name}`); };
  const navigate = async (query = "") => {
    const previous = page.navigations;
    await page.send("Page.navigate", { url: origin + "/" + query });
    await eventually(() => page.navigations > previous, "new document committed");
    await eventually(() => page.evaluate(`document.querySelector('#app-loading')?.hidden === true`), "page loaded");
  };

  const capture = async (name, width = 1440) => {
    await page.send("Emulation.setDeviceMetricsOverride", {width, height:1000, deviceScaleFactor:1, mobile:false});
    await page.evaluate("window.scrollTo(0, 0)");
    const bounds = await page.evaluate(`(() => {
      const detail = document.querySelector('#app-detail');
      if (!detail?.getClientRects().length) return null;
      const head = detail.querySelector('.detail-head').getBoundingClientRect();
      const nav = detail.querySelector('.detail-nav').getBoundingClientRect();
      const context = detail.querySelector('#detail-context').getBoundingClientRect();
      return {headBottom:head.bottom, navTop:nav.top, contextTop:context.top, headTop:head.top};
    })()`);
    if (bounds) assert.ok(bounds.navTop >= bounds.headBottom - 1 && bounds.contextTop >= bounds.headTop, `detail context and navigation must not be clipped: ${JSON.stringify(bounds)}`);
    const shot = await page.send("Page.captureScreenshot", {format:"png", captureBeyondViewport:false});
    const ref = `dist/docker-app-ui-validation/${suite}/${name}-${width}.png`;
    await mkdir(dirname(resolve(repo, ref)), {recursive:true});
    await writeFile(resolve(repo, ref), Buffer.from(shot.data, "base64"));
    const theme = await page.evaluate("document.documentElement.dataset.theme");
    const screenshot = {ref, width, theme, scenario:`fixture-${name}`};
    (evidence.screenshots ||= []).push(screenshot);
    return screenshot;
  };
  if (suite === "workspace") {
    const closeDraft = async () => {
      await page.click("#create-cancel");
      await eventually(async () => (await page.visible("#confirm-dialog")) || !(await page.visible("#create-form")), "close deployment or confirm discard");
      if (await page.visible("#confirm-dialog")) await page.click("#confirm-ok");
      await eventually(async () => !(await page.visible("#create-form")), "deployment closed");
    };
  await test("detail request immediately shows progress and reports failures", async () => {
    await navigate("?agent_id=node-a"); await page.waitVisible('[data-id="alpha"]');
    const pending = hold("/api/apps/alpha");
    try {
      await page.click('[data-id="alpha"] [data-action="detail"]');
      await eventually(() => pending.seen, "detail request pending");
      assert.equal(await page.evaluate(`document.querySelector('[data-id="alpha"] [data-action="detail"]').textContent`), "加载中…");
      assert.match(await page.evaluate(`document.querySelector('#app-status').textContent`), /正在读取.*alpha/);
    } finally { pending.release(); }
    await page.waitVisible("#app-detail");
    assert.equal(await page.evaluate(`document.querySelector('#app-status').hidden`), true);
    await page.click("#detail-back");
    assert.equal(await page.evaluate(`document.querySelector('[data-id="alpha"] [data-action="detail"]').disabled`), false);
    const original = apps;
    const missing = hold("/api/apps/alpha");
    try {
      await page.click('[data-id="alpha"] [data-action="detail"]');
      await eventually(() => missing.seen, "missing detail pending");
      apps = apps.filter(app => app.id !== "alpha");
      missing.release();
      await eventually(() => page.evaluate(`document.querySelector('#app-status').dataset.state === 'failed'`), "detail failure shown");
      assert.match(await page.evaluate(`document.querySelector('#app-status').textContent`), /应用已不存在/);
      assert.equal(await page.evaluate(`document.querySelector('[data-id="alpha"] [data-action="detail"]').disabled`), false);
    } finally { apps = original; missing.release(); }
  });

  await test("multi-service cards separate images from identity and keep actions compact", async () => {
    const original = apps;
    apps = [makeApp("sample", "node-a", {
      version:"example/gateway:v1.2.3", services:["gateway", "worker"], ports:[8765],
      service_images:[{name:"gateway",image:"example/gateway:v1.2.3"},{name:"worker",image:"example/worker:latest"}],
    })];
    try {
      await navigate("?agent_id=node-a"); await page.waitVisible('[data-id="sample"]');
      for (const width of [1440, 375]) {
        await page.send("Emulation.setDeviceMetricsOverride", {width,height:1000,deviceScaleFactor:1,mobile:false});
        const layout = await page.evaluate(`(() => {
          const card = document.querySelector('.app-card');
          const image = card.querySelector('[data-app-image]');
          const r = image.getBoundingClientRect(), h = card.querySelector('.app-card-head').getBoundingClientRect();
          return {images:[...image.querySelectorAll('.app-card-image')].map(n=>n.textContent), imageLeft:r.left, headRight:h.right, imageTop:r.top, headBottom:h.bottom, imageWidth:r.width, headWidth:h.width,
            actions:[...card.querySelectorAll('.app-card-actions button')].filter(n=>n.getClientRects().length).map(n=>n.textContent)};
        })()`);
        assert.deepEqual(layout.images, ["example/gateway:v1.2.3", "example/worker:latest"]);
        assert.ok(width > 850 ? layout.imageLeft >= layout.headRight : layout.imageTop >= layout.headBottom, "identity and service images occupy separate regions");
        assert.deepEqual(layout.actions, ["详情"]);
        await capture("multi-service-card", width);
      }
    } finally { apps = original; }
  });

  await test("node menu reserves readable names and stays inside the viewport", async () => {
    const original = agents.map(agent=>({...agent}));
    Object.assign(agents[0], {name:"debian-jnp12",last_seen_at:new Date().toISOString()});
    Object.assign(agents[1], {name:"zouter-hk",last_seen_at:new Date().toISOString()});
    try {
      for (const width of [1440, 721, 375]) {
        await page.send("Emulation.setDeviceMetricsOverride", {width,height:1000,deviceScaleFactor:1,mobile:false});
        await navigate("?agent_id=node-a"); await page.click('.agent-search-select__trigger');
        await eventually(()=>page.visible('[data-agent-id="node-a"] .agent-search-select__engine'), "node engine badges loaded");
        const layout = await page.evaluate(`(() => {
          const menu = document.querySelector('.agent-search-select__dropdown').getBoundingClientRect();
          const name = document.querySelector('[data-agent-id="node-a"] .agent-search-select__option-name');
          return {left:menu.left,right:menu.right,width:menu.width,client:document.documentElement.clientWidth,nameHeight:name.getBoundingClientRect().height,lineHeight:parseFloat(getComputedStyle(name).lineHeight),nameWidth:name.clientWidth,nameScroll:name.scrollWidth};
        })()`);
        assert.ok(layout.left >= 0 && layout.right <= layout.client, `menu stays within viewport: ${JSON.stringify(layout)}`);
        if (width >= 721) assert.ok(layout.width >= 400, "desktop dropdown is wider than the compact trigger");
        assert.ok(layout.nameHeight <= layout.lineHeight + 1 && layout.nameScroll <= layout.nameWidth, `ordinary node names fit on one line at ${width}: ${JSON.stringify(layout)}`);
        await capture("node-menu", width);
      }
    } finally { agents.splice(0, agents.length, ...original); }
  });
  await test("background image checks update the card without reloading the page", async () => {
    const original = apps;
    apps = [makeApp("sample", "node-a", {image_checking:true})];
    try {
      await navigate("?agent_id=node-a"); await page.waitVisible('[data-id="sample"]');
      apps = [makeApp("sample", "node-a", {notice:"有新版本",actions:[{id:"update",label:"更新"}]})];
      await eventually(() => page.visible('[data-id="sample"] [data-action="update"]'), "background result appears on the card");
      assert.equal(await page.visible("#app-detail"), false);
      assert.equal(requests.filter(request=>request.method!=="GET").length, 0);
    } finally { apps = original; }
  });

  await test("image check refresh does not show a second detail loading banner", async () => {
    const original = apps;
    apps = [makeApp("sample", "node-a", {image_checking:true})];
    try {
      await navigate("?agent_id=node-a"); await page.waitVisible('[data-id="sample"]');
      await page.click('[data-id="sample"] [data-action="detail"]'); await page.waitVisible("#app-detail");
      assert.equal(await page.evaluate(`document.querySelector('#app-status').hidden`), true);
      apps = [makeApp("sample", "node-a", {notice:"有新版本",actions:[{id:"update",label:"更新"}]})];
      await eventually(() => page.visible('#detail-overview [data-action="update"]'), "quiet detail refresh");
      assert.doesNotMatch(await page.evaluate(`document.querySelector('#app-status').textContent || ""`), /正在读取/);
      assert.equal(await page.evaluate(`document.querySelector('[data-id="sample"] [data-action="detail"]').textContent`), "详情");
      assert.ok(requests.filter((request) => request.path === "/api/apps/sample").length >= 2, "background check still refetches detail");
    } finally { apps = original; }
  });

  await test("no selection and explicit node states", async () => {
    await navigate(); await page.waitVisible("#app-node-empty");
    await page.selectAgent("node-a"); await page.waitVisible('[data-id="alpha"]');
    assert.equal(await page.evaluate(`document.querySelector('#engine-status').dataset.ready`), "true");
    await page.selectAgent("failed"); await page.waitVisible("#app-detection-failed");
    assert.equal(await page.evaluate(`document.querySelector('#engine-status').dataset.ready`), "false", "ready-to-failed transition clears the success state");
    for (const [id, panel] of [["offline", "#app-offline"], ["unavailable", "#app-execution-unavailable"], ["failed", "#app-detection-failed"], ["denied", "#app-node-denied"], ["missing", "#engine-guide"]]) {
      await page.selectAgent(id); await page.waitVisible(panel);
      assert.equal(await page.visible("#engine-guide"), id === "missing", `install guide only for confirmed missing: ${id}`);
      assert.equal(await page.visible("#app-workspace"), false);
    }
    assert.equal(requests.filter((r) => r.path === "/api/apps" && ["offline", "unavailable", "failed", "denied", "missing"].includes(r.agent)).length, 0);
  });

  await test("zero, one, many apps and deployment/detail paths", async () => {
    await page.selectAgent("node-a"); await page.waitVisible('[data-id="alpha"]');
    assert.equal(await page.evaluate(`document.querySelectorAll('#app-list .app-card').length`), 3);
    assert.ok(await page.visible("#deploy-toggle"));
    assert.equal(await page.evaluate(`document.querySelector('#engine-status').hidden`), true);
    assert.equal(await page.evaluate(`document.querySelector('#engine-status').dataset.ready`), "true");
    assert.ok(await page.evaluate(`document.querySelector('.agent-search-select__engine')?.textContent === '引擎就绪'`), "ready engine stays on the picker");
    assert.equal(await page.evaluate(`document.querySelector('#app-list').textContent.includes('27.1.1')`), false);
    await page.click('[data-id="alpha"] [data-action="detail"]'); await page.waitVisible("#app-detail");
    assert.match(await page.evaluate(`document.querySelector('#detail-context').textContent`), /节点 A.*alpha/);
    await page.click("#detail-back"); await page.waitVisible("#app-list");
    await page.selectAgent("node-b"); await page.waitVisible('[data-id="bravo"]');
    assert.equal(await page.evaluate(`document.querySelectorAll('#app-list .app-card').length`), 1);
    apps = apps.filter((app) => app.agent_id !== "node-b");
    await page.click("#workspace-refresh"); await page.waitVisible("#app-empty");
    await page.click("#deploy-toggle"); await page.waitVisible("#create-form");
    await closeDraft();
    apps.push(makeApp("bravo", "node-b"));
  });

  await test("old detail cannot replace a new app or node", async () => {
    await page.selectAgent("node-a"); await page.waitVisible('[data-id="alpha"]');
    const first = hold("/api/apps/alpha");
    await page.click('[data-id="alpha"] [data-action="detail"]');
    await eventually(() => first.seen, "held alpha detail");
    await page.click('[data-id="beta"] [data-action="detail"]'); await page.waitVisible("#app-detail");
    first.release(); await delay(150);
    assert.equal(await page.evaluate(`document.querySelector('#detail-title').textContent`), "beta");
    await page.click("#detail-back");
    const second = hold("/api/apps/alpha");
    await page.click('[data-id="alpha"] [data-action="detail"]'); await eventually(() => second.seen, "held node A detail");
    await page.selectAgent("node-b"); await page.waitVisible('[data-id="bravo"]');
    second.release(); await delay(150);
    assert.equal(await page.visible("#app-detail"), false);
    assert.equal(await page.visible('[data-id="alpha"]'), false);
  });

  await test("late engine and list responses preserve current node", async () => {
    const engine = hold("/api/engine?agent_id=node-a");
    await page.selectAgent("node-a"); await eventually(() => engine.seen, "held engine");
    await page.selectAgent("node-b"); await page.waitVisible('[data-id="bravo"]');
    engine.release(); await delay(150);
    assert.equal(await page.evaluate(`document.querySelector('#agent-select').value`), "node-b");
    assert.equal(await page.visible('[data-id="alpha"]'), false);
    const list = hold("/api/apps?agent_id=node-a");
    await page.selectAgent("node-a"); await eventually(() => list.seen, "held list");
    await page.selectAgent("node-b"); await page.waitVisible('[data-id="bravo"]');
    list.release(); await delay(150);
    assert.equal(await page.visible('[data-id="alpha"]'), false);
  });

  await test("late detail cannot replace a deployment page or clear its input", async () => {
    await page.selectAgent("node-a"); await page.waitVisible('[data-id="alpha"]');
    const pending = hold("/api/apps/alpha");
    await page.click('[data-id="alpha"] [data-action="detail"]');
    await eventually(() => pending.seen, "held detail before deployment navigation");
    await page.click("#deploy-toggle"); await page.waitVisible("#create-form");
    const draft = 'services:\n  draft:\n    image: nginx:1.27\n';
    await page.click('#create-form input[name="id"]');
    await page.send("Input.insertText", { text: "draft-race" });
    await page.click('#create-form textarea[name="compose"]');
    await page.send("Input.insertText", { text: draft });
    pending.release(); await delay(150);
    assert.ok(await page.visible("#create-form"), "deployment must remain visible after the old detail responds");
    assert.equal(await page.visible("#app-detail"), false);
    assert.equal(await page.evaluate(`document.querySelector('#create-form input[name="id"]').value`), "draft-race");
    assert.equal(await page.evaluate(`document.querySelector('#create-form textarea[name="compose"]').value`), draft);
    assert.equal(requests.filter((r) => r.method !== "GET").length, 0);
    await closeDraft();
  });

  await test("long labels and all actions stay separate across representative widths", async () => {
    await page.selectAgent("node-a"); await page.waitVisible('[data-id="alpha"]');
    for (const width of [375, 721, 768, 1024, 1440]) {
      await page.send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: false });
      assert.ok(await page.evaluate(`document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1`), `no page overflow at ${width}`);
      const grid = await page.evaluate(`(() => {
        const cards = Array.from(document.querySelectorAll('#app-list .app-card')).map((node) => Math.round(node.getBoundingClientRect().top));
        const rows = new Set(cards).size;
        const refresh = document.querySelector('#workspace-refresh').getBoundingClientRect();
        const picker = document.querySelector('.agent-search-select__trigger').getBoundingClientRect();
        return {count: cards.length, rows, refreshWidth: refresh.width, pickerWidth: picker.width};
      })()`);
      assert.ok(grid.refreshWidth < grid.pickerWidth, `refresh is not a stretched primary at ${width}: ${JSON.stringify(grid)}`);
      assert.equal(grid.rows, grid.count, `applications remain separate information rows at ${width}: ${JSON.stringify(grid)}`);
      const bounds = await page.evaluate(`(() => {
        const client = document.documentElement.clientWidth;
        return {client, scroll: document.documentElement.scrollWidth, controls: Array.from(document.querySelectorAll('.agent-search-select__trigger, #deploy-toggle, #workspace-refresh, #app-list .app-card')).map(n => {
          const r = n.getBoundingClientRect(); return {id:n.id || n.className, left:r.left, right:r.right, height:r.height};
        })};
      })()`);
      assert.ok(bounds.controls.every((r) => r.left >= 0 && r.right <= bounds.client), `all controls within ${width}px: ${JSON.stringify(bounds)}`);
      const contents = await page.evaluate(`(() => {
        const card = document.querySelector(${JSON.stringify(`[data-id="${longApp.id}"]`)});
        const rects = (selector) => Array.from(card.querySelectorAll(selector)).filter(n => n.getClientRects().length).map(n => {
          const r = n.getBoundingClientRect();
          return {text:n.textContent, left:r.left, right:r.right, top:r.top, bottom:r.bottom};
        });
        return {labels:rects('.app-card-title-row, .app-card-meta, .app-port, .app-card-url'), buttons:rects('.app-card-actions button')};
      })()`);
      assert.deepEqual(contents.buttons.map((button) => button.text), ["打开", "更新", "详情"]);
      const overlaps = (a, b) => a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top;
      for (const label of contents.labels) {
        for (const button of contents.buttons) assert.equal(overlaps(label, button), false, `label/action overlap at ${width}: ${JSON.stringify({ label, button })}`);
      }
      contents.buttons.forEach((button, index) => {
        for (const other of contents.buttons.slice(index + 1)) assert.equal(overlaps(button, other), false, `actions overlap at ${width}`);
      });
      bounds.contents = contents;
      (evidence.layout ||= []).push({ width, ...bounds });
      await page.evaluate("window.scrollTo(0, 0)");
      const screenshot = await page.send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
      const screenshotRef = `dist/docker-app-ui-validation/workspace/list-${width}.png`;
      await mkdir(dirname(resolve(repo, screenshotRef)), { recursive: true });
      await writeFile(resolve(repo, screenshotRef), Buffer.from(screenshot.data, "base64"));
      (evidence.screenshots ||= []).push({ ref: screenshotRef, width, theme: "light", scenario: "fixture-list" });
      await page.click(`[data-id="${longApp.id}"] [data-action="detail"]`); await page.waitVisible("#app-detail");
      assert.equal(await page.evaluate(`document.querySelector('#detail-title').textContent`), longApp.id);
      assert.ok(await page.evaluate(`document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1`), `detail does not overflow at ${width}`);
      await page.click("#detail-back");
    }
  });

  await test("pending workspace refresh never restores detail over a newer navigation", async () => {
    for (const destination of ["create", "cancel-create", "list", "beta", "node-b", "compose"]) {
      await navigate("?agent_id=node-a"); await page.waitVisible('[data-id="alpha"]');
      await page.click('[data-id="alpha"] [data-action="detail"]'); await page.waitVisible("#app-detail");
      const pending = hold("/api/apps?agent_id=node-a");
      await page.click("#workspace-refresh"); await eventually(() => pending.seen, `held detail refresh for ${destination}`);
      if (destination === "compose") {
        await page.click('#detail-nav [data-section="compose"]');
      } else {
        await page.click("#detail-back");
        if (destination === "create" || destination === "cancel-create") {
          await page.click("#deploy-toggle"); await page.waitVisible("#create-form");
          await page.click('#create-form input[name="id"]');
          await page.send("Input.insertText", { text: "refresh-draft" });
          await page.click('#create-form textarea[name="compose"]');
          await page.send("Input.insertText", { text: "services:\n  draft:\n    image: nginx:1.27\n" });
          if (destination === "cancel-create") await closeDraft();
        } else if (destination === "beta") {
          // A newer list refresh supplies the next application while the first stays held.
          gates.delete("/api/apps?agent_id=node-a");
          await page.click("#workspace-refresh"); await page.waitVisible('[data-id="beta"]');
          await page.click('[data-id="beta"] [data-action="detail"]'); await page.waitVisible("#app-detail");
        } else if (destination === "node-b") {
          await page.selectAgent("node-b"); await page.waitVisible('[data-id="bravo"]');
        }
      }
      const detailReads = requests.filter((r) => r.path === "/api/apps/alpha").length;
      pending.release(); await delay(150);
      assert.equal(requests.filter((r) => r.path === "/api/apps/alpha").length, detailReads, `stale refresh must not issue a new alpha detail read after ${destination}`);
      if (destination === "create") {
        assert.ok(await page.visible("#create-form"));
        assert.equal(await page.visible("#app-detail"), false);
        assert.equal(await page.evaluate(`document.querySelector('#create-form input[name="id"]').value`), "refresh-draft");
        assert.equal(await page.evaluate(`document.querySelector('#create-form textarea[name="compose"]').value`), "services:\n  draft:\n    image: nginx:1.27\n");
      } else if (destination === "beta") {
        assert.equal(await page.evaluate(`document.querySelector('#detail-title').textContent`), "beta");
      } else if (destination === "compose") {
        assert.ok(await page.visible("#compose-form"));
        assert.equal(await page.evaluate(`document.querySelector('#detail-title').textContent`), "alpha");
      } else {
        assert.equal(await page.visible("#app-detail"), false, `detail stays closed after ${destination}`);
        assert.equal(await page.visible("#create-form"), false);
        if (destination === "node-b") assert.equal(await page.evaluate(`document.querySelector('#agent-select').value`), "node-b");
      }
    }
    assert.equal(requests.filter((r) => r.method !== "GET").length, 0, "refresh and navigation never mutate");
    await navigate("?agent_id=node-a"); await page.waitVisible('[data-id="alpha"]');
  });

  await test("confirmation Escape and cancel never mutate", async () => {
    await page.click('[data-id="alpha"] [data-action="detail"]'); await page.waitVisible("#app-detail");
    for (const dismiss of ["cancel", "escape", "cancel"]) {
      await page.click('#detail-overview [data-action="delete"]'); await page.waitVisible("#confirm-dialog");
      assert.equal(await page.evaluate(`document.activeElement.id`), "confirm-cancel");
      assert.equal(await page.evaluate(`document.querySelector('#app-status').dataset.state`), "confirming");
      if (dismiss === "escape") await page.key("Escape"); else await page.click("#confirm-cancel");
      await eventually(async () => !(await page.visible("#confirm-dialog")), "dialog closed");
      await eventually(() => page.evaluate(`document.querySelector('#app-status').dataset.state === 'cancelled' && !document.querySelector('.agent-search-select__trigger').disabled`), "cancellation finished");
      assert.equal(await page.evaluate(`document.activeElement.dataset.action`), "delete");
    }
    assert.equal(requests.filter((r) => r.method !== "GET").length, 0, "workspace navigation and cancelled dialogs issue zero mutations");
  });

  await test("busy locks node identity and reopening after success resets confirmation", async () => {
    const deletion = hold("/api/apps/alpha/delete");
    await page.click('#detail-overview [data-action="delete"]'); await page.waitVisible("#confirm-dialog");
    await page.click("#confirm-ok"); await eventually(() => deletion.seen, "confirmed deletion");
    assert.equal(await page.evaluate(`document.querySelector('.agent-search-select__trigger').disabled`), true);
    assert.equal(await page.evaluate(`document.querySelector('#app-status').dataset.state`), "running");
    deletion.release(); await page.waitVisible('[data-id="beta"]');
    await eventually(() => page.evaluate(`document.querySelector('#app-status').dataset.state === 'succeeded'`), "success feedback");
    assert.equal(await page.evaluate(`document.querySelector('.agent-search-select__trigger').disabled`), false);
    await page.click('[data-id="beta"] [data-action="detail"]'); await page.waitVisible("#app-detail");
    await page.click('#detail-overview [data-action="delete"]'); await page.waitVisible("#confirm-dialog");
    await page.key("Escape"); await eventually(async () => !(await page.visible("#confirm-dialog")), "reopened dialog cancelled");
    await eventually(() => page.evaluate(`!document.querySelector('.agent-search-select__trigger').disabled`), "cancelled operation controls restored");
    assert.equal(requests.filter((r) => r.method === "POST").length, 1);
    await page.click('#detail-overview [data-action="delete"]'); await page.waitVisible("#confirm-dialog"); await page.click("#confirm-ok");
    await eventually(() => page.evaluate(`document.querySelector('#app-status').dataset.state === 'failed'`), "failure feedback");
    assert.match(await page.evaluate(`document.querySelector('#app-status').textContent`), /删除失败/);
    assert.equal(requests.filter((r) => r.method === "POST").length, 2);
  });
  } else if (suite === "compose") {
    await runCompose({page, test, navigate, hold, requests, state:composeState, capture, eventually});
  } else if (suite === "operations") {
    await runOperations({page, test, navigate, hold, requests, state:operationsState, capture, eventually});
  } else if (suite === "resources") {
    await runResources({page, test, navigate, hold, requests, state:resourcesState, capture, eventually, outputDir:resolve(repo,"dist/docker-app-ui-validation/resources")});
  } else {
    await runExperience({page,test,navigate,capture,eventually,origin});
  }
  assert.deepEqual(page.errors, [], "no uncaught page exceptions");
  evidence.status = "passed";
  evidence.browser = executable;
  const hash = createHash("sha256");
  for (const name of UI_ASSETS) hash.update(await readFile(join(assets, name)));
  evidence.assets_sha256 = hash.digest("hex");
} catch (error) {
  if (page) {
    evidence.failure_context = await page.evaluate(`({title:document.querySelector('#detail-title')?.textContent,section:document.querySelector('#detail-nav [aria-current="page"]')?.dataset.section,status:document.querySelector('#app-status')?.textContent,fileSelection:document.querySelector('#files-selected')?.textContent,fileEditorHidden:document.querySelector('#files-editor')?.hidden,focus:document.activeElement?.id})`).catch(() => null);
    evidence.last_requests = requests.slice(-12);
  }
  evidence.status = "failed"; evidence.error = error.stack; process.exitCode = 1; console.error(error);
} finally {
  evidence.finished_at = new Date().toISOString();
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, JSON.stringify(evidence, null, 2) + "\n");
  for (const gate of gates.values()) gate.release();
  if (page) {
    try { await page.send("Browser.close"); } catch { /* Browser may already be closed. */ }
    page.socket.close();
  }
  if (browser && browser.exitCode === null) browser.kill();
  server.closeAllConnections(); server.close();
  // Delete only the exact temporary profile created by this invocation.
  if (profile?.startsWith(join(tmpdir(), "nre-ui-browser-"))) {
    await rm(profile, { recursive: true, force: true, maxRetries: 8, retryDelay: 200 }).catch(() => {});
  }
}
