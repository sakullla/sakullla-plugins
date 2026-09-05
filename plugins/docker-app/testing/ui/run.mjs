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

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "../../../..");
const assets = resolve(here, "../../assets/ui");
const suite = process.argv[process.argv.indexOf("--suite") + 1];
if (suite !== "workspace") throw new Error(`Suite ${suite || "<missing>"} is not implemented; no tests were run.`);

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
    this.socket = socket; this.id = 0; this.pending = new Map(); this.errors = [];
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
    });
  }
  send(method, params = {}) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 15000);
      this.pending.set(id, { resolve, reject, timer });
      this.socket.send(JSON.stringify({ id, method, params }));
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
      return {x:r.x+r.width/2, y:r.y+r.height/2};
    })()`);
    await this.send("Input.dispatchMouseEvent", { type: "mousePressed", button: "left", clickCount: 1, ...point });
    await this.send("Input.dispatchMouseEvent", { type: "mouseReleased", button: "left", clickCount: 1, ...point });
  }
  async key(key) {
    await this.send("Input.dispatchKeyEvent", { type: "keyDown", key, code: key, windowsVirtualKeyCode: key === "Escape" ? 27 : 13 });
    await this.send("Input.dispatchKeyEvent", { type: "keyUp", key, code: key });
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

const requests = [];
const gates = new Map();
let apps = [makeApp("alpha"), makeApp("beta"), longApp, makeApp("bravo", "node-b")];
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
    if (url.pathname === "/api/apps") return json({ apps: apps.filter((app) => app.agent_id === record.agent) });
    if (url.pathname === "/api/disk-cleanup") return json({ cleanup: { steps: [] } });
    if (request.method === "POST" && url.pathname === "/api/apps/alpha/delete") {
      apps = apps.filter((app) => app.id !== "alpha");
      return json({ accepted: true });
    }
    if (request.method === "POST" && url.pathname === "/api/apps/beta/delete") return json({ error: "应用删除失败，请重试。" }, 500);
    if (/^\/api\/apps\/[^/]+$/.test(url.pathname)) {
      const app = apps.find((app) => app.id === decodeURIComponent(url.pathname.split("/").pop()));
      return json({ app }, app ? 200 : 404);
    }
    if (request.method !== "GET") return json({ error: "Unexpected mutation in workspace suite" }, 500);
    const name = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
    if (!["index.html", "app.js", "style.css"].includes(name)) { response.writeHead(404); response.end(); return; }
    response.writeHead(200, { "Content-Type": name.endsWith("js") ? "text/javascript" : name.endsWith("css") ? "text/css" : "text/html" });
    response.end(await readFile(join(assets, name)));
  } catch (error) { response.writeHead(500); response.end(String(error)); }
});

function hold(path) {
  const gate = { seen: false };
  gate.promise = new Promise((resolve) => { gate.release = () => { gates.delete(path); resolve(); }; });
  gates.set(path, gate);
  return gate;
}

const evidence = { kind: "fixture-browser", suite, results: [], started_at: new Date().toISOString() };
const output = resolve(repo, "dist/docker-app-ui-validation/workspace.json");
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
  await page.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false });
  const test = async (name, run) => { await run(); evidence.results.push({ name, status: "passed" }); console.log(`PASS ${name}`); };
  const navigate = async (query = "") => { await page.send("Page.navigate", { url: origin + "/" + query }); await eventually(() => page.evaluate(`document.querySelector('#app-loading')?.hidden === true`), "page loaded"); };

  await test("no selection and explicit node states", async () => {
    await navigate(); await page.waitVisible("#app-node-empty");
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
    assert.match(await page.evaluate(`document.querySelector('#engine-status').textContent`), /Docker.*27.1.1/);
    assert.equal(await page.evaluate(`document.querySelector('#app-list').textContent.includes('27.1.1')`), false);
    await page.click('[data-id="alpha"] [data-action="detail"]'); await page.waitVisible("#app-detail");
    assert.match(await page.evaluate(`document.querySelector('#detail-context').textContent`), /节点 A.*alpha/);
    await page.click("#detail-back"); await page.waitVisible("#app-list");
    await page.selectAgent("node-b"); await page.waitVisible('[data-id="bravo"]');
    assert.equal(await page.evaluate(`document.querySelectorAll('#app-list .app-card').length`), 1);
    apps = apps.filter((app) => app.agent_id !== "node-b");
    await page.click("#workspace-refresh"); await page.waitVisible("#app-empty");
    await page.click("#deploy-toggle"); await page.waitVisible("#create-form");
    await page.click("#create-cancel");
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
    await page.click("#create-cancel");
  });

  await test("long labels and all actions stay separate across representative widths", async () => {
    await page.selectAgent("node-a"); await page.waitVisible('[data-id="alpha"]');
    for (const width of [375, 721, 768, 1024, 1440]) {
      await page.send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: false });
      assert.ok(await page.evaluate(`document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1`), `no page overflow at ${width}`);
      const bounds = await page.evaluate(`(() => {
        const client = document.documentElement.clientWidth;
        return {client, scroll: document.documentElement.scrollWidth, controls: Array.from(document.querySelectorAll('.agent-search-select__trigger, #deploy-toggle, #app-list .app-card')).map(n => {
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

  await test("confirmation Escape and cancel never mutate", async () => {
    await page.click('[data-id="alpha"] [data-action="detail"]'); await page.waitVisible("#app-detail");
    for (const dismiss of ["cancel", "escape", "cancel"]) {
      await page.click('#detail-overview [data-action="delete"]'); await page.waitVisible("#confirm-dialog");
      assert.equal(await page.evaluate(`document.activeElement.id`), "confirm-cancel");
      assert.equal(await page.evaluate(`document.querySelector('#app-status').dataset.state`), "confirming");
      if (dismiss === "escape") await page.key("Escape"); else await page.click("#confirm-cancel");
      await eventually(async () => !(await page.visible("#confirm-dialog")), "dialog closed");
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
    assert.equal(requests.filter((r) => r.method === "POST").length, 1);
    await page.click('#detail-overview [data-action="delete"]'); await page.waitVisible("#confirm-dialog"); await page.click("#confirm-ok");
    await eventually(() => page.evaluate(`document.querySelector('#app-status').dataset.state === 'failed'`), "failure feedback");
    assert.match(await page.evaluate(`document.querySelector('#app-status').textContent`), /删除失败/);
    assert.equal(requests.filter((r) => r.method === "POST").length, 2);
  });
  assert.deepEqual(page.errors, [], "no uncaught page exceptions");
  evidence.status = "passed";
  evidence.browser = executable;
  const hash = createHash("sha256");
  for (const name of ["index.html", "app.js", "style.css"]) hash.update(await readFile(join(assets, name)));
  evidence.assets_sha256 = hash.digest("hex");
} catch (error) {
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
