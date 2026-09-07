import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import {
  access,
  readFile,
  mkdtemp,
  mkdir,
  writeFile,
  rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
async function eventually(check, description, timeout = 10000) {
  const until = Date.now() + timeout;
  do {
    if (await check()) return;
    await delay(40);
  } while (Date.now() < until);
  throw new Error(`Timed out: ${description}`);
}

async function findBrowser() {
  const candidates = [
    process.env.NRE_UI_BROWSER,
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  ].filter(Boolean);
  for (const candidate of candidates) {
    try {
      await access(candidate);
      return candidate;
    } catch {
      /* Try next actual executable. */
    }
  }
  throw new Error(
    "No browser found. Set NRE_UI_BROWSER to a Chromium/Chrome/Edge executable. Nothing was verified.",
  );
}

class Page {
  constructor(socket) {
    this.socket = socket;
    this.id = 0;
    this.pending = new Map();
    this.errors = [];
    this.navigations = 0;
    this.javascriptDialogs = [];
    socket.addEventListener("message", ({ data }) => {
      const message = JSON.parse(data);
      const pending = this.pending.get(message.id);
      if (pending) {
        this.pending.delete(message.id);
        clearTimeout(pending.timer);
        if (message.error)
          pending.reject(new Error(JSON.stringify(message.error)));
        else pending.resolve(message.result);
      }
      if (message.method === "Runtime.exceptionThrown")
        this.errors.push(message.params.exceptionDetails.text);
      if (
        message.method === "Page.frameNavigated" &&
        !message.params.frame.parentId
      )
        this.navigations += 1;
      if (message.method === "Page.javascriptDialogOpening") {
        this.javascriptDialogs.push(message.params.type);
        if (message.params.type === "beforeunload")
          this.send("Page.handleJavaScriptDialog", { accept: true });
      }
    });
  }
  send(method, params = {}, sessionId) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`CDP timeout: ${method}`));
      }, 15000);
      this.pending.set(id, { resolve, reject, timer });
      this.socket.send(
        JSON.stringify({
          id,
          method,
          params,
          ...(sessionId ? { sessionId } : {}),
        }),
      );
    });
  }
  async evaluate(expression) {
    const result = await this.send("Runtime.evaluate", {
      expression,
      awaitPromise: true,
      returnByValue: true,
    });
    if (result.exceptionDetails)
      throw new Error(JSON.stringify(result.exceptionDetails));
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
    await this.send("Input.dispatchMouseEvent", {
      type: "mousePressed",
      button: "left",
      clickCount: 1,
      ...point,
    });
    await this.send("Input.dispatchMouseEvent", {
      type: "mouseReleased",
      button: "left",
      clickCount: 1,
      ...point,
    });
  }
  async key(key, { shift = false, ctrl = false, meta = false } = {}) {
    const code =
      key === " " ? "Space" : key === "s" || key === "S" ? "KeyS" : key;
    const keyCode =
      {
        Escape: 27,
        Enter: 13,
        Tab: 9,
        ArrowDown: 40,
        ArrowUp: 38,
        " ": 32,
        s: 83,
        S: 83,
      }[key] || 0;
    const modifiers = (ctrl ? 2 : 0) | (meta ? 4 : 0) | (shift ? 8 : 0);
    await this.send("Input.dispatchKeyEvent", {
      type: "keyDown",
      key,
      code,
      windowsVirtualKeyCode: keyCode,
      modifiers,
    });
    await this.send("Input.dispatchKeyEvent", {
      type: "keyUp",
      key,
      code,
      windowsVirtualKeyCode: keyCode,
      modifiers,
    });
  }
  visible(selector) {
    return this.evaluate(
      `!!document.querySelector(${JSON.stringify(selector)})?.getClientRects().length`,
    );
  }
  waitVisible(selector) {
    return eventually(() => this.visible(selector), `visible ${selector}`);
  }
  async selectAgent(id) {
    await this.click(".agent-search-select__trigger");
    const name = agents.find((agent) => agent.id === id)?.name;
    // Locate the rendered option by its user-visible name; no application internals.
    const index = await this.evaluate(
      `Array.from(document.querySelectorAll('.agent-search-select__option')).findIndex(n => n.querySelector('.agent-search-select__option-name')?.textContent === ${JSON.stringify(name)})`,
    );
    assert.ok(index >= 0, `node option ${id}`);
    await this.click(`.agent-search-select__option:nth-child(${index + 1})`);
  }
}

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");
const assets = join(repo, "plugins/waf/assets/ui"),
  output = join(repo, "dist/waf-ui-validation");
const agents = [
  {
    id: "local",
    name: "本机节点",
    online: true,
    is_local: true,
    last_seen_at: Date.now(),
  },
  { id: "remote", name: "香港边缘节点", online: false },
  { id: "uninstalled", name: "未安装节点", online: true },
  ...Array.from({ length: 15 }, (_, i) => ({
    id: "node-" + i,
    name: "已安装节点-" + i,
    online: true,
  })),
];
const managed = (
  await readFile(join(repo, "plugins/waf/rules/managed.rules"), "utf8")
)
  .split(/\r?\n/)
  .filter((line) => line && !line.startsWith("#"))
  .map((line) => {
    const [id, target, needle] = line.split("|");
    return { id, target: target.toLowerCase(), needle };
  });
let entries = Array.from({ length: 23 }, (_, i) => ({
  rule_ref: String(i + 1),
  frontend_url: "https://media" + i + ".example.com",
  backend: "http://192.0.2.10:" + String(8000 + i),
  enabled: true,
  attached: i !== 0,
  mode: i % 3 === 0 ? "deny" : "observe",
}));
let events = Array.from({ length: 31 }, (_, i) => ({
  id: "event-" + i,
  created_at: new Date(Date.now() - i * 60000).toISOString(),
  site: "media.example.com",
  path: "/api/content/" + i,
  rule_id: "managed-sqli-union",
  reason: i % 5 === 1 ? "body_window_skipped" : "rule_matched",
  disposition: i % 2 === 0 ? "deny" : "observe",
  digest: "a19b8b6b57c2f90a",
}));
let custom = [],
  exclusions = [],
  eventError = false;
const calls = [];
const mode = (e) =>
  e.disposition === "deny"
    ? "deny"
    : e.reason !== "rule_matched"
      ? "skip"
      : "observe";
const paginate = (items, page = 1) => {
  const total = items.length;
  page = Math.min(Number(page), Math.max(1, Math.ceil(total / 10)));
  return {
    items: items.slice((page - 1) * 10, page * 10),
    page,
    page_size: 10,
    total,
  };
};
const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://fixture.invalid");
    calls.push({
      path: url.pathname,
      query: Object.fromEntries(url.searchParams),
      method: req.method,
    });
    const json = (body, status = 200) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (url.pathname === "/panel-api/agents") return json({ agents });
    if (url.pathname === "/panel-api/plugins/waf")
      return json({
        instances: [
          {
            targets: agents
              .filter((a) => a.id !== "uninstalled")
              .map((a) => a.id),
          },
        ],
      });
    if (url.pathname === "/api/state") {
      const filtered = entries.filter(
        (e) =>
          (!url.searchParams.get("entry_mode") ||
            (e.attached ? e.mode : "skip") ===
              url.searchParams.get("entry_mode")) &&
          JSON.stringify(e)
            .toLowerCase()
            .includes(
              (url.searchParams.get("entry_query") || "").toLowerCase(),
            ),
      );
      const page = paginate(filtered, url.searchParams.get("entry_page") || 1);
      const filteredEvents = events.filter(
        (e) =>
          (!url.searchParams.get("event_mode") ||
            mode(e) === url.searchParams.get("event_mode")) &&
          JSON.stringify(e)
            .toLowerCase()
            .includes(
              (url.searchParams.get("event_query") || "").toLowerCase(),
            ),
      );
      const eventPage = paginate(
        filteredEvents,
        url.searchParams.get("event_page") || 1,
      );
      return json({
        ready: true,
        events_available: !eventError,
        error: eventError ? "宿主事件记录暂时不可用。" : "",
        events: eventError ? [] : eventPage.items,
        events_page: eventPage,
        recent_events: eventError ? [] : events.slice(0, 5),
        event_summary: eventError ? null : { deny: 16, observe: 12, skip: 3 },
        entries: page.items,
        entries_page: page,
        managed_rules: managed,
        custom_rules: custom,
        exclusions,
        coverage: {
          total: 23,
          deny: 7,
          observe: 15,
          unprotected: 1,
          disabled: 0,
        },
      });
    }
    if (req.method === "POST" || req.method === "DELETE") {
      let raw = "";
      for await (const chunk of req) raw += chunk;
      const body = JSON.parse(raw || "{}");
      if (url.pathname === "/api/custom-rules") {
        if (req.method === "DELETE")
          custom = custom.filter((r) => r.id !== body.id);
        else custom.push(body);
        return json({ ready: true });
      }
      if (url.pathname === "/api/exclusions") {
        if (req.method === "DELETE")
          exclusions = exclusions.filter(
            (r) =>
              r.rule_id !== body.rule_id || r.path_prefix !== body.path_prefix,
          );
        else exclusions.push(body);
        return json({ ready: true });
      }
      if (url.pathname === "/api/entries/mode") {
        entries = entries.map((e) =>
          e.rule_ref === body.rule_ref ? { ...e, mode: body.mode } : e,
        );
        return json({ ready: true });
      }
      if (url.pathname === "/api/entries/mode-all") {
        entries = entries.map((e) => ({ ...e, mode: body.mode }));
        return json({ ready: true });
      }
    }
    const name = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
    if (!["index.html", "app.js", "style.css"].includes(name)) {
      res.statusCode = 404;
      return res.end();
    }
    res.setHeader(
      "Content-Type",
      {
        "index.html": "text/html; charset=utf-8",
        "app.js": "text/javascript; charset=utf-8",
        "style.css": "text/css",
      }[name],
    );
    res.end(await readFile(join(assets, name)));
  } catch (error) {
    res.statusCode = 500;
    res.end(error.message);
  }
});
let browser, page, profile;
try {
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const origin = "http://127.0.0.1:" + server.address().port;
  profile = await mkdtemp(join(tmpdir(), "waf-ui-browser-"));
  browser = spawn(
    await findBrowser(),
    [
      "--headless=new",
      "--no-first-run",
      "--no-default-browser-check",
      "--remote-debugging-port=0",
      "--user-data-dir=" + profile,
      "about:blank",
    ],
    { stdio: "ignore", windowsHide: true },
  );
  let port;
  await eventually(async () => {
    try {
      port = (
        await readFile(join(profile, "DevToolsActivePort"), "utf8")
      ).split(String.fromCharCode(10))[0];
      return !!port;
    } catch {
      return false;
    }
  }, "browser");
  const targets = await (
    await fetch("http://127.0.0.1:" + port + "/json/list")
  ).json();
  const socket = new WebSocket(
    targets.find((target) => target.type === "page").webSocketDebuggerUrl,
  );
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });
  page = new Page(socket);
  await page.send("Runtime.enable");
  await page.send("Page.enable");
  await page.send("Emulation.setDeviceMetricsOverride", {
    width: 1440,
    height: 1100,
    deviceScaleFactor: 1,
    mobile: false,
  });
  const fill = (selector, value) =>
    page.evaluate(
      "(()=>{const node=document.querySelector(" +
        JSON.stringify(selector) +
        ");node.value=" +
        JSON.stringify(value) +
        ';node.dispatchEvent(new Event("input",{bubbles:true}));})()',
    );
  const loaded = () =>
    eventually(
      () => page.evaluate("!document.querySelector('#refresh-state').disabled"),
      "workspace refresh",
    );
  const capture = async (name) => {
    await page.evaluate(
      "new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))",
    );
    await page.evaluate(
      "Promise.all(document.getAnimations().map(animation=>animation.finished.catch(()=>{})))",
    );
    await mkdir(output, { recursive: true });
    await writeFile(
      join(output, name + ".png"),
      Buffer.from(
        (
          await page.send("Page.captureScreenshot", {
            captureBeyondViewport: true,
          })
        ).data,
        "base64",
      ),
    );
  };
  await page.send("Page.navigate", { url: origin + "/?agent_id=uninstalled" });
  await page.waitVisible("#app-node-empty");
  assert.equal(
    calls.some((call) => call.path === "/api/state"),
    false,
  );
  await page.click(".agent-search-select__trigger");
  assert.ok(
    await page.evaluate(
      "(()=>{const n=document.querySelector('.agent-search-select__list');return n.scrollHeight>n.clientHeight})()",
    ),
  );
  assert.equal(
    await page.evaluate(
      "document.querySelector('.agent-search-select__list').textContent.includes('未安装节点')",
    ),
    false,
  );
  await fill("input[type=search]", "本机");
  await page.key("ArrowDown");
  await page.key("Enter");
  await page.waitVisible("#view-overview");
  assert.equal(
    await page.evaluate("document.querySelector('#stat-deny').textContent"),
    "16",
  );
  assert.equal(await page.visible("#view-scope"), false);
  await capture("overview");
  console.log("PASS installed-node picker and overview");
  await page.click('[data-event-mode="observe"]');
  await loaded();
  assert.equal(
    await page.evaluate("document.querySelector('#event-mode').value"),
    "observe",
  );
  await page.evaluate(
    "document.querySelector('#event-mode').value='';document.querySelector('#event-mode').dispatchEvent(new Event('change'))",
  );
  await loaded();
  assert.equal(
    await page.evaluate("document.querySelectorAll('#event-list tr').length"),
    10,
  );
  await page.click("#event-pagination .actions button:last-child");
  await loaded();
  assert.equal(
    await page.evaluate(
      "document.querySelector('#event-pagination .actions span').textContent",
    ),
    "2 / 4",
  );
  await page.click("#event-pagination .actions button:first-child");
  await loaded();
  await capture("events");
  await page.click("#event-list tr:first-child button");
  await page.waitVisible("#event-dialog");
  assert.ok(
    await page.evaluate(
      "document.querySelector('#event-detail').textContent.includes('WAF 已拒绝')",
    ),
  );
  await capture("event-detail");
  await page.click("#event-create-exclusion");
  await page.waitVisible("#rule-dialog");
  assert.equal(
    await page.evaluate(
      "document.querySelector('#exclusion-form [name=path_prefix]').value",
    ),
    "",
  );
  await fill("#exclusion-form [name=path_prefix]", "/api/content");
  await page.click("#exclusion-form [type=submit]");
  await eventually(
    () =>
      page.evaluate(
        "document.querySelector('#exclusion-count').textContent==='1' && !document.querySelector('#rule-dialog').open",
      ),
    "exclusion rendered",
  );
  assert.equal(
    await page.evaluate(
      "document.querySelector('#exclusion-count').textContent",
    ),
    "1",
  );
  await page.click("#exclusion-list button");
  await eventually(
    () =>
      page.evaluate(
        "document.querySelector('#exclusion-count').textContent==='0'",
      ),
    "exclusion removed",
  );
  assert.equal(exclusions.length, 0);
  console.log("PASS event pagination, details and exclusion lifecycle");
  await page.click("#custom-tab");
  await page.click("#add-rule");
  await fill("#custom-form [name=id]", "protect-private");
  await fill("#custom-form [name=needle]", "/private");
  await page.click("#custom-form [type=submit]");
  await eventually(
    () =>
      page.evaluate(
        "document.querySelector('#custom-count').textContent==='1' && !document.querySelector('#rule-dialog').open",
      ),
    "custom rule rendered",
  );
  await page.click("#custom-list button");
  await eventually(
    () =>
      page.evaluate(
        "document.querySelector('#custom-count').textContent==='0'",
      ),
    "custom removed",
  );
  assert.equal(custom.length, 0);
  await page.click("#managed-tab");
  await page.click(".managed-group summary");
  await capture("rules");
  assert.equal(
    await page.evaluate("document.querySelector('#managed-count').textContent"),
    String(managed.length),
  );
  console.log("PASS managed detection visibility and custom rule lifecycle");
  await page.click("#tab-scope");
  assert.equal(
    await page.evaluate("document.querySelectorAll('#entry-list li').length"),
    10,
  );
  await page.click("#entry-pagination .actions button:last-child");
  await loaded();
  assert.ok(
    calls.some(
      (call) => call.path === "/api/state" && call.query.entry_page === "2",
    ),
  );
  await capture("scope");
  await page.click("#entry-list li:first-child [data-mode=deny][type=button]");
  await eventually(
    () =>
      page.evaluate(
        "document.querySelector('#entry-list li:first-child [data-mode=deny][type=button]').getAttribute('aria-pressed')==='true'",
      ),
    "entry mode rendered",
  );
  assert.ok(calls.some((call) => call.path === "/api/entries/mode"));
  await page.click("#global-deny");
  await eventually(
    () => page.evaluate("!document.querySelector('#global-deny').disabled"),
    "bulk completed",
  );
  assert.ok(calls.some((call) => call.path === "/api/entries/mode-all"));
  console.log("PASS entry pagination and mode controls");
  eventError = true;
  await page.click("#tab-overview");
  await page.click("#refresh-state");
  await loaded();
  assert.equal(
    await page.evaluate("document.querySelector('#stat-deny').textContent"),
    "—",
  );
  assert.ok(
    await page.evaluate(
      "document.querySelector('#event-source-status').textContent.includes('不可用')",
    ),
  );
  eventError = false;
  const savedEvents = events;
  events = [];
  await page.click("#refresh-state");
  await loaded();
  assert.ok(
    await page.evaluate(
      "document.querySelector('#event-source-status').textContent.includes('不提供采集健康状态')",
    ),
  );
  await page.click("#tab-events");
  assert.ok(
    await page.evaluate(
      "document.querySelector('#event-empty').textContent.includes('不能据此判断')",
    ),
  );
  await page.click("#tab-overview");
  events = savedEvents;
  await page.click("#refresh-state");
  await loaded();
  await page.evaluate(
    "document.documentElement.setAttribute('data-theme','dark')",
  );
  await capture("dark");
  await page.send("Emulation.setDeviceMetricsOverride", {
    width: 390,
    height: 844,
    deviceScaleFactor: 1,
    mobile: true,
  });
  assert.ok(
    await page.evaluate("document.documentElement.scrollWidth<=innerWidth"),
  );
  await capture("mobile");
  assert.ok(
    !calls.some((call) => call.path === "/panel-api/plugins/waf/events"),
  );
  assert.deepEqual(page.errors, []);
  console.log(
    "PASS unavailable telemetry, dark mode, mobile layout and no page errors",
  );
} catch (error) {
  if (page)
    console.error(
      await page.evaluate(
        "({errors:document.querySelector('#app-status')?.textContent,body:document.body.innerText.slice(0,700)})",
      ),
    );
  throw error;
} finally {
  if (page) {
    try {
      await page.send("Browser.close");
    } catch {}
    page.socket.close();
  }
  if (browser && browser.exitCode === null) browser.kill();
  server.closeAllConnections();
  server.close();
  if (
    profile &&
    dirname(resolve(profile)) === resolve(tmpdir()) &&
    profile.includes("waf-ui-browser-")
  ) {
    await rm(profile, {
      recursive: true,
      force: true,
      maxRetries: 2,
      retryDelay: 100,
    }).catch(() => {});
  }
}
