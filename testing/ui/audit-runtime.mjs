// Shared runtime for the two R6 evidence audits. It opens the same deterministic
// previews and scenes as capture.mjs, but only inspects the live page: the
// component audit reads classes/computed tokens, and the keyboard audit presses
// real Tab/Enter/Escape keys through CDP.
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { launch, until } from "./browser.mjs";
import { discoverPlugins, themeBootstrapScript, themeFamily, viewportHeight } from "./capture.mjs";

export const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

// The nine pages R6 covers. Order is stable so every generated report is stable.
export const AUDIT_PLUGINS = [
  "accelerator-sources",
  "cloudflare-dns",
  "docker-app",
  "doh",
  "ip-policy",
  "reverse-l4",
  "shadowsocks-server",
  "waf",
  "webdav",
];

// The scene a reader lands on for each page, before optional empty/dialog states.
export const MAIN_SCENES = {
  "accelerator-sources": "usage",
  "cloudflare-dns": "mappings",
  "docker-app": "apps",
  "doh": "endpoint",
  "ip-policy": "global",
  "reverse-l4": "mappings",
  "shadowsocks-server": "listens",
  "waf": "events",
  "webdav": "files",
};

export async function loadPlugins() {
  const discovered = new Map((await discoverPlugins(repoRoot)).map((plugin) => [plugin.id, plugin]));
  return AUDIT_PLUGINS.map((id) => {
    const plugin = discovered.get(id);
    if (!plugin) throw new Error(`缺少九页审计插件 ${id} 的 capture-plugin.mjs`);
    return plugin;
  });
}

const findExpression = (selector) =>
  `(() => { const node = document.querySelector(${JSON.stringify(selector)}); if (!node) throw new Error("找不到元素 " + ${JSON.stringify(selector)}); return node; })()`;

const driverFor = (page) => {
  const evaluate = page.evaluate;
  return {
    evaluate,
    open: async (url) => {
      await page.send("Page.navigate", { url });
      await until(() => evaluate("document.readyState === 'complete'"), "页面加载");
      await evaluate("document.fonts ? document.fonts.ready.then(() => true) : true");
    },
    waitFor: (selector, ms = 8000) =>
      until(() => evaluate(`Boolean(document.querySelector(${JSON.stringify(selector)})?.getClientRects().length)`), selector, ms),
    click: (selector) => evaluate(`${findExpression(selector)}.click()`),
    fill: (selector, value) =>
      evaluate(`(() => { const node = ${findExpression(selector)}; node.focus(); node.value = ${JSON.stringify(value)}; node.dispatchEvent(new Event("input", { bubbles: true })); node.dispatchEvent(new Event("change", { bubbles: true })); })()`),
    submit: (selector) => evaluate(`${findExpression(selector)}.requestSubmit()`),
    view: (name) => evaluate(`${findExpression(`.primary [data-view="${name}"]`)}.click()`),
  };
};

export async function settle(page) {
  await page.evaluate("new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done)))");
  await delay(80);
}

// Opens one preview/page, installs the requested theme before navigation, runs
// the plugin's own scene, and returns a driver. Callers must close the result.
export async function openScene(browser, plugin, sceneName, { theme = "light" } = {}) {
  const scene = plugin.scenes.find((item) => item.name === sceneName);
  if (!scene) throw new Error(`插件 ${plugin.id} 没有场景 ${sceneName}`);
  const preview = await plugin.startPreview({ root: repoRoot });
  const page = await browser.openPage();
  let bootstrapId = null;
  const close = async () => {
    if (bootstrapId) {
      await page.send("Page.removeScriptToEvaluateOnNewDocument", { identifier: bootstrapId }).catch(() => {});
      bootstrapId = null;
    }
    try { await page.close(); } catch { /* the socket may already be gone */ }
    try { await preview.close(); } catch { /* the preview may already be stopped */ }
  };
  try {
    bootstrapId = (await page.send("Page.addScriptToEvaluateOnNewDocument", {
      source: themeBootstrapScript(plugin.themeKey, theme, { clear: true }),
    })).identifier;
    await page.send("Emulation.setDeviceMetricsOverride", {
      width: 1440,
      height: viewportHeight,
      deviceScaleFactor: 1,
      mobile: false,
    });
    await page.send("Emulation.setEmulatedMedia", {
      features: [
        { name: "prefers-color-scheme", value: themeFamily(theme) },
        { name: "prefers-reduced-motion", value: "reduce" },
      ],
    });
    const driver = driverFor(page);
    await driver.open(preview.url);
    if (scene.run) await scene.run(driver);
    await settle(page);
    return { page, preview, driver, close };
  } catch (error) {
    await close();
    throw error;
  }
}

export async function withBrowser(callback) {
  const browser = await launch();
  try {
    return await callback(browser);
  } finally {
    try { await browser.close(); } catch { /* the browser may already have exited */ }
  }
}

const KEY_PRESSES = {
  Tab: { key: "Tab", code: "Tab", windowsVirtualKeyCode: 9, nativeVirtualKeyCode: 9 },
  Enter: { key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, nativeVirtualKeyCode: 13, text: "\r" },
  Escape: { key: "Escape", code: "Escape", windowsVirtualKeyCode: 27, nativeVirtualKeyCode: 27 },
};

export async function pressKey(page, name) {
  const spec = KEY_PRESSES[name];
  if (!spec) throw new Error(`未知按键 ${name}`);
  const base = {
    key: spec.key,
    code: spec.code,
    windowsVirtualKeyCode: spec.windowsVirtualKeyCode,
    nativeVirtualKeyCode: spec.nativeVirtualKeyCode,
  };
  await page.send("Input.dispatchKeyEvent", { type: "rawKeyDown", ...base });
  if (spec.text) {
    await page.send("Input.dispatchKeyEvent", { type: "char", ...base, text: spec.text, unmodifiedText: spec.text });
  }
  await page.send("Input.dispatchKeyEvent", { type: "keyUp", ...base });
  await delay(40);
}

export const activeElementExpression = `(() => {
  const node = document.activeElement;
  if (!node) return null;
  const style = getComputedStyle(node);
  const outlineWidth = parseFloat(style.outlineWidth) || 0;
  const outline = style.outlineStyle !== "none" && outlineWidth > 0;
  const boxShadow = style.boxShadow && style.boxShadow !== "none";
  return {
    tag: node.tagName ? node.tagName.toLowerCase() : "",
    id: node.id || "",
    classes: node.classList ? [...node.classList] : [],
    focusVisible: typeof node.matches === "function" ? node.matches(":focus-visible") : false,
    outline,
    outlineWidth: outlineWidth ? style.outlineWidth : "0px",
    boxShadow: Boolean(boxShadow),
    label: (node.tagName ? node.tagName.toLowerCase() : "") +
      (node.id ? "#" + node.id : "") +
      (node.classList && node.classList.length ? "." + [...node.classList].slice(0, 4).join(".") : ""),
  };
})()`;

export async function activeElement(page) {
  return page.evaluate(activeElementExpression);
}

export async function blurActive(page) {
  await page.evaluate("document.activeElement && document.activeElement.blur ? document.activeElement.blur() : null");
}

// Presses Tab until the active element matches the selector. The path is kept
// for failure diagnostics; the report only prints the tab count.
export async function tabTo(page, selector, max = 80) {
  await blurActive(page);
  const path = [];
  for (let count = 1; count <= max; count += 1) {
    await pressKey(page, "Tab");
    const state = await activeElement(page);
    if (!state) {
      path.push("（无焦点）");
      continue;
    }
    path.push(state.label);
    const matched = await page.evaluate(`Boolean(document.activeElement && document.activeElement.matches(${JSON.stringify(selector)}))`);
    if (matched) return { found: true, tabs: count, state, path };
  }
  return { found: false, tabs: max, state: null, path };
}

export async function waitFor(page, expression, label, ms = 4000) {
  await until(() => page.evaluate(expression), label, ms);
}
