#!/usr/bin/env node
// Shared UI capture runner. Discovers plugins/<id>/testing/ui/capture-plugin.mjs.
// A module exports id, scenes[{name,title,settle,run}], and startPreview({root})
// which resolves to {url, close}. settle:false skips the network-idle wait so a
// scene can keep a request open. The driver passed to run() provides evaluate,
// open, click, fill, submit, waitFor, and view.
import { existsSync, realpathSync } from "node:fs";
import { mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { launch, until } from "./browser.mjs";
import { writeGallery } from "./gallery.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
export const viewportHeight = 900;
const namePattern = /^[a-z0-9][a-z0-9-]*$/;

// Host pages read the same-origin `localStorage.theme`; standalone pages keep
// their own `<plugin>.theme` key. The ids match the canonical ui-kit themes.
export const HOST_THEMES = ["fresh-green", "sakura-day", "sakura-night", "neko-dark", "business"];
const DARK_THEMES = new Set(["sakura-night", "neko-dark", "dark"]);
const HOST_PLUGINS = new Set(["cloudflare-dns", "docker-app", "ip-policy", "reverse-l4", "shadowsocks-server", "waf"]);
const THEME_ALIASES = ["all", "light", "dark", "host"];
export const AVAILABLE_THEMES = [...THEME_ALIASES, ...HOST_THEMES];

export function themeFamily(theme) {
  return DARK_THEMES.has(theme) ? "dark" : "light";
}

export function expandThemes(value) {
  const requested = String(value ?? "").split(",").map((item) => item.trim()).filter(Boolean);
  if (!requested.length) throw new Error(`--theme 需要至少一个主题。可用主题：${AVAILABLE_THEMES.join("、")}`);
  const themes = [];
  for (const theme of requested) {
    if (!AVAILABLE_THEMES.includes(theme)) throw new Error(`未知主题 ${theme}。可用主题：${AVAILABLE_THEMES.join("、")}`);
    if (theme === "all") themes.push("light", "dark");
    else if (theme === "host") themes.push(...HOST_THEMES);
    else themes.push(theme);
  }
  return unique(themes);
}

export function themeModeForPlugin(id, plugin) {
  if (plugin?.themeMode === "host" || plugin?.themeMode === "standalone") return plugin.themeMode;
  return HOST_PLUGINS.has(id) ? "host" : "standalone";
}

export function themeKeyForPlugin(id, mode, plugin) {
  if (typeof plugin?.themeKey === "string" && plugin.themeKey) return plugin.themeKey;
  return mode === "host" ? "theme" : `${id}.theme`;
}

// ui-kit resolves host themes by id; standalone pages only expose light/dark.
export function resolveTheme(requested, mode) {
  if (mode === "host") return requested;
  if (requested === "light" || requested === "dark") return requested;
  return DARK_THEMES.has(requested) ? "dark" : "light";
}

// Runs before page scripts. Capture clears stale storage first; the probe writes
// only the requested key so a page cannot rely on an injected data-theme.
export function themeBootstrapScript(key, theme, { clear = false } = {}) {
  return `(() => { try { ${clear ? "localStorage.clear(); " : ""}localStorage.setItem(${JSON.stringify(key)}, ${JSON.stringify(theme)}); } catch (_) {} })();`;
}

export const themeStateExpression = `(() => {
  const root = document.documentElement;
  const style = root ? getComputedStyle(root) : null;
  return {
    top: window.top === window,
    mode: root ? root.getAttribute("data-theme-mode") || "" : "",
    key: root ? root.getAttribute("data-theme-key") || "" : "",
    theme: root ? root.getAttribute("data-theme") || "" : "",
    family: root ? root.getAttribute("data-theme-family") || "" : "",
    colorScheme: style ? (style.colorScheme || "").trim() : "",
  };
})()`;

// Theme verification compares the page's real root state with what the kit
// should resolve from the requested value and the page's theme authority.
export function themeIssues(state, requested, mode, key, expected = resolveTheme(requested, mode)) {
  const family = themeFamily(expected);
  const issues = [];
  if (!state?.theme) issues.push(`主题解析不符：请求 ${requested}（${mode}），期望根主题 ${expected}，实际未设置`);
  else if (state.theme !== expected) issues.push(`主题解析不符：请求 ${requested}（${mode}），期望根主题 ${expected}，实际 ${state.theme}`);
  if (state?.mode && state.mode !== mode) issues.push(`主题模式不符：页面声明 ${state.mode}，捕获按 ${mode} 运行`);
  if (state?.key && state.key !== key) issues.push(`主题存储键不符：页面声明 ${state.key}，捕获写入 ${key}`);
  if (state?.family && state.family !== family) issues.push(`主题族不符：期望 ${family}，实际 ${state.family}`);
  return issues;
}

const usage = `用法：node testing/ui/capture.mjs [选项]

  --plugin a,b    只捕获这些插件（默认全部已注册插件）
  --only 模式     按场景名筛选，支持 * 和 ?；与 --plugin 同时使用时取交集
  --theme 值      all、light、dark、host、5 个宿主主题 id，或逗号分隔组合（默认 all）
  --size 宽度     逗号分隔的视口宽度（默认 1440,768,390）
  --out 目录      输出目录（默认 dist/ui-capture）
  --list          列出当前选择的插件和场景，不写画廊
  -h, --help      显示帮助

环境变量 NRE_UI_BROWSER 可指定 Chrome、Edge 或 Chromium。找不到浏览器时失败，不写出画廊。`;

const unique = (items) => [...new Set(items)];

const take = (argv, index, flag) => {
  const value = argv[index + 1];
  if (value === undefined || value.startsWith("--")) throw new Error(`${flag} 需要一个值\n\n${usage}`);
  return value;
};

export function parseArgs(argv, base = root) {
  const options = {
    plugins: null,
    only: null,
    themes: ["light", "dark"],
    widths: [1440, 768, 390],
    out: join(base, "dist/ui-capture"),
    list: false,
    help: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    switch (flag) {
      case "--plugin":
        options.plugins = unique(take(argv, index, flag).split(",").map((item) => item.trim()).filter(Boolean));
        index += 1;
        if (!options.plugins.length) throw new Error(`--plugin 需要至少一个插件。可用插件请运行 --list`);
        break;
      case "--only":
        options.only = unique(take(argv, index, flag).split(",").map((item) => item.trim()).filter(Boolean));
        index += 1;
        if (!options.only.length) throw new Error(`--only 需要至少一个场景模式`);
        break;
      case "--theme": {
        const theme = take(argv, index, flag);
        index += 1;
        options.themes = expandThemes(theme);
        break;
      }
      case "--size": {
        const widths = unique(take(argv, index, flag).split(",").map((item) => item.trim()).filter(Boolean).map(Number));
        index += 1;
        if (!widths.length || widths.some((width) => !Number.isInteger(width) || width < 280 || width > 3840)) {
          throw new Error(`非法宽度。可用宽度：280-3840 的整数，例如 1440、768、390`);
        }
        options.widths = widths;
        break;
      }
      case "--out": {
        const out = resolve(take(argv, index, flag));
        index += 1;
        if (out === resolve(base)) throw new Error("拒绝把仓库根目录当作输出目录");
        options.out = out;
        break;
      }
      case "--list": options.list = true; break;
      case "-h":
      case "--help": options.help = true; break;
      default: throw new Error(`未知参数 ${flag}\n\n${usage}`);
    }
  }
  return options;
}

const globToRegExp = (pattern) => new RegExp(`^${pattern.split("").map((char) => {
  if (char === "*") return ".*";
  if (char === "?") return ".";
  return char.replace(/[\\^$+.[\]{}()|]/g, "\\$&");
}).join("")}$`);

export function availableScenes(plugins) {
  const text = plugins.flatMap((plugin) => plugin.scenes.map((scene) => `${plugin.id} ${scene.name}`)).join("、");
  return text || "（无）";
}

export function selectPlugins(plugins, { plugins: requested, only } = {}) {
  let selected = plugins;
  if (requested) {
    const known = new Set(plugins.map((plugin) => plugin.id));
    const unknown = requested.filter((id) => !known.has(id));
    if (unknown.length) throw new Error(`未知插件 ${unknown.join(", ")}。可用插件：${plugins.map((plugin) => plugin.id).join("、") || "（无）"}`);
    selected = requested.map((id) => plugins.find((plugin) => plugin.id === id));
  }
  if (!selected.length) throw new Error(`没有可捕获的插件。可用插件：${plugins.map((plugin) => plugin.id).join("、") || "（无）"}`);
  if (!only) return selected.map((plugin) => ({ ...plugin, scenes: [...plugin.scenes] }));
  const exactMisses = only.filter((pattern) => !/[*?]/.test(pattern) && !selected.some((plugin) => plugin.scenes.some((scene) => scene.name === pattern)));
  if (exactMisses.length) throw new Error(`未知场景 ${exactMisses.join(", ")}。可用场景：${availableScenes(selected)}`);
  const patterns = only.map(globToRegExp);
  const narrowed = selected.map((plugin) => ({
    ...plugin,
    scenes: plugin.scenes.filter((scene) => patterns.some((pattern) => pattern.test(scene.name))),
  })).filter((plugin) => plugin.scenes.length);
  if (!narrowed.length) throw new Error(`没有匹配的场景。可用场景：${availableScenes(selected)}`);
  return narrowed;
}

export function formatList(plugins, themes = AVAILABLE_THEMES) {
  const lines = [`可用主题：${themes.join("、")}`, ""];
  for (const plugin of plugins) {
    lines.push(plugin.id, ...plugin.scenes.map((scene) => `  ${scene.name}  ${scene.title}`));
  }
  return lines.join("\n");
}

export function normalizePlugin(plugin, directoryName = "") {
  const id = plugin?.id;
  if (typeof id !== "string" || !namePattern.test(id)) throw new Error(`插件 id 无效${directoryName ? `：${directoryName}` : ""}`);
  if (directoryName && id !== directoryName) throw new Error(`插件目录 ${directoryName} 与导出的 id ${id} 不一致`);
  if (!Array.isArray(plugin.scenes) || !plugin.scenes.length) throw new Error(`插件 ${id} 没有场景`);
  if (typeof plugin.startPreview !== "function") throw new Error(`插件 ${id} 没有 startPreview`);
  const names = new Set();
  const scenes = plugin.scenes.map((scene) => {
    if (typeof scene?.name !== "string" || !namePattern.test(scene.name)) throw new Error(`插件 ${id} 的场景名无效`);
    if (names.has(scene.name)) throw new Error(`插件 ${id} 的场景 ${scene.name} 重复`);
    names.add(scene.name);
    if (scene.run !== undefined && typeof scene.run !== "function") throw new Error(`插件 ${id} 的场景 ${scene.name} 无法运行`);
    return { name: scene.name, title: scene.title || scene.name, settle: scene.settle, run: scene.run };
  });
  const themeMode = plugin?.themeMode === undefined ? themeModeForPlugin(id) : plugin.themeMode;
  if (themeMode !== "host" && themeMode !== "standalone") throw new Error(`插件 ${id} 的主题模式无效`);
  const themeKey = plugin?.themeKey === undefined ? themeKeyForPlugin(id, themeMode) : plugin.themeKey;
  if (typeof themeKey !== "string" || !themeKey.trim()) throw new Error(`插件 ${id} 的主题存储键无效`);
  return { id, scenes, startPreview: plugin.startPreview, themeMode, themeKey };
}

export async function discoverPlugins(repo = root) {
  const pluginsDir = join(repo, "plugins");
  const entries = await readdir(pluginsDir, { withFileTypes: true });
  const plugins = [];
  for (const entry of entries.filter((item) => item.isDirectory()).sort((left, right) => left.name.localeCompare(right.name))) {
    const modulePath = join(pluginsDir, entry.name, "testing", "ui", "capture-plugin.mjs");
    if (!existsSync(modulePath)) continue;
    const imported = await import(pathToFileURL(modulePath).href);
    plugins.push(normalizePlugin({
      id: imported.id,
      scenes: imported.scenes,
      startPreview: imported.startPreview,
      themeMode: imported.themeMode,
      themeKey: imported.themeKey,
    }, entry.name));
  }
  return plugins;
}

const describeException = (details) => (details?.exception?.description || details?.text || "未知页面错误").split("\n")[0];

// Visible boxes are clipped to ancestor horizontal scroll containers. Body and
// the document element are not clippers: their used overflow scrolls the viewport.
const overflowExpression = `(() => {
  const width = window.innerWidth;
  const clip = new Set(["auto", "scroll", "hidden", "clip"]);
  const label = (node) => node.tagName.toLowerCase() + (node.id ? "#" + node.id : "") + (node.classList.length ? "." + [...node.classList].slice(0, 3).join(".") : "");
  const offenders = [];
  for (const el of document.body ? document.body.querySelectorAll("*") : []) {
    if (!el.getClientRects().length) continue;
    const style = getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden") continue;
    let { left, right } = el.getBoundingClientRect();
    for (let parent = el.parentElement; parent && parent !== document.body && parent !== document.documentElement; parent = parent.parentElement) {
      if (clip.has(getComputedStyle(parent).overflowX)) {
        const rect = parent.getBoundingClientRect();
        left = Math.max(left, rect.left);
        right = Math.min(right, rect.right);
      }
    }
    if (right <= left + 1) continue;
    if (right > width + 1 || left < -1) offenders.push(label(el));
    if (offenders.length >= 8) break;
  }
  return offenders;
})()`;

const documentHeightExpression = `Math.max(document.documentElement ? document.documentElement.scrollHeight : 0, document.body ? document.body.scrollHeight : 0)`;

const pngSize = (bytes) => {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (buffer.length < 24 || buffer[0] !== 0x89 || buffer.toString("ascii", 1, 4) !== "PNG") throw new Error("截图不是 PNG");
  return { width: buffer.readUInt32BE(16), height: buffer.readUInt32BE(20) };
};

// fromSurface must stay true: false ignores captureBeyondViewport and returns only the viewport.
// captureScreenshot may return PNG bytes for one scene; null keeps the browser shot.
const capturePng = async (page, scene, options) => {
  if (typeof options.captureScreenshot === "function") {
    const overridden = await options.captureScreenshot({ page, scene });
    if (overridden) return Buffer.from(overridden);
  }
  const shot = await page.send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true, fromSurface: true });
  return Buffer.from(shot.data, "base64");
};

const createDriver = (page, pageErrors, inflight) => {
  const evaluate = page.evaluate;
  const find = (selector) => `(() => { const node = document.querySelector(${JSON.stringify(selector)}); if (!node) throw new Error("找不到元素 " + ${JSON.stringify(selector)}); return node; })()`;
  const open = async (url) => {
    pageErrors.length = 0;
    inflight.clear();
    await page.send("Page.navigate", { url });
    await until(() => evaluate("document.readyState === 'complete'"), "页面加载");
    await evaluate("document.fonts ? document.fonts.ready.then(() => true) : true");
  };
  return {
    evaluate,
    open,
    waitFor: (selector, ms = 8000) => until(() => evaluate(`Boolean(document.querySelector(${JSON.stringify(selector)})?.getClientRects().length)`), selector, ms),
    click: (selector) => evaluate(`${find(selector)}.click()`),
    fill: (selector, value) => evaluate(`(() => { const node = ${find(selector)}; node.focus(); node.value = ${JSON.stringify(value)}; node.dispatchEvent(new Event("input", { bubbles: true })); node.dispatchEvent(new Event("change", { bubbles: true })); })()`),
    submit: (selector) => evaluate(`${find(selector)}.requestSubmit()`),
    view: (name) => evaluate(`${find(`.primary [data-view="${name}"]`)}.click()`),
  };
};

const relativeFile = (plugin, scene, theme, width) => `${plugin}/${scene}-${theme}-${width}.png`;

const blankCapture = (plugin, scene, theme, width, issue) => ({
  plugin: plugin.id,
  scene: scene.name,
  title: scene.title,
  theme,
  themeMode: plugin.themeMode,
  themeKey: plugin.themeKey,
  expectedTheme: resolveTheme(theme, plugin.themeMode),
  resolvedTheme: null,
  themeFamily: null,
  width,
  height: viewportHeight,
  file: null,
  issues: [issue],
});

async function capturePlugin(browser, plugin, options, report) {
  let preview = null;
  let page = null;
  try {
    try {
      preview = await plugin.startPreview({ root: options.root });
    } catch (error) {
      for (const scene of plugin.scenes) {
        for (const theme of options.themes) {
          for (const width of options.widths) report.captures.push(blankCapture(plugin, scene, theme, width, `场景失败：预览启动失败：${error.message}`));
        }
      }
      return;
    }
    if (!preview?.url || typeof preview.close !== "function") throw new Error(`插件 ${plugin.id} 的预览没有返回 url 和 close`);
    page = await browser.openPage();
    const pageErrors = [];
    const inflight = new Set();
    page.on("Runtime.exceptionThrown", (event) => pageErrors.push(describeException(event.exceptionDetails)));
    page.on("Network.requestWillBeSent", ({ requestId }) => inflight.add(requestId));
    page.on("Network.loadingFinished", ({ requestId }) => inflight.delete(requestId));
    page.on("Network.loadingFailed", ({ requestId }) => inflight.delete(requestId));
    let bootstrapId = null;
    for (const theme of options.themes) {
      await page.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: themeFamily(theme) }, { name: "prefers-reduced-motion", value: "reduce" }] });
      if (bootstrapId) await page.send("Page.removeScriptToEvaluateOnNewDocument", { identifier: bootstrapId }).catch(() => {});
      bootstrapId = (await page.send("Page.addScriptToEvaluateOnNewDocument", {
        source: themeBootstrapScript(plugin.themeKey, theme, { clear: true }),
      })).identifier;
      for (const width of options.widths) {
        await page.send("Emulation.setDeviceMetricsOverride", { width, height: viewportHeight, deviceScaleFactor: 1, mobile: width < 600 });
        for (const scene of plugin.scenes) {
          const issues = [];
          const driver = createDriver(page, pageErrors, inflight);
          let opened = false;
          try {
            await driver.open(preview.url);
            opened = true;
            if (scene.run) await scene.run(driver);
            if (scene.settle !== false) await until(() => inflight.size === 0, "网络空闲", 8000);
            await page.evaluate("new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done)))");
            await delay(120);
          } catch (error) {
            issues.push(`场景失败：${error.message}`);
          }
          let file = null;
          let height = viewportHeight;
          let resolvedTheme = null;
          let resolvedFamily = null;
          if (opened) {
            let documentHeight = null;
            try {
              const themeState = await page.evaluate(themeStateExpression);
              resolvedTheme = themeState?.theme || null;
              resolvedFamily = themeState?.family || null;
              for (const issue of themeIssues(themeState, theme, plugin.themeMode, plugin.themeKey)) issues.push(issue);
            } catch (error) {
              issues.push(`场景失败：无法读取主题状态：${error.message}`);
            }
            try {
              const overflow = await page.evaluate(overflowExpression);
              if (Array.isArray(overflow) && overflow.length) issues.push(`横向溢出：${overflow.join("、")}`);
              documentHeight = Number(await page.evaluate(documentHeightExpression));
              if (!Number.isFinite(documentHeight)) throw new Error("无法读取文档高度");
            } catch (error) {
              issues.push(`场景失败：${error.message}`);
            }
            for (const message of [...new Set(pageErrors)]) issues.push(`页面错误：${message}`);
            try {
              const bytes = await capturePng(page, scene, options);
              const size = pngSize(bytes);
              file = relativeFile(plugin.id, scene.name, theme, width);
              const target = join(options.out, ...file.split("/"));
              await mkdir(dirname(target), { recursive: true });
              await writeFile(target, bytes);
              height = size.height;
              if (Number.isFinite(documentHeight) && documentHeight > viewportHeight && size.height <= viewportHeight) {
                issues.push(`整页内容没有进入图片（文档 ${documentHeight}px，图片 ${size.height}px）`);
              }
            } catch (error) {
              file = null;
              issues.push(`场景失败：${error.message}`);
            }
          }
          report.captures.push({
            plugin: plugin.id,
            scene: scene.name,
            title: scene.title,
            theme,
            themeMode: plugin.themeMode,
            themeKey: plugin.themeKey,
            expectedTheme: resolveTheme(theme, plugin.themeMode),
            resolvedTheme,
            themeFamily: resolvedFamily,
            width,
            height,
            file,
            issues,
          });
          console.log(`${issues.length ? "FAIL" : "ok  "} ${plugin.id}/${scene.name}-${theme}-${width}.png${issues.map((issue) => `\n     - ${issue}`).join("")}`);
        }
      }
    }
  } catch (error) {
    for (const scene of plugin.scenes) {
      for (const theme of options.themes) {
        for (const width of options.widths) {
          if (report.captures.some((item) => item.plugin === plugin.id && item.scene === scene.name && item.theme === theme && item.width === width)) continue;
          report.captures.push(blankCapture(plugin, scene, theme, width, `场景失败：${error.message}`));
        }
      }
    }
  } finally {
    try { await page?.close?.(); } catch { /* the socket may already be gone */ }
    try { await preview?.close?.(); } catch { /* the preview may already be stopped */ }
  }
}

const fileExists = (out, file) => file && existsSync(join(out, ...file.split("/")));

function finalizeReport(report, out) {
  report.missing = [];
  for (const item of report.selected) {
    for (const scene of item.scenes) {
      for (const theme of report.themes) {
        for (const width of report.widths) {
          const capture = report.captures.find((candidate) => candidate.plugin === item.plugin && candidate.scene === scene && candidate.theme === theme && candidate.width === width);
          if (!fileExists(out, capture?.file)) report.missing.push({ plugin: item.plugin, scene, theme, width });
        }
      }
    }
  }
  const failures = report.captures.filter((item) => item.issues.length).map((item) => ({ plugin: item.plugin, scene: item.scene, theme: item.theme, width: item.width, issues: [...item.issues] }));
  for (const missing of report.missing) {
    const existing = failures.find((item) => item.plugin === missing.plugin && item.scene === missing.scene && item.theme === missing.theme && item.width === missing.width);
    if (existing) {
      if (!existing.issues.includes("缺少图片")) existing.issues.push("缺少图片");
    } else {
      failures.push({ ...missing, issues: ["缺少图片"] });
    }
  }
  report.failures = failures;
  report.imageCount = report.captures.filter((item) => fileExists(out, item.file)).length;
  report.failureCount = failures.length;
  report.success = failures.length === 0;
}

export async function runCapture(options) {
  const plugins = options.plugins.map((plugin) => normalizePlugin(plugin));
  const browser = await launch();
  const report = {
    capturedAt: new Date().toISOString(),
    invocation: options.invocation,
    themes: options.themes,
    widths: options.widths,
    selected: plugins.map((plugin) => ({ plugin: plugin.id, scenes: plugin.scenes.map((scene) => scene.name) })),
    missing: [],
    success: false,
    imageCount: 0,
    failureCount: 0,
    captures: [],
    failures: [],
  };
  try {
    await rm(options.out, { recursive: true, force: true });
    await mkdir(options.out, { recursive: true });
    try {
      for (const plugin of plugins) await capturePlugin(browser, plugin, options, report);
    } finally {
      finalizeReport(report, options.out);
      await writeGallery(options.out, report);
    }
  } finally {
    try { await browser.close(); } catch { /* the browser may already have exited */ }
  }
  return report;
}

const shellJoin = (args) => ["node", "testing/ui/capture.mjs", ...args].map((arg) => (/^[A-Za-z0-9_./:=,@*?+-]+$/.test(arg) ? arg : JSON.stringify(arg))).join(" ");

export async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    console.log(usage);
    return;
  }
  const selected = selectPlugins(await discoverPlugins(root), options);
  if (options.list) {
    console.log(formatList(selected));
    return;
  }
  const report = await runCapture({ ...options, plugins: selected, root, invocation: shellJoin(argv) });
  const gallery = relative(process.cwd(), join(options.out, "index.html")).split(sep).join("/");
  console.log(`\n${report.imageCount} 张截图，${report.failureCount} 项失败 → ${gallery}`);
  if (!report.success) process.exitCode = 1;
}

const invokedDirectly = () => {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
};

if (invokedDirectly()) {
  main().catch((error) => {
    console.error(error.message || error);
    process.exitCode = 1;
  });
}
