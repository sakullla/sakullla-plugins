#!/usr/bin/env node
// Top-level theme probe. Opens a page with only `localStorage[key]` prepared
// before navigation and checks the root theme the page resolves. Host pages
// must land on the five host theme ids; standalone pages only expose light/dark.
//
//   node testing/ui/theme-probe.mjs                       # all host pages x 5 themes
//   node testing/ui/theme-probe.mjs --plugin waf --theme neko-dark
//   node testing/ui/theme-probe.mjs --url http://127.0.0.1:8080/ --theme fresh-green
import { realpathSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { launch, until } from "./browser.mjs";
import {
  HOST_THEMES,
  discoverPlugins,
  expandThemes,
  resolveTheme,
  themeFamily,
  themeIssues,
  themeBootstrapScript,
  themeStateExpression,
} from "./capture.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

const usage = `用法：node testing/ui/theme-probe.mjs [选项]

  --plugin a,b    只探测这些插件（默认全部宿主主题插件）
  --theme 值      host（默认）、all、light、dark、5 个宿主主题 id 或逗号分隔组合
  --url URL       直接探测一个 URL，跳过插件发现
  --mode 值       host 或 standalone（配合 --url，默认 host）
  --key 键        localStorage 存储键（配合 --url；默认 theme）
  --expect 主题   期望根主题（配合 --url；默认按 mode 解析）
  --list          列出将探测的页面和主题
  -h, --help      显示帮助

每个探测只写 localStorage，不注入 data-theme；页面必须自己解析出根主题。`;

const unique = (items) => [...new Set(items)];

const take = (argv, index, flag) => {
  const value = argv[index + 1];
  if (value === undefined || value.startsWith("--")) throw new Error(`${flag} 需要一个值\n\n${usage}`);
  return value;
};

export function parseArgs(argv) {
  const options = {
    plugins: null,
    themes: [...HOST_THEMES],
    url: null,
    mode: "host",
    key: null,
    expect: null,
    list: false,
    help: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    switch (flag) {
      case "--plugin":
        options.plugins = unique(take(argv, index, flag).split(",").map((item) => item.trim()).filter(Boolean));
        index += 1;
        if (!options.plugins.length) throw new Error("--plugin 需要至少一个插件");
        break;
      case "--theme":
        options.themes = expandThemes(take(argv, index, flag));
        index += 1;
        break;
      case "--url":
        options.url = take(argv, index, flag);
        index += 1;
        break;
      case "--mode": {
        const mode = take(argv, index, flag);
        index += 1;
        if (mode !== "host" && mode !== "standalone") throw new Error(`未知主题模式 ${mode}。可用模式：host、standalone`);
        options.mode = mode;
        break;
      }
      case "--key":
        options.key = take(argv, index, flag);
        index += 1;
        break;
      case "--expect":
        options.expect = take(argv, index, flag);
        index += 1;
        break;
      case "--list": options.list = true; break;
      case "-h":
      case "--help": options.help = true; break;
      default: throw new Error(`未知参数 ${flag}\n\n${usage}`);
    }
  }
  return options;
}

const waitForComplete = async (page) => {
  await until(() => page.evaluate("document.readyState === 'complete'"), "页面加载");
  await page.evaluate("document.fonts ? document.fonts.ready.then(() => true) : true");
  await page.evaluate("new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done)))");
  await delay(80);
};

// Only localStorage is prepared; the page itself must resolve data-theme.
export async function probeTheme(page, { url, theme, mode, key, expected = resolveTheme(theme, mode) }) {
  const { identifier } = await page.send("Page.addScriptToEvaluateOnNewDocument", {
    source: themeBootstrapScript(key, theme),
  });
  try {
    await page.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
    await page.send("Emulation.setEmulatedMedia", {
      features: [
        { name: "prefers-color-scheme", value: themeFamily(expected) },
        { name: "prefers-reduced-motion", value: "reduce" },
      ],
    });
    await page.send("Page.navigate", { url });
    await waitForComplete(page);
    const state = await page.evaluate(themeStateExpression);
    const issues = themeIssues(state, theme, mode, key, expected);
    if (!state.top) issues.unshift("不是顶层页面（window.top 不是 window）");
    return { state, issues };
  } finally {
    await page.send("Page.removeScriptToEvaluateOnNewDocument", { identifier }).catch(() => {});
  }
}

const describe = (state) => `mode=${state.mode || "?"} root=${state.theme || "未设置"} family=${state.family || "?"}`;

async function probeHostPages(options) {
  const plugins = (await discoverPlugins(root)).filter((plugin) => options.plugins
    ? options.plugins.includes(plugin.id)
    : plugin.themeMode === "host");
  if (options.plugins) {
    const known = new Set(plugins.map((plugin) => plugin.id));
    const unknown = options.plugins.filter((id) => !known.has(id));
    if (unknown.length) throw new Error(`未知或非捕获插件 ${unknown.join(", ")}`);
  }
  if (!plugins.length) throw new Error("没有可探测的宿主主题插件");
  if (options.list) {
    for (const plugin of plugins) console.log(`${plugin.id}（${plugin.themeMode}）: ${options.themes.join(", ")}`);
    return { passed: 0, failed: 0 };
  }
  const browser = await launch();
  let passed = 0;
  let failed = 0;
  try {
    for (const plugin of plugins) {
      let preview = null;
      try {
        preview = await plugin.startPreview({ root });
      } catch (error) {
        for (const theme of options.themes) {
          failed += 1;
          console.log(`FAIL ${plugin.id}/${theme}: 预览启动失败：${error.message}`);
        }
        continue;
      }
      let page = null;
      try {
        page = await browser.openPage();
        for (const theme of options.themes) {
          const key = plugin.themeKey;
          const expected = resolveTheme(theme, plugin.themeMode);
          try {
            const { state, issues } = await probeTheme(page, { url: preview.url, theme, mode: plugin.themeMode, key, expected });
            if (issues.length) {
              failed += 1;
              console.log(`FAIL ${plugin.id}/${theme}: ${describe(state)}\n     - ${issues.join("\n     - ")}`);
            } else {
              passed += 1;
              console.log(`ok   ${plugin.id}/${theme}: ${describe(state)}`);
            }
          } catch (error) {
            failed += 1;
            console.log(`FAIL ${plugin.id}/${theme}: ${error.message}`);
          }
        }
      } finally {
        try { await page?.close?.(); } catch { /* the socket may already be gone */ }
        try { await preview?.close?.(); } catch { /* the preview may already be stopped */ }
      }
    }
  } finally {
    try { await browser.close(); } catch { /* the browser may already have exited */ }
  }
  return { passed, failed };
}

async function probeUrl(options) {
  const key = options.key || "theme";
  if (options.list) {
    for (const theme of options.themes) console.log(`${options.url}（${options.mode}, key=${key}）: ${theme}`);
    return { passed: 0, failed: 0 };
  }
  const browser = await launch();
  let passed = 0;
  let failed = 0;
  try {
    const page = await browser.openPage();
    try {
      for (const theme of options.themes) {
        const expected = options.expect || resolveTheme(theme, options.mode);
        try {
          const { state, issues } = await probeTheme(page, { url: options.url, theme, mode: options.mode, key, expected });
          if (issues.length) {
            failed += 1;
            console.log(`FAIL ${theme}: ${describe(state)}\n     - ${issues.join("\n     - ")}`);
          } else {
            passed += 1;
            console.log(`ok   ${theme}: ${describe(state)}`);
          }
        } catch (error) {
          failed += 1;
          console.log(`FAIL ${theme}: ${error.message}`);
        }
      }
    } finally {
      try { await page.close(); } catch { /* the socket may already be gone */ }
    }
  } finally {
    try { await browser.close(); } catch { /* the browser may already have exited */ }
  }
  return { passed, failed };
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    console.log(usage);
    return;
  }
  const result = options.url ? await probeUrl(options) : await probeHostPages(options);
  if (options.list) return;
  console.log(`\n${result.passed} 项通过，${result.failed} 项失败`);
  if (result.failed) process.exitCode = 1;
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
