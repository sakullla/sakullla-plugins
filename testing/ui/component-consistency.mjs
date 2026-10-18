#!/usr/bin/env node
// R6 component consistency audit. It opens the nine registered plugin pages with
// their own preview fixtures, inspects the live DOM for the primary button,
// input, table, badge, dialog and empty state, and checks that each rendered
// component uses the shared kit class and the canonical --ui-* tokens.
//
//   node testing/ui/component-consistency.mjs          # regenerate the report
//   node testing/ui/component-consistency.mjs --check  # fail when it is stale
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  MAIN_SCENES,
  openScene,
  loadPlugins,
  settle,
  withBrowser,
} from "./audit-runtime.mjs";

const here = dirname(fileURLToPath(import.meta.url));
export const REPORT_PATH = join(here, "component-consistency.md");

const CATEGORIES = [
  ["primary", "主按钮"],
  ["input", "输入"],
  ["table", "表格"],
  ["badge", "徽章"],
  ["dialog", "对话框"],
  ["empty", "空状态"],
];

// Some pages only render a component on a secondary view of the main flow.
// Open that view for the specific component so the report describes a rendered
// instance rather than a hidden fallback.
const CATEGORY_SCENES = {
  "accelerator-sources": { primary: "mirrors", empty: "mirrors" },
  "docker-app": { dialog: "files" },
  "shadowsocks-server": { table: "routing" },
  "waf": { primary: "overview" },
  "webdav": { primary: "login", input: "login" },
};

const EMPTY_TARGETS = {
  "docker-app": "#app-empty",
  "shadowsocks-server": "#app-empty",
  "waf": "#event-empty",
};

const componentExpression = (emptyTarget) => `(() => {
  const targetSelector = ${JSON.stringify(emptyTarget || null)};
  const isVisible = (node) => {
    if (!node || !node.getClientRects().length) return false;
    const style = getComputedStyle(node);
    return style.visibility !== "hidden" && style.display !== "none";
  };
  const label = (node) => (node.tagName ? node.tagName.toLowerCase() : "") +
    (node.id ? "#" + node.id : "") +
    (node.classList && node.classList.length ? "." + [...node.classList].slice(0, 4).join(".") : "");
  const resolved = (property, token) => {
    const probe = document.createElement("div");
    probe.style.cssText = "position:absolute;left:-9999px;top:0;visibility:hidden;width:1px;height:1px;";
    document.body.appendChild(probe);
    if (property === "borderTopColor") {
      probe.style.borderStyle = "solid";
      probe.style.borderWidth = "1px";
      probe.style.setProperty("border-color", "var(" + token + ")");
    } else {
      probe.style.setProperty(property.replace(/[A-Z]/g, (letter) => "-" + letter.toLowerCase()), "var(" + token + ")");
    }
    const value = getComputedStyle(probe)[property];
    probe.remove();
    return value;
  };
  const same = (left, right) => String(left || "").trim().toLowerCase() === String(right || "").trim().toLowerCase();
  const check = (node, property, token, name) => ({
    name,
    token,
    ok: same(getComputedStyle(node)[property], resolved(property, token)),
  });
  const checkColorPair = (node, background, foreground, name) => ({
    name,
    token: background + " / " + foreground,
    ok: same(getComputedStyle(node).backgroundColor, resolved("backgroundColor", background)) &&
      same(getComputedStyle(node).color, resolved("color", foreground)),
  });
  const pick = (selector) => {
    const nodes = [...document.querySelectorAll(selector)];
    return { nodes, node: nodes.find(isVisible) || nodes[0] || null };
  };
  const describe = (node) => {
    if (!node) return { present: false };
    const classes = node.classList ? [...node.classList] : [];
    return {
      present: true,
      hidden: !isVisible(node),
      label: label(node),
      count: node.isConnected ? document.querySelectorAll("." + classes[0]).length : 0,
      classes,
      modifiers: classes.filter((name) => name.startsWith("ui-")),
      pageClasses: classes.filter((name) => !name.startsWith("ui-")),
    };
  };
  const result = {};

  {
    const { nodes, node } = pick('.ui-btn:not(.ui-btn--secondary):not(.ui-btn--ghost):not(.ui-btn--danger):not(.ui-btn--danger-soft):not(.ui-btn--icon)');
    if (!node) result.primary = { present: false, reason: "页面主流程没有主按钮" };
    else {
      const small = node.classList.contains("ui-btn--sm");
      const large = node.classList.contains("ui-btn--lg");
      const info = describe(node);
      info.kit = node.classList.contains("ui-btn");
      info.tokenChecks = [
        check(node, "backgroundColor", "--ui-primary", "背景"),
        check(node, "color", "--ui-on-primary", "文字"),
        check(node, "borderRadius", small ? "--ui-radius-md" : "--ui-radius-lg", "圆角"),
        check(node, "fontSize", small ? "--ui-text-xs" : large ? "--ui-text-base" : "--ui-text-sm", "字号"),
      ];
      info.count = nodes.length;
      result.primary = info;
    }
  }

  {
    const node = document.querySelector("dialog.ui-dialog");
    if (!node) result.dialog = { present: false, reason: "页面没有对话框" };
    else {
      // The page may keep an unused dialog in the hidden state; remove that
      // presentation flag so its rendered kit tokens can be measured.
      if (node.hasAttribute("hidden")) node.removeAttribute("hidden");
      if (!node.open && typeof node.showModal === "function") {
        try { node.showModal(); } catch (_) { /* keep the closed element for inspection */ }
      }
      const info = describe(node);
      info.kit = node.classList.contains("ui-dialog");
      info.tokenChecks = [
        check(node, "backgroundColor", "--ui-surface", "背景"),
        check(node, "color", "--ui-text", "文字"),
        check(node, "borderTopColor", "--ui-border", "边框"),
        check(node, "borderTopLeftRadius", "--ui-radius-2xl", "圆角"),
      ];
      info.count = document.querySelectorAll("dialog.ui-dialog").length;
      result.dialog = info;
    }
  }

  {
    const { nodes, node } = pick(".ui-input");
    if (!node) result.input = { present: false, reason: "页面主流程没有输入控件" };
    else {
      const info = describe(node);
      info.kit = node.classList.contains("ui-input");
      // The accelerator converter deliberately uses the large control tokens
      // (--ui-control-height-lg / --ui-text-base) for its first-screen input.
      const large = same(getComputedStyle(node).fontSize, resolved("fontSize", "--ui-text-base")) &&
        same(getComputedStyle(node).minHeight, resolved("minHeight", "--ui-control-height-lg"));
      info.variants = large ? ["大尺寸变体（--ui-control-height-lg、--ui-text-base）"] : [];
      info.tokenChecks = [
        check(node, "backgroundColor", "--ui-surface", "背景"),
        check(node, "color", "--ui-text", "文字"),
        check(node, "borderTopColor", "--ui-border", "边框"),
        check(node, "borderRadius", "--ui-radius-md", "圆角"),
        check(node, "fontSize", large ? "--ui-text-base" : "--ui-text-sm", "字号"),
      ];
      info.count = nodes.length;
      result.input = info;
    }
  }

  {
    const { nodes, node } = pick(".ui-table");
    if (!node) result.table = { present: false, reason: "页面主流程没有表格" };
    else {
      const info = describe(node);
      info.kit = node.classList.contains("ui-table");
      const header = node.querySelector("th");
      info.tokenChecks = [
        check(node, "fontSize", "--ui-text-sm", "字号"),
        ...(header ? [
          check(header, "backgroundColor", "--ui-sunken", "表头背景"),
          check(header, "color", "--ui-text-tertiary", "表头文字"),
        ] : []),
      ];
      info.count = nodes.length;
      result.table = info;
    }
  }

  {
    const { nodes, node } = pick(".ui-badge");
    if (!node) result.badge = { present: false, reason: "页面主流程没有徽章" };
    else {
      const info = describe(node);
      info.kit = node.classList.contains("ui-badge");
      const pairs = [
        ["--ui-subtle", "--ui-text-secondary"],
        ["--ui-primary-soft", "--ui-primary"],
        ["--ui-success-soft", "--ui-success-text"],
        ["--ui-warning-soft", "--ui-warning-text"],
        ["--ui-danger-soft", "--ui-danger-text"],
      ];
      const pair = pairs.find(([background, foreground]) =>
        same(getComputedStyle(node).backgroundColor, resolved("backgroundColor", background)) &&
        same(getComputedStyle(node).color, resolved("color", foreground)));
      info.tokenChecks = [
        {
          name: "背景/文字",
          token: pair ? pair[0] + " / " + pair[1] : "kit 徽章组合",
          ok: Boolean(pair),
        },
        check(node, "borderRadius", "--ui-radius-full", "圆角"),
        check(node, "fontSize", "--ui-text-xs", "字号"),
      ];
      info.count = nodes.length;
      result.badge = info;
    }
  }

  {
    const measure = (node) => {
      const info = describe(node);
      info.kit = node.classList.contains("ui-empty");
      const title = node.querySelector(".ui-empty__title");
      // App state panels reuse .ui-empty with the quieter --ui-border-subtle
      // boundary; both are kit tokens, so record the state-panel variant.
      const borderToken = ["--ui-border", "--ui-border-subtle"].find((token) =>
        same(getComputedStyle(node).borderTopColor, resolved("borderTopColor", token)));
      info.variants = borderToken === "--ui-border-subtle" ? ["状态面板变体（--ui-border-subtle，实线边框）"] : [];
      info.tokenChecks = [
        check(node, "backgroundColor", "--ui-surface", "背景"),
        { name: "边框", token: borderToken || "--ui-border", ok: Boolean(borderToken) },
        check(node, "borderTopLeftRadius", "--ui-radius-2xl", "圆角"),
        ...(title ? [check(title, "color", "--ui-text", "标题文字")] : []),
      ];
      info.count = document.querySelectorAll(".ui-empty").length;
      return info;
    };

    if (targetSelector) {
      const node = document.querySelector(targetSelector);
      if (!node) result.empty = { present: false, reason: "页面没有空数据容器 " + targetSelector };
      else {
        // The capture fixture hides the real empty-data container (and often a
        // hidden workspace ancestor). Reveal it only for this measurement, then
        // restore every attribute; this mirrors the hidden-dialog treatment.
        const revealed = [];
        for (let current = node; current && current !== document.documentElement; current = current.parentElement) {
          if (current.hasAttribute("hidden")) {
            current.removeAttribute("hidden");
            revealed.push(current);
          }
        }
        const info = measure(node);
        info.revealed = revealed.length > 0;
        info.revealedCount = revealed.length;
        info.rendered = isVisible(node);
        for (const current of revealed) current.setAttribute("hidden", "");
        result.empty = info;
      }
    } else {
      const { nodes, node } = pick(".ui-empty");
      if (!node) result.empty = { present: false, reason: "页面没有空状态" };
      else {
        const info = measure(node);
        info.count = nodes.length;
        result.empty = info;
      }
    }
  }

  return result;
})()`;

async function collect(page, emptyTarget = null) {
  const data = await page.evaluate(componentExpression(emptyTarget));
  await settle(page);
  return data;
}

const emptySceneFor = (plugin) => plugin.scenes.find((scene) => /(^|-)empty($|-)/.test(scene.name))?.name || null;

function tokenState(item) {
  const failed = item.tokenChecks.filter((check) => !check.ok);
  return { ok: failed.length === 0, failed };
}

function row(pageId, scene, category, item) {
  const title = category[1];
  if (!item.present) {
    return `| ${pageId} | ${scene} | ${title} | — | — | — | 不适用（${item.reason}） |`;
  }
  const tokens = tokenState(item);
  const kit = item.kit ? "是" : "否";
  const token = tokens.ok ? "是" : `否（${tokens.failed.map((check) => check.name).join("、")}）`;
  const element = `${item.label}${item.revealed
    ? item.hidden ? "（测量时临时解除 hidden 后仍不可见）" : "（测量时临时解除 hidden）"
    : item.hidden ? "（隐藏）" : ""}`;
  const layout = item.pageClasses.length ? `（布局类：${item.pageClasses.join("、")}）` : "";
  const variants = item.variants?.length ? `（${item.variants.join("；")}）` : "";
  let difference;
  if (item.revealed && item.rendered === false) difference = "未验证：临时解除 hidden 后仍不可见";
  else if (!item.kit) difference = "未消除：缺少 kit 类名";
  else if (!tokens.ok) difference = `未消除：${tokens.failed.map((check) => check.name).join("、")} 与 token 不一致`;
  else difference = `已消除${variants}${layout}`;
  return `| ${pageId} | ${scene} | ${title} | ${element} | ${kit} | ${token} | ${difference} |`;
}

const BASE_CLASSES = {
  primary: "ui-btn",
  input: "ui-input",
  table: "ui-table",
  badge: "ui-badge",
  dialog: "ui-dialog",
  empty: "ui-empty",
};

function summaryLine(category, items) {
  const present = items.filter((item) => item.data.present);
  const missing = items.filter((item) => !item.data.present).map((item) => item.page);
  const failures = present.filter((item) => !item.data.kit || !tokenState(item.data).ok);
  const base = BASE_CLASSES[category[0]];
  const modifiers = [...new Set(present.flatMap((item) => item.data.modifiers.filter((name) => name !== base)))].sort();
  const variants = [...new Set(present.flatMap((item) => item.data.variants || []))].sort();
  const layout = [...new Set(present.flatMap((item) => item.data.pageClasses))].sort();
  const parts = [`${present.length}/${items.length} 页存在`];
  if (failures.length) parts.push(`未消除 ${failures.map((item) => item.page).join("、")}`);
  else if (present.length) parts.push("类名与 token 检查全部通过");
  if (modifiers.length) parts.push(`kit 变体：${modifiers.join("、")}`);
  if (variants.length) parts.push(`token 变体：${variants.join("、")}`);
  if (layout.length) parts.push(`页面布局类：${layout.join("、")}`);
  if (missing.length) parts.push(`不适用：${missing.join("、")}`);
  return `- ${category[1]}：${parts.join("；")}。`;
}

export async function buildComponentReport() {
  const plugins = await loadPlugins();
  const rows = [];
  const byCategory = Object.fromEntries(CATEGORIES.map((category) => [category[0], []]));
  const failures = [];

  await withBrowser(async (browser) => {
    for (const plugin of plugins) {
      const sceneName = MAIN_SCENES[plugin.id];
      const main = await openScene(browser, plugin, sceneName);
      let mainData;
      try {
        mainData = await collect(main.page, EMPTY_TARGETS[plugin.id] || null);
      } finally {
        await main.close();
      }

      const emptyScene = emptySceneFor(plugin);
      let emptyData = null;
      let emptySceneName = sceneName;
      if (emptyScene && emptyScene !== sceneName) {
        const emptyPage = await openScene(browser, plugin, emptyScene);
        try {
          const data = await collect(emptyPage.page, EMPTY_TARGETS[plugin.id] || null);
          emptyData = data.empty;
        } finally {
          await emptyPage.close();
        }
        emptySceneName = emptyScene;
      }

      for (const category of CATEGORIES) {
        let data = mainData[category[0]];
        let scene = sceneName;
        const overrideScene = CATEGORY_SCENES[plugin.id]?.[category[0]];
        if (overrideScene) {
          const overridePage = await openScene(browser, plugin, overrideScene);
          try {
            data = (await collect(overridePage.page, EMPTY_TARGETS[plugin.id] || null))[category[0]];
          } finally {
            await overridePage.close();
          }
          scene = overrideScene;
        } else if (category[0] === "empty" && emptyData) {
          data = emptyData;
          scene = emptySceneName;
        }
        rows.push(row(plugin.id, scene, category, data));
        byCategory[category[0]].push({ page: plugin.id, data });
        if (data.present && (!data.kit || !tokenState(data).ok)) {
          const reasons = [];
          if (!data.kit) reasons.push("缺少 kit 类名");
          if (!tokenState(data).ok) reasons.push(`token 不一致：${tokenState(data).failed.map((check) => check.name).join("、")}`);
          failures.push(`${plugin.id}/${category[1]}：${reasons.join("；")}`);
        }
      }
    }
  });

  const presentTotal = CATEGORIES.reduce((sum, category) => sum + byCategory[category[0]].filter((item) => item.data.present).length, 0);
  const lines = [
    "# 九页组件一致性审计",
    "",
    "> 本文件由 `node testing/ui/component-consistency.mjs` 从当前页面实时生成；请勿手改。",
    "> 检查对象为 R6 的九页：accelerator-sources、cloudflare-dns、docker-app、doh、ip-policy、reverse-l4、shadowsocks-server、waf、webdav。",
    "",
    `- 主题：light；视口：1440×900；场景：各页主流程及必要子视图（如 mirrors、login、routing、files）；空状态优先使用页面自带的空数据场景。`,
    `- 夹具中隐藏的空数据容器（docker-app #app-empty、shadowsocks-server #app-empty、waf #event-empty）在测量时临时解除自身与祖先的 hidden，测量后立即恢复；元素列标注该测量方式。`,
    `- 结果：${presentTotal} 个存在的组件中 ${presentTotal - failures.length} 个通过，${failures.length} 个未消除。`,
    "",
    "## 检查口径",
    "",
    "| 组件 | kit 类名 | 检查的 `--ui-*` token |",
    "| --- | --- | --- |",
    "| 主按钮 | `.ui-btn`（不含 secondary、ghost、danger、icon） | 背景 `--ui-primary`、文字 `--ui-on-primary`、圆角与字号（`--sm`/`--lg` 取对应 kit token） |",
    "| 输入 | `.ui-input` | 背景 `--ui-surface`、文字 `--ui-text`、边框 `--ui-border`、圆角 `--ui-radius-md`；字号 `--ui-text-sm`，转换器大输入允许 `--ui-control-height-lg`/`--ui-text-base` 变体 |",
    "| 表格 | `.ui-table` | 字号 `--ui-text-sm`、表头背景 `--ui-sunken`、表头文字 `--ui-text-tertiary` |",
    "| 徽章 | `.ui-badge` | 圆角 `--ui-radius-full`、字号 `--ui-text-xs`，背景/文字必须命中一套 kit 徽章 token |",
    "| 对话框 | `dialog.ui-dialog` | 背景 `--ui-surface`、文字 `--ui-text`、边框 `--ui-border`、圆角 `--ui-radius-2xl` |",
    "| 空状态 | `.ui-empty` | 背景 `--ui-surface`、边框 `--ui-border` 或状态面板的 `--ui-border-subtle`、圆角 `--ui-radius-2xl`、标题文字 `--ui-text`；夹具隐藏的空数据容器在测量时临时解除 hidden |",
    "",
    "「已消除」表示组件使用 kit 类名、检查的 `--ui-*` token 全部命中；页面自身布局类（如栅格、宽度）不会改变组件 token，按布局类单独列出。临时解除 hidden 后仍不可见的空状态标为“未验证”，不计入已消除。",
    "",
    "## 逐项清单",
    "",
    "| 页面 | 场景 | 组件 | 元素 | kit 类名 | `--ui-*` token | 差异是否已消除 |",
    "| --- | --- | --- | --- | --- | --- | --- |",
    ...rows,
    "",
    "## 跨页差异",
    "",
    ...CATEGORIES.map((category) => summaryLine(category, byCategory[category[0]])),
    "",
  ];
  if (failures.length) lines.push("## 未消除项", "", ...failures.map((failure) => `- ${failure}`), "");
  else lines.push("## 结论", "", "九页主流程实际出现的组件均使用共享 kit 类名与 `--ui-*` token；夹具中隐藏的空数据状态按标注的临时解除 hidden 方式测量，尺寸与布局差异均落在 kit token 变体内，差异已消除。", "");

  return { markdown: lines.join("\n"), failures };
}

export async function main(argv = process.argv.slice(2)) {
  const check = argv.includes("--check");
  if (argv.some((arg) => arg !== "--check")) throw new Error("用法：node testing/ui/component-consistency.mjs [--check]");
  const { markdown, failures } = await buildComponentReport();
  if (check) {
    const existing = await readFile(REPORT_PATH, "utf8").catch(() => null);
    if (existing !== markdown) {
      console.error(`${REPORT_PATH} 与当前页面不一致；请运行 node testing/ui/component-consistency.mjs 重新生成`);
      process.exitCode = 1;
      return;
    }
    console.log(`${REPORT_PATH} 与当前页面一致（${failures.length} 项未消除）`);
    if (failures.length) process.exitCode = 1;
    return;
  }
  await writeFile(REPORT_PATH, markdown, "utf8");
  console.log(`${REPORT_PATH} 已生成（${failures.length} 项未消除）`);
  if (failures.length) process.exitCode = 1;
}

const invokedDirectly = () => {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return resolve(entry) === resolve(fileURLToPath(import.meta.url));
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
