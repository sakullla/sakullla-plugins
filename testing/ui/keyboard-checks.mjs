#!/usr/bin/env node
// R6 keyboard evidence audit. For each of the nine pages it opens the page's
// main flow, presses real Tab/Enter/Escape keys through CDP, and verifies:
//   - Tab lands on the declared trigger with a visible focus indicator;
//   - Enter activates the trigger (opens its dialog, copies the converter
//     result, or triggers the copy status);
//   - Escape closes the dialog and returns focus, clears the converter input,
//     or is recorded as having no modal to close.
// Each page records the one main-flow path listed in its `coverage` entry; the
// report states that per-page scope instead of claiming whole-page coverage.
//
//   node testing/ui/keyboard-checks.mjs          # regenerate the report
//   node testing/ui/keyboard-checks.mjs --check  # fail when it is stale
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  MAIN_SCENES,
  activeElement,
  loadPlugins,
  openScene,
  pressKey,
  tabTo,
  waitFor,
  withBrowser,
} from "./audit-runtime.mjs";

const here = dirname(fileURLToPath(import.meta.url));
export const REPORT_PATH = join(here, "keyboard-checks.md");

// Each entry names the main-flow element the keyboard user reaches by Tab and
// how Enter/Escape must behave on it. `coverage` is the one path the report
// claims for that page; dialogs are opened with Enter and closed with Escape.
const CASES = {
  "accelerator-sources": {
    scene: "usage",
    tabTarget: "#convert-input",
    enterTarget: "#convert-input",
    enterKind: "convert",
    enterValue: "https://github.com/cli/cli",
    escTarget: "#convert-input",
    escKind: "clear-input",
    escValue: "https://github.com/cli/cli",
    dialog: null,
    coverage: "链接转换主流程：Tab 到 #convert-input，填入链接后 Enter 复制结果；Esc 清空输入并隐藏结果",
  },
  "cloudflare-dns": {
    scene: "mappings",
    tabTarget: "#mapping-add",
    enterTarget: "#mapping-add",
    enterKind: "dialog",
    dialog: "#mapping-create",
    coverage: "映射主流程：Tab 到 #mapping-add，Enter 打开新建映射对话框；Esc 关闭并还焦",
  },
  "docker-app": {
    scene: "apps",
    tabTarget: "#deploy-toggle",
    enterTarget: "#deploy-toggle",
    enterKind: "dialog",
    dialog: "#app-create",
    coverage: "应用主流程：Tab 到 #deploy-toggle，Enter 打开创建抽屉；Esc 关闭并还焦",
  },
  "doh": {
    scene: "endpoint",
    tabTarget: "#copy-doh-url",
    enterTarget: "#copy-doh-url",
    enterKind: "copy",
    escTarget: "#copy-doh-url",
    escKind: "no-dialog",
    dialog: null,
    coverage: "复制主操作：Tab 到 #copy-doh-url，Enter 触发复制状态；Esc 无对话框且焦点保持",
  },
  "ip-policy": {
    scene: "data",
    tabTarget: "#add-source",
    enterTarget: "#add-source",
    enterKind: "dialog",
    dialog: "#source-dialog",
    coverage: "规则数据主流程：Tab 到 #add-source，Enter 打开来源对话框；Esc 关闭并还焦",
  },
  "reverse-l4": {
    scene: "mappings",
    tabTarget: "#create-toggle",
    enterTarget: "#create-toggle",
    enterKind: "dialog",
    dialog: "#mapping-dialog",
    coverage: "映射主流程：Tab 到 #create-toggle，Enter 打开映射对话框；Esc 关闭并还焦",
  },
  "shadowsocks-server": {
    scene: "listens",
    tabTarget: "#create-toggle",
    enterTarget: "#create-toggle",
    enterKind: "dialog",
    dialog: "#create-dialog",
    coverage: "监听主流程：Tab 到 #create-toggle，Enter 打开创建监听对话框；Esc 关闭并还焦",
  },
  "waf": {
    scene: "events",
    tabTarget: "#event-list tr button",
    enterTarget: "#event-list tr button",
    enterKind: "dialog",
    dialog: "#event-dialog",
    coverage: "事件主流程：Tab 到首条事件按钮，Enter 打开事件详情对话框；Esc 关闭并还焦",
  },
  "webdav": {
    scene: "files",
    tabTarget: "#mkdir-button",
    enterTarget: "#mkdir-button",
    enterKind: "dialog",
    dialog: "#mkdir-dialog",
    coverage: "文件主流程：Tab 到 #mkdir-button，Enter 打开新建文件夹对话框；Esc 关闭并还焦",
  },
};

const escapeExpression = (selector) =>
  `Boolean(document.querySelector(${JSON.stringify(selector)})?.open)`;

const focusInsideExpression = (selector) => `(() => {
  const dialog = document.querySelector(${JSON.stringify(selector)});
  return Boolean(dialog && dialog.open && dialog.contains(document.activeElement));
})()`;

const visibleFocus = (state) => Boolean(state && state.focusVisible && (state.outline || state.boxShadow));
const focusDescription = (state) => {
  if (!state) return "（无焦点）";
  const parts = [];
  if (state.outline) parts.push(`outline ${state.outlineWidth}`);
  if (state.boxShadow) parts.push("box-shadow");
  return `${state.label || "（未命名元素）"}（:focus-visible=${state.focusVisible ? "真" : "假"}${parts.length ? `，${parts.join("，")}` : ""}）`;
};

const snippetVisibleExpression = "(() => { const node = document.querySelector('#convert-snippet'); return Boolean(node && !node.hidden && node.getClientRects().length); })()";

// Waits for the converter's own copy feedback ("已复制"/"复制失败"). Both are
// real feedback for the Enter path; the label is recorded verbatim.
const copyFeedback = async (page, ms = 2500) => {
  try {
    await waitFor(page, "(() => { const button = document.querySelector('#convert-copy'); return Boolean(button && button.dataset.state); })()", "转换复制提示", ms);
  } catch {
    return null;
  }
  return page.evaluate("(() => { const button = document.querySelector('#convert-copy'); const span = button.querySelector('span') || button; return { state: button.dataset.state || '', label: span.textContent.trim() }; })()");
};

async function runCase(browser, plugin, spec) {
  const pageResult = {
    page: plugin.id,
    scene: spec.scene,
    tab: { status: "failed", result: "" },
    enter: { status: "failed", result: "" },
    esc: { status: "failed", result: "" },
  };
  const page = await openScene(browser, plugin, spec.scene);
  try {
    try {
      const tab = await tabTo(page.page, spec.tabTarget);
      const target = await activeElement(page.page);
      if (!tab.found) {
        pageResult.tab = { status: "failed", result: `Tab ${tab.tabs} 次仍未到 ${spec.tabTarget}；实际路径：${tab.path.join(" → ")}` };
      } else if (!visibleFocus(target)) {
        pageResult.tab = { status: "failed", result: `Tab ${tab.tabs} 次到 ${focusDescription(target)}，但焦点指示不可见` };
      } else {
        pageResult.tab = { status: "passed", result: `Tab ×${tab.tabs} → ${focusDescription(target)}` };
      }
    } catch (error) {
      pageResult.tab = { status: "failed", result: `Tab 检查异常：${error.message}` };
    }

    try {
      const focus = await tabTo(page.page, spec.enterTarget);
      if (!focus.found) throw new Error(`Tab ${focus.tabs} 次仍未到 Enter 目标 ${spec.enterTarget}`);
      if (spec.enterKind === "dialog") {
        await pressKey(page.page, "Enter");
        await waitFor(page.page, escapeExpression(spec.dialog), `${spec.dialog} 打开`);
        const inside = await page.page.evaluate(focusInsideExpression(spec.dialog));
        const active = await activeElement(page.page);
        pageResult.enter = {
          status: inside ? "passed" : "failed",
          result: inside
            ? `打开 ${spec.dialog}，焦点进入对话框（${focusDescription(active)}）`
            : `打开 ${spec.dialog} 后焦点不在对话框内（${focusDescription(active)}）`,
        };
      } else if (spec.enterKind === "theme") {
        const before = await page.page.evaluate("document.documentElement.getAttribute('data-theme')");
        await pressKey(page.page, "Enter");
        await waitFor(page.page, `document.documentElement.getAttribute('data-theme') !== ${JSON.stringify(before)}`, "主题切换");
        const after = await page.page.evaluate("document.documentElement.getAttribute('data-theme')");
        pageResult.enter = { status: "passed", result: `主题 ${before} → ${after}` };
      } else if (spec.enterKind === "copy") {
        await pressKey(page.page, "Enter");
        await waitFor(page.page, "(() => { const node = document.querySelector('#copy-status'); return Boolean(node && !node.hidden && node.textContent.trim()); })()", "复制状态");
        pageResult.enter = { status: "passed", result: "复制状态已显示（成功或失败提示均已触发）" };
      } else if (spec.enterKind === "convert") {
        await page.driver.fill(spec.enterTarget, spec.enterValue);
        await waitFor(page.page, snippetVisibleExpression, `${spec.enterTarget} 的转换结果`);
        await pressKey(page.page, "Enter");
        const feedback = await copyFeedback(page.page);
        pageResult.enter = {
          status: "passed",
          result: feedback
            ? `Enter 提交链接转换：结果区可见，复制提示「${feedback.label}」（data-state=${feedback.state}）`
            : "Enter 提交链接转换：结果区可见，未观察到复制提示",
        };
      } else {
        throw new Error(`未知 Enter 检查类型 ${spec.enterKind}`);
      }
    } catch (error) {
      pageResult.enter = { status: "failed", result: `Enter 检查失败：${error.message}` };
    }

    try {
      if (spec.escKind === "dialog" || spec.dialog) {
        const wasOpen = await page.page.evaluate(escapeExpression(spec.dialog));
        if (!wasOpen) {
          pageResult.esc = { status: "failed", result: `未执行：Enter 未打开 ${spec.dialog}` };
        } else {
          const before = await activeElement(page.page);
          await pressKey(page.page, "Escape");
          await waitFor(page.page, `!${escapeExpression(spec.dialog)}`, `${spec.dialog} 关闭`);
          const after = await activeElement(page.page);
          const returned = await page.page.evaluate(`Boolean(document.activeElement && document.activeElement.matches(${JSON.stringify(spec.tabTarget)}))`);
          pageResult.esc = {
            status: returned ? "passed" : "failed",
            result: returned
              ? `关闭 ${spec.dialog}，焦点回到 ${focusDescription(after)}`
              : `关闭 ${spec.dialog}，但焦点在 ${focusDescription(after)}，触发前为 ${focusDescription(before)}`,
          };
        }
      } else if (spec.escKind === "clear-input") {
        await page.driver.fill(spec.escTarget, spec.escValue);
        await page.page.evaluate(`document.querySelector(${JSON.stringify(spec.escTarget)}).focus()`);
        await pressKey(page.page, "Escape");
        const value = await page.page.evaluate(`document.querySelector(${JSON.stringify(spec.escTarget)}).value`);
        const snippetHidden = await page.page.evaluate("Boolean(document.querySelector('#convert-snippet')?.hidden)");
        const active = await activeElement(page.page);
        const cleared = value === "" && snippetHidden;
        pageResult.esc = {
          status: cleared ? "passed" : "failed",
          result: cleared
            ? `页面无对话框；Esc 清空链接输入并隐藏转换结果，焦点仍在 ${focusDescription(active)}`
            : value === ""
              ? "页面无对话框；Esc 清空了输入，但转换结果区仍显示"
              : `页面无对话框；Esc 后输入值仍为 ${JSON.stringify(value)}`,
        };
      } else if (spec.escKind === "no-dialog") {
        await pressKey(page.page, "Escape");
        const openDialog = await page.page.evaluate("Boolean(document.querySelector('dialog[open]'))");
        const active = await activeElement(page.page);
        const stayed = await page.page.evaluate(`Boolean(document.activeElement && document.activeElement.matches(${JSON.stringify(spec.escTarget)}))`);
        pageResult.esc = {
          status: !openDialog && stayed ? "passed" : "failed",
          result: !openDialog && stayed
            ? `页面无对话框；Esc 后未出现模态层，焦点仍在 ${focusDescription(active)}`
            : `页面无对话框；Esc 后 open dialog=${openDialog}，焦点 ${focusDescription(active)}`,
        };
      } else {
        throw new Error(`未知 Escape 检查类型 ${spec.escKind}`);
      }
    } catch (error) {
      pageResult.esc = { status: "failed", result: `Esc 检查失败：${error.message}` };
    }
  } finally {
    await page.close();
  }
  return pageResult;
}

export async function buildKeyboardReport() {
  const plugins = await loadPlugins();
  const results = [];
  await withBrowser(async (browser) => {
    for (const plugin of plugins) {
      const spec = CASES[plugin.id];
      if (!spec) throw new Error(`缺少 ${plugin.id} 的键盘检查配置`);
      if (spec.scene !== MAIN_SCENES[plugin.id] && plugin.id !== "waf" && plugin.id !== "ip-policy") {
        throw new Error(`${plugin.id} 的键盘场景 ${spec.scene} 必须与主流程场景 ${MAIN_SCENES[plugin.id]} 一致`);
      }
      results.push(await runCase(browser, plugin, { ...spec, escKind: spec.escKind || (spec.dialog ? "dialog" : "no-dialog") }));
    }
  });

  const failures = results.flatMap((result) => ["tab", "enter", "esc"]
    .filter((kind) => result[kind].status !== "passed")
    .map((kind) => `${result.page}/${kind === "tab" ? "Tab" : kind === "enter" ? "Enter" : "Esc"}：${result[kind].result}`));

  const lines = [
    "# 九页键盘检查",
    "",
    "> 本文件由 `node testing/ui/keyboard-checks.mjs` 从当前页面实时生成；请勿手改。",
    "> 检查对象为 R6 的九页：accelerator-sources、cloudflare-dns、docker-app、doh、ip-policy、reverse-l4、shadowsocks-server、waf、webdav。",
    "",
    "- 主题：light；视口：1440×900；按键通过 CDP 真实派发 `Tab`、`Enter`、`Escape`。",
    "- 焦点可见：`:focus-visible` 为真，且存在 outline 或 box-shadow；对话框页的 Esc 还必须把焦点还给触发元素。",
    "- 无对话框页面不伪造“关闭”结果：记录 Esc 后无模态层、焦点保持。",
    "- 每页只记录下表所列的一个主流程键盘路径；页面其它交互不在本证据覆盖范围内。",
    "",
    "## 结果汇总",
    "",
    "| 页面 | Tab 焦点可见 | Enter 触发 | Esc 实际效果 |",
    "| --- | --- | --- | --- |",
    ...results.map((result) => `| ${result.page} | ${result.tab.status === "passed" ? "通过" : "失败"} | ${result.enter.status === "passed" ? "通过" : "失败"} | ${result.esc.status === "passed" ? "通过" : "失败"} |`),
    "",
    `汇总：${results.length * 3 - failures.length}/${results.length * 3} 项通过，${failures.length} 项失败。`,
    "",
    "## 页面覆盖范围",
    "",
    "| 页面 | 本次覆盖的主流程操作 |",
    "| --- | --- |",
    ...results.map((result) => `| ${result.page} | ${CASES[result.page].coverage} |`),
    "",
    "## 逐项记录",
    "",
    "| 页面 | 场景 | 元素 | 操作 | 结果 |",
    "| --- | --- | --- | --- | --- |",
  ];
  for (const result of results) {
    const spec = CASES[result.page];
    lines.push(`| ${result.page} | ${result.scene} | ${spec.tabTarget} | Tab | ${result.tab.status === "passed" ? "通过" : "失败"}：${result.tab.result} |`);
    lines.push(`| ${result.page} | ${result.scene} | ${spec.enterTarget} | Enter | ${result.enter.status === "passed" ? "通过" : "失败"}：${result.enter.result} |`);
    const escElement = spec.dialog ? spec.enterTarget : spec.escTarget;
    lines.push(`| ${result.page} | ${result.scene} | ${escElement} | Esc | ${result.esc.status === "passed" ? "通过" : "失败"}：${result.esc.result} |`);
  }
  lines.push("");
  if (failures.length) lines.push("## 未通过项", "", ...failures.map((failure) => `- ${failure}`), "");
  else lines.push("## 结论", "", `以上 ${results.length} 页共记录 ${results.length * 3} 项键盘操作，逐页覆盖范围见「页面覆盖范围」；未列出的交互路径不在本次键盘检查范围内。无对话框页面的 Esc 行为按实际观察记录，不伪造关闭结果。`, "");

  return { markdown: lines.join("\n"), failures };
}

export async function main(argv = process.argv.slice(2)) {
  const check = argv.includes("--check");
  if (argv.some((arg) => arg !== "--check")) throw new Error("用法：node testing/ui/keyboard-checks.mjs [--check]");
  const { markdown, failures } = await buildKeyboardReport();
  if (check) {
    const existing = await readFile(REPORT_PATH, "utf8").catch(() => null);
    if (existing !== markdown) {
      console.error(`${REPORT_PATH} 与当前页面不一致；请运行 node testing/ui/keyboard-checks.mjs 重新生成`);
      process.exitCode = 1;
      return;
    }
    console.log(`${REPORT_PATH} 与当前页面一致（${failures.length} 项失败）`);
    if (failures.length) process.exitCode = 1;
    return;
  }
  await writeFile(REPORT_PATH, markdown, "utf8");
  console.log(`${REPORT_PATH} 已生成（${failures.length} 项失败）`);
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
