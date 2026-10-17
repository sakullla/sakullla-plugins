import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { createServer } from "node:http";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { deflateSync } from "node:zlib";
import { buildGallery, manifestName } from "./gallery.mjs";
import {
  HOST_THEMES,
  expandThemes,
  parseArgs,
  resolveTheme,
  themeIssues,
  themeKeyForPlugin,
  themeModeForPlugin,
  viewportHeight,
} from "./capture.mjs";

const repo = fileURLToPath(new URL("../..", import.meta.url));
const scenes = ["usage", "convert-github", "convert-repo", "convert-docker", "convert-unsupported", "mirrors", "mirrors-loading", "mirrors-browse", "mirrors-ready", "mirrors-error"];

const runCli = (args, cwd = repo) => spawnSync(process.execPath, ["testing/ui/capture.mjs", ...args], {
  cwd,
  encoding: "utf8",
  timeout: 30000,
});

const outputOf = (run) => `${run.stdout || ""}\n${run.stderr || ""}`;

function galleryDom(html) {
  const attributes = (source) => Object.fromEntries([...source.matchAll(/\bdata-([a-z]+)=\"([^\"]*)\"/g)].map((item) => [item[1], item[2]]));
  const figures = [...html.matchAll(/<figure\b([^>]*)>/g)].map((match) => ({
    dataset: attributes(match[1]),
    hidden: false,
  }));
  const groups = [...html.matchAll(/<section\b([^>]*)>/g)].flatMap((match) => {
    if (!/\bdata-group=/.test(match[1])) return [];
    return [{ dataset: attributes(match[1]), hidden: false }];
  });
  const links = [...html.matchAll(/<a\b([^>]*)>/g)].flatMap((match) => {
    if (!/\bclass="view"/.test(match[1])) return [];
    const listeners = {};
    const href = match[1].match(/\bhref=\"([^\"]*)\"/)?.[1] ?? "";
    const alt = match[1].match(/\bdata-alt=\"([^\"]*)\"/)?.[1] ?? "";
    return [{
      dataset: { alt },
      listeners,
      getAttribute: (name) => (name === "href" ? href : ""),
      addEventListener(type, fn) { listeners[type] = fn; },
    }];
  });
  const values = { plugin: "", scene: "", theme: "", width: "", query: "" };
  const listeners = {};
  const formListeners = {};
  const button = () => {
    const buttonListeners = {};
    return { listeners: buttonListeners, addEventListener(type, fn) { buttonListeners[type] = fn; } };
  };
  const nodes = {
    count: { textContent: "" },
    empty: { hidden: true },
    filters: { addEventListener(type, fn) { formListeners[type] = fn; } },
    viewer: { hidden: true, scrollTop: 0 },
    "viewer-image": { alt: "", setAttribute(name, value) { this[name] = value; } },
    "viewer-close": button(),
    "viewer-close-end": button(),
  };
  for (const id of Object.keys(values)) {
    nodes[id] = {
      get value() { return values[id]; },
      set value(next) { values[id] = next; },
      addEventListener(type, fn) { listeners[`${id}:${type}`] = fn; },
    };
  }
  const documentShim = {
    getElementById: (id) => nodes[id],
    querySelectorAll: (selector) => {
      if (selector === "figure") return figures;
      if (selector === "section[data-group]") return groups;
      if (selector === "a.view") return links;
      return [];
    },
  };
  const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  new Function("document", script)(documentShim);
  return {
    figures,
    groups,
    links,
    nodes,
    visible: () => figures.filter((figure) => !figure.hidden),
    set(id, value) {
      values[id] = value;
      listeners[`${id}:input`]();
    },
    async reset() {
      for (const id of Object.keys(values)) values[id] = "";
      formListeners.reset();
      await new Promise((resolve) => setTimeout(resolve, 0));
    },
  };
}

test("lists accelerator-sources scenes and does not write a gallery", async () => {
  const out = await mkdtemp(join(tmpdir(), "nre-ui-list-"));
  try {
    const run = runCli(["--list", "--out", out]);
    assert.equal(run.status, 0, outputOf(run));
    for (const scene of ["accelerator-sources", ...scenes]) assert.match(run.stdout, new RegExp(scene));
    assert.equal(run.stdout.includes("rate-limit"), false);
    assert.equal(existsSync(join(out, "index.html")), false);
    assert.equal(existsSync(join(out, manifestName)), false);
  } finally {
    await rm(out, { recursive: true, force: true });
  }
});

test("list filters scenes with globs", () => {
  const usageOnly = runCli(["--list", "--only", "usage"]);
  assert.equal(usageOnly.status, 0, outputOf(usageOnly));
  assert.match(usageOnly.stdout, /usage/);
  assert.equal(usageOnly.stdout.includes("mirrors-browse"), false);

  const mirrors = runCli(["--list", "--plugin", "accelerator-sources", "--only", "mirrors-*"]);
  assert.equal(mirrors.status, 0, outputOf(mirrors));
  for (const scene of ["mirrors-loading", "mirrors-browse", "mirrors-ready", "mirrors-error"]) assert.match(mirrors.stdout, new RegExp(scene));
  assert.equal(mirrors.stdout.includes("\n  usage"), false);
});

test("theme values expand aliases and host ids, and map the two theme authorities", () => {
  assert.deepEqual(expandThemes("all"), ["light", "dark"]);
  assert.deepEqual(expandThemes("host"), HOST_THEMES);
  assert.deepEqual(expandThemes("dark, light, dark"), ["dark", "light"]);
  assert.deepEqual(expandThemes("fresh-green"), ["fresh-green"]);
  assert.throws(() => expandThemes("blue"), /未知主题 blue。可用主题：all、light、dark、host、fresh-green/);
  assert.deepEqual(parseArgs(["--theme", "host,sakura-day"]).themes, HOST_THEMES);
  assert.deepEqual(parseArgs([]).themes, ["light", "dark"]);
  assert.equal(resolveTheme("sakura-night", "host"), "sakura-night");
  assert.equal(resolveTheme("sakura-night", "standalone"), "dark");
  assert.equal(resolveTheme("fresh-green", "standalone"), "light");
  assert.equal(themeModeForPlugin("waf"), "host");
  assert.equal(themeModeForPlugin("doh"), "standalone");
  assert.equal(themeModeForPlugin("waf", { themeMode: "standalone" }), "standalone");
  assert.equal(themeKeyForPlugin("waf", "host"), "theme");
  assert.equal(themeKeyForPlugin("accelerator-sources", "standalone"), "accelerator-sources.theme");
  assert.equal(themeKeyForPlugin("doh", "standalone"), "doh.theme");
  assert.deepEqual(themeIssues({ theme: "dark", family: "dark", mode: "standalone", key: "doh.theme" }, "sakura-night", "standalone", "doh.theme"), []);
  assert.match(themeIssues({ theme: "light", mode: "standalone" }, "dark", "standalone", "doh.theme").join("\n"), /主题解析不符/);
  assert.match(themeIssues({ theme: "dark", mode: "host" }, "dark", "standalone", "doh.theme").join("\n"), /主题模式不符/);
});

test("unknown plugin, theme, width, and scene fail with available values and do not pass", async () => {
  const out = await mkdtemp(join(tmpdir(), "nre-ui-bad-"));
  try {
    const missing = runCli(["--plugin", "missing", "--out", out]);
    assert.notEqual(missing.status, 0);
    assert.match(outputOf(missing), /accelerator-sources/);
    assert.match(outputOf(missing), /可用插件/);
    assert.equal(existsSync(join(out, manifestName)), false);
    assert.equal(outputOf(missing).includes("本次结果：通过"), false);

    const theme = runCli(["--theme", "blue", "--out", out]);
    assert.notEqual(theme.status, 0);
    assert.match(outputOf(theme), /light/);
    assert.match(outputOf(theme), /dark/);
    assert.match(outputOf(theme), /可用主题/);
    for (const name of ["host", ...HOST_THEMES]) assert.match(outputOf(theme), new RegExp(name));
    assert.equal(existsSync(join(out, "index.html")), false);

    const width = runCli(["--size", "10", "--list"]);
    assert.notEqual(width.status, 0);
    assert.match(outputOf(width), /1440/);
    assert.match(outputOf(width), /390/);

    const scene = runCli(["--only", "nope"]);
    assert.notEqual(scene.status, 0);
    assert.match(outputOf(scene), /usage/);
    assert.match(outputOf(scene), /可用场景/);

    const removed = runCli(["--scenes", "usage"]);
    assert.notEqual(removed.status, 0);
    assert.match(outputOf(removed), /未知参数/);
  } finally {
    await rm(out, { recursive: true, force: true });
  }
});

test("old accelerator capture entry is gone and the readme points at the shared command", async () => {
  assert.equal(existsSync(join(repo, "plugins/accelerator-sources/testing/ui/capture.mjs")), false);
  assert.equal(existsSync(join(repo, "plugins/accelerator-sources/testing/ui/browser.mjs")), false);
  assert.equal(existsSync(join(repo, "plugins/accelerator-sources/testing/ui/mock.mjs")), false);
  const readme = await readFile(join(repo, "plugins/accelerator-sources/README.md"), "utf8");
  assert.match(readme, /node testing\/ui\/capture\.mjs/);
  assert.match(readme, /already displayed below the first screen/);
  assert.equal(readme.includes("plugins/accelerator-sources/testing/ui/capture.mjs"), false);
  const agents = await readFile(join(repo, "AGENTS.md"), "utf8");
  assert.match(agents, /already displayed below the first screen/);
  const plugin = await import(pathToFileURL(join(repo, "plugins/accelerator-sources/testing/ui/capture-plugin.mjs")).href);
  assert.equal(plugin.id, "accelerator-sources");
  assert.deepEqual(plugin.scenes.map((scene) => scene.name), scenes);
  assert.equal(plugin.scenes.find((scene) => scene.name === "mirrors-loading").settle, false);
});

test("gallery filters by plugin, scene, theme, width, and keyword", async () => {
  const report = {
    capturedAt: "2026-10-17T00:00:00.000Z",
    invocation: "node testing/ui/capture.mjs --theme all --size 390,1440",
    themes: ["light", "dark"],
    widths: [390, 1440],
    selected: [
      { plugin: "accelerator-sources", scenes: ["usage", "mirrors"] },
      { plugin: "demo-plugin", scenes: ["usage"] },
    ],
    missing: [],
    success: false,
    imageCount: 3,
    failureCount: 1,
    captures: [
      { plugin: "accelerator-sources", scene: "usage", title: "用法首页", theme: "dark", width: 390, height: 900, file: "accelerator-sources/usage-dark-390.png", issues: ["横向溢出：main"] },
      { plugin: "accelerator-sources", scene: "mirrors", title: "镜像工作台", theme: "light", width: 1440, height: 900, file: "accelerator-sources/mirrors-light-1440.png", issues: [] },
      { plugin: "demo-plugin", scene: "usage", title: "示例", theme: "dark", width: 390, height: 900, file: "demo-plugin/usage-dark-390.png", issues: [] },
    ],
    failures: [{ plugin: "accelerator-sources", scene: "usage", theme: "dark", width: 390, issues: ["横向溢出：main"] }],
  };
  const built = buildGallery(report);
  assert.match(built.html, /本次结果：有失败/);
  assert.equal(built.html.includes("本次结果：通过"), false);
  for (const label of ["插件", "场景", "主题", "宽度", "关键词", "重置", "没有匹配的图片"]) assert.match(built.html, new RegExp(label));
  assert.match(built.readme, /index\.html/);
  assert.match(built.readme, new RegExp(manifestName));
  assert.match(built.readme, /node testing\/ui\/capture\.mjs/);
  assert.match(built.readme, /3 张图片，1 项失败/);
  const manifest = JSON.parse(built.manifest);
  assert.equal(manifest.success, false);
  assert.equal(manifest.captures[0].file, "accelerator-sources/usage-dark-390.png");
  assert.equal(manifest.failures[0].issues[0].includes("横向溢出"), true);

  const dom = galleryDom(built.html);
  assert.equal(dom.visible().length, 3);
  dom.set("plugin", "demo-plugin");
  assert.deepEqual(dom.visible().map((card) => card.dataset.plugin), ["demo-plugin"]);
  await dom.reset();
  dom.set("scene", "mirrors");
  assert.equal(dom.visible().length, 1);
  assert.equal(dom.visible()[0].dataset.scene, "mirrors");
  await dom.reset();
  dom.set("theme", "light");
  assert.equal(dom.visible().length, 1);
  await dom.reset();
  dom.set("width", "1440");
  assert.equal(dom.visible().length, 1);
  await dom.reset();
  dom.set("query", "用法");
  assert.equal(dom.visible().length, 1);
  dom.set("query", "USAGE");
  assert.equal(dom.visible().length, 2);
  dom.set("plugin", "accelerator-sources");
  dom.set("scene", "mirrors");
  assert.equal(dom.visible().length, 0);
  assert.equal(dom.nodes.empty.hidden, false);
  await dom.reset();
  assert.equal(dom.visible().length, 3);
  assert.equal(dom.nodes.empty.hidden, true);
});


test("gallery filters host themes recorded in the manifest", async () => {
  const capture = (theme, family) => ({
    plugin: "waf",
    scene: "overview",
    title: "概览",
    theme,
    themeMode: "host",
    themeKey: "theme",
    expectedTheme: theme,
    resolvedTheme: theme,
    themeFamily: family,
    width: 1440,
    height: 900,
    file: `waf/overview-${theme}-1440.png`,
    issues: [],
  });
  const report = {
    capturedAt: "2026-10-17T00:00:00.000Z",
    invocation: "node testing/ui/capture.mjs --plugin waf --theme host --size 1440",
    themes: ["fresh-green", "sakura-day", "sakura-night", "neko-dark", "business"],
    widths: [1440],
    selected: [{ plugin: "waf", scenes: ["overview"] }],
    missing: [],
    success: true,
    imageCount: 5,
    failureCount: 0,
    captures: [
      capture("fresh-green", "light"),
      capture("sakura-day", "light"),
      capture("sakura-night", "dark"),
      capture("neko-dark", "dark"),
      capture("business", "light"),
    ],
    failures: [],
  };
  const built = buildGallery(report);
  assert.match(built.html, /清新绿/);
  assert.match(built.html, /夜樱/);
  assert.match(built.html, /猫夜/);
  assert.match(built.html, /商务/);
  const manifest = JSON.parse(built.manifest);
  assert.deepEqual(manifest.themes, report.themes);
  assert.equal(manifest.captures[0].themeMode, "host");
  assert.equal(manifest.captures[0].resolvedTheme, "fresh-green");
  assert.equal(manifest.captures[2].themeFamily, "dark");
  const dom = galleryDom(built.html);
  assert.equal(dom.visible().length, 5);
  dom.set("theme", "fresh-green");
  assert.deepEqual(dom.visible().map((card) => card.dataset.theme), ["fresh-green"]);
  await dom.reset();
  dom.set("theme", "neko-dark");
  assert.deepEqual(dom.visible().map((card) => card.dataset.theme), ["neko-dark"]);
  await dom.reset();
  dom.set("plugin", "waf");
  dom.set("width", "1440");
  assert.equal(dom.visible().length, 5);
});

test("groups scene variants with failures first and opens the full image", async () => {
  const capture = (plugin, scene, title, theme, width, issues = [], file = `${plugin}/${scene}-${theme}-${width}.png`) => ({
    plugin, scene, title, theme, width, height: 1400, file, issues,
  });
  const report = {
    capturedAt: "2026-10-17T00:00:00.000Z",
    invocation: "node testing/ui/capture.mjs --theme all --size 390,1440",
    themes: ["light", "dark"],
    widths: [390, 1440],
    selected: [
      { plugin: "alpha", scenes: ["pass", "fail"] },
      { plugin: "beta", scenes: ["empty", "later"] },
    ],
    missing: [
      { plugin: "beta", scene: "empty", theme: "light", width: 390 },
      { plugin: "beta", scene: "empty", theme: "light", width: 1440 },
      { plugin: "beta", scene: "empty", theme: "dark", width: 390 },
      { plugin: "beta", scene: "empty", theme: "dark", width: 1440 },
      { plugin: "beta", scene: "later", theme: "dark", width: 1440 },
    ],
    success: false,
    imageCount: 11,
    failureCount: 6,
    captures: [
      capture("alpha", "pass", "通过场景", "dark", 1440),
      capture("alpha", "pass", "通过场景", "light", 1440),
      capture("alpha", "pass", "通过场景", "dark", 390),
      capture("alpha", "pass", "通过场景", "light", 390),
      capture("alpha", "fail", "失败场景", "dark", 1440, ["横向溢出：main"]),
      capture("alpha", "fail", "失败场景", "light", 1440),
      capture("alpha", "fail", "失败场景", "dark", 390),
      capture("alpha", "fail", "失败场景", "light", 390),
      { plugin: "beta", scene: "empty", title: "没有图片", theme: "dark", width: 1440, height: 900, file: null, issues: ["场景失败：预览启动失败：x"] },
      { plugin: "beta", scene: "empty", title: "没有图片", theme: "light", width: 1440, height: 900, file: null, issues: ["场景失败：预览启动失败：x"] },
      { plugin: "beta", scene: "empty", title: "没有图片", theme: "dark", width: 390, height: 900, file: null, issues: ["场景失败：预览启动失败：x"] },
      { plugin: "beta", scene: "empty", title: "没有图片", theme: "light", width: 390, height: 900, file: null, issues: ["场景失败：预览启动失败：x"] },
      capture("beta", "later", "靠后场景", "dark", 390),
      capture("beta", "later", "靠后场景", "light", 1440),
      capture("beta", "later", "靠后场景", "light", 390),
    ],
    failures: [{ plugin: "alpha", scene: "fail", theme: "dark", width: 1440, issues: ["横向溢出：main"] }],
  };
  const built = buildGallery(report);
  assert.match(built.html, /本次结果：有失败。11 张图片，6 项失败。/);
  assert.equal(built.html.includes("本次结果：通过"), false);
  for (const label of ["插件", "场景", "主题", "宽度", "关键词", "重置", "没有匹配的图片"]) assert.match(built.html, new RegExp(label));
  assert.match(built.html, /href="index\.html"/);
  assert.match(built.html, /href="README\.md"/);
  assert.match(built.html, new RegExp(`href="${manifestName}"`));
  assert.equal(built.html.includes("target=\"_blank\""), false);
  for (const word of ["标注", "评论", "对比", "历史", "baseline"]) {
    assert.equal(built.html.includes(word), false, word);
    assert.equal(built.readme.includes(word), false, word);
  }
  const viewerRule = built.html.match(/#viewer img\{([^}]*)\}/)[1];
  assert.match(viewerRule, /width:100%/);
  assert.match(viewerRule, /height:auto/);
  assert.equal(viewerRule.includes("320px"), false);
  assert.match(built.html.match(/#viewer\{([^}]*)\}/)[1], /overflow:auto/);
  assert.match(built.html, /figure img\{[^}]*height:320px/);
  assert.match(built.html, /id="viewer-close"/);
  assert.match(built.html, /id="viewer-close-end"/);

  const section = (scene) => {
    const found = built.html.match(new RegExp(`<section\\b(?=[^>]*data-scene="${scene}")[^>]*>[\\s\\S]*?<\\/section>`));
    assert.ok(found, scene);
    return found[0];
  };
  const failSection = section("fail");
  assert.match(failSection, /横向溢出：main/);
  assert.equal(failSection.includes("通过"), false);
  assert.deepEqual([...failSection.matchAll(/data-theme="([^"]+)"/g)].map((item) => item[1]), ["light", "light", "dark", "dark"]);
  assert.deepEqual([...failSection.matchAll(/data-width="([^"]+)"/g)].map((item) => item[1]), ["390", "1440", "390", "1440"]);
  const figuresIn = (source) => [...source.matchAll(/<figure\b[\s\S]*?<\/figure>/g)].map((item) => item[0]);
  const emptySection = section("empty");
  assert.match(emptySection, /场景失败：预览启动失败：x/);
  assert.match(emptySection, /缺少图片/);
  assert.equal(emptySection.includes("通过"), false);
  assert.deepEqual([...emptySection.matchAll(/data-theme="([^"]+)"/g)].map((item) => item[1]), ["light", "light", "dark", "dark"]);
  assert.deepEqual([...emptySection.matchAll(/data-width="([^"]+)"/g)].map((item) => item[1]), ["390", "1440", "390", "1440"]);
  const emptyFigures = figuresIn(emptySection);
  assert.equal(emptyFigures.length, 4);
  for (const card of emptyFigures) {
    assert.match(card, /class="bad"/);
    assert.match(card, /data-keywords="[^"]*empty[^"]*没有图片/);
    assert.match(card, /场景失败：预览启动失败：x/);
    assert.match(card, /缺少图片/);
    assert.equal(card.includes("<img"), false);
    assert.equal(card.includes('class="view"'), false);
  }
  const laterSection = section("later");
  assert.match(laterSection, /缺少图片/);
  assert.equal(laterSection.includes("通过"), false);
  assert.deepEqual([...laterSection.matchAll(/data-theme="([^"]+)"/g)].map((item) => item[1]), ["light", "light", "dark", "dark"]);
  assert.deepEqual([...laterSection.matchAll(/data-width="([^"]+)"/g)].map((item) => item[1]), ["390", "1440", "390", "1440"]);
  const laterFigures = figuresIn(laterSection);
  assert.equal(laterFigures.length, 4);
  assert.match(laterFigures[0], /<img/);
  assert.equal(laterFigures[0].includes("缺少图片"), false);
  assert.match(laterFigures[3], /data-theme="dark"/);
  assert.match(laterFigures[3], /data-width="1440"/);
  assert.match(laterFigures[3], /缺少图片/);
  assert.match(laterFigures[3], /later · dark · 1440px/);
  assert.equal(laterFigures[3].includes("<img"), false);
  assert.equal(laterFigures[3].includes("dark-1440.png"), false);
  const failFigures = figuresIn(failSection);
  assert.match(failFigures[3], /<img[^>]*fail-dark-1440\.png/);
  assert.match(failFigures[3], /横向溢出：main/);
  assert.equal(failFigures[3].includes("缺少图片"), false);
  const passSection = section("pass");
  assert.equal(passSection.includes("缺少图片"), false);
  assert.equal(figuresIn(passSection).length, 4);

  const dom = galleryDom(built.html);
  assert.deepEqual(dom.groups.map((group) => `${group.dataset.plugin}:${group.dataset.scene}`), [
    "alpha:fail", "beta:empty", "beta:later", "alpha:pass",
  ]);
  assert.deepEqual(dom.figures.map((card) => `${card.dataset.plugin}:${card.dataset.scene}:${card.dataset.theme}:${card.dataset.width}`), [
    "alpha:fail:light:390", "alpha:fail:light:1440", "alpha:fail:dark:390", "alpha:fail:dark:1440",
    "beta:empty:light:390", "beta:empty:light:1440", "beta:empty:dark:390", "beta:empty:dark:1440",
    "beta:later:light:390", "beta:later:light:1440", "beta:later:dark:390", "beta:later:dark:1440",
    "alpha:pass:light:390", "alpha:pass:light:1440", "alpha:pass:dark:390", "alpha:pass:dark:1440",
  ]);
  assert.equal(dom.groups.every((group) => !group.hidden), true);
  assert.equal(dom.visible().length, 16);

  dom.set("theme", "dark");
  assert.deepEqual(dom.visible().map((card) => `${card.dataset.plugin}:${card.dataset.scene}:${card.dataset.width}`), [
    "alpha:fail:390", "alpha:fail:1440", "beta:empty:390", "beta:empty:1440", "beta:later:390", "beta:later:1440", "alpha:pass:390", "alpha:pass:1440",
  ]);
  assert.equal(dom.groups.find((group) => group.dataset.scene === "empty").hidden, false);
  assert.equal(dom.groups.find((group) => group.dataset.scene === "pass").hidden, false);
  assert.equal(dom.nodes.empty.hidden, true);
  await dom.reset();
  dom.set("theme", "light");
  assert.equal(dom.groups.find((group) => group.dataset.scene === "empty").hidden, false);
  assert.deepEqual(dom.visible().filter((card) => card.dataset.scene === "empty").map((card) => card.dataset.width), ["390", "1440"]);
  assert.equal(dom.visible().some((card) => card.dataset.scene === "empty" && card.dataset.theme === "dark"), false);
  assert.equal(dom.nodes.empty.hidden, true);
  await dom.reset();
  dom.set("width", "1440");
  assert.deepEqual(dom.visible().filter((card) => card.dataset.scene === "empty").map((card) => card.dataset.theme), ["light", "dark"]);
  assert.ok(dom.visible().some((card) => card.dataset.scene === "later" && card.dataset.theme === "dark" && card.dataset.width === "1440"));
  assert.equal(dom.nodes.empty.hidden, true);
  await dom.reset();
  dom.set("query", "靠后");
  assert.equal(dom.visible().length, 4);
  assert.deepEqual(dom.groups.filter((group) => !group.hidden).map((group) => group.dataset.scene), ["later"]);
  dom.set("query", "FAIL");
  assert.deepEqual([...new Set(dom.visible().map((card) => card.dataset.scene))], ["fail"]);
  dom.set("query", "没有图片");
  assert.deepEqual([...new Set(dom.visible().map((card) => card.dataset.scene))], ["empty"]);
  assert.equal(dom.nodes.empty.hidden, true);
  dom.set("query", "EMPTY");
  assert.deepEqual([...new Set(dom.visible().map((card) => card.dataset.scene))], ["empty"]);
  assert.equal(dom.groups.find((group) => group.dataset.scene === "empty").hidden, false);
  assert.equal(dom.nodes.empty.hidden, true);
  dom.set("query", "没有这个");
  assert.equal(dom.visible().length, 0);
  assert.equal(dom.nodes.empty.hidden, false);
  assert.equal(dom.groups.every((group) => group.hidden), true);
  await dom.reset();
  dom.set("scene", "empty");
  assert.equal(dom.visible().length, 4);
  assert.equal(dom.groups.find((group) => group.dataset.scene === "empty").hidden, false);
  assert.equal(dom.nodes.empty.hidden, true);
  await dom.reset();
  assert.equal(dom.visible().length, 16);
  assert.equal(dom.nodes.empty.hidden, true);

  const link = dom.links.find((item) => item.getAttribute("href") === "alpha/fail-light-390.png");
  let prevented = false;
  link.listeners.click({ preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  assert.equal(dom.nodes.viewer.hidden, false);
  assert.equal(dom.nodes.viewer.scrollTop, 0);
  assert.equal(dom.nodes["viewer-image"].src, "alpha/fail-light-390.png");
  assert.match(dom.nodes["viewer-image"].alt, /失败场景/);
  dom.nodes["viewer-close"].listeners.click();
  assert.equal(dom.nodes.viewer.hidden, true);
  link.listeners.click({ preventDefault() {} });
  dom.nodes["viewer-close-end"].listeners.click();
  assert.equal(dom.nodes.viewer.hidden, true);

  const readmeRows = built.readme.split("\n").filter((line) => line.startsWith("| alpha") || line.startsWith("| beta"));
  assert.deepEqual(readmeRows.map((line) => line.split("|")[2].trim()), [
    "失败场景（fail）", "没有图片（empty）", "靠后场景（later）", "通过场景（pass）",
  ]);
  assert.match(readmeRows[0], /横向溢出：main/);
  assert.match(readmeRows[1], /场景失败：预览启动失败：x；缺少图片/);
  assert.equal(readmeRows[1].includes("—"), false);
  assert.equal(readmeRows[1].includes(".png"), false);
  for (const variant of ["light 390", "light 1440", "dark 390", "dark 1440"]) {
    assert.match(readmeRows[1], new RegExp(`${variant}：场景失败：预览启动失败：x；缺少图片`));
  }
  assert.match(readmeRows[2], /缺少图片/);
  assert.match(readmeRows[2], /\[light 390\]\(beta\/later-light-390\.png\)/);
  assert.match(readmeRows[2], /\[dark 390\]\(beta\/later-dark-390\.png\)/);
  assert.match(readmeRows[2], /dark 1440：缺少图片/);
  assert.equal(readmeRows[2].includes("later-dark-1440.png"), false);
  assert.match(readmeRows[3], /\| 通过 \|/);
  assert.equal(readmeRows[3].includes("缺少图片"), false);
  assert.match(built.readme, /\[浏览画廊\]\(index\.html\)/);
  assert.match(built.readme, new RegExp(`\\[捕获清单\\]\\(${manifestName}\\)`));
  assert.match(built.readme, /node testing\/ui\/capture\.mjs --theme all --size 390,1440/);
  const manifest = JSON.parse(built.manifest);
  assert.equal(manifest.captures[0].file, "alpha/pass-dark-1440.png");
  assert.equal(manifest.captures.some((item) => item.scene === "empty" || !item.file), false);
  assert.equal(manifest.captures.filter((item) => item.scene === "later").length, 3);
  assert.equal(manifest.success, false);

  const passed = buildGallery({
    capturedAt: "2026-10-17T00:00:00.000Z",
    invocation: "node testing/ui/capture.mjs",
    themes: ["light"],
    widths: [390],
    selected: [{ plugin: "alpha", scenes: ["pass"] }],
    missing: [],
    success: true,
    imageCount: 1,
    failureCount: 0,
    captures: [capture("alpha", "pass", "通过场景", "light", 390)],
    failures: [],
  });
  assert.match(passed.html, /本次结果：通过。1 张图片，0 项失败。/);
  assert.equal(passed.html.includes("本次结果：有失败"), false);
  assert.match(passed.readme, /\| 通过 \|/);
  assert.equal(passed.html.includes("target=\"_blank\""), false);
});

const probePlugin = `import { createServer } from "node:http";

const pages = {
  "/home": "<!doctype html><html data-theme-mode=\\"standalone\\" data-theme-key=\\"layout-probe.theme\\"><head><meta charset=\\"utf-8\\"><script>const stored=localStorage.getItem('layout-probe.theme');const dark=stored==='dark'||stored==='sakura-night'||stored==='neko-dark';document.documentElement.setAttribute('data-theme',stored==='light'||stored==='dark'?stored:(dark?'dark':'light'));document.documentElement.setAttribute('data-theme-family',dark?'dark':'light');</script></head><body><p>home</p></body></html>",
  "/overflow": "<!doctype html><html data-theme-mode=\\"standalone\\" data-theme-key=\\"layout-probe.theme\\"><head><meta charset=\\"utf-8\\"><script>const stored=localStorage.getItem('layout-probe.theme');const dark=stored==='dark'||stored==='sakura-night'||stored==='neko-dark';document.documentElement.setAttribute('data-theme',stored==='light'||stored==='dark'?stored:(dark?'dark':'light'));document.documentElement.setAttribute('data-theme-family',dark?'dark':'light');</script></head><body style=\\"margin:0\\"><main id=\\"wide\\" style=\\"width:2400px;height:40px\\">overflow-marker</main></body></html>",
  "/scrolled": "<!doctype html><html data-theme-mode=\\"standalone\\" data-theme-key=\\"layout-probe.theme\\"><head><meta charset=\\"utf-8\\"><script>const stored=localStorage.getItem('layout-probe.theme');const dark=stored==='dark'||stored==='sakura-night'||stored==='neko-dark';document.documentElement.setAttribute('data-theme',stored==='light'||stored==='dark'?stored:(dark?'dark':'light'));document.documentElement.setAttribute('data-theme-family',dark?'dark':'light');</script></head><body style=\\"margin:0\\"><div id=\\"strip\\" style=\\"overflow-x:auto;width:200px;max-width:100%;height:48px\\"><main id=\\"inner\\" style=\\"width:2400px;height:40px\\">scrolled-marker</main></div></body></html>",
  "/broken": "<!doctype html><html data-theme-mode=\\"standalone\\" data-theme-key=\\"layout-probe.theme\\"><head><meta charset=\\"utf-8\\"><script>const stored=localStorage.getItem('layout-probe.theme');const dark=stored==='dark'||stored==='sakura-night'||stored==='neko-dark';document.documentElement.setAttribute('data-theme',stored==='light'||stored==='dark'?stored:(dark?'dark':'light'));document.documentElement.setAttribute('data-theme-family',dark?'dark':'light');</script></head><body style=\\"margin:0\\"><script>throw new Error(\\"fixture-page-error\\")</script><p>broken</p></body></html>",
};

let base = "";
const serverFor = async () => {
  const server = createServer((request, response) => {
    const path = new URL(request.url, "http://127.0.0.1").pathname;
    if (path === "/favicon.ico") {
      response.writeHead(204);
      response.end();
      return;
    }
    const body = pages[path] || pages["/home"];
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(body);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = "http://127.0.0.1:" + server.address().port;
  return {
    url: base + "/home",
    async close() {
      server.closeAllConnections?.();
      await new Promise((resolve) => server.close(resolve));
    },
  };
};

export const plugin = {
  id: "layout-probe",
  scenes: [
    { name: "overflow", title: "横向溢出", run: (ui) => ui.open(base + "/overflow") },
    { name: "scrolled", title: "横向滚动", run: (ui) => ui.open(base + "/scrolled") },
    { name: "broken", title: "页面错误", run: (ui) => ui.open(base + "/broken") },
  ],
  startPreview: () => serverFor(),
};
`;

test("overflow and page errors still write a failing gallery; scrolled content does not fail", { timeout: 180000 }, async () => {
  const dir = await mkdtemp(join(tmpdir(), "nre-ui-probe-"));
  const out = join(dir, "out");
  try {
    await writeFile(join(dir, "probe-plugin.mjs"), probePlugin);
    const runner = `import { runCapture } from ${JSON.stringify(pathToFileURL(join(repo, "testing/ui/capture.mjs")).href)};
import { plugin } from "./probe-plugin.mjs";
const report = await runCapture({
  root: ${JSON.stringify(repo)},
  plugins: [plugin],
  themes: ["light"],
  widths: [800],
  out: ${JSON.stringify(out)},
  invocation: "node testing/ui/capture.mjs --plugin layout-probe",
});
process.exit(report.success ? 0 : 1);
`;
    await writeFile(join(dir, "run-probe.mjs"), runner);
    const run = spawnSync(process.execPath, [join(dir, "run-probe.mjs")], { encoding: "utf8", timeout: 150000 });
    assert.notEqual(run.status, 0, outputOf(run));
    const manifest = JSON.parse(await readFile(join(out, manifestName), "utf8"));
    assert.equal(manifest.success, false);
    assert.equal(manifest.missing.length, 0);
    const byScene = Object.fromEntries(manifest.captures.map((item) => [item.scene, item]));
    assert.match(byScene.overflow.issues.join("\n"), /横向溢出/);
    assert.deepEqual(byScene.scrolled.issues, []);
    assert.equal(byScene.scrolled.themeMode, "standalone");
    assert.equal(byScene.scrolled.expectedTheme, "light");
    assert.equal(byScene.scrolled.resolvedTheme, "light");
    assert.equal(byScene.scrolled.themeFamily, "light");
    assert.match(byScene.broken.issues.join("\n"), /页面错误/);
    assert.match(byScene.broken.issues.join("\n"), /fixture-page-error/);
    assert.equal(manifest.failures.some((item) => item.scene === "scrolled"), false);
    const html = await readFile(join(out, "index.html"), "utf8");
    const readme = await readFile(join(out, "README.md"), "utf8");
    assert.match(html, /本次结果：有失败/);
    assert.equal(html.includes("本次结果：通过"), false);
    assert.match(readme, /index\.html/);
    assert.match(readme, new RegExp(manifestName));
    for (const scene of ["overflow", "scrolled", "broken"]) {
      const file = join(out, "layout-probe", `${scene}-light-800.png`);
      const bytes = await readFile(file);
      assert.equal(bytes.subarray(0, 4).toString("hex"), "89504e47");
      assert.equal(manifest.captures.find((item) => item.scene === scene).file.includes("\\"), false);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

const crcTable = new Uint32Array(256);
for (let index = 0; index < 256; index += 1) {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) value = (value & 1) ? (0xedb88320 ^ (value >>> 1)) : (value >>> 1);
  crcTable[index] = value >>> 0;
}

const crc32 = (buffer) => {
  let value = 0xffffffff;
  for (const byte of buffer) value = crcTable[(value ^ byte) & 0xff] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
};

const pngChunk = (type, data) => {
  const body = Buffer.concat([Buffer.from(type), data]);
  const header = Buffer.alloc(4);
  header.writeUInt32BE(data.length);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([header, body, crc]);
};

const makePng = (width, height) => {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  const row = Buffer.alloc(1 + width);
  const raw = Buffer.alloc(row.length * height);
  for (let y = 0; y < height; y += 1) row.copy(raw, y * row.length);
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk("IHDR", ihdr),
    pngChunk("IDAT", deflateSync(raw)),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
};

const pngHeight = (bytes) => {
  assert.equal(bytes.subarray(0, 4).toString("hex"), "89504e47");
  return bytes.readUInt32BE(20);
};

const pageProbe = `import { createServer } from "node:http";

const pages = {
  "/tall": "<!doctype html><html data-theme-mode=\\"standalone\\" data-theme-key=\\"page-probe.theme\\"><head><meta charset=\\"utf-8\\"><script>const stored=localStorage.getItem('page-probe.theme');const dark=stored==='dark';document.documentElement.setAttribute('data-theme',stored==='light'||stored==='dark'?stored:(dark?'dark':'light'));document.documentElement.setAttribute('data-theme-family',dark?'dark':'light');</script></head><body style=\\"margin:0\\"><main style=\\"height:1400px\\">below-the-fold</main></body></html>",
  "/nested": "<!doctype html><html data-theme-mode=\\"standalone\\" data-theme-key=\\"page-probe.theme\\"><head><meta charset=\\"utf-8\\"><script>const stored=localStorage.getItem('page-probe.theme');const dark=stored==='dark';document.documentElement.setAttribute('data-theme',stored==='light'||stored==='dark'?stored:(dark?'dark':'light'));document.documentElement.setAttribute('data-theme-family',dark?'dark':'light');</script></head><body style=\\"margin:0\\"><div style=\\"overflow:auto;height:160px\\"><main style=\\"height:2400px\\">nested-line</main></div></body></html>",
  "/clipped": "<!doctype html><html data-theme-mode=\\"standalone\\" data-theme-key=\\"page-probe.theme\\"><head><meta charset=\\"utf-8\\"><script>const stored=localStorage.getItem('page-probe.theme');const dark=stored==='dark';document.documentElement.setAttribute('data-theme',stored==='light'||stored==='dark'?stored:(dark?'dark':'light'));document.documentElement.setAttribute('data-theme-family',dark?'dark':'light');</script></head><body style=\\"margin:0\\"><main style=\\"height:1400px\\">clipped-below</main></body></html>",
};

let base = "";
const serverFor = async () => {
  const server = createServer((request, response) => {
    const path = new URL(request.url, "http://127.0.0.1").pathname;
    if (path === "/favicon.ico") {
      response.writeHead(204);
      response.end();
      return;
    }
    const body = pages[path] || pages["/tall"];
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(body);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = "http://127.0.0.1:" + server.address().port;
  return {
    url: base + "/tall",
    async close() {
      server.closeAllConnections?.();
      await new Promise((resolve) => server.close(resolve));
    },
  };
};

export const plugin = {
  id: "page-probe",
  scenes: [
    { name: "tall", title: "高于视口", run: (ui) => ui.open(base + "/tall") },
    { name: "nested", title: "内部滚动", run: (ui) => ui.open(base + "/nested") },
    { name: "clipped", title: "整页缺失", run: (ui) => ui.open(base + "/clipped") },
  ],
  startPreview: () => serverFor(),
};
`;

test("tall pages capture below the viewport and a short PNG fails the gallery", { timeout: 180000 }, async () => {
  assert.equal(viewportHeight, 900);
  const dir = await mkdtemp(join(tmpdir(), "nre-ui-tall-"));
  const out = join(dir, "out");
  try {
    await writeFile(join(dir, "probe-plugin.mjs"), pageProbe);
    await writeFile(join(dir, "short.png"), makePng(1, viewportHeight));
    const runner = `import { readFile } from "node:fs/promises";
import { runCapture } from ${JSON.stringify(pathToFileURL(join(repo, "testing/ui/capture.mjs")).href)};
import { plugin } from "./probe-plugin.mjs";
const shortPng = await readFile(new URL("./short.png", import.meta.url));
const report = await runCapture({
  root: ${JSON.stringify(repo)},
  plugins: [plugin],
  themes: ["light"],
  widths: [800],
  out: ${JSON.stringify(out)},
  invocation: "node testing/ui/capture.mjs --plugin page-probe",
  captureScreenshot: async ({ scene }) => (scene.name === "clipped" ? shortPng : null),
});
process.exit(report.success ? 0 : 1);
`;
    await writeFile(join(dir, "run-probe.mjs"), runner);
    const run = spawnSync(process.execPath, [join(dir, "run-probe.mjs")], { encoding: "utf8", timeout: 150000 });
    assert.notEqual(run.status, 0, outputOf(run));
    const manifest = JSON.parse(await readFile(join(out, manifestName), "utf8"));
    assert.equal(manifest.success, false);
    const byScene = Object.fromEntries(manifest.captures.map((item) => [item.scene, item]));
    const tallPng = await readFile(join(out, ...byScene.tall.file.split("/")));
    const tallHeight = pngHeight(tallPng);
    assert.ok(tallHeight > 900, outputOf(run));
    assert.equal(byScene.tall.height, tallHeight);
    assert.deepEqual(byScene.tall.issues, []);
    const nestedPng = await readFile(join(out, ...byScene.nested.file.split("/")));
    const nestedHeight = pngHeight(nestedPng);
    assert.ok(nestedHeight <= 900);
    assert.equal(byScene.nested.height, nestedHeight);
    assert.deepEqual(byScene.nested.issues, []);
    const clippedPng = await readFile(join(out, ...byScene.clipped.file.split("/")));
    const clippedHeight = pngHeight(clippedPng);
    assert.ok(clippedHeight <= 900);
    assert.equal(byScene.clipped.height, clippedHeight);
    assert.match(byScene.clipped.issues.join("\n"), /整页内容没有进入图片（文档 (\d+)px/);
    const documentHeight = Number(byScene.clipped.issues.join("\n").match(/文档 (\d+)px/)[1]);
    assert.ok(documentHeight > 900);
    assert.equal(manifest.failures.some((item) => item.scene === "tall" || item.scene === "nested"), false);
    const html = await readFile(join(out, "index.html"), "utf8");
    assert.match(html, /本次结果：有失败/);
    assert.equal(html.includes("本次结果：通过"), false);
    assert.match(html, /整页内容没有进入图片/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("captures the accelerator usage scene into a filterable gallery", { timeout: 180000 }, async () => {
  const out = await mkdtemp(join(tmpdir(), "nre-ui-usage-"));
  try {
    const run = spawnSync(process.execPath, [
      "testing/ui/capture.mjs",
      "--plugin", "accelerator-sources",
      "--only", "usage",
      "--theme", "dark",
      "--size", "390",
      "--out", out,
    ], { cwd: repo, encoding: "utf8", timeout: 150000 });
    assert.equal(run.status, 0, outputOf(run));
    const html = await readFile(join(out, "index.html"), "utf8");
    const readme = await readFile(join(out, "README.md"), "utf8");
    const manifest = JSON.parse(await readFile(join(out, manifestName), "utf8"));
    assert.equal(manifest.success, true);
    assert.deepEqual(manifest.themes, ["dark"]);
    assert.deepEqual(manifest.widths, [390]);
    assert.deepEqual(manifest.selected, [{ plugin: "accelerator-sources", scenes: ["usage"] }]);
    assert.equal(manifest.captures[0].plugin, "accelerator-sources");
    assert.equal(manifest.captures[0].scene, "usage");
    assert.equal(manifest.captures[0].file, "accelerator-sources/usage-dark-390.png");
    assert.equal(manifest.captures[0].theme, "dark");
    assert.equal(manifest.captures[0].themeMode, "standalone");
    assert.equal(manifest.captures[0].expectedTheme, "dark");
    assert.equal(manifest.captures[0].resolvedTheme, "dark");
    assert.equal(manifest.missing.length, 0);
    const png = await readFile(join(out, "accelerator-sources", "usage-dark-390.png"));
    assert.equal(png.subarray(0, 4).toString("hex"), "89504e47");
    for (const label of ["插件", "场景", "主题", "宽度", "关键词", "重置"]) assert.match(html, new RegExp(label));
    assert.match(html, /本次结果：通过/);
    assert.match(readme, /capture-ui-manifest\.json/);
    assert.match(readme, /index\.html/);
    assert.match(readme, /node testing\/ui\/capture\.mjs --plugin accelerator-sources --only usage --theme dark --size 390/);
    const dom = galleryDom(html);
    assert.equal(dom.visible().length, 1);
    dom.set("plugin", "accelerator-sources");
    dom.set("scene", "usage");
    dom.set("theme", "dark");
    dom.set("width", "390");
    dom.set("query", "用法");
    assert.equal(dom.visible().length, 1);
    dom.set("query", "不存在的词");
    assert.equal(dom.visible().length, 0);
    assert.equal(dom.nodes.empty.hidden, false);
    await dom.reset();
    assert.equal(dom.visible().length, 1);
  } finally {
    await rm(out, { recursive: true, force: true });
  }
});

const themeAuditPlugin = `import { createServer } from "node:http";

const pages = {
  "/bootstrap": "<!doctype html><html data-theme-mode='standalone' data-theme-key='theme-audit.theme'><head><meta charset='utf-8'><script>const stored=localStorage.getItem('theme-audit.theme');const dark=stored==='dark'||stored==='sakura-night'||stored==='neko-dark';document.documentElement.setAttribute('data-theme',stored==='light'||stored==='dark'?stored:(dark?'dark':'light'));document.documentElement.setAttribute('data-theme-family',dark?'dark':'light');</script></head><body>bootstrap</body></html>",
  "/stubborn": "<!doctype html><html data-theme-mode='standalone' data-theme-key='theme-audit.theme'><head><meta charset='utf-8'><script>document.documentElement.setAttribute('data-theme','light');document.documentElement.setAttribute('data-theme-family','light');</script></head><body>stubborn</body></html>",
};

let base = "";
const serverFor = async () => {
  const server = createServer((request, response) => {
    const path = new URL(request.url, "http://127.0.0.1").pathname;
    if (path === "/favicon.ico") { response.writeHead(204); response.end(); return; }
    const body = pages[path] || pages["/bootstrap"];
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(body);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = "http://127.0.0.1:" + server.address().port;
  return {
    url: base + "/bootstrap",
    async close() {
      server.closeAllConnections?.();
      await new Promise((resolve) => server.close(resolve));
    },
  };
};

export const plugin = {
  id: "theme-audit",
  scenes: [
    { name: "bootstrap", title: "导航前写入", run: (ui) => ui.open(base + "/bootstrap") },
    { name: "stubborn", title: "页面自定主题", run: (ui) => ui.open(base + "/stubborn") },
  ],
  startPreview: () => serverFor(),
};
`;

const themeHostPlugin = `import { createServer } from "node:http";

const page = "<!doctype html><html data-theme-mode='host' data-theme-key='theme'><head><meta charset='utf-8'><script>const stored=localStorage.getItem('theme')||'light';const dark=['sakura-night','neko-dark','dark'].includes(stored);document.documentElement.setAttribute('data-theme',stored);document.documentElement.setAttribute('data-theme-family',dark?'dark':'light');</script></head><body>host</body></html>";

let base = "";
const serverFor = async () => {
  const server = createServer((request, response) => {
    const path = new URL(request.url, "http://127.0.0.1").pathname;
    if (path === "/favicon.ico") { response.writeHead(204); response.end(); return; }
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(page);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = "http://127.0.0.1:" + server.address().port;
  return {
    url: base + "/host",
    async close() {
      server.closeAllConnections?.();
      await new Promise((resolve) => server.close(resolve));
    },
  };
};

export const hostPlugin = {
  id: "theme-audit-host",
  themeMode: "host",
  themeKey: "theme",
  scenes: [{ name: "host", title: "宿主主题", run: (ui) => ui.open(base + "/host") }],
  startPreview: () => serverFor(),
};
`;

test("captures resolve the declared theme authority and fail on a mismatch", { timeout: 240000 }, async () => {
  const dir = await mkdtemp(join(tmpdir(), "nre-ui-theme-"));
  try {
    await writeFile(join(dir, "audit-plugin.mjs"), themeAuditPlugin);
    await writeFile(join(dir, "host-plugin.mjs"), themeHostPlugin);
    const outs = {
      good: join(dir, "good"),
      bad: join(dir, "bad"),
      host: join(dir, "host"),
    };
    const runner = `import { runCapture } from ${JSON.stringify(pathToFileURL(join(repo, "testing/ui/capture.mjs")).href)};
import { plugin } from "./audit-plugin.mjs";
import { hostPlugin } from "./host-plugin.mjs";
const pick = (source, names) => ({ ...source, scenes: source.scenes.filter((scene) => names.includes(scene.name)) });
const base = { root: ${JSON.stringify(repo)}, widths: [800] };
const good = await runCapture({ ...base, plugins: [pick(plugin, ["bootstrap"])], themes: ["sakura-night"], out: ${JSON.stringify(outs.good)}, invocation: "good" });
const bad = await runCapture({ ...base, plugins: [pick(plugin, ["stubborn"])], themes: ["dark"], out: ${JSON.stringify(outs.bad)}, invocation: "bad" });
const host = await runCapture({ ...base, plugins: [pick(hostPlugin, ["host"])], themes: ["fresh-green"], out: ${JSON.stringify(outs.host)}, invocation: "host" });
console.log(JSON.stringify({ good: good.success, bad: bad.success, host: host.success }));
process.exit(good.success && !bad.success && host.success ? 0 : 1);
`;
    await writeFile(join(dir, "run-theme.mjs"), runner);
    const run = spawnSync(process.execPath, [join(dir, "run-theme.mjs")], { encoding: "utf8", timeout: 210000 });
    assert.equal(run.status, 0, outputOf(run));

    const good = JSON.parse(await readFile(join(outs.good, manifestName), "utf8"));
    assert.equal(good.success, true);
    assert.equal(good.captures[0].theme, "sakura-night");
    assert.equal(good.captures[0].themeMode, "standalone");
    assert.equal(good.captures[0].expectedTheme, "dark");
    assert.equal(good.captures[0].resolvedTheme, "dark");
    assert.equal(good.captures[0].themeFamily, "dark");
    assert.deepEqual(good.captures[0].issues, []);

    const bad = JSON.parse(await readFile(join(outs.bad, manifestName), "utf8"));
    assert.equal(bad.success, false);
    assert.equal(bad.captures[0].resolvedTheme, "light");
    assert.match(bad.captures[0].issues.join("\n"), /主题解析不符/);
    assert.match(bad.captures[0].issues.join("\n"), /实际 light/);
    assert.equal(bad.captures[0].themeMode, "standalone");

    const host = JSON.parse(await readFile(join(outs.host, manifestName), "utf8"));
    assert.equal(host.success, true);
    assert.equal(host.captures[0].themeMode, "host");
    assert.equal(host.captures[0].resolvedTheme, "fresh-green");
    assert.equal(host.captures[0].themeFamily, "light");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

const runCliAsync = (args) => new Promise((resolve) => {
  const child = spawn(process.execPath, ["testing/ui/theme-probe.mjs", ...args], { cwd: repo });
  let output = "";
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.stderr.on("data", (chunk) => { output += chunk; });
  child.on("close", (status) => resolve({ status, output }));
});

test("theme-probe verifies a top-level page that only reads localStorage.theme", { timeout: 120000 }, async () => {
  const server = createServer((request, response) => {
    if (new URL(request.url, "http://127.0.0.1").pathname === "/favicon.ico") {
      response.writeHead(204);
      response.end();
      return;
    }
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(`<!doctype html><html data-theme-mode="host" data-theme-key="theme"><head><meta charset="utf-8"><script>
const stored=localStorage.getItem("theme");
document.documentElement.setAttribute("data-theme",stored||"missing");
document.documentElement.setAttribute("data-theme-family",["sakura-night","neko-dark"].includes(stored)?"dark":"light");
</script></head><body>probe</body></html>`);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = "http://127.0.0.1:" + server.address().port + "/";
  try {
    const run = await runCliAsync(["--url", url, "--theme", "neko-dark"]);
    assert.equal(run.status, 0, run.output);
    assert.match(run.output, /ok   neko-dark/);
    assert.match(run.output, /1 项通过，0 项失败/);
  } finally {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  }
});

test("contrast audit covers the required kit token pairs", async () => {
  const run = spawnSync(process.execPath, ["testing/ui/contrast.mjs"], { cwd: repo, encoding: "utf8" });
  assert.equal(run.status, 0, outputOf(run));
  assert.match(run.stdout, /必需组合通过/);
  const { auditThemes } = await import(pathToFileURL(join(repo, "testing/ui/contrast.mjs")).href);
  const tokens = `
    --ui-text:#dddddd; --ui-bg:#ffffff; --ui-surface:#ffffff; --ui-surface-raised:#ffffff;
    --ui-text-secondary:#dddddd; --ui-text-tertiary:#dddddd; --ui-text-muted:#dddddd;
    --ui-danger-text:#dddddd; --ui-success-text:#dddddd; --ui-warning-text:#dddddd;
    --ui-success-soft:#ffffff; --ui-warning-soft:#ffffff; --ui-danger-soft:#ffffff;
    --ui-on-danger:#dddddd; --ui-danger-button:#ffffff; --ui-on-primary:#dddddd;
    --ui-primary-hover:#ffffff; --ui-primary-active:#ffffff; --ui-primary:#dddddd;
    --ui-danger:#dddddd; --ui-success:#dddddd; --ui-warning:#dddddd; --ui-border-strong:#dddddd;
  `;
  const bad = auditThemes(`:root{${tokens}}[data-theme="light"]{${tokens}}`);
  assert.ok(bad.failures.length > 0);
  assert.ok(bad.failures.some((item) => item.fg === "--ui-text" && item.bg === "--ui-bg"));
});
