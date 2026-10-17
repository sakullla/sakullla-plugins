import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildGallery, manifestName } from "./gallery.mjs";

const repo = fileURLToPath(new URL("../..", import.meta.url));
const scenes = ["usage", "convert-github", "convert-repo", "convert-docker", "convert-unsupported", "mirrors", "mirrors-loading", "mirrors-browse", "mirrors-ready", "mirrors-error"];

const runCli = (args, cwd = repo) => spawnSync(process.execPath, ["testing/ui/capture.mjs", ...args], {
  cwd,
  encoding: "utf8",
  timeout: 30000,
});

const outputOf = (run) => `${run.stdout || ""}\n${run.stderr || ""}`;

function galleryDom(html) {
  const figures = [...html.matchAll(/<figure\b([^>]*)>/g)].map((match) => ({
    dataset: Object.fromEntries([...match[1].matchAll(/\bdata-([a-z]+)=\"([^\"]*)\"/g)].map((item) => [item[1], item[2]])),
    hidden: false,
  }));
  const values = { plugin: "", scene: "", theme: "", width: "", query: "" };
  const listeners = {};
  const formListeners = {};
  const nodes = {
    count: { textContent: "" },
    empty: { hidden: true },
    filters: { addEventListener(type, fn) { formListeners[type] = fn; } },
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
    querySelectorAll: (selector) => (selector === "figure" ? figures : []),
  };
  const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  new Function("document", script)(documentShim);
  return {
    figures,
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
  assert.equal(readme.includes("plugins/accelerator-sources/testing/ui/capture.mjs"), false);
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

const probePlugin = `import { createServer } from "node:http";

const pages = {
  "/home": "<!doctype html><html><head><meta charset=\\"utf-8\\"></head><body><p>home</p></body></html>",
  "/overflow": "<!doctype html><html><head><meta charset=\\"utf-8\\"></head><body style=\\"margin:0\\"><main id=\\"wide\\" style=\\"width:2400px;height:40px\\">overflow-marker</main></body></html>",
  "/scrolled": "<!doctype html><html><head><meta charset=\\"utf-8\\"></head><body style=\\"margin:0\\"><div id=\\"strip\\" style=\\"overflow-x:auto;width:200px;max-width:100%;height:48px\\"><main id=\\"inner\\" style=\\"width:2400px;height:40px\\">scrolled-marker</main></div></body></html>",
  "/broken": "<!doctype html><html><head><meta charset=\\"utf-8\\"></head><body style=\\"margin:0\\"><script>throw new Error(\\"fixture-page-error\\")</script><p>broken</p></body></html>",
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
