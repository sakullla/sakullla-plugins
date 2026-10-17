#!/usr/bin/env node
// UI capture tool for the accelerator-sources visitor page.
//
//   node plugins/accelerator-sources/testing/ui/capture.mjs            # all scenes × themes × widths
//   node plugins/accelerator-sources/testing/ui/capture.mjs --scenes usage,mirrors-browse --widths 390
//   node plugins/accelerator-sources/testing/ui/capture.mjs --serve --port 4180
//   node plugins/accelerator-sources/testing/ui/capture.mjs --list
//
// Screenshots, report.json and a browsable index.html are written to
// dist/accelerator-sources-ui/ (override with --out). The run fails when a
// capture shows horizontal overflow, runtime errors, CSP violations, or any
// request leaving the page origin.
import { mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { launch, until } from "./browser.mjs";
import { readProductionCSP, startMockServer } from "./mock.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");

const usage = `用法：node plugins/accelerator-sources/testing/ui/capture.mjs [选项]

  --scenes a,b       只捕获这些场景（默认全部，--list 查看）
  --themes a,b       light、dark（默认两者）
  --widths a,b       视口宽度（默认 1440,768,390）
  --height n         视口高度（默认 900）
  --scale n          设备像素比（默认 1）
  --viewport         只截取首屏，而不是整页
  --latency ms       模拟 API 延迟（默认 0）
  --out dir          输出目录（默认 dist/accelerator-sources-ui）
  --serve            只启动带模拟 API 的预览服务，不截图
  --port n           预览服务端口（--serve 默认 4180，否则随机）
  --list             列出场景
  环境变量 NRE_UI_BROWSER 可指定 Chrome / Edge / Chromium 路径。`;

const parseArgs = (argv) => {
  const options = { themes: ["light", "dark"], widths: [1440, 768, 390], height: 900, scale: 1, latency: 0, full: true, out: join(root, "dist/accelerator-sources-ui") };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = () => {
      const next = argv[index + 1];
      if (next === undefined || next.startsWith("--")) throw new Error(`${flag} 需要一个值`);
      index += 1;
      return next;
    };
    const list = () => value().split(",").map((item) => item.trim()).filter(Boolean);
    switch (flag) {
      case "--scenes": options.scenes = list(); break;
      case "--themes": options.themes = list(); break;
      case "--widths": options.widths = list().map(Number); break;
      case "--height": options.height = Number(value()); break;
      case "--scale": options.scale = Number(value()); break;
      case "--latency": options.latency = Number(value()); break;
      case "--out": options.out = resolve(value()); break;
      case "--port": options.port = Number(value()); break;
      case "--viewport": options.full = false; break;
      case "--serve": options.serve = true; break;
      case "--list": options.list = true; break;
      case "-h": case "--help": options.help = true; break;
      default: throw new Error(`未知参数 ${flag}\n\n${usage}`);
    }
  }
  if (options.widths.some((width) => !Number.isInteger(width) || width < 280 || width > 3840)) throw new Error("--widths 需为 280-3840 之间的整数");
  if (options.themes.some((theme) => theme !== "light" && theme !== "dark")) throw new Error("--themes 只支持 light、dark");
  return options;
};

// Scenes only drive the page through stable ids/classes that the Go tests and
// web corpus already pin, so they keep working while the visual design moves.
const scenes = {
  "usage": { title: "用法首页", run: async () => {} },
  "convert-github": {
    title: "链接转换 · GitHub 发行包",
    run: async (ui) => { await ui.fill("#convert-input", "https://github.com/cli/cli/releases/download/v2.62.0/gh_2.62.0_linux_amd64.tar.gz"); },
  },
  "convert-repo": {
    title: "链接转换 · 仓库克隆",
    run: async (ui) => { await ui.fill("#convert-input", "https://github.com/cli/cli"); },
  },
  "convert-docker": {
    title: "链接转换 · 镜像引用",
    run: async (ui) => { await ui.fill("#convert-input", "ghcr.io/home-assistant/home-assistant:stable"); },
  },
  "convert-unsupported": {
    title: "链接转换 · 不支持的域名",
    run: async (ui) => { await ui.fill("#convert-input", "https://example.com/files/archive.zip"); },
  },
  "mirrors": { title: "镜像工作台", run: async (ui) => { await ui.view("mirrors"); } },
  "mirrors-loading": {
    title: "镜像 · 搜索加载中",
    settle: false,
    run: async (ui) => {
      await ui.view("mirrors");
      await ui.fill("#query", "hold");
      await ui.submit("#search-form");
      await delay(350);
    },
  },
  "mirrors-browse": {
    title: "镜像 · 搜索结果与标签",
    run: async (ui) => {
      await ui.view("mirrors");
      await ui.fill("#query", "nginx");
      await ui.submit("#search-form");
      await ui.waitFor("#results .result-card");
      await ui.click("#results .result-card");
      await ui.waitFor("#tag-results .tag-chip");
      await ui.click("#tag-results .tag-chip:nth-of-type(1)");
      await ui.click("#tag-results .tag-chip:nth-of-type(4)");
      await ui.evaluate("window.scrollTo(0, 0)");
    },
  },
  "mirrors-ready": {
    title: "镜像 · 离线包已就绪",
    run: async (ui) => {
      await ui.view("mirrors");
      await ui.fill("#images", "alpine:latest\nlibrary/nginx:stable\nghcr.io/home-assistant/home-assistant:stable");
      await ui.submit("#offline-form");
      await ui.waitFor("#download a");
    },
  },
  "mirrors-error": {
    title: "镜像 · 上游错误",
    run: async (ui) => {
      await ui.view("mirrors");
      await ui.fill("#query", "fail");
      await ui.submit("#search-form");
      await ui.fill("#images", "alpine:latest\nfail/unknown:1");
      await ui.submit("#offline-form");
      await ui.waitFor("#download .status-error");
    },
  },
};

const driver = (page) => {
  const evaluate = page.evaluate;
  const find = (selector) => `(() => { const node = document.querySelector(${JSON.stringify(selector)}); if (!node) throw new Error("找不到元素 " + ${JSON.stringify(selector)}); return node; })()`;
  return {
    evaluate,
    waitFor: (selector, ms = 8000) => until(() => evaluate(`Boolean(document.querySelector(${JSON.stringify(selector)})?.getClientRects().length)`), selector, ms),
    click: (selector) => evaluate(`${find(selector)}.click()`),
    fill: (selector, value) => evaluate(`(() => { const node = ${find(selector)}; node.focus(); node.value = ${JSON.stringify(value)}; node.dispatchEvent(new Event("input", { bubbles: true })); node.dispatchEvent(new Event("change", { bubbles: true })); })()`),
    submit: (selector) => evaluate(`${find(selector)}.requestSubmit()`),
    view: (name) => evaluate(`${find(`.primary [data-view="${name}"]`)}.click()`),
  };
};

const overflowReport = (page) => page.evaluate(`(() => {
  const width = document.documentElement.clientWidth;
  if (document.documentElement.scrollWidth <= width) return [];
  const label = (node) => node.tagName.toLowerCase() + (node.id ? "#" + node.id : "") + (node.classList.length ? "." + [...node.classList].join(".") : "");
  return [...document.querySelectorAll("body *")].filter((node) => node.getBoundingClientRect().right > width + 1 && node.getClientRects().length).slice(0, 6).map(label);
})()`);

const contactSheet = (report) => {
  const escape = (value) => String(value).replace(/[&<>"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[char]);
  const groups = [...new Set(report.captures.map((item) => item.scene))].map((scene) => {
    const items = report.captures.filter((item) => item.scene === scene);
    const cards = items.map((item) => `<figure class="${item.issues.length ? "bad" : ""}"><a href="${escape(item.file)}" target="_blank"><img loading="lazy" src="${escape(item.file)}" alt=""></a><figcaption>${escape(item.theme)} · ${item.width}px${item.issues.map((issue) => `<br><b>${escape(issue)}</b>`).join("")}</figcaption></figure>`).join("");
    return `<section><h2>${escape(items[0].title)} <small>${escape(scene)}</small></h2><div class="row">${cards}</div></section>`;
  }).join("");
  return `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>资源加速 UI 捕获</title><style>
body{margin:0;padding:24px 32px;font:14px/1.5 system-ui,"Microsoft YaHei",sans-serif;background:#f4f5f8;color:#1b1f2a}
h1{font-size:20px;margin:0 0 4px}p{margin:0 0 20px;color:#5b6375}h2{font-size:15px;margin:28px 0 10px}small{color:#8a91a3;font-weight:400;margin-left:6px}
.row{display:flex;gap:16px;overflow-x:auto;align-items:flex-start;padding-bottom:8px}figure{margin:0;flex:none;background:#fff;border:1px solid #e1e4ec;border-radius:10px;padding:8px}
figure.bad{border-color:#e5484d}img{display:block;height:420px;width:auto;border-radius:6px}figcaption{margin-top:6px;color:#5b6375}b{color:#c62a2f;font-weight:600}
</style><h1>资源加速 UI 捕获</h1><p>${escape(report.generated_at)} · ${report.captures.length} 张截图 · ${report.status === "passed" ? "全部通过" : "存在问题"}</p>${groups}</html>`;
};

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) return console.log(usage);
  if (options.list) {
    for (const [name, scene] of Object.entries(scenes)) console.log(`${name.padEnd(22)}${scene.title}`);
    return;
  }
  const csp = await readProductionCSP(root);
  const server = await startMockServer({ root, csp, latency: options.latency, port: options.port ?? (options.serve ? 4180 : 0) });
  if (options.serve) {
    console.log(`预览地址：${server.url}\n模拟数据：搜索任意词；以 hold 开头保持加载，以 fail 开头返回上游错误。按 Ctrl+C 退出。`);
    return;
  }
  const selected = options.scenes || Object.keys(scenes);
  const unknown = selected.filter((name) => !scenes[name]);
  if (unknown.length) throw new Error(`未知场景 ${unknown.join(", ")}；可用：${Object.keys(scenes).join(", ")}`);

  await rm(options.out, { recursive: true, force: true });
  await mkdir(options.out, { recursive: true });
  const browser = await launch();
  const report = { generated_at: new Date().toISOString(), status: "passed", options: { themes: options.themes, widths: options.widths, scale: options.scale, full_page: options.full }, captures: [] };
  try {
    const page = await browser.openPage();
    const origin = new URL(server.url).origin;
    let log = [];
    const inflight = new Set();
    page.on("Runtime.exceptionThrown", (event) => log.push(`脚本异常：${event.exceptionDetails.exception?.description || event.exceptionDetails.text}`));
    page.on("Runtime.consoleAPICalled", (event) => {
      if (event.type === "error") log.push(`console.error：${event.args.map((arg) => arg.value ?? arg.description).join(" ")}`);
    });
    page.on("Log.entryAdded", ({ entry }) => {
      if (entry.level === "error" && !/status of (4|5)\d\d/.test(entry.text)) log.push(`浏览器：${entry.text}`);
    });
    page.on("Network.requestWillBeSent", ({ requestId, request }) => {
      inflight.add(requestId);
      if (!request.url.startsWith(origin) && !/^(data|blob|about):/.test(request.url)) log.push(`外部请求：${request.url}`);
    });
    page.on("Network.loadingFinished", ({ requestId }) => inflight.delete(requestId));
    page.on("Network.loadingFailed", ({ requestId }) => inflight.delete(requestId));
    await page.send("Page.addScriptToEvaluateOnNewDocument", { source: "try { localStorage.clear(); } catch (_) {}" });

    for (const theme of options.themes) {
      await page.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: theme }, { name: "prefers-reduced-motion", value: "reduce" }] });
      for (const width of options.widths) {
        await page.send("Emulation.setDeviceMetricsOverride", { width, height: options.height, deviceScaleFactor: options.scale, mobile: width < 600 });
        for (const name of selected) {
          const scene = scenes[name];
          log = [];
          inflight.clear();
          await page.send("Page.navigate", { url: server.url });
          await until(() => page.evaluate("document.readyState === 'complete'"), "页面加载");
          await page.evaluate("document.fonts.ready.then(() => true)");
          const forced = await page.evaluate(`document.documentElement.getAttribute("data-theme") !== ${JSON.stringify(theme)} && (document.documentElement.setAttribute("data-theme", ${JSON.stringify(theme)}), true)`);
          const issues = [];
          try {
            await scene.run(driver(page));
            if (scene.settle !== false) await until(() => inflight.size === 0, "网络空闲", 8000);
            await page.evaluate("new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done)))");
            await delay(120);
          } catch (error) {
            issues.push(`场景失败：${error.message}`);
          }
          // Full-page captures render sticky/fixed layers at the current
          // scroll offset, so always shoot from the top of the document.
          if (options.full) await page.evaluate("window.scrollTo(0, 0)");
          const overflow = await overflowReport(page);
          if (overflow.length) issues.push(`横向溢出：${overflow.join(", ")}`);
          issues.push(...log);
          const shot = await page.send("Page.captureScreenshot", { format: "png", captureBeyondViewport: options.full });
          const file = `${name}-${theme}-${width}.png`;
          await writeFile(join(options.out, file), Buffer.from(shot.data, "base64"));
          report.captures.push({ scene: name, title: scene.title, theme, width, file, theme_forced: forced, issues });
          console.log(`${issues.length ? "FAIL" : "ok  "} ${file}${issues.map((issue) => `\n     - ${issue}`).join("")}`);
        }
      }
    }
    page.close();
  } finally {
    await browser.close();
    await server.close();
  }
  const failed = report.captures.filter((item) => item.issues.length);
  report.status = failed.length ? "failed" : "passed";
  await writeFile(join(options.out, "report.json"), `${JSON.stringify(report, null, 2)}\n`);
  await writeFile(join(options.out, "index.html"), contactSheet(report));
  console.log(`\n${report.captures.length} 张截图，${failed.length} 张存在问题 → ${relative(process.cwd(), join(options.out, "index.html"))}`);
  if (failed.length) process.exitCode = 1;
}

main().catch((error) => {
  console.error(error.message || error);
  process.exitCode = 1;
});
