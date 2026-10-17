// Minimal Chrome DevTools Protocol driver. Node's built-in WebSocket talks to
// a locally installed Chromium-family browser; there is no npm dependency.
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const candidates = () => {
  const env = process.env;
  const list = [env.NRE_UI_BROWSER];
  if (process.platform === "win32") {
    for (const base of [env.PROGRAMFILES, env["PROGRAMFILES(X86)"], env.LOCALAPPDATA].filter(Boolean)) {
      list.push(join(base, "Google/Chrome/Application/chrome.exe"), join(base, "Microsoft/Edge/Application/msedge.exe"), join(base, "Chromium/Application/chrome.exe"));
    }
  } else if (process.platform === "darwin") {
    list.push("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/Applications/Chromium.app/Contents/MacOS/Chromium", "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge");
  } else {
    list.push("/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/usr/bin/chromium", "/usr/bin/chromium-browser", "/snap/bin/chromium", "/usr/bin/microsoft-edge");
  }
  return list.filter(Boolean);
};

export const findBrowser = () => {
  const found = candidates().find((path) => existsSync(path));
  if (!found) {
    throw new Error("未找到 Chromium 内核浏览器；请用 NRE_UI_BROWSER 指定 chrome / msedge / chromium 可执行文件路径");
  }
  return found;
};

export const until = async (fn, label, ms = 10000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return;
    await delay(40);
  }
  throw new Error(`等待超时：${label}`);
};

const readJson = async (response) => {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
};

export async function launch({ executable = findBrowser() } = {}) {
  const profile = await mkdtemp(join(tmpdir(), "nre-ui-capture-"));
  const child = spawn(executable, [
    "--headless=new",
    "--no-sandbox",
    "--disable-gpu",
    "--hide-scrollbars",
    "--force-color-profile=srgb",
    "--font-render-hinting=none",
    "--no-first-run",
    "--no-default-browser-check",
    "--remote-debugging-port=0",
    `--user-data-dir=${profile}`,
    "about:blank",
  ], { windowsHide: true, stdio: "ignore" });
  let port = "";
  await until(async () => {
    try {
      port = (await readFile(join(profile, "DevToolsActivePort"), "utf8")).split("\n")[0].trim();
      return Boolean(port);
    } catch {
      return false;
    }
  }, "浏览器启动", 20000);

  const close = async () => {
    child.kill();
    await delay(200);
    await rm(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }).catch(() => {});
  };

  const openPage = async () => {
    let target = null;
    for (const method of ["PUT", "GET"]) {
      const response = await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method });
      if (!response.ok) continue;
      target = await readJson(response);
      if (target?.webSocketDebuggerUrl) break;
    }
    if (!target?.webSocketDebuggerUrl) {
      const listed = await readJson(await fetch(`http://127.0.0.1:${port}/json/list`));
      target = Array.isArray(listed) ? listed.find((item) => item.type === "page" && item.webSocketDebuggerUrl) : null;
    }
    if (!target?.webSocketDebuggerUrl) throw new Error("无法打开浏览器页面");
    const socket = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      socket.addEventListener("open", resolve, { once: true });
      socket.addEventListener("error", reject, { once: true });
    });
    let sequence = 0;
    const pending = new Map();
    const listeners = new Map();
    socket.addEventListener("message", ({ data }) => {
      const message = JSON.parse(data);
      if (message.id && pending.has(message.id)) {
        const { resolve, reject } = pending.get(message.id);
        pending.delete(message.id);
        if (message.error) reject(new Error(`${message.error.message} (${message.error.code})`));
        else resolve(message.result);
        return;
      }
      for (const handler of listeners.get(message.method) || []) handler(message.params);
    });
    const send = (method, params = {}) => new Promise((resolve, reject) => {
      const id = ++sequence;
      pending.set(id, { resolve, reject });
      socket.send(JSON.stringify({ id, method, params }));
    });
    const on = (method, handler) => {
      if (!listeners.has(method)) listeners.set(method, []);
      listeners.get(method).push(handler);
    };
    const evaluate = async (expression) => {
      const result = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
      if (result.exceptionDetails) {
        const detail = result.exceptionDetails.exception?.description || result.exceptionDetails.text;
        throw new Error(`页面脚本执行失败：${detail}`);
      }
      return result.result.value;
    };
    const call = (fn, ...args) => evaluate(`(${fn})(...${JSON.stringify(args)})`);
    await Promise.all([send("Page.enable"), send("Runtime.enable"), send("Network.enable"), send("Log.enable")]);
    return { send, on, evaluate, call, close: () => socket.close() };
  };

  return { openPage, close };
}
