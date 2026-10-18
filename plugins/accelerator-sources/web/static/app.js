const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));
const store = {
  get(key) {
    try {
      return window.localStorage.getItem(`accelerator-sources.${key}`);
    } catch (_error) {
      return null;
    }
  },
  set(key, value) {
    try {
      if (value === null || value === "") {
        window.localStorage.removeItem(`accelerator-sources.${key}`);
      } else {
        window.localStorage.setItem(`accelerator-sources.${key}`, value);
      }
    } catch (_error) {
      // Private browsing or disabled storage: preferences simply are not kept.
    }
  },
};

/* ---------- Shared helpers ---------- */

const origin = window.location.origin;
const host = window.location.host;

const toast = (() => {
  const node = $("#toast");
  const text = $("#toast-text");
  const action = $("#toast-action");
  let timer = 0;
  let handler = null;
  action.addEventListener("click", () => {
    node.hidden = true;
    if (handler) {
      handler();
    }
  });
  return (message, options = {}) => {
    window.clearTimeout(timer);
    text.textContent = message;
    handler = options.onAction || null;
    action.hidden = !options.action;
    action.textContent = options.action || "";
    node.hidden = false;
    node.classList.remove("is-in");
    void node.offsetWidth;
    node.classList.add("is-in");
    timer = window.setTimeout(() => {
      node.hidden = true;
    }, options.duration || 2600);
  };
})();

// navigator.clipboard only exists in secure contexts; plain-HTTP deployments
// fall back to a temporary selection so copy keeps working everywhere.
const copyText = async (value) => {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch (_error) {
      // Fall through to the selection-based copy.
    }
  }
  const buffer = document.createElement("textarea");
  buffer.value = value;
  buffer.setAttribute("readonly", "");
  buffer.className = "copy-buffer";
  document.body.append(buffer);
  buffer.select();
  let copied = false;
  try {
    copied = document.execCommand("copy");
  } catch (_error) {
    copied = false;
  }
  buffer.remove();
  return copied;
};

const flashCopied = (button, ok) => {
  const label = button.querySelector("span") || button;
  if (!button.dataset.copyLabel) {
    button.dataset.copyLabel = label.textContent;
  }
  window.clearTimeout(Number(button.dataset.copyTimer || 0));
  label.textContent = ok ? "已复制" : "复制失败";
  button.dataset.state = ok ? "copied" : "failed";
  button.dataset.copyTimer = String(window.setTimeout(() => {
    label.textContent = button.dataset.copyLabel;
    delete button.dataset.state;
  }, 1600));
};

// Builds a copy button identical to the static ones (icons included).
const copyButton = (value) => {
  const button = $("[data-copy]").cloneNode(true);
  button.removeAttribute("data-copy");
  delete button.dataset.state;
  delete button.dataset.copyLabel;
  button.querySelector("span").textContent = "复制";
  button.addEventListener("click", () => copyFrom(button, value));
  return button;
};

const copyFrom = async (button, value) => {
  if (!value) {
    return;
  }
  flashCopied(button, await copyText(value));
};

const create = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (text !== undefined) {
    node.textContent = text;
  }
  return node;
};

const friendlyError = (message, status) => {
  const raw = String(message || "").toLowerCase();
  const table = [
    ["search query is required", "请输入要搜索的镜像名称。"],
    ["valid docker hub image is required", "请输入有效的 Docker Hub 镜像名，例如 nginx 或 bitnami/redis（不含标签）。"],
    ["catalog upstream failed", "暂时无法连接 Docker Hub，请稍后重试。"],
    ["catalog request failed", "暂时无法连接 Docker Hub，请稍后重试。"],
    ["requires 1-", "离线包需要 1 到 16 个镜像引用。"],
    ["too many prepared downloads", "待下载的离线包过多，请几分钟后再试。"],
    ["download token not found", "下载链接已失效，请重新生成。"],
    ["unable to resolve image manifest", "有镜像无法解析，请检查名称、标签与架构。"],
    ["unsupported registry", "包含暂不支持的镜像仓库。"],
    ["platform", "架构格式无效。"],
  ];
  const hit = table.find(([needle]) => raw.includes(needle));
  if (hit) {
    return hit[1];
  }
  if (status === 429) {
    return "请求过于频繁，请稍后再试。";
  }
  if (status >= 500) {
    return "服务暂时不可用，请稍后重试。";
  }
  return message ? `请求失败：${message}` : `请求失败（HTTP ${status}）。`;
};

const api = async (url, options = {}) => {
  let response;
  try {
    response = await fetch(url, options);
  } catch (error) {
    if (error && error.name === "AbortError") {
      throw error;
    }
    throw new Error("网络连接失败，请检查网络后重试。");
  }
  let payload = null;
  if (options.method !== "HEAD") {
    try {
      payload = await response.json();
    } catch (_error) {
      payload = null;
    }
  }
  if (!response.ok) {
    throw new Error(friendlyError(payload && (payload.error || payload.message || payload.detail), response.status));
  }
  return payload || {};
};

const setBusy = (button, busy, label) => {
  if (!button) {
    return;
  }
  if (busy) {
    button.dataset.idleLabel = button.dataset.idleLabel || button.textContent;
    button.textContent = label || button.dataset.idleLabel;
  } else if (button.dataset.idleLabel) {
    button.textContent = button.dataset.idleLabel;
  }
  button.disabled = busy;
  button.setAttribute("aria-busy", busy ? "true" : "false");
};

const stateIcon = (kind) => {
  const icon = create("span", `${kind}__icon`);
  icon.innerHTML = kind === "ui-error-state"
    ? '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 3.2 21 20H3L12 3.2Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M12 9v4.4M12 16.8v.1" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>'
    : '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="10.5" cy="10.5" r="6.5" stroke="currentColor" stroke-width="1.8"/><path d="m15.5 15.5 4.5 4.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>';
  return icon;
};

const renderState = (target, kind, title, message) => {
  const box = create("div", kind);
  box.append(stateIcon(kind), create("p", `${kind}__title`, title), create("p", `${kind}__desc`, message));
  target.replaceChildren(box);
};

const renderEmpty = (target, title, message) => renderState(target, "ui-empty", title, message);
const renderError = (target, title, message) => renderState(target, "ui-error-state", title, message);

const renderLoading = (target, message, count = 3, variant = "row") => {
  const wrap = create("div", "accel-loading");
  const line = create("div", "ui-loading");
  line.append(create("span", "ui-spinner"), create("span", "", message));
  wrap.append(line);
  if (variant === "chip") {
    wrap.classList.add("accel-loading--chips");
  }
  for (let index = 0; index < count; index += 1) {
    wrap.append(create("div", variant === "chip" ? "ui-skeleton accel-skeleton-chip" : "ui-skeleton accel-skeleton-row"));
  }
  target.replaceChildren(wrap);
};

/* ---------- Views ---------- */

const views = ["usage", "mirrors"];

const showView = (name, push = false) => {
  if (!views.includes(name)) {
    name = "usage";
  }
  $$("[data-panel]").forEach((panel) => {
    panel.hidden = panel.dataset.panel !== name;
  });
  $$("[data-view]").forEach((item) => {
    const active = item.dataset.view === name;
    item.setAttribute("aria-selected", active ? "true" : "false");
    item.setAttribute("tabindex", active ? "0" : "-1");
  });
  const hash = name === "usage" ? "" : `#${name}`;
  if (window.location.hash !== hash && !(hash === "" && window.location.hash === "#usage")) {
    window.history[push ? "pushState" : "replaceState"](null, "", hash || `${window.location.pathname}${window.location.search}`);
  }
};

$$("[data-view]").forEach((item) => {
  item.addEventListener("click", (event) => {
    event.preventDefault();
    const name = item.dataset.view;
    const changed = $(`[data-panel="${name}"]`).hidden;
    showView(name, changed);
    if (changed) {
      window.scrollTo(0, 0);
    }
  });
});

window.addEventListener("popstate", () => showView(window.location.hash.slice(1)));
showView(window.location.hash.slice(1));

document.addEventListener("keydown", (event) => {
  if (event.key !== "/" || event.ctrlKey || event.metaKey || event.altKey) {
    return;
  }
  const active = document.activeElement;
  if (active && (active.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(active.tagName))) {
    return;
  }
  event.preventDefault();
  const target = $("#usage").hidden ? $("#query") : $("#convert-input");
  target.focus();
  target.select();
});

/* ---------- Usage examples ---------- */

const examples = {
  "docker-pull": `docker pull ${host}/library/nginx:latest`,
  "docker-ghcr": `${host}/ghcr.io/owner/app:latest`,
  "docker-mirror": JSON.stringify({ "registry-mirrors": [origin] }, null, 2),
  "file-sample": `${origin}/github.com/owner/repo/releases/download/v1/file.zip`,
  "script-sample": `curl -fsSL ${origin}/raw.githubusercontent.com/owner/repo/main/install.sh | bash`,
  "clone-sample": `git clone ${origin}/github.com/owner/repo.git`,
  "offline-cli": "",
};

const fill = (name) => {
  $$(`[data-example="${name}"]`).forEach((node) => {
    node.textContent = examples[name];
  });
};

Object.keys(examples).forEach(fill);

const hostBadge = $("#current-host");
if (hostBadge) {
  hostBadge.textContent = host;
}

$$("[data-copy]").forEach((button) => {
  button.addEventListener("click", () => copyFrom(button, examples[button.dataset.copy]));
});

const daemonTargets = {
  linux: { path: "/etc/docker/daemon.json", apply: ["保存后执行 ", { code: "sudo systemctl restart docker" }, " 生效。"] },
  windows: { path: "%USERPROFILE%\\.docker\\daemon.json", apply: ["Docker Desktop 用户可在 Settings → Docker Engine 中合并这段配置，点击 Apply & restart。"] },
  macos: { path: "~/.docker/daemon.json", apply: ["Docker Desktop 用户可在 Settings → Docker Engine 中合并这段配置，点击 Apply & restart。"] },
};

const showDaemonTarget = (os) => {
  const target = daemonTargets[os] || daemonTargets.linux;
  $$("[data-os]").forEach((button) => button.setAttribute("aria-pressed", button.dataset.os === os ? "true" : "false"));
  $("#daemon-path").textContent = target.path;
  const parts = target.apply.map((part) => (typeof part === "string" ? document.createTextNode(part) : create("code", "", part.code)));
  parts.push(document.createTextNode("镜像源只作用于 Docker Hub，其它仓库请用上面的域名前缀。"));
  $("#daemon-apply").replaceChildren(...parts);
};

$$("[data-os]").forEach((button) => {
  button.addEventListener("click", () => showDaemonTarget(button.dataset.os));
});
showDaemonTarget("linux");

/* ---------- Converter ---------- */

// Mirrors the source prefixes routed by internal/service.
const supportedHosts = ["github.com", "api.github.com", "codeload.github.com", "raw.githubusercontent.com", "gist.github.com", "gist.githubusercontent.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com", "github.githubassets.com", "huggingface.co"];
const registryHosts = ["docker.io", "ghcr.io", "gcr.io", "quay.io", "registry.k8s.io"];
const hostAliases = { "www.github.com": "github.com", "hf.co": "huggingface.co", "www.huggingface.co": "huggingface.co" };
const imagePattern = /^(?:[a-z0-9]+(?:[.-][a-z0-9]+)*(?::\d+)?\/)?[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:\/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$/;

const convertInput = $("#convert-input");
const convertSnippet = $("#convert-snippet");
const convertResult = $("#convert-result");
const convertCopy = $("#convert-copy");
const convertHint = $("#convert-hint");
const convertNote = $("#convert-note");
const convertKind = $("#convert-kind");
const convertFormats = $("#convert-formats");
const convertOpen = $("#convert-open");
const convertAdd = $("#convert-add");
const convertClear = $("#convert-clear");

const normalizeSourceUrl = (value) => value.trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/^\/+/, "");

const analyzeSource = (raw) => {
  let value = raw.trim();
  const pull = value.match(/^(?:sudo\s+)?(?:docker|podman|nerdctl)\s+(?:image\s+)?pull\s+(.+)$/i);
  if (pull) {
    value = pull[1].trim().split(/\s+/).pop();
  }
  const hadScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(value);
  let target = normalizeSourceUrl(value);
  if (target.toLowerCase().startsWith(`${host.toLowerCase()}/`)) {
    target = target.slice(host.length + 1);
  }
  if (!target) {
    return null;
  }
  const slash = target.indexOf("/");
  let name = (slash < 0 ? target : target.slice(0, slash)).toLowerCase();
  let path = slash < 0 ? "" : target.slice(slash);
  name = hostAliases[name] || name;
  const notes = [];

  const looksLikeImage = imagePattern.test(target.toLowerCase());
  if (registryHosts.includes(name) || (!hadScheme && !name.includes(".") && !name.includes(":") && looksLikeImage)) {
    if (!looksLikeImage || (registryHosts.includes(name) && !path)) {
      return { kind: "invalid", message: "镜像引用格式不正确，例如 nginx:latest 或 ghcr.io/owner/app:1.0。" };
    }
    return { kind: "image", label: registryHosts.includes(name) ? `${name} 镜像` : "Docker Hub 镜像", ref: target };
  }
  if (!supportedHosts.includes(name)) {
    if (/\s/.test(target) || !/[.:]/.test(name)) {
      return { kind: "invalid", message: "无法识别输入。请粘贴 GitHub、Hugging Face 链接，或 nginx:latest 这样的镜像名。" };
    }
    if (!hadScheme && looksLikeImage && /:[^/]+$/.test(target)) {
      return { kind: "invalid", message: `暂不支持 ${name} 镜像仓库，可用：${registryHosts.join("、")}。` };
    }
    return { kind: "invalid", message: `暂不支持 ${name || "该地址"}。可加速 GitHub（含 raw、Gist、发行包）与 Hugging Face 的地址。` };
  }

  let kind = "file";
  let label = name === "huggingface.co" ? "Hugging Face" : "GitHub 文件";
  const segments = path.split(/[?#]/)[0].split("/").filter(Boolean);
  if (name === "github.com" && segments.length >= 4 && segments[2] === "blob") {
    name = "raw.githubusercontent.com";
    path = `/${[segments[0], segments[1], ...segments.slice(3)].join("/")}${path.slice(path.split(/[?#]/)[0].length)}`;
    notes.push("网页地址已转换为 raw 文件地址。");
  } else if (name === "github.com" && (segments.length === 2 || (segments.length >= 3 && segments[2] === "tree"))) {
    kind = "repo";
    label = "GitHub 仓库";
    path = `/${segments[0]}/${segments[1].replace(/\.git$/i, "")}.git`;
  } else if (name === "huggingface.co" && segments.includes("blob")) {
    path = path.replace("/blob/", "/resolve/");
    notes.push("网页地址已转换为 resolve 下载地址。");
  }
  return { kind, label, url: `${origin}/${name}${path}`, notes };
};

const formatsFor = {
  file: [["link", "链接"], ["curl", "curl"], ["wget", "wget"]],
  repo: [["clone", "git clone"], ["link", "链接"]],
  image: [["pull", "拉取命令"], ["ref", "镜像地址"]],
};
const chosenFormat = { file: "link", repo: "clone", image: "pull" };

const quote = (value) => (/[\s&;|<>()$`'"!*?]/.test(value) ? `"${value.replace(/(["\\$`])/g, "\\$1")}"` : value);

const outputFor = (result, format) => {
  if (result.kind === "image") {
    const reference = `${host}/${result.ref}`;
    return format === "ref" ? reference : `docker pull ${reference}`;
  }
  if (format === "curl") {
    return `curl -fLO ${quote(result.url)}`;
  }
  if (format === "wget") {
    return `wget ${quote(result.url)}`;
  }
  if (format === "clone") {
    return `git clone ${result.url}`;
  }
  return result.url;
};

let currentConversion = null;

const renderFormats = (result) => {
  const options = formatsFor[result.kind] || [];
  convertFormats.replaceChildren(...options.map(([value, label]) => {
    const button = create("button", "", label);
    button.type = "button";
    button.dataset.format = value;
    button.setAttribute("aria-pressed", chosenFormat[result.kind] === value ? "true" : "false");
    button.addEventListener("click", () => {
      chosenFormat[result.kind] = value;
      updateConversion();
    });
    return button;
  }));
};

const updateConversion = () => {
  const raw = convertInput.value;
  convertClear.hidden = !raw;
  const result = raw.trim() ? analyzeSource(raw) : null;
  currentConversion = result && result.kind !== "invalid" ? result : null;
  convertHint.hidden = !result || result.kind !== "invalid";
  if (result && result.kind === "invalid") {
    convertHint.textContent = result.message;
  }
  if (!currentConversion) {
    convertSnippet.hidden = true;
    convertNote.hidden = true;
    convertCopy.disabled = true;
    convertResult.textContent = "";
    return;
  }
  const output = outputFor(currentConversion, chosenFormat[currentConversion.kind]);
  convertResult.textContent = output;
  convertKind.textContent = currentConversion.label;
  convertKind.dataset.kind = currentConversion.kind === "image" ? "image" : currentConversion.label === "Hugging Face" ? "model" : "file";
  renderFormats(currentConversion);
  convertOpen.hidden = currentConversion.kind === "image";
  convertOpen.href = currentConversion.url || "#";
  convertAdd.hidden = currentConversion.kind !== "image";
  const notes = currentConversion.notes || [];
  convertNote.hidden = notes.length === 0;
  convertNote.textContent = notes.join(" ");
  convertSnippet.hidden = false;
  convertCopy.disabled = false;
};

convertInput.addEventListener("input", () => {
  $$("[data-sample]").forEach((item) => item.setAttribute("aria-pressed", "false"));
  updateConversion();
});

convertInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !convertCopy.disabled) {
    event.preventDefault();
    copyFrom(convertCopy, convertResult.textContent);
  } else if (event.key === "Escape" && convertInput.value) {
    event.preventDefault();
    convertInput.value = "";
    updateConversion();
  }
});

convertClear.addEventListener("click", () => {
  convertInput.value = "";
  $$("[data-sample]").forEach((item) => item.setAttribute("aria-pressed", "false"));
  updateConversion();
  convertInput.focus();
});

const samples = {
  github: "github.com/cli/cli/releases/download/v2.62.0/gh_2.62.0_linux_amd64.tar.gz",
  repo: "github.com/cli/cli",
  huggingface: "huggingface.co/bert-base-uncased/resolve/main/config.json",
  docker: "nginx:latest",
};

$$("[data-sample]").forEach((button) => {
  button.addEventListener("click", () => {
    convertInput.value = samples[button.dataset.sample] || "";
    $$("[data-sample]").forEach((item) => {
      item.setAttribute("aria-pressed", item === button ? "true" : "false");
    });
    updateConversion();
    convertInput.focus();
  });
});

convertCopy.addEventListener("click", () => {
  if (!convertCopy.disabled) {
    copyFrom(convertCopy, convertResult.textContent);
  }
});

/* ---------- Offline pack ---------- */

const maxImages = 16;
const imageArea = $("#images");
const packCount = $("#pack-count");
const packError = $("#pack-error");
const packClear = $("#pack-clear");
const download = $("#download");
const platformSelect = $("#platform");
const compressedToggle = $("#compressed-layers");

const imageLines = () => imageArea.value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);

// The server lower-cases repository paths, so validate case-insensitively.
const invalidImages = (lines) => lines.filter((line) => !imagePattern.test(line.toLowerCase()));

const offlineCommand = (lines) => {
  const params = new URLSearchParams();
  (lines.length ? lines : ["alpine:latest"]).forEach((line) => params.append("image", line));
  if (platformSelect.value) {
    params.set("platform", platformSelect.value);
  }
  if (!compressedToggle.checked) {
    params.set("compressed_layers", "false");
  }
  return `curl -fL -o images.tar "${origin}/api/offline?${params.toString()}"\ndocker load -i images.tar`;
};

const syncTagPressed = () => {
  const image = tagState.image;
  const lines = imageLines();
  $$("#tag-results .tag-chip").forEach((chip) => {
    chip.setAttribute("aria-pressed", lines.includes(`${image}:${chip.dataset.tag}`) ? "true" : "false");
  });
};

const renderQueue = () => {
  const lines = imageLines();
  packCount.textContent = `${lines.length} / ${maxImages}`;
  const over = lines.length > maxImages;
  packCount.dataset.state = over ? "over" : lines.length ? "filled" : "empty";
  packCount.className = "ui-badge ui-badge--plain" + (over ? " ui-badge--danger" : lines.length ? " ui-badge--info" : "");
  packClear.disabled = lines.length === 0;
  if (!packError.hidden && packError.dataset.source === "validate") {
    packError.hidden = true;
  }
  imageArea.removeAttribute("aria-invalid");
  examples["offline-cli"] = offlineCommand(lines);
  fill("offline-cli");
  store.set("pack", lines.join("\n"));
  syncTagPressed();
};

const writeImageLines = (lines) => {
  imageArea.value = lines.join("\n");
  renderQueue();
};

const revealPack = () => {
  showView("mirrors", true);
  $("#offline-heading").scrollIntoView({ behavior: "smooth", block: "start" });
};

const packIsVisible = () => {
  const box = $(".accel-pane-offline").getBoundingClientRect();
  return box.top < window.innerHeight && box.bottom > 80;
};

const addToPack = (reference) => {
  const lines = imageLines();
  if (lines.includes(reference)) {
    return false;
  }
  writeImageLines([...lines, reference]);
  return true;
};

imageArea.value = store.get("pack") || "";
imageArea.addEventListener("input", renderQueue);
platformSelect.addEventListener("change", renderQueue);
compressedToggle.addEventListener("change", renderQueue);
packClear.addEventListener("click", () => {
  const previous = imageArea.value;
  writeImageLines([]);
  download.replaceChildren();
  toast("离线包已清空", { action: "撤销", onAction: () => { imageArea.value = previous; renderQueue(); } });
});

convertAdd.addEventListener("click", () => {
  if (!currentConversion || currentConversion.kind !== "image") {
    return;
  }
  const added = addToPack(currentConversion.ref);
  toast(added ? `已加入离线包，共 ${imageLines().length} 个` : "离线包里已经有这个镜像", { action: "查看", onAction: revealPack });
});

/* ---------- Search ---------- */

const searchForm = $("#search-form");
const searchButton = searchForm.querySelector("button");
const queryInput = $("#query");
const results = $("#results");
const resultsMeta = $("#results-meta");
const resultsMore = $("#results-more");
const searchState = { query: "", page: 1, controller: null, selected: "" };

const compactNumber = (value) => {
  const number = Number(value) || 0;
  if (number >= 1e8) {
    return `${(number / 1e8).toFixed(number >= 1e9 ? 0 : 1).replace(/\.0$/, "")} 亿`;
  }
  if (number >= 1e4) {
    return `${(number / 1e4).toFixed(number >= 1e5 ? 0 : 1).replace(/\.0$/, "")} 万`;
  }
  return String(number);
};

// Docker Hub's catalog rejects tags or digests, so strip them from free text.
const repositoryName = (value) => value.trim().toLowerCase().replace(/^docker\.io\//, "").replace(/@.*$/, "").replace(/:[^/]*$/, "");


const renderResultCard = (entry) => {
  const name = entry.repo_name || entry.name;
  const card = create("button", "result-card");
  card.type = "button";
  card.dataset.name = name;
  card.setAttribute("aria-pressed", searchState.selected === name ? "true" : "false");
  const title = create("span", "result-title");
  title.append(create("strong", "", name));
  if (entry.is_official) {
    title.append(create("span", "ui-badge ui-badge--info ui-badge--plain", "官方"));
  }
  const detail = create("span", "result-desc", entry.short_description || "暂无简介");
  const meta = create("span", "result-meta");
  meta.append(create("span", "", `★ ${compactNumber(entry.star_count)}`), create("span", "", `${compactNumber(entry.pull_count)} 次拉取`));
  card.append(title, detail, meta);
  card.addEventListener("click", () => {
    searchState.selected = name;
    $$("#results .result-card").forEach((item) => item.setAttribute("aria-pressed", item === card ? "true" : "false"));
    $("#tag-image").value = name;
    loadTags(false);
    const tags = $(".accel-pane-tags");
    if (tags.getBoundingClientRect().top > window.innerHeight * 0.6) {
      tags.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  });
  return card;
};

const runSearch = async (append) => {
  const query = append ? searchState.query : repositoryName(queryInput.value) || queryInput.value.trim();
  if (!query) {
    queryInput.focus();
    return;
  }
  if (searchState.controller) {
    searchState.controller.abort();
  }
  const controller = new AbortController();
  searchState.controller = controller;
  searchState.query = query;
  searchState.page = append ? searchState.page + 1 : 1;
  setBusy(append ? resultsMore : searchButton, true, append ? "正在加载…" : "搜索中");
  if (!append) {
    resultsMore.hidden = true;
    resultsMeta.textContent = "";
    results.setAttribute("aria-busy", "true");
    renderLoading(results, "正在搜索 Docker Hub…");
  }
  try {
    const payload = await api(`/api/search?q=${encodeURIComponent(query)}&page=${searchState.page}&page_size=10`, { signal: controller.signal });
    const entries = Array.isArray(payload.results) ? payload.results : [];
    if (!append && entries.length === 0) {
      renderEmpty(results, "没有找到匹配的镜像", `没有与「${query}」匹配的仓库，换一个关键字再试。`);
      return;
    }
    const cards = entries.map(renderResultCard);
    if (append) {
      results.append(...cards);
    } else {
      results.replaceChildren(...cards);
    }
    resultsMeta.textContent = payload.count ? `${compactNumber(payload.count)} 个结果` : "";
    resultsMore.hidden = !payload.next;
  } catch (error) {
    if (error.name === "AbortError") {
      return;
    }
    if (append) {
      searchState.page -= 1;
      toast(error.message);
    } else {
      renderError(results, "搜索失败", error.message);
    }
  } finally {
    if (searchState.controller === controller) {
      results.removeAttribute("aria-busy");
      setBusy(append ? resultsMore : searchButton, false);
    }
  }
};

searchForm.addEventListener("submit", (event) => {
  event.preventDefault();
  runSearch(false);
});
resultsMore.addEventListener("click", () => runSearch(true));

/* ---------- Tags ---------- */

const tagForm = $("#tags-form");
const tagButton = tagForm.querySelector("button");
const tagImage = $("#tag-image");
const tagBoard = $("#tag-results");
const tagTools = $("#tag-tools");
const tagFilter = $("#tag-filter");
const tagMeta = $("#tag-meta");
const tagsMore = $("#tags-more");
const tagState = { image: "", page: 1, items: [], count: 0, controller: null };

const formatSize = (bytes) => {
  const value = Number(bytes) || 0;
  if (value >= 1 << 30) {
    return `${(value / (1 << 30)).toFixed(1)} GB`;
  }
  if (value >= 1 << 20) {
    return `${(value / (1 << 20)).toFixed(1)} MB`;
  }
  return value ? `${Math.max(1, Math.round(value / 1024))} KB` : "";
};

const tagTooltip = (entry) => {
  const parts = [];
  if (entry.last_updated) {
    parts.push(`更新于 ${entry.last_updated.slice(0, 10)}`);
  }
  if (entry.full_size) {
    parts.push(formatSize(entry.full_size));
  }
  const arches = (entry.images || []).map((image) => [image.architecture, image.variant].filter(Boolean).join("/")).filter((arch) => arch && arch !== "unknown");
  if (arches.length) {
    parts.push(Array.from(new Set(arches)).join(", "));
  }
  return parts.join(" · ");
};

const renderTags = () => {
  const term = tagFilter.value.trim().toLowerCase();
  const visible = term ? tagState.items.filter((entry) => entry.name.toLowerCase().includes(term)) : tagState.items;
  if (visible.length === 0) {
    renderEmpty(tagBoard, term ? "没有匹配的标签" : "没有可显示的标签", term ? `已加载的标签中没有包含「${term}」的。` : "该镜像没有可显示的标签。");
    return;
  }
  tagBoard.replaceChildren(...visible.map((entry) => {
    const chip = create("button", "tag-chip ui-badge ui-badge--plain", entry.name);
    chip.type = "button";
    chip.dataset.tag = entry.name;
    chip.title = tagTooltip(entry);
    chip.addEventListener("click", () => {
      const reference = `${tagState.image}:${entry.name}`;
      const lines = imageLines();
      if (lines.includes(reference)) {
        writeImageLines(lines.filter((item) => item !== reference));
        toast(`已移出 ${reference}`);
        return;
      }
      if (lines.length >= maxImages) {
        toast(`离线包最多 ${maxImages} 个镜像`);
        return;
      }
      writeImageLines([...lines, reference]);
      if (packIsVisible()) {
        toast(`已加入 ${reference}`);
      } else {
        toast(`已加入离线包，共 ${imageLines().length} 个`, { action: "查看", onAction: revealPack });
      }
    });
    return chip;
  }));
  syncTagPressed();
};

const loadTags = async (append) => {
  const image = append ? tagState.image : repositoryName(tagImage.value);
  if (!image) {
    tagImage.focus();
    return;
  }
  if (!append) {
    tagImage.value = image;
  }
  if (tagState.controller) {
    tagState.controller.abort();
  }
  const controller = new AbortController();
  tagState.controller = controller;
  tagState.page = append ? tagState.page + 1 : 1;
  setBusy(append ? tagsMore : tagButton, true, append ? "正在加载…" : "加载中");
  if (!append) {
    tagState.image = image;
    tagState.items = [];
    tagFilter.value = "";
    tagTools.hidden = true;
    tagsMore.hidden = true;
    tagMeta.textContent = "";
    tagBoard.setAttribute("aria-busy", "true");
    renderLoading(tagBoard, "正在加载标签…", 6, "chip");
  }
  try {
    const payload = await api(`/api/tags?image=${encodeURIComponent(image)}&page=${tagState.page}&page_size=100`, { signal: controller.signal });
    const entries = Array.isArray(payload.results) ? payload.results : [];
    tagState.items = append ? tagState.items.concat(entries) : entries;
    tagState.count = Number(payload.count) || tagState.items.length;
    tagMeta.textContent = tagState.items.length ? `${image} · ${tagState.count} 个标签` : image;
    tagTools.hidden = tagState.items.length === 0;
    tagsMore.hidden = !payload.next;
    renderTags();
  } catch (error) {
    if (error.name === "AbortError") {
      return;
    }
    if (append) {
      tagState.page -= 1;
      toast(error.message);
    } else {
      renderError(tagBoard, "标签加载失败", error.message);
    }
  } finally {
    if (tagState.controller === controller) {
      tagBoard.removeAttribute("aria-busy");
      setBusy(append ? tagsMore : tagButton, false);
    }
  }
};

tagForm.addEventListener("submit", (event) => {
  event.preventDefault();
  searchState.selected = repositoryName(tagImage.value);
  $$("#results .result-card").forEach((item) => item.setAttribute("aria-pressed", item.dataset.name === searchState.selected ? "true" : "false"));
  loadTags(false);
});
tagsMore.addEventListener("click", () => loadTags(true));
tagFilter.addEventListener("input", renderTags);

/* ---------- Prepare download ---------- */

const offlineForm = $("#offline-form");
const packSubmit = $("#pack-submit");
let countdown = 0;

const showPackError = (message) => {
  packError.textContent = message;
  packError.dataset.source = "validate";
  packError.hidden = false;
  imageArea.setAttribute("aria-invalid", "true");
  imageArea.focus();
};

const validatePack = (lines) => {
  if (lines.length === 0) {
    return "请至少填写一个镜像引用，或在标签列表中点选。";
  }
  if (lines.length > maxImages) {
    return `一次最多打包 ${maxImages} 个镜像，当前 ${lines.length} 个。`;
  }
  const duplicates = lines.filter((line, index) => lines.indexOf(line) !== index);
  if (duplicates.length) {
    return `重复的镜像引用：${Array.from(new Set(duplicates)).join("、")}`;
  }
  const invalid = invalidImages(lines);
  if (invalid.length) {
    return `无法识别的镜像引用：${invalid.slice(0, 3).join("、")}${invalid.length > 3 ? " 等" : ""}`;
  }
  return "";
};

const summaryText = (lines, platform, compressed) => `${lines.length} 个镜像 · ${platform || "linux/amd64"} · ${compressed ? "压缩层" : "未压缩层"}`;

const renderReady = (payload, lines, platform, compressed) => {
  const card = create("div", "ui-card ui-card--flat download-ready");
  const head = create("div", "ui-card__head download-head");
  const text = create("div");
  text.append(create("p", "ui-card__title", "离线包已就绪"), create("p", "ui-card__desc", summaryText(lines, platform, compressed)));
  head.append(text, create("span", "ui-badge ui-badge--success", "可下载"));
  const link = create("a", "ui-btn ui-btn--lg download-link", "下载 images.tar");
  link.href = payload.download_url;
  link.setAttribute("download", "images.tar");
  const expiry = create("p", "ui-help-text download-expiry");
  const loadCommand = create("div", "snippet");
  const chrome = create("div", "snippet-chrome");
  chrome.append(create("p", "snippet-label", "下载后导入 Docker"), copyButton("docker load -i images.tar"));
  loadCommand.append(chrome, create("pre", "snippet-body", "docker load -i images.tar"));
  card.append(head, link, expiry, loadCommand);
  download.replaceChildren(card);

  const deadline = Date.parse(payload.expires_at) || Date.now() + 5 * 60 * 1000;
  const expire = (message) => {
    window.clearInterval(countdown);
    link.removeAttribute("href");
    link.setAttribute("aria-disabled", "true");
    link.textContent = "链接已使用";
    card.dataset.state = "used";
    expiry.textContent = message;
  };
  const tick = () => {
    const left = Math.max(0, Math.round((deadline - Date.now()) / 1000));
    if (left === 0) {
      expire("链接已过期，请重新生成。");
      link.textContent = "链接已过期";
      return;
    }
    expiry.textContent = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")} 后失效 · 链接只能下载一次`;
  };
  window.clearInterval(countdown);
  tick();
  countdown = window.setInterval(tick, 1000);
  link.addEventListener("click", () => {
    window.setTimeout(() => expire("下载已开始。如需再次下载，请重新生成离线包。"), 0);
  });
};

// A prepared plan is only consumed by GET, so HEAD resolves every manifest up
// front. On failure each image is probed separately to name the culprit.
const findBrokenImages = async (lines, platform) => {
  const broken = [];
  let cursor = 0;
  const worker = async () => {
    while (cursor < lines.length) {
      const line = lines[cursor];
      cursor += 1;
      const params = new URLSearchParams({ image: line });
      if (platform) {
        params.set("platform", platform);
      }
      try {
        await api(`/api/offline?${params.toString()}`, { method: "HEAD" });
      } catch (_error) {
        broken.push(line);
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(4, lines.length) }, worker));
  return lines.filter((line) => broken.includes(line));
};

offlineForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const lines = imageLines();
  const problem = validatePack(lines);
  if (problem) {
    showPackError(problem);
    return;
  }
  packError.hidden = true;
  window.clearInterval(countdown);
  const platform = platformSelect.value;
  const compressedLayers = compressedToggle.checked;
  setBusy(packSubmit, true, "正在生成…");
  renderLoading(download, `正在解析 ${lines.length} 个镜像的清单…`);
  try {
    const payload = await api("/api/offline/prepare", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        images: lines,
        platform,
        compressed_layers: compressedLayers,
      }),
    });
    try {
      await api(payload.download_url, { method: "HEAD" });
    } catch (error) {
      const broken = await findBrokenImages(lines, platform);
      if (broken.length) {
        throw new Error(`以下镜像无法解析，请检查名称、标签或架构：${broken.join("、")}`);
      }
      throw error;
    }
    renderReady(payload, lines, platform, compressedLayers);
  } catch (error) {
    renderError(download, "离线包生成失败", error.message);
  } finally {
    setBusy(packSubmit, false);
  }
});

renderQueue();
