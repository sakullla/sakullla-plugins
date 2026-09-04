const applyHostTheme = () => {
  const allowed = { light: true, dark: true };
  const aliases = { "sakura-day": "light", business: "light", "fresh-green": "light", sakura: "light", cyberpunk: "light", "sakura-night": "dark", "neko-dark": "dark", midnight: "dark" };
  let theme = "light";
  try {
    const raw = window.parent && window.parent !== window
      ? window.parent.document.documentElement.getAttribute("data-theme")
      : document.documentElement.getAttribute("data-theme");
    const mapped = aliases[raw] || raw;
    if (allowed[mapped]) {
      theme = mapped;
    }
  } catch (_error) {
    theme = "light";
  }
  document.documentElement.setAttribute("data-theme", theme);
};

applyHostTheme();

const origin = window.location.origin;
const host = window.location.host;
const examples = {
  "docker-pull": `docker pull ${host}/library/nginx:latest`,
  "docker-mirror": JSON.stringify({ "registry-mirrors": [origin] }, null, 2),
  "file-sample": `${origin}/github.com/owner/repo/releases/download/v1/file.zip`,
};

const fill = (name) => {
  document.querySelectorAll(`[data-example="${name}"]`).forEach((node) => {
    node.textContent = examples[name];
  });
};

Object.keys(examples).forEach(fill);

const hostBadge = document.querySelector("#current-host");
if (hostBadge) {
  hostBadge.textContent = host;
}

const showView = (name) => {
  document.querySelectorAll("[data-panel]").forEach((panel) => {
    panel.hidden = panel.dataset.panel !== name;
  });
  document.querySelectorAll(".primary button, .wordmark").forEach((item) => {
    if (item.matches("button")) {
      item.setAttribute("aria-pressed", item.dataset.view === name ? "true" : "false");
    }
  });
};

document.querySelectorAll("[data-view]").forEach((item) => {
  item.addEventListener("click", (event) => {
    event.preventDefault();
    showView(item.dataset.view);
  });
});

const flashCopied = (button, ok) => {
  const previous = button.dataset.copyLabel || button.textContent;
  button.dataset.copyLabel = previous;
  button.textContent = ok ? "已复制" : "复制失败";
  window.setTimeout(() => {
    button.textContent = previous;
  }, 1600);
};

document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    const name = button.dataset.copy;
    try {
      await navigator.clipboard.writeText(examples[name]);
      flashCopied(button, true);
    } catch (error) {
      flashCopied(button, false);
    }
  });
});

const supportedHosts = ["github.com", "gist.github.com", "api.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com", "codeload.github.com", "github-releases.githubusercontent.com", "huggingface.co"];

const convertInput = document.querySelector("#convert-input");
const convertSnippet = document.querySelector("#convert-snippet");
const convertResult = document.querySelector("#convert-result");
const convertCopy = document.querySelector("#convert-copy");
const convertHint = document.querySelector("#convert-hint");

const normalizeSourceUrl = (value) => value.trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/^\/+/, "");

const updateConversion = () => {
  const target = normalizeSourceUrl(convertInput.value);
  if (!target) {
    convertSnippet.hidden = true;
    convertHint.hidden = true;
    convertCopy.disabled = true;
    convertResult.textContent = "";
    return;
  }
  convertResult.textContent = `${origin}/${target}`;
  convertSnippet.hidden = false;
  convertCopy.disabled = false;
  const hostName = target.split("/")[0].toLowerCase();
  const supported = supportedHosts.some((item) => hostName === item || hostName.endsWith(`.${item}`));
  convertHint.hidden = supported;
  if (!supported) {
    convertHint.textContent = "该域名可能不受支持：当前入口支持 GitHub 与 Hugging Face 的地址。";
  }
};

convertInput.addEventListener("input", updateConversion);

const samples = {
  github: "github.com/cli/cli/releases/download/v2.40.0/gh_linux_amd64.tar.gz",
  huggingface: "huggingface.co/bert-base-uncased/resolve/main/config.json",
};

document.querySelectorAll("[data-sample]").forEach((button) => {
  button.addEventListener("click", () => {
    convertInput.value = samples[button.dataset.sample] || "";
    document.querySelectorAll("[data-sample]").forEach((item) => {
      item.setAttribute("aria-pressed", item === button ? "true" : "false");
    });
    updateConversion();
    convertInput.focus();
  });
});

convertCopy.addEventListener("click", async () => {
  if (convertCopy.disabled) {
    return;
  }
  try {
    await navigator.clipboard.writeText(convertResult.textContent);
    flashCopied(convertCopy, true);
  } catch (error) {
    flashCopied(convertCopy, false);
  }
});

const renderStatus = (target, message) => {
  const status = document.createElement("p");
  status.className = "status";
  status.textContent = message;
  target.replaceChildren(status);
};

document.querySelector("#search-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const results = document.querySelector("#results");
  renderStatus(results, "正在搜索...");
  try {
    const query = document.querySelector("#query").value;
    const response = await fetch(`/api/search?q=${encodeURIComponent(query)}`);
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "搜索失败");
    }
    const entries = Array.isArray(payload.results) ? payload.results : [];
    if (entries.length === 0) {
      renderStatus(results, "没有找到匹配的镜像。");
      return;
    }
    results.replaceChildren(...entries.map((entry) => {
      const name = entry.repo_name || entry.name;
      const card = document.createElement("button");
      card.type = "button";
      card.className = "result-card";
      const title = document.createElement("strong");
      title.textContent = name;
      const detail = document.createElement("span");
      detail.textContent = entry.short_description || "进入标签浏览";
      card.append(title, detail);
      card.addEventListener("click", () => {
        document.querySelector("#tag-image").value = name;
        document.querySelector("#tags-form").requestSubmit();
        document.querySelector("#tags-heading").scrollIntoView({ block: "start" });
      });
      return card;
    }));
  } catch (error) {
    renderStatus(results, error.message);
  }
});

document.querySelector("#tags-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const board = document.querySelector("#tag-results");
  renderStatus(board, "正在加载标签...");
  const image = document.querySelector("#tag-image").value.trim();
  try {
    const response = await fetch(`/api/tags?image=${encodeURIComponent(image)}`);
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "标签加载失败");
    }
    const entries = Array.isArray(payload.results) ? payload.results : [];
    if (entries.length === 0) {
      renderStatus(board, "该镜像没有可显示的标签。");
      return;
    }
    board.replaceChildren(...entries.map((entry) => {
      const chip = document.createElement("button");
      chip.type = "button";
      chip.className = "tag-chip";
      chip.textContent = entry.name;
      chip.addEventListener("click", () => {
        const area = document.querySelector("#images");
        const reference = `${image}:${entry.name}`;
        const lines = area.value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
        if (!lines.includes(reference)) {
          area.value = [...lines, reference].join("\n");
        }
        area.scrollIntoView({ block: "center" });
      });
      return chip;
    }));
  } catch (error) {
    renderStatus(board, error.message);
  }
});

document.querySelector("#offline-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const output = document.querySelector("#download");
  renderStatus(output, "正在准备离线包...");
  const images = document.querySelector("#images").value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
  const platform = document.querySelector("#platform").value;
  const compressedLayers = document.querySelector("#compressed-layers").checked;
  try {
    const response = await fetch("/api/offline/prepare", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        images,
        platform,
        compressed_layers: compressedLayers,
      }),
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "准备失败");
    }
    const link = document.createElement("a");
    link.href = payload.download_url;
    link.textContent = "下载 Docker 离线包";
    output.replaceChildren(link);
  } catch (error) {
    renderStatus(output, error.message);
  }
});
