const origin = window.location.origin;
const host = window.location.host;
const examples = {
  "docker-pull": `docker pull ${host}/library/nginx:latest`,
  "docker-mirror": JSON.stringify({ "registry-mirrors": [origin] }, null, 2),
  github: `${origin}/github.com/owner/repo/archive/refs/heads/main.zip`,
  huggingface: `${origin}/huggingface.co/org/model/resolve/main/config.json`,
};

const fill = (name) => {
  document.querySelectorAll(`[data-example="${name}"]`).forEach((node) => {
    node.textContent = examples[name];
  });
};

Object.keys(examples).forEach(fill);

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

document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    const name = button.dataset.copy;
    try {
      await navigator.clipboard.writeText(examples[name]);
      button.textContent = "已复制";
    } catch (error) {
      button.textContent = error.message || "复制失败";
    }
  });
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
        showView("tags");
        document.querySelector("#tags-form").requestSubmit();
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
        showView("offline");
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
