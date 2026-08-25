const applyHostTheme = () => {
  const allowed = { "sakura-day": true, "sakura-night": true };
  const aliases = { sakura: "sakura-day", midnight: "sakura-night", "neko-dark": "sakura-night", cyberpunk: "sakura-day" };
  let theme = "sakura-day";
  try {
    const raw = window.parent && window.parent !== window
      ? window.parent.document.documentElement.getAttribute("data-theme")
      : document.documentElement.getAttribute("data-theme");
    const mapped = aliases[raw] || raw;
    if (allowed[mapped]) {
      theme = mapped;
    }
  } catch (_error) {
    theme = "sakura-day";
  }
  document.documentElement.setAttribute("data-theme", theme);
};

applyHostTheme();

const origin = window.location.origin.replace(/\/$/, "");
const davUrl = origin + "/dav/";
const davNode = document.querySelector("#dav-url");
if (davNode) {
  davNode.textContent = davUrl;
}

const listing = document.querySelector("#listing");
const empty = document.querySelector("#empty");
const crumbs = document.querySelector("#crumbs");
const statusNode = document.querySelector("#status");
const uploadInput = document.querySelector("#upload-input");
const mkdirButton = document.querySelector("#mkdir-button");

let currentPath = "/";

const showStatus = (message, isError) => {
  if (!statusNode) {
    return;
  }
  statusNode.hidden = !message;
  statusNode.textContent = message || "";
  statusNode.dataset.error = isError ? "true" : "false";
};

const joinPath = (dir, name) => {
  if (!dir || dir === "/") {
    return "/" + name;
  }
  return dir.replace(/\/$/, "") + "/" + name;
};

const parentPath = (dir) => {
  if (!dir || dir === "/") {
    return "/";
  }
  const trimmed = dir.replace(/\/$/, "");
  const index = trimmed.lastIndexOf("/");
  if (index <= 0) {
    return "/";
  }
  return trimmed.slice(0, index);
};

const sendJSON = async (path, body) => {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (response.status === 204) {
    return {};
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || "操作失败");
  }
  return payload;
};

const loadList = async (dir) => {
  currentPath = dir || "/";
  const response = await fetch("/api/list?path=" + encodeURIComponent(currentPath));
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || "无法列出目录");
  }
  renderCrumbs(payload.path || currentPath);
  renderListing(payload.entries || []);
};

const renderCrumbs = (dir) => {
  if (!crumbs) {
    return;
  }
  crumbs.replaceChildren();
  const parts = (dir || "/").split("/").filter(Boolean);
  const add = (label, target) => {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = label;
    button.addEventListener("click", () => {
      showStatus("", false);
      loadList(target).catch((error) => showStatus(error.message, true));
    });
    crumbs.append(button);
  };
  add("共享根", "/");
  let prefix = "";
  parts.forEach((part) => {
    prefix += "/" + part;
    crumbs.append(document.createTextNode(" / "));
    add(part, prefix);
  });
};

const renderListing = (entries) => {
  if (!listing || !empty) {
    return;
  }
  listing.replaceChildren();
  empty.hidden = entries.length > 0;
  entries.forEach((entry) => {
    const row = document.createElement("tr");
    const nameCell = document.createElement("td");
    const typeCell = document.createElement("td");
    const sizeCell = document.createElement("td");
    const actionCell = document.createElement("td");
    actionCell.className = "row-actions";
    typeCell.textContent = entry.dir ? "目录" : "文件";
    if (entry.dir) {
      sizeCell.textContent = "—";
    } else {
      const sizeText = typeof entry.size_text === "string" && entry.size_text ? entry.size_text : "—";
      const sizeExact = typeof entry.size_exact === "string" ? entry.size_exact : "";
      sizeCell.textContent = sizeText;
      if (sizeExact) {
        sizeCell.title = sizeExact + " bytes";
        sizeCell.setAttribute("aria-label", sizeText + "，精确大小 " + sizeExact + " 字节");
      }
    }
    if (entry.dir) {
      const open = document.createElement("button");
      open.type = "button";
      open.textContent = entry.name;
      open.addEventListener("click", () => {
        showStatus("", false);
        loadList(joinPath(currentPath, entry.name)).catch((error) => showStatus(error.message, true));
      });
      nameCell.append(open);
    } else {
      const link = document.createElement("a");
      link.href = "/api/download?path=" + encodeURIComponent(joinPath(currentPath, entry.name));
      link.textContent = entry.name;
      nameCell.append(link);
    }
    const rename = document.createElement("button");
    rename.type = "button";
    rename.className = "ghost";
    rename.textContent = "重命名";
    rename.addEventListener("click", async () => {
      const next = window.prompt("新名称", entry.name);
      if (!next || next === entry.name) {
        return;
      }
      try {
        await sendJSON("/api/rename", {
          from: joinPath(currentPath, entry.name),
          to: joinPath(currentPath, next),
        });
        await loadList(currentPath);
        showStatus("已重命名。", false);
      } catch (error) {
        showStatus(error.message, true);
      }
    });
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "ghost danger";
    remove.textContent = "删除";
    remove.addEventListener("click", async () => {
      if (!window.confirm("删除 " + entry.name + "？")) {
        return;
      }
      try {
        await sendJSON("/api/delete", { path: joinPath(currentPath, entry.name) });
        await loadList(currentPath);
        showStatus("已删除。", false);
      } catch (error) {
        showStatus(error.message, true);
      }
    });
    actionCell.append(rename, remove);
    row.append(nameCell, typeCell, sizeCell, actionCell);
    listing.append(row);
  });
};

if (uploadInput) {
  uploadInput.addEventListener("change", async () => {
    const file = uploadInput.files && uploadInput.files[0];
    uploadInput.value = "";
    if (!file) {
      return;
    }
    const body = new FormData();
    body.set("path", currentPath);
    body.set("file", file, file.name);
    try {
      const response = await fetch("/api/upload", { method: "POST", body });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(payload.error || "上传失败");
      }
      await loadList(currentPath);
      showStatus("已上传。", false);
    } catch (error) {
      showStatus(error.message, true);
    }
  });
}

if (mkdirButton) {
  mkdirButton.addEventListener("click", async () => {
    const name = window.prompt("目录名称");
    if (!name) {
      return;
    }
    try {
      await sendJSON("/api/mkdir", { path: joinPath(currentPath, name) });
      await loadList(currentPath);
      showStatus("已新建目录。", false);
    } catch (error) {
      showStatus(error.message, true);
    }
  });
}

loadList("/").catch((error) => showStatus(error.message, true));
