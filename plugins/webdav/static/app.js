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

const credentialUsernameKey = "webdav.username";
const credentialPasswordKey = "webdav.password";

const origin = window.location.origin.replace(/\/$/, "");
const davUrl = origin + "/dav/";
const davNode = document.querySelector("#dav-url");
if (davNode) {
  davNode.textContent = davUrl;
}

const loginView = document.querySelector("#login-view");
const managerView = document.querySelector("#manager-view");
const loginForm = document.querySelector("#login-form");
const loginUsername = document.querySelector("#login-username");
const loginPassword = document.querySelector("#login-password");
const loginError = document.querySelector("#login-error");
const logoutButton = document.querySelector("#logout-button");
const currentUsername = document.querySelector("#current-username");
const whoInitial = document.querySelector("#who-initial");
const listing = document.querySelector("#listing");
const empty = document.querySelector("#empty");
const crumbs = document.querySelector("#crumbs");
const statusNode = document.querySelector("#status");
const uploadInput = document.querySelector("#upload-input");
const mkdirButton = document.querySelector("#mkdir-button");
const mkdirDialog = document.querySelector("#mkdir-dialog");
const mkdirForm = document.querySelector("#mkdir-form");
const mkdirName = document.querySelector("#mkdir-name");
const mkdirCancel = document.querySelector("#mkdir-cancel");
const mkdirError = document.querySelector("#mkdir-error");

let currentPath = "/";

const encodeBasic = (username, password) => {
  const bytes = new TextEncoder().encode(username + ":" + password);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return "Basic " + btoa(binary);
};

const readCredentials = () => {
  const username = sessionStorage.getItem(credentialUsernameKey) || "";
  const password = sessionStorage.getItem(credentialPasswordKey) || "";
  if (!username || !password) {
    return null;
  }
  return { username, password };
};

const saveCredentials = (username, password) => {
  sessionStorage.setItem(credentialUsernameKey, username);
  sessionStorage.setItem(credentialPasswordKey, password);
};

const clearCredentials = () => {
  sessionStorage.removeItem(credentialUsernameKey);
  sessionStorage.removeItem(credentialPasswordKey);
};

const withAuthHeaders = (headers) => {
  const next = headers ? Object.assign({}, headers) : {};
  const credentials = readCredentials();
  if (credentials) {
    next.Authorization = encodeBasic(credentials.username, credentials.password);
  }
  return next;
};

const showLogin = () => {
  if (loginView) {
    loginView.hidden = false;
  }
  if (managerView) {
    managerView.hidden = true;
  }
};

const showManager = (username) => {
  if (loginView) {
    loginView.hidden = true;
  }
  if (managerView) {
    managerView.hidden = false;
  }
  if (currentUsername) {
    currentUsername.textContent = username || "";
  }
  if (whoInitial) {
    const trimmed = (username || "").trim();
    whoInitial.textContent = trimmed ? trimmed.slice(0, 1) : "";
  }
};

const setLoginError = (message) => {
  if (!loginError) {
    return;
  }
  loginError.hidden = !message;
  loginError.textContent = message || "";
};

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
    headers: withAuthHeaders({ "Content-Type": "application/json" }),
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
  const response = await fetch("/api/list?path=" + encodeURIComponent(currentPath), {
    headers: withAuthHeaders(),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || "无法列出目录");
  }
  renderCrumbs(payload.path || currentPath);
  renderListing(payload.entries || []);
};

const downloadFile = async (name) => {
  const response = await fetch("/api/download?path=" + encodeURIComponent(joinPath(currentPath, name)), {
    headers: withAuthHeaders(),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.error || "下载失败");
  }
  const blob = await response.blob();
  const objectURL = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = objectURL;
  link.download = name;
  link.rel = "noopener";
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(objectURL);
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
    const sep = document.createElement("span");
    sep.className = "crumb-sep";
    sep.setAttribute("aria-hidden", "true");
    crumbs.append(sep);
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
    row.className = entry.dir ? "row-dir" : "row-file";
    const nameCell = document.createElement("td");
    const typeCell = document.createElement("td");
    const sizeCell = document.createElement("td");
    const actionCell = document.createElement("td");
    actionCell.className = "row-actions";
    const typePill = document.createElement("span");
    typePill.className = "type-pill";
    typePill.textContent = entry.dir ? "目录" : "文件";
    typeCell.append(typePill);
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
    const open = document.createElement("button");
    open.type = "button";
    open.textContent = entry.name;
    if (entry.dir) {
      open.addEventListener("click", () => {
        showStatus("", false);
        loadList(joinPath(currentPath, entry.name)).catch((error) => showStatus(error.message, true));
      });
    } else {
      open.addEventListener("click", () => {
        showStatus("", false);
        downloadFile(entry.name).catch((error) => showStatus(error.message, true));
      });
    }
    const glyph = document.createElement("span");
    glyph.className = "file-glyph";
    glyph.setAttribute("aria-hidden", "true");
    const nameWrap = document.createElement("div");
    nameWrap.className = "name-wrap";
    nameWrap.append(glyph, open);
    nameCell.append(nameWrap);
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
      const response = await fetch("/api/upload", { method: "POST", headers: withAuthHeaders(), body });
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

const setMkdirError = (message) => {
  if (!mkdirError) {
    return;
  }
  mkdirError.hidden = !message;
  mkdirError.textContent = message || "";
};

if (mkdirButton && mkdirDialog && mkdirForm && mkdirName) {
  mkdirButton.addEventListener("click", () => {
    setMkdirError("");
    mkdirName.value = "";
    mkdirDialog.showModal();
    mkdirName.focus();
  });
  mkdirForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const name = mkdirName.value.trim();
    if (!name) {
      return;
    }
    try {
      await sendJSON("/api/mkdir", { path: joinPath(currentPath, name) });
      mkdirDialog.close();
      await loadList(currentPath);
      showStatus("已新建目录。", false);
    } catch (error) {
      setMkdirError(error.message);
      showStatus(error.message, true);
    }
  });
  if (mkdirCancel) {
    mkdirCancel.addEventListener("click", () => mkdirDialog.close());
  }
  mkdirDialog.addEventListener("close", () => {
    mkdirName.value = "";
    setMkdirError("");
  });
}

if (loginForm && loginUsername && loginPassword) {
  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const username = loginUsername.value.trim();
    const password = loginPassword.value;
    if (!username || !password) {
      setLoginError("请填写用户名和共享口令。");
      return;
    }
    try {
      setLoginError("");
      const response = await fetch("/api/list?path=/", {
        headers: { Authorization: encodeBasic(username, password) },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(payload.error || "登录失败");
      }
      saveCredentials(username, password);
      loginPassword.value = "";
      showManager(username);
      showStatus("", false);
      await loadList("/");
    } catch (error) {
      setLoginError(error.message);
    }
  });
}

if (logoutButton) {
  logoutButton.addEventListener("click", () => {
    clearCredentials();
    currentPath = "/";
    if (listing) {
      listing.replaceChildren();
    }
    if (empty) {
      empty.hidden = true;
    }
    showStatus("", false);
    setLoginError("");
    if (loginPassword) {
      loginPassword.value = "";
    }
    showLogin();
  });
}

const restoreSession = () => {
  const credentials = readCredentials();
  if (!credentials) {
    showLogin();
    return;
  }
  showManager(credentials.username);
  loadList("/").catch((error) => {
    clearCredentials();
    showStatus("", false);
    setLoginError(error.message);
    showLogin();
  });
};

restoreSession();
