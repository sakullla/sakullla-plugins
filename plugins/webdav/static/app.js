/* 文件共享页面：登录、目录浏览和文件操作。
   主题（跟随系统浅色/深色）与对话框/按钮/输入框外观由 ui-kit 提供；
   本文件只负责业务请求、列表渲染和操作反馈。 */

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
const tableWrap = document.querySelector("#table-wrap");
const emptyUpload = document.querySelector("#empty-upload");
const emptyMkdir = document.querySelector("#empty-mkdir");
const crumbs = document.querySelector("#crumbs");
const statusNode = document.querySelector("#status");
const uploadButton = document.querySelector("#upload-button");
const uploadInput = document.querySelector("#upload-input");
const mkdirButton = document.querySelector("#mkdir-button");
const mkdirDialog = document.querySelector("#mkdir-dialog");
const mkdirForm = document.querySelector("#mkdir-form");
const mkdirName = document.querySelector("#mkdir-name");
const mkdirCancel = document.querySelector("#mkdir-cancel");
const mkdirSubmit = document.querySelector("#mkdir-submit");
const mkdirError = document.querySelector("#mkdir-error");
const renameDialog = document.querySelector("#rename-dialog");
const renameForm = document.querySelector("#rename-form");
const renameName = document.querySelector("#rename-name");
const renameCancel = document.querySelector("#rename-cancel");
const renameSubmit = document.querySelector("#rename-submit");
const renameError = document.querySelector("#rename-error");

let currentPath = "/";
let renameTarget = null;

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

const showStatus = (message, tone) => {
  if (!statusNode) {
    return;
  }
  statusNode.hidden = !message;
  statusNode.textContent = message || "";
  if (message && tone) {
    statusNode.dataset.tone = tone;
  } else {
    delete statusNode.dataset.tone;
  }
};

const setBusy = (node, busy) => {
  if (!node) {
    return;
  }
  if (window.NREUI && typeof window.NREUI.setBusy === "function") {
    window.NREUI.setBusy(node, busy);
    return;
  }
  if (busy) {
    node.setAttribute("aria-busy", "true");
    node.disabled = true;
  } else {
    node.removeAttribute("aria-busy");
    node.disabled = false;
  }
};

const openDialog = (dialog) => {
  if (!dialog) {
    return;
  }
  if (window.NREUI && typeof window.NREUI.openDialog === "function") {
    window.NREUI.openDialog(dialog);
    return;
  }
  if (dialog.showModal) {
    dialog.showModal();
  }
};

const closeDialog = (dialog) => {
  if (!dialog) {
    return;
  }
  if (window.NREUI && typeof window.NREUI.closeDialog === "function") {
    window.NREUI.closeDialog(dialog);
    return;
  }
  if (dialog.open && dialog.close) {
    dialog.close();
  }
};

const confirmAction = (options) => {
  if (window.NREUI && typeof window.NREUI.confirm === "function") {
    return window.NREUI.confirm(options);
  }
  return Promise.resolve(window.confirm(options.message || "确认执行？"));
};

const joinPath = (dir, name) => {
  if (!dir || dir === "/") {
    return "/" + name;
  }
  return dir.replace(/\/$/, "") + "/" + name;
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
  const entries = payload.entries || [];
  renderCrumbs(payload.path || currentPath);
  renderListing(entries);
  if (tableWrap) {
    tableWrap.hidden = entries.length === 0;
  }
  if (empty) {
    empty.hidden = entries.length > 0;
  }
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
  const add = (label, target, isCurrent) => {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = label;
    if (isCurrent) {
      button.setAttribute("aria-current", "page");
    }
    button.addEventListener("click", () => {
      if (isCurrent) {
        return;
      }
      showStatus("", "");
      loadList(target).catch((error) => showStatus(error.message, "error"));
    });
    crumbs.append(button);
  };
  add("共享根", "/", parts.length === 0);
  let prefix = "";
  parts.forEach((part, index) => {
    prefix += "/" + part;
    const sep = document.createElement("span");
    sep.className = "crumb-sep";
    sep.setAttribute("aria-hidden", "true");
    crumbs.append(sep);
    add(part, prefix, index === parts.length - 1);
  });
};

const openRename = (entry) => {
  renameTarget = entry;
  if (renameName) {
    renameName.value = entry.name;
  }
  setRenameError("");
  openDialog(renameDialog);
  if (renameName) {
    renameName.focus();
    if (typeof renameName.select === "function") {
      renameName.select();
    }
  }
};

const setRenameError = (message) => {
  if (!renameError) {
    return;
  }
  renameError.hidden = !message;
  renameError.textContent = message || "";
};

const renderListing = (entries) => {
  if (!listing) {
    return;
  }
  listing.replaceChildren();
  entries.forEach((entry) => {
    const row = document.createElement("tr");
    row.className = entry.dir ? "row-dir" : "row-file";
    const nameCell = document.createElement("td");
    const typeCell = document.createElement("td");
    const sizeCell = document.createElement("td");
    const actionCell = document.createElement("td");
    actionCell.className = "row-actions ui-table__actions";
    const typePill = document.createElement("span");
    typePill.className = "ui-badge ui-badge--plain";
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
    open.className = "file-name-button";
    const glyph = document.createElement("span");
    glyph.className = "file-glyph";
    glyph.setAttribute("aria-hidden", "true");
    const label = document.createElement("span");
    label.className = "file-name";
    label.textContent = entry.name;
    open.append(glyph, label);
    if (entry.dir) {
      open.addEventListener("click", () => {
        showStatus("", "");
        loadList(joinPath(currentPath, entry.name)).catch((error) => showStatus(error.message, "error"));
      });
    } else {
      open.addEventListener("click", () => {
        showStatus("", "");
        downloadFile(entry.name).catch((error) => showStatus(error.message, "error"));
      });
    }
    nameCell.append(open);
    const rename = document.createElement("button");
    rename.type = "button";
    rename.className = "ui-btn ui-btn--ghost ui-btn--sm";
    rename.textContent = "重命名";
    rename.addEventListener("click", () => openRename(entry));
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "ui-btn ui-btn--danger-soft ui-btn--sm";
    remove.textContent = "删除";
    remove.addEventListener("click", async () => {
      const confirmed = await confirmAction({
        title: "删除文件",
        message: "删除 " + entry.name + "？删除后不可恢复。",
        confirmLabel: "删除",
        tone: "danger",
      });
      if (!confirmed) {
        showStatus("已取消删除，内容未变。", "");
        return;
      }
      setBusy(remove, true);
      showStatus("正在删除 " + entry.name + "…", "");
      try {
        await sendJSON("/api/delete", { path: joinPath(currentPath, entry.name) });
        await loadList(currentPath);
        showStatus("已删除 " + entry.name + "。", "success");
      } catch (error) {
        showStatus("删除失败：" + error.message, "error");
      } finally {
        setBusy(remove, false);
      }
    });
    actionCell.append(rename, remove);
    row.append(nameCell, typeCell, sizeCell, actionCell);
    listing.append(row);
  });
};

const uploadFile = async (file) => {
  if (!file) {
    return;
  }
  setBusy(uploadButton, true);
  showStatus("正在上传 " + file.name + "…", "");
  try {
    const body = new FormData();
    body.set("path", currentPath);
    body.set("file", file, file.name);
    const response = await fetch("/api/upload", { method: "POST", headers: withAuthHeaders(), body });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || "上传失败");
    }
    await loadList(currentPath);
    showStatus("已上传 " + file.name + "。", "success");
  } catch (error) {
    showStatus("上传失败：" + error.message, "error");
  } finally {
    setBusy(uploadButton, false);
  }
};

if (uploadButton && uploadInput) {
  uploadButton.addEventListener("click", () => uploadInput.click());
  uploadInput.addEventListener("change", () => {
    const file = uploadInput.files && uploadInput.files[0];
    uploadInput.value = "";
    uploadFile(file);
  });
}

if (emptyUpload && uploadInput) {
  emptyUpload.addEventListener("click", () => uploadInput.click());
}

const setMkdirError = (message) => {
  if (!mkdirError) {
    return;
  }
  mkdirError.hidden = !message;
  mkdirError.textContent = message || "";
};

const openMkdir = () => {
  setMkdirError("");
  if (mkdirName) {
    mkdirName.value = "";
  }
  openDialog(mkdirDialog);
  if (mkdirName) {
    mkdirName.focus();
  }
};

if (mkdirButton) {
  mkdirButton.addEventListener("click", openMkdir);
}

if (emptyMkdir) {
  emptyMkdir.addEventListener("click", openMkdir);
}

if (mkdirDialog && mkdirForm && mkdirName) {
  mkdirForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (mkdirSubmit && mkdirSubmit.disabled) {
      return;
    }
    const name = mkdirName.value.trim();
    if (!name) {
      setMkdirError("请填写目录名称。");
      mkdirName.focus();
      return;
    }
    setBusy(mkdirSubmit, true);
    try {
      await sendJSON("/api/mkdir", { path: joinPath(currentPath, name) });
      closeDialog(mkdirDialog);
      await loadList(currentPath);
      showStatus("已新建目录。", "success");
    } catch (error) {
      setMkdirError(error.message);
      showStatus(error.message, "error");
    } finally {
      setBusy(mkdirSubmit, false);
    }
  });
  if (mkdirCancel) {
    mkdirCancel.addEventListener("click", () => closeDialog(mkdirDialog));
  }
  mkdirDialog.addEventListener("close", () => {
    mkdirName.value = "";
    setMkdirError("");
  });
}

if (renameDialog && renameForm && renameName) {
  renameForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (renameSubmit && renameSubmit.disabled) {
      return;
    }
    const next = renameName.value.trim();
    if (!next) {
      setRenameError("请填写新名称。");
      renameName.focus();
      return;
    }
    if (!renameTarget || next === renameTarget.name) {
      closeDialog(renameDialog);
      return;
    }
    setBusy(renameSubmit, true);
    try {
      await sendJSON("/api/rename", {
        from: joinPath(currentPath, renameTarget.name),
        to: joinPath(currentPath, next),
      });
      closeDialog(renameDialog);
      await loadList(currentPath);
      showStatus("已重命名。", "success");
    } catch (error) {
      setRenameError(error.message);
      showStatus(error.message, "error");
    } finally {
      setBusy(renameSubmit, false);
    }
  });
  if (renameCancel) {
    renameCancel.addEventListener("click", () => closeDialog(renameDialog));
  }
  renameDialog.addEventListener("close", () => {
    renameTarget = null;
    renameName.value = "";
    setRenameError("");
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
      showStatus("", "");
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
    renameTarget = null;
    closeDialog(mkdirDialog);
    closeDialog(renameDialog);
    if (listing) {
      listing.replaceChildren();
    }
    if (empty) {
      empty.hidden = true;
    }
    if (tableWrap) {
      tableWrap.hidden = true;
    }
    showStatus("", "");
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
    showStatus("", "");
    setLoginError(error.message);
    showLogin();
  });
};

restoreSession();