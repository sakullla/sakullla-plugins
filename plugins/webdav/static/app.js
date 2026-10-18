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
const statusRow = document.querySelector(".file-status-row");
const statusRetry = document.querySelector("#status-retry");
const listingRegion = document.querySelector("#listing-region");
const listingLoading = document.querySelector("#listing-loading");

let currentPath = "/";
let renameTarget = null;
let listBusy = false;

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
  if (statusRow) {
    statusRow.hidden = !message;
  }
  if (statusRetry) {
    statusRetry.hidden = !(message && tone === "error");
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

const resetManagerState = () => {
  currentPath = "/";
  renameTarget = null;
  closeDialog(mkdirDialog);
  closeDialog(renameDialog);
  if (listing) {
    listing.replaceChildren();
  }
  if (tableWrap) {
    tableWrap.hidden = true;
  }
  if (empty) {
    empty.hidden = true;
  }
  if (listingLoading) {
    listingLoading.hidden = true;
  }
  if (listingRegion) {
    listingRegion.removeAttribute("aria-busy");
  }
  [uploadButton, mkdirButton].forEach((button) => {
    if (button) {
      button.disabled = false;
    }
  });
  listBusy = false;
  showStatus("", "");
};

const setListBusy = (busy) => {
  listBusy = busy;
  if (listingRegion) {
    if (busy) {
      listingRegion.setAttribute("aria-busy", "true");
    } else {
      listingRegion.removeAttribute("aria-busy");
    }
  }
  if (listingLoading) {
    listingLoading.hidden = !busy;
  }
  if (busy) {
    if (tableWrap) {
      tableWrap.hidden = true;
    }
    if (empty) {
      empty.hidden = true;
    }
  }
  if (crumbs) {
    crumbs.querySelectorAll("button").forEach((button) => {
      button.disabled = busy;
    });
  }
  if (listing) {
    listing.querySelectorAll(".file-name-button").forEach((button) => {
      button.disabled = busy;
    });
  }
  [uploadButton, mkdirButton].forEach((button) => {
    if (button) {
      button.disabled = busy;
    }
  });
};

class ApiFailure extends Error {
  constructor(code, details) {
    super(code || "api_failure");
    this.name = "ApiFailure";
    this.code = code || "";
    this.status = details && details.status ? details.status : 0;
    this.kind = (details && details.kind) || "api";
    this.cause = details && details.cause;
  }
}

const apiErrorMessages = {
  unauthorized: "共享口令不正确，请重新输入。",
  "path is not found": "找不到这个路径，可能已被移动或删除。",
  "path is not a directory": "这个路径不是目录，请返回上一级重试。",
  "directory cannot be listed": "目录暂时无法列出，请稍后重试。",
  "path is a directory": "这是一个目录，不能作为文件下载。",
  "upload is invalid": "上传内容无效，请选择文件后重试。",
  "upload name is invalid": "文件名称无效，请改名后重试。",
  "path is invalid": "路径无效，请检查名称后重试。",
  "directory cannot be created": "目录创建失败，可能已存在同名项。",
  "rename is invalid": "重命名参数无效，请检查名称后重试。",
  "rename failed": "重命名没有完成，请稍后重试。",
  "delete failed": "删除没有完成，请稍后重试。",
  "file cannot be written": "文件写入失败，请检查磁盘空间后重试。",
  "path is outside the share root": "路径超出共享目录范围，请返回共享根后重试。",
  "request is invalid": "请求无效，请刷新页面后重试。",
};

const failureMessage = (error) => {
  if (!error) {
    return "操作没有完成，请稍后重试。";
  }
  if (error.kind === "network") {
    return "网络不可用，请检查连接后重试。";
  }
  if (error.status === 401) {
    return apiErrorMessages.unauthorized;
  }
  if (error.status === 403) {
    return "没有权限执行这个操作，请重新输入共享口令。";
  }
  return apiErrorMessages[error.code] || "操作没有完成，请稍后重试。";
};

const logFailure = (error) => {
  console.error("[webdav] 原始错误", error && error.cause ? error.cause : error);
};

const apiFetch = async (path, options) => {
  try {
    return await fetch(path, options);
  } catch (cause) {
    throw new ApiFailure("network", { kind: "network", cause });
  }
};

const apiFailure = async (response) => {
  const payload = await response.json().catch(() => ({}));
  const code = payload && typeof payload.error === "string" ? payload.error : "";
  console.error("[webdav] API 返回错误", response.status, code);
  return new ApiFailure(code, { status: response.status, code });
};

const requestJSON = async (path, options) => {
  const response = await apiFetch(path, options);
  if (response.status === 204) {
    return {};
  }
  if (!response.ok) {
    throw await apiFailure(response);
  }
  return response.json().catch(() => ({}));
};

const handleFailure = (error, prefix) => {
  logFailure(error);
  const message = failureMessage(error);
  if (error && error.status === 401) {
    clearCredentials();
    resetManagerState();
    setLoginError(message);
    if (loginPassword) {
      loginPassword.value = "";
    }
    showLogin();
    return { message, unauthorized: true };
  }
  showStatus((prefix ? prefix + "：" : "") + message, "error");
  return { message, unauthorized: false };
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


const pathLabel = (dir) => (dir && dir !== "/" ? dir : "共享根");

const sendJSON = async (path, body) => {
  const response = await apiFetch(path, {
    method: "POST",
    headers: withAuthHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(body),
  });
  if (response.status === 204) {
    return {};
  }
  if (!response.ok) {
    throw await apiFailure(response);
  }
  return response.json().catch(() => ({}));
};

const loadList = async (dir) => {
  const target = dir || "/";
  const previousPath = currentPath;
  const previousTableHidden = tableWrap ? tableWrap.hidden : true;
  const previousEmptyHidden = empty ? empty.hidden : true;
  currentPath = target;
  renderCrumbs(target);
  setListBusy(true);
  showStatus("正在加载 " + pathLabel(target) + "…", "");
  try {
    const payload = await requestJSON("/api/list?path=" + encodeURIComponent(target), {
      headers: withAuthHeaders(),
    });
    const entries = payload.entries || [];
    currentPath = payload.path || target;
    renderCrumbs(currentPath);
    renderListing(entries);
    if (tableWrap) {
      tableWrap.hidden = entries.length === 0;
    }
    if (empty) {
      empty.hidden = entries.length > 0;
    }
    showStatus("", "");
  } catch (error) {
    currentPath = previousPath;
    renderCrumbs(previousPath);
    if (tableWrap) {
      tableWrap.hidden = previousTableHidden;
    }
    if (empty) {
      empty.hidden = previousEmptyHidden;
    }
    throw error;
  } finally {
    setListBusy(false);
  }
};

const downloadFile = async (name) => {
  const response = await apiFetch("/api/download?path=" + encodeURIComponent(joinPath(currentPath, name)), {
    headers: withAuthHeaders(),
  });
  if (!response.ok) {
    throw await apiFailure(response);
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
      if (isCurrent || listBusy) {
        return;
      }
      showStatus("", "");
      loadList(target).catch((error) => handleFailure(error));
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

const deleteConfirmation = (entry) => {
  if (entry.dir) {
    return {
      title: "删除目录",
      message: "“" + entry.name + "” 及其中的全部内容一并删除且不可恢复？",
      confirmLabel: "删除目录",
      tone: "danger",
    };
  }
  return {
    title: "删除文件",
    message: "“" + entry.name + "”？删除后不可恢复。",
    confirmLabel: "删除文件",
    tone: "danger",
  };
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
        if (listBusy) {
          return;
        }
        showStatus("", "");
        loadList(joinPath(currentPath, entry.name)).catch((error) => handleFailure(error));
      });
    } else {
      open.addEventListener("click", () => {
        if (listBusy) {
          return;
        }
        showStatus("", "");
        downloadFile(entry.name).catch((error) => handleFailure(error));
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
      const confirmed = await confirmAction(deleteConfirmation(entry));
      if (!confirmed) {
        showStatus("已取消删除，内容未变。", "");
        return;
      }
      const kindLabel = entry.dir ? "目录" : "文件";
      let deleted = false;
      setBusy(remove, true);
      showStatus("正在删除" + kindLabel + " " + entry.name + "…", "");
      try {
        await sendJSON("/api/delete", { path: joinPath(currentPath, entry.name) });
        deleted = true;
        await loadList(currentPath);
        showStatus("已删除" + kindLabel + " " + entry.name + "。", "success");
      } catch (error) {
        handleFailure(error, deleted ? "刷新目录失败" : "删除失败");
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
  if (!file || listBusy) {
    return;
  }
  setBusy(uploadButton, true);
  showStatus("正在上传 " + file.name + "…", "");
  let uploaded = false;
  try {
    const body = new FormData();
    body.set("path", currentPath);
    body.set("file", file, file.name);
    const response = await apiFetch("/api/upload", { method: "POST", headers: withAuthHeaders(), body });
    if (!response.ok) {
      throw await apiFailure(response);
    }
    uploaded = true;
    await loadList(currentPath);
    showStatus("已上传 " + file.name + "。", "success");
  } catch (error) {
    handleFailure(error, uploaded ? "刷新目录失败" : "上传失败");
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
    let created = false;
    try {
      await sendJSON("/api/mkdir", { path: joinPath(currentPath, name) });
      created = true;
      closeDialog(mkdirDialog);
      await loadList(currentPath);
      showStatus("已新建目录。", "success");
    } catch (error) {
      const failure = handleFailure(error, created ? "刷新目录失败" : "新建目录失败");
      if (!failure.unauthorized && !created) {
        setMkdirError(failure.message);
      }
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
    let renamed = false;
    try {
      await sendJSON("/api/rename", {
        from: joinPath(currentPath, renameTarget.name),
        to: joinPath(currentPath, next),
      });
      renamed = true;
      closeDialog(renameDialog);
      await loadList(currentPath);
      showStatus("已重命名。", "success");
    } catch (error) {
      const failure = handleFailure(error, renamed ? "刷新目录失败" : "重命名失败");
      if (!failure.unauthorized && !renamed) {
        setRenameError(failure.message);
      }
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
      const payload = await requestJSON("/api/list?path=/", {
        headers: { Authorization: encodeBasic(username, password) },
      });
      saveCredentials(username, password);
      loginPassword.value = "";
      showManager(username);
      showStatus("", "");
      const entries = payload.entries || [];
      currentPath = payload.path || "/";
      renderCrumbs(currentPath);
      renderListing(entries);
      if (tableWrap) {
        tableWrap.hidden = entries.length === 0;
      }
      if (empty) {
        empty.hidden = entries.length > 0;
      }
    } catch (error) {
      logFailure(error);
      setLoginError(failureMessage(error));
    }
  });
}

if (logoutButton) {
  logoutButton.addEventListener("click", () => {
    clearCredentials();
    resetManagerState();
    setLoginError("");
    if (loginPassword) {
      loginPassword.value = "";
    }
    showLogin();
  });
}

if (statusRetry) {
  statusRetry.addEventListener("click", () => {
    if (listBusy) {
      return;
    }
    showStatus("", "");
    loadList(currentPath).catch((error) => handleFailure(error));
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
    handleFailure(error);
  });
};

restoreSession();