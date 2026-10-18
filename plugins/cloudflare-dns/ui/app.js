"use strict";

const providerNames = {
  cloudflare: "Cloudflare",
  aliyun: "阿里云解析",
  "dnspod-cn": "DNSPod .cn",
  "dnspod-com": "DNSPod .com",
  "tencent-dns": "腾讯云 DNS",
};

const credentialFields = {
  cloudflare: ["token"],
  aliyun: ["access_key_id", "access_key_secret"],
  "dnspod-cn": ["token_id", "token"],
  "dnspod-com": ["token_id", "token"],
  "tencent-dns": ["secret_id", "secret_key"],
};

const credentialLabels = {
  access_key_id: "AccessKey ID",
  access_key_secret: "AccessKey Secret",
  token_id: "Token ID",
  token: "Token",
  secret_id: "SecretId",
  secret_key: "SecretKey",
};

const tokenLabels = {
  cloudflare: "Cloudflare DNS Token",
  "dnspod-cn": "Token",
  "dnspod-com": "Token",
};

const textFields = new Set(["access_key_id", "token_id", "secret_id"]);

const nodes = {
  loading: document.getElementById("mapping-loading"),
  error: document.getElementById("mapping-error"),
  errorDesc: document.getElementById("mapping-error-desc"),
  retry: document.getElementById("mapping-retry"),
  unavailable: document.getElementById("mapping-unavailable"),
  denied: document.getElementById("mapping-denied"),
  workspace: document.getElementById("mapping-workspace"),
  addButton: document.getElementById("mapping-add"),
  search: document.getElementById("mapping-search"),
  count: document.getElementById("mapping-count"),
  refresh: document.getElementById("mapping-refresh"),
  status: document.getElementById("mapping-status"),
  list: document.getElementById("mapping-list"),
  empty: document.getElementById("mapping-empty"),
  emptyDesc: document.getElementById("mapping-empty-desc"),
  emptyAdd: document.getElementById("mapping-empty-add"),
  filterEmpty: document.getElementById("mapping-filter-empty"),
  clearFilter: document.getElementById("mapping-clear-filter"),
  createDialog: document.getElementById("mapping-create"),
  createForm: document.getElementById("create-form"),
  createError: document.getElementById("create-error"),
  renameDialog: document.getElementById("mapping-rename"),
  renameForm: document.getElementById("rename-form"),
  renameError: document.getElementById("rename-error"),
  renameCurrent: document.getElementById("rename-current"),
  rotateDialog: document.getElementById("mapping-rotate"),
  rotateForm: document.getElementById("rotate-form"),
  rotateError: document.getElementById("rotate-error"),
  rotateCurrent: document.getElementById("rotate-current"),
  rotateFields: document.getElementById("rotate-fields"),
};

const state = {
  mappings: [],
  access: { can_write: false, can_rotate: false },
  filter: "",
};

const providerID = (mapping) => String((mapping && mapping.provider) || "cloudflare");

const fieldsFor = (provider) => credentialFields[provider] || credentialFields.cloudflare;

const openDialog = (dialog) => {
  if (!dialog) return;
  if (window.NREUI && window.NREUI.openDialog) {
    window.NREUI.openDialog(dialog);
  } else if (dialog.showModal) {
    dialog.showModal();
  }
};

const closeDialog = (dialog) => {
  if (!dialog) return;
  if (window.NREUI && window.NREUI.closeDialog) {
    window.NREUI.closeDialog(dialog);
  } else if (dialog.close && dialog.open) {
    dialog.close();
  }
};

const confirmAction = (options) => {
  if (window.NREUI && window.NREUI.confirm) {
    return window.NREUI.confirm(options);
  }
  return Promise.resolve(window.confirm(options.message));
};

const newOperationKey = () => {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return `operation/ui/${Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("")}`;
};

const request = async (path, options) => {
  const response = await fetch(path, options || {});
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.error || "请求失败，请稍后重试。");
    error.status = response.status;
    throw error;
  }
  return payload;
};

const sendJSON = (path, body) => request(path, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-NRE-Operation-Key": newOperationKey(),
  },
  body: JSON.stringify(body),
});

const showStatus = (message, tone) => {
  if (!nodes.status) return;
  if (!message) {
    nodes.status.hidden = true;
    nodes.status.textContent = "";
    return;
  }
  nodes.status.hidden = false;
  nodes.status.textContent = message;
  nodes.status.dataset.tone = tone || "neutral";
};

const clearFormError = (node) => {
  if (!node) return;
  node.textContent = "";
  node.hidden = true;
};

const showFormError = (node, message) => {
  if (!node) return;
  node.textContent = String(message || "保存失败，请稍后重试。");
  node.hidden = false;
};

const isBusy = (form) => form.dataset.busy === "true";

const setFormBusy = (form, busy) => {
  form.dataset.busy = busy ? "true" : "false";
  const submit = form.querySelector("button[type='submit']");
  if (window.NREUI && window.NREUI.setBusy) {
    window.NREUI.setBusy(submit, busy);
  } else if (submit) {
    submit.disabled = busy;
  }
};

const syncCredentialFields = (form) => {
  const provider = String(new FormData(form).get("provider") || form.dataset.provider || "cloudflare");
  const active = new Set(fieldsFor(provider));
  form.querySelectorAll("[data-credential]").forEach((field) => {
    const name = field.getAttribute("data-credential");
    const enabled = active.has(name);
    field.hidden = !enabled;
    field.querySelectorAll("input").forEach((input) => {
      input.disabled = !enabled;
      input.required = enabled;
    });
    if (name === "token") {
      const label = field.querySelector(".ui-label");
      if (label) label.textContent = tokenLabels[provider] || "Token";
    }
  });
};

const credentialField = (name, provider) => {
  const field = document.createElement("label");
  field.className = "ui-field ui-field--full";
  const label = document.createElement("span");
  label.className = "ui-label";
  label.textContent = name === "token" ? (tokenLabels[provider] || "Token") : credentialLabels[name];
  const input = document.createElement("input");
  input.className = "ui-input";
  input.name = name;
  input.type = textFields.has(name) ? "text" : "password";
  input.autocomplete = textFields.has(name) ? "off" : "new-password";
  input.spellcheck = false;
  input.required = true;
  field.append(label, input);
  return field;
};

const matches = (mapping, needle) => {
  if (!needle) return true;
  const provider = providerID(mapping);
  return `${mapping.suffix || ""} ${providerNames[provider] || provider}`.toLowerCase().includes(needle);
};

const rowAction = (action, label, mapping, extraClass) => {
  const button = document.createElement("button");
  button.type = "button";
  button.className = `ui-btn ui-btn--sm ${extraClass}`;
  button.setAttribute("data-row-action", action);
  button.setAttribute("data-suffix", mapping.suffix || "");
  button.setAttribute("data-provider", providerID(mapping));
  button.setAttribute("aria-label", `${label} ${mapping.suffix || ""}`.trim());
  button.textContent = label;
  return button;
};

const cell = (className, text) => {
  const node = document.createElement("td");
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};

const buildRow = (mapping, canWrite, canRotate) => {
  const provider = providerID(mapping);
  const row = document.createElement("tr");
  row.className = "mapping";
  row.dataset.suffix = mapping.suffix || "";

  const suffix = cell("mapping-suffix", mapping.suffix || "");
  const providerCell = cell("mapping-provider", providerNames[provider] || provider);

  const statusCell = cell("mapping-status");
  const badge = document.createElement("span");
  badge.className = `ui-badge ${mapping.configured ? "ui-badge--success" : "ui-badge--warning"}`;
  badge.textContent = mapping.configured ? "已配置" : "未配置";
  statusCell.append(badge);

  const revision = cell("mapping-revision", mapping.updated_at ? `修订 #${mapping.updated_at}` : "—");

  const actions = cell("ui-table__actions mapping-actions");
  if (canWrite) actions.append(rowAction("rename", "改后缀", mapping, "ui-btn--ghost"));
  if (canRotate) actions.append(rowAction("rotate", "轮换凭证", mapping, "ui-btn--ghost"));
  if (canWrite) actions.append(rowAction("delete", "删除", mapping, "ui-btn--danger-soft"));
  if (!canWrite && !canRotate) {
    const readOnly = document.createElement("span");
    readOnly.className = "ui-tertiary";
    readOnly.textContent = "只读";
    actions.append(readOnly);
  }

  row.append(suffix, providerCell, statusCell, revision, actions);
  return row;
};

const buildTable = (mappings, canWrite, canRotate) => {
  const wrap = document.createElement("div");
  wrap.className = "ui-table-wrap";
  const table = document.createElement("table");
  table.className = "ui-table";
  table.setAttribute("aria-label", "已保存的域名后缀映射");

  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  const headers = [
    ["域名后缀", ""],
    ["服务商", ""],
    ["状态", ""],
    ["修订", "ui-table__num"],
    ["操作", "ui-table__actions"],
  ];
  for (const [label, className] of headers) {
    const th = document.createElement("th");
    th.scope = "col";
    if (className) th.className = className;
    th.textContent = label;
    headRow.append(th);
  }
  thead.append(headRow);

  const body = document.createElement("tbody");
  for (const mapping of mappings) {
    body.append(buildRow(mapping, canWrite, canRotate));
  }
  table.append(thead, body);
  wrap.append(table);
  return wrap;
};

const render = () => {
  const canWrite = state.access.can_write === true;
  const canRotate = state.access.can_rotate === true;
  nodes.addButton.hidden = !canWrite;
  nodes.emptyAdd.hidden = !canWrite;
  nodes.emptyDesc.textContent = canWrite
    ? "添加第一条域名后缀映射后，DNS 查询会使用对应服务商的凭证。"
    : "还没有映射。当前账号只有查看权限，请联系管理员添加。";

  const needle = state.filter.trim().toLowerCase();
  const total = state.mappings.length;
  const visible = state.mappings.filter((mapping) => matches(mapping, needle));
  nodes.count.textContent = needle && visible.length !== total
    ? `筛选 ${visible.length} / ${total} 条`
    : `${total} 条映射`;

  nodes.list.replaceChildren();
  nodes.list.hidden = false;
  nodes.empty.hidden = total !== 0;
  nodes.filterEmpty.hidden = true;

  if (total === 0) {
    nodes.list.hidden = true;
    return;
  }
  if (visible.length === 0) {
    nodes.list.hidden = true;
    nodes.filterEmpty.hidden = false;
    return;
  }
  nodes.list.append(buildTable(visible, canWrite, canRotate));
};

const refreshMappings = async () => {
  const payload = await request("api/mappings", { headers: { Accept: "application/json" } });
  state.mappings = Array.isArray(payload.mappings) ? payload.mappings : [];
  const access = payload.access || {};
  state.access = { can_write: access.can_write === true, can_rotate: access.can_rotate === true };
  render();
};

const setState = (name) => {
  nodes.loading.hidden = name !== "loading";
  nodes.error.hidden = name !== "error";
  nodes.unavailable.hidden = name !== "unavailable";
  nodes.denied.hidden = name !== "denied";
  nodes.workspace.hidden = name !== "ready";
};

const load = async () => {
  setState("loading");
  try {
    await refreshMappings();
    setState("ready");
  } catch (error) {
    if (error.status === 403) {
      setState("denied");
      return;
    }
    if (error.status === 503) {
      setState("unavailable");
      return;
    }
    nodes.errorDesc.textContent = error.message || "请重试；如果持续失败，请检查宿主连接后刷新页面。";
    setState("error");
  }
};

const refreshAfterWrite = async (message) => {
  try {
    await refreshMappings();
    showStatus(message, "success");
  } catch (error) {
    showStatus(`${message}但列表刷新失败：${error.message}`, "danger");
  }
};

const openCreate = () => {
  nodes.createForm.reset();
  syncCredentialFields(nodes.createForm);
  clearFormError(nodes.createError);
  showStatus("");
  openDialog(nodes.createDialog);
};

const openRename = (mapping) => {
  nodes.renameForm.reset();
  nodes.renameForm.dataset.suffix = mapping.suffix || "";
  nodes.renameCurrent.textContent = mapping.suffix || "";
  clearFormError(nodes.renameError);
  showStatus("");
  openDialog(nodes.renameDialog);
};

const openRotate = (mapping) => {
  const provider = providerID(mapping);
  nodes.rotateForm.reset();
  nodes.rotateForm.dataset.suffix = mapping.suffix || "";
  nodes.rotateForm.dataset.provider = provider;
  nodes.rotateCurrent.textContent = mapping.suffix || "";
  nodes.rotateFields.replaceChildren(...fieldsFor(provider).map((name) => credentialField(name, provider)));
  clearFormError(nodes.rotateError);
  showStatus("");
  openDialog(nodes.rotateDialog);
};

const removeMapping = async (mapping) => {
  const current = mapping.suffix || "";
  const confirmed = await confirmAction({
    title: "删除映射",
    message: `确认对 ${current} 执行删除？删除后该后缀的查询会失去映射，取消不会更改映射。`,
    confirmLabel: "删除映射",
    tone: "danger",
  });
  if (!confirmed) {
    showStatus("已取消，映射未更改。", "neutral");
    return;
  }
  try {
    await sendJSON(`api/mappings/${encodeURIComponent(current)}/delete`, { confirm: current });
    await refreshAfterWrite("已删除映射。");
  } catch (error) {
    showStatus(error.message, "danger");
  }
};

nodes.list.addEventListener("click", (event) => {
  const trigger = event.target.closest ? event.target.closest("[data-row-action]") : null;
  if (!trigger || !nodes.list.contains(trigger)) return;
  const suffix = trigger.getAttribute("data-suffix") || "";
  const mapping = state.mappings.find((item) => item.suffix === suffix);
  if (!mapping) return;
  const action = trigger.getAttribute("data-row-action");
  if (action === "rename") {
    openRename(mapping);
  } else if (action === "rotate") {
    openRotate(mapping);
  } else if (action === "delete") {
    void removeMapping(mapping);
  }
});

document.addEventListener("click", (event) => {
  const trigger = event.target.closest ? event.target.closest("[data-open-create]") : null;
  if (!trigger) return;
  openCreate();
});

document.querySelectorAll("[data-ui-close]").forEach((button) => {
  button.addEventListener("click", () => {
    closeDialog(button.closest("dialog"));
  });
});

nodes.search.addEventListener("input", () => {
  state.filter = nodes.search.value;
  render();
});

nodes.clearFilter.addEventListener("click", () => {
  nodes.search.value = "";
  state.filter = "";
  render();
  nodes.search.focus();
});

nodes.refresh.addEventListener("click", async () => {
  nodes.refresh.disabled = true;
  try {
    await refreshMappings();
    showStatus("已刷新映射列表。", "neutral");
  } catch (error) {
    showStatus(error.message, "danger");
  } finally {
    nodes.refresh.disabled = false;
  }
});

nodes.retry.addEventListener("click", () => {
  void load();
});

nodes.createForm.querySelector("select[name='provider']").addEventListener("change", () => {
  syncCredentialFields(nodes.createForm);
});

nodes.createForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (isBusy(nodes.createForm) || !nodes.createForm.reportValidity()) return;
  const data = new FormData(nodes.createForm);
  const provider = String(data.get("provider") || "cloudflare");
  const body = {
    suffix: String(data.get("suffix") || "").trim(),
    provider,
  };
  for (const name of fieldsFor(provider)) {
    body[name] = String(data.get(name) || "");
  }
  clearFormError(nodes.createError);
  setFormBusy(nodes.createForm, true);
  try {
    await sendJSON("api/mappings", body);
    closeDialog(nodes.createDialog);
    await refreshAfterWrite("已添加映射。");
  } catch (error) {
    showFormError(nodes.createError, error.message);
  } finally {
    setFormBusy(nodes.createForm, false);
  }
});

nodes.renameForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (isBusy(nodes.renameForm) || !nodes.renameForm.reportValidity()) return;
  const current = nodes.renameForm.dataset.suffix || "";
  const next = String(new FormData(nodes.renameForm).get("suffix") || "").trim();
  if (!current || !next) return;
  clearFormError(nodes.renameError);
  setFormBusy(nodes.renameForm, true);
  try {
    await sendJSON(`api/mappings/${encodeURIComponent(current)}/rename`, { suffix: next, confirm: current });
    closeDialog(nodes.renameDialog);
    await refreshAfterWrite("已修改域名后缀。");
  } catch (error) {
    showFormError(nodes.renameError, error.message);
  } finally {
    setFormBusy(nodes.renameForm, false);
  }
});

nodes.rotateForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (isBusy(nodes.rotateForm) || !nodes.rotateForm.reportValidity()) return;
  const current = nodes.rotateForm.dataset.suffix || "";
  const provider = nodes.rotateForm.dataset.provider || "cloudflare";
  if (!current) return;
  const data = new FormData(nodes.rotateForm);
  const body = { confirm: current, provider };
  for (const name of fieldsFor(provider)) {
    body[name] = String(data.get(name) || "");
  }
  clearFormError(nodes.rotateError);
  setFormBusy(nodes.rotateForm, true);
  try {
    await sendJSON(`api/mappings/${encodeURIComponent(current)}/rotate`, body);
    closeDialog(nodes.rotateDialog);
    await refreshAfterWrite("凭证已轮换，页面不会回显。");
  } catch (error) {
    showFormError(nodes.rotateError, error.message);
  } finally {
    setFormBusy(nodes.rotateForm, false);
  }
});

nodes.createDialog.addEventListener("close", () => {
  nodes.createForm.reset();
  syncCredentialFields(nodes.createForm);
  clearFormError(nodes.createError);
  nodes.createForm.dataset.busy = "false";
});

nodes.renameDialog.addEventListener("close", () => {
  nodes.renameForm.reset();
  clearFormError(nodes.renameError);
  nodes.renameForm.dataset.busy = "false";
  delete nodes.renameForm.dataset.suffix;
});

nodes.rotateDialog.addEventListener("close", () => {
  nodes.rotateForm.reset();
  nodes.rotateFields.replaceChildren();
  clearFormError(nodes.rotateError);
  nodes.rotateForm.dataset.busy = "false";
  delete nodes.rotateForm.dataset.suffix;
  delete nodes.rotateForm.dataset.provider;
});

void load();