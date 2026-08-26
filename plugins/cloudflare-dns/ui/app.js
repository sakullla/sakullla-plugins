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

const statusNode = document.querySelector("#mapping-status");
const loadingNode = document.querySelector("#mapping-loading");
const unavailableNode = document.querySelector("#mapping-unavailable");
const deniedNode = document.querySelector("#mapping-denied");
const workspaceNode = document.querySelector("#mapping-workspace");
const listNode = document.querySelector("#mapping-list");
const emptyNode = document.querySelector("#mapping-empty");
const countNode = document.querySelector("#mapping-count");
const createSection = document.querySelector("#mapping-create");
const createForm = document.querySelector("#create-form");

let busy = false;

const showStatus = (message, isError) => {
  if (!statusNode) {
    return;
  }
  statusNode.hidden = !message;
  statusNode.textContent = message;
  statusNode.dataset.error = isError ? "true" : "false";
};

const confirmAction = (suffix, action) => window.confirm(`确认对 ${suffix} 执行${action}？取消不会更改映射。`);

const newOperationKey = () => {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return `operation/ui/${Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("")}`;
};

const sendJSON = async (path, body) => {
  const response = await fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-NRE-Operation-Key": newOperationKey(),
    },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || "保存失败");
  }
  return payload;
};

const setBusy = (form, next) => {
  busy = next;
  form.querySelectorAll("button, input").forEach((node) => {
    node.disabled = next;
  });
};

const bindForm = (form) => {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) {
      return;
    }
    const action = form.dataset.action;
    const current = form.dataset.suffix || "";
    const data = new FormData(form);
    const suffix = String(data.get("suffix") || current).trim();
    const token = String(data.get("token") || "");
    const label = form.querySelector("button[type='submit']").textContent;
    if ((action === "delete" || action === "rotate" || action === "rename") && !confirmAction(current, label)) {
      showStatus("已取消，映射未更改。", false);
      return;
    }
    setBusy(form, true);
    try {
      if (action === "create") {
        await sendJSON("api/mappings", { suffix, token });
      } else if (action === "rename") {
        await sendJSON(`api/mappings/${encodeURIComponent(current)}/rename`, { suffix, confirm: current });
      } else if (action === "rotate") {
        await sendJSON(`api/mappings/${encodeURIComponent(current)}/rotate`, { token, confirm: current });
      } else if (action === "delete") {
        await sendJSON(`api/mappings/${encodeURIComponent(current)}/delete`, { confirm: current });
      }
      form.reset();
      await refreshMappings();
      showStatus(action === "delete" ? "已删除映射。" : "已保存映射。", false);
    } catch (error) {
      showStatus(error.message, true);
    } finally {
      setBusy(form, false);
    }
  });
};

const actionForm = (action, suffix, label, input) => {
  const form = document.createElement("form");
  form.className = "inline";
  form.method = "post";
  form.dataset.action = action;
  form.dataset.suffix = suffix;
  if (input) {
    const fieldLabel = document.createElement("label");
    fieldLabel.append(input.label, " ");
    const field = document.createElement("input");
    field.name = input.name;
    field.required = true;
    field.autocomplete = input.autocomplete;
    field.type = input.type;
    field.spellcheck = false;
    fieldLabel.append(field);
    form.append(fieldLabel);
  }
  const button = document.createElement("button");
  button.type = "submit";
  button.textContent = label;
  button.className = action === "delete" ? "btn-link danger" : "btn-primary";
  form.append(button);
  if (action !== "delete") {
    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.className = "btn-link";
    cancel.textContent = "取消";
    cancel.addEventListener("click", () => {
      const row = form.closest("tr");
      if (row) {
        closeEditors(row.previousElementSibling);
      }
    });
    form.append(cancel);
  }
  bindForm(form);
  return form;
};

const closeEditors = (row) => {
  if (!row) {
    return;
  }
  const table = row.closest("table");
  table.querySelectorAll(".editor-row").forEach((node) => {
    node.hidden = true;
  });
  table.querySelectorAll("[data-editor]").forEach((node) => {
    node.classList.remove("is-open");
    node.setAttribute("aria-expanded", "false");
  });
};

const openEditor = (row, name) => {
  const next = row.nextElementSibling;
  const already = next && !next.hidden && next.dataset.editor === name;
  closeEditors(row);
  if (already || !next) {
    return;
  }
  next.hidden = false;
  next.dataset.editor = name;
  next.querySelectorAll(".editor").forEach((node) => {
    node.hidden = node.dataset.editor !== name;
  });
  const toggle = row.querySelector(`[data-editor="${name}"]`);
  if (toggle) {
    toggle.classList.add("is-open");
    toggle.setAttribute("aria-expanded", "true");
  }
};

const toggleButton = (label, editor) => {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "btn-link";
  button.dataset.editor = editor;
  button.setAttribute("aria-expanded", "false");
  button.textContent = label;
  button.addEventListener("click", (event) => {
    const row = event.currentTarget.closest("tr");
    if (row) {
      openEditor(row, editor);
    }
  });
  return button;
};

const renderMapping = (mapping, canWrite, canRotate) => {
  const row = document.createElement("tr");
  row.className = "mapping";
  row.dataset.suffix = mapping.suffix;

  const suffix = document.createElement("td");
  suffix.className = "suffix";
  suffix.textContent = mapping.suffix;

  const status = document.createElement("td");
  status.className = "status";
  const statusText = document.createElement("span");
  statusText.className = mapping.configured ? "status-ok" : "status-off";
  statusText.textContent = mapping.configured ? "已配置" : "未配置";
  status.append(statusText);

  const revision = document.createElement("td");
  revision.className = "revision";
  revision.textContent = mapping.updated_at ? String(mapping.updated_at) : "-";

  const actions = document.createElement("td");
  actions.className = "actions";
  const toolbar = document.createElement("div");
  toolbar.className = "toolbar";

  if (canWrite) {
    toolbar.append(toggleButton("改后缀", "rename"));
  }
  if (canRotate) {
    toolbar.append(toggleButton("轮换 Token", "rotate"));
  }
  if (canWrite) {
    toolbar.append(actionForm("delete", mapping.suffix, "删除"));
  }
  if (toolbar.childElementCount) {
    actions.append(toolbar);
  }

  row.append(suffix, status, revision, actions);
  if (!canWrite && !canRotate) {
    return [row];
  }

  const editorRow = document.createElement("tr");
  editorRow.className = "editor-row";
  editorRow.hidden = true;
  const editorCell = document.createElement("td");
  editorCell.colSpan = 4;

  if (canWrite) {
    const rename = document.createElement("div");
    rename.className = "editor";
    rename.dataset.editor = "rename";
    rename.hidden = true;
    rename.append(actionForm("rename", mapping.suffix, "保存后缀", { label: "新后缀", name: "suffix", type: "text", autocomplete: "off" }));
    editorCell.append(rename);
  }
  if (canRotate) {
    const rotate = document.createElement("div");
    rotate.className = "editor";
    rotate.dataset.editor = "rotate";
    rotate.hidden = true;
    rotate.append(actionForm("rotate", mapping.suffix, "保存 Token", { label: "新 Token", name: "token", type: "password", autocomplete: "new-password" }));
    editorCell.append(rotate);
  }
  editorRow.append(editorCell);
  return [row, editorRow];
};

const renderMappings = (payload) => {
  const mappings = Array.isArray(payload.mappings) ? payload.mappings : [];
  const access = payload.access || {};
  const canWrite = access.can_write === true;
  const canRotate = access.can_rotate === true;
  createSection.hidden = !canWrite;
  emptyNode.hidden = mappings.length !== 0;
  countNode.hidden = mappings.length === 0;
  countNode.textContent = mappings.length ? `${mappings.length} 条` : "";
  listNode.replaceChildren();
  if (mappings.length === 0) {
    return;
  }
  const table = document.createElement("table");
  const head = document.createElement("thead");
  head.innerHTML = "<tr><th>域名后缀</th><th>状态</th><th>修订</th><th>操作</th></tr>";
  const body = document.createElement("tbody");
  for (const mapping of mappings) {
    body.append(...renderMapping(mapping, canWrite, canRotate));
  }
  table.append(head, body);
  listNode.append(table);
};

const refreshMappings = async () => {
  const response = await fetch("api/mappings", { headers: { "Accept": "application/json" } });
  const payload = await response.json().catch(() => ({}));
  if (response.status === 403) {
    throw new Error("无权访问 Cloudflare 域名 Token 映射，请求已被明确拒绝。");
  }
  if (!response.ok) {
    throw new Error(payload.error || "刷新映射失败");
  }
  renderMappings(payload);
  return payload;
};

const loadMappings = async () => {
  try {
    await refreshMappings();
    loadingNode.hidden = true;
    workspaceNode.hidden = false;
  } catch (error) {
    loadingNode.hidden = true;
    if (String(error.message).includes("明确拒绝")) {
      deniedNode.hidden = false;
      return;
    }
    unavailableNode.hidden = false;
  }
};

if (createForm) {
  bindForm(createForm);
}

loadMappings();
