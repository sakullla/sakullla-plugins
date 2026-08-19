const statusNode = document.querySelector("#mapping-status");
const loadingNode = document.querySelector("#mapping-loading");
const unavailableNode = document.querySelector("#mapping-unavailable");
const deniedNode = document.querySelector("#mapping-denied");
const workspaceNode = document.querySelector("#mapping-workspace");
const tableNode = document.querySelector("#mapping-table");
const emptyNode = document.querySelector("#mapping-empty");
const rowTemplate = document.querySelector("#mapping-row-template");
const createSection = document.querySelector("#mapping-create");

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

const bindForm = (form) => {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const action = form.dataset.action;
    const current = form.dataset.suffix || "";
    const data = new FormData(form);
    const suffix = String(data.get("suffix") || current).trim();
    const token = String(data.get("token") || "");
    if ((action === "delete" || action === "rotate" || action === "rename") && !confirmAction(current, form.querySelector("button").textContent)) {
      showStatus("已取消，映射未更改。", false);
      return;
    }
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
      window.location.reload();
    } catch (error) {
      showStatus(error.message, true);
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
    fieldLabel.append(field);
    form.append(fieldLabel);
  }
  const button = document.createElement("button");
  button.type = "submit";
  button.textContent = label;
  form.append(button);
  bindForm(form);
  return form;
};

const renderMappings = (payload) => {
  const mappings = Array.isArray(payload.mappings) ? payload.mappings : [];
  const access = payload.access || {};
  const canWrite = access.can_write === true;
  const canRotate = access.can_rotate === true;
  document.querySelector("#mapping-actions-heading").hidden = !canWrite && !canRotate;
  tableNode.hidden = mappings.length === 0;
  emptyNode.hidden = mappings.length !== 0;
  createSection.hidden = !canWrite;
  for (const mapping of mappings) {
    const row = rowTemplate.cloneNode(true);
    row.id = "";
    row.hidden = false;
    row.dataset.suffix = mapping.suffix;
    row.querySelector('[data-field="suffix"]').textContent = mapping.suffix;
    row.querySelector('[data-field="configured"]').textContent = mapping.configured ? "是" : "否";
    row.querySelector('[data-field="updated"]').textContent = String(mapping.updated_at || "-");
    const actions = row.querySelector('[data-field="actions"]');
    actions.hidden = !canWrite && !canRotate;
    if (canWrite) {
      actions.append(
        actionForm("rename", mapping.suffix, "改后缀", { label: "新后缀", name: "suffix", type: "text", autocomplete: "off" }),
        actionForm("delete", mapping.suffix, "删除"),
      );
    }
    if (canRotate) {
      actions.append(actionForm("rotate", mapping.suffix, "轮换 Token", { label: "新 Token", name: "token", type: "password", autocomplete: "new-password" }));
    }
    rowTemplate.parentNode.append(row);
  }
  bindForm(document.querySelector("#create-form"));
};

const loadMappings = async () => {
  try {
    const response = await fetch("api/mappings", { headers: { "Accept": "application/json" } });
    const payload = await response.json().catch(() => ({}));
    loadingNode.hidden = true;
    if (response.status === 403) {
      deniedNode.hidden = false;
      return;
    }
    if (!response.ok) {
      unavailableNode.hidden = false;
      return;
    }
    workspaceNode.hidden = false;
    renderMappings(payload);
  } catch (_error) {
    loadingNode.hidden = true;
    unavailableNode.hidden = false;
  }
};

loadMappings();
