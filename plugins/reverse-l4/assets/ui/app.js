const applyHostTheme = () => {
  const allowed = { "sakura-day": true, "sakura-night": true };
  const aliases = { sakura: "sakura-day", midnight: "sakura-night", "neko-dark": "sakura-night", cyberpunk: "sakura-day" };
  let theme = "sakura-day";
  try {
    const raw = window.parent && window.parent !== window
      ? window.parent.document.documentElement.getAttribute("data-theme")
      : document.documentElement.getAttribute("data-theme");
    const mapped = aliases[raw] || raw;
    if (allowed[mapped]) theme = mapped;
  } catch (_error) {
    theme = "sakura-day";
  }
  document.documentElement.setAttribute("data-theme", theme);
};

applyHostTheme();

const statusNode = document.querySelector("#map-status");
const loadingNode = document.querySelector("#map-loading");
const unavailableNode = document.querySelector("#map-unavailable");
const deniedNode = document.querySelector("#map-denied");
const workspaceNode = document.querySelector("#map-workspace");
const listNode = document.querySelector("#map-list");
const emptyNode = document.querySelector("#map-empty");
const countNode = document.querySelector("#map-count");
const formPanel = document.querySelector("#map-form");
const formTitle = document.querySelector("#map-form-title");
const formNode = document.querySelector("#mapping-form");
const formSubmit = document.querySelector("#form-submit");
const formCancel = document.querySelector("#form-cancel");
const createToggle = document.querySelector("#create-toggle");

let busy = false;
let editingID = "";

const panelAuthHeaders = () => {
  const headers = { "Content-Type": "application/json" };
  try {
    const session = window.localStorage.getItem("panel_session");
    const token = window.localStorage.getItem("panel_token");
    if (session) headers.Authorization = `Bearer ${session}`;
    else if (token) headers["X-Panel-Token"] = token;
  } catch (_error) {
    // Cookie-only same-origin auth still applies.
  }
  return headers;
};

const showStatus = (message, isError) => {
  if (!statusNode) return;
  statusNode.hidden = !message;
  statusNode.textContent = message;
  statusNode.dataset.error = isError ? "true" : "false";
};

const newOperationKey = () => {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return `operation/ui/${Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("")}`;
};

const pluginJSON = async (path, options = {}) => {
  const headers = { ...panelAuthHeaders(), ...(options.headers || {}) };
  if (!options.method || options.method === "POST") {
    headers["X-NRE-Operation-Key"] = newOperationKey();
  }
  const response = await fetch(path, { credentials: "same-origin", ...options, headers });
  const payload = await response.json().catch(() => ({}));
  if (response.status === 403) {
    throw Object.assign(new Error(payload.error || payload.message || "无权访问"), { denied: true });
  }
  if (!response.ok) {
    throw new Error(payload.error || payload.message || "请求失败");
  }
  return payload;
};

const setBusy = (next) => {
  busy = next;
  workspaceNode.querySelectorAll("button, input, select").forEach((node) => {
    node.disabled = next;
  });
};

const chip = (text, className) => {
  const node = document.createElement("span");
  node.className = className ? `chip ${className}` : "chip";
  node.textContent = text;
  return node;
};

const channelChip = (mapping) => {
  if (mapping.channel_state === "online") return chip("通道在线", "chip-state-online");
  if (mapping.channel_state === "offline") return chip("通道离线", "chip-state-offline");
  return chip("通道未知", "chip-state-unknown");
};

const parseRelayChain = (raw) => String(raw || "")
  .split(",")
  .map((part) => Number(part.trim()))
  .filter((hop) => Number.isInteger(hop) && hop > 0);

const formMapping = () => {
  const data = new FormData(formNode);
  return {
    id: String(data.get("id") || "").trim(),
    name: String(data.get("name") || "").trim(),
    entry_agent_id: String(data.get("entry_agent_id") || "").trim(),
    exit_agent_id: String(data.get("exit_agent_id") || "").trim(),
    protocol: String(data.get("protocol") || "tcp").trim(),
    listen_port: Number(data.get("listen_port") || 0),
    backend_host: String(data.get("backend_host") || "").trim(),
    backend_port: Number(data.get("backend_port") || 0),
    relay_chain: parseRelayChain(data.get("relay_chain")),
  };
};

const openForm = (mapping) => {
  editingID = mapping ? String(mapping.id || "") : "";
  formTitle.textContent = editingID ? "编辑映射" : "新建映射";
  formSubmit.textContent = editingID ? "保存" : "创建";
  formNode.reset();
  if (editingID) {
    formNode.querySelector('input[name="id"]').value = mapping.id;
    formNode.querySelector('input[name="id"]').readOnly = true;
    formNode.querySelector('input[name="name"]').value = mapping.name || "";
    formNode.querySelector('select[name="protocol"]').value = mapping.protocol || "tcp";
    formNode.querySelector('input[name="entry_agent_id"]').value = mapping.entry_agent_id || "";
    formNode.querySelector('input[name="exit_agent_id"]').value = mapping.exit_agent_id || "";
    formNode.querySelector('input[name="listen_port"]').value = mapping.listen_port || "";
    formNode.querySelector('input[name="backend_host"]').value = mapping.backend_host || "";
    formNode.querySelector('input[name="backend_port"]').value = mapping.backend_port || "";
    formNode.querySelector('input[name="relay_chain"]').value = Array.isArray(mapping.relay_chain) && mapping.relay_chain.length
      ? mapping.relay_chain.join(", ")
      : "";
  } else {
    formNode.querySelector('input[name="id"]').readOnly = false;
  }
  formPanel.hidden = false;
  createToggle.hidden = true;
  formNode.querySelector('input[name="id"]').focus();
};

const closeForm = () => {
  editingID = "";
  formNode.reset();
  formNode.querySelector('input[name="id"]').readOnly = false;
  formTitle.textContent = "新建映射";
  formSubmit.textContent = "创建";
  formPanel.hidden = true;
  createToggle.hidden = false;
};

const refresh = async () => {
  const payload = await pluginJSON("api/mappings");
  renderMappings(payload.mappings);
};

const postAction = async (mapping, action, body = {}) => {
  const payload = await pluginJSON(`api/mappings/${encodeURIComponent(mapping.id)}/${action}`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  renderMappings(payload.mappings);
};

const renderMapping = (mapping) => {
  const card = document.createElement("article");
  card.className = "map-card";
  card.dataset.id = mapping.id;

  const head = document.createElement("div");
  head.className = "map-card-head";
  const identity = document.createElement("div");
  const title = document.createElement("h3");
  title.textContent = mapping.name || mapping.id;
  const chips = document.createElement("div");
  chips.className = "map-chips";
  chips.append(channelChip(mapping));
  chips.append(chip(mapping.enabled ? "已启用" : "已停用", mapping.enabled ? "chip-state-online" : "chip-state-offline"));
  chips.append(chip(String(mapping.protocol || "").toUpperCase(), "chip-protocol"));
  chips.append(chip(`入口 ${mapping.entry_agent_id}`));
  chips.append(chip(`出口 ${mapping.exit_agent_id}`));
  chips.append(chip(`:${mapping.listen_port}`));
  if (Array.isArray(mapping.relay_chain) && mapping.relay_chain.length) {
    chips.append(chip(`中继 ${mapping.relay_chain.join("→")}`));
  }
  identity.append(title, chips);
  if (mapping.last_error) {
    const error = document.createElement("p");
    error.className = "map-error";
    error.textContent = mapping.last_error;
    identity.append(error);
  }

  const actions = document.createElement("div");
  actions.className = "map-actions";
  const editButton = document.createElement("button");
  editButton.type = "button";
  editButton.className = "btn-link";
  editButton.textContent = "编辑";
  editButton.addEventListener("click", () => openForm(mapping));
  const toggleButton = document.createElement("button");
  toggleButton.type = "button";
  toggleButton.className = "btn-link";
  toggleButton.textContent = mapping.enabled ? "停用" : "启用";
  toggleButton.addEventListener("click", async () => {
    if (busy) return;
    setBusy(true);
    try {
      await postAction(mapping, mapping.enabled ? "disable" : "enable");
      showStatus(mapping.enabled ? "已停用映射，规则停止转发并拆除通道。" : "已启用映射，通道重建完成。", false);
    } catch (error) {
      showStatus(error.message, true);
    } finally {
      setBusy(false);
    }
  });
  const deleteButton = document.createElement("button");
  deleteButton.type = "button";
  deleteButton.className = "btn-link danger";
  deleteButton.textContent = "删除";
  deleteButton.addEventListener("click", async () => {
    if (busy) return;
    if (!window.confirm(`确认删除 ${mapping.id}？入口规则与反向通道会被一并释放。`)) {
      showStatus("已取消，映射未更改。", false);
      return;
    }
    setBusy(true);
    try {
      await postAction(mapping, "delete", { confirm: mapping.id });
      showStatus("已删除映射。", false);
    } catch (error) {
      showStatus(error.message, true);
    } finally {
      setBusy(false);
    }
  });
  actions.append(editButton, toggleButton, deleteButton);
  head.append(identity, actions);
  card.append(head);

  const details = document.createElement("details");
  const summary = document.createElement("summary");
  summary.textContent = "转发目标";
  const backend = document.createElement("p");
  backend.className = "map-backend";
  backend.textContent = `${mapping.protocol} :${mapping.listen_port} → ${mapping.exit_agent_id} → ${mapping.backend_host}:${mapping.backend_port}`;
  details.append(summary, backend);
  card.append(details);
  return card;
};

const renderMappings = (mappings) => {
  const list = Array.isArray(mappings) ? mappings : [];
  listNode.replaceChildren(...list.map(renderMapping));
  emptyNode.hidden = list.length > 0;
  countNode.hidden = list.length === 0;
  countNode.textContent = `${list.length} 条`;
};

if (createToggle) {
  createToggle.addEventListener("click", () => openForm(null));
}

if (formCancel) {
  formCancel.addEventListener("click", closeForm);
}

if (formNode) {
  formNode.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) return;
    const mapping = formMapping();
    const updating = Boolean(editingID);
    setBusy(true);
    try {
      if (updating) {
        await postAction(mapping, "update", mapping);
      } else {
        const payload = await pluginJSON("api/mappings", { method: "POST", body: JSON.stringify(mapping) });
        renderMappings(payload.mappings);
      }
      closeForm();
      showStatus(updating ? "已保存映射。" : "已创建映射。", false);
    } catch (error) {
      showStatus(error.message, true);
    } finally {
      setBusy(false);
    }
  });
}

(async () => {
  try {
    await refresh();
    loadingNode.hidden = true;
    workspaceNode.hidden = false;
  } catch (error) {
    loadingNode.hidden = true;
    if (error.denied) deniedNode.hidden = false;
    else {
      unavailableNode.hidden = false;
      unavailableNode.textContent = error.message || unavailableNode.textContent;
    }
  }
})();
