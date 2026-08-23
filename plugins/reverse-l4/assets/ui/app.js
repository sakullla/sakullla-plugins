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
const entryInput = formNode ? formNode.querySelector('input[name="entry_agent_id"]') : null;
const exitInput = formNode ? formNode.querySelector('input[name="exit_agent_id"]') : null;
const entryPickerRoot = formNode ? formNode.querySelector('[data-agent-picker="entry"]') : null;
const exitPickerRoot = formNode ? formNode.querySelector('[data-agent-picker="exit"]') : null;
const relayHops = document.querySelector("#relay-hops");
const relayAdd = document.querySelector("#relay-add");
const catalogErrorNode = document.querySelector("#catalog-error");
const mappingIDDisplay = document.querySelector("#mapping-id-display");

const maxRelayHops = 32;

let busy = false;
let editingID = "";
let catalogReady = false;
let agentsCache = [];
let listenersCache = [];

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

const showCatalogError = (message) => {
  if (!catalogErrorNode) return;
  catalogErrorNode.hidden = !message;
  catalogErrorNode.textContent = message || "";
};

const newOperationKey = () => {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return `operation/ui/${Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("")}`;
};

const panelJSON = async (path, options = {}) => {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: { ...panelAuthHeaders(), ...(options.headers || {}) },
  });
  const payload = await response.json().catch(() => null);
  if (response.status === 403) {
    throw Object.assign(new Error((payload && (payload.error || payload.message)) || "无权访问"), { denied: true });
  }
  if (!response.ok) {
    throw new Error((payload && (payload.error || payload.message)) || "请求失败");
  }
  if (!payload || typeof payload !== "object") {
    throw new Error("目录响应不是 JSON。");
  }
  return payload;
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

const parseAgentTime = (value) => {
  if (value == null || value === "") return 0;
  if (typeof value === "number" && Number.isFinite(value)) return value < 1e12 ? value * 1000 : value;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : 0;
};

const timeAgo = (value) => {
  const ts = parseAgentTime(value);
  if (!ts) return "";
  const delta = Date.now() - ts;
  if (delta < 60 * 1000) return "刚刚";
  if (delta < 60 * 60 * 1000) return `${Math.floor(delta / 60000)} 分钟前`;
  if (delta < 24 * 60 * 60 * 1000) return `${Math.floor(delta / 3600000)} 小时前`;
  return `${Math.floor(delta / 86400000)} 天前`;
};

const getAgentStatus = (agent) => {
  if (!agent) return "offline";
  if (agent.status === "offline" || agent.online === false) return "offline";
  if (agent.status === "failed") return "failed";
  if (agent.status === "pending") return "pending";
  if (agent.online === true || agent.status === "online") return "online";
  return "offline";
};

const isAgentOnline = (agent) => getAgentStatus(agent) === "online";

const listenerID = (listener) => {
  const raw = listener && (listener.id ?? listener.listener_id);
  const id = Number(raw);
  return Number.isInteger(id) && id > 0 ? id : 0;
};

const agentDisplayName = (agent) => {
  if (!agent) return "";
  return agent.name && agent.name !== agent.id ? agent.name : (agent.name || agent.id || "");
};

const agentSearchText = (agent) => [
  agent && agent.name,
  agent && agent.id,
  agent && agent.ddns_domain,
  agent && agent.last_seen_ip,
  agent && agent.agent_url,
].filter(Boolean).join(" ").toLowerCase();

const agentLabel = (agent) => {
  const label = agent.name && agent.name !== agent.id ? `${agent.name} · ${agent.id}` : (agent.name || agent.id);
  return isAgentOnline(agent) ? label : `${label}（离线）`;
};

const closeAllAgentPickers = (except) => {
  agentPickers.forEach((picker) => {
    if (picker !== except) picker.close();
  });
};

const mountAgentSearchSelect = (root, hiddenInput, placeholder) => {
  const picker = {
    root,
    hiddenInput,
    placeholder,
    open: false,
    disabled: false,
    statusFilter: "",
    sortBy: "last_seen",
    search: "",
    selected: "",
    close() {},
    setValue() {},
    setDisabled() {},
    refresh() {},
  };
  if (!root || !hiddenInput) return picker;

  const trigger = document.createElement("button");
  trigger.type = "button";
  trigger.className = "agent-search-select__trigger";
  trigger.setAttribute("aria-haspopup", "listbox");
  trigger.setAttribute("aria-expanded", "false");
  const statusDot = document.createElement("span");
  statusDot.className = "agent-search-select__status";
  statusDot.hidden = true;
  const label = document.createElement("span");
  label.className = "agent-search-select__label";
  const chevron = document.createElement("span");
  chevron.className = "agent-search-select__chevron";
  chevron.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><polyline points="6 9 12 15 18 9"/></svg>';
  trigger.append(statusDot, label, chevron);

  const dropdown = document.createElement("div");
  dropdown.className = "agent-search-select__dropdown";
  dropdown.hidden = true;
  dropdown.setAttribute("role", "listbox");

  const searchWrap = document.createElement("div");
  searchWrap.className = "agent-search-select__search";
  const searchShell = document.createElement("div");
  searchShell.className = "agent-search-select__search-shell";
  const searchInput = document.createElement("input");
  searchInput.type = "search";
  searchInput.className = "agent-search-select__search-input";
  searchInput.placeholder = "搜索节点...";
  searchInput.setAttribute("aria-label", "搜索节点");
  searchInput.autocomplete = "off";
  searchShell.append(searchInput);
  searchWrap.append(searchShell);

  const filters = document.createElement("div");
  filters.className = "agent-search-select__filters";
  const filterButtons = [
    { value: "", text: "全部" },
    { value: "online", text: "在线" },
    { value: "offline", text: "离线" },
  ].map((opt) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "agent-search-select__chip";
    button.textContent = opt.text;
    button.dataset.status = opt.value;
    button.addEventListener("click", () => {
      picker.statusFilter = opt.value;
      renderList();
    });
    filters.append(button);
    return button;
  });

  const list = document.createElement("div");
  list.className = "agent-search-select__list";

  const sortBar = document.createElement("div");
  sortBar.className = "agent-search-select__sort";
  sortBar.append(document.createTextNode("排序:"));
  const sortButtons = [
    { value: "last_seen", text: "最近活跃" },
    { value: "name", text: "名称" },
  ].map((opt) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "agent-search-select__chip";
    button.textContent = opt.text;
    button.dataset.sort = opt.value;
    button.addEventListener("click", () => {
      picker.sortBy = opt.value;
      renderList();
    });
    sortBar.append(button);
    return button;
  });

  dropdown.append(searchWrap, filters, list, sortBar);
  root.replaceChildren(trigger, dropdown);

  const selectedAgent = () => agentsCache.find((agent) => agent && agent.id === picker.selected) || null;

  const syncTrigger = () => {
    hiddenInput.value = picker.selected;
    const agent = selectedAgent();
    if (agent) {
      label.textContent = agentDisplayName(agent);
      label.dataset.empty = "false";
      statusDot.hidden = false;
      statusDot.className = `agent-search-select__status agent-search-select__status--${getAgentStatus(agent)}`;
      trigger.title = agentLabel(agent);
    } else if (picker.selected) {
      label.textContent = picker.selected;
      label.dataset.empty = "false";
      statusDot.hidden = true;
      trigger.title = picker.selected;
    } else {
      label.textContent = placeholder;
      label.dataset.empty = "true";
      statusDot.hidden = true;
      trigger.title = placeholder;
    }
  };

  const filteredAgents = () => {
    const query = picker.search.trim().toLowerCase();
    let result = agentsCache.slice();
    if (picker.statusFilter) {
      result = result.filter((agent) => getAgentStatus(agent) === picker.statusFilter);
    }
    if (query) {
      result = result.filter((agent) => agentSearchText(agent).includes(query));
    }
    result.sort((left, right) => {
      if (picker.sortBy === "name") {
        return String(agentDisplayName(left)).localeCompare(String(agentDisplayName(right)), "zh");
      }
      return parseAgentTime(right.last_seen_at) - parseAgentTime(left.last_seen_at);
    });
    return result;
  };

  const renderList = () => {
    filterButtons.forEach((button) => {
      button.setAttribute("aria-pressed", button.dataset.status === picker.statusFilter ? "true" : "false");
    });
    sortButtons.forEach((button) => {
      button.setAttribute("aria-pressed", button.dataset.sort === picker.sortBy ? "true" : "false");
    });
    const items = filteredAgents();
    list.replaceChildren();
    if (!items.length) {
      const empty = document.createElement("div");
      empty.className = "agent-search-select__empty";
      empty.textContent = agentsCache.length ? "没有匹配的节点" : "暂无可用节点";
      list.append(empty);
      return;
    }
    items.forEach((agent) => {
      const option = document.createElement("button");
      option.type = "button";
      option.className = "agent-search-select__option";
      option.setAttribute("role", "option");
      option.setAttribute("aria-selected", agent.id === picker.selected ? "true" : "false");
      const dot = document.createElement("span");
      dot.className = `agent-search-select__status agent-search-select__status--${getAgentStatus(agent)}`;
      const name = document.createElement("span");
      name.className = "agent-search-select__option-name";
      name.textContent = agentDisplayName(agent);
      const meta = document.createElement("span");
      meta.className = "agent-search-select__option-meta";
      meta.textContent = timeAgo(agent.last_seen_at) || (isAgentOnline(agent) ? "在线" : "离线");
      option.append(dot, name, meta);
      option.addEventListener("click", () => {
        picker.setValue(agent.id);
        picker.close();
      });
      list.append(option);
    });
  };

  picker.close = () => {
    picker.open = false;
    picker.search = "";
    picker.statusFilter = "";
    picker.sortBy = "last_seen";
    searchInput.value = "";
    dropdown.hidden = true;
    trigger.setAttribute("aria-expanded", "false");
  };

  picker.setValue = (value) => {
    picker.selected = String(value || "");
    syncTrigger();
  };

  picker.setDisabled = (next) => {
    picker.disabled = Boolean(next);
    trigger.disabled = picker.disabled;
    searchInput.disabled = picker.disabled;
  };

  picker.refresh = (selected) => {
    if (selected !== undefined) picker.selected = String(selected || "");
    syncTrigger();
    if (picker.open) renderList();
  };

  trigger.addEventListener("click", () => {
    if (picker.disabled) return;
    if (picker.open) {
      picker.close();
      return;
    }
    closeAllAgentPickers(picker);
    picker.open = true;
    dropdown.hidden = false;
    trigger.setAttribute("aria-expanded", "true");
    renderList();
    searchInput.focus();
  });

  searchInput.addEventListener("input", () => {
    picker.search = searchInput.value;
    renderList();
  });

  searchInput.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      event.preventDefault();
      picker.close();
      trigger.focus();
    }
  });

  document.addEventListener("mousedown", (event) => {
    if (!picker.open) return;
    if (root.contains(event.target)) return;
    picker.close();
  });

  syncTrigger();
  return picker;
};

const agentPickers = [];
const entryPicker = mountAgentSearchSelect(entryPickerRoot, entryInput, "选择入口节点");
const exitPicker = mountAgentSearchSelect(exitPickerRoot, exitInput, "选择出口节点");
if (entryPicker.root) agentPickers.push(entryPicker);
if (exitPicker.root) agentPickers.push(exitPicker);

const listenerLabel = (listener, id) => {
  const name = String((listener && listener.name) || "").trim();
  const agent = String((listener && (listener.agent_name || listener.agent_id || listener.agent)) || "").trim();
  const disabled = listener && listener.enabled === false ? "（停用）" : "";
  let label = `监听器 ${id}`;
  if (name && agent && name !== String(id) && agent !== name) label = `${name} · ${agent} · ${id}`;
  else if (name && name !== String(id)) label = `${name} · ${id}`;
  else if (agent && agent !== String(id)) label = `${agent} · ${id}`;
  return label + disabled;
};

const fillAgentPickers = (entryID, exitID) => {
  entryPicker.refresh(entryID || "");
  exitPicker.refresh(exitID || "");
};

const fillListenerSelect = (select, selected) => {
  if (!select) return;
  const selectedID = Number(selected);
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = listenersCache.length ? "选择中继监听器" : "暂无中继监听器";
  select.replaceChildren(placeholder);
  const seen = new Set();
  listenersCache.forEach((listener) => {
    const id = listenerID(listener);
    if (!id || seen.has(id)) return;
    seen.add(id);
    const option = document.createElement("option");
    option.value = String(id);
    option.textContent = listenerLabel(listener, id);
    select.append(option);
  });
  if (selectedID > 0 && !seen.has(selectedID)) {
    const option = document.createElement("option");
    option.value = String(selectedID);
    option.textContent = `监听器 ${selectedID}`;
    select.append(option);
  }
  select.value = selectedID > 0 ? String(selectedID) : "";
};

const relabelRelayHops = () => {
  if (!relayHops) return;
  Array.from(relayHops.querySelectorAll("select")).forEach((select, index) => {
    select.setAttribute("aria-label", `中继跳 ${index + 1}`);
  });
};

const syncFormControls = () => {
  if (formSubmit) formSubmit.disabled = busy || !catalogReady;
  if (relayAdd) {
    const hopCount = relayHops ? relayHops.children.length : 0;
    relayAdd.disabled = busy || !catalogReady || listenersCache.length === 0 || hopCount >= maxRelayHops;
  }
};

const setBusy = (next) => {
  busy = next;
  if (next) closeAllAgentPickers();
  workspaceNode.querySelectorAll("button, input, select").forEach((node) => {
    node.disabled = next;
  });
  entryPicker.setDisabled(next);
  exitPicker.setDisabled(next);
  if (!next) syncFormControls();
};

const addRelayHop = (selected) => {
  if (!relayHops || relayHops.children.length >= maxRelayHops) return;
  const row = document.createElement("div");
  row.className = "relay-hop";
  const select = document.createElement("select");
  fillListenerSelect(select, selected);
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "btn-link danger";
  remove.textContent = "移除";
  remove.addEventListener("click", () => {
    if (busy) return;
    row.remove();
    relabelRelayHops();
    syncFormControls();
  });
  row.append(select, remove);
  relayHops.append(row);
  relabelRelayHops();
  syncFormControls();
};

const renderRelayHops = (hops) => {
  if (!relayHops) return;
  const values = Array.isArray(hops)
    ? hops.filter((hop) => Number.isInteger(hop) && hop > 0)
    : [];
  relayHops.replaceChildren();
  values.forEach((hop) => addRelayHop(hop));
  relabelRelayHops();
  syncFormControls();
};

const collectRelayHops = () => {
  if (!relayHops) return { hops: [], error: "" };
  const hops = [];
  for (const select of relayHops.querySelectorAll("select")) {
    const hop = Number(select.value);
    if (!Number.isInteger(hop) || hop <= 0) {
      return { hops: [], error: "请为每一跳选择中继监听器，或移除空跳。" };
    }
    hops.push(hop);
  }
  return { hops, error: "" };
};

const loadCatalogs = async () => {
  catalogReady = false;
  agentsCache = [];
  listenersCache = [];
  const [agentsPayload, listenersPayload] = await Promise.all([
    panelJSON("/panel-api/agents"),
    panelJSON("/panel-api/relay-listeners"),
  ]);
  if (!Array.isArray(agentsPayload.agents)) {
    throw new Error("节点目录缺少 agents 集合。");
  }
  if (!Array.isArray(listenersPayload.listeners)) {
    throw new Error("中继目录缺少 listeners 集合。");
  }
  agentsCache = agentsPayload.agents.filter((agent) => agent && agent.is_local !== true && agent.mode !== "local");
  listenersCache = listenersPayload.listeners.filter((listener) => listenerID(listener) > 0);
  catalogReady = true;
};

const formMapping = () => {
  const data = new FormData(formNode);
  const relay = collectRelayHops();
  return {
    name: String(data.get("name") || "").trim(),
    entry_agent_id: String(data.get("entry_agent_id") || "").trim(),
    exit_agent_id: String(data.get("exit_agent_id") || "").trim(),
    protocol: String(data.get("protocol") || "tcp").trim(),
    listen_port: Number(data.get("listen_port") || 0),
    backend_host: String(data.get("backend_host") || "").trim(),
    backend_port: Number(data.get("backend_port") || 0),
    relay_chain: relay.hops,
    relayError: relay.error,
  };
};

const openForm = async (mapping) => {
  editingID = mapping ? String(mapping.id || "") : "";
  formTitle.textContent = editingID ? "编辑映射" : "新建映射";
  formSubmit.textContent = editingID ? "保存" : "创建";
  formNode.reset();
  if (mappingIDDisplay) {
    mappingIDDisplay.hidden = !editingID;
    mappingIDDisplay.textContent = editingID ? `映射 ID ${editingID}（创建后不可更改）` : "";
  }
  if (editingID) {
    formNode.querySelector('input[name="name"]').value = mapping.name || "";
    formNode.querySelector('select[name="protocol"]').value = mapping.protocol || "tcp";
    formNode.querySelector('input[name="listen_port"]').value = mapping.listen_port || "";
    formNode.querySelector('input[name="backend_host"]').value = mapping.backend_host || "";
    formNode.querySelector('input[name="backend_port"]').value = mapping.backend_port || "";
  }
  showCatalogError("");
  formPanel.hidden = false;
  createToggle.hidden = true;
  try {
    await loadCatalogs();
    fillAgentPickers(mapping ? mapping.entry_agent_id : "", mapping ? mapping.exit_agent_id : "");
    renderRelayHops(mapping ? mapping.relay_chain : []);
    if (!editingID && agentsCache.length === 0) {
      showCatalogError("暂无可用节点，无法创建映射。");
    }
  } catch (error) {
    catalogReady = false;
    agentsCache = [];
    listenersCache = [];
    fillAgentPickers(mapping ? mapping.entry_agent_id : "", mapping ? mapping.exit_agent_id : "");
    renderRelayHops([]);
    showCatalogError(error.message || "无法加载节点或中继目录，不能手输 ID 创建映射。");
  }
  syncFormControls();
  formNode.querySelector('input[name="name"]').focus();
};

const closeForm = () => {
  editingID = "";
  formNode.reset();
  closeAllAgentPickers();
  fillAgentPickers("", "");
  if (relayHops) relayHops.replaceChildren();
  if (mappingIDDisplay) {
    mappingIDDisplay.hidden = true;
    mappingIDDisplay.textContent = "";
  }
  showCatalogError("");
  formTitle.textContent = "新建映射";
  formSubmit.textContent = "创建";
  formPanel.hidden = true;
  createToggle.hidden = false;
  syncFormControls();
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

const mappingTitle = (mapping) => mapping.name || mapping.id;

const renderMapping = (mapping) => {
  const card = document.createElement("article");
  card.className = "map-card";
  card.dataset.id = mapping.id;

  const head = document.createElement("div");
  head.className = "map-card-head";
  const identity = document.createElement("div");
  const title = document.createElement("h3");
  title.textContent = mappingTitle(mapping);
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
  editButton.addEventListener("click", async () => {
    if (busy) return;
    setBusy(true);
    try {
      await openForm(mapping);
    } catch (error) {
      showStatus(error.message, true);
    } finally {
      setBusy(false);
    }
  });
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
    if (!window.confirm(`确认删除 ${mappingTitle(mapping)}？入口规则与反向通道会被一并释放。`)) {
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
  createToggle.addEventListener("click", async () => {
    if (busy) return;
    setBusy(true);
    try {
      await openForm(null);
    } catch (error) {
      showStatus(error.message, true);
    } finally {
      setBusy(false);
    }
  });
}

if (formCancel) {
  formCancel.addEventListener("click", closeForm);
}

if (relayAdd) {
  relayAdd.addEventListener("click", () => {
    if (busy || !catalogReady) return;
    addRelayHop("");
  });
}

if (formNode) {
  formNode.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) return;
    if (!catalogReady) {
      showStatus(catalogErrorNode && catalogErrorNode.textContent
        ? catalogErrorNode.textContent
        : "节点或中继目录不可用，无法保存映射。", true);
      return;
    }
    const mapping = formMapping();
    if (mapping.relayError) {
      showStatus(mapping.relayError, true);
      return;
    }
    if (!mapping.entry_agent_id || !mapping.exit_agent_id) {
      showStatus("请选择入口节点和出口节点。", true);
      return;
    }
    if (mapping.entry_agent_id === mapping.exit_agent_id) {
      showStatus("入口与出口节点不能相同。", true);
      return;
    }
    const updating = Boolean(editingID);
    const body = {
      name: mapping.name,
      entry_agent_id: mapping.entry_agent_id,
      exit_agent_id: mapping.exit_agent_id,
      protocol: mapping.protocol,
      listen_port: mapping.listen_port,
      backend_host: mapping.backend_host,
      backend_port: mapping.backend_port,
      relay_chain: mapping.relay_chain,
    };
    setBusy(true);
    try {
      if (updating) {
        await postAction({ id: editingID }, "update", body);
      } else {
        const payload = await pluginJSON("api/mappings", { method: "POST", body: JSON.stringify(body) });
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
