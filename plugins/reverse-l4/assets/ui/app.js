const statusNode = document.querySelector("#map-status");
const toastStack = document.querySelector("#map-toasts");
const loadingNode = document.querySelector("#map-loading");
const unavailableNode = document.querySelector("#map-unavailable");
const deniedNode = document.querySelector("#map-denied");
const workspaceNode = document.querySelector("#map-workspace");
const listNode = document.querySelector("#map-list");
const emptyNode = document.querySelector("#map-empty");
const countNode = document.querySelector("#map-count");
const createToggle = document.querySelector("#create-toggle");
const createEmpty = document.querySelector("#create-empty");
const mappingDialog = document.querySelector("#mapping-dialog");
const formNode = document.querySelector("#mapping-form");
const formTitle = document.querySelector("#map-form-title");
const formDesc = document.querySelector("#map-form-desc");
const formSubmit = document.querySelector("#form-submit");
const formCancel = document.querySelector("#form-cancel");
const formClose = document.querySelector("#form-close");
const wizardNext = document.querySelector("#wizard-next");
const wizardBack = document.querySelector("#wizard-back");
const wizardErrorNode = document.querySelector("#wizard-error");
const wizardStepList = document.querySelector("#wizard-steps");
const wizardStepNodes = wizardStepList ? Array.from(wizardStepList.querySelectorAll(".wizard-step")) : [];
const wizardSections = Array.from(document.querySelectorAll("[data-wizard-step]"));
const entryInput = formNode ? formNode.querySelector('input[name="entry_agent_id"]') : null;
const exitInput = formNode ? formNode.querySelector('input[name="exit_agent_id"]') : null;
const entryPickerRoot = formNode ? formNode.querySelector('[data-agent-picker="entry"]') : null;
const exitPickerRoot = formNode ? formNode.querySelector('[data-agent-picker="exit"]') : null;
const relayHops = document.querySelector("#relay-hops");
const relayAdd = document.querySelector("#relay-add");
const catalogErrorNode = document.querySelector("#catalog-error");
const mappingIDDisplay = document.querySelector("#mapping-id-display");
const confirmDialog = document.querySelector("#confirm-dialog");
const confirmTitle = document.querySelector("#confirm-title");
const confirmDesc = document.querySelector("#confirm-desc");
const confirmAccept = document.querySelector("#confirm-accept");
const confirmCancel = document.querySelector("#confirm-cancel");

const fieldNodes = {
  name: formNode ? formNode.querySelector('input[name="name"]') : null,
  protocol: formNode ? formNode.querySelector('select[name="protocol"]') : null,
  listenHost: formNode ? formNode.querySelector('input[name="listen_host"]') : null,
  listenPort: formNode ? formNode.querySelector('input[name="listen_port"]') : null,
  backendHost: formNode ? formNode.querySelector('input[name="backend_host"]') : null,
  backendPort: formNode ? formNode.querySelector('input[name="backend_port"]') : null,
};

const totalSteps = 3;
const maxRelayHops = 32;

let busy = false;
let editingID = "";
let wizardStep = 1;
let catalogReady = false;
let agentsCache = [];
let listenersCache = [];
let pendingConfirm = null;

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

const pushToast = (message, isError) => {
  if (!message) return;
  if (statusNode) {
    statusNode.hidden = false;
    statusNode.textContent = message;
    statusNode.dataset.error = isError ? "true" : "false";
  }
  if (!toastStack) return;
  const toast = document.createElement("div");
  toast.className = `ui-toast ${isError ? "ui-toast--danger" : "ui-toast--success"}`;
  toast.setAttribute("role", isError ? "alert" : "status");
  const text = document.createElement("span");
  text.className = "map-toast__text";
  text.textContent = message;
  toast.append(text);
  if (isError) {
    const close = document.createElement("button");
    close.type = "button";
    close.className = "ui-btn ui-btn--icon ui-btn--ghost ui-btn--sm";
    close.setAttribute("aria-label", "关闭提示");
    close.textContent = "×";
    close.addEventListener("click", () => toast.remove());
    toast.append(close);
  } else {
    window.setTimeout(() => toast.remove(), 4200);
  }
  toastStack.append(toast);
};

const showStatus = (message, isError) => pushToast(message, isError);

const showCatalogError = (message) => {
  if (!catalogErrorNode) return;
  catalogErrorNode.hidden = !message;
  catalogErrorNode.textContent = message || "";
};

const showWizardError = (message) => {
  if (!wizardErrorNode) return;
  wizardErrorNode.hidden = !message;
  wizardErrorNode.textContent = message || "";
};

const clearFieldErrors = () => {
  Object.values(fieldNodes).forEach((node) => {
    if (node && window.NREUI && window.NREUI.clearFieldError) window.NREUI.clearFieldError(node);
  });
  [entryInput, exitInput].forEach((node) => {
    if (node && window.NREUI && window.NREUI.clearFieldError) window.NREUI.clearFieldError(node);
  });
  if (formNode) {
    formNode.querySelectorAll('[aria-invalid="true"]').forEach((node) => node.removeAttribute("aria-invalid"));
  }
};

const markFieldError = (node, message) => {
  if (!node) return;
  if (window.NREUI && window.NREUI.fieldError) {
    window.NREUI.fieldError(node, message);
    return;
  }
  node.setAttribute("aria-invalid", "true");
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

const agentIdentity = (id) => {
  const normalizedID = String(id || "").trim();
  const agent = agentsCache.find((candidate) => String(candidate && candidate.id || "") === normalizedID);
  const displayName = agentDisplayName(agent) || normalizedID || "未知节点";
  return { displayName, id: normalizedID, resolved: Boolean(agent && displayName !== normalizedID) };
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

const agentPickers = [];
const listenerPickers = [];

const closeAllPickers = (except) => {
  [...agentPickers, ...listenerPickers].forEach((picker) => {
    if (picker !== except && picker.close) picker.close();
  });
};

const closeAllAgentPickers = (except) => closeAllPickers(except);

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
    closeAllPickers(picker);
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

const entryPicker = mountAgentSearchSelect(entryPickerRoot, entryInput, "选择入口节点");
const exitPicker = mountAgentSearchSelect(exitPickerRoot, exitInput, "选择出口节点");
if (entryPicker.root) agentPickers.push(entryPicker);
if (exitPicker.root) agentPickers.push(exitPicker);

const fillAgentPickers = (entryID, exitID) => {
  entryPicker.refresh(entryID || "");
  exitPicker.refresh(exitID || "");
};
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

const listenerIdentity = (id) => {
  const normalizedID = Number(id);
  const listener = listenersCache.find((candidate) => listenerID(candidate) === normalizedID);
  const name = String((listener && listener.name) || "").trim();
  const agent = String((listener && (listener.agent_name || listener.agent_id || listener.agent)) || "").trim();
  const displayName = name && name !== String(normalizedID)
    ? name
    : (agent && agent !== String(normalizedID) ? agent : `监听器 ${normalizedID}`);
  const owner = name && agent && agent !== name ? agent : "";
  return { displayName, id: normalizedID, owner };
};

const isListenerEnabled = (listener) => !listener || listener.enabled !== false;

const listenerSearchText = (listener) => [
  listener && listener.name,
  listener && listener.agent_name,
  listener && listener.agent_id,
  listener && listener.agent,
  listenerID(listener),
  listener && listener.public_addr,
  listener && listener.listen_port,
].filter(Boolean).join(" ").toLowerCase();

const uniqueListeners = () => {
  const seen = new Set();
  const result = [];
  listenersCache.forEach((listener) => {
    const id = listenerID(listener);
    if (!id || seen.has(id)) return;
    seen.add(id);
    result.push(listener);
  });
  return result;
};

const mountListenerSearchSelect = (root, hiddenInput, placeholder) => {
  const picker = {
    root,
    hiddenInput,
    placeholder,
    open: false,
    disabled: false,
    enabledFilter: "",
    sortBy: "name",
    search: "",
    selected: 0,
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
  searchInput.placeholder = "搜索中继...";
  searchInput.setAttribute("aria-label", "搜索中继");
  searchInput.autocomplete = "off";
  searchShell.append(searchInput);
  searchWrap.append(searchShell);

  const filters = document.createElement("div");
  filters.className = "agent-search-select__filters";
  const filterButtons = [
    { value: "", text: "全部" },
    { value: "enabled", text: "启用" },
    { value: "disabled", text: "停用" },
  ].map((opt) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "agent-search-select__chip";
    button.textContent = opt.text;
    button.dataset.enabled = opt.value;
    button.addEventListener("click", () => {
      picker.enabledFilter = opt.value;
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
    { value: "name", text: "名称" },
    { value: "agent", text: "节点" },
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

  const selectedListener = () => uniqueListeners().find((listener) => listenerID(listener) === picker.selected) || null;

  const syncTrigger = () => {
    hiddenInput.value = picker.selected > 0 ? String(picker.selected) : "";
    const listener = selectedListener();
    if (listener) {
      const id = listenerID(listener);
      label.textContent = listenerLabel(listener, id);
      label.dataset.empty = "false";
      statusDot.hidden = false;
      statusDot.className = `agent-search-select__status agent-search-select__status--${isListenerEnabled(listener) ? "online" : "offline"}`;
      trigger.title = listenerLabel(listener, id);
    } else if (picker.selected > 0) {
      label.textContent = `监听器 ${picker.selected}`;
      label.dataset.empty = "false";
      statusDot.hidden = true;
      trigger.title = `监听器 ${picker.selected}`;
    } else {
      label.textContent = uniqueListeners().length ? placeholder : "暂无中继监听器";
      label.dataset.empty = "true";
      statusDot.hidden = true;
      trigger.title = label.textContent;
    }
  };

  const filteredListeners = () => {
    const query = picker.search.trim().toLowerCase();
    let result = uniqueListeners();
    if (picker.enabledFilter === "enabled") result = result.filter((listener) => isListenerEnabled(listener));
    if (picker.enabledFilter === "disabled") result = result.filter((listener) => !isListenerEnabled(listener));
    if (query) result = result.filter((listener) => listenerSearchText(listener).includes(query));
    result.sort((left, right) => {
      if (picker.sortBy === "agent") {
        const leftAgent = String(left.agent_name || left.agent_id || left.agent || "");
        const rightAgent = String(right.agent_name || right.agent_id || right.agent || "");
        return leftAgent.localeCompare(rightAgent, "zh") || listenerID(left) - listenerID(right);
      }
      return listenerLabel(left, listenerID(left)).localeCompare(listenerLabel(right, listenerID(right)), "zh");
    });
    return result;
  };

  const renderList = () => {
    filterButtons.forEach((button) => {
      button.setAttribute("aria-pressed", button.dataset.enabled === picker.enabledFilter ? "true" : "false");
    });
    sortButtons.forEach((button) => {
      button.setAttribute("aria-pressed", button.dataset.sort === picker.sortBy ? "true" : "false");
    });
    const items = filteredListeners();
    list.replaceChildren();
    if (!items.length) {
      const empty = document.createElement("div");
      empty.className = "agent-search-select__empty";
      empty.textContent = uniqueListeners().length ? "没有匹配的中继" : "暂无中继监听器";
      list.append(empty);
      return;
    }
    items.forEach((listener) => {
      const id = listenerID(listener);
      const option = document.createElement("button");
      option.type = "button";
      option.className = "agent-search-select__option";
      option.setAttribute("role", "option");
      option.setAttribute("aria-selected", id === picker.selected ? "true" : "false");
      const dot = document.createElement("span");
      dot.className = `agent-search-select__status agent-search-select__status--${isListenerEnabled(listener) ? "online" : "offline"}`;
      const copy = document.createElement("span");
      copy.className = "agent-search-select__option-copy";
      const name = document.createElement("span");
      name.className = "agent-search-select__option-name";
      name.textContent = String(listener.name || "").trim() && String(listener.name) !== String(id)
        ? listener.name
        : `监听器 ${id}`;
      const meta = document.createElement("span");
      meta.className = "agent-search-select__option-meta";
      const agent = String(listener.agent_name || listener.agent_id || listener.agent || "").trim();
      meta.textContent = [agent ? `节点 ${agent}` : "", `监听器 ID ${id}`, isListenerEnabled(listener) ? "启用" : "停用"].filter(Boolean).join(" · ");
      copy.append(name, meta);
      option.append(dot, copy);
      option.addEventListener("click", () => {
        picker.setValue(id);
        picker.close();
      });
      list.append(option);
    });
  };

  picker.close = () => {
    picker.open = false;
    picker.search = "";
    picker.enabledFilter = "";
    picker.sortBy = "name";
    searchInput.value = "";
    dropdown.hidden = true;
    trigger.setAttribute("aria-expanded", "false");
  };

  picker.setValue = (value) => {
    const id = Number(value);
    picker.selected = Number.isInteger(id) && id > 0 ? id : 0;
    syncTrigger();
  };

  picker.setDisabled = (next) => {
    picker.disabled = Boolean(next);
    trigger.disabled = picker.disabled;
    searchInput.disabled = picker.disabled;
  };

  picker.refresh = (selected) => {
    if (selected !== undefined) picker.setValue(selected);
    else syncTrigger();
    if (picker.open) renderList();
  };

  trigger.addEventListener("click", () => {
    if (picker.disabled) return;
    if (picker.open) {
      picker.close();
      return;
    }
    closeAllPickers(picker);
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

const hopSideHint = (index, total) => {
  if (total === 1) return "（入口之后、出口之前）";
  if (index === 0) return "（入口之后）";
  if (index === total - 1) return "（出口之前）";
  return "";
};

const relabelRelayHops = () => {
  if (!relayHops) return;
  const rows = Array.from(relayHops.querySelectorAll(".relay-hop"));
  rows.forEach((row, index) => {
    let badge = row.querySelector(".relay-hop-index");
    if (!badge) {
      badge = document.createElement("span");
      badge.className = "relay-hop-index";
      row.insertBefore(badge, row.firstChild);
    }
    const n = index + 1;
    badge.textContent = `第 ${n} 跳${hopSideHint(index, rows.length)}`;
    const trigger = row.querySelector(".agent-search-select__trigger");
    if (trigger) trigger.setAttribute("aria-label", `中继第 ${n} 跳`);
  });
};

const syncFormControls = () => {
  const ready = catalogReady;
  if (formSubmit) formSubmit.disabled = busy || !ready;
  if (wizardNext) wizardNext.disabled = busy || !ready;
  if (wizardBack) wizardBack.disabled = busy;
  if (relayAdd) {
    const hopCount = relayHops ? relayHops.children.length : 0;
    relayAdd.disabled = busy || !ready || listenersCache.length === 0 || hopCount >= maxRelayHops;
  }
};

const setBusy = (next) => {
  busy = Boolean(next);
  if (busy) closeAllPickers();
  [workspaceNode, mappingDialog, confirmDialog].forEach((root) => {
    if (!root) return;
    root.querySelectorAll("button, input, select").forEach((node) => {
      node.disabled = busy;
    });
  });
  entryPicker.setDisabled(busy);
  exitPicker.setDisabled(busy);
  listenerPickers.forEach((picker) => picker.setDisabled(busy));
  if (!busy) syncFormControls();
};

const addRelayHop = (selected) => {
  if (!relayHops || relayHops.children.length >= maxRelayHops) return;
  const row = document.createElement("div");
  row.className = "relay-hop";
  const hidden = document.createElement("input");
  hidden.type = "hidden";
  hidden.dataset.relayHop = "true";
  hidden.value = "";
  const pickerRoot = document.createElement("div");
  pickerRoot.className = "agent-search-select";
  pickerRoot.dataset.listenerPicker = "true";
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "ui-btn ui-btn--ghost ui-btn--sm map-relay-remove";
  remove.textContent = "移除";
  row.append(hidden, pickerRoot, remove);
  relayHops.append(row);
  const picker = mountListenerSearchSelect(pickerRoot, hidden, "选择中继监听器");
  listenerPickers.push(picker);
  picker.refresh(selected || "");
  picker.setDisabled(busy || !catalogReady);
  remove.addEventListener("click", () => {
    if (busy) return;
    const index = listenerPickers.indexOf(picker);
    if (index >= 0) listenerPickers.splice(index, 1);
    picker.close();
    row.remove();
    relabelRelayHops();
    syncFormControls();
  });
  relabelRelayHops();
  syncFormControls();
};

const renderRelayHops = (hops) => {
  if (!relayHops) return;
  listenerPickers.slice().forEach((picker) => picker.close());
  listenerPickers.splice(0, listenerPickers.length);
  const values = Array.isArray(hops)
    ? hops.filter((hop) => Number.isInteger(hop) && hop > 0)
    : [];
  relayHops.replaceChildren();
  values.forEach((hop) => addRelayHop(hop));
  relabelRelayHops();
  syncFormControls();
};

const relaySelection = () => {
  if (!relayHops) return { hops: [], error: "" };
  const hops = [];
  for (const input of relayHops.querySelectorAll("input[data-relay-hop]")) {
    const hop = Number(input.value);
    if (!Number.isInteger(hop) || hop <= 0) {
      return { hops: [], error: "请为每一跳选择中继监听器，或移除空跳。" };
    }
    hops.push(hop);
  }
  return { hops, error: "" };
};

const loadCatalogs = async () => {
  catalogReady = false;
  syncFormControls();
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
  const nextAgents = agentsPayload.agents.filter((agent) => agent && agent.is_local !== true && agent.mode !== "local");
  const nextListeners = listenersPayload.listeners.filter((listener) => listenerID(listener) > 0);
  agentsCache = nextAgents;
  listenersCache = nextListeners;
  catalogReady = true;
  listenerPickers.forEach((picker) => picker.refresh());
  syncFormControls();
};

const portNumber = (node) => {
  const raw = String((node && node.value) || "").trim();
  if (!raw) return 0;
  const value = Number(raw);
  return Number.isInteger(value) && value >= 1 && value <= 65535 ? value : 0;
};

const checkStep = (step) => {
  if (step === 1) {
    if (!entryInput || !entryInput.value) {
      markFieldError(entryInput, "请选择入口节点。");
      return "请选择入口节点。";
    }
    if (!portNumber(fieldNodes.listenPort)) {
      markFieldError(fieldNodes.listenPort, "监听端口需为 1–65535 的整数。");
      return "监听端口需为 1–65535 的整数。";
    }
    return "";
  }
  if (step === 2) {
    if (!exitInput || !exitInput.value) {
      markFieldError(exitInput, "请选择出口节点。");
      return "请选择出口节点。";
    }
    if (entryInput && entryInput.value === exitInput.value) {
      markFieldError(exitInput, "入口与出口节点不能相同。");
      return "入口与出口节点不能相同。";
    }
    return relaySelection().error;
  }
  if (step === 3) {
    if (!String((fieldNodes.backendHost && fieldNodes.backendHost.value) || "").trim()) {
      markFieldError(fieldNodes.backendHost, "请填写内网服务地址。");
      return "请填写内网服务地址。";
    }
    if (!portNumber(fieldNodes.backendPort)) {
      markFieldError(fieldNodes.backendPort, "内网服务端口需为 1–65535 的整数。");
      return "内网服务端口需为 1–65535 的整数。";
    }
    return "";
  }
  return "";
};

const checkAllSteps = () => {
  for (let step = 1; step <= totalSteps; step += 1) {
    const error = checkStep(step);
    if (error) {
      applyStep(step, { clear: false });
      showWizardError(error);
      return false;
    }
  }
  return true;
};

const applyStep = (step, options = {}) => {
  wizardStep = Math.min(totalSteps, Math.max(1, Number(step) || 1));
  wizardSections.forEach((section) => {
    section.hidden = Number(section.dataset.wizardStep) !== wizardStep;
  });
  wizardStepNodes.forEach((node) => {
    const index = Number(node.dataset.step);
    node.setAttribute("aria-current", index === wizardStep ? "step" : "false");
    node.dataset.state = index < wizardStep ? "done" : index === wizardStep ? "current" : "upcoming";
  });
  if (wizardBack) wizardBack.hidden = wizardStep === 1;
  if (wizardNext) wizardNext.hidden = wizardStep === totalSteps;
  if (formSubmit) {
    formSubmit.hidden = wizardStep !== totalSteps;
    formSubmit.textContent = editingID ? "保存" : "创建";
  }
  if (options.clear !== false) {
    showWizardError("");
    clearFieldErrors();
  }
  syncFormControls();
};

const resetWizard = () => {
  editingID = "";
  if (formNode) formNode.reset();
  closeAllAgentPickers();
  fillAgentPickers("", "");
  if (relayHops) relayHops.replaceChildren();
  listenerPickers.slice().forEach((picker) => picker.close());
  listenerPickers.splice(0, listenerPickers.length);
  showCatalogError("");
  if (mappingIDDisplay) {
    mappingIDDisplay.hidden = true;
    mappingIDDisplay.textContent = "";
  }
  if (formTitle) formTitle.textContent = "新建映射";
  if (formDesc) formDesc.textContent = "按公网入口、反向通道、出口内网服务三步填写。";
  applyStep(1, { clear: true });
  syncFormControls();
};

const openForm = async (mapping) => {
  editingID = mapping ? String(mapping.id || "") : "";
  if (formTitle) formTitle.textContent = editingID ? "编辑映射" : "新建映射";
  if (formDesc) {
    formDesc.textContent = editingID
      ? `映射 ID ${editingID} 创建后不可更改；保存后按新配置重建通道。`
      : "按公网入口、反向通道、出口内网服务三步填写。";
  }
  if (formNode) formNode.reset();
  clearFieldErrors();
  showWizardError("");
  showCatalogError("");
  fillAgentPickers("", "");
  if (relayHops) relayHops.replaceChildren();
  listenerPickers.slice().forEach((picker) => picker.close());
  listenerPickers.splice(0, listenerPickers.length);
  if (mappingIDDisplay) {
    mappingIDDisplay.hidden = !editingID;
    mappingIDDisplay.textContent = editingID ? `映射 ID ${editingID}（创建后不可更改）` : "";
  }
  if (editingID) {
    if (fieldNodes.name) fieldNodes.name.value = mapping.name || "";
    if (fieldNodes.protocol) fieldNodes.protocol.value = mapping.protocol || "tcp";
    if (fieldNodes.listenHost) fieldNodes.listenHost.value = mapping.listen_host || "0.0.0.0";
    if (fieldNodes.listenPort) fieldNodes.listenPort.value = mapping.listen_port || "";
    if (fieldNodes.backendHost) fieldNodes.backendHost.value = mapping.backend_host || "";
    if (fieldNodes.backendPort) fieldNodes.backendPort.value = mapping.backend_port || "";
  }
  catalogReady = false;
  applyStep(1, { clear: true });
  if (mappingDialog && !mappingDialog.open) mappingDialog.showModal();
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
  if (fieldNodes.name) fieldNodes.name.focus();
};

const closeForm = () => {
  if (mappingDialog && mappingDialog.open) mappingDialog.close();
  resetWizard();
  if (createToggle) createToggle.focus();
};

const goNext = () => {
  if (busy || wizardStep >= totalSteps) return;
  clearFieldErrors();
  showWizardError("");
  const error = checkStep(wizardStep);
  if (error) {
    showWizardError(error);
    return;
  }
  applyStep(wizardStep + 1, { clear: true });
};

const goBack = () => {
  if (busy || wizardStep <= 1) return;
  applyStep(wizardStep - 1, { clear: true });
};

const formMapping = () => {
  const data = new FormData(formNode);
  const relay = relaySelection();
  return {
    name: String(data.get("name") || "").trim(),
    entry_agent_id: String(data.get("entry_agent_id") || "").trim(),
    exit_agent_id: String(data.get("exit_agent_id") || "").trim(),
    protocol: String(data.get("protocol") || "tcp").trim(),
    listen_host: String(data.get("listen_host") || "").trim() || "0.0.0.0",
    listen_port: Number(data.get("listen_port") || 0),
    backend_host: String(data.get("backend_host") || "").trim(),
    backend_port: Number(data.get("backend_port") || 0),
    relay_chain: relay.hops,
  };
};
const mappingTitle = (mapping) => mapping.name || mapping.id;

const badge = (text, tone) => {
  const node = document.createElement("span");
  node.className = `ui-badge${tone ? ` ui-badge--${tone}` : " ui-badge--plain"}`;
  node.textContent = text;
  return node;
};

const channelBadge = (mapping) => {
  if (mapping.channel_state === "online") return badge("通道在线", "success");
  if (mapping.channel_state === "offline") return badge("通道离线", "danger");
  return badge("通道未知", "warning");
};

const actionButton = (text, toneClass, handler) => {
  const button = document.createElement("button");
  button.type = "button";
  button.className = `ui-btn ui-btn--sm ${toneClass}`;
  button.textContent = text;
  button.addEventListener("click", handler);
  return button;
};

const routeConnector = () => {
  const node = document.createElement("span");
  node.className = "map-route-connector";
  node.setAttribute("aria-hidden", "true");
  node.textContent = "→";
  return node;
};

const routeStage = (eyebrow, titleText, metaText) => {
  const stage = document.createElement("div");
  stage.className = "map-route-stage";
  const label = document.createElement("span");
  label.className = "map-route-label";
  label.textContent = eyebrow;
  const title = document.createElement("strong");
  title.textContent = titleText;
  const meta = document.createElement("small");
  meta.textContent = metaText;
  stage.append(label, title, meta);
  return stage;
};

const relayRoute = (relayChain) => {
  const stage = document.createElement("div");
  stage.className = "map-route-stage map-route-channel";
  const label = document.createElement("span");
  label.className = "map-route-label";
  label.textContent = "反向通道";
  const title = document.createElement("strong");
  const hops = Array.isArray(relayChain) ? relayChain : [];
  title.textContent = hops.length ? `经 ${hops.length} 个中继` : "出口直连入口";
  const meta = document.createElement("small");
  meta.textContent = hops.length
    ? "转发：入口 → 下列各跳 → 出口；出口主动建链"
    : "出口主动连入口，中间不经中继";
  stage.append(label, title, meta);
  if (hops.length) {
    const list = document.createElement("ol");
    list.className = "map-route-relays";
    list.setAttribute("aria-label", "中继转发顺序，入口之后到出口之前");
    hops.forEach((hop, index) => {
      const identity = listenerIdentity(hop);
      const item = document.createElement("li");
      const name = document.createElement("span");
      name.textContent = `第 ${index + 1} 跳 · ${identity.displayName}`;
      const detail = document.createElement("small");
      const side = hopSideHint(index, hops.length);
      detail.textContent = identity.owner
        ? `${identity.owner} · 监听器 ID ${identity.id}${side}`
        : `监听器 ID ${identity.id}${side}`;
      item.append(name, detail);
      list.append(item);
    });
    stage.append(list);
  }
  return stage;
};

const renderMapping = (mapping) => {
  const card = document.createElement("article");
  card.className = "ui-card map-card";
  card.dataset.id = mapping.id;
  if (!mapping.enabled) card.classList.add("map-card--disabled");

  const head = document.createElement("div");
  head.className = "map-card-head";
  const identity = document.createElement("div");
  identity.className = "map-card__identity";
  const title = document.createElement("h3");
  title.className = "map-card__title";
  title.textContent = mappingTitle(mapping);
  const badges = document.createElement("div");
  badges.className = "map-badges";
  badges.append(channelBadge(mapping));
  badges.append(badge(mapping.enabled ? "已启用" : "已停用", mapping.enabled ? "success" : ""));
  const protocol = badge(String(mapping.protocol || "").toUpperCase());
  protocol.classList.add("map-protocol");
  badges.append(protocol);
  identity.append(title, badges);
  if (mapping.last_error) {
    const error = document.createElement("p");
    error.className = "map-error";
    error.textContent = mapping.last_error;
    identity.append(error);
  }

  const actions = document.createElement("div");
  actions.className = "map-actions";
  const editButton = actionButton("编辑", "ui-btn--ghost", async () => {
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
  const toggleButton = actionButton(mapping.enabled ? "停用" : "启用", "ui-btn--ghost", async () => {
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
  const deleteButton = actionButton("删除", "ui-btn--danger-soft", async () => {
    if (busy) return;
    const confirmed = await askConfirm({
      title: "删除映射",
      desc: `将删除“${mappingTitle(mapping)}”。入口 L4 规则与反向通道会一并释放，删除后无法恢复。`,
      label: "确认删除",
    });
    if (!confirmed) {
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

  const entry = agentIdentity(mapping.entry_agent_id);
  const exit = agentIdentity(mapping.exit_agent_id);
  const routeHeading = document.createElement("p");
  routeHeading.className = "map-route-heading";
  routeHeading.textContent = "流量路径";
  const route = document.createElement("div");
  route.className = "map-route";
  const listenHost = mapping.listen_host || "0.0.0.0";
  const listenAddress = listenHost.includes(":") ? `[${listenHost}]:${mapping.listen_port}` : `${listenHost}:${mapping.listen_port}`;
  const entryMeta = `${String(mapping.protocol || "").toUpperCase()} ${listenAddress} · 客户端连接此处`;
  const backendMeta = `${mapping.backend_host}:${mapping.backend_port} · 由出口节点访问`;
  route.append(
    routeStage("公网入口", entry.displayName, entryMeta),
    routeConnector(),
    relayRoute(mapping.relay_chain),
    routeConnector(),
    routeStage("出口与内网服务", exit.displayName, backendMeta),
  );
  const technical = document.createElement("details");
  technical.className = "map-technical";
  const technicalSummary = document.createElement("summary");
  technicalSummary.className = "ui-help-text";
  technicalSummary.textContent = "技术标识";
  const technicalIDs = document.createElement("p");
  technicalIDs.className = "ui-mono";
  technicalIDs.textContent = `入口节点 ID ${entry.id} · 出口节点 ID ${exit.id} · 映射 ID ${mapping.id}`;
  technical.append(technicalSummary, technicalIDs);
  card.append(routeHeading, route, technical);
  return card;
};

const renderMappings = (mappings) => {
  const list = Array.isArray(mappings) ? mappings : [];
  if (listNode) listNode.replaceChildren(...list.map(renderMapping));
  if (emptyNode) emptyNode.hidden = list.length > 0;
  if (countNode) {
    countNode.hidden = list.length === 0;
    countNode.textContent = `${list.length} 条映射`;
  }
};

const postAction = async (mapping, action, body = {}) => {
  const payload = await pluginJSON(`api/mappings/${encodeURIComponent(mapping.id)}/${action}`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  renderMappings(payload.mappings);
};

const refresh = async (loadNames = false) => {
  const payload = await pluginJSON("api/mappings");
  if (loadNames) {
    try {
      await loadCatalogs();
    } catch (_error) {
      // Mappings remain usable with ID fallbacks when a panel catalog is temporarily unavailable.
    }
  }
  renderMappings(payload.mappings);
};

const settleConfirm = (value) => {
  if (!pendingConfirm || pendingConfirm.done) return;
  const pending = pendingConfirm;
  pending.done = true;
  pendingConfirm = null;
  if (confirmDialog && confirmDialog.open) confirmDialog.close();
  pending.resolve(Boolean(value));
};

const askConfirm = ({ title, desc, label }) => new Promise((resolve) => {
  if (!confirmDialog || typeof confirmDialog.showModal !== "function") {
    resolve(false);
    return;
  }
  if (pendingConfirm) settleConfirm(false);
  if (confirmTitle) confirmTitle.textContent = title || "确认操作";
  if (confirmDesc) confirmDesc.textContent = desc || "";
  if (confirmAccept) confirmAccept.textContent = label || "确认";
  pendingConfirm = { resolve, done: false };
  confirmDialog.showModal();
});

if (confirmCancel) confirmCancel.addEventListener("click", () => settleConfirm(false));
if (confirmAccept) confirmAccept.addEventListener("click", () => settleConfirm(true));
if (confirmDialog) {
  confirmDialog.addEventListener("cancel", (event) => {
    event.preventDefault();
    settleConfirm(false);
  });
  confirmDialog.addEventListener("close", () => {
    // 关闭事件是异步派发的：若用户已重新打开确认框，旧事件不能结算新请求。
    if (pendingConfirm && !confirmDialog.open) settleConfirm(false);
  });
}

if (mappingDialog) {
  mappingDialog.addEventListener("cancel", (event) => {
    event.preventDefault();
    closeForm();
  });
  mappingDialog.addEventListener("close", () => {
    if (!mappingDialog.open) resetWizard();
  });
}

[createToggle, createEmpty].forEach((button) => {
  if (!button) return;
  button.addEventListener("click", async () => {
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
});

if (formCancel) formCancel.addEventListener("click", closeForm);
if (formClose) formClose.addEventListener("click", closeForm);
if (wizardNext) wizardNext.addEventListener("click", goNext);
if (wizardBack) wizardBack.addEventListener("click", goBack);

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
    clearFieldErrors();
    showWizardError("");
    if (!catalogReady) {
      const message = (catalogErrorNode && catalogErrorNode.textContent)
        || "节点或中继目录不可用，无法保存映射。";
      showWizardError(message);
      showStatus(message, true);
      return;
    }
    if (!checkAllSteps()) return;
    const mapping = formMapping();
    const updating = Boolean(editingID);
    setBusy(true);
    try {
      if (updating) {
        await postAction({ id: editingID }, "update", mapping);
      } else {
        const payload = await pluginJSON("api/mappings", { method: "POST", body: JSON.stringify(mapping) });
        renderMappings(payload.mappings);
      }
      closeForm();
      showStatus(updating ? "已保存映射。" : "已创建映射。", false);
    } catch (error) {
      showWizardError(error.message);
      showStatus(error.message, true);
    } finally {
      setBusy(false);
    }
  });
}

(async () => {
  try {
    await refresh(true);
    if (loadingNode) loadingNode.hidden = true;
    if (workspaceNode) workspaceNode.hidden = false;
  } catch (error) {
    if (loadingNode) loadingNode.hidden = true;
    if (error.denied) {
      if (deniedNode) deniedNode.hidden = false;
    } else if (unavailableNode) {
      unavailableNode.hidden = false;
      const desc = document.querySelector("#map-unavailable-desc");
      if (desc) desc.textContent = error.message || desc.textContent;
    }
  }
})();