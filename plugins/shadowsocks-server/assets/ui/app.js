const applyHostTheme = () => {
  const allowed = { light: true, dark: true };
  const aliases = { "sakura-day": "light", business: "light", "fresh-green": "light", sakura: "light", cyberpunk: "light", "sakura-night": "dark", "neko-dark": "dark", midnight: "dark" };
  let theme = "light";
  try {
    const raw = window.parent && window.parent !== window
      ? window.parent.document.documentElement.getAttribute("data-theme")
      : document.documentElement.getAttribute("data-theme");
    const mapped = aliases[raw] || raw;
    if (allowed[mapped]) theme = mapped;
  } catch (_error) {
    theme = "light";
  }
  document.documentElement.setAttribute("data-theme", theme);
};

applyHostTheme();

const statusNode = document.querySelector("#app-status");
const loadingNode = document.querySelector("#app-loading");
const unavailableNode = document.querySelector("#app-unavailable");
const deniedNode = document.querySelector("#app-denied");
const contextNode = document.querySelector("#app-context");
const workspaceNode = document.querySelector("#app-workspace");
const listNode = document.querySelector("#listen-list");
const emptyNode = document.querySelector("#app-empty");
const countNode = document.querySelector("#listen-count");
const listPanel = document.querySelector("#app-list-panel");
const workspaceHead = document.querySelector(".workspace-head");
const createDialog = document.querySelector("#create-dialog");
const createForm = document.querySelector("#create-form");
const createSubmit = document.querySelector("#create-submit");
const createCancel = document.querySelector("#create-cancel");
const createToggle = document.querySelector("#create-toggle");
const emptyCreate = document.querySelector("#empty-create");
const shareHostInput = document.querySelector("#share-host");
const shareHostSave = document.querySelector("#share-host-save");
const shareHostAuto = document.querySelector("#share-host-auto");
const shareHostSource = document.querySelector("#share-host-source");
const shareHostBar = document.querySelector(".share-host-bar");
const detailDialog = document.querySelector("#detail-dialog");
const detailTitle = document.querySelector("#detail-title");
const detailMeta = document.querySelector("#detail-meta");
const detailUsers = document.querySelector("#detail-users");
const detailActions = document.querySelector("#detail-actions");
const agentSelect = document.querySelector("#agent-select");
const agentPickerRoot = document.querySelector('[data-agent-picker="workspace"]');
const nodeEmpty = document.querySelector("#app-node-empty");
const offlineNode = document.querySelector("#app-offline");
const executionUnavailableNode = document.querySelector("#app-execution-unavailable");
const executionStatus = document.querySelector("#execution-status");
const serverPskField = document.querySelector("#server-psk-field");
const confirmDialog = document.querySelector("#confirm-dialog");
const confirmTitle = document.querySelector("#confirm-title");
const confirmBody = document.querySelector("#confirm-body");
const confirmOk = document.querySelector("#confirm-ok");
const confirmCancel = document.querySelector("#confirm-cancel");
const qrDialog = document.querySelector("#qr-dialog");
const qrTitle = document.querySelector("#qr-title");
const qrCaption = document.querySelector("#qr-caption");
const qrImage = document.querySelector("#qr-image");
const qrCopy = document.querySelector("#qr-copy");
const advancedKeys = document.querySelector("#advanced-keys");
const appendDialog = document.querySelector("#append-dialog");
const appendForm = document.querySelector("#append-form");
const appendName = document.querySelector("#append-name");
const appendMeta = document.querySelector("#append-meta");
const appendCancel = document.querySelector("#append-cancel");

const METHOD_LABELS = {
  "2022-blake3-aes-128-gcm": "SS2022 · AES-128",
  "2022-blake3-aes-256-gcm": "SS2022 · AES-256",
  "aes-128-gcm": "AES-128-GCM",
  "aes-256-gcm": "AES-256-GCM",
};

const askConfirm = ({ title, body, confirm = "确定", cancel = "取消", danger = false } = {}) => {
  if (!confirmDialog || typeof confirmDialog.showModal !== "function") {
    return Promise.resolve(window.confirm([title, body].filter(Boolean).join("\n")));
  }
  if (confirmDialog.open) confirmDialog.close("cancel");
  if (confirmTitle) confirmTitle.textContent = title || "确认";
  if (confirmBody) {
    confirmBody.textContent = body || "";
    confirmBody.hidden = !body;
  }
  if (confirmOk) {
    confirmOk.textContent = confirm;
    confirmOk.dataset.danger = danger ? "true" : "false";
  }
  if (confirmCancel) confirmCancel.textContent = cancel;
  return new Promise((resolve) => {
    const onClose = () => resolve(confirmDialog.returnValue === "ok");
    confirmDialog.addEventListener("close", onClose, { once: true });
    confirmDialog.showModal();
    if (confirmCancel) confirmCancel.focus();
  });
};

let busy = false;
let selectedAgentID = "";
let agentsCache = [];
let listensCache = [];
let openListenID = "";
let pendingAppendListen = null;
let executionReady = false;
let agentOnline = false;
let lastExecution = null;
let workspaceSeq = 0;
const executionCache = new Map();
const EXECUTION_CACHE_MS = 15000;
const EXECUTION_PROBE_CONCURRENCY = 3;

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

let statusTimer = null;
const STATUS_CLEAR_MS = 4000;

const showStatus = (message, isError) => {
  if (!statusNode) return;
  if (statusTimer) {
    clearTimeout(statusTimer);
    statusTimer = null;
  }
  statusNode.hidden = !message;
  statusNode.textContent = message || "";
  if (!message) {
    delete statusNode.dataset.error;
    return;
  }
  statusNode.dataset.error = isError ? "true" : "false";
  if (!isError) {
    statusTimer = setTimeout(() => {
      if (statusNode.textContent === message) showStatus("", false);
    }, STATUS_CLEAR_MS);
  }
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
  const payload = await response.json().catch(() => ({}));
  if (response.status === 403) {
    throw Object.assign(new Error(payload.error || payload.message || "无权访问"), { denied: true, status: 403 });
  }
  if (!response.ok) {
    throw Object.assign(new Error(payload.error || payload.message || "请求失败"), { status: response.status });
  }
  return payload;
};

const selectedAgentRecord = () => agentsCache.find((agent) => agent && agent.id === selectedAgentID) || null;

const agentIdentityFields = () => {
  const agent = selectedAgentRecord();
  if (!agent) return {};
  const lastSeen = String(agent.last_seen_ip || "").trim();
  const ipv4 = String(agent.last_seen_ipv4 || agent.ipv4 || "").trim();
  const ipv6 = String(agent.last_seen_ipv6 || agent.ipv6 || "").trim();
  return {
    ddns_domain: String(agent.ddns_domain || "").trim(),
    ipv4: ipv4 || (/^\d{1,3}(\.\d{1,3}){3}$/.test(lastSeen) ? lastSeen : ""),
    ipv6: ipv6,
  };
};

const mutateBody = (extra = {}) => ({ agent_id: selectedAgentID, ...agentIdentityFields(), ...extra });

const sendPluginJSON = async (path, body) => {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      ...panelAuthHeaders(),
      "X-NRE-Operation-Key": newOperationKey(),
    },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || payload.message || "保存失败");
  }
  return payload;
};

const syncSelectionActions = () => {
  const blocked = busy || !selectedAgentID || !executionReady || !agentOnline;
  if (createToggle) createToggle.disabled = blocked;
  if (emptyCreate) emptyCreate.disabled = blocked;
  if (shareHostSave) shareHostSave.disabled = blocked;
  if (shareHostAuto) shareHostAuto.disabled = blocked;
  if (shareHostInput) shareHostInput.disabled = blocked;
};

const setBusy = (next) => {
  busy = next;
  const roots = [workspaceNode, contextNode, createDialog, detailDialog, appendDialog].filter(Boolean);
  roots.forEach((root) => {
    root.querySelectorAll("button, input, textarea, select").forEach((node) => {
      if (node === agentSelect) return;
      if (agentPickerRoot && agentPickerRoot.contains(node)) return;
      node.disabled = next;
    });
  });
  if (!next) syncSelectionActions();
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

const cachedExecution = (agentID) => {
  const cached = executionCache.get(agentID);
  if (!cached) return null;
  if (Date.now() - cached.at > EXECUTION_CACHE_MS) return null;
  return cached;
};

const rememberExecution = (agentID, execution) => {
  if (!agentID) return null;
  const entry = {
    ready: execution?.ready === true,
    online: execution?.online === true,
    at: Date.now(),
  };
  executionCache.set(agentID, entry);
  return entry;
};

const probeExecution = async (agentID) => {
  if (!agentID) return null;
  const cached = executionCache.get(agentID);
  if (cached && Date.now() - cached.at < EXECUTION_CACHE_MS) return cached;
  try {
    const payload = await panelJSON(`api/execution?agent_id=${encodeURIComponent(agentID)}`);
    return rememberExecution(agentID, payload.execution || null);
  } catch (_error) {
    return cached || null;
  }
};

const probeExecutions = async (agentIDs, onDone) => {
  const pending = agentIDs.filter((id) => {
    if (!id) return false;
    const cached = executionCache.get(id);
    return !cached || Date.now() - cached.at >= EXECUTION_CACHE_MS;
  });
  if (!pending.length) return;
  let index = 0;
  const workers = Array.from({ length: Math.min(EXECUTION_PROBE_CONCURRENCY, pending.length) }, async () => {
    while (index < pending.length) {
      const id = pending[index];
      index += 1;
      await probeExecution(id);
    }
  });
  await Promise.all(workers);
  if (typeof onDone === "function") onDone();
};

const executionMark = (state) => {
  const node = document.createElement("span");
  node.className = "agent-search-select__engine";
  node.dataset.ready = state.ready ? "true" : "false";
  node.textContent = state.ready ? "可创建" : "不可用";
  return node;
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
    onChange: null,
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
  const triggerEngine = document.createElement("span");
  triggerEngine.className = "agent-search-select__engine";
  triggerEngine.hidden = true;
  const chevron = document.createElement("span");
  chevron.className = "agent-search-select__chevron";
  chevron.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><polyline points="6 9 12 15 18 9"/></svg>';
  trigger.append(statusDot, label, triggerEngine, chevron);

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

  const currentAgent = () => agentsCache.find((agent) => agent && agent.id === picker.selected) || null;

  const syncTrigger = () => {
    hiddenInput.value = picker.selected;
    const agent = currentAgent();
    const execution = picker.selected ? cachedExecution(picker.selected) : null;
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
    if (execution && !execution.ready && agent && isAgentOnline(agent)) {
      triggerEngine.hidden = false;
      triggerEngine.dataset.ready = "false";
      triggerEngine.textContent = "不可用";
    } else {
      triggerEngine.hidden = true;
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

  const emitChange = (value) => {
    picker.setValue(value);
    picker.close();
    if (typeof picker.onChange === "function") picker.onChange(value);
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
    if (!picker.search.trim() && !picker.statusFilter && agentsCache.length) {
      const clear = document.createElement("button");
      clear.type = "button";
      clear.className = "agent-search-select__option";
      clear.setAttribute("role", "option");
      clear.setAttribute("aria-selected", picker.selected ? "false" : "true");
      const name = document.createElement("span");
      name.className = "agent-search-select__option-name";
      name.dataset.empty = "true";
      name.textContent = placeholder;
      clear.append(name);
      clear.addEventListener("click", () => emitChange(""));
      list.append(clear);
    }
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
      const execution = cachedExecution(agent.id);
      if (execution && !execution.ready && isAgentOnline(agent)) option.append(executionMark(execution));
      option.addEventListener("click", () => emitChange(agent.id));
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
    picker.open = true;
    dropdown.hidden = false;
    trigger.setAttribute("aria-expanded", "true");
    renderList();
    searchInput.focus();
    probeExecutions(filteredAgents().slice(0, 12).map((agent) => agent.id), () => {
      if (picker.open) renderList();
      syncTrigger();
    });
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

const agentPicker = mountAgentSearchSelect(agentPickerRoot, agentSelect, "选择节点");

const selectedAgent = () => agentsCache.find((agent) => agent.id === selectedAgentID) || null;

const isSS2022 = (method) => String(method || "").startsWith("2022-");

const copyText = async (text) => {
  const value = String(text || "");
  if (!value) throw new Error("没有可复制的内容");
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(value);
      return;
    }
  } catch (_error) {
    // Fall back to a selected textarea; iframe panels often deny clipboard.
  }
  const area = document.createElement("textarea");
  area.value = value;
  area.setAttribute("readonly", "");
  area.style.cssText = "position:fixed;left:-9999px;top:0";
  document.body.append(area);
  area.focus();
  area.select();
  const ok = document.execCommand("copy");
  area.remove();
  if (!ok) throw new Error("当前环境无法复制");
};

const markCopied = (button) => {
  if (!button) return;
  const original = button.dataset.copyLabel || button.textContent;
  button.dataset.copyLabel = original;
  button.textContent = "已复制";
  window.setTimeout(() => {
    if (button.textContent === "已复制") button.textContent = original;
  }, 1600);
};

const showContext = (kind) => {
  if (!contextNode) return;
  contextNode.hidden = !kind;
  if (nodeEmpty) nodeEmpty.hidden = kind !== "empty";
  if (offlineNode) offlineNode.hidden = kind !== "offline";
  if (executionUnavailableNode) executionUnavailableNode.hidden = kind !== "execution-unavailable";
};

const methodLabel = (method) => METHOD_LABELS[String(method || "")] || String(method || "");

const listenHostPort = (listen) => {
  if (listen && listen.host_port) return String(listen.host_port);
  const user = ((listen && listen.users) || []).find((item) => item && item.host_port);
  return user ? String(user.host_port) : "";
};

const listenShareHost = (listen) => {
  const hostPort = listenHostPort(listen);
  if (!hostPort) return "";
  if (hostPort.startsWith("[")) {
    const end = hostPort.indexOf("]");
    return end > 0 ? hostPort.slice(1, end) : hostPort;
  }
  const index = hostPort.lastIndexOf(":");
  return index > 0 ? hostPort.slice(0, index) : hostPort;
};

const renderExecutionBadge = (execution) => {
  if (!executionStatus) return;
  if (!execution || execution.ready) {
    executionStatus.hidden = true;
    executionStatus.textContent = "";
    delete executionStatus.dataset.ready;
    return;
  }
  executionStatus.hidden = false;
  executionStatus.dataset.ready = "false";
  executionStatus.textContent = "暂时无法执行";
};

const syncListPanel = () => {
  const hasListens = listNode && listNode.children.length > 0;
  if (emptyNode) emptyNode.hidden = !selectedAgentID || !executionReady || hasListens;
  if (listPanel) listPanel.hidden = false;
  if (workspaceHead) workspaceHead.hidden = false;
  if (createToggle) createToggle.hidden = !(selectedAgentID && executionReady && agentOnline);
};

const closeCreate = () => {
  if (createForm) createForm.reset();
  if (advancedKeys) advancedKeys.open = false;
  if (createDialog && createDialog.open) createDialog.close();
  syncListPanel();
};

const methodInput = () => (createForm ? createForm.querySelector('select[name="method"]') : null);

const syncServerPskField = () => {
  const method = methodInput() ? methodInput().value : "";
  if (serverPskField) serverPskField.hidden = !isSS2022(method);
};

const fillDefaults = (defaults) => {
  if (!createForm || !defaults) return;
  createForm.querySelector('input[name="name"]').value = "";
  createForm.querySelector('select[name="method"]').value = defaults.method || "2022-blake3-aes-128-gcm";
  createForm.querySelector('input[name="port"]').value = defaults.port || "";
  createForm.querySelector('input[name="password"]').value = "";
  createForm.querySelector('input[name="server_psk"]').value = "";
  if (advancedKeys) advancedKeys.open = false;
  syncServerPskField();
};

const openCreate = async () => {
  if (!executionReady || !agentOnline) return;
  try {
    const payload = await panelJSON(`api/defaults?agent_id=${encodeURIComponent(selectedAgentID)}`);
    fillDefaults(payload.defaults);
  } catch (error) {
    showStatus(error.message, true);
    return;
  }
  if (createDialog) {
    if (createDialog.open) createDialog.close();
    createDialog.showModal();
  }
};

const qrDataURL = (user) => {
  if (user && user.qr_png_base64) return `data:image/png;base64,${user.qr_png_base64}`;
  return "";
};

const qrFallbackURL = (user) => (user && user.id ? `api/users/${encodeURIComponent(user.id)}/qr.png` : "");

let pendingQRURI = "";

const bindQRImage = (img, user) => {
  if (!img) return;
  img.alt = "ss:// 二维码";
  img.hidden = false;
  const data = qrDataURL(user);
  const fallback = qrFallbackURL(user);
  const fail = () => {
    if (fallback && !img.dataset.fallbackUsed) {
      img.dataset.fallbackUsed = "true";
      img.src = fallback;
      return;
    }
    img.hidden = true;
  };
  img.onerror = fail;
  if (data) img.src = data;
  else if (fallback) {
    img.dataset.fallbackUsed = "true";
    img.src = fallback;
  } else {
    img.hidden = true;
  }
};

const qrButton = (user) => {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "btn-secondary";
  button.textContent = "二维码";
  button.addEventListener("click", () => openQR(user));
  return button;
};

const openQR = (user) => {
  if (!qrDialog || typeof qrDialog.showModal !== "function") return;
  pendingQRURI = user && user.uri ? String(user.uri) : "";
  if (qrTitle) qrTitle.textContent = (user && (user.name || user.id)) || "二维码";
  if (qrCaption) {
    qrCaption.textContent = (user && user.host_port) || "";
    qrCaption.hidden = !qrCaption.textContent;
  }
  if (qrImage) {
    delete qrImage.dataset.fallbackUsed;
    bindQRImage(qrImage, user);
  }
  if (qrDialog.open) qrDialog.close();
  qrDialog.showModal();
};

const renderStatusPill = (text, on) => {
  const status = document.createElement("span");
  status.className = "status-pill";
  status.dataset.on = on ? "true" : "false";
  status.textContent = text;
  return status;
};

const copyURIButton = (user) => {
  const copy = document.createElement("button");
  copy.type = "button";
  copy.className = "btn-primary";
  copy.textContent = "复制 ss://";
  copy.addEventListener("click", async () => {
    try {
      await copyText(user.uri);
      markCopied(copy);
    } catch (error) {
      showStatus(error.message, true);
    }
  });
  return copy;
};

const shareHint = (user) => {
  const hint = document.createElement("p");
  hint.className = "hint";
  hint.textContent = user.enabled
    ? (user.reason || "暂时无法分享")
    : "停用后无法导入。再启用即可复制链接。";
  return hint;
};

const renderShare = (user) => {
  const wrap = document.createElement("div");
  wrap.className = "share-row";
  if (user.share_available && user.uri) {
    wrap.append(copyURIButton(user), qrButton(user));
  } else {
    wrap.append(shareHint(user));
  }
  return wrap;
};

const userManageButtons = (user) => {
  const actions = document.createElement("div");
  actions.className = "account-actions";
  const toggle = document.createElement("button");
  toggle.type = "button";
  toggle.className = "btn-secondary";
  toggle.textContent = user.enabled ? "停用" : "再启用";
  toggle.addEventListener("click", () => mutateUser(user, user.enabled ? "disable" : "enable"));
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "btn-link danger";
  remove.textContent = "删除用户";
  remove.addEventListener("click", () => mutateUser(user, "delete", true));
  actions.append(toggle, remove);
  return actions;
};

const renderUser = (user, { manage = false, compact = false } = {}) => {
  const article = document.createElement("article");
  article.className = compact ? "account account--card" : "account";
  article.dataset.id = user.id;
  article.dataset.enabled = user.enabled ? "true" : "false";
  const head = document.createElement("div");
  head.className = "account-head";
  const identity = document.createElement("strong");
  identity.textContent = user.name || user.id;
  head.append(identity, renderStatusPill(user.enabled ? "启用" : "已停用", user.enabled));
  article.append(head, renderShare(user));
  if (manage) article.append(userManageButtons(user));
  return article;
};

const primaryUser = (listen) => {
  const users = (listen && listen.users) || [];
  return users.find((user) => user && user.enabled && user.share_available && user.uri) || users[0] || null;
};

const listenFooterActions = (listen, { detail = false, close = false } = {}) => {
  const actions = document.createElement("div");
  actions.className = detail ? "dialog-actions" : "listen-card-actions";
  if (!detail) {
    const open = document.createElement("button");
    open.type = "button";
    open.className = "btn-secondary";
    open.textContent = "详情";
    open.addEventListener("click", () => openDetail(listen));
    actions.append(open);
  }
  if (isSS2022(listen.method)) {
    const append = document.createElement("button");
    append.type = "button";
    append.className = "btn-secondary";
    append.textContent = "追加用户";
    append.addEventListener("click", () => appendUser(listen));
    actions.append(append);
  }
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "btn-link danger";
  remove.textContent = "删除监听";
  remove.addEventListener("click", () => deleteListen(listen));
  actions.append(remove);
  if (close) {
    const done = document.createElement("button");
    done.type = "button";
    done.className = "btn-secondary";
    done.textContent = "关闭";
    done.addEventListener("click", closeDetail);
    actions.append(done);
  }
  return actions;
};

const renderListen = (listen) => {
  const card = document.createElement("article");
  card.className = "listen-card";
  card.dataset.id = listen.id;
  card.dataset.bound = listen.bound ? "true" : "false";

  const head = document.createElement("div");
  head.className = "listen-card-head";
  const mark = document.createElement("span");
  mark.className = "listen-card-mark";
  mark.dataset.tone = String((Number(listen.port) || 0) % 6);
  mark.textContent = String(listen.port || "");
  const identity = document.createElement("div");
  identity.className = "listen-card-identity";
  const titleRow = document.createElement("div");
  titleRow.className = "listen-card-title-row";
  const title = document.createElement("h3");
  title.textContent = `端口 ${listen.port}`;
  titleRow.append(title, renderStatusPill(listen.bound ? "运行中" : "未生效", listen.bound));
  const meta = document.createElement("p");
  meta.className = "listen-card-meta";
  const users = listen.users || [];
  meta.textContent = [methodLabel(listen.method), users.length ? `${users.length} 个用户` : ""].filter(Boolean).join(" · ");
  identity.append(titleRow, meta);
  head.append(mark, identity);
  card.append(head);
  const first = primaryUser(listen);
  if (first) {
    const account = renderUser(first, { compact: true });
    if (users.length > 1) {
      const more = document.createElement("button");
      more.type = "button";
      more.className = "btn-link more-users";
      more.textContent = `还有 ${users.length - 1} 个用户`;
      more.addEventListener("click", () => openDetail(listen));
      const share = account.querySelector(".share-row");
      if (share) share.append(more);
      else account.append(more);
    }
    card.append(account);
  }
  card.append(listenFooterActions(listen));
  return card;
};

const closeDetail = () => {
  openListenID = "";
  if (detailDialog && detailDialog.open) detailDialog.close();
};

const renderDetail = (listen) => {
  if (!detailDialog) return;
  openListenID = listen.id;
  if (detailTitle) detailTitle.textContent = `端口 ${listen.port}`;
  if (detailMeta) {
    const parts = [methodLabel(listen.method), listenShareHost(listen), listen.bound ? "运行中" : "未生效"].filter(Boolean);
    detailMeta.textContent = parts.join(" · ");
    detailMeta.hidden = !detailMeta.textContent;
  }
  if (detailUsers) {
    detailUsers.replaceChildren();
    (listen.users || []).forEach((user) => detailUsers.append(renderUser(user, { manage: true })));
  }
  if (detailActions) {
    const footer = listenFooterActions(listen, { detail: true, close: true });
    detailActions.replaceChildren(...Array.from(footer.children));
  }
};

const openDetail = (listen) => {
  renderDetail(listen);
  if (detailDialog && typeof detailDialog.showModal === "function") {
    if (detailDialog.open) return;
    detailDialog.showModal();
  }
};

const refreshOpenDetail = () => {
  if (!openListenID || !detailDialog || !detailDialog.open) return;
  const listen = listensCache.find((item) => item && item.id === openListenID);
  if (listen) renderDetail(listen);
  else if (listensCache.length) closeDetail();
};

const renderListens = (listens) => {
  if (!listNode) return;
  listensCache = listens || [];
  listNode.replaceChildren();
  listensCache.forEach((listen) => listNode.append(renderListen(listen)));
  if (countNode) {
    countNode.hidden = !listensCache.length;
    countNode.textContent = listensCache.length ? `${listensCache.length} 条监听` : "";
  }
  syncListPanel();
  refreshOpenDetail();
  if (busy) setBusy(true);
};

const mutateUser = async (user, action, confirmDelete = false) => {
  if (!canMutate()) return;
  if (confirmDelete) {
    const ok = await askConfirm({ title: "删除用户", body: "删掉后不能恢复。同一端口的其他人不受影响。", confirm: "删除", danger: true });
    if (!ok) return;
  }
  setBusy(true);
  try {
    await sendPluginJSON(`api/users/${encodeURIComponent(user.id)}/${action}`, mutateBody());
    await renderWorkspace();
    const message = action === "enable" ? "已启用该用户。" : action === "disable" ? "已停用该用户。" : "已删除用户。";
    showStatus(message, false);
  } catch (error) {
    showStatus(error.message, true);
  } finally {
    setBusy(false);
  }
};

const closeAppend = () => {
  pendingAppendListen = null;
  if (appendForm) appendForm.reset();
  if (appendDialog && appendDialog.open) appendDialog.close();
};

const openAppend = (listen) => {
  if (!canMutate() || !listen) return;
  pendingAppendListen = listen;
  if (appendMeta) {
    appendMeta.textContent = `端口 ${listen.port} · ${methodLabel(listen.method)}`;
    appendMeta.hidden = !appendMeta.textContent;
  }
  if (appendForm) appendForm.reset();
  if (appendDialog && typeof appendDialog.showModal === "function") {
    if (appendDialog.open) appendDialog.close();
    appendDialog.showModal();
  }
  if (appendName) appendName.focus();
};

const appendUser = (listen) => {
  openAppend(listen);
};

const deleteListen = async (listen) => {
  if (!canMutate()) return;
  const ok = await askConfirm({ title: "删除监听", body: "会关掉这个端口，上面的用户也会一起删掉。", confirm: "删除", danger: true });
  if (!ok) return;
  setBusy(true);
  try {
    if (openListenID === listen.id) closeDetail();
    await sendPluginJSON(`api/listens/${encodeURIComponent(listen.id)}/delete`, mutateBody());
    await renderWorkspace();
    showStatus("已删除监听。", false);
  } catch (error) {
    showStatus(error.message, true);
  } finally {
    setBusy(false);
  }
};

const canMutate = () => {
  if (!selectedAgentID) {
    showStatus("请先选择一台节点。", true);
    return false;
  }
  if (!agentOnline) {
    showStatus("该节点离线，不能新增或改动监听。", true);
    return false;
  }
  if (!executionReady) {
    showStatus("该节点暂时无法执行监听。", true);
    return false;
  }
  return true;
};

const loadExecution = async () => {
  if (!selectedAgentID) return null;
  const payload = await panelJSON(`api/execution?agent_id=${encodeURIComponent(selectedAgentID)}`);
  rememberExecution(selectedAgentID, payload.execution || null);
  return payload.execution || null;
};

const agentShareHost = (agent) => {
  if (!agent) return "";
  return String(agent.ddns_domain || agent.last_seen_ipv4 || agent.ipv4 || "").trim();
};

const shareHostSourceLabel = (source) => {
  if (source === "override") return "已手动指定，保存后不随节点变更";
  if (source === "ddns") return "来自节点域名，随节点自动更新";
  if (source === "ipv4") return "来自节点 IPv4，随节点自动更新";
  if (source === "ipv6") return "来自节点 IPv6，随节点自动更新";
  return "";
};

const fillShareHost = (execution, listens) => {
  if (!shareHostInput) return;
  shareHostInput.value = String(
    (execution && execution.share_host) ||
      listenShareHost((listens || [])[0] || null) ||
      agentShareHost(selectedAgent()) ||
      ""
  );
  const source = String((execution && execution.share_host_source) || "");
  const note = shareHostSourceLabel(source);
  if (shareHostSource) {
    shareHostSource.textContent = note;
    shareHostSource.hidden = !note;
  }
  if (shareHostAuto) shareHostAuto.hidden = source !== "override";
};

const syncShareHostBar = (visible) => {
  if (shareHostBar) shareHostBar.hidden = !visible;
  if (!visible && shareHostAuto) shareHostAuto.hidden = true;
  if (!visible && shareHostSource) {
    shareHostSource.hidden = true;
    shareHostSource.textContent = "";
  }
};

const clearWorkspace = (kind) => {
  executionReady = false;
  lastExecution = null;
  workspaceNode.hidden = true;
  emptyNode.hidden = true;
  renderListens([]);
  renderExecutionBadge(null);
  showContext(kind);
  fillShareHost(null, []);
  syncShareHostBar(Boolean(selectedAgentID));
};

const renderWorkspace = async () => {
  const seq = workspaceSeq + 1;
  workspaceSeq = seq;
  const agent = selectedAgent();
  agentOnline = isAgentOnline(agent);
  closeCreate();
  if (!selectedAgentID) {
    clearWorkspace("empty");
    return;
  }
  if (!agentOnline) {
    let execution = null;
    try {
      execution = await loadExecution();
    } catch (_error) {
      execution = null;
    }
    if (seq !== workspaceSeq) return;
    clearWorkspace("offline");
    fillShareHost(execution, []);
    return;
  }
  showContext("");
  let execution = null;
  try {
    execution = await loadExecution();
  } catch (error) {
    if (seq !== workspaceSeq) return;
    if (error && error.denied) throw error;
    if (error && error.message === "暂时无法管理 Shadowsocks 服务。") throw error;
    clearWorkspace("execution-unavailable");
    return;
  }
  if (seq !== workspaceSeq) return;
  lastExecution = execution;
  executionReady = execution?.ready === true;
  renderExecutionBadge(execution);
  if (!executionReady) {
    clearWorkspace("execution-unavailable");
    return;
  }
  workspaceNode.hidden = false;
  const payload = await panelJSON(`api/listens?agent_id=${encodeURIComponent(selectedAgentID)}`);
  if (seq !== workspaceSeq) return;
  renderListens(payload.listens);
  fillShareHost(execution, payload.listens);
  syncShareHostBar(true);
  if (payload.error) showStatus(payload.error, true);
};

const loadAgents = async () => {
  const payload = await panelJSON("/panel-api/agents");
  agentsCache = Array.isArray(payload.agents)
    ? payload.agents.filter((agent) => agent && agent.is_local !== true && agent.mode !== "local")
    : [];
  const requested = new URLSearchParams(window.location.search).get("agent_id") || "";
  selectedAgentID = agentsCache.some((agent) => agent.id === requested)
    ? requested
    : (agentsCache.length === 1 ? agentsCache[0].id : "");
  agentPicker.refresh(selectedAgentID);
};

agentPicker.onChange = async (value) => {
  selectedAgentID = String(value || "");
  const url = new URL(window.location.href);
  if (selectedAgentID) url.searchParams.set("agent_id", selectedAgentID);
  else url.searchParams.delete("agent_id");
  window.history.replaceState({}, "", url);
  closeCreate();
  closeDetail();
  closeAppend();
  fillShareHost(null, []);
  syncShareHostBar(Boolean(selectedAgentID));
  try {
    await renderWorkspace();
  } catch (error) {
    showStatus(error.message, true);
  }
};

const openCreateFromButton = () => {
  if (!canMutate()) return;
  openCreate();
};
if (createToggle) createToggle.addEventListener("click", openCreateFromButton);
if (emptyCreate) emptyCreate.addEventListener("click", openCreateFromButton);

if (createCancel) createCancel.addEventListener("click", closeCreate);
if (createDialog) {
  createDialog.addEventListener("click", (event) => {
    if (event.target === createDialog) closeCreate();
  });
}
if (detailDialog) {
  detailDialog.addEventListener("click", (event) => {
    if (event.target === detailDialog) closeDetail();
  });
  detailDialog.addEventListener("close", () => {
    openListenID = "";
  });
}
if (methodInput()) methodInput().addEventListener("change", syncServerPskField);
if (qrCopy) {
  qrCopy.addEventListener("click", async () => {
    try {
      await copyText(pendingQRURI);
      markCopied(qrCopy);
    } catch (error) {
      showStatus(error.message, true);
    }
  });
}
const saveShareHost = async (host, message) => {
  if (!canMutate()) return;
  setBusy(true);
  try {
    await sendPluginJSON("api/share-host", mutateBody({ host }));
    await renderWorkspace();
    showStatus(message, false);
  } catch (error) {
    showStatus(error.message, true);
  } finally {
    setBusy(false);
  }
};

if (shareHostSave) {
  shareHostSave.addEventListener("click", () => {
    const host = shareHostInput ? String(shareHostInput.value || "").trim() : "";
    saveShareHost(host, "已更新连接地址。");
  });
}
if (shareHostAuto) {
  shareHostAuto.addEventListener("click", () => {
    saveShareHost("", "已恢复为节点自动地址。");
  });
}

if (appendCancel) appendCancel.addEventListener("click", closeAppend);
if (appendDialog) {
  appendDialog.addEventListener("click", (event) => {
    if (event.target === appendDialog) closeAppend();
  });
}
if (appendForm) {
  appendForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const listen = pendingAppendListen;
    if (!listen || !canMutate()) return;
    const name = String(new FormData(appendForm).get("name") || "").trim();
    setBusy(true);
    try {
      await sendPluginJSON(`api/listens/${encodeURIComponent(listen.id)}/users`, mutateBody({ name }));
      const listenID = listen.id;
      closeAppend();
      await renderWorkspace();
      const updated = listensCache.find((item) => item && item.id === listenID);
      if (updated) openDetail(updated);
      showStatus("已追加用户。", false);
    } catch (error) {
      showStatus(error.message, true);
    } finally {
      setBusy(false);
    }
  });
}

if (createForm) {
  createForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!canMutate()) return;
    const data = new FormData(createForm);
    const body = mutateBody({
      name: String(data.get("name") || "").trim(),
      method: String(data.get("method") || "").trim(),
      password: String(data.get("password") || "").trim(),
      server_psk: String(data.get("server_psk") || "").trim(),
    });
    const port = Number(data.get("port"));
    if (Number.isFinite(port) && port > 0) body.port = port;
    setBusy(true);
    try {
      await sendPluginJSON("api/listens", body);
      showStatus("已保存。", false);
      closeCreate();
      await renderWorkspace();
    } catch (error) {
      showStatus(error.message, true);
    } finally {
      setBusy(false);
    }
  });
}

const boot = async () => {
  if (loadingNode) loadingNode.hidden = false;
  try {
    await loadAgents();
    await renderWorkspace();
    if (deniedNode) deniedNode.hidden = true;
    if (unavailableNode) unavailableNode.hidden = true;
  } catch (error) {
    if (error && error.denied) {
      if (deniedNode) deniedNode.hidden = false;
      return;
    }
    if (unavailableNode) {
      unavailableNode.hidden = false;
      unavailableNode.textContent = error.message || "暂时无法管理 Shadowsocks 服务。";
    }
  } finally {
    if (loadingNode) loadingNode.hidden = true;
  }
};

boot();
