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
const listNode = document.querySelector("#app-list");
const appCardTemplate = document.querySelector("#app-card-template");
const emptyNode = document.querySelector("#app-empty");
const countNode = document.querySelector("#app-count");
const createPanel = document.querySelector("#app-create");
const listPanel = document.querySelector("#app-list-panel");
const workspaceHead = document.querySelector(".workspace-head");
const detailPanel = document.querySelector("#app-detail");
const detailTitle = document.querySelector("#detail-title");
const detailStatus = document.querySelector("#detail-status");
const detailOpen = document.querySelector("#detail-open");
const detailStart = document.querySelector("#detail-start");
const detailStop = document.querySelector("#detail-stop");
const detailRestart = document.querySelector("#detail-restart");
const detailNav = document.querySelector("#detail-nav");
const detailBack = document.querySelector("#detail-back");
const createTemplates = document.querySelector("#create-templates");
const overviewPanel = document.querySelector("#detail-overview");
const filesPanel = document.querySelector("#detail-files");
const httpPanel = document.querySelector("#detail-http");
const composeForm = document.querySelector("#compose-form");
const composeSubmit = document.querySelector("#compose-submit");
const logsService = document.querySelector("#logs-service");
const logsRefresh = document.querySelector("#logs-refresh");
const logsPause = document.querySelector("#logs-pause");
const logsStatus = document.querySelector("#logs-status");
const logsView = document.querySelector("#logs-view");
const createForm = document.querySelector("#create-form");
const createTitle = document.querySelector("#app-create-title");
const createSubmit = document.querySelector("#create-submit");
const createCancel = document.querySelector("#create-cancel");
const createBack = document.querySelector("#create-back");
const deployToggle = document.querySelector("#deploy-toggle");
const diskCleanup = document.querySelector("#disk-cleanup");
const agentSelect = document.querySelector("#agent-select");
const agentPickerRoot = document.querySelector('[data-agent-picker="workspace"]');
const nodeEmpty = document.querySelector("#app-node-empty");
const undeployedNode = document.querySelector("#app-undeployed");
const offlineNode = document.querySelector("#app-offline");
const executionUnavailableNode = document.querySelector("#app-execution-unavailable");
const engineGuide = document.querySelector("#engine-guide");
const engineStatus = document.querySelector("#engine-status");
const engineScript = document.querySelector("#engine-install-script");
const daemonWrap = document.querySelector("#engine-daemon-json-wrap");
const daemonNode = document.querySelector("#engine-daemon-json");
const copyScript = document.querySelector("#copy-install-script");
const copyDaemon = document.querySelector("#copy-daemon-json");
const idInput = createForm ? createForm.querySelector('input[name="id"]') : null;
const composeInput = createForm ? createForm.querySelector('textarea[name="compose"]') : null;
const envInput = createForm ? createForm.querySelector('textarea[name="env"]') : null;
const autoUpdateInput = createForm ? createForm.querySelector('input[name="auto_update"]') : null;
const detailComposeInput = composeForm ? composeForm.querySelector('textarea[name="compose"]') : null;
const detailEnvInput = composeForm ? composeForm.querySelector('textarea[name="env"]') : null;
const detailAutoUpdateInput = composeForm ? composeForm.querySelector('input[name="auto_update"]') : null;
const confirmDialog = document.querySelector("#confirm-dialog");
const confirmTitle = document.querySelector("#confirm-title");
const confirmBody = document.querySelector("#confirm-body");
const confirmOk = document.querySelector("#confirm-ok");
const confirmCancel = document.querySelector("#confirm-cancel");
const updateDialog = document.querySelector("#update-dialog");
const updateForm = document.querySelector("#update-form");
const updateCopy = document.querySelector("#update-copy");
const updateServices = document.querySelector("#update-services");
const updateConfirm = document.querySelector("#update-confirm");

const askConfirm = ({ title, body, confirm = "确定", cancel = "取消", danger = false, hideConfirm = false } = {}) => {
  if (!confirmDialog || typeof confirmDialog.showModal !== "function") {
    const text = [title, body].filter(Boolean).join("\n");
    if (hideConfirm) {
      window.alert(text);
      return Promise.resolve(false);
    }
    return Promise.resolve(window.confirm(text));
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
    confirmOk.hidden = !!hideConfirm;
  }
  if (confirmCancel) {
    confirmCancel.textContent = cancel;
    confirmCancel.hidden = false;
  }
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
let engineReady = false;
let agentOnline = false;
let lastEngine = null;
let workspaceSeq = 0;
let view = "list";
let selectedAppID = "";
let detailSection = "overview";
let detailApp = null;
let logsPaused = false;
let logsTimer = null;
let logsLoaded = false;
let logsSeq = 0;
let filesDirty = false;
let filesEditorOpen = false;
let filesMountedFor = "";
let composeFilledFor = "";
let discardFileEditor = () => {
  filesDirty = false;
  filesEditorOpen = false;
};
let syncSelectionActions = () => {};
const engineCache = new Map();
const ENGINE_CACHE_MS = 15000;
const ENGINE_PROBE_CONCURRENCY = 3;
const LOG_REFRESH_MS = 4000;
const OFFICIAL_INSTALL_SCRIPT = "curl -fsSL https://get.docker.com | sh";
const COMPOSE_TEMPLATES = {
  blank: { compose: "" },
  site: {
    id: "site",
    compose: "services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"8080:80\"\n    volumes:\n      - ./html:/usr/share/nginx/html\n",
  },
  media: {
    id: "media",
    compose: "services:\n  media:\n    image: jellyfin/jellyfin:latest\n    ports:\n      - \"8096:8096\"\n    volumes:\n      - ./config:/config\n      - ./media:/media\n",
  },
  files: {
    id: "files",
    compose: "services:\n  files:\n    image: filebrowser/filebrowser:latest\n    ports:\n      - \"8080:80\"\n    volumes:\n      - ./data:/srv\n",
  },
};

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
    delete statusNode.dataset.tone;
    return;
  }
  const cancelled = !isError && /^已取消/.test(message);
  statusNode.dataset.error = isError ? "true" : "false";
  statusNode.dataset.tone = isError ? "error" : (cancelled ? "info" : "success");
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
    throw Object.assign(new Error(payload.error || payload.message || "保存失败"), {
      status: response.status,
      preview: payload.preview,
    });
  }
  return payload;
};

const requiresRiskConfirm = (preview) => {
  const items = Array.isArray(preview && preview.items) ? preview.items : [];
  return items.some((item) => item.kind === "privileged" || item.kind === "host-mount" || item.kind === "capability");
};

const riskConfirmBody = (preview) => {
  const labels = {
    privileged: "特权模式",
    "host-mount": "宿主机挂载",
    capability: "额外权限",
    network: "网络",
    volume: "数据卷",
    rule: "规则",
  };
  const items = Array.isArray(preview && preview.items) ? preview.items : [];
  if (!items.length) return "该配置包含高风险项。";
  return items.map((item) => `${labels[item.kind] || item.kind}${item.target ? `：${item.target}` : ""}`).join("\n");
};

const confirmComposeRisk = async (preview) => {
  if (!requiresRiskConfirm(preview)) return true;
  const ok = await askConfirm({
    title: "确认高风险配置",
    body: riskConfirmBody(preview),
    confirm: "继续",
    cancel: "取消",
    danger: true,
  });
  if (!ok) showStatus("已取消，应用未更改。", false);
  return ok;
};

const deployComposePayload = async (payload) => {
  const previewed = await sendPluginJSON("api/apps/preview", {
    id: payload.id,
    agent_id: payload.agent_id,
    compose: payload.compose,
  });
  if (!(await confirmComposeRisk(previewed.preview))) return null;
  const next = { ...payload };
  if (previewed.preview && previewed.preview.digest) next.confirm = previewed.preview.digest;
  return sendPluginJSON("api/apps", next);
};

const setBusy = (next) => {
  busy = next;
  const roots = [workspaceNode, contextNode].filter(Boolean);
  roots.forEach((root) => {
    root.querySelectorAll("button, input, textarea, select").forEach((node) => {
      if (node === agentSelect || node === copyScript || node === copyDaemon) return;
      if (agentPickerRoot && agentPickerRoot.contains(node)) return;
      if (!next && (node.id === "files-edit" || node.id === "files-download" || node.id === "files-delete")) return;
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

const cachedEngine = (agentID) => {
  const cached = engineCache.get(agentID);
  if (!cached) return null;
  if (Date.now() - cached.at > ENGINE_CACHE_MS) return null;
  return cached;
};

const rememberEngine = (agentID, engine) => {
  if (!agentID) return null;
  const entry = {
    ready: engine?.ready === true,
    online: engine?.online === true,
    version: engine?.version || "",
    at: Date.now(),
  };
  engineCache.set(agentID, entry);
  return entry;
};

const probeEngine = async (agentID) => {
  if (!agentID) return null;
  const cached = engineCache.get(agentID);
  if (cached && Date.now() - cached.at < ENGINE_CACHE_MS) return cached;
  try {
    const payload = await panelJSON(`api/engine?agent_id=${encodeURIComponent(agentID)}`);
    return rememberEngine(agentID, payload.engine || null);
  } catch (_error) {
    return cached || null;
  }
};

const probeEngines = async (agentIDs, onDone) => {
  const pending = agentIDs.filter((id) => {
    if (!id) return false;
    const cached = engineCache.get(id);
    return !cached || Date.now() - cached.at >= ENGINE_CACHE_MS;
  });
  if (!pending.length) return;
  let index = 0;
  const workers = Array.from({ length: Math.min(ENGINE_PROBE_CONCURRENCY, pending.length) }, async () => {
    while (index < pending.length) {
      const id = pending[index];
      index += 1;
      await probeEngine(id);
    }
  });
  await Promise.all(workers);
  if (typeof onDone === "function") onDone();
};

const engineMark = (state) => {
  const node = document.createElement("span");
  node.className = "agent-search-select__engine";
  node.dataset.ready = state.ready ? "true" : "false";
  node.textContent = state.ready ? "引擎就绪" : "引擎未就绪";
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
    const engine = picker.selected ? cachedEngine(picker.selected) : null;
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
    if (engine) {
      triggerEngine.hidden = false;
      triggerEngine.dataset.ready = engine.ready ? "true" : "false";
      triggerEngine.textContent = engine.ready ? "引擎就绪" : "引擎未就绪";
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
      empty.textContent = agentsCache.length ? "没有匹配的节点" : "请先在插件详情页部署执行面";
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
      const engine = cachedEngine(agent.id);
      if (engine) option.append(engineMark(engine));
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
    probeEngines(filteredAgents().slice(0, 12).map((agent) => agent.id), () => {
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

const escapeHtml = (value) => String(value)
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;");

const tok = (name, text) => `<span class="tok-${name}">${escapeHtml(text)}</span>`;
const tokHtml = (name, html) => `<span class="tok-${name}">${html}</span>`;

const splitInlineComment = (text) => {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === "#" && !inSingle && !inDouble && (i === 0 || /\s/.test(text[i - 1]))) {
      return [text.slice(0, i), text.slice(i)];
    }
  }
  return [text, ""];
};

const highlightInterp = (text) => {
  const parts = String(text).split(/(\$\{[^}]*\})/g);
  if (parts.length === 1) return escapeHtml(text);
  return parts.map((part, index) => (index % 2 ? tok("interp", part) : escapeHtml(part))).join("");
};

const highlightScalar = (value) => {
  const trimmed = value.trimStart();
  const lead = value.slice(0, value.length - trimmed.length);
  if (!trimmed) return escapeHtml(value);
  const prefix = escapeHtml(lead);
  if (trimmed.startsWith('"') || trimmed.startsWith("'")) {
    const quote = trimmed[0];
    let end = 1;
    while (end < trimmed.length) {
      if (quote === '"' && trimmed[end] === "\\") {
        end += 2;
        continue;
      }
      if (trimmed[end] === quote) {
        end += 1;
        break;
      }
      end += 1;
    }
    return prefix + tok("string", trimmed.slice(0, end)) + highlightInterp(trimmed.slice(end));
  }
  const keyword = trimmed.match(/^(true|false|null|yes|no|True|False|Null|YES|NO)\b/);
  if (keyword) return prefix + tok("keyword", keyword[0]) + highlightInterp(trimmed.slice(keyword[0].length));
  const number = trimmed.match(/^-?\d+(?:\.\d+)?\b/);
  if (number) return prefix + tok("number", number[0]) + highlightInterp(trimmed.slice(number[0].length));
  return prefix + tokHtml("string", highlightInterp(trimmed));
};

const highlightYamlLine = (line) => {
  if (!line) return "";
  const commentLine = line.match(/^(\s*)(#.*)$/);
  if (commentLine) return escapeHtml(commentLine[1]) + tok("comment", commentLine[2]);
  if (/^\s*(---|\.\.\.)\s*$/.test(line)) return tok("punct", line);
  const indent = line.match(/^\s*/)[0];
  let rest = line.slice(indent.length);
  let html = escapeHtml(indent);
  if (rest.startsWith("- ")) {
    html += tok("punct", "- ");
    rest = rest.slice(2);
  } else if (rest === "-") {
    return html + tok("punct", "-");
  }
  const keyed = rest.match(/^((?:"[^"]*"|'[^']*'|[A-Za-z0-9_./-]+))(:)(\s*)(.*)$/);
  if (keyed) {
    html += tok("key", keyed[1]) + tok("punct", keyed[2]) + escapeHtml(keyed[3]);
    const [value, comment] = splitInlineComment(keyed[4]);
    html += highlightScalar(value);
    if (comment) html += tok("comment", comment);
    return html;
  }
  const [value, comment] = splitInlineComment(rest);
  html += highlightScalar(value);
  if (comment) html += tok("comment", comment);
  return html;
};

const highlightYaml = (source) => String(source || "").split("\n").map(highlightYamlLine).join("\n");

const highlightEnvLine = (line) => {
  if (!line) return "";
  const commentLine = line.match(/^(\s*)(#.*)$/);
  if (commentLine) return escapeHtml(commentLine[1]) + tok("comment", commentLine[2]);
  const matched = line.match(/^(\s*)((?:export\s+)?)([A-Za-z_][A-Za-z0-9_]*)(\s*=\s*)(.*)$/);
  if (!matched) return escapeHtml(line);
  const [, indent, exported, key, assign, raw] = matched;
  const [value, comment] = splitInlineComment(raw);
  return escapeHtml(indent)
    + (exported ? tok("keyword", exported) : "")
    + tok("key", key)
    + tok("punct", assign)
    + highlightScalar(value)
    + (comment ? tok("comment", comment) : "");
};

const highlightEnv = (source) => String(source || "").split("\n").map(highlightEnvLine).join("\n");

const highlighterFor = (lang) => {
  if (lang === "env") return highlightEnv;
  if (lang === "yaml") return highlightYaml;
  return (source) => escapeHtml(source);
};

const paintCodeEditor = (textarea) => {
  const wrap = textarea && textarea.closest(".code-editor");
  const layer = wrap ? wrap.querySelector(".code-editor__highlight") : null;
  if (!textarea || !layer) return;
  const lang = highlighterFor(wrap.dataset.lang);
  layer.innerHTML = `${lang(textarea.value)}\n`;
  layer.scrollTop = textarea.scrollTop;
  layer.scrollLeft = textarea.scrollLeft;
};

const mountCodeEditor = (textarea) => {
  if (!textarea) return;
  const wrap = textarea.closest(".code-editor");
  if (!wrap) return;
  textarea.addEventListener("input", () => paintCodeEditor(textarea));
  textarea.addEventListener("scroll", () => paintCodeEditor(textarea));
  if (typeof ResizeObserver === "function") {
    new ResizeObserver(() => paintCodeEditor(textarea)).observe(textarea);
  }
  paintCodeEditor(textarea);
};

mountCodeEditor(composeInput);
mountCodeEditor(envInput);
mountCodeEditor(detailComposeInput);
mountCodeEditor(detailEnvInput);
if (createForm) {
  createForm.addEventListener("reset", () => {
    requestAnimationFrame(() => {
      paintCodeEditor(composeInput);
      paintCodeEditor(envInput);
    });
  });
}

const confirmLeaveEditor = async () => {
  if (!filesEditorOpen || !filesDirty) return true;
  const ok = await askConfirm({
    title: "文本尚未保存",
    body: "离开将丢弃改动，取消则留在当前编辑。",
    confirm: "丢弃",
    cancel: "取消",
    danger: true,
  });
  if (!ok) return false;
  discardFileEditor();
  return true;
};

const markCreateTemplate = (name) => {
  const root = createTemplates || createPanel;
  if (!root) return;
  root.querySelectorAll("[data-template]").forEach((button) => {
    button.setAttribute("aria-pressed", button.dataset.template === name ? "true" : "false");
  });
};

const applyCreateTemplate = (name) => {
  const template = COMPOSE_TEMPLATES[name];
  if (!template || !composeInput) return;
  composeInput.value = template.compose || "";
  paintCodeEditor(composeInput);
  markCreateTemplate(name);
  composeInput.focus();
};

const openCreate = async () => {
  if (!engineReady || !agentOnline) return;
  if (view === "detail" && !(await leaveDetail())) return;
  if (createTitle) createTitle.textContent = "部署应用";
  if (createSubmit) createSubmit.textContent = "部署";
  if (idInput) {
    idInput.value = "";
    idInput.readOnly = false;
  }
  if (composeInput) {
    composeInput.value = "";
    paintCodeEditor(composeInput);
  }
  if (envInput) {
    envInput.value = "";
    paintCodeEditor(envInput);
  }
  if (autoUpdateInput) autoUpdateInput.checked = false;
  markCreateTemplate("blank");
  createPanel.hidden = false;
  syncListPanel();
  if (composeInput) composeInput.focus();
};

const closeCreate = () => {
  if (createForm) createForm.reset();
  if (idInput) idInput.readOnly = false;
  if (createTitle) createTitle.textContent = "部署应用";
  if (createSubmit) createSubmit.textContent = "部署";
  if (createPanel) createPanel.hidden = true;
  markCreateTemplate("blank");
  requestAnimationFrame(() => {
    paintCodeEditor(composeInput);
    paintCodeEditor(envInput);
  });
  syncListPanel();
};

const syncListPanel = () => {
  const hasApps = listNode && listNode.children.length > 0;
  const creating = createPanel && createPanel.hidden === false;
  const inDetail = view === "detail";
  if (emptyNode) emptyNode.hidden = inDetail || !selectedAgentID || !engineReady || hasApps || creating;
  if (listPanel) listPanel.hidden = inDetail || creating;
  if (detailPanel) detailPanel.hidden = !inDetail;
  if (workspaceHead) workspaceHead.hidden = inDetail || creating;
  const canOperate = selectedAgentID && engineReady && agentOnline;
  if (deployToggle) deployToggle.hidden = inDetail || creating || !canOperate;
  if (diskCleanup) diskCleanup.hidden = inDetail || creating || !canOperate;
};

const parsePublishedPorts = (compose) => {
  const ports = [];
  const seen = new Set();
  const mapping = /(?:^|[\s,[])(?:['"]?)(?:\d{1,3}(?:\.\d{1,3}){3}:)?(\d{1,5}):(\d{1,5})(?:\/[A-Za-z0-9]+)?(?:['"]?)/g;
  String(compose || "").split(/\r?\n/).forEach((line) => {
    const published = line.match(/published:\s*['"]?(\d{1,5})['"]?/);
    if (published) {
      const port = Number(published[1]);
      if (port > 0 && port <= 65535 && !seen.has(port)) {
        seen.add(port);
        ports.push(port);
      }
    }
    mapping.lastIndex = 0;
    const match = mapping.exec(line);
    if (match) {
      const port = Number(match[1]);
      if (port > 0 && port <= 65535 && !seen.has(port)) {
        seen.add(port);
        ports.push(port);
      }
    }
  });
  return ports;
};

const parseImage = (compose) => {
  const match = String(compose || "").match(/^\s*image:\s*['"]?([^\s'"]+)['"]?\s*$/m);
  return match ? match[1] : "";
};

const parseComposeScalar = (compose, key) => {
  const match = String(compose || "").match(new RegExp(`^\\s*${key}:\\s*['"]?([^\\s'"]+)['"]?\\s*$`, "m"));
  return match ? match[1] : "";
};

const parseComposeVolumes = (compose) => {
  const volumes = [];
  const seen = new Set();
  String(compose || "").split(/\r?\n/).forEach((line) => {
    const match = line.match(/^\s*-\s*['"]?([^:'"\s]+):([^:'"\s]+)(?::[^'"]+)?['"]?\s*$/);
    if (!match) return;
    const source = match[1];
    const target = match[2];
    if (/^\d+$/.test(source) && /^\d+$/.test(target)) return;
    const key = `${source}:${target}`;
    if (seen.has(key)) return;
    seen.add(key);
    volumes.push({ source, target });
  });
  return volumes;
};

const chip = (text) => {
  const node = document.createElement("span");
  node.className = "chip";
  node.textContent = text;
  return node;
};

const appPorts = (app) => (Array.isArray(app.ports) && app.ports.length ? app.ports : parsePublishedPorts(app.compose));
const appVersion = (app) => app.version || parseImage(app.compose) || "未解析镜像";

const splitImage = (value) => {
  const text = String(value || "");
  const at = text.indexOf("@sha256:");
  if (at > 0) return { name: text.slice(0, at), digest: text.slice(at + 8) };
  return { name: text, digest: "" };
};

const shortVersion = (value) => {
  const parts = splitImage(value);
  if (parts.digest) {
    const short = parts.digest.slice(0, 12);
    return `${parts.name}@${short}${parts.digest.length > 12 ? "…" : ""}`;
  }
  if (parts.name.length > 36) return `${parts.name.slice(0, 34)}…`;
  return parts.name;
};

const cardImage = (value) => {
  const name = splitImage(value).name;
  if (!name || name === "未解析镜像") return "";
  if (name.length > 42) return `${name.slice(0, 40)}…`;
  return name;
};

const appendAppChips = (chips, app, options = {}) => {
  if (!options.omitStatus && app.status && app.status !== "有新版本") {
    const statusChip = chip(app.status);
    statusChip.className = "chip app-status";
    statusChip.dataset.status = app.status;
    chips.append(statusChip);
  }
  if (app.notice === "有新版本" || app.status === "有新版本") {
    const noticeChip = chip("有新版本");
    noticeChip.className = "chip app-status-update";
    chips.append(noticeChip);
  }
  const version = appVersion(app);
  const versionChip = chip(shortVersion(version));
  versionChip.className = "chip app-version";
  versionChip.title = version;
  chips.append(versionChip);
  const ports = appPorts(app);
  if (ports.length) ports.forEach((port) => chips.append(chip(`:${port}`)));
  else chips.append(chip("无发布端口"));
};

const copyText = async (text) => {
  const value = String(text || "");
  if (!value) return;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    await navigator.clipboard.writeText(value);
  } else {
    throw new Error("当前环境无法复制");
  }
  showStatus("已复制。", false);
};

const postAppAction = async (app, action, body = {}) => {
  await sendPluginJSON(`api/apps/${encodeURIComponent(app.id)}/${action}`, body);
  closeCreate();
  if (action === "delete" && selectedAppID === app.id) leaveDetail({ force: true });
  await renderWorkspace();
};

const postAppActionWithRisk = async (app, action, body = {}) => {
  try {
    await postAppAction(app, action, body);
    return true;
  } catch (error) {
    if (action !== "update" || !requiresRiskConfirm(error.preview)) throw error;
    if (!(await confirmComposeRisk(error.preview))) return false;
    await postAppAction(app, action, { ...body, confirm: error.preview.digest });
    return true;
  }
};

const saveServicePolicy = async (app, payload, okMessage) => {
  setBusy(true);
  try {
    if (await postAppActionWithRisk(app, "update", payload)) showStatus(okMessage || "已保存。", false);
  } catch (error) {
    showStatus(error.message, true);
  } finally {
    setBusy(false);
  }
};

const MAX_WORKSPACE_FILE_BYTES = 1048576;
const workspacePathError = "只能使用应用工作区内的相对路径";

const relativeWorkspacePath = (value) => {
  const path = String(value || "").trim().replace(/\\/g, "/");
  if (!path || path.includes("..")) return "";
  if (path.startsWith("/") || path.startsWith("~")) return "";
  if (/^[a-zA-Z]:\//.test(path)) return "";
  return path;
};

const joinWorkspacePath = (dir, name) => {
  const leaf = String(name || "").trim().replace(/\\/g, "/");
  if (!leaf || leaf.includes("/") || leaf.includes("..") || leaf === ".") return "";
  const base = relativeWorkspacePath(dir);
  if (!base || base === ".") return leaf;
  return `${base}/${leaf}`;
};

const parentWorkspacePath = (path) => {
  const relative = relativeWorkspacePath(path);
  if (!relative || relative === ".") return ".";
  const index = relative.lastIndexOf("/");
  if (index <= 0) return ".";
  return relative.slice(0, index);
};

const looksLikeText = (value) => {
  if (typeof value !== "string" || value.includes("\u0000")) return false;
  let bad = 0;
  const limit = Math.min(value.length, 4096);
  for (let i = 0; i < limit; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 9 || (code > 13 && code < 32) || code === 127) bad += 1;
  }
  return bad < 8;
};

const downloadTextFile = (filename, content) => {
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename || "file.txt";
  link.click();
  URL.revokeObjectURL(url);
};

const formatFileSize = (size) => {
  const value = Number(size);
  if (!Number.isFinite(value) || value < 0) return "";
  if (value < 1024) return `${value} B`;
  return `${(value / 1024).toFixed(1)} KiB`;
};

const editorLangFor = (name) => {
  const lower = String(name || "").toLowerCase();
  if (lower.endsWith(".yml") || lower.endsWith(".yaml")) return "yaml";
  if (lower === ".env" || lower.endsWith(".env") || lower.includes(".env.")) return "env";
  return "text";
};

const postAppFiles = async (app, body) => {
  const path = relativeWorkspacePath(body.path);
  if (!path) throw new Error(workspacePathError);
  const payload = { action: body.action, path };
  if (Object.prototype.hasOwnProperty.call(body, "content")) payload.content = body.content;
  return sendPluginJSON(`api/apps/${encodeURIComponent(app.id)}/files`, payload);
};

const mountAppFiles = () => {
  const template = document.querySelector("#app-files-template");
  if (!template || !filesPanel) {
    return {
      bind() {},
      confirmLeave: () => true,
      discard() {},
    };
  }
  if (!filesPanel.querySelector(".app-files")) {
    filesPanel.replaceChildren(template.content.cloneNode(true));
  }
  const section = filesPanel.querySelector(".app-files") || filesPanel;
  const browser = section.querySelector("#files-browser") || section.querySelector(".files-browser");
  const breadcrumb = section.querySelector("#files-breadcrumb") || section.querySelector(".files-breadcrumb");
  const upBtn = section.querySelector("#files-up");
  const listEl = section.querySelector("#files-list") || section.querySelector(".files-list");
  const emptyEl = section.querySelector(".files-empty");
  const mkdirBtn = section.querySelector("#files-mkdir");
  const mkdirDialog = section.querySelector("#files-mkdir-dialog");
  const mkdirForm = section.querySelector("#files-mkdir-form");
  const mkdirName = section.querySelector("#files-mkdir-name");
  const newName = section.querySelector("#files-new-name");
  const newTextBtn = section.querySelector("#files-new-text");
  const newDialog = section.querySelector("#files-new-dialog");
  const newForm = section.querySelector("#files-new-form");
  const selectedLabel = section.querySelector("#files-selected");
  const editBtn = section.querySelector("#files-edit");
  const uploadBtn = section.querySelector("#files-upload");
  const uploadInput = section.querySelector("[data-files-input]");
  const downloadBtn = section.querySelector("#files-download");
  const deleteBtn = section.querySelector("#files-delete");
  const editor = section.querySelector("#files-editor") || section.querySelector(".files-editor");
  const editorName = section.querySelector("#files-editor-name");
  const dirtyMark = section.querySelector("#files-dirty") || section.querySelector(".files-dirty");
  const closeBtn = section.querySelector("#files-editor-close");
  const editorInput = editor ? editor.querySelector("textarea") : null;
  const saveBtn = section.querySelector("#files-save");
  const binaryHint = section.querySelector("[data-files-binary]");
  if (editorInput) mountCodeEditor(editorInput);

  let app = null;
  let currentPath = ".";
  let selectedPath = "";
  let selectedName = "";
  let selectedDir = false;
  let savedContent = "";

  const setDirty = (next) => {
    filesDirty = Boolean(next);
    if (dirtyMark) dirtyMark.hidden = !filesDirty;
  };

  const paintSelection = () => {
    if (!listEl) return;
    listEl.querySelectorAll("li").forEach((item) => {
      item.setAttribute("aria-selected", item.dataset.path === selectedPath ? "true" : "false");
    });
  };

  syncSelectionActions = () => {
    const hasFile = Boolean(selectedPath) && !selectedDir;
    const hasTarget = Boolean(selectedPath) && selectedPath !== ".";
    if (editBtn) editBtn.disabled = !hasFile;
    if (downloadBtn) downloadBtn.disabled = !hasFile;
    if (deleteBtn) deleteBtn.disabled = !hasTarget;
    if (selectedLabel) {
      selectedLabel.textContent = hasTarget
        ? `已选择 ${selectedName || selectedPath}`
        : "请选择一个文件或目录后再编辑、下载或删除。";
    }
  };

  const hideEditor = () => {
    filesEditorOpen = false;
    setDirty(false);
    savedContent = "";
    if (editor) editor.hidden = true;
    if (editorInput) editorInput.value = "";
    if (binaryHint) binaryHint.hidden = true;
    if (browser) browser.hidden = false;
    if (editorName) editorName.textContent = "";
    syncSelectionActions();
  };

  discardFileEditor = hideEditor;

  const confirmLeave = async () => {
    if (!filesEditorOpen || !filesDirty) {
      if (filesEditorOpen && !filesDirty) hideEditor();
      return true;
    }
    const ok = await askConfirm({
      title: "文本尚未保存",
      body: "离开将丢弃改动，取消则留在当前编辑。",
      confirm: "丢弃",
      cancel: "取消",
      danger: true,
    });
    if (!ok) return false;
    hideEditor();
    return true;
  };

  const selectEntry = (path, name, isDir) => {
    selectedPath = path;
    selectedName = name;
    selectedDir = isDir;
    paintSelection();
    syncSelectionActions();
  };

  const setEditorLang = (name) => {
    const wrap = editorInput && editorInput.closest(".code-editor");
    if (!wrap) return;
    wrap.dataset.lang = editorLangFor(name);
  };

  const showEditor = (path, name, content) => {
    filesEditorOpen = true;
    savedContent = content;
    setDirty(false);
    selectEntry(path, name, false);
    if (browser) browser.hidden = true;
    if (editor) editor.hidden = false;
    if (editorName) editorName.textContent = path;
    if (binaryHint) binaryHint.hidden = true;
    if (editorInput) {
      editorInput.hidden = false;
      editorInput.value = content;
      setEditorLang(name);
      paintCodeEditor(editorInput);
      editorInput.focus();
    }
    if (saveBtn) saveBtn.hidden = false;
  };

  const renderBreadcrumb = () => {
    if (upBtn) upBtn.hidden = currentPath === ".";
    if (!breadcrumb) return;
    breadcrumb.replaceChildren();
    const addCrumb = (label, path, current) => {
      if (current) {
        const currentNode = document.createElement("span");
        currentNode.textContent = label;
        currentNode.setAttribute("aria-current", "page");
        breadcrumb.append(currentNode);
        return;
      }
      const button = document.createElement("button");
      button.type = "button";
      button.className = "btn-link";
      button.textContent = label;
      button.addEventListener("click", () => requestList(path));
      breadcrumb.append(button);
    };
    const parts = currentPath === "." ? [] : currentPath.split("/").filter(Boolean);
    addCrumb("工作区", ".", parts.length === 0);
    let acc = "";
    parts.forEach((part, index) => {
      const sep = document.createElement("span");
      sep.className = "files-sep";
      sep.textContent = "/";
      sep.setAttribute("aria-hidden", "true");
      breadcrumb.append(sep);
      acc = acc ? `${acc}/${part}` : part;
      addCrumb(part, acc, index === parts.length - 1);
    });
  };

  const openFile = async (path, name) => {
    if (!app) return;
    if (filesEditorOpen && filesDirty && selectedPath === path) return;
    if (!(await confirmLeave())) return;
    const relative = relativeWorkspacePath(path);
    if (!relative) {
      showStatus(workspacePathError, true);
      return;
    }
    try {
      const payload = await postAppFiles(app, { action: "read", path: relative });
      const content = typeof payload.content === "string" ? payload.content : "";
      if (new TextEncoder().encode(content).length > MAX_WORKSPACE_FILE_BYTES) {
        showStatus("文件超过 1MiB 上限", true);
        return;
      }
      if (!looksLikeText(content)) {
        showStatus("该文件不适合文本编辑，请下载或重新上传。", true);
        if (binaryHint) binaryHint.hidden = false;
        return;
      }
      showEditor(relative, name || relative.split("/").pop(), content);
    } catch (error) {
      showStatus(error.message, true);
    }
  };

  const openNewFile = async (path, name) => {
    if (!(await confirmLeave())) return;
    showEditor(path, name, "");
  };

  const loadList = async (path) => {
    if (!app) return;
    const relative = relativeWorkspacePath(path);
    if (!relative) {
      showStatus(workspacePathError, true);
      return;
    }
    try {
      const payload = await postAppFiles(app, { action: "list", path: relative });
      currentPath = relativeWorkspacePath(payload.path) || relative;
      const entries = Array.isArray(payload.entries) ? payload.entries : [];
      if (!filesEditorOpen) {
        const visible = entries.some((entry) => relativeWorkspacePath(entry.path || entry.name) === selectedPath);
        if (!visible) selectEntry("", "", false);
        else paintSelection();
      }
      renderBreadcrumb();
      if (listEl) listEl.replaceChildren();
      let listed = 0;
      entries.forEach((entry) => {
        const entryPath = relativeWorkspacePath(entry.path || entry.name);
        if (!entryPath) return;
        listed += 1;
        const item = document.createElement("li");
        item.dataset.path = entryPath;
        item.dataset.kind = entry.dir ? "dir" : "file";
        item.setAttribute("aria-selected", selectedPath === entryPath ? "true" : "false");
        const nameWrap = document.createElement("div");
        nameWrap.className = "files-list-name";
        const open = document.createElement("button");
        open.type = "button";
        open.className = "files-name";
        open.textContent = entry.dir ? `${entry.name || entryPath}/` : (entry.name || entryPath);
        open.addEventListener("click", (event) => {
          event.stopPropagation();
          if (entry.dir) requestList(entryPath);
          else selectEntry(entryPath, entry.name || entryPath, false);
        });
        nameWrap.append(open);
        item.append(nameWrap);
        if (!entry.dir && entry.size != null) {
          const size = document.createElement("span");
          size.className = "files-size";
          size.textContent = formatFileSize(entry.size);
          item.append(size);
        }
        item.addEventListener("click", () => {
          selectEntry(entryPath, entry.name || entryPath, Boolean(entry.dir));
        });
        if (listEl) listEl.append(item);
      });
      if (emptyEl) emptyEl.hidden = listed !== 0;
    } catch (error) {
      if (listEl) listEl.replaceChildren();
      if (emptyEl) emptyEl.hidden = true;
      showStatus(error.message, true);
    }
  };

  const requestList = async (path) => {
    if (!(await confirmLeave())) return;
    loadList(path);
  };

  const removePath = async (path, name) => {
    if (!app) return;
    const relative = relativeWorkspacePath(path);
    if (!relative || relative === ".") {
      showStatus(relative === "." ? "不能删除应用工作区根目录" : workspacePathError, true);
      return;
    }
    if (!await askConfirm({
      title: "删除",
      body: `确认删除 ${name || relative}？取消不会更改工作区。`,
      confirm: "删除",
      cancel: "取消",
      danger: true,
    })) {
      showStatus("已取消，工作区未更改。", false);
      return;
    }
    setBusy(true);
    try {
      await postAppFiles(app, { action: "delete", path: relative });
      if (selectedPath === relative) hideEditor();
      showStatus("已删除工作区文件。", false);
      await loadList(currentPath);
    } catch (error) {
      showStatus(error.message, true);
    } finally {
      setBusy(false);
    }
  };

  const openNamedDialog = (dialog, input) => {
    if (!dialog || typeof dialog.showModal !== "function") return;
    if (input) input.value = "";
    dialog.showModal();
    if (input) input.focus();
  };
  const closeNamedDialog = (dialog) => {
    if (dialog && dialog.open) dialog.close();
  };
  section.querySelectorAll("[data-dialog-close]").forEach((button) => {
    button.addEventListener("click", () => {
      const dialog = button.closest("dialog");
      closeNamedDialog(dialog);
    });
  });
  if (mkdirBtn) {
    mkdirBtn.addEventListener("click", () => {
      if (busy || !app) return;
      openNamedDialog(mkdirDialog, mkdirName);
    });
  }
  if (mkdirForm) {
    mkdirForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (busy || !app) return;
      const name = mkdirName ? mkdirName.value.trim() : "";
      if (!name) {
        if (mkdirName) mkdirName.focus();
        return;
      }
      const next = joinWorkspacePath(currentPath, name);
      if (!next) {
        showStatus(workspacePathError, true);
        return;
      }
      setBusy(true);
      try {
        await postAppFiles(app, { action: "mkdir", path: next });
        if (mkdirName) mkdirName.value = "";
        closeNamedDialog(mkdirDialog);
        showStatus("已新建目录。", false);
        await loadList(currentPath);
      } catch (error) {
        showStatus(error.message, true);
      } finally {
        setBusy(false);
      }
    });
  }
  if (newTextBtn) {
    newTextBtn.addEventListener("click", async () => {
      if (busy || !app) return;
      if (!(await confirmLeave())) return;
      openNamedDialog(newDialog, newName);
    });
  }
  if (newForm) {
    newForm.addEventListener("submit", (event) => {
      event.preventDefault();
      if (busy || !app) return;
      const name = newName ? newName.value.trim() : "";
      if (!name) {
        showStatus("请填写要新建的文本文件名。", true);
        if (newName) newName.focus();
        return;
      }
      const next = joinWorkspacePath(currentPath, name);
      if (!next) {
        showStatus(workspacePathError, true);
        return;
      }
      if (newName) newName.value = "";
      closeNamedDialog(newDialog);
      openNewFile(next, name);
      setDirty(true);
    });
  }
  if (editBtn) {
    editBtn.addEventListener("click", () => {
      if (busy || !app) return;
      if (!selectedPath || selectedDir) {
        showStatus("请先选择一个文件再编辑。", true);
        return;
      }
      openFile(selectedPath, selectedName);
    });
  }
  if (uploadBtn && uploadInput) {
    uploadBtn.addEventListener("click", () => uploadInput.click());
    uploadInput.addEventListener("change", async () => {
      const file = uploadInput.files && uploadInput.files[0];
      uploadInput.value = "";
      if (!file || !app) return;
      const next = joinWorkspacePath(currentPath, file.name);
      if (!next) {
        showStatus(workspacePathError, true);
        return;
      }
      if (file.size > MAX_WORKSPACE_FILE_BYTES) {
        showStatus("文件超过 1MiB 上限", true);
        return;
      }
      const content = await file.text();
      setBusy(true);
      try {
        await postAppFiles(app, { action: "write", path: next, content });
        showStatus("已上传工作区文件。", false);
        await loadList(currentPath);
      } catch (error) {
        showStatus(error.message, true);
      } finally {
        setBusy(false);
      }
    });
  }
  if (downloadBtn) {
    downloadBtn.addEventListener("click", async () => {
      if (busy || !app) return;
      if (!selectedPath || selectedDir) {
        showStatus("请先选择一个文件再下载。", true);
        return;
      }
      try {
        const file = await postAppFiles(app, { action: "read", path: selectedPath });
        downloadTextFile(selectedName || selectedPath.split("/").pop(), file.content || "");
        showStatus("已开始下载。", false);
      } catch (error) {
        showStatus(error.message, true);
      }
    });
  }
  if (deleteBtn) {
    deleteBtn.addEventListener("click", () => {
      if (busy || !app) return;
      if (!selectedPath || selectedPath === ".") {
        showStatus("请先选择要删除的文件或目录。", true);
        return;
      }
      removePath(selectedPath, selectedName);
    });
  }
  if (saveBtn) {
    saveBtn.addEventListener("click", async () => {
      if (busy || !app || !selectedPath || selectedDir) return;
      const content = editorInput ? editorInput.value : "";
      if (new TextEncoder().encode(content).length > MAX_WORKSPACE_FILE_BYTES) {
        showStatus("文件超过 1MiB 上限", true);
        return;
      }
      setBusy(true);
      try {
        await postAppFiles(app, { action: "write", path: selectedPath, content });
        savedContent = content;
        setDirty(false);
        showStatus("已保存工作区文件。", false);
        await loadList(currentPath);
      } catch (error) {
        showStatus(error.message, true);
      } finally {
        setBusy(false);
      }
    });
  }
  if (upBtn) {
    upBtn.addEventListener("click", () => {
      if (busy || currentPath === ".") return;
      requestList(parentWorkspacePath(currentPath));
    });
  }
  if (closeBtn) {
    closeBtn.addEventListener("click", async () => {
      if (!(await confirmLeave())) return;
      if (browser) browser.hidden = false;
      loadList(currentPath);
    });
  }
  syncSelectionActions();
  if (editorInput) {
    editorInput.addEventListener("input", () => {
      setDirty(editorInput.value !== savedContent);
      paintCodeEditor(editorInput);
    });
  }

  return {
    bind(nextApp) {
      app = nextApp;
      if (!app) {
        hideEditor();
        filesMountedFor = "";
        return;
      }
      if (filesMountedFor !== app.id) {
        hideEditor();
        currentPath = ".";
        selectEntry("", "", false);
        filesMountedFor = app.id;
        loadList(".");
      }
    },
    confirmLeave,
    discard: hideEditor,
  };
};

const filesWorkspace = mountAppFiles();

const actionButton = (action, className, label) => {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  button.dataset.action = action.id;
  button.textContent = label;
  return button;
};

const runAppAction = async (app, action) => {
  if (busy) return;
  if (action.id === "configure") {
    showDetail(app.id, "compose");
    return;
  }
  if (action.id === "logs") {
    showDetail(app.id, "logs");
    return;
  }
  if (action.id === "delete") {
    if (!await askConfirm({
      title: "删除应用",
      body: `确认删除 ${app.id}？取消不会更改应用。`,
      confirm: "删除",
      cancel: "取消",
      danger: true,
    })) {
      showStatus("已取消，应用未更改。", false);
      return;
    }
    setBusy(true);
    try {
      await postAppAction(app, "delete", { confirm: app.id });
      showStatus("已删除应用。", false);
    } catch (error) {
      showStatus(error.message, true);
    } finally {
      setBusy(false);
    }
    return;
  }
  if (action.id === "rollback") {
    if (!await askConfirm({
      title: "回滚应用",
      body: `确认回滚 ${app.id} 到上一版本？取消不会更改应用。`,
      confirm: "回滚",
      cancel: "取消",
      danger: true,
    })) {
      showStatus("已取消，应用未更改。", false);
      return;
    }
  }
  if (action.id === "update") {
    const payload = await askServiceUpdate(app);
    if (!payload) {
      showStatus("已取消，应用未更改。", false);
      return;
    }
    setBusy(true);
    try {
      if (await postAppActionWithRisk(app, action.id, payload)) showStatus("已更新应用。", false);
    } catch (error) {
      showStatus(error.message, true);
    } finally {
      setBusy(false);
    }
    return;
  }
  setBusy(true);
  try {
    await postAppAction(app, action.id);
    showStatus(action.id === "rollback" ? "已回滚应用。" : "已执行操作。", false);
  } catch (error) {
    showStatus(error.message, true);
  } finally {
    setBusy(false);
  }
};

const serviceImages = (app) => (Array.isArray(app.service_images) ? app.service_images.filter((item) => item && item.name) : []);

const askServiceUpdate = (app) => {
  const services = serviceImages(app);
  if (!updateDialog || typeof updateDialog.showModal !== "function") {
    const selected = services.filter((item) => item.update && item.default_tag).map((item) => ({ name: item.name, tag: item.default_tag }));
    if (!selected.length) return Promise.resolve(null);
    const lines = selected.map((item) => `${item.name} → ${item.tag}`).join("\n");
    return Promise.resolve(window.confirm(`确认更新 ${app.id}？\n${lines}\n取消不会改 compose。`) ? { services: selected } : null);
  }
  if (updateDialog.open) updateDialog.close("cancel");
  const digestRefresh = services.some((item) => Array.isArray(item.candidates) && item.candidates.some((candidate) => candidate.digest));
  if (updateCopy) {
    updateCopy.textContent = digestRefresh
      ? `确认拉取 ${app.id} 的新 digest。取消不会改 compose 或运行镜像。`
      : `按服务选择 ${app.id} 要写入 compose 的目标版本。取消不会改 compose 或运行镜像。`;
  }
  if (updateServices) {
    updateServices.replaceChildren();
    services.forEach((service) => {
      updateServices.append(renderUpdateServiceRow(service));
    });
    if (!services.length) {
      const empty = document.createElement("p");
      empty.className = "files-dialog-copy";
      empty.textContent = "没有可更新的服务镜像。";
      updateServices.append(empty);
    }
  }
  return new Promise((resolve) => {
    const onClose = () => {
      if (updateDialog.returnValue !== "ok") {
        resolve(null);
        return;
      }
      const payload = collectUpdatePayload();
      if (!payload || (!payload.services && !payload.ignore && !payload.locks)) {
        resolve(null);
        return;
      }
      resolve(payload);
    };
    updateDialog.addEventListener("close", onClose, { once: true });
    updateDialog.showModal();
    if (updateConfirm) updateConfirm.focus();
  });
};

const renderServiceLockSelect = (service) => {
  const options = Array.isArray(service.lock_options) ? service.lock_options : [];
  if (!options.length && !service.lock) return null;
  const lockLabel = document.createElement("label");
  lockLabel.className = "update-lock";
  lockLabel.append("锁定");
  const lock = document.createElement("select");
  lock.name = `lock-${service.name}`;
  const none = document.createElement("option");
  none.value = "";
  none.textContent = "未锁定";
  if (!service.lock) none.selected = true;
  lock.append(none);
  options.forEach((item) => {
    const option = document.createElement("option");
    option.value = item.constraint || "";
    option.textContent = item.label || item.id;
    if (service.lock && item.constraint === service.lock) option.selected = true;
    lock.append(option);
  });
  if (service.lock && !options.some((item) => item.constraint === service.lock)) {
    const custom = document.createElement("option");
    custom.value = service.lock;
    custom.textContent = service.lock;
    custom.selected = true;
    lock.append(custom);
  }
  lockLabel.append(lock);
  return lockLabel;
};

const persistedIgnoredTags = (service) => (Array.isArray(service.ignored) ? service.ignored.filter(Boolean) : []);

const renderIgnoredClearControls = (service, { buttons = false } = {}) => persistedIgnoredTags(service).map((tag) => {
  if (buttons) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "btn-link";
    button.dataset.tag = tag;
    button.textContent = `取消忽略 ${tag}`;
    return button;
  }
  const label = document.createElement("label");
  label.className = "inline-check";
  const box = document.createElement("input");
  box.type = "checkbox";
  box.name = `clear-ignore-${service.name}`;
  box.dataset.tag = tag;
  box.dataset.clearIgnore = "true";
  label.append(box, `取消忽略 ${tag}`);
  return label;
});

const renderUpdateServiceRow = (service) => {
  const row = document.createElement("section");
  row.className = "update-service";
  row.dataset.service = service.name;
  row.dataset.lock = service.lock || "";
  const candidates = Array.isArray(service.candidates) ? service.candidates : [];
  const defaultTag = service.default_tag || (candidates[0] && candidates[0].tag) || "";
  const checked = service.update === true && !!defaultTag;
  if (!candidates.length) row.dataset.empty = "true";
  const head = document.createElement("div");
  head.className = "update-service-head";
  const pick = document.createElement("label");
  pick.className = "update-service-pick";
  const selectBox = document.createElement("input");
  selectBox.type = "checkbox";
  selectBox.name = `update-${service.name}`;
  selectBox.checked = checked;
  selectBox.disabled = candidates.length === 0;
  const identity = document.createElement("span");
  identity.className = "update-service-identity";
  const title = document.createElement("strong");
  title.textContent = service.name;
  const current = document.createElement("span");
  current.className = "update-current";
  current.textContent = service.tag || service.image || "未知版本";
  identity.append(title);
  pick.append(selectBox, identity);
  head.append(pick);
  const body = document.createElement("div");
  body.className = "update-service-body";
  const flow = document.createElement("div");
  flow.className = "update-flow";
  flow.append(current);
  const arrow = document.createElement("span");
  arrow.className = "update-arrow";
  arrow.textContent = "→";
  flow.append(arrow);
  const target = document.createElement("div");
  target.className = "update-target";
  const targetLabel = document.createElement("span");
  targetLabel.className = "update-target-label";
  targetLabel.textContent = "将更新到";
  if (!candidates.length) {
    const empty = document.createElement("p");
    empty.className = "update-empty";
    empty.textContent = service.unknown ? "无法列出仓库 tag" : "没有允许的候选";
    target.append(targetLabel, empty);
  } else {
    const select = document.createElement("select");
    select.name = `target-${service.name}`;
    candidates.forEach((candidate) => {
      const option = document.createElement("option");
      option.value = candidate.tag;
      if (candidate.digest) option.textContent = `${candidate.tag}（新 digest）`;
      else option.textContent = candidate.major ? `${candidate.tag}（主版本）` : candidate.tag;
      if (candidate.major) option.dataset.major = "true";
      if (candidate.digest) option.dataset.digest = "true";
      if (candidate.tag === defaultTag) option.selected = true;
      select.append(option);
    });
    target.append(targetLabel, select);
  }
  flow.append(target);
  const tools = document.createElement("div");
  tools.className = "update-tools";
  const ignore = document.createElement("label");
  ignore.className = "inline-check";
  const ignoreBox = document.createElement("input");
  ignoreBox.type = "checkbox";
  ignoreBox.name = `ignore-${service.name}`;
  ignoreBox.disabled = !defaultTag;
  ignore.append(ignoreBox, "忽略此版本");
  ignoreBox.addEventListener("change", () => {
    if (ignoreBox.checked) selectBox.checked = false;
  });
  tools.append(ignore);
  const lockSelect = renderServiceLockSelect(service);
  if (lockSelect) tools.append(lockSelect);
  renderIgnoredClearControls(service).forEach((node) => tools.append(node));
  body.append(flow, tools);
  row.append(head, body);
  return row;
};

const collectUpdatePayload = () => {
  if (!updateServices) return null;
  const services = [];
  const ignore = [];
  const locks = {};
  updateServices.querySelectorAll(".update-service").forEach((row) => {
    const name = row.dataset.service;
    const selected = row.querySelector(`input[name="update-${name}"]`);
    const target = row.querySelector(`select[name="target-${name}"]`);
    const ignored = row.querySelector(`input[name="ignore-${name}"]`);
    const lock = row.querySelector(`select[name="lock-${name}"]`);
    const tag = target ? String(target.value || "").trim() : "";
    if (selected && selected.checked && tag) services.push({ name, tag });
    if (ignored && ignored.checked && tag) ignore.push({ service: name, tag });
    row.querySelectorAll(`input[data-clear-ignore="true"]`).forEach((box) => {
      const clearTag = String(box.dataset.tag || "").trim();
      if (box.checked && clearTag) ignore.push({ service: name, tag: clearTag, clear: true });
    });
    if (lock && lock.value !== (row.dataset.lock || "")) locks[name] = lock.value;
  });
  const payload = {};
  if (services.length) payload.services = services;
  if (ignore.length) payload.ignore = ignore;
  if (Object.keys(locks).length) payload.locks = locks;
  return payload;
};

const actionGroups = (app, options = {}) => {
  const apiActions = Array.isArray(app.actions) && app.actions.length
    ? app.actions
    : [{ id: "configure", label: "编辑" }, { id: "delete", label: "删除" }];
  const primary = document.createElement("div");
  primary.className = "app-actions app-actions-primary";
  const secondary = document.createElement("div");
  secondary.className = "app-actions app-actions-secondary";
  const danger = document.createElement("div");
  danger.className = "app-actions app-actions-danger";
  apiActions.forEach((action) => {
    if (action.id === "configure") return;
    if (action.id === "logs") return;
    if (options.card && action.id !== "update") return;
    if (options.overview && (action.id === "start" || action.id === "stop" || action.id === "restart")) return;
    const isPrimary = action.id === "start" || action.id === "stop" || action.id === "restart" || action.id === "update";
    const isDelete = action.id === "delete";
    const button = actionButton(
      action,
      isDelete ? "btn-link danger" : (isPrimary ? "btn-primary" : "btn-secondary"),
      action.label || action.id,
    );
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      runAppAction(app, action);
    });
    if (isDelete) danger.append(button);
    else if (isPrimary) primary.append(button);
    else secondary.append(button);
  });
  return [primary, secondary, danger].filter((group) => group.childNodes.length);
};

const publicURLFromRule = (rule) => {
  if (!rule || rule.enabled === false) return "";
  const domain = String(rule.domain || "").trim();
  if (!domain) return "";
  try {
    const parsed = new URL(/^https?:\/\//i.test(domain) ? domain : `https://${domain}`);
    if (parsed.username || parsed.password) return "";
    parsed.search = "";
    parsed.hash = "";
    const path = parsed.pathname && parsed.pathname !== "/" ? parsed.pathname.replace(/\/$/, "") : "";
    return `${parsed.protocol}//${parsed.host}${path}`;
  } catch (_error) {
    if (/^https?:\/\//i.test(domain)) return domain.replace(/\/$/, "");
    return `https://${domain}`;
  }
};

const backendPortFromRule = (rule) => {
  const port = Number(rule && rule.port);
  if (port > 0 && port <= 65535) return port;
  const backend = String((rule && rule.backend) || "");
  const match = backend.match(/:(\d{1,5})\s*$/);
  if (!match) return 0;
  const parsed = Number(match[1]);
  return parsed > 0 && parsed <= 65535 ? parsed : 0;
};

const firstEnabledRuleURL = (app) => {
  const rules = Array.isArray(app.rules) ? app.rules : [];
  for (const rule of rules) {
    const openURL = publicURLFromRule(rule);
    if (openURL) return openURL;
  }
  return "";
};

const appMark = (id) => {
  const text = String(id || "?").replace(/[^a-z0-9\u4e00-\u9fff]/gi, "") || "?";
  const letters = text.slice(0, text.charCodeAt(0) > 127 ? 1 : 2).toUpperCase();
  let hash = 0;
  for (let i = 0; i < text.length; i += 1) hash = (hash * 33 + text.charCodeAt(i)) >>> 0;
  return { letters, tone: String(hash % 6) };
};

const displayHost = (url) => {
  try {
    const parsed = new URL(url);
    return parsed.host + (parsed.pathname && parsed.pathname !== "/" ? parsed.pathname.replace(/\/$/, "") : "");
  } catch (_error) {
    return String(url || "").replace(/^https?:\/\//i, "");
  }
};

const renderApp = (app) => {
  const source = appCardTemplate && appCardTemplate.content.querySelector(".app-card");
  const card = source ? source.cloneNode(true) : document.createElement("article");
  card.className = "app-card";
  card.dataset.id = app.id;
  card.dataset.status = app.status || "已停止";
  card.tabIndex = 0;
  const nameNode = card.querySelector("[data-app-name]");
  if (nameNode) nameNode.textContent = app.name || app.id;
  const markNode = card.querySelector("[data-app-mark]");
  if (markNode) {
    const mark = appMark(app.name || app.id);
    markNode.textContent = mark.letters;
    markNode.dataset.tone = mark.tone;
  }
  const statusHook = card.querySelector("[data-app-status]");
  if (statusHook) {
    const status = app.status && app.status !== "有新版本" ? app.status : "";
    const hasUpdate = app.notice === "有新版本" || app.status === "有新版本";
    statusHook.textContent = status;
    statusHook.hidden = !status;
    if (status) statusHook.dataset.status = status;
    else delete statusHook.dataset.status;
    if (hasUpdate && statusHook.parentNode) {
      const notice = document.createElement("span");
      notice.className = "app-card-status";
      notice.dataset.status = "有新版本";
      notice.textContent = "有新版本";
      statusHook.parentNode.append(notice);
    }
  }
  const imageNode = card.querySelector("[data-app-image]");
  if (imageNode) {
    const version = appVersion(app);
    const shown = cardImage(version);
    imageNode.textContent = shown;
    imageNode.hidden = !shown;
    imageNode.title = version;
  }
  const portNode = card.querySelector("[data-app-ports]");
  if (portNode) {
    portNode.replaceChildren();
    const ports = appPorts(app);
    const services = Array.isArray(app.services) ? app.services.filter(Boolean) : [];
    if (ports.length) {
      ports.forEach((port) => {
        const bit = document.createElement("span");
        bit.className = "app-port";
        bit.textContent = String(port);
        portNode.append(bit);
      });
    } else {
      const empty = document.createElement("span");
      empty.className = "app-port app-port-empty";
      empty.textContent = "无发布端口";
      portNode.append(empty);
    }
    if (services.length > 1) {
      const extra = document.createElement("span");
      extra.className = "app-port app-port-empty";
      extra.textContent = `${services.length} 个服务`;
      portNode.append(extra);
    }
    portNode.hidden = false;
  }
  const openURL = firstEnabledRuleURL(app);
  const urlNode = card.querySelector("[data-app-url]");
  if (urlNode) {
    urlNode.hidden = !openURL;
    urlNode.textContent = openURL ? displayHost(openURL) : "";
    urlNode.title = openURL;
  }
  const openButton = card.querySelector('[data-action="open"]');
  if (openButton) {
    openButton.hidden = !openURL;
    openButton.textContent = "打开";
    if (openURL) {
      openButton.addEventListener("click", (event) => {
        event.stopPropagation();
        window.open(openURL, "_blank", "noopener,noreferrer");
      });
    }
  }
  const actionsByID = new Map((Array.isArray(app.actions) ? app.actions : []).map((action) => [action.id, action]));
  ["update"].forEach((id) => {
    const button = card.querySelector(`[data-action="${id}"]`);
    const action = actionsByID.get(id);
    if (!button) return;
    button.hidden = !action;
    if (!action) return;
    button.textContent = action.label || id;
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      runAppAction(app, action);
    });
  });
  const openDetail = () => { showDetail(app.id, "overview"); };
  const detailButton = card.querySelector('[data-action="detail"]');
  if (detailButton) {
    detailButton.textContent = "详情";
    detailButton.addEventListener("click", (event) => {
      event.stopPropagation();
      openDetail();
    });
  }
  card.addEventListener("click", (event) => {
    if (event.target.closest("button")) return;
    openDetail();
  });
  card.addEventListener("keydown", (event) => {
    if (event.target !== card) return;
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      openDetail();
    }
  });
  return card;
};

const fillCompose = (app) => {
  if (detailComposeInput) {
    detailComposeInput.value = app.compose || "";
    paintCodeEditor(detailComposeInput);
  }
  if (detailEnvInput) {
    detailEnvInput.value = "";
    paintCodeEditor(detailEnvInput);
  }
  if (detailAutoUpdateInput) detailAutoUpdateInput.checked = app.auto_update === true;
  composeFilledFor = app.id;
};

const renderOverview = (app) => {
  if (!overviewPanel) return;
  overviewPanel.replaceChildren();
  const serviceViews = serviceImages(app);
  const services = serviceViews.length
    ? serviceViews.map((item) => item.name)
    : (Array.isArray(app.services) ? app.services.filter(Boolean) : []);
  const ports = appPorts(app);
  const rules = Array.isArray(app.rules) ? app.rules : [];
  const volumes = parseComposeVolumes(app.compose);
  const agent = selectedAgent();
  const version = appVersion(app);
  const image = splitImage(version);
  const restart = parseComposeScalar(app.compose, "restart");
  const user = parseComposeScalar(app.compose, "user");
  const hasUpdate = app.notice === "有新版本" || app.status === "有新版本";
  const statusValue = app.status && app.status !== "有新版本" ? app.status : (hasUpdate ? "有新版本" : "已停止");

  const stats = document.createElement("div");
  stats.className = "overview-stats";
  [
    [statusValue, "状态"],
    [String(services.length || 1), "服务"],
    [String(ports.length), "端口"],
    [String(rules.length), "入口"],
  ].forEach(([value, label]) => {
    const item = document.createElement("div");
    item.className = "overview-stat";
    if (label === "状态") item.dataset.status = value;
    const small = document.createElement("span");
    small.textContent = label;
    const strong = document.createElement("strong");
    strong.textContent = value;
    item.append(small, strong);
    stats.append(item);
  });
  overviewPanel.append(stats);

  const sheet = document.createElement("div");
  sheet.className = "overview-sheet";
  const addBlock = (title) => {
    const block = document.createElement("section");
    block.className = "overview-block";
    const heading = document.createElement("h3");
    heading.textContent = title;
    const grid = document.createElement("dl");
    grid.className = "overview-grid";
    block.append(heading, grid);
    sheet.append(block);
    return grid;
  };
  const addRow = (grid, label, value, options = {}) => {
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    if (options.node) dd.append(options.node);
    else dd.textContent = value;
    if (options.title) dd.title = options.title;
    if (options.mono) dd.classList.add("overview-mono");
    grid.append(dt, dd);
  };

  const run = addBlock("运行");
  addRow(run, "节点", agentDisplayName(agent) || app.agent_id || "未绑定节点");
  const imageNode = document.createElement("div");
  imageNode.className = "overview-image";
  const imageName = document.createElement("span");
  imageName.className = "overview-mono";
  imageName.textContent = image.name;
  imageName.title = version;
  imageNode.append(imageName);
  if (image.digest) {
    const digest = chip(image.digest.slice(0, 12));
    digest.className = "chip app-version";
    digest.title = version;
    imageNode.append(digest);
  }
  if (serviceViews.length) {
    const list = document.createElement("div");
    list.className = "overview-services";
    serviceViews.forEach((service) => {
      const item = document.createElement("div");
      item.className = "overview-service";
      const head = document.createElement("div");
      head.className = "overview-service-head";
      const name = document.createElement("strong");
      name.textContent = service.name;
      const image = document.createElement("span");
      image.className = "overview-mono";
      image.textContent = service.image || service.tag || "未解析镜像";
      head.append(name, image);
      item.append(head);
      const tools = document.createElement("div");
      tools.className = "overview-service-tools";
      const flag = document.createElement("p");
      flag.className = "overview-service-flag";
      const digestRefresh = Array.isArray(service.candidates) && service.candidates.some((candidate) => candidate.digest);
      if (digestRefresh) {
        flag.dataset.state = "ready";
        flag.textContent = "镜像有新 digest";
      } else if (service.update) {
        flag.dataset.state = "ready";
        flag.textContent = "有允许候选";
      } else if (service.unknown) {
        flag.dataset.state = "unknown";
        flag.textContent = "候选未知";
      } else {
        flag.dataset.state = "empty";
        flag.textContent = "无允许候选";
      }
      tools.append(flag);
      const lockSelect = renderServiceLockSelect(service);
      if (lockSelect) tools.append(lockSelect);
      const lock = tools.querySelector(`select[name="lock-${service.name}"]`);
      if (lock) {
        lock.addEventListener("change", () => {
          saveServicePolicy(app, { locks: { [service.name]: lock.value } }, "已保存锁定。");
        });
      }
      renderIgnoredClearControls(service, { buttons: true }).forEach((button) => {
        button.addEventListener("click", (event) => {
          event.preventDefault();
          event.stopPropagation();
          const tag = String(button.dataset.tag || "").trim();
          if (!tag) return;
          saveServicePolicy(app, { ignore: [{ service: service.name, tag, clear: true }] }, "已取消忽略。");
        });
        tools.append(button);
      });
      item.append(tools);
      list.append(item);
    });
    addRow(run, "服务镜像", "", { node: list });
  } else {
    addRow(run, "镜像", "", { node: imageNode });
    addRow(run, "服务", services.length ? services.join(" · ") : app.id);
  }
  if (ports.length) {
    const list = document.createElement("div");
    list.className = "overview-chips";
    ports.forEach((port) => list.append(chip(String(port))));
    addRow(run, "端口", "", { node: list });
  } else {
    addRow(run, "端口", "无发布端口");
  }
  if (restart) addRow(run, "重启策略", restart);
  if (user) addRow(run, "容器用户", user);
  addRow(run, "自动更新", app.auto_update === true ? "已开启" : "默认关闭");
  if (hasUpdate) addRow(run, "更新", "镜像有新版本");

  const net = addBlock("入口");
  if (rules.length) {
    const list = document.createElement("div");
    list.className = "overview-links";
    rules.forEach((rule) => {
      const domain = String(rule.domain || "").trim();
      const openURL = rule.enabled === false ? "" : firstEnabledRuleURL({ rules: [rule] });
      if (openURL) {
        const link = document.createElement("a");
        link.href = openURL;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.className = "http-rule-open";
        link.textContent = displayHost(openURL) || domain || openURL;
        list.append(link);
      } else {
        const span = document.createElement("span");
        span.textContent = domain ? `${domain}${rule.enabled === false ? "（已停用）" : ""}` : "未命名入口";
        list.append(span);
      }
    });
    addRow(net, "域名", "", { node: list });
  } else {
    addRow(net, "域名", "未配置 HTTP 入口");
  }

  const store = addBlock("存储");
  if (volumes.length) {
    const list = document.createElement("ul");
    list.className = "overview-mounts";
    volumes.forEach((volume) => {
      const item = document.createElement("li");
      const src = document.createElement("span");
      src.className = "overview-mono";
      src.textContent = volume.source;
      const arrow = document.createElement("span");
      arrow.className = "overview-arrow";
      arrow.textContent = "→";
      const dst = document.createElement("span");
      dst.className = "overview-mono";
      dst.textContent = volume.target;
      item.append(src, arrow, dst);
      list.append(item);
    });
    addRow(store, "数据卷", "", { node: list });
  } else {
    addRow(store, "数据卷", "无数据卷");
  }
  overviewPanel.append(sheet);
  actionGroups(app, { overview: true }).forEach((group) => {
    if (group.classList.contains("app-actions-danger")) {
      const copy = document.createElement("p");
      copy.className = "overview-danger-copy";
      copy.textContent = "删除会停止容器并清掉该应用工作区。";
      group.prepend(copy);
    }
    overviewPanel.append(group);
  });
};

const renderHTTP = (app) => {
  if (!httpPanel) return;
  httpPanel.replaceChildren();
  const ports = appPorts(app);
  const rules = Array.isArray(app.rules) ? app.rules : [];
  if (rules.length) {
    const ruleList = document.createElement("ul");
    ruleList.className = "http-rules";
    rules.forEach((rule) => {
      const item = document.createElement("li");
      const domain = String(rule.domain || "").trim();
      const disabled = rule.enabled === false;
      const openURL = disabled ? "" : publicURLFromRule(rule);
      const main = document.createElement("div");
      main.className = "http-rule-main";
      if (openURL) {
        const link = document.createElement("a");
        link.href = openURL;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.className = "http-rule-open";
        link.textContent = openURL;
        link.addEventListener("click", (event) => {
          event.preventDefault();
          window.open(openURL, "_blank", "noopener,noreferrer");
        });
        main.append(link);
      } else {
        const label = document.createElement("span");
        label.textContent = `${domain || "未命名入口"}${disabled ? "（已停用）" : ""}`;
        if (disabled) label.className = "http-rule-disabled";
        main.append(label);
      }
      const backendPort = backendPortFromRule(rule);
      if (backendPort) {
        const bound = chip(`后端 ${backendPort}`);
        bound.title = "容器发布端口，不是入口监听端口";
        main.append(bound);
      }
      item.append(main);
      if (rule.ref) {
        const deleteRule = document.createElement("button");
        deleteRule.type = "button";
        deleteRule.className = "btn-link danger";
        deleteRule.textContent = "删除";
        deleteRule.addEventListener("click", async () => {
          if (busy) return;
          if (!await askConfirm({
            title: "删除入口",
            body: `确认删除入口 ${domain || rule.ref}？取消不会更改规则。`,
            confirm: "删除",
            cancel: "取消",
            danger: true,
          })) {
            showStatus("已取消，规则未更改。", false);
            return;
          }
          setBusy(true);
          try {
            await sendPluginJSON(`api/apps/${encodeURIComponent(app.id)}/http-rule-delete`, {
              rule_ref: rule.ref,
            });
            showStatus("已删除 HTTP 规则。", false);
            await renderWorkspace();
          } catch (error) {
            showStatus(error.message, true);
          } finally {
            setBusy(false);
          }
        });
        item.append(deleteRule);
      }
      ruleList.append(item);
    });
    httpPanel.append(ruleList);
  } else if (ports.length) {
    const empty = document.createElement("p");
    empty.className = "http-empty";
    empty.textContent = "还没有入口。把域名绑定到下面的发布端口。";
    httpPanel.append(empty);
  }
  if (ports.length) {
    const form = document.createElement("form");
    form.className = "http-form";
    const formTitle = document.createElement("p");
    formTitle.className = "http-form-title";
    formTitle.textContent = "添加入口";
    form.append(formTitle);
    const portLabel = document.createElement("label");
    portLabel.append("端口");
    const portSelect = document.createElement("select");
    portSelect.name = "port";
    ports.forEach((port) => {
      const option = document.createElement("option");
      option.value = String(port);
      option.textContent = String(port);
      portSelect.append(option);
    });
    portLabel.append(portSelect);
    const domainLabel = document.createElement("label");
    domainLabel.append("入口域名");
    const domain = document.createElement("input");
    domain.name = "domain";
    domain.required = true;
    domain.autocomplete = "off";
    domain.spellcheck = false;
    domain.placeholder = "app.example.com";
    domainLabel.append(domain);
    const submit = document.createElement("button");
    submit.type = "submit";
    submit.className = "btn-primary";
    submit.textContent = "添加入口";
    form.append(portLabel, domainLabel, submit);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (busy) return;
      setBusy(true);
      try {
        await sendPluginJSON(`api/apps/${encodeURIComponent(app.id)}/http-rule`, {
          domain: domain.value.trim(),
          port: Number(portSelect.value),
        });
        showStatus("已创建 HTTP 规则。", false);
        form.reset();
        await renderWorkspace();
      } catch (error) {
        showStatus(error.message, true);
      } finally {
        setBusy(false);
      }
    });
    httpPanel.append(form);
  } else {
    const hint = document.createElement("p");
    hint.className = "hint";
    hint.textContent = "没有可挂的端口";
    httpPanel.append(hint);
  }
};

const fillLogServices = (app) => {
  const services = Array.isArray(app.services) ? app.services : [];
  const previous = logsService ? logsService.value : "";
  if (!logsService) return;
  logsService.replaceChildren();
  services.forEach((name) => {
    const option = document.createElement("option");
    option.value = name;
    option.textContent = name;
    logsService.append(option);
  });
  if (previous && services.includes(previous)) logsService.value = previous;
};

const stopLogPolling = () => {
  if (logsTimer) {
    clearInterval(logsTimer);
    logsTimer = null;
  }
};

const setLogsState = (text, isError) => {
  if (!logsStatus) return;
  logsStatus.textContent = text;
  logsStatus.dataset.error = isError ? "true" : "false";
};

const paintLogsView = () => {
  if (!logsView) return;
  const raw = logsView.textContent || "";
  if (!raw) return;
  const frag = document.createDocumentFragment();
  raw.replace(/\n$/, "").split("\n").forEach((line) => {
    const row = document.createElement("span");
    row.className = "log-line";
    const lower = line.toLowerCase();
    if (/\b(error|fatal|panic|fail|failed)\b/.test(lower)) row.dataset.level = "error";
    else if (/\b(warn|warning)\b/.test(lower)) row.dataset.level = "warn";
    else if (/\b(ready|started|listening)\b/.test(lower)) row.dataset.level = "ok";
    const time = line.match(/^(\d{4}-\d{2}-\d{2}[T ][\d:.Z+-]+)\s*(.*)$/);
    if (time) {
      const stamp = document.createElement("span");
      stamp.className = "log-time";
      stamp.textContent = `${time[1]} `;
      const rest = document.createElement("span");
      rest.textContent = time[2];
      row.append(stamp, rest);
    } else {
      row.textContent = line || " ";
    }
    frag.append(row);
  });
  logsView.replaceChildren(frag);
};

const resetLogsTerminal = () => {
  logsSeq += 1;
  if (logsView) {
    logsView.textContent = "";
    logsView.dataset.error = "false";
  }
  setLogsState("", false);
};

const logsContextCurrent = () => detailApp && view === "detail" && detailSection === "logs";

const fetchLogs = async () => {
  if (!logsContextCurrent()) return;
  const service = logsService ? logsService.value : "";
  if (!service) {
    logsLoaded = true;
    resetLogsTerminal();
    setLogsState("没有可查看的服务", false);
    stopLogPolling();
    return;
  }
  const seq = ++logsSeq;
  const appID = detailApp.id;
  try {
    const payload = await sendPluginJSON(`api/apps/${encodeURIComponent(appID)}/logs`, { service });
    if (seq !== logsSeq || !logsContextCurrent() || detailApp.id !== appID) return;
    if (logsView) {
      logsView.textContent = payload.logs || "";
      logsView.dataset.error = "false";
      paintLogsView();
    }
    logsLoaded = true;
    if (!logsPaused) setLogsState("自动刷新", false);
  } catch (error) {
    if (seq !== logsSeq || !logsContextCurrent() || detailApp.id !== appID) return;
    if (logsView) logsView.dataset.error = "true";
    setLogsState("自动刷新失败，已保留上次快照", true);
    if (!logsLoaded) showStatus(error.message, true);
  }
};

const startLogPolling = () => {
  stopLogPolling();
  if (view !== "detail" || detailSection !== "logs") return;
  fetchLogs();
  if (logsPaused || document.visibilityState === "hidden") return;
  if (!(logsService && logsService.value)) return;
  logsTimer = setInterval(fetchLogs, LOG_REFRESH_MS);
};

const paintDetail = (app) => {
  const appChanged = !detailApp || detailApp.id !== app.id;
  detailApp = app;
  selectedAppID = app.id;
  if (detailTitle) detailTitle.textContent = app.id;
  if (detailStatus) {
    const status = app.status && app.status !== "有新版本" ? app.status : "";
    detailStatus.textContent = status;
    detailStatus.hidden = !status;
    if (status) detailStatus.dataset.status = status;
    else delete detailStatus.dataset.status;
  }
  const openURL = firstEnabledRuleURL(app);
  if (detailOpen) {
    detailOpen.hidden = !openURL;
    detailOpen.textContent = "打开";
    if (openURL) detailOpen.setAttribute("href", openURL);
    else detailOpen.removeAttribute("href");
  }
  const actionsByID = new Map((Array.isArray(app.actions) ? app.actions : []).map((action) => [action.id, action]));
  [
    ["start", detailStart],
    ["stop", detailStop],
    ["restart", detailRestart],
  ].forEach(([id, button]) => {
    if (!button) return;
    const action = actionsByID.get(id);
    button.hidden = !action;
    if (action) button.textContent = action.label || id;
  });
  renderOverview(app);
  if (composeFilledFor !== app.id) fillCompose(app);
  renderHTTP(app);
  fillLogServices(app);
  if (appChanged) resetLogsTerminal();
};

const setDetailSection = async (section) => {
  const next = section || "overview";
  if (next !== "files" && !(await filesWorkspace.confirmLeave())) return false;
  if (detailSection === "logs" && next !== "logs") stopLogPolling();
  detailSection = next;
  document.querySelectorAll("[data-section-panel]").forEach((panel) => {
    panel.hidden = panel.getAttribute("data-section-panel") !== next;
  });
  if (detailNav) {
    detailNav.querySelectorAll("[data-section]").forEach((button) => {
      button.setAttribute("aria-current", button.dataset.section === next ? "page" : "false");
    });
  }
  if (next === "files" && detailApp) filesWorkspace.bind(detailApp);
  if (next === "compose") {
    paintCodeEditor(detailComposeInput);
    paintCodeEditor(detailEnvInput);
  }
  if (next === "logs") {
    logsPaused = false;
    logsLoaded = false;
    if (logsPause) {
      logsPause.textContent = "暂停";
      logsPause.setAttribute("aria-pressed", "false");
    }
    if (logsRefresh) logsRefresh.dataset.action = "logs";
    startLogPolling();
  }
  return true;
};

const leaveDetail = async ({ force } = {}) => {
  if (!force && !(await filesWorkspace.confirmLeave())) return false;
  stopLogPolling();
  resetLogsTerminal();
  if (force) filesWorkspace.discard();
  view = "list";
  selectedAppID = "";
  detailApp = null;
  detailSection = "overview";
  logsPaused = false;
  logsLoaded = false;
  composeFilledFor = "";
  filesMountedFor = "";
  showStatus("", false);
  syncListPanel();
  return true;
};

const showDetail = async (appID, section) => {
  if (!(await confirmLeaveEditor())) return;
  try {
    const payload = await panelJSON(`api/apps/${encodeURIComponent(appID)}`);
    const app = payload.app;
    if (!app) throw Object.assign(new Error("应用已不存在。"), { status: 404 });
    view = "detail";
    closeCreate();
    paintDetail(app);
    if (!(await setDetailSection(section || detailSection || "overview"))) return;
    syncListPanel();
  } catch (error) {
    const missing = error.status === 404 || error.message === "app is unknown";
    showStatus(missing ? "应用已不存在。" : error.message, true);
    leaveDetail({ force: true });
  }
};

const loadEngine = async () => {
  if (!selectedAgentID) return null;
  const payload = await panelJSON(`api/engine?agent_id=${encodeURIComponent(selectedAgentID)}`);
  const engine = payload.engine || null;
  rememberEngine(selectedAgentID, engine);
  agentPicker.refresh();
  return engine;
};

const renderGuide = (engine) => {
  const command = engine?.command || {};
  if (engineScript) engineScript.textContent = command.script || OFFICIAL_INSTALL_SCRIPT;
  const daemonJSON = command.daemon_json || "";
  if (daemonNode) daemonNode.textContent = daemonJSON;
  if (daemonWrap) daemonWrap.hidden = !daemonJSON;
};

const showUnreadyGuide = (engine) => {
  const viewState = engine && engine.ready !== true
    ? engine
    : { ready: false, command: engine?.command || { script: OFFICIAL_INSTALL_SCRIPT } };
  lastEngine = viewState;
  engineReady = false;
  if (deployToggle) deployToggle.hidden = true;
  if (diskCleanup) diskCleanup.hidden = true;
  if (workspaceNode) workspaceNode.hidden = true;
  leaveDetail({ force: true });
  renderGuide(viewState);
  renderEngineBadge(viewState);
  showContext(executionFaceUnavailable(viewState) ? "execution-unavailable" : "unready");
};

const executionFaceUnavailable = (engine) => agentOnline && engine && engine.online === false && engine.ready !== true;

const showContext = (which) => {
  if (nodeEmpty) nodeEmpty.hidden = which !== "empty";
  if (undeployedNode) undeployedNode.hidden = which !== "undeployed";
  if (offlineNode) offlineNode.hidden = which !== "offline";
  if (executionUnavailableNode) executionUnavailableNode.hidden = which !== "execution-unavailable";
  if (engineGuide) engineGuide.hidden = which !== "unready";
  if (contextNode) contextNode.hidden = which !== "empty" && which !== "undeployed" && which !== "offline" && which !== "execution-unavailable";
};

const renderApps = (apps) => {
  const list = Array.isArray(apps) ? apps : [];
  listNode.replaceChildren(...list.map(renderApp));
  countNode.hidden = list.length === 0;
  countNode.textContent = `${list.length} 个`;
  syncListPanel();
};

const renderEngineBadge = (engine) => {
  if (!engineStatus) return;
  if (!selectedAgentID) {
    engineStatus.hidden = true;
    return;
  }
  engineStatus.hidden = false;
  if (!agentOnline) {
    engineReady = false;
    engineStatus.dataset.ready = "false";
    engineStatus.textContent = "节点离线";
    return;
  }
  if (!engine) {
    engineReady = false;
    engineStatus.dataset.ready = "false";
    engineStatus.textContent = "引擎未就绪";
    return;
  }
  engineReady = engine.ready === true;
  engineStatus.dataset.ready = engineReady ? "true" : "false";
  if (executionFaceUnavailable(engine)) {
    engineStatus.textContent = "暂时无法执行";
    return;
  }
  engineStatus.textContent = engineReady
    ? (engine.version ? `引擎 ${engine.version} 已就绪` : "引擎已就绪")
    : "引擎未就绪";
};

const renderWorkspace = async () => {
  const seq = ++workspaceSeq;
  const keepDetailID = view === "detail" ? selectedAppID : "";
  const keepSection = detailSection;
  const agent = selectedAgent();
  agentOnline = isAgentOnline(agent);
  engineReady = false;
  lastEngine = null;
  workspaceNode.hidden = true;
  emptyNode.hidden = true;
  closeCreate();
  showStatus("", false);
  renderApps([]);
  if (!selectedAgentID) {
    leaveDetail({ force: true });
    renderEngineBadge(null);
    showContext(agentsCache.length ? "empty" : "undeployed");
    return;
  }
  if (!agentOnline) {
    leaveDetail({ force: true });
    renderEngineBadge(null);
    showContext("offline");
    return;
  }
  showContext("");
  let engine = null;
  try {
    engine = await loadEngine();
  } catch (error) {
    if (seq !== workspaceSeq) return;
    if (error && error.denied) throw error;
    if (error && error.message === "暂时无法管理 Docker 应用。") throw error;
    leaveDetail({ force: true });
    renderGuide(null);
    renderEngineBadge(null);
    showContext("execution-unavailable");
    return;
  }
  if (seq !== workspaceSeq) return;
  lastEngine = engine;
  engineReady = engine?.ready === true;
  renderEngineBadge(engine);
  if (!engineReady) {
    leaveDetail({ force: true });
    renderGuide(engine);
    showContext(executionFaceUnavailable(engine) ? "execution-unavailable" : "unready");
    return;
  }
  showContext("");
  workspaceNode.hidden = false;
  const payload = await panelJSON(`api/apps?agent_id=${encodeURIComponent(selectedAgentID)}`);
  if (seq !== workspaceSeq) return;
  renderApps(payload.apps);
  if (payload.error) showStatus(payload.error, true);
  if (keepDetailID) {
    const stillThere = (payload.apps || []).some((app) => app.id === keepDetailID);
    if (!stillThere) {
      showStatus("应用已不存在。", true);
      leaveDetail({ force: true });
      return;
    }
    await showDetail(keepDetailID, keepSection);
  } else {
    syncListPanel();
  }
};

const loadAgents = async () => {
  const payload = await panelJSON("/panel-api/agents");
  const remotes = Array.isArray(payload.agents)
    ? payload.agents.filter((agent) => agent && agent.is_local !== true && agent.mode !== "local")
    : [];
  const plugin = await panelJSON("/panel-api/plugins/docker-app");
  const deployed = new Set();
  const instances = Array.isArray(plugin.instances) ? plugin.instances : [];
  instances.forEach((instance) => {
    const targets = Array.isArray(instance && instance.targets) ? instance.targets : [];
    targets.forEach((target) => {
      const id = String(target || "").trim();
      if (id) deployed.add(id);
    });
  });
  agentsCache = remotes.filter((agent) => deployed.has(agent.id));
  const requested = new URLSearchParams(window.location.search).get("agent_id") || "";
  selectedAgentID = agentsCache.some((agent) => agent.id === requested)
    ? requested
    : (agentsCache.length === 1 ? agentsCache[0].id : "");
  agentPicker.refresh(selectedAgentID);
};

agentPicker.onChange = async (value) => {
  if (!(await confirmLeaveEditor())) {
    agentPicker.setValue(selectedAgentID);
    return;
  }
  leaveDetail({ force: true });
  selectedAgentID = String(value || "");
  const url = new URL(window.location.href);
  if (selectedAgentID) url.searchParams.set("agent_id", selectedAgentID);
  else url.searchParams.delete("agent_id");
  window.history.replaceState({}, "", url);
  closeCreate();
  try {
    await renderWorkspace();
  } catch (error) {
    showStatus(error.message, true);
  }
};

if (deployToggle) {
  deployToggle.addEventListener("click", () => {
    if (!selectedAgentID) {
      showStatus("请先选择一台节点。", true);
      return;
    }
    if (!agentOnline) {
      showStatus("该节点离线，不能部署。", true);
      return;
    }
    if (!engineReady) {
      showUnreadyGuide(lastEngine);
      showStatus("引擎未就绪，请先在该节点本机安装 Docker。", true);
      return;
    }
    openCreate();
  });
}

const diskCleanupStatusLabel = (status) => {
  switch (String(status || "").trim()) {
    case "success":
      return "完成";
    case "partial":
      return "部分成功";
    case "failed":
      return "失败";
    case "skipped":
      return "未执行";
    default:
      return String(status || "").trim();
  }
};

const diskCleanupFailureKindLabel = (kind) => {
  switch (String(kind || "").trim()) {
    case "docker-unavailable":
      return "无法连接目标节点的 Docker，请确认 Docker 已启动后重试";
    case "readonly-stats":
      return "读取节点磁盘占用失败，请稍后重试";
    default:
      return "";
  }
};

const diskCleanupPreviewFailed = (cleanup) => {
  if (!cleanup) return false;
  const kind = String(cleanup.failure_kind || "").trim();
  return cleanup.status === "failed" || kind === "docker-unavailable" || kind === "readonly-stats";
};

const formatDiskCleanupPreviewFailure = (cleanup) => {
  const kind = diskCleanupFailureKindLabel(cleanup && cleanup.failure_kind);
  const detail = String((cleanup && (cleanup.images || cleanup.builder_cache)) || "").trim();
  if (kind && detail && detail !== kind) return `${kind}\n${detail}`;
  return kind || "读取节点磁盘占用失败，请稍后重试";
};

const formatDiskCleanupBody = (cleanup) => {
  if (diskCleanupPreviewFailed(cleanup)) {
    return formatDiskCleanupPreviewFailure(cleanup);
  }
  const policy = "以下为估算值。将只删除 dangling 镜像（无标签且未被容器引用），构建缓存按 keep-storage 保留 2GB，数据卷不受影响。";
  if (!cleanup || cleanup.empty) {
    return `${policy}\n\n没有可清理的闲置镜像或构建缓存。关闭不会更改节点。`;
  }
  const chunks = [];
  if (cleanup.images) chunks.push(`镜像（估算值）\n${cleanup.images}`);
  if (cleanup.builder_cache) chunks.push(`构建缓存（估算值）\n${cleanup.builder_cache}`);
  const lead = `${policy} 取消不会更改节点。`;
  return chunks.length ? `${lead}\n\n${chunks.join("\n\n")}` : lead;
};

const formatDiskCleanupResult = (cleanup) => {
  if (!cleanup) return "已执行磁盘清理。";
  if (cleanup.unchanged) return "已取消，未清理节点磁盘。";
  const overall = diskCleanupStatusLabel(cleanup.status) || "未知";
  const imageState = diskCleanupStatusLabel(cleanup.images_status) || "未知";
  const builderState = diskCleanupStatusLabel(cleanup.builder_cache_status) || "未知";
  const lines = [];
  if (cleanup.empty) lines.push("没有可清理项。");
  lines.push(`总体状态：${overall}`);
  lines.push(cleanup.images ? `镜像：${imageState}\n${cleanup.images}` : `镜像：${imageState}`);
  lines.push(cleanup.builder_cache ? `构建缓存：${builderState}\n${cleanup.builder_cache}` : `构建缓存：${builderState}`);
  if (cleanup.status === "partial") {
    const failed = [];
    const completed = [];
    if (cleanup.images_status === "failed") failed.push("镜像");
    else if (cleanup.images_status === "success") completed.push("镜像");
    if (cleanup.builder_cache_status === "failed") failed.push("构建缓存");
    else if (cleanup.builder_cache_status === "success") completed.push("构建缓存");
    if (failed.length) {
      const other = completed.length ? `${completed.join("、")}已完成。` : "另一步未完成。";
      lines.push(`失败阶段：${failed.join("、")}。${other}`);
    }
  }
  return lines.join("\n\n");
};

const runDiskCleanup = async () => {
  if (busy || !selectedAgentID) return;
  if (!agentOnline) {
    showStatus("该节点离线，不能清理磁盘。", true);
    return;
  }
  if (!engineReady) {
    showStatus("引擎未就绪，不能清理磁盘。", true);
    return;
  }
  setBusy(true);
  let previewed = null;
  try {
    const payload = await panelJSON(`api/disk-cleanup?agent_id=${encodeURIComponent(selectedAgentID)}`);
    previewed = payload.cleanup || null;
  } catch (error) {
    showStatus(error.message, true);
    setBusy(false);
    return;
  }
  setBusy(false);
  if (diskCleanupPreviewFailed(previewed)) {
    showStatus(formatDiskCleanupPreviewFailure(previewed), true);
    return;
  }
  const empty = !previewed || previewed.empty === true;
  const ok = await askConfirm({
    title: "清理节点磁盘",
    body: formatDiskCleanupBody(previewed),
    confirm: empty ? "知道了" : "清理",
    cancel: empty ? "知道了" : "取消",
    danger: !empty,
    hideConfirm: empty,
  });
  if (!ok || empty) {
    showStatus(empty ? "没有可清理项。" : "已取消，未清理节点磁盘。", false);
    return;
  }
  setBusy(true);
  try {
    const payload = await sendPluginJSON("api/disk-cleanup", {
      agent_id: selectedAgentID,
      confirm: true,
    });
    const cleanup = payload.cleanup || {};
    const failed = cleanup.status === "failed" || cleanup.status === "partial";
    showStatus(formatDiskCleanupResult(cleanup), failed);
  } catch (error) {
    showStatus(error.message, true);
  } finally {
    setBusy(false);
  }
};

if (diskCleanup) {
  diskCleanup.addEventListener("click", () => {
    runDiskCleanup();
  });
}

if (createCancel) createCancel.addEventListener("click", closeCreate);
if (createBack) createBack.addEventListener("click", closeCreate);

const templateRoot = createTemplates || createPanel;
if (templateRoot) {
  templateRoot.querySelectorAll("[data-template]").forEach((button) => {
    button.addEventListener("click", () => {
      applyCreateTemplate(button.dataset.template);
    });
  });
}

if (detailBack) {
  detailBack.addEventListener("click", () => {
    leaveDetail();
  });
}

[
  ["start", detailStart],
  ["stop", detailStop],
  ["restart", detailRestart],
].forEach(([id, button]) => {
  if (!button) return;
  button.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    if (!detailApp || busy) return;
    const action = (Array.isArray(detailApp.actions) ? detailApp.actions : []).find((item) => item.id === id);
    if (action) runAppAction(detailApp, action);
  });
});

if (detailNav) {
  detailNav.querySelectorAll("[data-section]").forEach((button) => {
    button.addEventListener("click", () => {
      if (view !== "detail") return;
      setDetailSection(button.dataset.section);
    });
  });
}

if (logsRefresh) {
  logsRefresh.dataset.action = "logs";
  logsRefresh.addEventListener("click", () => {
    if (view === "detail" && detailSection === "logs") fetchLogs();
  });
}

if (logsPause) {
  logsPause.addEventListener("click", () => {
    if (view !== "detail" || detailSection !== "logs") return;
    logsPaused = !logsPaused;
    logsPause.textContent = logsPaused ? "继续" : "暂停";
    logsPause.setAttribute("aria-pressed", logsPaused ? "true" : "false");
    if (logsPaused) {
      stopLogPolling();
      setLogsState("已暂停", false);
    } else {
      startLogPolling();
    }
  });
}

if (logsService) {
  logsService.addEventListener("change", () => {
    if (view === "detail" && detailSection === "logs") startLogPolling();
  });
}

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "hidden") {
    stopLogPolling();
    return;
  }
  if (view === "detail" && detailSection === "logs" && !logsPaused) startLogPolling();
});

if (copyScript) {
  copyScript.addEventListener("click", async () => {
    try {
      await copyText(engineScript ? engineScript.textContent : "");
    } catch (error) {
      showStatus(error.message, true);
    }
  });
}

if (copyDaemon) {
  copyDaemon.addEventListener("click", async () => {
    try {
      await copyText(daemonNode ? daemonNode.textContent : "");
    } catch (error) {
      showStatus(error.message, true);
    }
  });
}

if (composeForm) {
  composeForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy || !detailApp) return;
    if (!selectedAgentID) {
      showStatus("请先选择一台节点。", true);
      return;
    }
    if (!agentOnline) {
      showStatus("该节点离线，不能部署。", true);
      return;
    }
    if (!engineReady) {
      showStatus("引擎未就绪，不能部署。", true);
      return;
    }
    const updating = true;
    setBusy(true);
    showStatus("正在更新应用…", false);
    try {
      const saved = await deployComposePayload({
        id: detailApp.id,
        agent_id: selectedAgentID,
        compose: detailComposeInput ? detailComposeInput.value : "",
        env: detailEnvInput ? String(detailEnvInput.value || "") : "",
        auto_update: detailAutoUpdateInput ? detailAutoUpdateInput.checked : false,
      });
      if (!saved) return;
      composeFilledFor = "";
      showStatus("已更新应用。", false);
      try {
        await renderWorkspace();
      } catch (refreshError) {
        showStatus(`应用已更新，但列表刷新失败：${refreshError.message}`, true);
      }
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
    if (busy) return;
    if (!selectedAgentID) {
      showStatus("请先选择一台节点。", true);
      return;
    }
    if (!agentOnline) {
      showStatus("该节点离线，不能部署。", true);
      return;
    }
    if (!engineReady) {
      showStatus("引擎未就绪，不能部署。", true);
      return;
    }
    const data = new FormData(createForm);
    const nextApp = {
      id: String(data.get("id") || "").trim(),
      agent_id: selectedAgentID,
      compose: String(data.get("compose") || ""),
      env: String(data.get("env") || ""),
      auto_update: data.get("auto_update") === "on",
    };
    const updating = false;
    setBusy(true);
    showStatus(updating ? "正在更新应用…" : "正在部署应用…", false);
    try {
      const saved = await deployComposePayload(nextApp);
      if (!saved) return;
      closeCreate();
      showStatus(updating ? "已更新应用。" : "已部署应用。", false);
      try {
        await renderWorkspace();
      } catch (refreshError) {
        showStatus(`${updating ? "应用已更新" : "应用已部署"}，但列表刷新失败：${refreshError.message}`, true);
      }
    } catch (error) {
      showStatus(error.message, true);
    } finally {
      setBusy(false);
    }
  });
}

(async () => {
  try {
    await loadAgents();
    await renderWorkspace();
    loadingNode.hidden = true;
  } catch (error) {
    loadingNode.hidden = true;
    if (error.denied) deniedNode.hidden = false;
    else {
      unavailableNode.hidden = false;
      unavailableNode.textContent = error.message || unavailableNode.textContent;
    }
  }
})();
