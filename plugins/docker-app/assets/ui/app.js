const applyHostTheme = () => {
  const allowed = { light: true, dark: true };
  const aliases = { "sakura-day": "light", business: "light", "fresh-green": "light", sakura: "light", cyberpunk: "light", "sakura-night": "dark", "neko-dark": "dark", midnight: "dark" };
  let theme = "light";
  try {
    const embedded = window.parent && window.parent !== window;
    const raw = embedded
      ? window.parent.document.documentElement.getAttribute("data-theme")
      : (window.localStorage.getItem("theme") || document.documentElement.getAttribute("data-theme"));
    const mapped = aliases[raw] || raw;
    if (allowed[mapped]) theme = mapped;
  } catch (_error) {
    theme = "light";
  }
  if (document.documentElement.getAttribute("data-theme") !== theme) document.documentElement.setAttribute("data-theme", theme);
};
applyHostTheme();
try {
  const root = window.parent && window.parent !== window ? window.parent.document.documentElement : document.documentElement;
  new MutationObserver(applyHostTheme).observe(root, {attributes:true,attributeFilter:["data-theme"]});
} catch (_error) { /* Cross-origin parents use the safe initial fallback. */ }
window.addEventListener("storage", (event) => { if (event.key === "theme" || event.key === null) applyHostTheme(); });

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
const logsEmpty = document.querySelector("#logs-empty");
const logsContext = document.querySelector("#logs-context");
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

// All native dialogs reset their result and return focus to the caller.
const dialogClosures = new WeakMap();
const openDialog = (dialog, initialFocus) => {
  if (dialog.open) return false;
  let closed;
  dialogClosures.set(dialog, new Promise((resolve) => { closed = resolve; }));
  const trigger = document.activeElement;
  dialog.returnValue = "";
  dialog.tabIndex = -1;
  const cancel = () => { dialog.returnValue = "cancel"; };
  const keydown = (event) => {
    if (event.key !== "Tab") return;
    const nodes = Array.from(dialog.querySelectorAll('button,input,textarea,select,a[href],[tabindex]'))
      .filter((node) => !node.disabled && node.tabIndex >= 0 && node.getClientRects().length);
    const first = nodes[0], last = nodes[nodes.length - 1];
    if (!first) { event.preventDefault(); dialog.focus(); return; }
    if (event.shiftKey && (document.activeElement === first || !dialog.contains(document.activeElement))) {
      event.preventDefault(); last.focus();
    } else if (!event.shiftKey && (document.activeElement === last || !dialog.contains(document.activeElement))) {
      event.preventDefault(); first.focus();
    }
  };
  dialog.addEventListener("cancel", cancel);
  dialog.addEventListener("keydown", keydown);
  dialog.addEventListener("close", () => {
    dialog.removeEventListener("cancel", cancel);
    dialog.removeEventListener("keydown", keydown);
    if (trigger?.isConnected && !trigger.disabled) trigger.focus();
    else document.querySelector("#workspace-refresh")?.focus();
    dialogClosures.delete(dialog);
    closed();
  }, { once: true });
  dialog.showModal();
  initialFocus?.focus();
  return true;
};

const askConfirm = async ({ title, body, confirm = "确定", cancel = "取消", danger = false, hideConfirm = false } = {}) => {
  if (!confirmDialog || typeof confirmDialog.showModal !== "function") {
    const text = [title, body].filter(Boolean).join("\n");
    if (hideConfirm) {
      window.alert(text);
      return Promise.resolve(false);
    }
    return Promise.resolve(window.confirm(text));
  }
  if (confirmDialog.open) return Promise.resolve(false);
  if (dialogClosures.has(confirmDialog)) await dialogClosures.get(confirmDialog);
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
    const previous = statusNode?.textContent || "";
    const previousState = statusNode?.dataset.state;
    showStatus("等待确认操作。", false, "confirming");
    const onClose = () => {
      showStatus(previous, previousState === "failed", previousState);
      resolve(confirmDialog.returnValue === "ok");
    };
    confirmDialog.addEventListener("close", onClose, { once: true });
    openDialog(confirmDialog, confirmCancel);
  });
};

let busy = false;
let busyFocusTarget = null;
let selectedAgentID = "";
let agentsCache = [];
let engineReady = false;
let agentOnline = false;
let lastEngine = null;
let workspaceSeq = 0;
let contextVersion = 0;
let readVersion = 0;
let detailRequest = 0;
const contextSnapshot = () => ({ version: contextVersion, read: readVersion, agent: selectedAgentID });
const contextCurrent = (snapshot) => snapshot.version === contextVersion && snapshot.read === readVersion && snapshot.agent === selectedAgentID;
let view = "list";
let selectedAppID = "";
let detailSection = "overview";
let detailApp = null;
let navigationVersion = 0;
const advanceNavigation = () => { navigationVersion += 1; };
const navigationSnapshot = () => ({
  ...contextSnapshot(), navigation: navigationVersion, view,
  app: selectedAppID, section: detailSection, create: !createPanel.hidden,
});
const navigationCurrent = (snapshot) => contextCurrent(snapshot)
  && snapshot.navigation === navigationVersion && snapshot.view === view
  && snapshot.app === selectedAppID && snapshot.section === detailSection
  && snapshot.create === !createPanel.hidden;
let logsPaused = false;
let logsTimer = null;
let logsLoaded = false;
let logsSnapshotKey = "";
let logsSeq = 0;
let filesDirty = false;
let filesEditorOpen = false;
let filesMountedFor = "";
let composeFilledFor = "";
let composeDraftOwner = "";
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

const showStatus = (message, isError, state) => {
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
    delete statusNode.dataset.state;
    return;
  }
  const cancelled = !isError && /^已取消/.test(message);
  state ||= isError ? "failed" : cancelled ? "cancelled" : /^正在/.test(message) ? "running" : "succeeded";
  if (/已.*(但|，).*刷新失败/.test(message)) state = "partial";
  statusNode.dataset.state = state;
  statusNode.dataset.error = isError ? "true" : "false";
  statusNode.dataset.tone = state === "failed" ? "error" : state === "succeeded" ? "success" : "info";
  if (state === "cancelled") {
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

const confirmComposeRisk = async (preview, target) => {
  if (!requiresRiskConfirm(preview)) return true;
  const agent = agentsCache.find((agent) => agent.id === target.agent_id);
  const ok = await askConfirm({
    title: "确认高风险配置",
    body: `节点 ${agentDisplayName(agent) || target.agent_id} · 应用 ${target.id}\n${riskConfirmBody(preview)}`,
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
  if (!(await confirmComposeRisk(previewed.preview, payload))) return null;
  const next = { ...payload };
  if (previewed.preview && previewed.preview.digest) next.confirm = previewed.preview.digest;
  return sendPluginJSON("api/apps", next);
};

const setBusy = (next) => {
  if (next && !busy) {
    busyFocusTarget = document.activeElement;
    // A mutation owns the target from preview through confirmation and completion.
    // Reads started before it may not restore pages or replace draft/status state.
    readVersion += 1;
    workspaceSeq += 1;
    detailRequest += 1;
  }
  busy = next;
  if (next) showStatus("正在执行操作…", false, "running");
  const roots = [workspaceNode, contextNode, document.querySelector(".page-head")].filter(Boolean);
  roots.forEach((root) => {
    root.querySelectorAll("button, input, textarea, select").forEach((node) => {
      if (node === copyScript || node === copyDaemon) return;
      if (next) {
        if (!node.hasAttribute("data-before-busy")) node.dataset.beforeBusy = String(node.disabled);
        node.disabled = true;
      } else if (node.hasAttribute("data-before-busy")) {
        node.disabled = node.dataset.beforeBusy === "true";
        delete node.dataset.beforeBusy;
      }
    });
  });
  agentPicker.setDisabled(next);
  if (!next) syncSelectionActions();
  if (!next && !document.querySelector("dialog[open]")) {
    const target = busyFocusTarget;
    if (target?.isConnected && !target.disabled && target.getClientRects().length) target.focus();
    else document.querySelector("#workspace-refresh")?.focus();
    busyFocusTarget = null;
  }
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
    state: engine?.state || "detection-failed",
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
  node.textContent = state.state === "detection-failed" ? "检测失败" : state.ready ? "引擎就绪" : "引擎未就绪";
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
      triggerEngine.textContent = engine.state === "detection-failed" ? "检测失败" : engine.ready ? "引擎就绪" : "引擎未就绪";
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
      option.dataset.agentId = agent.id;
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
    if (picker.open) refreshEngineMarks();
  };

  // Probe completion must not replace an option between pointer down and click.
  const refreshEngineMarks = () => {
    list.querySelectorAll("[data-agent-id]").forEach((option) => {
      option.setAttribute("aria-selected", option.dataset.agentId === picker.selected ? "true" : "false");
      const engine = cachedEngine(option.dataset.agentId);
      if (!engine) return;
      const previous = option.querySelector(".agent-search-select__engine");
      if (previous) previous.replaceWith(engineMark(engine));
      else option.append(engineMark(engine));
    });
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
      if (picker.open) refreshEngineMarks();
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

// Draft baselines live only in this document, including optional .env values.
const makeDraft = (read, restore) => ({
  baseline: read(),
  revision: 0,
  touch() { this.revision += 1; },
  get dirty() { return JSON.stringify(read()) !== JSON.stringify(this.baseline); },
  capture(value = read()) { this.baseline = value; this.touch(); },
  discard() { this.touch(); restore(this.baseline); },
});
const readComposeForm = (form) => Object.fromEntries(Array.from(form.elements)
  .filter((field) => field.name).map((field) => [field.name, field.type === "checkbox" ? field.checked : field.value]));
const restoreComposeForm = (form, values) => {
  Object.entries(values).forEach(([name, value]) => {
    const field = form.elements.namedItem(name);
    if (field.type === "checkbox") field.checked = value;
    else { field.value = value; if (field.tagName === "TEXTAREA") paintCodeEditor(field); }
  });
  updateDraftIndicators();
};
const createDraft = makeDraft(() => readComposeForm(createForm), (value) => restoreComposeForm(createForm, value));
const composeDraft = makeDraft(() => readComposeForm(composeForm), (value) => restoreComposeForm(composeForm, value));
let fileDraft = null;
const activeDrafts = () => [
  { id: "create", label: "部署", draft: createDraft, active: !createPanel.hidden },
  { id: "compose", label: "Compose", draft: composeDraft, active: view === "detail" },
  { id: "file", label: "文件", draft: fileDraft, active: filesEditorOpen },
];
const updateDraftIndicators = () => {
  document.querySelector("#create-dirty").hidden = !createDraft.dirty;
  document.querySelector("#compose-dirty").hidden = !composeDraft.dirty;
};
const confirmDiscardDrafts = async (ids = ["create", "compose", "file"], { discard = true } = {}) => {
  const dirty = activeDrafts().filter((item) => ids.includes(item.id) && item.active && item.draft?.dirty);
  if (!dirty.length) return true;
  const ok = await askConfirm({
    title: "改动尚未保存",
    body: `${dirty.map((item) => item.label).join("、")}有未保存的输入。丢弃后继续，取消则保留输入和当前位置。`,
    confirm: "丢弃", cancel: "取消", danger: true,
  });
  if (!ok) return false;
  if (discard) dirty.forEach((item) => item.draft.discard());
  updateDraftIndicators();
  return true;
};
const confirmLeaveEditor = () => confirmDiscardDrafts();
[createForm, composeForm].forEach((form) => {
  const changed = () => {
    (form === createForm ? createDraft : composeDraft).touch();
    updateDraftIndicators();
  };
  form.addEventListener("input", changed);
  form.addEventListener("change", changed);
});
window.addEventListener("beforeunload", (event) => {
  if (!activeDrafts().some((item) => item.active && item.draft?.dirty)) return;
  event.preventDefault();
  event.returnValue = "";
});

const markCreateTemplate = (name) => {
  const root = createTemplates || createPanel;
  if (!root) return;
  root.querySelectorAll("[data-template]").forEach((button) => {
    button.setAttribute("aria-pressed", button.dataset.template === name ? "true" : "false");
  });
};

const applyCreateTemplate = async (name) => {
  const template = COMPOSE_TEMPLATES[name];
  if (!template || !composeInput || busy) return;
  if (composeInput.value !== createDraft.baseline.compose && !(await confirmDiscardDrafts(["create"], { discard: false }))) return;
  composeInput.value = template.compose || "";
  createDraft.touch();
  paintCodeEditor(composeInput);
  markCreateTemplate(name);
  updateDraftIndicators();
  composeInput.focus();
};

const openCreate = async () => {
  if (!engineReady || !agentOnline) return;
  if (view === "detail" && !(await leaveDetail())) return;
  advanceNavigation();
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
  createDraft.capture();
  updateDraftIndicators();
  document.querySelector("#create-context").textContent = `目标节点：${agentDisplayName(selectedAgent())}`;
  showFormFeedback(createForm, "");
  createPanel.hidden = false;
  syncListPanel();
  if (idInput) idInput.focus();
};

const closeCreate = () => {
  if (createPanel && !createPanel.hidden) advanceNavigation();
  if (createForm) createForm.reset();
  createDraft.capture();
  updateDraftIndicators();
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
  const payload = await sendPluginJSON(`api/apps/${encodeURIComponent(app.id)}/${action}`, body);
  closeCreate();
  if (action === "delete" && selectedAppID === app.id) await leaveDetail({ force: true });
  try {
    if (await renderWorkspace() === false) throw new Error("节点或详情未能刷新");
    return { payload };
  } catch (error) {
    return { payload, refreshError: error.message };
  }
};
const reportActionResult = (result, message) => {
  if (!result) return;
  if (result.refreshError) showStatus(`${message}但页面刷新失败：${result.refreshError}`, true, "partial");
  else showStatus(message, false);
};
const postAppActionWithRisk = async (app, action, body = {}) => {
  let next = { ...body };
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      return await postAppAction(app, action, next);
    } catch (error) {
      if (action !== "update" || !requiresRiskConfirm(error.preview)) throw error;
      const digest = error.preview?.digest;
      if (!digest || digest === next.confirm) throw new Error("风险确认已失效，请重新打开版本操作。");
      if (attempt === 2) throw new Error("风险摘要持续变化，请刷新应用后重新确认。");
      if (!(await confirmComposeRisk(error.preview, app))) return null;
      next = { ...body, confirm: digest };
    }
  }
  throw new Error("风险摘要持续变化，请刷新应用后重新确认。");
};
const saveServicePolicy = (app, service) => runAppAction(app, { id: "service-policy", label: "管理版本策略", service });

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
      unbind() {},
      confirmLeave: () => true,
      discard() {},
    };
  }
  if (!filesPanel.querySelector(".app-files")) {
    filesPanel.replaceChildren(template.content.cloneNode(true));
  }
  const section = filesPanel.querySelector(".app-files") || filesPanel;
  const filesStatus = section.querySelector("#files-status");
  const setFilesStatus = (message, state = "ready") => {
    if (!filesStatus) return;
    filesStatus.textContent = message; filesStatus.hidden = !message; filesStatus.dataset.state = state;
    filesStatus.setAttribute("role", state === "failed" ? "alert" : "status");
  };
  const fileError = (message) => { setFilesStatus(message, "failed"); showStatus(message, true); };
  const dialogError = (dialog, message) => {
    const feedback = dialog?.querySelector("[data-dialog-feedback]");
    if (feedback) { feedback.hidden = false; feedback.textContent = message; feedback.dataset.state = "failed"; }
  };
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
  let fileReadSequence = 0;
  let fileListSequence = 0;
  let boundOwner = "";
  let bindingVersion = 0;
  let listingSnapshot = null;
  let selectedOwner = "";
  let selectedBinding = 0;
  const namedTargets = new WeakMap();
  const ownerKey = (value) => value ? `${value.agent_id}/${value.id}` : "";
  const bindingCurrent = (owner = boundOwner, version = bindingVersion) => !!owner
    && owner === boundOwner && owner === ownerKey(app) && version === bindingVersion
    && app.agent_id === selectedAgentID && app.id === selectedAppID && view === "detail" && detailSection === "files";
  const selectionCurrent = () => bindingCurrent(selectedOwner, selectedBinding);
  const snapshotCurrent = (snapshot) => snapshot && snapshot === listingSnapshot && bindingCurrent(snapshot.owner, snapshot.binding);

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
    const hasFile = selectionCurrent() && Boolean(selectedPath) && !selectedDir;
    const hasTarget = selectionCurrent() && Boolean(selectedPath) && selectedPath !== ".";
    if (editBtn) editBtn.disabled = busy || !hasFile;
    if (downloadBtn) downloadBtn.disabled = busy || !hasFile;
    if (deleteBtn) deleteBtn.disabled = busy || !hasTarget;
    if (selectedLabel) {
      selectedLabel.textContent = hasTarget
        ? `已选择 ${selectedName || selectedPath}`
        : "请选择一个文件或目录后再编辑、下载或删除。";
    }
  };

  const hideEditor = () => {
    fileDraft?.touch();
    filesEditorOpen = false;
    setDirty(false);
    if (editor) editor.hidden = true;
    if (editorInput) editorInput.value = "";
    if (binaryHint) binaryHint.hidden = true;
    if (browser) browser.hidden = false;
    if (editorName) editorName.textContent = "";
    syncSelectionActions();
  };


  fileDraft = makeDraft(() => editorInput?.value || "", (value) => {
    if (editorInput) editorInput.value = value || "";
    hideEditor();
  });
  const confirmLeave = async () => {
    if (!(await confirmDiscardDrafts(["file"]))) return false;
    if (filesEditorOpen) hideEditor();
    return true;
  };

  const selectEntry = (path, name, isDir, owner = boundOwner, binding = bindingVersion) => {
    if (path && (busy || !bindingCurrent(owner, binding))) return;
    selectedPath = path;
    selectedName = name;
    selectedDir = isDir;
    selectedOwner = path ? owner : "";
    selectedBinding = binding;
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
    fileDraft.capture(content);
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
    const snapshot = listingSnapshot;
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
      button.addEventListener("click", () => { if (snapshotCurrent(snapshot)) requestList(path); });
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
    if (!bindingCurrent() || !selectionCurrent()) return;
    const owner = boundOwner;
    const binding = bindingVersion;
    if (filesEditorOpen && filesDirty && selectedPath === path) return;
    if (!(await confirmLeave())) return;
    if (!bindingCurrent(owner, binding)) return;
    const relative = relativeWorkspacePath(path);
    if (!relative) {
      fileError(workspacePathError);
      return;
    }
    const target = app;
    const navigation = navigationSnapshot();
    const revision = fileDraft.revision;
    const request = ++fileReadSequence;
    const current = () => bindingCurrent(owner, binding) && navigationCurrent(navigation) && app?.id === target.id
      && revision === fileDraft.revision && request === fileReadSequence;
    setFilesStatus(`正在读取文件 ${relative}…`, "loading");
    try {
      const payload = await postAppFiles(target, { action: "read", path: relative });
      if (!current()) return;
      const content = typeof payload.content === "string" ? payload.content : "";
      if (new TextEncoder().encode(content).length > MAX_WORKSPACE_FILE_BYTES) {
        fileError("文件超过 1MiB 上限");
        return;
      }
      if (!looksLikeText(content)) {
        fileError("该文件不适合文本编辑，请下载或重新上传。");
        if (binaryHint) binaryHint.hidden = false;
        return;
      }
      showEditor(relative, name || relative.split("/").pop(), content);
      setFilesStatus(`已打开 ${relative}`);
      showStatus("已打开工作区文件。", false);
    } catch (error) {
      if (!current()) return;
      fileError(`读取文件失败：${error.message}`);
    }
  };

  const openNewFile = async (path, name, target) => {
    if (!target || !bindingCurrent(target.owner, target.binding)) return false;
    if (!(await confirmLeave())) return;
    if (!bindingCurrent(target.owner, target.binding)) return false;
    showEditor(path, name, "");
    return true;
  };

  const loadList = async (path) => {
    if (!bindingCurrent()) return;
    const relative = relativeWorkspacePath(path);
    if (!relative) {
      fileError(workspacePathError);
      return;
    }
    const target = app;
    const owner = boundOwner;
    const binding = bindingVersion;
    const context = contextSnapshot();
    const request = ++fileListSequence;
    setFilesStatus(`正在读取目录 ${relative}…`, "loading");
    const current = () => bindingCurrent(owner, binding) && contextCurrent(context) && selectedAppID === target.id
      && view === "detail" && request === fileListSequence;
    try {
      const payload = await postAppFiles(target, { action: "list", path: relative });
      if (!current()) return;
      currentPath = relativeWorkspacePath(payload.path) || relative;
      listingSnapshot = {owner, binding, path:currentPath};
      const snapshot = listingSnapshot;
      const entries = Array.isArray(payload.entries) ? payload.entries : [];
      if (!filesEditorOpen) {
        const visible = entries.some((entry) => relativeWorkspacePath(entry.path || entry.name) === selectedPath);
        if (!visible) selectEntry("", "", false);
        else paintSelection();
      }
      renderBreadcrumb();
      if (listEl) { listEl.replaceChildren(); listEl.dataset.stale = "false"; }
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
        open.title = entryPath;
        open.textContent = entry.dir ? `${entry.name || entryPath}/` : (entry.name || entryPath);
        open.addEventListener("click", (event) => {
          event.stopPropagation();
          if (!snapshotCurrent(snapshot)) return;
          if (entry.dir) requestList(entryPath);
          else selectEntry(entryPath, entry.name || entryPath, false, snapshot.owner, snapshot.binding);
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
          if (snapshotCurrent(snapshot)) selectEntry(entryPath, entry.name || entryPath, Boolean(entry.dir), snapshot.owner, snapshot.binding);
        });
        if (listEl) listEl.append(item);
      });
      if (emptyEl) emptyEl.hidden = listed !== 0;
      setFilesStatus(listed ? `目录已读取 · ${listed} 项` : "此目录为空", listed ? "ready" : "empty");
      return true;
    } catch (error) {
      if (!current()) return;
      const retained = snapshotCurrent(listingSnapshot);
      if (listEl) {
        if (!retained) listEl.replaceChildren();
        listEl.dataset.stale = String(!!retained);
      }
      if (emptyEl) emptyEl.hidden = true;
      fileError(`目录 ${relative} 读取失败。${retained ? `显示该应用上次读取的 ${currentPath}。` : "未获得该应用的目录快照。"}${error.message}`);
      return false;
    }
  };

  const requestList = async (path) => {
    const owner = boundOwner;
    const binding = bindingVersion;
    if (!bindingCurrent(owner, binding)) return;
    if (!(await confirmLeave())) return;
    if (!bindingCurrent(owner, binding)) return;
    fileReadSequence += 1;
    loadList(path);
  };

  const removePath = async (path, name) => {
    if (busy || !bindingCurrent() || !selectionCurrent()) return;
    const relative = relativeWorkspacePath(path);
    if (!relative || relative === ".") { fileError(relative === "." ? "不能删除应用工作区根目录" : workspacePathError); return; }
    const target = app;
    setBusy(true);
    try {
      if (!(await askConfirm({
        title: "删除工作区文件",
        body: `节点 ${agentDisplayName(selectedAgent())} · 应用 ${target.id}\n确认删除 ${name || relative}？路径：${relative}。取消不会更改工作区。`,
        confirm: "删除", cancel: "取消", danger: true,
      }))) { showStatus("已取消，工作区未更改。", false); return; }
      await postAppFiles(target, {action:"delete",path:relative});
      if (selectedPath === relative) hideEditor();
      showStatus("已删除工作区文件。", false);
      if (await loadList(currentPath) === false) showStatus("文件已删除，但目录刷新失败。", true, "partial");
    } catch (error) { fileError(error.message); }
    finally { setBusy(false); }
  };

  const openNamedDialog = (dialog, input) => {
    if (!bindingCurrent() || !dialog || typeof dialog.showModal !== "function") return;
    fileReadSequence += 1;
    fileListSequence += 1;
    namedTargets.set(dialog, {app,owner:boundOwner,binding:bindingVersion,path:currentPath});
    if (input) input.value = "";
    const feedback = dialog.querySelector("[data-dialog-feedback]");
    if (feedback) { feedback.hidden = true; feedback.textContent = ""; }
    const copy = dialog.querySelector(".files-dialog-copy");
    if (copy) copy.textContent = `应用 ${app.id} · 当前目录 ${currentPath}。使用工作区内的相对名称。`;
    openDialog(dialog, input);
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
      const target = namedTargets.get(mkdirDialog);
      if (!target || !bindingCurrent(target.owner, target.binding)) return;
      const name = mkdirName ? mkdirName.value.trim() : "";
      if (!name) {
        if (mkdirName) mkdirName.focus();
        return;
      }
      const next = joinWorkspacePath(target.path, name);
      if (!next) {
        dialogError(mkdirDialog, workspacePathError);
        return;
      }
      setBusy(true);
      try {
        await postAppFiles(target.app, { action: "mkdir", path: next });
        if (mkdirName) mkdirName.value = "";
        closeNamedDialog(mkdirDialog);
        showStatus("已新建目录。", false);
        if (await loadList(target.path) === false) showStatus(`目录 ${next} 已创建，但目录刷新失败。无需重复创建。`, true, "partial");
      } catch (error) {
        dialogError(mkdirDialog, error.message);
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
    newForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (busy || !app) return;
      const target = namedTargets.get(newDialog);
      if (!target || !bindingCurrent(target.owner, target.binding)) return;
      const name = newName ? newName.value.trim() : "";
      if (!name) {
        showStatus("请填写要新建的文本文件名。", true);
        if (newName) newName.focus();
        return;
      }
      const next = joinWorkspacePath(target.path, name);
      if (!next) {
        dialogError(newDialog, workspacePathError);
        return;
      }
      if (newName) newName.value = "";
      closeNamedDialog(newDialog);
      if (!(await openNewFile(next, name, target))) return;
      fileDraft.capture(null);
      setDirty(true);
    });
  }
  if (editBtn) {
    editBtn.addEventListener("click", () => {
      if (busy || !selectionCurrent()) return;
      if (!selectedPath || selectedDir) {
        showStatus("请先选择一个文件再编辑。", true);
        return;
      }
      openFile(selectedPath, selectedName);
    });
  }
  if (uploadBtn && uploadInput) {
    let uploadContext = null;
    uploadBtn.addEventListener("click", () => {
      if (busy || !bindingCurrent()) return;
      fileReadSequence += 1;
      fileListSequence += 1;
      uploadContext = {navigation:navigationSnapshot(),app,path:currentPath,owner:boundOwner,binding:bindingVersion};
      uploadInput.click();
    });
    uploadInput.addEventListener("change", async () => {
      const file = uploadInput.files && uploadInput.files[0];
      uploadInput.value = "";
      const context = uploadContext;
      uploadContext = null;
      if (!file || busy || !context || !bindingCurrent(context.owner, context.binding) || context.path !== currentPath || !navigationCurrent(context.navigation)) return;
      const next = joinWorkspacePath(context.path, file.name);
      if (!next) { fileError(workspacePathError); return; }
      if (file.size > MAX_WORKSPACE_FILE_BYTES) { fileError("文件超过 1MiB 上限"); return; }
      setBusy(true);
      try {
        let content;
        try { content = new TextDecoder("utf-8", {fatal:true}).decode(await file.arrayBuffer()); }
        catch { throw new Error("上传仅支持 UTF-8 文本文件。"); }
        if (!looksLikeText(content)) throw new Error("上传仅支持 UTF-8 文本文件。");
        await postAppFiles(context.app, {action:"write",path:next,content});
        showStatus("已上传工作区文件。", false);
        if (await loadList(context.path) === false) showStatus("文件已上传，但目录刷新失败。", true, "partial");
      } catch (error) { fileError(error.message); }
      finally { setBusy(false); }
    });
  }
  if (downloadBtn) {
    downloadBtn.addEventListener("click", async () => {
      if (busy || !selectionCurrent()) return;
      if (!selectedPath || selectedDir) {
        showStatus("请先选择一个文件再下载。", true);
        return;
      }
      const target = app;
      const filename = selectedName || selectedPath.split("/").pop();
      const context = contextSnapshot();
      const owner = boundOwner;
      const binding = bindingVersion;
      try {
        const file = await postAppFiles(target, { action: "read", path: selectedPath });
        if (!bindingCurrent(owner, binding) || !contextCurrent(context)) return;
        downloadTextFile(filename, file.content || "");
        showStatus("已开始下载。", false);
      } catch (error) {
        showStatus(error.message, true);
      }
    });
  }
  if (deleteBtn) {
    deleteBtn.addEventListener("click", () => {
      if (busy || !selectionCurrent()) return;
      if (!selectedPath || selectedPath === ".") {
        showStatus("请先选择要删除的文件或目录。", true);
        return;
      }
      removePath(selectedPath, selectedName);
    });
  }
  if (saveBtn) {
    saveBtn.addEventListener("click", async () => {
      if (busy || !selectionCurrent() || !selectedPath || selectedDir) return;
      const target = app;
      const path = selectedPath;
      const content = editorInput ? editorInput.value : "";
      if (new TextEncoder().encode(content).length > MAX_WORKSPACE_FILE_BYTES) {
        fileError("文件超过 1MiB 上限");
        return;
      }
      setBusy(true);
      try {
        await postAppFiles(target, { action: "write", path, content });
        fileDraft.capture(content);
        setDirty(false);
        showStatus("已保存工作区文件。", false);
        if (await loadList(currentPath) === false) showStatus("文件已保存，但目录刷新失败。请稍后刷新，无需重复保存。", true, "partial");
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
  section.querySelector("#files-refresh")?.addEventListener("click", () => { if (!busy) requestList(currentPath); });
  syncSelectionActions();
  if (editorInput) {
    editorInput.addEventListener("input", () => {
      fileDraft.touch();
      setDirty(fileDraft.dirty);
      paintCodeEditor(editorInput);
    });
  }

  const unbind = () => {
    bindingVersion += 1;
    fileReadSequence += 1;
    fileListSequence += 1;
    app = null;
    boundOwner = "";
    filesMountedFor = "";
    listingSnapshot = null;
    currentPath = ".";
    selectedPath = "";
    selectedName = "";
    selectedDir = false;
    selectedOwner = "";
    hideEditor();
    fileDraft.capture("");
    if (listEl) { listEl.replaceChildren(); delete listEl.dataset.stale; }
    if (breadcrumb) breadcrumb.replaceChildren();
    if (emptyEl) emptyEl.hidden = true;
    setFilesStatus("");
    closeNamedDialog(mkdirDialog);
    closeNamedDialog(newDialog);
    namedTargets.delete(mkdirDialog);
    namedTargets.delete(newDialog);
  };
  return {
    bind(nextApp) {
      const owner = ownerKey(nextApp);
      if (!owner || owner !== boundOwner) {
        unbind();
        app = nextApp;
        boundOwner = owner;
        filesMountedFor = owner;
        if (owner) { renderBreadcrumb(); loadList("."); }
      } else {
        app = nextApp;
        syncSelectionActions();
        if (!listingSnapshot && !filesEditorOpen) loadList(currentPath);
      }
    },
    unbind,
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
  const trigger = document.activeElement;
  if (action.id === "configure") { await showDetail(app.id, "compose"); return; }
  if (action.id === "logs") { await showDetail(app.id, "logs"); return; }
  const policy = action.id === "service-policy";
  if (!policy && !(app.actions || []).some((item) => item.id === action.id)) return;
  if (policy && !serviceImages(app).some((service) => service.name === action.service)) return;
  if (["update", "rollback", "delete"].includes(action.id) && !(await confirmLeaveEditor())) return;
  const target = `节点 ${agentDisplayName(selectedAgent())} · 应用 ${app.id}`;
  setBusy(true);
  busyFocusTarget = trigger;
  try {
    if (action.id === "delete") {
      const rules = Array.isArray(app.rules) ? app.rules : [];
      const entries = rules.length ? `\n当前显示的入口：${rules.map((rule) => rule.domain || rule.ref).join("、")}` : "";
      if (!(await askConfirm({
        title: "删除应用",
        body: `${target}\n先删除宿主上的关联 HTTP 规则，再停止容器并删除应用工作区。规则清理失败会中止应用删除；规则删除后若应用删除失败，已删除的入口不会恢复。${entries}`,
        confirm: "删除", cancel: "取消", danger: true,
      }))) { showStatus("已取消，应用未更改。", false); return; }
      reportActionResult(await postAppAction(app, "delete", { confirm: app.id }), `${target}：已删除应用。`);
      return;
    }
    if (action.id === "rollback") {
      if (!(await askConfirm({
        title: "回滚应用",
        body: `${target}\n当前镜像：${appVersion(app)}\n目标：服务端记录的上一部署版本。将重新创建应用服务，期间可能短暂不可用。取消不会更改应用。`,
        confirm: "回滚", cancel: "取消", danger: true,
      }))) { showStatus("已取消，应用未更改。", false); return; }
    }
    if (action.id === "update" || policy) {
      const payload = await askServiceUpdate(app, { service: action.service, policyOnly: policy });
      if (!payload) { showStatus("已取消，应用未更改。", false); return; }
      const result = await postAppActionWithRisk(app, "update", payload);
      reportActionResult(result, `${target}：${payload.services?.length ? "已更新所选服务。" : "已保存版本策略。"}`);
      return;
    }
    const messages = { start: "已启动应用。", stop: "已停止应用。", restart: "已重启应用。", rollback: "已回滚应用。" };
    reportActionResult(await postAppAction(app, action.id), `${target}：${messages[action.id] || "已执行操作。"}`);
  } catch (error) {
    // This is the plugin's existing public, server-authoritative deletion stage.
    const partial = error.message.startsWith("入口规则已按宿主结果删除") || error.message.startsWith("Docker 操作已完成，但应用状态保存失败");
    showStatus(`${target}：${error.message}`, true, partial ? "partial" : "failed");
  } finally {
    setBusy(false);
  }
};

const serviceImages = (app) => (Array.isArray(app.service_images) ? app.service_images.filter((item) => item && item.name) : []);

const askServiceUpdate = async (app, options = {}) => {
  const services = serviceImages(app).filter((service) => !options.service || service.name === options.service);
  if (!updateDialog || typeof updateDialog.showModal !== "function") {
    const selected = services.filter((item) => item.update && item.default_tag).map((item) => ({ name: item.name, tag: item.default_tag }));
    if (!selected.length) return Promise.resolve(null);
    const lines = selected.map((item) => `${item.name} → ${item.tag}`).join("\n");
    return Promise.resolve(window.confirm(`确认更新 ${app.id}？\n${lines}\n取消不会改 compose。`) ? { services: selected } : null);
  }
  if (updateDialog.open) return Promise.resolve(null);
  if (dialogClosures.has(updateDialog)) await dialogClosures.get(updateDialog);
  const digestRefresh = services.some((item) => Array.isArray(item.candidates) && item.candidates.some((candidate) => candidate.digest));
  if (updateCopy) {
    updateCopy.textContent = `节点 ${agentDisplayName(selectedAgent())} · 应用 ${app.id}。${digestRefresh ? "有新的镜像 digest。" : ""}仅更新勾选的服务；锁定和忽略在确认后保存。取消不会改 Compose、版本策略或运行镜像。`;
  }
  if (updateServices) {
    updateServices.replaceChildren();
    services.forEach((service) => {
      updateServices.append(renderUpdateServiceRow(service, options));
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
    openDialog(updateDialog, updateDialog.querySelector('button[value="cancel"]'));
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

const renderUpdateServiceRow = (service, options = {}) => {
  const row = document.createElement("section");
  row.className = "update-service";
  row.dataset.service = service.name;
  row.dataset.lock = service.lock || "";
  const candidates = Array.isArray(service.candidates) ? service.candidates : [];
  const defaultTag = service.default_tag || (candidates[0] && candidates[0].tag) || "";
  const checked = !options.policyOnly && service.update === true && !!defaultTag;
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
  current.textContent = `当前：${service.image || service.tag || "未知版本"}`;
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
  selectBox.addEventListener("change", () => { if (selectBox.checked) ignoreBox.checked = false; });
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
  const apiActions = Array.isArray(app.actions) ? app.actions : [];
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
  if (app.rules_error) return "";
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
    const shown = serviceImages(app).length > 1
      ? serviceImages(app).map((service) => `${service.name}: ${service.image || service.current || version}`).join(" · ")
      : version;
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
    urlNode.hidden = !openURL && !app.rules_error;
    urlNode.textContent = app.rules_error ? "入口读取失败" : openURL ? displayHost(openURL) : "";
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
  const openDetail = () => { if (!busy) showDetail(app.id, "overview"); };
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

const fillCompose = (app, revision = composeDraft.revision) => {
  const owner = `${app.agent_id}/${app.id}`;
  // A refresh may start while clean and finish after typing. Neither a delayed
  // collection nor a same-app detail response may turn those edits into a baseline.
  if (composeDraftOwner === owner && (composeDraft.dirty || composeDraft.revision !== revision)) {
    showFormFeedback(composeForm, "已刷新应用状态，保留当前未提交的编辑。", "info");
    return;
  }
  if (detailComposeInput) {
    detailComposeInput.value = app.compose || "";
    paintCodeEditor(detailComposeInput);
  }
  if (detailEnvInput) {
    detailEnvInput.value = app.env || "";
    paintCodeEditor(detailEnvInput);
  }
  if (detailAutoUpdateInput) detailAutoUpdateInput.checked = app.auto_update === true;
  composeFilledFor = app.id;
  composeDraftOwner = owner;
  composeDraft.capture();
  updateDraftIndicators();
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
    [app.rules_error ? "未知" : String(rules.length), "入口"],
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
      const currentPolicy = document.createElement("p");
      currentPolicy.className = "service-policy-summary";
      currentPolicy.textContent = `锁定：${service.lock || "未锁定"} · 忽略：${persistedIgnoredTags(service).join("、") || "无"}`;
      const candidates = document.createElement("p");
      candidates.className = "service-candidates";
      candidates.textContent = `候选：${(service.candidates || []).map((candidate) => candidate.tag).join("、") || "无允许的候选"}`;
      const manage = actionButton({ id: "service-policy" }, "btn-secondary", "管理版本策略");
      manage.dataset.service = service.name;
      manage.addEventListener("click", () => saveServicePolicy(app, service.name));
      tools.append(currentPolicy, candidates, manage);
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
  if (app.rules_error) addRow(net, "读取状态", app.rules_error);
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
  } else if (!app.rules_error) {
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
  if (!(app.actions || []).some((action) => action.id === "rollback")) {
    const history = document.createElement("p");
    history.className = "hint rollback-unavailable";
    history.textContent = "当前没有可用的回滚操作；有上一部署记录且节点可执行时才能回滚。";
    overviewPanel.append(history);
  }
  overviewPanel.append(sheet);
  actionGroups(app, { overview: true }).forEach((group) => {
    if (group.classList.contains("app-actions-danger")) {
      const copy = document.createElement("p");
      copy.className = "overview-danger-copy";
      copy.textContent = "删除会先处理关联 HTTP 入口，再停止容器并清掉应用工作区。";
      group.prepend(copy);
    }
    overviewPanel.append(group);
  });
};

const runHTTPAction = async (app, action, body, form) => {
  if (busy || selectedAgentID !== app.agent_id) return;
  const deleting = action === "http-rule-delete";
  const trigger = document.activeElement;
  setBusy(true);
  busyFocusTarget = trigger;
  try {
    const target = deleting ? body.domain : `${body.domain} → 发布端口 ${body.port}`;
    if (!(await askConfirm({
      title: deleting ? "删除入口" : "添加入口",
      body: `节点 ${agentDisplayName(selectedAgent())} · 应用 ${app.id}\n${target}\n${deleting ? "删除后此入口停止提供访问。" : "确认将此域名绑定到所选发布端口。"}取消不会更改规则。`,
      confirm: deleting ? "删除" : "创建", cancel: "取消", danger: deleting,
    }))) { showStatus("已取消，规则未更改。", false); return; }
    const payload = deleting ? {rule_ref:body.rule_ref} : {domain:body.domain,port:body.port};
    await sendPluginJSON(`api/apps/${encodeURIComponent(app.id)}/${action}`, payload);
    form?.reset();
    const message = deleting ? "已删除 HTTP 规则。" : "已创建 HTTP 规则。";
    showStatus(message, false);
    try {
      if (await renderWorkspace() === false) throw new Error("入口或应用信息未能刷新");
      showStatus(message, false);
    } catch (error) { showStatus(`${message}但页面刷新失败：${error.message}`, true, "partial"); }
  } catch (error) {
    const feedback = httpPanel.querySelector("#http-feedback");
    if (feedback) { feedback.hidden = false; feedback.textContent = error.message; }
    showStatus(error.message, true);
  } finally { setBusy(false); }
};

const renderHTTP = (app) => {
  if (!httpPanel) return;
  const owner = `${app.agent_id}/${app.id}`;
  const draft = httpPanel.dataset.owner === owner ? {
    domain:httpPanel.querySelector('input[name="domain"]')?.value || "",
    port:httpPanel.querySelector('select[name="port"]')?.value || "",
  } : null;
  httpPanel.replaceChildren();
  httpPanel.dataset.owner = owner;
  const ports = appPorts(app);
  const rules = Array.isArray(app.rules) ? app.rules : [];
  const feedback = document.createElement("p");
  feedback.id = "http-feedback";
  feedback.className = "resource-error";
  feedback.setAttribute("role", "alert");
  feedback.textContent = app.rules_error || "";
  feedback.hidden = !app.rules_error;
  httpPanel.append(feedback);
  const retry = actionButton({id:"refresh-http"}, "btn-secondary", "刷新入口");
  retry.addEventListener("click", () => { if (!busy) showDetail(app.id, "http"); });
  httpPanel.append(retry);
  if (rules.length) {
    const ruleList = document.createElement("ul");
    ruleList.className = "http-rules";
    rules.forEach((rule) => {
      const item = document.createElement("li");
      item.dataset.ruleRef = rule.ref || "";
      const domain = String(rule.domain || "").trim();
      const openURL = publicURLFromRule(rule);
      const main = document.createElement("div");
      main.className = "http-rule-main";
      const label = document.createElement("strong");
      label.textContent = domain || "未命名入口";
      main.append(label, chip(rule.enabled === false ? "已停用" : "已启用"));
      const backendPort = backendPortFromRule(rule);
      if (backendPort) main.append(chip(`发布端口 ${backendPort}`));
      const target = document.createElement("p");
      target.className = "http-rule-target";
      target.textContent = openURL ? `访问目标：${openURL}` : "已停用，不提供访问链接";
      main.append(target);
      if (openURL) {
        const link = document.createElement("a");
        link.className = "http-rule-open";
        link.href = openURL;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.textContent = "访问";
        main.append(link);
      }
      item.append(main);
      if (rule.ref) {
        const deleteRule = actionButton({id:"delete-http"}, "btn-link danger", "删除");
        deleteRule.addEventListener("click", () => runHTTPAction(app, "http-rule-delete", {rule_ref:rule.ref,domain:domain || rule.ref}));
        item.append(deleteRule);
      }
      ruleList.append(item);
    });
    httpPanel.append(ruleList);
  } else if (!app.rules_error) {
    const empty = document.createElement("p");
    empty.className = "http-empty";
    empty.textContent = "还没有 HTTP 入口。";
    httpPanel.append(empty);
  }
  if (ports.length) {
    const form = document.createElement("form");
    form.className = "http-form";
    const title = document.createElement("p");
    title.className = "http-form-title";
    title.textContent = "添加入口";
    const portLabel = document.createElement("label");
    portLabel.append("发布端口");
    const portSelect = document.createElement("select");
    portSelect.name = "port";
    ports.forEach((port) => {
      const option = document.createElement("option");
      option.value = String(port); option.textContent = String(port);
      portSelect.append(option);
    });
    if (draft && ports.some((port) => String(port) === draft.port)) portSelect.value = draft.port;
    portLabel.append(portSelect);
    const domainLabel = document.createElement("label");
    domainLabel.append("入口域名");
    const domain = document.createElement("input");
    domain.name = "domain"; domain.required = true; domain.autocomplete = "off"; domain.spellcheck = false;
    domain.placeholder = "app.example.com";
    domain.value = draft?.domain || "";
    domainLabel.append(domain);
    const submit = document.createElement("button");
    submit.type = "submit"; submit.className = "btn-primary"; submit.textContent = "添加入口";
    form.append(title,portLabel,domainLabel,submit);
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      if (!domain.value.trim()) { domain.focus(); return; }
      runHTTPAction(app, "http-rule", {domain:domain.value.trim(),port:Number(portSelect.value)}, form);
    });
    httpPanel.append(form);
  } else {
    const hint = document.createElement("p");
    hint.className = "hint http-no-ports";
    hint.textContent = "没有发布端口，暂不能添加入口。";
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
  logsSeq += 1;
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
  logsLoaded = false;
  logsSnapshotKey = "";
  if (logsView) { logsView.textContent = ""; logsView.dataset.error = "false"; }
  if (logsEmpty) logsEmpty.hidden = true;
  setLogsState("", false);
};
const logsContextCurrent = () => detailApp && view === "detail" && detailSection === "logs";
const fetchLogs = async () => {
  if (!logsContextCurrent() || document.visibilityState === "hidden") return;
  const service = logsService ? logsService.value : "";
  if (!service) {
    resetLogsTerminal();
    setLogsState("没有可查看的服务", false);
    stopLogPolling();
    return;
  }
  const appID = detailApp.id;
  const key = `${selectedAgentID}/${appID}/${service}`;
  if (logsSnapshotKey !== key) { resetLogsTerminal(); logsSnapshotKey = key; }
  logsContext.textContent = `节点 ${agentDisplayName(selectedAgent())} · 应用 ${appID} · 服务 ${service} · 每 4 秒读取快照`;
  const seq = ++logsSeq;
  const context = contextSnapshot();
  const current = () => seq === logsSeq && contextCurrent(context) && logsContextCurrent() && detailApp.id === appID && logsService.value === service;
  setLogsState(logsLoaded ? "正在刷新，显示上次快照" : "正在读取日志快照…", false);
  try {
    const payload = await sendPluginJSON(`api/apps/${encodeURIComponent(appID)}/logs`, { service });
    if (!current()) return;
    logsView.textContent = payload.logs || "";
    logsView.dataset.error = "false";
    paintLogsView();
    logsLoaded = true;
    logsEmpty.hidden = !!payload.logs;
    setLogsState(`${logsPaused ? "已暂停自动刷新" : "自动刷新"} · 最近读取 ${new Date().toLocaleTimeString()}`, false);
  } catch (error) {
    if (!current()) return;
    logsView.dataset.error = "true";
    setLogsState(logsLoaded ? "自动刷新失败，已保留上次快照" : "日志读取失败，请重试", true);
    if (!logsLoaded) showStatus(error.message, true);
  }
};
const startLogPolling = () => {
  stopLogPolling();
  if (view !== "detail" || detailSection !== "logs" || logsPaused || document.visibilityState === "hidden") return;
  fetchLogs();
  if (!(logsService && logsService.value)) return;
  logsTimer = setInterval(fetchLogs, LOG_REFRESH_MS);
};

const paintDetail = (app, composeRevision) => {
  const appChanged = !detailApp || detailApp.id !== app.id;
  if (appChanged || detailApp?.agent_id !== app.agent_id) filesWorkspace.unbind();
  detailApp = app;
  selectedAppID = app.id;
  if (detailTitle) detailTitle.textContent = app.name || app.id;
  document.querySelector("#detail-context").textContent = `节点：${agentDisplayName(selectedAgent())} · 应用：${app.id}`;
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
  if (composeFilledFor !== app.id) fillCompose(app, composeRevision);
  renderHTTP(app);
  fillLogServices(app);
  if (appChanged) resetLogsTerminal();
};

const setDetailSection = async (section) => {
  const navigation = navigationSnapshot();
  const next = section || "overview";
  const previousSection = detailSection;
  if (next !== "files" && !(await filesWorkspace.confirmLeave())) return false;
  if (!navigationCurrent(navigation)) return false;
  if (next !== detailSection) advanceNavigation();
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
    if (previousSection !== "logs") logsPaused = false;
    if (logsPause) {
      logsPause.textContent = logsPaused ? "继续" : "暂停";
      logsPause.setAttribute("aria-pressed", String(logsPaused));
    }
    if (logsRefresh) logsRefresh.dataset.action = "logs";
    startLogPolling();
  }
  return true;
};

const leaveDetail = async ({ force } = {}) => {
  const navigation = navigationSnapshot();
  const leavingAppID = selectedAppID;
  if (!force && !(await confirmLeaveEditor())) return false;
  if (!navigationCurrent(navigation)) return false;
  advanceNavigation();
  stopLogPolling();
  resetLogsTerminal();
  filesWorkspace.unbind();
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
  if (!force) {
    const target = listNode.querySelector(`[data-id="${leavingAppID}"] [data-action="detail"]`) || deployToggle;
    if (target?.getClientRects().length) target.focus();
  }
  return true;
};

const showDetail = async (appID, section, composeRevision = composeDraft.revision) => {
  const snapshot = contextSnapshot();
  const previousNavigation = navigationSnapshot();
  if (appID !== selectedAppID && !(await confirmLeaveEditor())) return;
  if (!navigationCurrent(previousNavigation)) return;
  advanceNavigation();
  const navigation = navigationSnapshot();
  const request = ++detailRequest;
  try {
    const payload = await panelJSON(`api/apps/${encodeURIComponent(appID)}`);
    if (!navigationCurrent(navigation) || request !== detailRequest) return;
    const app = payload.app;
    if (!app) throw Object.assign(new Error("应用已不存在。"), { status: 404 });
    if (app.id !== appID || app.agent_id !== snapshot.agent) throw new Error("应用与当前节点不匹配，请刷新列表。");
    view = "detail";
    closeCreate();
    paintDetail(app, composeRevision);
    if (!(await setDetailSection(section || detailSection || "overview"))) return;
    syncListPanel();
    if (previousNavigation.view !== "detail" || previousNavigation.app !== appID) detailTitle?.focus();
    return !app.rules_error;
  } catch (error) {
    if (!navigationCurrent(navigation) || request !== detailRequest) return;
    const missing = error.status === 404 || error.message === "app is unknown";
    if (view === "detail" && selectedAppID === appID
      && (composeDraft.revision !== composeRevision || activeDrafts().some((item) => item.active && item.draft?.dirty))) {
      showFormFeedback(composeForm, "详情刷新失败，已保留当前编辑。", "failed");
      showStatus(missing ? "应用已不存在，当前编辑已保留。" : "详情刷新失败，当前编辑已保留。", true);
      return false;
    }
    await leaveDetail({ force: true });
    showStatus(missing ? "应用已不存在。" : error.message, true);
    return false;
  }
};

const loadEngine = async () => {
  if (!selectedAgentID) return null;
  const snapshot = contextSnapshot();
  const payload = await panelJSON(`api/engine?agent_id=${encodeURIComponent(snapshot.agent)}`);
  const engine = payload.engine || null;
  if (contextCurrent(snapshot)) {
    rememberEngine(snapshot.agent, engine);
    agentPicker.refresh();
  }
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
  if (engine?.state !== "missing") {
    showContext("detection-failed");
    return;
  }
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

const executionFaceUnavailable = (engine) => agentOnline && engine?.state === "report-offline";

const showContext = (which) => {
  document.querySelector("#app-detection-failed").hidden = which !== "detection-failed";
  document.querySelector("#app-node-denied").hidden = which !== "denied";
  if (nodeEmpty) nodeEmpty.hidden = which !== "empty";
  if (undeployedNode) undeployedNode.hidden = which !== "undeployed";
  if (offlineNode) offlineNode.hidden = which !== "offline";
  if (executionUnavailableNode) executionUnavailableNode.hidden = which !== "execution-unavailable";
  if (engineGuide) engineGuide.hidden = which !== "unready";
  if (contextNode) contextNode.hidden = !["empty", "undeployed", "offline", "execution-unavailable", "detection-failed", "denied"].includes(which);
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
    engineStatus.textContent = "无法检测 Docker 状态";
    return;
  }
  engineReady = engine.ready === true;
  if (engine.state === "detection-failed") {
    engineStatus.dataset.ready = "false";
    engineStatus.textContent = "无法检测 Docker 状态";
    return;
  }
  engineStatus.dataset.ready = engineReady ? "true" : "false";
  if (executionFaceUnavailable(engine)) {
    engineStatus.textContent = "暂时无法执行";
    return;
  }
  engineStatus.textContent = engineReady
    ? (engine.version ? `Docker 引擎 ${engine.version} 已就绪` : "Docker 引擎已就绪")
    : "尚未安装 Docker";
};

const renderWorkspace = async () => {
  const seq = ++workspaceSeq;
  const snapshot = contextSnapshot();
  const keepDetailID = view === "detail" ? selectedAppID : "";
  const keepDetailApp = detailApp;
  const composeRevision = composeDraft.revision;
  const keepSection = detailSection;
  const agent = selectedAgent();
  agentOnline = isAgentOnline(agent);
  engineReady = false;
  lastEngine = null;
  deniedNode.hidden = true;
  unavailableNode.hidden = true;
  workspaceNode.hidden = true;
  emptyNode.hidden = true;
  closeCreate();
  const navigation = navigationSnapshot();
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
    leaveDetail({ force: true });
    renderEngineBadge(null);
    showContext(error.denied ? "denied" : "detection-failed");
    if (error.denied) engineStatus.textContent = "无权管理该节点";
    return false;
  }
  if (seq !== workspaceSeq) return;
  lastEngine = engine;
  engineReady = engine?.ready === true;
  renderEngineBadge(engine);
  if (!engineReady) {
    leaveDetail({ force: true });
    renderGuide(engine);
    showContext(executionFaceUnavailable(engine) ? "execution-unavailable" : engine?.state === "missing" ? "unready" : "detection-failed");
    return false;
  }
  showContext("");
  workspaceNode.hidden = false;
  let payload;
  try {
    payload = await panelJSON(`api/apps?agent_id=${encodeURIComponent(snapshot.agent)}`);
  } catch (error) {
    if (seq !== workspaceSeq || !navigationCurrent(navigation)) return;
    throw error;
  }
  if (seq !== workspaceSeq || !contextCurrent(snapshot)) return;
  // Collection data belongs to the node; restoring a detail page also belongs to
  // the exact navigation and detail object that initiated this refresh.
  renderApps(payload.apps);
  if (!navigationCurrent(navigation) || detailApp !== keepDetailApp) return;
  if (payload.error) showStatus(payload.error, true);
  if (keepDetailID) {
    const stillThere = (payload.apps || []).some((app) => app.id === keepDetailID);
    if (!stillThere) {
      if (activeDrafts().some((item) => item.active && item.draft?.dirty)) {
        showStatus("应用已不存在，当前编辑已保留。", true);
        return false;
      }
      showStatus("应用已不存在。", true);
      leaveDetail({ force: true });
      return;
    }
    const restored = await showDetail(keepDetailID, keepSection, composeRevision);
    return payload.error ? false : restored;
  } else {
    syncListPanel();
    return !payload.error;
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
  if (busy) { agentPicker.setValue(selectedAgentID); return; }
  if (!(await confirmLeaveEditor())) {
    agentPicker.setValue(selectedAgentID);
    return;
  }
  leaveDetail({ force: true });
  contextVersion += 1;
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

document.querySelector("#workspace-refresh")?.addEventListener("click", async () => {
  if (busy || !(await confirmLeaveEditor())) return;
  composeFilledFor = "";
  try { await renderWorkspace(); } catch (error) { showStatus(error.message, true); }
});

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
  if (!cleanup) return "未返回磁盘清理结果，请刷新检查节点状态。";
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
  if (!agentOnline || !engineReady) { showStatus("当前节点无法清理磁盘，请检查节点状态。", true); return; }
  const agentID = selectedAgentID;
  const target = agentDisplayName(selectedAgent());
  setBusy(true);
  try {
    const payload = await panelJSON(`api/disk-cleanup?agent_id=${encodeURIComponent(agentID)}`);
    const previewed = payload.cleanup;
    if (!previewed) throw new Error("未获得磁盘清理预览，请重试。");
    if (diskCleanupPreviewFailed(previewed)) throw new Error(formatDiskCleanupPreviewFailure(previewed));
    const empty = previewed.empty === true;
    const ok = await askConfirm({
      title: `清理节点磁盘 · ${target}`, body: formatDiskCleanupBody(previewed),
      confirm: "清理", cancel: empty ? "知道了" : "取消", danger: !empty, hideConfirm: empty,
    });
    if (!ok || empty) { showStatus(empty ? "没有可清理项。" : "已取消，未清理节点磁盘。", false, "cancelled"); return; }
    showStatus(`正在清理节点 ${target}…`, false, "running");
    const result = await sendPluginJSON("api/disk-cleanup", { agent_id: agentID, confirm: true });
    const cleanup = result.cleanup;
    if (!cleanup || !["success", "partial", "failed"].includes(cleanup.status)) throw new Error("未获得可确认的清理结果，请刷新检查节点状态。");
    const steps = [cleanup.images_status, cleanup.builder_cache_status];
    const allDone = steps.every((step) => step === "success" || step === "skipped");
    const state = cleanup.unchanged ? "cancelled" : cleanup.status === "partial" ? "partial" : cleanup.status === "success" && allDone ? "succeeded" : "failed";
    showStatus(`节点 ${target}\n${formatDiskCleanupResult(cleanup)}`, state === "partial" || state === "failed", state);
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

const requestCloseCreate = async () => {
  if (busy || !(await confirmDiscardDrafts(["create"]))) return;
  closeCreate();
  deployToggle?.focus();
};
if (createCancel) createCancel.addEventListener("click", requestCloseCreate);
if (createBack) createBack.addEventListener("click", requestCloseCreate);

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
      setLogsState(logsLoaded ? "已暂停，显示上次快照" : "已暂停，尚未获得快照", logsView?.dataset.error === "true");
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

const showFormFeedback = (form, message, state = "failed") => {
  const node = form.querySelector("[data-form-feedback]");
  node.textContent = message;
  node.hidden = !message;
  node.dataset.state = state;
  node.setAttribute("role", state === "failed" ? "alert" : "status");
};
const submitCompose = async (form, updating) => {
  if (busy || (updating && !detailApp)) return;
  const invalid = Array.from(form.elements).find((field) => field.willValidate && (!field.checkValidity() || (field.required && !field.value.trim())));
  if (invalid) {
    showFormFeedback(form, invalid.name === "id" ? "填写有效的应用 ID：小写字母、数字及连字符。" : "请填写 Compose YAML。");
    invalid.setAttribute("aria-invalid", "true");
    invalid.focus();
    return;
  }
  form.querySelectorAll('[aria-invalid]').forEach((field) => field.removeAttribute("aria-invalid"));
  if (!selectedAgentID || !agentOnline || !engineReady) {
    showFormFeedback(form, "当前节点无法部署，请检查节点状态。");
    return;
  }
  const data = new FormData(form);
  const nextApp = {
    id: updating ? detailApp.id : String(data.get("id") || "").trim(),
    agent_id: selectedAgentID,
    compose: String(data.get("compose") || ""),
    env: String(data.get("env") || ""),
    auto_update: data.get("auto_update") === "on",
  };
  const draft = updating ? composeDraft : createDraft;
  setBusy(true);
  showFormFeedback(form, updating ? "正在保存 Compose…" : "正在部署应用…", "running");
  try {
    const saved = await deployComposePayload(nextApp);
    if (!saved) { showFormFeedback(form, "已取消，输入已保留。", "cancelled"); return; }
    if (selectedAgentID !== nextApp.agent_id || (updating && selectedAppID !== nextApp.id)) {
      showStatus(`应用 ${nextApp.id} 已保存，请在目标节点刷新查看结果。`, false);
      return;
    }
    // Submission succeeded. The persisted configuration becomes the draft
    // baseline before any fallible refresh.
    draft.capture();
    updateDraftIndicators();
    if (updating) composeFilledFor = "";
    else closeCreate();
    showStatus(updating ? "已更新应用。" : "已部署应用。", false);
    showFormFeedback(form, "已保存。", "succeeded");
    try {
      const refreshed = await renderWorkspace();
      if (refreshed === false) throw new Error("节点或详情未能刷新");
      showStatus(updating ? "已更新应用。" : "已部署应用。", false);
    } catch (refreshError) {
      showStatus(`${updating ? "应用已更新" : "应用已部署"}，但列表刷新失败：${refreshError.message}`, true, "partial");
      showFormFeedback(form, "操作已完成，但页面刷新失败。请稍后刷新，无需重复提交。", "partial");
    }
  } catch (error) {
    showFormFeedback(form, error.message);
    showStatus(error.message, true);
  } finally {
    setBusy(false);
  }
};
[ [composeForm, true], [createForm, false] ].forEach(([form, updating]) => {
  form.noValidate = true;
  form.addEventListener("submit", (event) => { event.preventDefault(); submitCompose(form, updating); });
});

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
