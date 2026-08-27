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
const emptyNode = document.querySelector("#app-empty");
const countNode = document.querySelector("#app-count");
const createPanel = document.querySelector("#app-create");
const listPanel = document.querySelector("#app-list-panel");
const workspaceHead = document.querySelector(".workspace-head");
const detailPanel = document.querySelector("#app-detail");
const detailTitle = document.querySelector("#detail-title");
const detailNav = document.querySelector("#detail-nav");
const detailBack = document.querySelector("#detail-back");
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
const deployToggle = document.querySelector("#deploy-toggle");
const agentSelect = document.querySelector("#agent-select");
const agentPickerRoot = document.querySelector('[data-agent-picker="workspace"]');
const nodeEmpty = document.querySelector("#app-node-empty");
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
const engineCache = new Map();
const ENGINE_CACHE_MS = 15000;
const ENGINE_PROBE_CONCURRENCY = 3;
const LOG_REFRESH_MS = 4000;
const OFFICIAL_INSTALL_SCRIPT = "curl -fsSL https://get.docker.com | sh";

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
    throw new Error(payload.error || payload.message || "保存失败");
  }
  return payload;
};

const setBusy = (next) => {
  busy = next;
  const roots = [workspaceNode, contextNode].filter(Boolean);
  roots.forEach((root) => {
    root.querySelectorAll("button, input, textarea, select").forEach((node) => {
      if (node === agentSelect || node === copyScript || node === copyDaemon) return;
      if (agentPickerRoot && agentPickerRoot.contains(node)) return;
      node.disabled = next;
    });
  });
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
  return prefix + highlightInterp(trimmed);
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

const confirmLeaveEditor = () => {
  if (!filesEditorOpen || !filesDirty) return true;
  if (!window.confirm("文本尚未保存。离开将丢弃改动，取消则留在当前编辑。")) return false;
  discardFileEditor();
  return true;
};

const openCreate = () => {
  if (!engineReady || !agentOnline) return;
  if (view === "detail" && !leaveDetail()) return;
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
  if (listPanel) listPanel.hidden = inDetail || Boolean(creating && !hasApps);
  if (detailPanel) detailPanel.hidden = !inDetail;
  if (workspaceHead) workspaceHead.hidden = inDetail;
  if (deployToggle) deployToggle.hidden = inDetail || creating || !(selectedAgentID && engineReady && agentOnline);
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

const chip = (text) => {
  const node = document.createElement("span");
  node.className = "chip";
  node.textContent = text;
  return node;
};

const appPorts = (app) => (Array.isArray(app.ports) && app.ports.length ? app.ports : parsePublishedPorts(app.compose));
const appVersion = (app) => app.version || parseImage(app.compose) || "未解析镜像";

const appendAppChips = (chips, app) => {
  if (app.status && app.status !== "有新版本") {
    const statusChip = chip(`Agent 执行面 · ${app.status}`);
    statusChip.className = "chip app-status";
    chips.append(statusChip);
  }
  if (app.notice === "有新版本" || app.status === "有新版本") {
    const noticeChip = chip("Agent 执行面 · 有新版本");
    noticeChip.className = "chip app-status-update";
    chips.append(noticeChip);
  }
  const versionChip = chip(appVersion(app));
  versionChip.className = "chip app-version";
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
  const listEl = section.querySelector("#files-list") || section.querySelector(".files-list");
  const emptyEl = section.querySelector(".files-empty");
  const mkdirBtn = section.querySelector("#files-mkdir");
  const mkdirName = section.querySelector("#files-mkdir-name");
  const newName = section.querySelector("#files-new-name");
  const newTextBtn = section.querySelector("#files-new-text");
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
  let selectedDir = true;
  let savedContent = "";

  const setDirty = (next) => {
    filesDirty = Boolean(next);
    if (dirtyMark) dirtyMark.hidden = !filesDirty;
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
  };

  discardFileEditor = hideEditor;

  const confirmLeave = () => {
    if (!filesEditorOpen || !filesDirty) {
      if (filesEditorOpen && !filesDirty) hideEditor();
      return true;
    }
    if (!window.confirm("文本尚未保存。离开将丢弃改动，取消则留在当前编辑。")) return false;
    hideEditor();
    return true;
  };

  const paintSelection = () => {
    if (!listEl) return;
    listEl.querySelectorAll("li").forEach((item) => {
      item.setAttribute("aria-selected", item.dataset.path === selectedPath ? "true" : "false");
    });
  };

  const selectEntry = (path, name, isDir) => {
    selectedPath = path;
    selectedName = name;
    selectedDir = isDir;
    paintSelection();
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
    if (!breadcrumb) return;
    breadcrumb.replaceChildren();
    const addCrumb = (label, path, current) => {
      if (current) {
        const currentNode = document.createElement("span");
        currentNode.textContent = label;
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
      sep.textContent = "/";
      breadcrumb.append(sep);
      acc = acc ? `${acc}/${part}` : part;
      addCrumb(part, acc, index === parts.length - 1);
    });
  };

  const openFile = async (path, name) => {
    if (!app) return;
    if (filesEditorOpen && filesDirty && selectedPath === path) return;
    if (!confirmLeave()) return;
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
      showStatus("已打开工作区文件。", false);
    } catch (error) {
      showStatus(error.message, true);
    }
  };

  const openNewFile = (path, name) => {
    if (!confirmLeave()) return;
    showEditor(path, name, "");
    showStatus("已打开新建文本文件，保存后写入工作区。", false);
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
      if (!filesEditorOpen) selectEntry(currentPath, currentPath === "." ? "工作区" : currentPath.split("/").pop(), true);
      renderBreadcrumb();
      const entries = Array.isArray(payload.entries) ? payload.entries : [];
      if (listEl) listEl.replaceChildren();
      entries.forEach((entry) => {
        const entryPath = relativeWorkspacePath(entry.path || entry.name);
        if (!entryPath) return;
        const item = document.createElement("li");
        item.dataset.path = entryPath;
        item.setAttribute("aria-selected", selectedPath === entryPath ? "true" : "false");
        const nameWrap = document.createElement("div");
        nameWrap.className = "files-list-name";
        const open = document.createElement("button");
        open.type = "button";
        open.className = "btn-link";
        open.textContent = entry.dir ? `${entry.name || entryPath}/` : (entry.name || entryPath);
        open.addEventListener("click", () => {
          if (entry.dir) requestList(entryPath);
          else selectEntry(entryPath, entry.name || entryPath, false);
        });
        nameWrap.append(open);
        if (!entry.dir && entry.size != null) {
          const size = document.createElement("span");
          size.className = "files-size";
          size.textContent = formatFileSize(entry.size);
          nameWrap.append(size);
        }
        const actions = document.createElement("div");
        actions.className = "files-toolbar";
        if (!entry.dir) {
          const edit = document.createElement("button");
          edit.type = "button";
          edit.className = "btn-link";
          edit.textContent = "编辑";
          edit.addEventListener("click", () => openFile(entryPath, entry.name || entryPath));
          actions.append(edit);
          const download = document.createElement("button");
          download.type = "button";
          download.className = "btn-link";
          download.textContent = "下载";
          download.addEventListener("click", async () => {
            try {
              const file = await postAppFiles(app, { action: "read", path: entryPath });
              downloadTextFile(entry.name || entryPath.split("/").pop(), file.content || "");
              showStatus("已开始下载。", false);
            } catch (error) {
              showStatus(error.message, true);
            }
          });
          actions.append(download);
        }
        const remove = document.createElement("button");
        remove.type = "button";
        remove.className = "btn-link danger";
        remove.textContent = "删除";
        remove.addEventListener("click", () => removePath(entryPath, entry.name || entryPath));
        actions.append(remove);
        item.append(nameWrap, actions);
        if (listEl) listEl.append(item);
      });
      if (emptyEl) emptyEl.hidden = entries.length !== 0;
    } catch (error) {
      if (listEl) listEl.replaceChildren();
      if (emptyEl) emptyEl.hidden = true;
      showStatus(error.message, true);
    }
  };

  const requestList = (path) => {
    if (!confirmLeave()) return;
    loadList(path);
  };

  const removePath = async (path, name) => {
    if (!app) return;
    const relative = relativeWorkspacePath(path);
    if (!relative || relative === ".") {
      showStatus(relative === "." ? "不能删除应用工作区根目录" : workspacePathError, true);
      return;
    }
    if (!window.confirm(`确认删除 ${name || relative}？取消不会更改工作区。`)) {
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

  if (mkdirBtn) {
    mkdirBtn.addEventListener("click", async () => {
      if (busy || !app) return;
      const name = mkdirName ? mkdirName.value.trim() : "";
      if (!name) return;
      const next = joinWorkspacePath(currentPath, name);
      if (!next) {
        showStatus(workspacePathError, true);
        return;
      }
      setBusy(true);
      try {
        await postAppFiles(app, { action: "mkdir", path: next });
        if (mkdirName) mkdirName.value = "";
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
    newTextBtn.addEventListener("click", () => {
      if (busy || !app) return;
      const name = newName ? newName.value.trim() : "";
      if (!name) {
        showStatus("请填写要新建的文本文件名。", true);
        return;
      }
      const next = joinWorkspacePath(currentPath, name);
      if (!next) {
        showStatus(workspacePathError, true);
        return;
      }
      if (newName) newName.value = "";
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
  if (closeBtn) {
    closeBtn.addEventListener("click", () => {
      if (!confirmLeave()) return;
    });
  }
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
  if (action.id === "delete") {
    if (!window.confirm(`确认删除 ${app.id}？取消不会更改应用。`)) {
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
  setBusy(true);
  try {
    await postAppAction(app, action.id);
    showStatus(action.id === "update" ? "已更新应用镜像。" : "已执行操作。", false);
  } catch (error) {
    showStatus(error.message, true);
  } finally {
    setBusy(false);
  }
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
    if (action.id === "rollback") return;
    if (action.id === "configure") return;
    const isPrimary = action.id === "start" || action.id === "stop" || action.id === "restart";
    const isDelete = action.id === "delete";
    const button = actionButton(
      action,
      isDelete ? "btn-link danger" : (isPrimary ? "btn-primary" : "btn-secondary"),
      action.label || action.id,
    );
    button.addEventListener("click", () => runAppAction(app, action));
    if (isDelete) danger.append(button);
    else if (isPrimary) primary.append(button);
    else secondary.append(button);
  });
  return [primary, secondary, danger].filter((group) => group.childNodes.length);
};

const renderApp = (app) => {
  const row = document.createElement("article");
  row.className = "app-row";
  row.dataset.id = app.id;
  row.tabIndex = 0;
  const main = document.createElement("div");
  main.className = "app-row-main";
  const title = document.createElement("h3");
  title.textContent = app.id;
  const chips = document.createElement("div");
  chips.className = "app-chips";
  appendAppChips(chips, app);
  main.append(title, chips);
  const actions = document.createElement("div");
  actions.className = "app-row-actions";
  actionGroups(app).forEach((group) => actions.append(group));
  const manage = document.createElement("button");
  manage.type = "button";
  manage.className = "btn-secondary";
  manage.textContent = "管理";
  manage.addEventListener("click", (event) => {
    event.stopPropagation();
    showDetail(app.id, "overview");
  });
  actions.append(manage);
  row.append(main, actions);
  const open = () => { showDetail(app.id, "overview"); };
  row.addEventListener("click", (event) => {
    if (event.target.closest("button")) return;
    open();
  });
  row.addEventListener("keydown", (event) => {
    if (event.target !== row) return;
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      open();
    }
  });
  return row;
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
  const identity = document.createElement("div");
  const title = document.createElement("h3");
  title.textContent = app.id;
  const chips = document.createElement("div");
  chips.className = "app-chips";
  appendAppChips(chips, app);
  identity.append(title, chips);
  overviewPanel.append(identity);
  actionGroups(app, { manage: false }).forEach((group) => overviewPanel.append(group));
};

const renderHTTP = (app) => {
  if (!httpPanel) return;
  httpPanel.replaceChildren();
  const ports = appPorts(app);
  const rules = Array.isArray(app.rules) ? app.rules : [];
  const title = document.createElement("h4");
  title.textContent = "HTTP 入口";
  httpPanel.append(title);
  if (rules.length) {
    const ruleList = document.createElement("ul");
    ruleList.className = "http-rules";
    rules.forEach((rule) => {
      const item = document.createElement("li");
      const domain = String(rule.domain || "").trim();
      const port = rule.port ? `:${rule.port}` : "";
      const enabled = rule.enabled === false;
      const label = document.createElement("span");
      label.textContent = `${domain}${port}${enabled ? "（已停用）" : ""}`;
      if (enabled) label.className = "http-rule-disabled";
      item.append(label);
      if (rule.ref) {
        const deleteRule = document.createElement("button");
        deleteRule.type = "button";
        deleteRule.className = "btn-link danger";
        deleteRule.textContent = "删除";
        deleteRule.addEventListener("click", async () => {
          if (busy) return;
          if (!window.confirm(`确认删除入口 ${domain || rule.ref}？取消不会更改规则。`)) {
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
  }
  if (ports.length) {
    const form = document.createElement("form");
    form.className = "http-form";
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
    submit.textContent = "保存规则";
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
  renderOverview(app);
  if (composeFilledFor !== app.id) fillCompose(app);
  renderHTTP(app);
  fillLogServices(app);
  if (appChanged) resetLogsTerminal();
};

const setDetailSection = (section) => {
  const next = section || "overview";
  if (next !== "files" && !filesWorkspace.confirmLeave()) return false;
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
  if (next === "logs") {
    logsPaused = false;
    logsLoaded = false;
    if (logsPause) logsPause.textContent = "暂停";
    if (logsRefresh) logsRefresh.dataset.action = "logs";
    startLogPolling();
  }
  return true;
};

const leaveDetail = ({ force } = {}) => {
  if (!force && !filesWorkspace.confirmLeave()) return false;
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
  syncListPanel();
  return true;
};

const showDetail = async (appID, section) => {
  if (!confirmLeaveEditor()) return;
  try {
    const payload = await panelJSON(`api/apps/${encodeURIComponent(appID)}`);
    const app = payload.app;
    if (!app) throw Object.assign(new Error("应用已不存在。"), { status: 404 });
    view = "detail";
    closeCreate();
    paintDetail(app);
    if (!setDetailSection(section || detailSection || "overview")) return;
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
  if (workspaceNode) workspaceNode.hidden = true;
  leaveDetail({ force: true });
  renderGuide(viewState);
  renderEngineBadge(viewState);
  showContext(executionFaceUnavailable(viewState) ? "execution-unavailable" : "unready");
};

const executionFaceUnavailable = (engine) => agentOnline && engine && engine.online === false && engine.ready !== true;

const showContext = (which) => {
  if (nodeEmpty) nodeEmpty.hidden = which !== "empty";
  if (offlineNode) offlineNode.hidden = which !== "offline";
  if (executionUnavailableNode) executionUnavailableNode.hidden = which !== "execution-unavailable";
  if (engineGuide) engineGuide.hidden = which !== "unready";
  if (contextNode) contextNode.hidden = which !== "empty" && which !== "offline" && which !== "execution-unavailable";
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
    engineStatus.textContent = "Agent 执行面 · 节点离线";
    return;
  }
  if (!engine) {
    engineReady = false;
    engineStatus.dataset.ready = "false";
    engineStatus.textContent = "Agent 执行面 · 引擎未就绪";
    return;
  }
  engineReady = engine.ready === true;
  engineStatus.dataset.ready = engineReady ? "true" : "false";
  if (executionFaceUnavailable(engine)) {
    engineStatus.textContent = "Agent 执行面 · 执行面未就绪";
    return;
  }
  engineStatus.textContent = engineReady
    ? (engine.version ? `Agent 执行面 · 引擎 ${engine.version} 已就绪` : "Agent 执行面 · 引擎已就绪")
    : "Agent 执行面 · 引擎未就绪";
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
    showContext("empty");
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
  if (!confirmLeaveEditor()) {
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

if (createCancel) createCancel.addEventListener("click", closeCreate);

if (detailBack) {
  detailBack.addEventListener("click", () => {
    leaveDetail();
  });
}

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
      await sendPluginJSON("api/apps", {
        id: detailApp.id,
        agent_id: selectedAgentID,
        compose: detailComposeInput ? detailComposeInput.value : "",
        env: detailEnvInput ? String(detailEnvInput.value || "") : "",
        auto_update: detailAutoUpdateInput ? detailAutoUpdateInput.checked : false,
      });
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
      await sendPluginJSON("api/apps", nextApp);
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
