const loadingNode = document.querySelector("#app-loading");
const unavailableNode = document.querySelector("#app-unavailable");
const deniedNode = document.querySelector("#app-denied");
const statusNode = document.querySelector("#app-status");
const contextNode = document.querySelector("#app-context");
const nodeEmpty = document.querySelector("#app-node-empty");
const executionUnavailable = document.querySelector(
  "#app-execution-unavailable",
);
const workspaceNode = document.querySelector("#app-workspace");
const emptyNode = document.querySelector("#app-empty");
const entryList = document.querySelector("#entry-list");
const entryCount = document.querySelector("#entry-count");
const exclusionList = document.querySelector("#exclusion-list");
const customList = document.querySelector("#custom-list");
const eventList = document.querySelector("#event-list");
const eventEmpty = document.querySelector("#event-empty");
const agentSelect = document.querySelector("#agent-select");
const agentPickerRoot = document.querySelector("#agent-picker");
const globalObserve = document.querySelector("#global-observe");
const globalDeny = document.querySelector("#global-deny");
const exclusionForm = document.querySelector("#exclusion-form");
const customForm = document.querySelector("#custom-form");

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
  statusNode.textContent = message || "";
  if (!message) {
    delete statusNode.dataset.error;
    return;
  }
  statusNode.dataset.error = isError ? "true" : "false";
};

const panelJSON = async (path, options = {}) => {
  let response;
  try {
    response = await fetch(path, {
      credentials: "same-origin",
      ...options,
      headers: { ...panelAuthHeaders(), ...(options.headers || {}) },
    });
  } catch (cause) {
    console.error("[waf] request failed", path, cause);
    throw Object.assign(new Error("网络连接失败"), {
      network: true,
      status: 0,
      cause,
    });
  }
  const payload = await response.json().catch(() => ({}));
  if (response.status === 401 || response.status === 403) {
    throw Object.assign(
      new Error(payload.error || payload.message || "无权管理 Web 防火墙。"),
      {
        denied: true,
        unauthorized: response.status === 401,
        status: response.status,
      },
    );
  }
  if (!response.ok) {
    throw Object.assign(
      new Error(payload.error || payload.message || "请求失败"),
      { status: response.status, unavailable: response.status >= 500 },
    );
  }
  return payload;
};

const showContext = (kind) => {
  if (contextNode) contextNode.hidden = !kind;
  if (nodeEmpty) nodeEmpty.hidden = kind !== "node-empty";
  if (executionUnavailable)
    executionUnavailable.hidden = kind !== "unavailable";
  if (workspaceNode) workspaceNode.hidden = !!kind;
};

const escapeText = (value) =>
  String(value || "").replace(
    /[&<>"']/g,
    (character) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[character],
  );

let selectedAgentID = "";
let agentsCache = [];

const parseAgentTime = (value) => {
  if (value == null || value === "") return 0;
  if (typeof value === "number" && Number.isFinite(value))
    return value < 1e12 ? value * 1000 : value;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : 0;
};

const timeAgo = (value) => {
  const ts = parseAgentTime(value);
  if (!ts) return "";
  const delta = Date.now() - ts;
  if (delta < 60 * 1000) return "刚刚";
  if (delta < 60 * 60 * 1000) return `${Math.floor(delta / 60000)} 分钟前`;
  if (delta < 24 * 60 * 60 * 1000)
    return `${Math.floor(delta / 3600000)} 小时前`;
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
  return agent.name && agent.name !== agent.id
    ? agent.name
    : agent.name || agent.id || "";
};

const agentSearchText = (agent) =>
  [
    agent && agent.name,
    agent && agent.id,
    agent && agent.ddns_domain,
    agent && agent.last_seen_ip,
    agent && agent.agent_url,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

const agentLabel = (agent) => {
  const label =
    agent.name && agent.name !== agent.id
      ? `${agent.name} · ${agent.id}`
      : agent.name || agent.id;
  return isAgentOnline(agent) ? label : `${label}（离线）`;
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
  const chevron = document.createElement("span");
  chevron.className = "agent-search-select__chevron";
  chevron.innerHTML =
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><polyline points="6 9 12 15 18 9"/></svg>';
  trigger.append(statusDot, label, chevron);

  const dropdown = document.createElement("div");
  dropdown.className = "agent-search-select__dropdown";
  dropdown.hidden = true;
  dropdown.id = "agent-picker-dropdown";
  trigger.setAttribute("aria-controls", dropdown.id);
  trigger.setAttribute("aria-label", placeholder);

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
  list.setAttribute("role", "listbox");
  list.setAttribute("aria-label", "节点");

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

  const currentAgent = () =>
    agentsCache.find((agent) => agent && agent.id === picker.selected) || null;

  const syncTrigger = () => {
    hiddenInput.value = picker.selected;
    const agent = currentAgent();
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
    trigger.setAttribute("aria-label", `节点：${label.textContent}`);
  };

  const filteredAgents = () => {
    const query = picker.search.trim().toLowerCase();
    let result = agentsCache.slice();
    if (picker.statusFilter) {
      result = result.filter(
        (agent) => getAgentStatus(agent) === picker.statusFilter,
      );
    }
    if (query) {
      result = result.filter((agent) => agentSearchText(agent).includes(query));
    }
    result.sort((left, right) => {
      if (picker.sortBy === "name") {
        return String(agentDisplayName(left)).localeCompare(
          String(agentDisplayName(right)),
          "zh",
        );
      }
      return (
        parseAgentTime(right.last_seen_at) - parseAgentTime(left.last_seen_at)
      );
    });
    return result;
  };

  const emitChange = (value) => {
    picker.setValue(value);
    picker.close();
    trigger.focus();
    if (typeof picker.onChange === "function") picker.onChange(value);
  };

  const renderList = () => {
    filterButtons.forEach((button) => {
      button.setAttribute(
        "aria-pressed",
        button.dataset.status === picker.statusFilter ? "true" : "false",
      );
    });
    sortButtons.forEach((button) => {
      button.setAttribute(
        "aria-pressed",
        button.dataset.sort === picker.sortBy ? "true" : "false",
      );
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
      empty.textContent = agentsCache.length
        ? "没有匹配的节点"
        : "暂无已安装 Web 防火墙的节点";
      list.append(empty);
      return;
    }
    items.forEach((agent) => {
      const option = document.createElement("button");
      option.type = "button";
      option.className = "agent-search-select__option";
      option.setAttribute("role", "option");
      option.setAttribute(
        "aria-selected",
        agent.id === picker.selected ? "true" : "false",
      );
      const dot = document.createElement("span");
      dot.className = `agent-search-select__status agent-search-select__status--${getAgentStatus(agent)}`;
      const name = document.createElement("span");
      name.className = "agent-search-select__option-name";
      name.textContent = agentDisplayName(agent);
      const meta = document.createElement("span");
      meta.className = "agent-search-select__option-meta";
      meta.textContent =
        timeAgo(agent.last_seen_at) || (isAgentOnline(agent) ? "在线" : "离线");
      option.append(dot, name, meta);
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
  });

  searchInput.addEventListener("input", () => {
    picker.search = searchInput.value;
    renderList();
  });

  root.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && picker.open) {
      event.preventDefault();
      picker.close();
      trigger.focus();
    } else if (
      picker.open &&
      event.key === "Enter" &&
      document.activeElement?.getAttribute("role") === "option"
    ) {
      event.preventDefault();
      document.activeElement.click();
    } else if (
      picker.open &&
      (event.key === "ArrowDown" || event.key === "ArrowUp")
    ) {
      const options = Array.from(list.querySelectorAll('[role="option"]'));
      if (!options.length) return;
      event.preventDefault();
      const index = options.indexOf(document.activeElement);
      const next =
        index < 0
          ? event.key === "ArrowDown"
            ? 0
            : options.length - 1
          : (index + (event.key === "ArrowDown" ? 1 : -1) + options.length) %
            options.length;
      options[next].focus();
    }
  });

  root.addEventListener("focusout", (event) => {
    if (picker.open && !root.contains(event.relatedTarget)) picker.close();
  });

  document.addEventListener("mousedown", (event) => {
    if (!picker.open) return;
    if (root.contains(event.target)) return;
    picker.close();
  });

  syncTrigger();
  return picker;
};

const agentPicker = mountAgentSearchSelect(
  agentPickerRoot,
  agentSelect,
  "选择节点",
);

const loadAgents = async () => {
  const [payload, plugin] = await Promise.all([
    panelJSON("/panel-api/agents"),
    panelJSON("/panel-api/plugins/waf"),
  ]);
  const agents = Array.isArray(payload.agents)
    ? payload.agents.filter((agent) => agent && agent.id)
    : [];
  const deployed = new Set();
  const instances = Array.isArray(plugin.instances) ? plugin.instances : [];
  instances.forEach((instance) => {
    const targets = Array.isArray(instance && instance.targets)
      ? instance.targets
      : [];
    targets.forEach((target) => {
      const id = String(target || "").trim();
      if (id) deployed.add(id);
    });
  });
  agentsCache = agents.filter((agent) => deployed.has(agent.id));
  const requested =
    new URLSearchParams(window.location.search).get("agent_id") || "";
  selectedAgentID = agentsCache.some((agent) => agent.id === requested)
    ? requested
    : agentsCache.length === 1
      ? agentsCache[0].id
      : "";
  agentPicker.refresh(selectedAgentID);
};

const $ = (selector) => document.querySelector(selector);
const ruleDialog = $("#rule-dialog");
const eventDialog = $("#event-dialog");
const confirmDialog = $("#confirm-dialog");
const eventEmptyDesc = $("#event-empty-desc");
const appEmptyDesc = $("#app-empty-desc");
const eventTableWrap = $("#event-table-wrap");
const entryTableWrap = $("#entry-table-wrap");
const loadingText = $("#app-loading [data-loading-text]");
const unavailableTitle = $("#app-unavailable-title");
const unavailableDesc = $("#app-unavailable-desc");
const deniedTitle = $("#app-denied-title");
const deniedDesc = $("#app-denied-desc");

const loadingTargets = () =>
  [
    workspaceNode,
    contextNode,
    entryTableWrap,
    eventTableWrap,
    $("#recent-events"),
  ].filter(Boolean);

const setLoading = (busy, message) => {
  const active = Boolean(busy);
  if (loadingNode) loadingNode.hidden = !active;
  if (loadingText && message) loadingText.textContent = message;
  loadingTargets().forEach((node) => {
    if (active) node.setAttribute("aria-busy", "true");
    else node.removeAttribute("aria-busy");
  });
  [$("#app-unavailable-retry"), $("#app-denied-retry")].forEach((button) => {
    if (button) button.disabled = active;
  });
};

const failureCopy = (error) => {
  const status = Number(error && error.status) || 0;
  const message = String((error && error.message) || "");
  if (error && error.denied) {
    return status === 401
      ? {
          kind: "denied",
          title: "登录状态已失效",
          desc: "当前登录状态已失效或尚未登录。请重新登录宿主，或刷新页面后重试。",
          label: "重新检查权限",
        }
      : {
          kind: "denied",
          title: "无权管理 Web 防火墙",
          desc: "当前账号没有该节点的防火墙管理权限。请确认节点归属，或联系管理员开通权限后重试。",
          label: "重新检查权限",
        };
  }
  if (
    (error && (error.network || error.name === "TypeError")) ||
    status === 0 ||
    /Failed to fetch|NetworkError|Load failed|network error/i.test(message)
  ) {
    return {
      kind: "unavailable",
      title: "网络连接失败",
      desc: "无法连接宿主或节点。请检查网络、宿主地址或代理后重试。",
      label: "重新加载",
    };
  }
  if (status >= 500) {
    return {
      kind: "unavailable",
      title: "服务暂时不可用",
      desc: /[\u4e00-\u9fff]/.test(message)
        ? `${message}请稍后重试；若持续失败，请联系管理员。`
        : "宿主或防护服务暂时不可用。请稍后重试；若持续失败，请联系管理员。",
      label: "重新加载",
    };
  }
  return {
    kind: "unavailable",
    title: "暂时无法加载 Web 防火墙",
    desc: /[\u4e00-\u9fff]/.test(message)
      ? `${message}请重新加载；若问题持续，请联系管理员。`
      : "页面没有拿到防护状态。请重新加载；若问题持续，请联系管理员。",
    label: "重新加载",
  };
};

const hideFailure = () => {
  if (unavailableNode) unavailableNode.hidden = true;
  if (deniedNode) deniedNode.hidden = true;
};

const showFailure = (error) => {
  const copy = failureCopy(error);
  setLoading(false);
  if (contextNode) contextNode.hidden = true;
  if (workspaceNode) workspaceNode.hidden = true;
  if (copy.kind === "denied") {
    if (unavailableNode) unavailableNode.hidden = true;
    if (deniedNode) deniedNode.hidden = false;
    if (deniedTitle) deniedTitle.textContent = copy.title;
    if (deniedDesc) deniedDesc.textContent = copy.desc;
    const retry = $("#app-denied-retry");
    if (retry) retry.textContent = copy.label;
    return;
  }
  if (deniedNode) deniedNode.hidden = true;
  if (unavailableNode) unavailableNode.hidden = false;
  if (unavailableTitle) unavailableTitle.textContent = copy.title;
  if (unavailableDesc) unavailableDesc.textContent = copy.desc;
  const retry = $("#app-unavailable-retry");
  if (retry) retry.textContent = copy.label;
};

const targetLabel = (target) =>
  ({ path: "请求路径", query: "查询参数", headers: "请求头", body: "请求体" })[
    target
  ] || target;
const groups = [
  {
    name: "路径穿越",
    copy: "检查目录跳转、敏感文件与编码路径特征。",
    match: (id) => /managed-(path|query)/.test(id),
  },
  {
    name: "SQL 注入特征",
    copy: "检查查询参数和请求体中的常见注入特征。",
    match: (id) => id.includes("sqli"),
  },
  {
    name: "脚本注入特征",
    copy: "检查脚本标签、事件属性等常见 XSS 特征。",
    match: (id) => id.includes("xss"),
  },
  {
    name: "危险请求特征",
    copy: "检查命令、敏感协议与危险请求头特征。",
    match: () => true,
  },
];
const reasonLabel = (reason) =>
  ({
    rule_matched: "命中检测规则",
    body_window_skipped: "请求体未完整检查",
    trusted_source_unavailable: "无法确认请求来源",
    source_unauthenticated: "无法确认请求来源",
    event_details_unavailable: "检查结果详情不可用",
  })[reason] ||
  reason ||
  "未提供原因";
const eventMode = (event) =>
  event.disposition === "deny"
    ? "deny"
    : event.reason && event.reason !== "rule_matched"
      ? "skip"
      : "observe";
const eventLabel = (event) =>
  ({ deny: "已拦截", observe: "仅检测", skip: "检查未完成" })[eventMode(event)];

// Status is always conveyed by text and an icon mark, never by colour alone.
const statusIcon = (tone, glyph) =>
  `<span class="waf-status-icon" data-tone="${tone}" aria-hidden="true">${glyph}</span>`;
const badgeMarkup = (tone, glyph, label) =>
  `<span class="ui-badge${tone ? " ui-badge--" + tone : ""} ui-badge--plain">${statusIcon(tone || "muted", glyph)}${escapeText(label)}</span>`;
const eventBadge = (event) => {
  const mode = eventMode(event);
  if (mode === "deny") return badgeMarkup("danger", "!", "已拦截");
  if (mode === "observe") return badgeMarkup("info", "◉", "仅检测");
  return badgeMarkup("warning", "?", "检查未完成");
};
const entryStatus = (entry) => {
  if (!entry.enabled)
    return { mode: "disabled", label: "入口已停用", tone: "", glyph: "—" };
  if (entry.overlay_invalid)
    return { mode: "invalid", label: "防护配置异常", tone: "danger", glyph: "!" };
  if (!entry.attached)
    return { mode: "skip", label: "未挂载防护", tone: "warning", glyph: "⊘" };
  if (entry.mode === "deny")
    return { mode: "deny", label: "检测并拦截", tone: "success", glyph: "✓" };
  return { mode: "observe", label: "仅检测", tone: "info", glyph: "◉" };
};

const listState = {
  entry: { page: 1, query: "", mode: "" },
  event: { page: 1, query: "", mode: "" },
};
let activeTab = "overview";
let activeRuleTab = "managed";
let requestSequence = 0;
let latestState = null;
let latestEvents = null;
let eventFailure = null;
let detailEvent = null;

const switchTab = (tab) => {
  activeTab = tab;
  ["overview", "events", "rules", "scope"].forEach((name) => {
    const trigger = $("#tab-" + name);
    const view = $("#view-" + name);
    if (!trigger || !view) return;
    trigger.setAttribute("aria-selected", String(name === tab));
    trigger.tabIndex = name === tab ? 0 : -1;
    view.hidden = name !== tab;
  });
};

const bindTabs = (selector, values, current, change) => {
  document.querySelectorAll(selector).forEach((button, index) => {
    button.addEventListener("click", () => change(values[index]));
    button.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key))
        return;
      event.preventDefault();
      const next =
        event.key === "Home"
          ? 0
          : event.key === "End"
            ? values.length - 1
            : (values.indexOf(current()) +
                (event.key === "ArrowRight" ? 1 : -1) +
                values.length) %
              values.length;
      change(values[next]);
      document.querySelectorAll(selector)[next]?.focus();
    });
  });
};
bindTabs(
  ".waf-tabbar [data-tab]",
  ["overview", "events", "rules", "scope"],
  () => activeTab,
  switchTab,
);
document
  .querySelectorAll("[data-open-tab]")
  .forEach((button) =>
    button.addEventListener("click", () => switchTab(button.dataset.openTab)),
  );

const renderPagination = (kind, info) => {
  const root = $("#" + kind + "-pagination");
  if (!root) return;
  root.replaceChildren();
  root.hidden = !info || !info.total;
  if (!info) return;
  listState[kind].page = info.page;
  const pages = Math.max(1, Math.ceil(info.total / info.page_size));
  const summary = document.createElement("span");
  summary.textContent = `共 ${info.total} 条 · 每页 ${info.page_size} 条`;
  const actions = document.createElement("div");
  actions.className = "actions";
  const label = document.createElement("span");
  label.textContent = `${info.page} / ${pages}`;
  const button = (text, delta, disabled) => {
    const node = document.createElement("button");
    node.type = "button";
    node.className = "ui-btn ui-btn--secondary ui-btn--sm";
    node.textContent = text;
    node.disabled = disabled;
    node.addEventListener("click", () => {
      listState[kind].page += delta;
      refreshWorkspace();
    });
    return node;
  };
  actions.append(
    button("上一页", -1, info.page <= 1),
    label,
    button("下一页", 1, info.page >= pages),
  );
  root.append(summary, actions);
  const count = $("#" + kind + "-count");
  if (count) count.textContent = info.total;
};

const showEvents = (mode = "", query = "") => {
  listState.event = { page: 1, query, mode };
  $("#event-query").value = query;
  $("#event-mode").value = mode;
  switchTab("events");
  refreshWorkspace();
};
document
  .querySelectorAll("[data-event-mode]")
  .forEach((button) =>
    button.addEventListener("click", () =>
      showEvents(button.dataset.eventMode),
    ),
  );

const changeEntryMode = async (entry, mode, controls, label) => {
  controls.forEach((control) => {
    control.disabled = true;
  });
  try {
    await panelJSON("api/entries/mode", {
      method: "POST",
      body: JSON.stringify({
        agent_id: selectedAgentID,
        rule_ref: entry.rule_ref,
        mode,
      }),
    });
    await refreshWorkspace();
    showStatus(
      `${entry.frontend_url || entry.rule_ref} 已切为${label}。`,
      false,
    );
  } catch (error) {
    showStatus(error.message, true);
  } finally {
    controls.forEach((control) => {
      control.disabled =
        !entry.enabled || !entry.attached || entry.overlay_invalid;
    });
  }
};

const renderEntries = (entries = []) => {
  if (entryList) entryList.replaceChildren();
  const filtered = Boolean(listState.entry.query || listState.entry.mode);
  if (emptyNode) emptyNode.hidden = entries.length > 0;
  if (appEmptyDesc)
    appEmptyDesc.textContent = filtered
      ? "没有符合条件的入口，请调整查询条件。"
      : "先在节点上添加 HTTP 入口，再回到本页设置防护模式。";
  if (entryTableWrap) entryTableWrap.hidden = entries.length === 0;
  entries.forEach((entry) => {
    const status = entryStatus(entry);
    const row = document.createElement("tr");

    const targetCell = document.createElement("td");
    targetCell.className = "waf-entry-target";
    const title = document.createElement("strong");
    title.textContent = entry.frontend_url || entry.rule_ref || "未命名入口";
    const meta = document.createElement("span");
    meta.className = "waf-entry-meta";
    meta.textContent = `后端 · ${entry.backend || "未配置"}`;
    targetCell.append(title, meta);
    if (entry.notice) {
      const notice = document.createElement("span");
      notice.className = "waf-entry-notice";
      notice.textContent = entry.notice;
      targetCell.append(notice);
    }

    const statusCell = document.createElement("td");
    statusCell.innerHTML = badgeMarkup(status.tone, status.glyph, status.label);
    const badge = statusCell.firstElementChild;
    if (badge) badge.dataset.mode = status.mode;

    const modeCell = document.createElement("td");
    modeCell.className = "waf-entry-mode";
    const switchGroup = document.createElement("div");
    switchGroup.className = "mode-switch";
    switchGroup.setAttribute("role", "group");
    switchGroup.setAttribute("aria-label", "入口防护模式");
    const controls = [];
    [
      ["observe", "仅检测"],
      ["deny", "检测并拦截"],
    ].forEach(([mode, label]) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "mode-switch__option";
      button.dataset.mode = mode;
      button.setAttribute("aria-pressed", String(status.mode === mode));
      button.textContent = label;
      button.disabled =
        !entry.enabled || !entry.attached || entry.overlay_invalid;
      button.title =
        mode === "deny"
          ? "仅拒绝命中 WAF 规则的请求"
          : "记录命中，不阻断请求";
      button.addEventListener("click", () =>
        changeEntryMode(entry, mode, controls, label),
      );
      controls.push(button);
      switchGroup.append(button);
    });
    modeCell.append(switchGroup);

    const actionCell = document.createElement("td");
    actionCell.className = "waf-table-actions";
    const eventsButton = document.createElement("button");
    eventsButton.type = "button";
    eventsButton.className = "ui-btn ui-btn--ghost ui-btn--sm";
    eventsButton.dataset.events = "true";
    eventsButton.textContent = "查看事件";
    eventsButton.addEventListener("click", () => {
      let site = entry.frontend_url || "";
      try {
        site = new URL(site).host;
      } catch {}
      showEvents("", site);
    });
    actionCell.append(eventsButton);

    row.append(targetCell, statusCell, modeCell, actionCell);
    if (entryList) entryList.append(row);
  });
};

const eventDetail = (event) => {
  detailEvent = event;
  const fields = [
    ["处理结果", eventLabel(event)],
    ["站点", event.site || "未标记"],
    ["请求路径", "现有接口未提供，请结合业务请求确认"],
    ["命中规则", event.rule_id || "未命中具体规则"],
    ["检查说明", reasonLabel(event.reason)],
    ["来源指纹", event.digest || "未提供"],
  ];
  $("#event-detail").innerHTML =
    `<div class="waf-event-status">${eventBadge(event)}</div>` +
    `<dl class="waf-event-fields">${fields
      .map(
        ([key, value]) =>
          `<div><dt>${key}</dt><dd>${escapeText(value)}</dd></div>`,
      )
      .join("")}</dl>` +
    `<p class="waf-event-explanation">${
      eventMode(event) === "deny"
        ? "该请求命中检测规则，WAF 已拒绝请求。请结合业务判断是否为误报。"
        : eventMode(event) === "observe"
          ? "该请求命中检测规则，但入口处于仅检测模式，请求仍然放行。"
          : "本次检查未完整完成，不能据此判断请求安全。请先查看检查说明。"
    }</p>` +
    `<p class="ui-help-text">确认属于正常业务请求后，再填写范围尽可能小的路径排除。</p>`;
  const actionable = !!event.rule_id && event.reason === "rule_matched";
  const createButton = $("#event-create-exclusion");
  if (createButton) {
    createButton.disabled = !actionable;
    createButton.title = actionable
      ? ""
      : "只有命中具体规则的记录才能创建排除";
  }
  eventDialog?.showModal();
};

const eventRow = (event) => {
  const row = document.createElement("tr");
  const siteCell = document.createElement("td");
  const site = document.createElement("strong");
  site.textContent = event.site || "未标记站点";
  siteCell.append(site);

  const ruleCell = document.createElement("td");
  const rule = document.createElement("span");
  rule.textContent = event.rule_id || "检查异常";
  const reason = document.createElement("small");
  reason.textContent = reasonLabel(event.reason);
  ruleCell.append(rule, reason);

  const statusCell = document.createElement("td");
  statusCell.innerHTML = eventBadge(event);

  const actionCell = document.createElement("td");
  actionCell.className = "waf-table-actions";
  const detailButton = document.createElement("button");
  detailButton.type = "button";
  detailButton.className = "ui-btn ui-btn--ghost ui-btn--sm";
  detailButton.textContent = "详情";
  detailButton.setAttribute("aria-label", `查看 ${event.site || "事件"} 详情`);
  detailButton.addEventListener("click", () => eventDetail(event));
  actionCell.append(detailButton);

  row.append(siteCell, ruleCell, statusCell, actionCell);
  return row;
};

const renderEvents = () => {
  if (eventList) eventList.replaceChildren();
  const events = latestEvents?.events || [];
  const filtered = Boolean(listState.event.query || listState.event.mode);
  events.forEach((event) => eventList?.append(eventRow(event)));
  const empty = Boolean(eventFailure) || events.length === 0;
  if (eventEmpty) eventEmpty.hidden = !empty;
  if (eventEmptyDesc)
    eventEmptyDesc.textContent =
      eventFailure ||
      (filtered
        ? "当前记录中没有符合条件的事件，请调整筛选条件。"
        : "宿主当前未返回相关记录，不能据此判断未发生攻击。");
  if (eventTableWrap) eventTableWrap.hidden = empty;
  $("#event-count").textContent = eventFailure ? "—" : latestEvents?.total || 0;
  renderPagination("event", eventFailure ? null : latestEvents);
  $("#event-retention").textContent =
    "仅展示现有宿主接口返回的近期记录；分页和筛选限于这些记录。接口不提供完整历史、发生时间和请求路径。";
};

const ruleGroups = (rules = []) => {
  const result = groups.map((group) => ({ ...group, rules: [] }));
  rules.forEach((rule) =>
    result.find((group) => group.match(rule.id)).rules.push(rule),
  );
  return result;
};

const switchRuleTab = (tab) => {
  activeRuleTab = tab;
  ["managed", "custom", "exclusion"].forEach((name) => {
    const trigger = $("#" + name + "-tab");
    const panel = $("#" + name + "-rule-panel");
    if (!trigger || !panel) return;
    trigger.setAttribute("aria-selected", String(name === tab));
    trigger.tabIndex = name === tab ? 0 : -1;
    panel.hidden = name !== tab;
  });
  const addRule = $("#add-rule");
  if (addRule)
    addRule.textContent =
      tab === "exclusion" ? "添加排除规则" : "添加自定义规则";
};
bindTabs(
  ".waf-rule-tabs [role=tab]",
  ["managed", "custom", "exclusion"],
  () => activeRuleTab,
  switchRuleTab,
);

const closeRuleDialog = () => {
  if (ruleDialog?.open) ruleDialog.close();
  [customForm, exclusionForm].forEach((form) => {
    if (!form) return;
    form.reset();
    clearFormFieldErrors(form);
    markFormClean(form);
  });
  const alert = $("#rule-dialog-error");
  if (alert) {
    alert.hidden = true;
    alert.textContent = "";
  }
};

const requestRuleDialogClose = async () => {
  if (!ruleDialog?.open) return;
  const form = activeRuleForm();
  if (form && isFormDirty(form)) {
    const discard = await askConfirm({
      title: "改动尚未保存",
      desc: "表单里有未保存的规则内容。丢弃后这些输入会被清空，规则不会被添加。",
      label: "丢弃修改",
    });
    if (!discard) return;
  }
  closeRuleDialog();
};

const openRuleDialog = (kind, event = null) => {
  if (!ruleDialog) return;
  const custom = kind === "custom";
  if (customForm) customForm.hidden = !custom;
  if (exclusionForm) exclusionForm.hidden = custom;
  $("#rule-dialog-title").textContent = custom
    ? "添加自定义规则"
    : "添加排除";
  $("#rule-dialog-desc").textContent = custom
    ? "只支持字面量匹配，不支持正则、CRS 或 PCRE 规则。"
    : "仅排除指定规则在匹配路径下的检查。";
  const alert = $("#rule-dialog-error");
  if (alert) {
    alert.hidden = true;
    alert.textContent = "";
  }
  customForm?.reset();
  exclusionForm?.reset();
  clearFormFieldErrors(customForm);
  clearFormFieldErrors(exclusionForm);
  if (!custom && event && exclusionForm) {
    exclusionForm.elements.rule_id.value = event.rule_id;
    exclusionForm.elements.path_prefix.value = "";
  }
  markFormClean(customForm);
  markFormClean(exclusionForm);
  ruleDialog.showModal();
};
$("#add-rule")?.addEventListener("click", () =>
  openRuleDialog(activeRuleTab === "exclusion" ? "exclusion" : "custom"),
);
$("#event-create-exclusion")?.addEventListener("click", () => {
  const event = detailEvent;
  eventDialog?.close();
  switchTab("rules");
  switchRuleTab("exclusion");
  openRuleDialog("exclusion", event);
});

let pendingConfirm = null;
const settleConfirm = (value) => {
  if (!pendingConfirm || pendingConfirm.done) return;
  const pending = pendingConfirm;
  pending.done = true;
  pendingConfirm = null;
  if (confirmDialog?.open) confirmDialog.close();
  pending.resolve(value);
};
const askConfirm = ({ title, desc, label, danger = true }) =>
  new Promise((resolve) => {
    if (!confirmDialog) {
      resolve(false);
      return;
    }
    if (pendingConfirm) settleConfirm(false);
    $("#confirm-title").textContent = title;
    $("#confirm-desc").textContent = desc;
    const accept = $("#confirm-accept");
    accept.textContent = label;
    accept.className = danger ? "ui-btn ui-btn--danger" : "ui-btn";
    pendingConfirm = { resolve, done: false };
    confirmDialog.showModal();
  });
$("#confirm-accept")?.addEventListener("click", () => settleConfirm(true));
document
  .querySelectorAll("[data-confirm-cancel]")
  .forEach((button) =>
    button.addEventListener("click", () => settleConfirm(false)),
  );
confirmDialog?.addEventListener("cancel", (event) => {
  event.preventDefault();
  settleConfirm(false);
});

const activeRuleForm = () =>
  ruleDialog && customForm && !customForm.hidden
    ? customForm
    : ruleDialog && exclusionForm && !exclusionForm.hidden
      ? exclusionForm
      : null;

const formSnapshot = (form) =>
  JSON.stringify(Array.from(new FormData(form).entries()));

const markFormClean = (form) => {
  if (form) form.dataset.baseline = formSnapshot(form);
};

const isFormDirty = (form) => {
  if (!form || typeof form.dataset.baseline !== "string") return false;
  return formSnapshot(form) !== form.dataset.baseline;
};

const hasDirtyRuleForm = () => {
  const form = activeRuleForm();
  return Boolean(ruleDialog?.open && form && isFormDirty(form));
};

const rememberFieldHints = (form) => {
  form
    ?.querySelectorAll("[aria-describedby]")
    .forEach((input) => {
      if (!input.dataset.hintId)
        input.dataset.hintId = input.getAttribute("aria-describedby");
    });
};

const clearFormField = (input) => {
  if (!input) return;
  if (window.NREUI && window.NREUI.clearFieldError) {
    window.NREUI.clearFieldError(input);
  } else {
    input.removeAttribute("aria-invalid");
    const field = input.closest(".ui-field");
    const error = field ? field.querySelector(".ui-error-text") : null;
    if (error) error.textContent = "";
  }
  if (input.dataset.hintId)
    input.setAttribute("aria-describedby", input.dataset.hintId);
  else input.removeAttribute("aria-describedby");
};

const clearFormFieldErrors = (form) => {
  form
    ?.querySelectorAll("[aria-invalid='true']")
    .forEach((input) => clearFormField(input));
};

const showFormFieldError = (input, message) => {
  if (!input || !message) return false;
  if (window.NREUI && window.NREUI.fieldError) {
    window.NREUI.fieldError(input, message);
  } else {
    input.setAttribute("aria-invalid", "true");
    const field = input.closest(".ui-field") || input.parentElement || input;
    let error = field.querySelector(".ui-error-text");
    if (!error) {
      error = document.createElement("p");
      error.className = "ui-error-text";
      error.setAttribute("role", "alert");
      field.appendChild(error);
    }
    if (!error.id)
      error.id = "field-error-" + Math.random().toString(36).slice(2, 10);
    error.textContent = message;
    input.setAttribute("aria-describedby", error.id);
  }
  if (input.focus) input.focus();
  return true;
};

const bindFieldErrorClearing = (form) => {
  const clear = (event) => {
    const input = event.target;
    if (
      input &&
      input.getAttribute &&
      input.getAttribute("aria-invalid") === "true"
    )
      clearFormField(input);
  };
  form?.addEventListener("input", clear);
  form?.addEventListener("change", clear);
};

const ruleIDPattern = /^[a-z][a-z0-9-]{0,31}$/;
const ruleTargets = new Set(["path", "query", "headers", "body"]);

const literalLength = (value) => [...String(value || "")].length;

const printableLiteral = (value, minimum, maximum) => {
  const text = String(value || "");
  const length = literalLength(text);
  return (
    length >= minimum &&
    length <= maximum &&
    !/[\r\n\x00]/.test(text) &&
    /^[\x20-\x7E]*$/.test(text)
  );
};

const serverFieldError = (form, error) => {
  if (!form || !error || error.status !== 400) return null;
  const message = String(error.message || "");
  if (/上限/.test(message)) return null;
  if (form === customForm) {
    if (/已存在/.test(message))
      return {
        input: form.elements.id,
        message: "该规则 ID 已存在，请换一个唯一标识。",
      };
    if (!ruleIDPattern.test(String(form.elements.id.value || "").trim()))
      return {
        input: form.elements.id,
        message:
          "规则 ID 需以小写字母开头，只能包含小写字母、数字和连字符，最长 32 个字符。",
      };
    if (!ruleTargets.has(String(form.elements.target.value || "")))
      return {
        input: form.elements.target,
        message: "请选择有效的检查目标。",
      };
    if (!printableLiteral(form.elements.needle.value, 2, 64))
      return {
        input: form.elements.needle,
        message: "匹配内容需为 2–64 个可打印 ASCII 字符。",
      };
  }
  if (form === exclusionForm) {
    const ruleID = String(form.elements.rule_id.value || "").trim();
    if (!ruleIDPattern.test(ruleID))
      return {
        input: form.elements.rule_id,
        message:
          "规则 ID 需以小写字母开头，只能包含小写字母、数字和连字符，最长 32 个字符。",
      };
    if (!printableLiteral(form.elements.path_prefix.value, 1, 96))
      return {
        input: form.elements.path_prefix,
        message: "路径前缀需为 1–96 个可打印 ASCII 字符。",
      };
    if (!String(form.elements.path_prefix.value || "").startsWith("/"))
      return {
        input: form.elements.path_prefix,
        message: "路径前缀需以 / 开头，例如 /api/health。",
      };
    if (/排除项无效/.test(message))
      return {
        input: form.elements.rule_id,
        message: "找不到该规则 ID，请从内置检测或自定义规则中选择。",
      };
  }
  return null;
};

const showSubmitError = (form, alert, error) => {
  clearFormFieldErrors(form);
  const field = serverFieldError(form, error);
  if (field && showFormFieldError(field.input, field.message)) {
    if (alert) {
      alert.hidden = true;
      alert.textContent = "";
    }
    return;
  }
  const copy = failureCopy(error);
  const raw = String(error.message || "");
  const status = Number(error.status) || 0;
  const localized =
    copy.kind === "denied" ||
    error.network ||
    status >= 500 ||
    !/[\u4e00-\u9fff]/.test(raw);
  const message = localized ? copy.desc : raw;
  if (alert) {
    alert.textContent = message;
    alert.hidden = false;
  }
};

[customForm, exclusionForm].forEach((form) => {
  if (!form) return;
  rememberFieldHints(form);
  bindFieldErrorClearing(form);
});

const deleteRecord = async (kind, rule, button) => {
  const name = rule.id || rule.rule_id || "";
  const confirmed = await askConfirm({
    title: kind === "custom" ? "删除自定义规则" : "删除排除规则",
    desc:
      kind === "custom"
        ? `将删除规则 ${name} 及其关联的排除项，删除后无法恢复，相关请求会重新接受该规则的检查。`
        : `将删除规则 ${name} 在路径 ${rule.path_prefix || ""} 下的排除，该路径会恢复检查。`,
    label: "确认删除",
  });
  if (!confirmed) return;
  button.disabled = true;
  try {
    await panelJSON(kind === "custom" ? "api/custom-rules" : "api/exclusions", {
      method: "DELETE",
      body: JSON.stringify({ ...rule, agent_id: selectedAgentID }),
    });
    await refreshWorkspace();
    showStatus(
      kind === "custom"
        ? "已删除规则及其关联排除。"
        : "已删除排除，恢复路径检查。",
      false,
    );
  } catch (error) {
    showStatus(error.message, true);
    button.disabled = false;
  }
};

const renderRules = () => {
  const managed = latestState?.managed_rules || [];
  $("#managed-count").textContent = managed.length;
  $("#managed-list").innerHTML = ruleGroups(managed)
    .map(
      (group) =>
        `<details class="managed-group"><summary><span><strong>${group.name}</strong><small>${group.copy}</small></span><span class="ui-badge ui-badge--plain">${group.rules.length} 项检测</span></summary><div class="managed-rows">${group.rules
          .map(
            (rule) =>
              `<div><span><strong>${escapeText(rule.id)}</strong><small>${targetLabel(rule.target)}</small></span><code>${escapeText(rule.needle)}</code></div>`,
          )
          .join("")}</div></details>`,
    )
    .join("");
  ["custom", "exclusion"].forEach((kind) => {
    const rules =
      (kind === "custom"
        ? latestState?.custom_rules
        : latestState?.exclusions) || [];
    $("#" + kind + "-count").textContent = rules.length;
    $("#" + kind + "-empty").hidden = rules.length > 0;
    const root = $("#" + kind + "-list");
    root.replaceChildren();
    rules.forEach((rule) => {
      const item = document.createElement("li");
      item.className = "ui-record";
      const main = document.createElement("div");
      main.className = "ui-record__main";
      const title = document.createElement("p");
      title.className = "ui-record__title";
      title.textContent = rule.id || rule.rule_id || "";
      const meta = document.createElement("div");
      meta.className = "ui-record__meta";
      const metaText = document.createElement("span");
      metaText.className = "ui-tertiary";
      metaText.textContent =
        kind === "custom" ? targetLabel(rule.target) : "排除路径前缀";
      meta.append(metaText);
      main.append(title, meta);
      const actions = document.createElement("div");
      actions.className = "ui-record__actions";
      const code = document.createElement("code");
      code.className = "ui-mono";
      code.textContent = rule.needle || rule.path_prefix || "";
      const button = document.createElement("button");
      button.type = "button";
      button.className = "ui-btn ui-btn--danger-soft ui-btn--sm";
      button.textContent = "删除";
      button.title =
        kind === "custom" ? "删除规则及其关联排除" : "删除后恢复对此路径的检查";
      button.addEventListener("click", () => deleteRecord(kind, rule, button));
      actions.append(code, button);
      item.append(main, actions);
      root.append(item);
    });
  });
};

const renderOverview = () => {
  const coverage = latestState?.coverage || {};
  const unprotected = coverage.unprotected || 0;
  const observed = coverage.observe || 0;
  const blocking = coverage.deny || 0;
  const disabled = coverage.disabled || 0;
  const gap = unprotected + disabled;
  $("#protection-title").textContent = gap
    ? `${gap} 个入口需要处理防护缺口`
    : observed
      ? "防护已启用，仍有入口处于仅检测"
      : blocking
        ? "当前节点已配置请求拦截"
        : "当前节点还没有可用的防护入口";
  const banner = $("#protection-banner");
  banner.dataset.state = gap
    ? "warning"
    : observed
      ? "info"
      : blocking
        ? "ready"
        : "empty";
  $("#protection-copy").textContent =
    `${blocking} 个入口检测并拦截 · ${observed} 个入口仅检测 · ` +
    `${unprotected} 个入口未挂载 · ${disabled} 个入口已停用。模式以节点实际应用的配置为准。`;
  const available = !eventFailure && latestState?.events_available === true;
  ["deny", "observe", "skip"].forEach((mode) => {
    $("#stat-" + mode).textContent = available
      ? (latestEvents?.summary?.[mode] ?? 0)
      : "—";
  });
  const status = $("#event-source-status");
  status.dataset.state = eventFailure ? "warning" : "info";
  status.textContent =
    eventFailure ||
    "统计仅基于宿主返回的近期记录，可能不完整；现有接口不提供采集健康状态。";
  const attention = [];
  if (unprotected)
    attention.push({
      title: `${unprotected} 个入口存在防护缺口`,
      copy: "这些入口的请求没有经过 Web 防火墙检查。先到防护范围确认挂载。",
      tab: "scope",
      label: "检查入口",
    });
  if (disabled)
    attention.push({
      title: `${disabled} 个入口已停用`,
      copy: "停用的入口不再接受检查；确认后重新启用或删除入口。",
      tab: "scope",
      label: "检查范围",
    });
  if (observed)
    attention.push({
      title: `${observed} 个入口只检测、不拦截`,
      copy: "先检查误报；确认业务正常后启用拦截。",
      tab: "scope",
      label: "检查模式",
    });
  if (!available)
    attention.push({
      title: "检测结果尚不能完整确认",
      copy: status.textContent,
      tab: "events",
      label: "查看事件",
    });
  if (latestEvents?.summary?.skip)
    attention.push({
      title: "存在未完成的请求检查",
      copy: "请求体截断或来源无法验证，都需要进一步排查。",
      mode: "skip",
      label: "调查原因",
    });
  const root = $("#attention-list");
  root.replaceChildren();
  if (!attention.length) {
    const item = document.createElement("li");
    item.className = "waf-attention__empty";
    const mark = document.createElement("span");
    mark.className = "waf-status-icon";
    mark.dataset.tone = "success";
    mark.setAttribute("aria-hidden", "true");
    mark.textContent = "✓";
    const copy = document.createElement("div");
    const strong = document.createElement("strong");
    strong.textContent = "当前没有待处理的配置问题";
    const detail = document.createElement("p");
    detail.textContent = "请持续查看安全事件，留意误报和检查失败。";
    copy.append(strong, detail);
    item.append(mark, copy);
    root.append(item);
  }
  attention.forEach((task) => {
    const item = document.createElement("li");
    item.className = "waf-attention__item";
    const mark = document.createElement("span");
    mark.className = "waf-status-icon";
    mark.dataset.tone = "warning";
    mark.setAttribute("aria-hidden", "true");
    mark.textContent = "!";
    const copy = document.createElement("div");
    const strong = document.createElement("strong");
    strong.textContent = task.title;
    const detail = document.createElement("p");
    detail.textContent = task.copy;
    copy.append(strong, detail);
    const button = document.createElement("button");
    button.type = "button";
    button.className = "ui-btn ui-btn--ghost ui-btn--sm";
    button.textContent = `${task.label} →`;
    button.addEventListener("click", () =>
      task.mode ? showEvents(task.mode) : switchTab(task.tab),
    );
    item.append(mark, copy, button);
    root.append(item);
  });
  $("#capability-list").innerHTML = ruleGroups(latestState?.managed_rules)
    .map(
      (group) =>
        `<div class="waf-capability"><span class="waf-status-icon" data-tone="success" aria-hidden="true">✓</span><span class="waf-capability__copy"><strong>${group.name}</strong><small>${group.copy}</small></span><span class="ui-badge ui-badge--plain">${group.rules.length}</span></div>`,
    )
    .join("");
  $("#policy-summary").textContent =
    `${latestState?.managed_rules?.length || 0} 项内置检测 · ` +
    `${latestState?.custom_rules?.length || 0} 条自定义规则 · ` +
    `${latestState?.exclusions?.length || 0} 项排除`;
  const recent = $("#recent-events");
  recent.replaceChildren();
  const events = (latestEvents?.recent || latestEvents?.events || []).slice(
    0,
    5,
  );
  if (eventFailure || !events.length) {
    const empty = document.createElement("p");
    empty.className = "ui-empty waf-inline-empty";
    empty.textContent =
      eventFailure || "宿主当前没有返回相关记录，不能据此判断未发生攻击。";
    recent.append(empty);
  } else {
    const wrap = document.createElement("div");
    wrap.className = "ui-table-wrap";
    const table = document.createElement("table");
    table.className = "ui-table waf-events-table";
    table.setAttribute("aria-label", "最近安全事件");
    const body = document.createElement("tbody");
    events.forEach((event) => body.append(eventRow(event)));
    table.append(body);
    wrap.append(table);
    recent.append(wrap);
  }
};

const renderWorkspace = async () => {
  const sequence = ++requestSequence;
  setLoading(true, "正在加载防护状态…");
  hideFailure();
  showStatus("", false);
  if (!selectedAgentID) {
    setLoading(false);
    showContext("node-empty");
    return;
  }
  const query = new URLSearchParams({
    agent_id: selectedAgentID,
    page_size: "10",
    entry_page: listState.entry.page,
    entry_query: listState.entry.query,
    entry_mode: listState.entry.mode,
  });
  query.set("event_page", listState.event.page);
  query.set("event_query", listState.event.query);
  query.set("event_mode", listState.event.mode);
  try {
    const payload = await panelJSON(`api/state?${query}`);
    if (sequence !== requestSequence) return;
    latestState = payload;
    latestEvents = {
      events: payload.events || [],
      recent: payload.recent_events || [],
      summary: payload.event_summary || {},
      ...payload.events_page,
    };
    eventFailure = payload.events_available ? null : "宿主事件记录暂时不可用。";
    if (latestState.ready === false) {
      showContext("unavailable");
      return;
    }
    showContext("");
    renderEntries(latestState.entries || []);
    renderPagination("entry", latestState.entries_page);
    renderEvents();
    renderRules();
    renderOverview();
    if (latestState.error) showStatus(latestState.error, true);
  } finally {
    if (sequence === requestSequence) setLoading(false);
  }
};

const refreshWorkspace = async () => {
  const refreshButton = $("#refresh-state");
  if (refreshButton) {
    refreshButton.disabled = true;
    refreshButton.setAttribute("aria-busy", "true");
    refreshButton.textContent = "正在刷新…";
  }
  try {
    await renderWorkspace();
  } catch (error) {
    console.error("[waf] refresh failed", error);
    if (failureCopy(error).kind === "denied") showFailure(error);
    else {
      setLoading(false);
      showStatus(failureCopy(error).desc, true);
    }
  } finally {
    if (refreshButton) {
      refreshButton.disabled = false;
      refreshButton.removeAttribute("aria-busy");
      refreshButton.textContent = "刷新数据";
    }
  }
};
$("#refresh-state")?.addEventListener("click", refreshWorkspace);

["entry", "event"].forEach((kind) => {
  const search = (event) => {
    event?.preventDefault();
    listState[kind].page = 1;
    listState[kind].query = $("#" + kind + "-query").value.trim();
    listState[kind].mode = $("#" + kind + "-mode").value;
    refreshWorkspace();
  };
  $("#" + kind + "-search-form")?.addEventListener("submit", search);
  $("#" + kind + "-mode")?.addEventListener("change", search);
});

agentPicker.onChange = async (value) => {
  const next = String(value || "");
  if (next === selectedAgentID) return;
  if (hasDirtyRuleForm()) {
    const discard = await askConfirm({
      title: "改动尚未保存",
      desc: "切换节点会关闭规则表单。丢弃后已填写的内容会被清空，规则不会被添加。",
      label: "丢弃并切换",
    });
    if (!discard) {
      agentPicker.setValue(selectedAgentID);
      return;
    }
  }
  closeRuleDialog();
  selectedAgentID = next;
  eventDialog?.close();
  settleConfirm(false);
  workspaceNode.hidden = true;
  latestState = null;
  latestEvents = null;
  ["entry", "event"].forEach((kind) => {
    listState[kind] = { page: 1, query: "", mode: "" };
    $("#" + kind + "-query").value = "";
    $("#" + kind + "-mode").value = "";
  });
  const url = new URL(window.location.href);
  if (selectedAgentID) url.searchParams.set("agent_id", selectedAgentID);
  else url.searchParams.delete("agent_id");
  window.history.replaceState({}, "", url);
  await refreshWorkspace();
};

[
  ["#global-observe", "observe"],
  ["#global-deny", "deny"],
].forEach(([selector, mode]) => {
  $(selector)?.addEventListener("click", async () => {
    if (mode === "deny") {
      const confirmed = await askConfirm({
        title: "切换为检测并拦截",
        desc: "将把当前节点的已挂载入口切为检测并拦截：命中规则的请求会立即被拒绝，可随时切回仅检测。",
        label: "确认切换",
      });
      if (!confirmed) return;
    }
    if (globalObserve) globalObserve.disabled = true;
    if (globalDeny) globalDeny.disabled = true;
    try {
      await panelJSON("api/entries/mode-all", {
        method: "POST",
        body: JSON.stringify({ agent_id: selectedAgentID, mode }),
      });
      await refreshWorkspace();
      showStatus("已更新当前节点的入口模式。", false);
    } catch (error) {
      await refreshWorkspace();
      showStatus(`${error.message} 部分入口可能已更新，请检查当前状态。`, true);
    } finally {
      if (globalObserve) globalObserve.disabled = false;
      if (globalDeny) globalDeny.disabled = false;
    }
  });
});

const bindDialog = (dialog, selector) => {
  document
    .querySelectorAll(selector)
    .forEach((button) =>
      button.addEventListener("click", () => dialog?.close()),
    );
  dialog?.addEventListener("click", (event) => {
    if (event.target !== dialog) return;
    const rect = dialog.getBoundingClientRect();
    if (
      event.clientX < rect.left ||
      event.clientX > rect.right ||
      event.clientY < rect.top ||
      event.clientY > rect.bottom
    )
      dialog.close();
  });
};
const bindRuleDialog = () => {
  document
    .querySelectorAll("#close-rule-dialog,[data-close-dialog]")
    .forEach((button) =>
      button.addEventListener("click", () => void requestRuleDialogClose()),
    );
  ruleDialog?.addEventListener("click", (event) => {
    if (event.target !== ruleDialog) return;
    const rect = ruleDialog.getBoundingClientRect();
    if (
      event.clientX < rect.left ||
      event.clientX > rect.right ||
      event.clientY < rect.top ||
      event.clientY > rect.bottom
    )
      void requestRuleDialogClose();
  });
  ruleDialog?.addEventListener("cancel", (event) => {
    event.preventDefault();
    void requestRuleDialogClose();
  });
  ruleDialog?.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || event.isComposing) return;
    if (confirmDialog?.open) return;
    event.preventDefault();
    event.stopPropagation();
    void requestRuleDialogClose();
  });
};
bindRuleDialog();
bindDialog(eventDialog, "[data-close-event]");

[
  [customForm, "api/custom-rules"],
  [exclusionForm, "api/exclusions"],
].forEach(([form, path]) => {
  form?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = form.querySelector("[type=submit]");
    if (submit.disabled) return;
    submit.disabled = true;
    submit.setAttribute("aria-busy", "true");
    const alert = $("#rule-dialog-error");
    if (alert) {
      alert.hidden = true;
      alert.textContent = "";
    }
    clearFormFieldErrors(form);
    try {
      const body = Object.fromEntries(new FormData(form));
      body.agent_id = selectedAgentID;
      await panelJSON(path, { method: "POST", body: JSON.stringify(body) });
      closeRuleDialog();
      await refreshWorkspace();
      showStatus("规则已添加。", false);
    } catch (error) {
      showSubmitError(form, alert, error);
    } finally {
      submit.disabled = false;
      submit.removeAttribute("aria-busy");
    }
  });
});

if (typeof window.addEventListener === "function") {
  window.addEventListener("beforeunload", (event) => {
    if (!hasDirtyRuleForm()) return;
    event.preventDefault();
    event.returnValue = "";
  });
}

$("#app-unavailable-retry")?.addEventListener("click", () => void start());
$("#app-denied-retry")?.addEventListener("click", () => void start());

const start = async () => {
  setLoading(true, "正在加载防护状态…");
  hideFailure();
  try {
    await loadAgents();
    await renderWorkspace();
  } catch (error) {
    console.error("[waf] start failed", error);
    showFailure(error);
  } finally {
    setLoading(false);
  }
};
start();