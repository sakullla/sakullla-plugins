const applyHostTheme = () => {
  const allowed = { light: true, dark: true };
  const aliases = {
    "sakura-day": "light",
    business: "light",
    "fresh-green": "light",
    sakura: "light",
    cyberpunk: "light",
    "sakura-night": "dark",
    "neko-dark": "dark",
    midnight: "dark",
  };
  let theme = "light";
  try {
    const raw =
      window.parent && window.parent !== window
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
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: { ...panelAuthHeaders(), ...(options.headers || {}) },
  });
  const payload = await response.json().catch(() => ({}));
  if (response.status === 403) {
    throw Object.assign(new Error(payload.error || "无权管理 Web 防火墙。"), {
      denied: true,
      status: 403,
    });
  }
  if (!response.ok) {
    throw Object.assign(
      new Error(payload.error || payload.message || "请求失败"),
      { status: response.status, unavailable: response.status === 503 },
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
const formatTime = (value) =>
  value && Number.isFinite(Date.parse(value))
    ? new Date(value).toLocaleString("zh-CN", { hour12: false })
    : "—";
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
    trigger.setAttribute("aria-selected", String(name === tab));
    trigger.tabIndex = name === tab ? 0 : -1;
    $("#view-" + name).hidden = name !== tab;
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
      document.querySelectorAll(selector)[next].focus();
    });
  });
};
bindTabs(
  ".main-tabs [data-tab]",
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
    node.className = "btn-secondary";
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
  $("#" + kind + "-count").textContent = info.total;
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

const renderEntries = (entries = []) => {
  entryList.replaceChildren();
  emptyNode.hidden = entries.length > 0;
  emptyNode.textContent =
    listState.entry.query || listState.entry.mode
      ? "没有符合条件的入口，请调整查询条件。"
      : "还没有 HTTP 入口。";
  entries.forEach((entry) => {
    const item = document.createElement("li");
    item.className = "entry-card";
    const mode = entry.overlay_invalid || !entry.attached ? "skip" : entry.mode;
    const label = !entry.enabled
      ? "入口已停用"
      : entry.overlay_invalid
        ? "防护配置异常"
        : !entry.attached
          ? "未挂载防护"
          : mode === "deny"
            ? "检测并拦截"
            : "仅检测";
    item.innerHTML = `<div><header><strong>${escapeText(entry.frontend_url || entry.rule_ref)}</strong><span class="badge" data-mode="${mode}">${label}</span></header><p class="meta">后端 · ${escapeText(entry.backend || "未配置")}</p>${entry.notice ? `<p class="notice">${escapeText(entry.notice)}</p>` : ""}</div><div class="workspace-head-actions"><div class="mode-switch" role="group" aria-label="入口防护模式"><button data-mode="observe" type="button" aria-pressed="${mode === "observe"}">仅检测</button><button data-mode="deny" type="button" aria-pressed="${mode === "deny"}">检测并拦截</button></div><button class="btn-link" data-events type="button">查看事件</button></div>`;
    const controls = item.querySelectorAll("[data-mode][type=button]");
    controls.forEach((button) => {
      button.disabled =
        !entry.enabled || !entry.attached || entry.overlay_invalid;
      button.title =
        button.dataset.mode === "deny"
          ? "仅拒绝命中 WAF 规则的请求"
          : "记录命中，不阻断请求";
      button.addEventListener("click", async () => {
        controls.forEach((control) => {
          control.disabled = true;
        });
        try {
          await panelJSON("api/entries/mode", {
            method: "POST",
            body: JSON.stringify({
              agent_id: selectedAgentID,
              rule_ref: entry.rule_ref,
              mode: button.dataset.mode,
            }),
          });
          await refreshWorkspace();
        } catch (error) {
          showStatus(error.message, true);
        } finally {
          controls.forEach((control) => {
            control.disabled =
              !entry.enabled || !entry.attached || entry.overlay_invalid;
          });
        }
      });
    });
    item.querySelector("[data-events]").addEventListener("click", () => {
      let site = entry.frontend_url || "";
      try {
        site = new URL(site).host;
      } catch {}
      showEvents("", site);
    });
    entryList.append(item);
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
    `<span class="badge" data-mode="${eventMode(event)}">${eventLabel(event)}</span><dl class="event-fields">${fields.map(([key, value]) => `<div><dt>${key}</dt><dd>${escapeText(value)}</dd></div>`).join("")}</dl><p class="event-explanation">${eventMode(event) === "deny" ? "该请求命中检测规则，WAF 已拒绝请求。请结合业务判断是否为误报。" : eventMode(event) === "observe" ? "该请求命中检测规则，但入口处于仅检测模式，请求仍然放行。" : "本次检查未完整完成，不能据此判断请求安全。请先查看检查说明。"}</p>`;
  const actionable = !!event.rule_id && event.reason === "rule_matched";
  $("#event-create-exclusion").disabled = !actionable;
  $("#event-create-exclusion").title = actionable
    ? ""
    : "只有命中具体规则的记录才能创建排除";
  eventDialog.showModal();
};
const eventRow = (event) => {
  const row = document.createElement("tr");
  row.innerHTML = `<td><strong>${escapeText(event.site || "未标记站点")}</strong></td><td><span>${escapeText(event.rule_id || "检查异常")}</span><small>${escapeText(reasonLabel(event.reason))}</small></td><td><span class="badge" data-mode="${eventMode(event)}">${eventLabel(event)}</span></td><td><button type="button" class="btn-link">详情 →</button></td>`;
  row
    .querySelector("button")
    .addEventListener("click", () => eventDetail(event));
  return row;
};
const renderEvents = () => {
  eventList.replaceChildren();
  const events = latestEvents?.events || [];
  events.forEach((event) => eventList.append(eventRow(event)));
  eventEmpty.hidden = events.length > 0 && !eventFailure;
  eventEmpty.textContent =
    eventFailure || "宿主当前未返回相关记录，不能据此判断未发生攻击。";
  if (
    !eventFailure &&
    (listState.event.query || listState.event.mode) &&
    events.length === 0
  )
    eventEmpty.textContent = "当前记录中没有符合条件的事件，请调整筛选条件。";
  $("#event-panel .events-table").hidden = eventEmpty.hidden === false;
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
    $("#" + name + "-tab").setAttribute("aria-selected", String(name === tab));
    $("#" + name + "-tab").tabIndex = name === tab ? 0 : -1;
    $("#" + name + "-rule-panel").hidden = name !== tab;
  });
  $("#add-rule").textContent =
    tab === "exclusion" ? "＋ 添加排除规则" : "＋ 添加自定义规则";
};
bindTabs(
  ".rule-tabs [role=tab]",
  ["managed", "custom", "exclusion"],
  () => activeRuleTab,
  switchRuleTab,
);
const openRuleDialog = (kind, event = null) => {
  customForm.hidden = kind !== "custom";
  exclusionForm.hidden = kind !== "exclusion";
  $("#rule-dialog-title").textContent =
    kind === "custom" ? "添加自定义规则" : "添加排除";
  $("#rule-dialog-error").hidden = true;
  if (event) {
    exclusionForm.reset();
    exclusionForm.elements.rule_id.value = event.rule_id;
    exclusionForm.elements.path_prefix.value = "";
  }
  ruleDialog.showModal();
};
$("#add-rule")?.addEventListener("click", () =>
  openRuleDialog(activeRuleTab === "exclusion" ? "exclusion" : "custom"),
);
$("#event-create-exclusion")?.addEventListener("click", () => {
  const event = detailEvent;
  eventDialog.close();
  switchTab("rules");
  switchRuleTab("exclusion");
  openRuleDialog("exclusion", event);
});
const renderRules = () => {
  const managed = latestState?.managed_rules || [];
  $("#managed-count").textContent = managed.length;
  $("#managed-list").innerHTML = ruleGroups(managed)
    .map(
      (group) =>
        `<details class="managed-group"><summary><span><strong>${group.name}</strong><small>${group.copy}</small></span><span class="count">${group.rules.length} 项检测</span></summary><div class="managed-rows">${group.rules.map((rule) => `<div><span><strong>${escapeText(rule.id)}</strong><small>${targetLabel(rule.target)}</small></span><code>${escapeText(rule.needle)}</code></div>`).join("")}</div></details>`,
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
      item.className = "rule-card";
      item.innerHTML = `<div><strong>${escapeText(rule.id || rule.rule_id)}</strong><p class="meta">${kind === "custom" ? targetLabel(rule.target) : "排除路径前缀"}</p></div><code>${escapeText(rule.needle || rule.path_prefix)}</code><button class="btn-link" type="button">删除</button>`;
      const button = item.querySelector("button");
      button.title =
        kind === "custom" ? "删除规则及其关联排除" : "删除后恢复对此路径的检查";
      button.addEventListener("click", async () => {
        button.disabled = true;
        try {
          await panelJSON(
            kind === "custom" ? "api/custom-rules" : "api/exclusions",
            {
              method: "DELETE",
              body: JSON.stringify({ ...rule, agent_id: selectedAgentID }),
            },
          );
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
      });
      root.append(item);
    });
  });
};

const renderOverview = () => {
  const coverage = latestState?.coverage || {};
  const unprotected = coverage.unprotected || 0,
    observed = coverage.observe || 0,
    blocking = coverage.deny || 0;
  $("#protection-title").textContent = unprotected
    ? "存在尚未受保护的入口"
    : observed
      ? "部分入口仍在仅检测"
      : blocking
        ? "已配置请求拦截"
        : "尚无启用的防护入口";
  $("#protection-banner").dataset.state =
    unprotected || observed ? "warning" : blocking ? "ready" : "empty";
  $("#protection-copy").textContent =
    `${blocking} 个入口检测并拦截 · ${observed} 个入口仅检测 · ${unprotected} 个入口需处理。模式以节点实际应用的配置为准。`;
  const available = !eventFailure && latestState?.events_available === true;
  ["deny", "observe", "skip"].forEach((mode) => {
    $("#stat-" + mode).textContent = available
      ? (latestEvents?.summary?.[mode] ?? 0)
      : "—";
  });
  const status = $("#event-source-status");
  status.dataset.state = "warning";
  status.textContent =
    eventFailure ||
    "统计仅基于宿主返回的近期记录，可能不完整；现有接口不提供采集健康状态。";
  const attention = [];
  if (unprotected)
    attention.push({
      title: `${unprotected} 个入口存在防护缺口`,
      copy: "检查未挂载的防护或无效配置。",
      tab: "scope",
      label: "检查入口",
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
    item.innerHTML =
      '<span class="attention-mark">✓</span><div><strong>当前没有待处理的配置问题</strong><p>请持续查看安全事件，留意误报和检查失败。</p></div>';
    root.append(item);
  }
  attention.forEach((task) => {
    const item = document.createElement("li");
    item.innerHTML = `<span class="attention-mark">!</span><div><strong>${task.title}</strong><p>${escapeText(task.copy)}</p></div><button class="btn-link" type="button">${task.label} →</button>`;
    item
      .querySelector("button")
      .addEventListener("click", () =>
        task.mode ? showEvents(task.mode) : switchTab(task.tab),
      );
    root.append(item);
  });
  $("#capability-list").innerHTML = ruleGroups(latestState?.managed_rules)
    .map(
      (group) =>
        `<div><span class="capability-mark">✓</span><span><strong>${group.name}</strong><small>${group.copy}</small></span><span class="count">${group.rules.length}</span></div>`,
    )
    .join("");
  $("#policy-summary").textContent =
    `${latestState?.managed_rules?.length || 0} 项内置检测 · ${latestState?.custom_rules?.length || 0} 条自定义规则 · ${latestState?.exclusions?.length || 0} 项排除`;
  const recent = $("#recent-events");
  recent.replaceChildren();
  const events = (latestEvents?.recent || latestEvents?.events || []).slice(
    0,
    5,
  );
  if (eventFailure || !events.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent =
      eventFailure || "宿主当前没有返回相关记录，不能据此判断未发生攻击。";
    recent.append(empty);
  } else {
    const table = document.createElement("table");
    table.className = "events-table";
    const body = document.createElement("tbody");
    events.forEach((event) => body.append(eventRow(event)));
    table.append(body);
    const scroll = document.createElement("div");
    scroll.className = "table-scroll";
    scroll.append(table);
    recent.append(scroll);
  }
};

const renderWorkspace = async () => {
  const sequence = ++requestSequence;
  loadingNode.hidden = true;
  deniedNode.hidden = true;
  unavailableNode.hidden = true;
  showStatus("", false);
  if (!selectedAgentID) {
    showContext("node-empty");
    return;
  }
  const entryQuery = new URLSearchParams({
    agent_id: selectedAgentID,
    page_size: "10",
    entry_page: listState.entry.page,
    entry_query: listState.entry.query,
    entry_mode: listState.entry.mode,
  });
  entryQuery.set("event_page", listState.event.page);
  entryQuery.set("event_query", listState.event.query);
  entryQuery.set("event_mode", listState.event.mode);
  const payload = await panelJSON(`api/state?${entryQuery}`);
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
};
const refreshWorkspace = async () => {
  $("#refresh-state").disabled = true;
  try {
    await renderWorkspace();
  } catch (error) {
    if (error.denied) {
      deniedNode.hidden = false;
      workspaceNode.hidden = true;
    } else showStatus(error.message, true);
  } finally {
    $("#refresh-state").disabled = false;
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
  selectedAgentID = String(value || "");
  ruleDialog?.close();
  eventDialog?.close();
  workspaceNode.hidden = true;
  latestState = null;
  latestEvents = null;
  ["entry", "event"].forEach((kind) => {
    listState[kind] = {
      page: 1,
      query: "",
      mode: "",
    };
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
    globalObserve.disabled = true;
    globalDeny.disabled = true;
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
      globalObserve.disabled = false;
      globalDeny.disabled = false;
    }
  });
});
const bindDialog = (dialog, selector) => {
  document
    .querySelectorAll(selector)
    .forEach((button) =>
      button.addEventListener("click", () => dialog.close()),
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
bindDialog(ruleDialog, "#close-rule-dialog,[data-close-dialog]");
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
    $("#rule-dialog-error").hidden = true;
    try {
      const body = Object.fromEntries(new FormData(form));
      body.agent_id = selectedAgentID;
      await panelJSON(path, { method: "POST", body: JSON.stringify(body) });
      form.reset();
      ruleDialog.close();
      await refreshWorkspace();
      showStatus("规则已添加。", false);
    } catch (error) {
      $("#rule-dialog-error").textContent = error.message;
      $("#rule-dialog-error").hidden = false;
    } finally {
      submit.disabled = false;
    }
  });
});
const start = async () => {
  try {
    await loadAgents();
    await renderWorkspace();
  } catch (error) {
    loadingNode.hidden = true;
    if (error.denied) deniedNode.hidden = false;
    else {
      unavailableNode.hidden = false;
      unavailableNode.textContent = error.message;
    }
  }
};
start();
