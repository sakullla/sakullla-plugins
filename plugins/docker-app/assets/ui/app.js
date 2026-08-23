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

const statusNode = document.querySelector("#app-status");
const loadingNode = document.querySelector("#app-loading");
const unavailableNode = document.querySelector("#app-unavailable");
const deniedNode = document.querySelector("#app-denied");
const workspaceNode = document.querySelector("#app-workspace");
const listNode = document.querySelector("#app-list");
const emptyNode = document.querySelector("#app-empty");
const countNode = document.querySelector("#app-count");
const createPanel = document.querySelector("#app-create");
const createForm = document.querySelector("#create-form");
const createTitle = document.querySelector("#app-create-title");
const createSubmit = document.querySelector("#create-submit");
const createCancel = document.querySelector("#create-cancel");
const deployToggle = document.querySelector("#deploy-toggle");
const agentSelect = document.querySelector("#agent-select");
const nodeHint = document.querySelector("#app-node-hint");
const offlineNode = document.querySelector("#app-offline");
const engineGuide = document.querySelector("#engine-guide");
const engineStatus = document.querySelector("#engine-status");
const engineScript = document.querySelector("#engine-install-script");
const daemonWrap = document.querySelector("#engine-daemon-json-wrap");
const daemonNode = document.querySelector("#engine-daemon-json");
const copyScript = document.querySelector("#copy-install-script");
const copyDaemon = document.querySelector("#copy-daemon-json");
const idInput = createForm ? createForm.querySelector('input[name="id"]') : null;
const composeInput = createForm ? createForm.querySelector('textarea[name="compose"]') : null;
const autoUpdateInput = createForm ? createForm.querySelector('input[name="auto_update"]') : null;

let busy = false;
let selectedAgentID = "";
let editingID = "";
let agentsCache = [];
let engineReady = false;
let agentOnline = false;

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
    throw Object.assign(new Error(payload.error || payload.message || "无权访问"), { denied: true });
  }
  if (!response.ok) {
    throw new Error(payload.error || payload.message || "请求失败");
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
  workspaceNode.querySelectorAll("button, input, textarea, select").forEach((node) => {
    if (node === agentSelect || node === copyScript || node === copyDaemon) return;
    node.disabled = next;
  });
};

const isAgentOnline = (agent) => Boolean(agent) && (agent.online === true || agent.status === "online");

const selectedAgent = () => agentsCache.find((agent) => agent.id === selectedAgentID) || null;

const openCreate = (app) => {
  if (!engineReady || !agentOnline) return;
  editingID = app ? String(app.id || "") : "";
  createTitle.textContent = editingID ? "更新应用" : "部署应用";
  createSubmit.textContent = editingID ? "保存" : "部署";
  if (idInput) {
    idInput.value = editingID;
    idInput.readOnly = Boolean(editingID);
  }
  if (composeInput) composeInput.value = app?.compose || "";
  if (autoUpdateInput) autoUpdateInput.checked = app?.auto_update === true;
  createPanel.hidden = false;
  deployToggle.hidden = true;
  if (composeInput) composeInput.focus();
};

const closeCreate = () => {
  editingID = "";
  createForm.reset();
  if (idInput) idInput.readOnly = false;
  createTitle.textContent = "部署应用";
  createSubmit.textContent = "部署";
  createPanel.hidden = true;
  deployToggle.hidden = !(selectedAgentID && engineReady && agentOnline);
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
  await renderWorkspace();
};

const renderApp = (app) => {
  const card = document.createElement("article");
  card.className = "app-card";
  card.dataset.id = app.id;
  const ports = Array.isArray(app.ports) && app.ports.length ? app.ports : parsePublishedPorts(app.compose);
  const version = app.version || parseImage(app.compose);
  const services = Array.isArray(app.services) && app.services.length ? app.services : [];

  const head = document.createElement("div");
  head.className = "app-card-head";
  const identity = document.createElement("div");
  const title = document.createElement("h3");
  title.textContent = app.id;
  const chips = document.createElement("div");
  chips.className = "app-chips";
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
  const versionChip = chip(version || "未解析镜像");
  versionChip.className = "chip app-version";
  chips.append(versionChip);
  if (ports.length) ports.forEach((port) => chips.append(chip(`:${port}`)));
  else chips.append(chip("无发布端口"));
  identity.append(title, chips);

  const actions = document.createElement("div");
  actions.className = "app-actions";
  const apiActions = Array.isArray(app.actions) && app.actions.length
    ? app.actions
    : [{ id: "configure", label: "编辑" }, { id: "delete", label: "删除" }];
  apiActions.forEach((action) => {
    if (action.id === "rollback") return;
    const button = document.createElement("button");
    button.type = "button";
    button.className = action.id === "delete" ? "btn-link danger" : "btn-link";
    button.dataset.action = action.id;
    button.textContent = action.id === "configure" ? "编辑" : (action.label || action.id);
    button.addEventListener("click", async () => {
      if (busy) return;
      if (action.id === "configure") {
        openCreate(app);
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
    });
    actions.append(button);
  });
  if (services.length) {
    const logsToggle = document.createElement("button");
    logsToggle.type = "button";
    logsToggle.className = "btn-link";
    logsToggle.dataset.action = "logs";
    logsToggle.textContent = "日志";
    logsToggle.addEventListener("click", () => {
      const panel = card.querySelector(".app-logs");
      if (panel) panel.hidden = !panel.hidden;
    });
    actions.append(logsToggle);
  }
  if (ports.length) {
    const httpToggle = document.createElement("button");
    httpToggle.type = "button";
    httpToggle.className = "btn-link";
    httpToggle.textContent = "挂 HTTP";
    httpToggle.addEventListener("click", () => {
      const form = card.querySelector(".http-form");
      if (form) form.hidden = !form.hidden;
    });
    actions.append(httpToggle);
  }
  head.append(identity, actions);
  card.append(head);

  if (app.compose) {
    const details = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = "Compose YAML";
    const pre = document.createElement("pre");
    pre.textContent = app.compose;
    details.append(summary, pre);
    card.append(details);
  }

  if (services.length) {
    const logsPanel = document.createElement("div");
    logsPanel.className = "app-logs";
    logsPanel.hidden = true;
    const serviceLabel = document.createElement("label");
    serviceLabel.append("服务");
    const serviceSelect = document.createElement("select");
    serviceSelect.name = "service";
    services.forEach((name) => {
      const option = document.createElement("option");
      option.value = name;
      option.textContent = name;
      serviceSelect.append(option);
    });
    serviceLabel.append(serviceSelect);
    const loadLogs = document.createElement("button");
    loadLogs.type = "button";
    loadLogs.className = "btn-primary";
    loadLogs.textContent = "查看日志";
    const logView = document.createElement("pre");
    loadLogs.addEventListener("click", async () => {
      if (busy) return;
      setBusy(true);
      try {
        const payload = await sendPluginJSON(`api/apps/${encodeURIComponent(app.id)}/logs`, {
          service: serviceSelect.value,
        });
        logView.textContent = payload.logs || "";
        showStatus("已加载日志。", false);
      } catch (error) {
        showStatus(error.message, true);
      } finally {
        setBusy(false);
      }
    });
    logsPanel.append(serviceLabel, loadLogs, logView);
    card.append(logsPanel);
  }

  if (ports.length) {
    const form = document.createElement("form");
    form.className = "http-form";
    form.hidden = true;
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
        form.hidden = true;
        form.reset();
        await renderWorkspace();
      } catch (error) {
        showStatus(error.message, true);
      } finally {
        setBusy(false);
      }
    });
    card.append(form);
  } else {
    const hint = document.createElement("p");
    hint.className = "hint";
    hint.textContent = "没有可挂的端口";
    card.append(hint);
  }
  return card;
};

const loadEngine = async () => {
  if (!selectedAgentID) return null;
  const payload = await panelJSON(`api/engine?agent_id=${encodeURIComponent(selectedAgentID)}`);
  return payload.engine || null;
};

const renderGuide = (engine) => {
  const command = engine?.command || {};
  if (engineScript) engineScript.textContent = command.script || "";
  const daemonJSON = command.daemon_json || "";
  if (daemonNode) daemonNode.textContent = daemonJSON;
  if (daemonWrap) daemonWrap.hidden = !daemonJSON;
};

const renderApps = (apps) => {
  const list = Array.isArray(apps) ? apps : [];
  listNode.replaceChildren(...list.map(renderApp));
  emptyNode.hidden = !selectedAgentID || !engineReady || list.length > 0;
  countNode.hidden = list.length === 0;
  countNode.textContent = `${list.length} 个`;
};

const renderWorkspace = async () => {
  const agent = selectedAgent();
  agentOnline = isAgentOnline(agent);
  engineReady = false;
  if (!selectedAgentID) {
    if (engineGuide) engineGuide.hidden = true;
    if (offlineNode) offlineNode.hidden = true;
    if (engineStatus) engineStatus.hidden = true;
    nodeHint.hidden = false;
    nodeHint.textContent = "请选择一台在线节点后再管理应用。";
    emptyNode.hidden = true;
    closeCreate();
    deployToggle.hidden = true;
    renderApps([]);
    return;
  }
  nodeHint.hidden = true;
  if (!agentOnline) {
    if (engineGuide) engineGuide.hidden = true;
    if (offlineNode) offlineNode.hidden = false;
    if (engineStatus) {
      engineStatus.hidden = false;
      engineStatus.textContent = "Agent 执行面 · 节点离线";
    }
    closeCreate();
    deployToggle.hidden = true;
    emptyNode.hidden = true;
    renderApps([]);
    return;
  }
  if (offlineNode) offlineNode.hidden = true;
  const engine = await loadEngine();
  engineReady = engine?.ready === true;
  if (engineStatus) {
    engineStatus.hidden = false;
    engineStatus.textContent = engineReady
      ? (engine.version ? `Agent 执行面 · 引擎 ${engine.version} 已就绪` : "Agent 执行面 · 引擎已就绪")
      : "Agent 执行面 · 引擎未就绪";
  }
  if (!engineReady) {
    renderGuide(engine);
    if (engineGuide) engineGuide.hidden = false;
    closeCreate();
    deployToggle.hidden = true;
    emptyNode.hidden = true;
    renderApps([]);
    return;
  }
  if (engineGuide) engineGuide.hidden = true;
  deployToggle.hidden = createPanel.hidden === false ? true : false;
  const payload = await panelJSON(`api/apps?agent_id=${encodeURIComponent(selectedAgentID)}`);
  renderApps(payload.apps);
};

const loadAgents = async () => {
  const payload = await panelJSON("/panel-api/agents");
  agentsCache = Array.isArray(payload.agents)
    ? payload.agents.filter((agent) => agent && agent.is_local !== true && agent.mode !== "local")
    : [];
  const requested = new URLSearchParams(window.location.search).get("agent_id") || "";
  agentSelect.replaceChildren();
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = agentsCache.length ? "选择节点" : "暂无节点";
  agentSelect.append(placeholder);
  agentsCache.forEach((agent) => {
    const option = document.createElement("option");
    option.value = agent.id;
    const label = agent.name && agent.name !== agent.id ? `${agent.name} · ${agent.id}` : (agent.name || agent.id);
    option.textContent = isAgentOnline(agent) ? label : `${label}（离线）`;
    agentSelect.append(option);
  });
  selectedAgentID = agentsCache.some((agent) => agent.id === requested)
    ? requested
    : (agentsCache.length === 1 ? agentsCache[0].id : "");
  agentSelect.value = selectedAgentID;
};

if (agentSelect) {
  agentSelect.addEventListener("change", async () => {
    selectedAgentID = agentSelect.value;
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
  });
}

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
      showStatus("引擎未就绪，请先在该节点本机安装 Docker。", true);
      return;
    }
    openCreate(null);
  });
}

if (createCancel) createCancel.addEventListener("click", closeCreate);

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
      auto_update: data.get("auto_update") === "on",
    };
    const updating = Boolean(editingID);
    setBusy(true);
    try {
      await sendPluginJSON("api/apps", nextApp);
      closeCreate();
      await renderWorkspace();
      showStatus(updating ? "已更新应用。" : "已部署应用。", false);
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
