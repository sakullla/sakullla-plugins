const PLUGIN_ID = "docker-app";

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
const idInput = createForm ? createForm.querySelector('input[name="id"]') : null;
const composeInput = createForm ? createForm.querySelector('textarea[name="compose"]') : null;
const autoUpdateInput = createForm ? createForm.querySelector('input[name="auto_update"]') : null;

let busy = false;
let pluginDetail = null;
let selectedAgentID = "";
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
    if (node === agentSelect) return;
    node.disabled = next;
  });
};

const openCreate = (app) => {
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
  deployToggle.hidden = !selectedAgentID;
};

const instanceTargetsAgent = (instance, agentID) => {
  const target = String(agentID || "").trim();
  if (!instance || !target) return false;
  const targets = Array.isArray(instance.targets) ? instance.targets : [];
  if (targets.some((item) => String(item || "").trim() === target)) return true;
  const bindings = Array.isArray(instance.bindings) ? instance.bindings : [];
  return bindings.some((binding) => String(binding?.target_agent_id || "").trim() === target);
};

const instanceForAgent = (detail, agentID) => {
  const instances = Array.isArray(detail?.instances) ? detail.instances : [];
  return instances.find((instance) => instanceTargetsAgent(instance, agentID)) || null;
};

const appsFromInstance = (instance) => {
  const apps = instance?.config?.apps;
  return Array.isArray(apps) ? apps.filter((app) => app && typeof app === "object") : [];
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

const defaultGroupID = (groups) => {
  const list = Array.isArray(groups) ? groups.filter((group) => group && group.id) : [];
  if (list.some((group) => group.id === "default")) return "default";
  return list[0]?.id || "";
};

const loadPluginDetail = async () => {
  pluginDetail = await panelJSON(`/panel-api/plugins/${encodeURIComponent(PLUGIN_ID)}`);
  return pluginDetail;
};

const saveApps = async (apps) => {
  const instance = instanceForAgent(pluginDetail, selectedAgentID);
  const groups = await panelJSON("/panel-api/access/resource-groups").catch(() => ({}));
  const groupList = Array.isArray(groups?.resource_groups) ? groups.resource_groups : [];
  const resourceGroupID = String(instance?.resource_group_id || defaultGroupID(groupList) || "").trim();
  if (!resourceGroupID) throw new Error("当前没有可用的资源组，无法部署。");
  const instanceID = String(instance?.id || `${PLUGIN_ID}-${selectedAgentID}`).slice(0, 128);
  const request = {
    instance_id: instanceID,
    resource_group_id: resourceGroupID,
    targets: [selectedAgentID],
    policy_chains: Array.isArray(instance?.policy_chains) ? instance.policy_chains : [],
    config: {
      apps,
      registry_mirror: instance?.config?.registry_mirror || "",
    },
  };
  if (!instance) request.bindings = [];
  await sendPluginJSON(`/panel-api/plugins/${encodeURIComponent(PLUGIN_ID)}/configure`, request);
  const lifecycle = pluginDetail?.plugin?.desired_lifecycle || pluginDetail?.plugin?.current_lifecycle;
  if (lifecycle && lifecycle !== "enabled" && lifecycle !== "active") {
    await sendPluginJSON(`/panel-api/plugins/${encodeURIComponent(PLUGIN_ID)}/enable`, {});
  }
  await loadPluginDetail();
};

const chip = (text) => {
  const node = document.createElement("span");
  node.className = "chip";
  node.textContent = text;
  return node;
};

const renderApp = (app) => {
  const card = document.createElement("article");
  card.className = "app-card";
  card.dataset.id = app.id;
  const ports = parsePublishedPorts(app.compose);
  const version = parseImage(app.compose);

  const head = document.createElement("div");
  head.className = "app-card-head";
  const identity = document.createElement("div");
  const title = document.createElement("h3");
  title.textContent = app.id;
  const chips = document.createElement("div");
  chips.className = "app-chips";
  chips.append(chip(version || "未解析镜像"));
  if (ports.length) ports.forEach((port) => chips.append(chip(`:${port}`)));
  else chips.append(chip("无发布端口"));
  identity.append(title, chips);

  const actions = document.createElement("div");
  actions.className = "app-actions";
  const edit = document.createElement("button");
  edit.type = "button";
  edit.className = "btn-link";
  edit.textContent = "编辑";
  edit.addEventListener("click", () => {
    if (!busy) openCreate(app);
  });
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "btn-link danger";
  remove.textContent = "删除";
  remove.addEventListener("click", async () => {
    if (busy) return;
    if (!window.confirm(`确认删除 ${app.id}？取消不会更改应用。`)) {
      showStatus("已取消，应用未更改。", false);
      return;
    }
    setBusy(true);
    try {
      const instance = instanceForAgent(pluginDetail, selectedAgentID);
      await saveApps(appsFromInstance(instance).filter((item) => item.id !== app.id));
      closeCreate();
      renderApps();
      showStatus("已删除应用。", false);
    } catch (error) {
      showStatus(error.message, true);
    } finally {
      setBusy(false);
    }
  });
  actions.append(edit, remove);
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
      } catch (error) {
        showStatus(error.message, true);
      } finally {
        setBusy(false);
      }
    });
    card.append(form);
  }
  return card;
};

const renderApps = () => {
  const instance = instanceForAgent(pluginDetail, selectedAgentID);
  const apps = appsFromInstance(instance);
  listNode.replaceChildren(...apps.map(renderApp));
  emptyNode.hidden = !selectedAgentID || apps.length > 0;
  countNode.hidden = apps.length === 0;
  countNode.textContent = `${apps.length} 个`;
  deployToggle.hidden = createPanel.hidden === false ? true : !selectedAgentID;
  if (!selectedAgentID) {
    nodeHint.hidden = false;
    nodeHint.textContent = "请选择一台节点后再管理应用。";
    emptyNode.hidden = true;
    closeCreate();
    deployToggle.hidden = true;
  } else if (!instance) {
    nodeHint.hidden = false;
    nodeHint.textContent = "这台节点还没有本插件。第一次部署会同时把它装到该节点。";
  } else {
    nodeHint.hidden = true;
  }
};

const loadAgents = async () => {
  const payload = await panelJSON("/panel-api/agents");
  const agents = Array.isArray(payload.agents) ? payload.agents : [];
  const requested = new URLSearchParams(window.location.search).get("agent_id") || "";
  agentSelect.replaceChildren();
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = agents.length ? "选择节点" : "暂无节点";
  agentSelect.append(placeholder);
  agents.forEach((agent) => {
    const option = document.createElement("option");
    option.value = agent.id;
    option.textContent = agent.name && agent.name !== agent.id ? `${agent.name} · ${agent.id}` : (agent.name || agent.id);
    agentSelect.append(option);
  });
  selectedAgentID = agents.some((agent) => agent.id === requested)
    ? requested
    : (agents.length === 1 ? agents[0].id : "");
  agentSelect.value = selectedAgentID;
};

if (agentSelect) {
  agentSelect.addEventListener("change", () => {
    selectedAgentID = agentSelect.value;
    const url = new URL(window.location.href);
    if (selectedAgentID) url.searchParams.set("agent_id", selectedAgentID);
    else url.searchParams.delete("agent_id");
    window.history.replaceState({}, "", url);
    closeCreate();
    renderApps();
  });
}

if (deployToggle) {
  deployToggle.addEventListener("click", () => {
    if (!selectedAgentID) {
      showStatus("请先选择一台节点。", true);
      return;
    }
    openCreate(null);
  });
}

if (createCancel) createCancel.addEventListener("click", closeCreate);

if (createForm) {
  createForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) return;
    if (!selectedAgentID) {
      showStatus("请先选择一台节点。", true);
      return;
    }
    const data = new FormData(createForm);
    const nextApp = {
      id: String(data.get("id") || "").trim(),
      compose: String(data.get("compose") || ""),
      auto_update: data.get("auto_update") === "on",
    };
    const updating = Boolean(editingID);
    setBusy(true);
    try {
      const instance = instanceForAgent(pluginDetail, selectedAgentID);
      const apps = appsFromInstance(instance).filter((item) => item.id !== nextApp.id);
      apps.push(nextApp);
      await saveApps(apps);
      closeCreate();
      renderApps();
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
    await loadPluginDetail();
    await loadAgents();
    renderApps();
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
