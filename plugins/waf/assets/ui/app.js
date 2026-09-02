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

const loadingNode = document.querySelector("#app-loading");
const unavailableNode = document.querySelector("#app-unavailable");
const deniedNode = document.querySelector("#app-denied");
const statusNode = document.querySelector("#app-status");
const contextNode = document.querySelector("#app-context");
const nodeEmpty = document.querySelector("#app-node-empty");
const executionUnavailable = document.querySelector("#app-execution-unavailable");
const workspaceNode = document.querySelector("#app-workspace");
const emptyNode = document.querySelector("#app-empty");
const entryList = document.querySelector("#entry-list");
const entryCount = document.querySelector("#entry-count");
const exclusionList = document.querySelector("#exclusion-list");
const customList = document.querySelector("#custom-list");
const eventList = document.querySelector("#event-list");
const eventEmpty = document.querySelector("#event-empty");
const agentSelect = document.querySelector("#agent-select");
const agentPicker = document.querySelector("#agent-picker");
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
    throw Object.assign(new Error(payload.error || "无权管理 Web 防火墙。"), { denied: true, status: 403 });
  }
  if (!response.ok) {
    throw Object.assign(new Error(payload.error || payload.message || "请求失败"), { status: response.status, unavailable: response.status === 503 });
  }
  return payload;
};

const showContext = (kind) => {
  if (contextNode) contextNode.hidden = !kind;
  if (nodeEmpty) nodeEmpty.hidden = kind !== "node-empty";
  if (executionUnavailable) executionUnavailable.hidden = kind !== "unavailable";
  if (workspaceNode) workspaceNode.hidden = !!kind;
};

const escapeText = (value) => String(value || "").replace(/[&<>"']/g, (character) => ({
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
}[character]));

const modeLabel = (mode) => (mode === "deny" ? "拦截" : "观察中");

const renderEntries = (entries) => {
  const items = Array.isArray(entries) ? entries : [];
  if (entryCount) entryCount.textContent = items.length ? `${items.length} 个入口` : "";
  if (emptyNode) emptyNode.hidden = items.length > 0;
  if (!entryList) return;
  entryList.innerHTML = "";
  items.forEach((entry) => {
    const item = document.createElement("li");
    item.className = "entry-card";
    const mode = entry.overlay_invalid ? "skip" : (entry.mode || "observe");
    item.innerHTML = `
      <header>
        <strong>${escapeText(entry.frontend_url || entry.rule_ref || "未命名入口")}</strong>
        <span class="badge" data-mode="${mode}">${entry.overlay_invalid ? "覆盖无效" : modeLabel(mode)}</span>
      </header>
      <p class="meta">${escapeText(entry.backend || "")}</p>
      ${entry.notice ? `<p class="notice">${escapeText(entry.notice)}</p>` : ""}
      <div class="workspace-head-actions">
        <button type="button" class="btn-secondary" data-mode="observe">观察</button>
        <button type="button" class="btn-primary" data-mode="deny">拦截</button>
      </div>
    `;
    item.querySelectorAll("button[data-mode]").forEach((button) => {
      button.addEventListener("click", async () => {
        try {
          await panelJSON("api/entries/mode", {
            method: "POST",
            body: JSON.stringify({ agent_id: selectedAgentID, rule_ref: entry.rule_ref, mode: button.dataset.mode }),
          });
          await renderWorkspace();
        } catch (error) {
          showStatus(error.message, true);
        }
      });
    });
    entryList.appendChild(item);
  });
};

const renderRules = (rules, root, format) => {
  if (!root) return;
  const items = Array.isArray(rules) ? rules : [];
  root.innerHTML = "";
  items.forEach((rule) => {
    const item = document.createElement("li");
    item.className = "rule-card";
    item.textContent = format(rule) || "";
    root.appendChild(item);
  });
};

const renderEvents = (events) => {
  const items = Array.isArray(events) ? events : [];
  if (eventEmpty) eventEmpty.hidden = items.length > 0;
  if (!eventList) return;
  eventList.innerHTML = "";
  items.forEach((event) => {
    const item = document.createElement("li");
    item.className = "event-card";
    const skip = event.reason && event.disposition === "observe" && event.reason !== "rule_matched";
    const mode = event.disposition === "deny" ? "deny" : (skip ? "skip" : "observe");
    const label = event.disposition === "deny" ? "拦截" : (skip ? "跳过" : "观察");
    item.innerHTML = `
      <header>
        <strong>${escapeText(event.site || "未标记站点")}</strong>
        <span class="badge" data-mode="${mode}">${label}</span>
      </header>
      <p class="meta">${escapeText([event.rule_id, event.reason, event.digest].filter(Boolean).join(" · "))}</p>
    `;
    eventList.appendChild(item);
  });
};

let selectedAgentID = "";
let agentsCache = [];

const renderWorkspace = async () => {
  if (loadingNode) loadingNode.hidden = true;
  if (deniedNode) deniedNode.hidden = true;
  if (unavailableNode) unavailableNode.hidden = true;
  showStatus("", false);
  if (!selectedAgentID) {
    showContext("node-empty");
    return;
  }
  const payload = await panelJSON(`api/state?agent_id=${encodeURIComponent(selectedAgentID)}`);
  if (payload.error && payload.ready === false) {
    showContext("unavailable");
    if (executionUnavailable) {
      const copy = executionUnavailable.querySelector("p");
      if (copy) copy.textContent = payload.error;
    }
    return;
  }
  showContext("");
  if (workspaceNode) workspaceNode.hidden = false;
  renderEntries(payload.entries);
  renderRules(payload.exclusions, exclusionList, (item) => `${item.rule_id} · ${item.path_prefix}`);
  renderRules(payload.custom_rules, customList, (item) => `${item.id} · ${item.target} · ${item.needle}`);
  renderEvents(payload.events);
  if (payload.notice && !(payload.entries || []).length) {
    if (emptyNode) {
      emptyNode.hidden = false;
      emptyNode.textContent = payload.notice;
    }
  }
  if (payload.error) showStatus(payload.error, true);
};

const loadAgents = async () => {
  try {
    const payload = await panelJSON("/panel-api/agents");
    agentsCache = Array.isArray(payload.agents)
      ? payload.agents.filter((agent) => agent && agent.is_local !== true && agent.mode !== "local")
      : [];
  } catch (_error) {
    agentsCache = [];
  }
  const requested = new URLSearchParams(window.location.search).get("agent_id") || "";
  selectedAgentID = agentsCache.some((agent) => agent.id === requested)
    ? requested
    : (agentsCache.length === 1 ? agentsCache[0].id : "");
  if (agentSelect) agentSelect.value = selectedAgentID;
  if (agentPicker) {
    agentPicker.innerHTML = `<option value="">选择节点</option>` + agentsCache.map((agent) => {
      const label = agent.name || agent.id;
      return `<option value="${agent.id}">${label}</option>`;
    }).join("");
    agentPicker.value = selectedAgentID;
  }
};

if (agentPicker) {
  agentPicker.addEventListener("change", async () => {
    selectedAgentID = String(agentPicker.value || "");
    if (agentSelect) agentSelect.value = selectedAgentID;
    const url = new URL(window.location.href);
    if (selectedAgentID) url.searchParams.set("agent_id", selectedAgentID);
    else url.searchParams.delete("agent_id");
    window.history.replaceState({}, "", url);
    try {
      await renderWorkspace();
    } catch (error) {
      if (error.denied) {
        if (deniedNode) deniedNode.hidden = false;
        if (workspaceNode) workspaceNode.hidden = true;
        return;
      }
      showStatus(error.message, true);
    }
  });
}

if (globalObserve) {
  globalObserve.addEventListener("click", async () => {
    try {
      await panelJSON("api/mode", { method: "POST", body: JSON.stringify({ agent_id: selectedAgentID, mode: "observe" }) });
      await renderWorkspace();
    } catch (error) {
      showStatus(error.message, true);
    }
  });
}

if (globalDeny) {
  globalDeny.addEventListener("click", async () => {
    try {
      await panelJSON("api/mode", { method: "POST", body: JSON.stringify({ agent_id: selectedAgentID, mode: "deny" }) });
      await renderWorkspace();
    } catch (error) {
      showStatus(error.message, true);
    }
  });
}

if (exclusionForm) {
  exclusionForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(exclusionForm);
    try {
      await panelJSON("api/exclusions", {
        method: "POST",
        body: JSON.stringify({
          agent_id: selectedAgentID,
          rule_id: String(data.get("rule_id") || ""),
          path_prefix: String(data.get("path_prefix") || ""),
        }),
      });
      exclusionForm.reset();
      await renderWorkspace();
    } catch (error) {
      showStatus(error.message, true);
    }
  });
}

if (customForm) {
  customForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(customForm);
    try {
      await panelJSON("api/custom-rules", {
        method: "POST",
        body: JSON.stringify({
          agent_id: selectedAgentID,
          id: String(data.get("id") || ""),
          target: String(data.get("target") || ""),
          needle: String(data.get("needle") || ""),
        }),
      });
      customForm.reset();
      await renderWorkspace();
    } catch (error) {
      showStatus(error.message, true);
    }
  });
}

const start = async () => {
  try {
    await loadAgents();
    await renderWorkspace();
  } catch (error) {
    if (loadingNode) loadingNode.hidden = true;
    if (error.denied && deniedNode) {
      deniedNode.hidden = false;
      return;
    }
    if (unavailableNode) {
      unavailableNode.hidden = false;
      unavailableNode.textContent = error.message || "暂时无法管理 Web 防火墙。";
    }
  }
};

start();
