// 主题由 ui-kit.js 的 host 模式根据 localStorage.theme 解析，并写入 data-theme / data-theme-family。

const statusNode = document.querySelector("#app-status");
const loadingNode = document.querySelector("#app-loading");
const unavailableNode = document.querySelector("#app-unavailable");
const unavailableDescNode = document.querySelector("#app-unavailable-desc");
const deniedNode = document.querySelector("#app-denied");
const contextNode = document.querySelector("#app-context");
const workspaceNode = document.querySelector("#app-workspace");
const workspaceMetrics = document.querySelector("#workspace-metrics");
const metricListens = document.querySelector("#metric-listens");
const metricUsers = document.querySelector("#metric-users");
const metricRouting = document.querySelector("#metric-routing");
const metricRoutingBtn = document.querySelector("#metric-routing-btn");
const listPanel = document.querySelector("#app-list-panel");
const routingPanel = document.querySelector("#routing-panel");
const tabBtnListens = document.querySelector("#tab-btn-listens");
const tabBtnRouting = document.querySelector("#tab-btn-routing");
const routingCountNode = document.querySelector("#routing-count");
const listNode = document.querySelector("#listen-list");
const emptyNode = document.querySelector("#app-empty");
const countNode = document.querySelector("#listen-count");
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
const detailPanel = document.querySelector("#listen-detail");
const detailTitle = document.querySelector("#detail-title");
const detailMeta = document.querySelector("#detail-meta");
const detailUsers = document.querySelector("#detail-users");
const detailActions = document.querySelector("#detail-actions");
const detailClose = document.querySelector("#detail-close");
const agentSelect = document.querySelector("#agent-select");
const agentPickerRoot = document.querySelector('[data-agent-picker="workspace"]');
const nodeEmpty = document.querySelector("#app-node-empty");
const undeployedNode = document.querySelector("#app-undeployed");
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
const upstreamDialog = document.querySelector("#upstream-dialog");
const upstreamForm = document.querySelector("#upstream-form");
const upstreamCancel = document.querySelector("#upstream-cancel");
const openUpstreamDialogBtn = document.querySelector("#open-upstream-dialog");
const upstreamList = document.querySelector("#route-upstreams");
const upstreamEmpty = document.querySelector("#route-upstreams-empty");
const upstreamBadge = document.querySelector("#route-upstreams-badge");
const routeDialog = document.querySelector("#route-dialog");
const routeForm = document.querySelector("#route-form");
const routeCancel = document.querySelector("#route-cancel");
const openRouteDialogBtn = document.querySelector("#open-route-dialog");
const routeList = document.querySelector("#route-rules");
const routeEmpty = document.querySelector("#route-rules-empty");
const routeBadge = document.querySelector("#route-rules-badge");
const routeKindSelect = document.querySelector("#route-kind-select");
const routeSourceInput = document.querySelector("#route-source-input");
const routeClassInput = document.querySelector("#route-class-input");
const routeAttrInput = document.querySelector("#route-attr-input");
const routeActionSelect = document.querySelector("#route-action-select");
const routeUpstreamField = document.querySelector("#route-upstream-field");
const routeUpstreamSelect = document.querySelector("#route-upstream-select");
const routeIdInput = document.querySelector("#route-id-input");
const routeDefaultAction = document.querySelector("#route-default-action");
const routeDefaultUpstreamField = document.querySelector("#route-default-upstream-field");
const routeDefaultUpstream = document.querySelector("#route-default-upstream");
const routeSaveDefault = document.querySelector("#route-save-default");
const routeRefreshBtn = document.querySelector("#route-refresh");
const routeRefreshStatus = document.querySelector("#route-refresh-status");
const appendDialog = document.querySelector("#append-dialog");
const appendForm = document.querySelector("#append-form");
const appendName = document.querySelector("#append-name");
const appendMeta = document.querySelector("#append-meta");
const appendCancel = document.querySelector("#append-cancel");
const listenLoading = document.querySelector("#listen-loading");
const listenError = document.querySelector("#listen-error");
const listenErrorDesc = document.querySelector("#listen-error-desc");
const listenRetry = document.querySelector("#listen-retry");
const routingError = document.querySelector("#routing-error");
const routingErrorDesc = document.querySelector("#routing-error-desc");
const routingRetry = document.querySelector("#routing-retry");
const rulesTable = document.querySelector("#route-rules-table");
const upstreamsTable = document.querySelector("#route-upstreams-table");
const appendSubmit = document.querySelector("#append-submit");
const upstreamSubmit = document.querySelector("#upstream-submit");
const routeSubmit = document.querySelector("#route-submit");
const createError = document.querySelector("#create-error");
const appendError = document.querySelector("#append-error");
const upstreamError = document.querySelector("#upstream-error");
const routeError = document.querySelector("#route-error");
const detailStatus = document.querySelector("#detail-status");
const detailSummary = document.querySelector("#detail-summary");
const detailUsersCount = document.querySelector("#detail-users-count");
const detailUsersHint = document.querySelector("#detail-users-hint");
const metricPending = document.querySelector("#metric-pending");
const metricPendingCount = document.querySelector("#metric-pending-count");
const listenFilterField = document.querySelector("#listen-filter-field");
const listenFilterInput = document.querySelector("#listen-filter");
const listenFilterEmpty = document.querySelector("#listen-filter-empty");
const routeDefaultHint = document.querySelector("#route-default-hint");
const routeUpstreamHint = document.querySelector("#route-upstream-hint");
const routeDialogTitle = document.querySelector("#route-dialog-title");
const routeDialogDesc = document.querySelector("#route-dialog-desc");
const upstreamDialogTitle = document.querySelector("#upstream-dialog-title");
const upstreamDialogDesc = document.querySelector("#upstream-dialog-desc");
const upstreamPasswordHint = document.querySelector("#upstream-password-hint");
const upstreamImportInput = document.querySelector("#upstream-import");
const upstreamImportHint = document.querySelector("#upstream-import-hint");

const LISTEN_FILTER_MIN = 4;

const METHOD_LABELS = {
  "2022-blake3-aes-128-gcm": "SS2022 · AES-128",
  "2022-blake3-aes-256-gcm": "SS2022 · AES-256",
  "aes-128-gcm": "AES-128-GCM",
  "aes-256-gcm": "AES-256-GCM",
};

const KIND_LABELS = {
  domain: "域名",
  cidr: "网段",
  country: "国家",
  region: "地区",
};

const ACTION_LABELS = {
  direct: "直连",
  reject: "拒绝",
  upstream: "转发上游",
};

const FAILURE_LABELS = {
  "dataset-unavailable": "数据源不可用",
  "upstream-missing": "上游不存在",
  "upstream-disabled": "上游已停用",
  "upstream-disabled-or-missing": "上游不可用",
  "tcp-unsupported": "上游未开启 TCP",
  "udp-unsupported": "上游未开启 UDP",
  "protocol-unsupported": "协议不支持",
};

// 只缺一种协议时规则仍可处理另一种流量，用警告色区分完全失效。
const PARTIAL_FAILURES = new Set(["tcp-unsupported", "udp-unsupported"]);

const FAILURE_HINTS = {
  "dataset-unavailable": "宿主暂时读不到该数据源，确认数据集已同步。",
  "upstream-missing": "目标上游已被删除，请改用其它上游。",
  "upstream-disabled": "启用目标上游后恢复。",
  "upstream-disabled-or-missing": "确认目标上游存在并已启用。",
  "tcp-unsupported": "命中的 TCP 流量无法经该上游转发。",
  "udp-unsupported": "命中的 UDP 流量无法经该上游转发。",
  "protocol-unsupported": "该上游未开启 TCP 或 UDP。",
};

const ROUTE_PRESETS = {
  "ai-upstream": {
    id: "ai-not-cn",
    source_id: "geosite",
    kind: "domain",
    classification: "category-ai",
    attribute: "!cn",
    action: "upstream",
  },
  "cn-direct": {
    id: "cn-domain-direct",
    source_id: "geosite",
    kind: "domain",
    classification: "cn",
    attribute: "",
    action: "direct",
  },
  "cn-ip-direct": {
    id: "cn-ip-direct",
    source_id: "geoip",
    kind: "country",
    classification: "cn",
    attribute: "",
    action: "direct",
  },
  "ads-reject": {
    id: "ads-reject",
    source_id: "geosite",
    kind: "domain",
    classification: "category-ads-all",
    attribute: "",
    action: "reject",
  },
  "private-reject": {
    id: "private-reject",
    source_id: "geoip",
    kind: "cidr",
    classification: "private",
    attribute: "",
    action: "reject",
  },
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

const agentStatusLabel = (status) => ({ online: "在线", offline: "离线", failed: "异常", pending: "等待中" }[status] || "离线");

const NETWORK_ERROR_TEXT = "网络连接失败，请检查网络或宿主连接后重试。";

const errorText = (error, fallback = "操作失败，请稍后重试。") => {
  const raw = String((error && error.message) || "").trim();
  if (error && (error.denied || error.status === 403)) return "无权执行该操作，请联系管理员授予权限后重试。";
  if (error && (error.network || error.name === "TypeError" || /failed to fetch|networkerror|load failed/i.test(raw))) return NETWORK_ERROR_TEXT;
  if (error && error.status === 404) return "目标不存在，可能已被删除。请刷新页面后重试。";
  if (error && error.status === 503) return "宿主服务暂时不可用，请稍后重试或刷新页面。";
  if (error && error.status >= 500) return "服务暂时出错，请稍后重试。";
  const hasChinese = /[\u4e00-\u9fff]/.test(raw);
  const englishOnly = !hasChinese && /[A-Za-z]{3,}/.test(raw);
  if (!raw || englishOnly) return fallback;
  const message = raw.replace(/[。.!！]+$/u, "");
  if (error && error.status === 409) return `${message}。请调整后重试。`;
  if (error && error.status === 400) return `${message}。请检查填写内容后重试。`;
  return `${message}。`;
};

const draftSnapshot = (form) => {
  if (!form) return "";
  return Array.from(new FormData(form).entries())
    .map(([name, value]) => `${name}=${String(value)}`)
    .join("&");
};

const draftDialogs = new Map();

const trackDraft = (dialog, form, close) => {
  if (!dialog || !form) return;
  draftDialogs.set(dialog, { form, close, baseline: draftSnapshot(form) });
};

const releaseDraft = (dialog) => {
  draftDialogs.delete(dialog);
};

const isDialogDirty = (dialog) => {
  const draft = draftDialogs.get(dialog);
  return Boolean(draft && draft.form && draftSnapshot(draft.form) !== draft.baseline);
};

const openDirtyDialog = () => {
  for (const dialog of draftDialogs.keys()) {
    if (dialog.open && isDialogDirty(dialog)) return dialog;
  }
  return null;
};

const confirmDiscardDraft = async (dialog, title = "放弃未保存的修改？") => {
  if (!isDialogDirty(dialog)) return true;
  return askConfirm({
    title,
    body: "关闭后本次填写的内容会丢失，且不能恢复。",
    confirm: "放弃修改",
    cancel: "继续编辑",
    danger: true,
  });
};

const requestCloseDraft = async (dialog, close, title) => {
  if (busy) return false;
  if (!(await confirmDiscardDraft(dialog, title))) return false;
  releaseDraft(dialog);
  close();
  return true;
};

const bindDraftDialog = (dialog, form, close) => {
  if (!dialog || !form) return;
  trackDraft(dialog, form, close);
  dialog.addEventListener("cancel", (event) => {
    event.preventDefault();
    window.setTimeout(() => requestCloseDraft(dialog, close), 0);
  });
  dialog.addEventListener("close", () => releaseDraft(dialog));
};

const topmostOpenDraftDialog = () => {
  const openDialogs = Array.from(document.querySelectorAll("dialog[open]"));
  const topmost = openDialogs[openDialogs.length - 1];
  return topmost && draftDialogs.has(topmost) ? topmost : null;
};

document.addEventListener(
  "keydown",
  (event) => {
    if (event.key !== "Escape" || event.defaultPrevented) return;
    const dialog = topmostOpenDraftDialog();
    if (!dialog) return;
    event.preventDefault();
    event.stopPropagation();
    const draft = draftDialogs.get(dialog);
    if (draft) requestCloseDraft(dialog, draft.close);
  },
  true
);

window.addEventListener("beforeunload", (event) => {
  if (!openDirtyDialog()) return;
  event.preventDefault();
  event.returnValue = "";
});

document.addEventListener(
  "click",
  (event) => {
    const dialog = event.target;
    if (!dialog || dialog.tagName !== "DIALOG" || !dialog.open) return;
    if (busy) {
      event.preventDefault();
      event.stopPropagation();
      return;
    }
    if (!isDialogDirty(dialog)) return;
    event.preventDefault();
    event.stopPropagation();
    const draft = draftDialogs.get(dialog);
    requestCloseDraft(dialog, draft && draft.close ? draft.close : () => dialog.close());
  },
  true
);

let busy = false;
let busyControl = null;
let busyControlLabel = "";
let busyScope = null;
let activeTab = "listens";
let selectedAgentID = "";
let agentsCache = [];
let listensCache = [];
let routingCache = { upstreams: [], rules: [], default_action: "direct" };
let routeStatusCache = [];
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
  // 成功提示走浮层，不推挤页面；错误同时留在页首状态行，滚动后也能看到浮层。
  const toast = window.NREUI && typeof window.NREUI.toast === "function" ? window.NREUI.toast : null;
  if (message && toast) {
    toast(message, isError ? "danger" : "success");
    if (!isError) {
      statusNode.hidden = true;
      statusNode.textContent = "";
      delete statusNode.dataset.error;
      return;
    }
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

const showModalError = (node, message) => {
  if (!node) return;
  node.hidden = !message;
  node.textContent = message || "";
};

const clearFormErrors = (form) => {
  if (!form) return;
  form.querySelectorAll('[aria-invalid="true"]').forEach((input) => {
    if (window.NREUI && typeof window.NREUI.clearFieldError === "function") window.NREUI.clearFieldError(input);
    else {
      input.removeAttribute("aria-invalid");
      input.removeAttribute("aria-describedby");
    }
  });
};

const markFieldError = (input, message) => {
  if (!input) return;
  if (window.NREUI && typeof window.NREUI.fieldError === "function") window.NREUI.fieldError(input, message);
  else input.setAttribute("aria-invalid", "true");
};

const clearFieldError = (input) => {
  if (!input) return;
  if (window.NREUI && typeof window.NREUI.clearFieldError === "function") window.NREUI.clearFieldError(input);
  else {
    input.removeAttribute("aria-invalid");
    input.removeAttribute("aria-describedby");
  }
};

const formField = (form, name) => (form ? form.querySelector(`[name="${name}"]`) : null);

const showDetailStatus = (message, isError) => {
  if (!detailStatus) return;
  detailStatus.hidden = !message;
  detailStatus.textContent = message || "";
  detailStatus.dataset.error = isError ? "true" : "false";
};

const showFeedback = (message, isError) => {
  if (detailPanel && detailPanel.open && detailStatus) {
    showDetailStatus(message, isError);
    return;
  }
  showStatus(message, isError);
};

const newOperationKey = () => {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return `operation/ui/${Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("")}`;
};

const fetchPanel = async (path, options) => {
  try {
    return await fetch(path, options);
  } catch (cause) {
    throw Object.assign(new Error(NETWORK_ERROR_TEXT), { network: true, cause });
  }
};

const panelJSON = async (path, options = {}) => {
  const response = await fetchPanel(path, {
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
  const response = await fetchPanel(path, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      ...panelAuthHeaders(),
      "X-NRE-Operation-Key": newOperationKey(),
    },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  if (response.status === 403) {
    throw Object.assign(new Error(payload.error || payload.message || "无权访问"), { denied: true, status: 403 });
  }
  if (!response.ok) {
    throw Object.assign(new Error(payload.error || payload.message || "保存失败"), { status: response.status });
  }
  return payload;
};

const switchWorkspaceTab = (tab) => {
  activeTab = tab === "routing" ? "routing" : "listens";
  const isRouting = activeTab === "routing";
  if (tabBtnListens) {
    tabBtnListens.setAttribute("aria-selected", isRouting ? "false" : "true");
    tabBtnListens.setAttribute("tabindex", isRouting ? "-1" : "0");
  }
  if (tabBtnRouting) {
    tabBtnRouting.setAttribute("aria-selected", isRouting ? "true" : "false");
    tabBtnRouting.setAttribute("tabindex", isRouting ? "0" : "-1");
  }
  if (listPanel) listPanel.hidden = isRouting;
  if (routingPanel) routingPanel.hidden = !isRouting;
  syncListPanel();
};

if (tabBtnListens) tabBtnListens.addEventListener("click", () => switchWorkspaceTab("listens"));
if (tabBtnRouting) tabBtnRouting.addEventListener("click", () => switchWorkspaceTab("routing"));
if (metricRoutingBtn) metricRoutingBtn.addEventListener("click", () => switchWorkspaceTab("routing"));

const updateOverviewMetrics = () => {
  const visible = Boolean(selectedAgentID && agentOnline && executionReady === true);
  if (workspaceMetrics) workspaceMetrics.hidden = !visible;
  if (!visible) return;
  if (metricListens) metricListens.textContent = String(listensCache.length);
  if (metricUsers) {
    let totalEnabled = 0;
    listensCache.forEach((listen) => {
      ((listen && listen.users) || []).forEach((user) => {
        if (user && user.enabled) totalEnabled += 1;
      });
    });
    metricUsers.textContent = String(totalEnabled);
  }
  if (metricPending) {
    const pending = listensCache.filter((listen) => listen && !listen.bound).length;
    metricPending.hidden = pending === 0;
    if (metricPendingCount) metricPendingCount.textContent = String(pending);
  }
  if (metricRouting) {
    const rulesCount = (routingCache.rules || []).length;
    const defAction = ACTION_LABELS[routingCache.default_action || "direct"] || "直连";
    metricRouting.textContent = rulesCount
      ? `${rulesCount} 条规则 · 默认${defAction}`
      : `默认${defAction}`;
  }
};

const syncSelectionActions = () => {
  const blocked = busy || !selectedAgentID || !agentOnline || executionReady !== true;
  if (createToggle) createToggle.disabled = blocked;
  if (emptyCreate) emptyCreate.disabled = blocked;
  if (shareHostSave) shareHostSave.disabled = blocked || !shareHostDirty();
  if (shareHostAuto) shareHostAuto.disabled = blocked;
  if (shareHostInput) shareHostInput.disabled = blocked;
  document.querySelectorAll("[data-mutate=true]").forEach((node) => {
    node.disabled = blocked;
  });
  syncDefaultRouteState();
};

const setBusy = (next, control = null, label = "") => {
  busy = Boolean(next);
  if (busy && control) {
    if (busyControl && busyControl !== control) {
      busyControl.textContent = busyControlLabel;
      busyControl.removeAttribute("aria-busy");
    }
    busyControl = control;
    busyControlLabel = control.textContent;
    control.textContent = label || "处理中…";
    control.setAttribute("aria-busy", "true");
    busyScope = control.closest("dialog") || workspaceNode || null;
    if (busyScope) busyScope.setAttribute("aria-busy", "true");
  } else if (!busy) {
    if (busyControl) {
      busyControl.textContent = busyControlLabel;
      busyControl.removeAttribute("aria-busy");
    }
    if (busyScope) busyScope.removeAttribute("aria-busy");
    busyControl = null;
    busyControlLabel = "";
    busyScope = null;
  }
  // 只锁住原本可用的控件，解锁时原样还原；本身禁用的（如首条规则的上移）保持禁用。
  const roots = [workspaceNode, contextNode, createDialog, appendDialog, detailPanel, upstreamDialog, routeDialog].filter(Boolean);
  roots.forEach((root) => {
    root.querySelectorAll("button, input, textarea, select").forEach((node) => {
      if (node === agentSelect) return;
      if (agentPickerRoot && agentPickerRoot.contains(node)) return;
      if (busy) {
        if (!node.disabled) {
          node.dataset.busyLock = "true";
          node.disabled = true;
        }
      } else if (node.dataset.busyLock === "true") {
        delete node.dataset.busyLock;
        node.disabled = false;
      }
    });
  });
  if (!busy) syncSelectionActions();
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
  const statusText = document.createElement("span");
  statusText.className = "agent-search-select__state";
  statusText.hidden = true;
  const label = document.createElement("span");
  label.className = "agent-search-select__label";
  const triggerEngine = document.createElement("span");
  triggerEngine.className = "agent-search-select__engine";
  triggerEngine.hidden = true;
  const chevron = document.createElement("span");
  chevron.className = "agent-search-select__chevron";
  chevron.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><polyline points="6 9 12 15 18 9"/></svg>';
  trigger.append(statusDot, label, statusText, triggerEngine, chevron);

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
      const status = getAgentStatus(agent);
      label.textContent = agentDisplayName(agent);
      label.dataset.empty = "false";
      statusDot.hidden = false;
      statusDot.className = `agent-search-select__status agent-search-select__status--${status}`;
      statusText.hidden = false;
      statusText.dataset.state = status;
      statusText.textContent = agentStatusLabel(status);
      trigger.title = agentLabel(agent);
    } else if (picker.selected) {
      label.textContent = picker.selected;
      label.dataset.empty = "false";
      statusDot.hidden = true;
      statusText.hidden = true;
      trigger.title = picker.selected;
    } else {
      label.textContent = placeholder;
      label.dataset.empty = "true";
      statusDot.hidden = true;
      statusText.hidden = true;
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
      const status = getAgentStatus(agent);
      const dot = document.createElement("span");
      dot.className = `agent-search-select__status agent-search-select__status--${status}`;
      const name = document.createElement("span");
      name.className = "agent-search-select__option-name";
      name.textContent = agentDisplayName(agent);
      const meta = document.createElement("span");
      meta.className = "agent-search-select__option-meta";
      meta.textContent = [agentStatusLabel(status), timeAgo(agent.last_seen_at)].filter(Boolean).join(" · ");
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

const notify = (message, tone = "success") => {
  if (!message) return;
  if (window.NREUI && typeof window.NREUI.toast === "function") {
    window.NREUI.toast(message, tone);
    return;
  }
  showStatus(message, tone === "danger");
};

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
  notify("已复制。", "success");
  window.setTimeout(() => {
    if (button.textContent === "已复制") button.textContent = original;
  }, 1600);
};

const showContext = (kind) => {
  if (!contextNode) return;
  contextNode.hidden = !kind;
  if (nodeEmpty) nodeEmpty.hidden = kind !== "empty";
  if (undeployedNode) undeployedNode.hidden = kind !== "undeployed";
  if (offlineNode) offlineNode.hidden = kind !== "offline";
  if (executionUnavailableNode) executionUnavailableNode.hidden = kind !== "execution-unavailable";
};

const setListenLoading = (loading) => {
  if (listenLoading) listenLoading.hidden = !loading;
  if (loading && listenError) listenError.hidden = true;
  syncListPanel();
};

const showListenError = (message) => {
  if (!listenError) return;
  if (listenErrorDesc) listenErrorDesc.textContent = message || "暂时无法读取监听列表。刷新页面，或稍后重试。";
  listenError.hidden = false;
  syncListPanel();
};

const hideListenError = () => {
  if (listenError) listenError.hidden = true;
};

const showRoutingError = (message) => {
  if (!routingError) return;
  if (routingErrorDesc) routingErrorDesc.textContent = message || "暂时无法读取规则与上游。刷新页面，或稍后重试。";
  if (rulesTable) rulesTable.hidden = true;
  if (upstreamsTable) upstreamsTable.hidden = true;
  if (routeEmpty) routeEmpty.hidden = true;
  if (upstreamEmpty) upstreamEmpty.hidden = true;
  routingError.hidden = false;
};

const hideRoutingError = () => {
  if (routingError) routingError.hidden = true;
};

const methodLabel = (method) => METHOD_LABELS[String(method || "")] || String(method || "");

const defaultUserName = (id) => {
  const value = String(id || "");
  const prefix = "acct-";
  if (!value.startsWith(prefix)) return value;
  const trimmed = value.slice(prefix.length);
  if (!trimmed) return value;
  return `user-${trimmed}`;
};

const listenTitle = (listen) => {
  const port = listen && listen.port != null ? String(listen.port) : "";
  const users = (listen && listen.users) || [];
  const user = users[0];
  const name = String((user && user.name) || "").trim();
  if (!name || name === defaultUserName(user && user.id)) return port;
  return `${name} · ${port}`;
};

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

const markSelectedCards = () => {
  if (!listNode) return;
  listNode.querySelectorAll(".listen-card").forEach((card) => {
    const selected = Boolean(openListenID) && card.dataset.id === openListenID;
    card.dataset.selected = selected ? "true" : "false";
    if (selected) card.setAttribute("aria-current", "true");
    else card.removeAttribute("aria-current");
  });
};

const resetDetailPrompt = () => {
  if (detailTitle) detailTitle.textContent = "监听详情";
  if (detailMeta) {
    detailMeta.textContent = "";
    detailMeta.hidden = true;
  }
  if (detailUsers) detailUsers.replaceChildren();
  if (detailActions) detailActions.replaceChildren();
  if (detailSummary) {
    detailSummary.replaceChildren();
    detailSummary.hidden = true;
  }
  if (detailUsersCount) detailUsersCount.textContent = "";
  if (detailUsersHint) detailUsersHint.hidden = true;
  showDetailStatus("", false);
};

const syncListPanel = () => {
  const hasListens = listNode && listNode.children.length > 0;
  const isRouting = activeTab === "routing";
  const canOperate = Boolean(selectedAgentID && agentOnline);
  const loading = Boolean(listenLoading && !listenLoading.hidden);
  const failed = Boolean(listenError && !listenError.hidden);
  if (emptyNode) emptyNode.hidden = isRouting || !canOperate || hasListens || loading || failed;
  if (createToggle) createToggle.hidden = isRouting || !canOperate;
};

const closeCreate = () => {
  releaseDraft(createDialog);
  showModalError(createError, "");
  clearFormErrors(createForm);
  if (createForm) createForm.reset();
  if (advancedKeys) advancedKeys.open = false;
  if (createDialog && createDialog.open) createDialog.close();
  syncListPanel();
};

const requestCloseCreate = () => requestCloseDraft(createDialog, closeCreate);

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
  if (!agentOnline) return;
  try {
    const payload = await panelJSON(`api/defaults?agent_id=${encodeURIComponent(selectedAgentID)}`);
    fillDefaults(payload.defaults);
  } catch (error) {
    showStatus(errorText(error, "暂时无法读取默认值，请稍后重试。"), true);
    return;
  }
  if (createDialog) {
    clearFormErrors(createForm);
    showModalError(createError, "");
    trackDraft(createDialog, createForm, closeCreate);
    createDialog._returnFocus = document.activeElement;
    if (createDialog.open) createDialog.close();
    createDialog.showModal();
    const nameInput = createForm ? createForm.querySelector('input[name="name"]') : null;
    if (nameInput) nameInput.focus();
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
  button.className = "ui-btn ui-btn--secondary ui-btn--sm";
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

const renderStatusPill = (text, on, tone = "") => {
  const status = document.createElement("span");
  const variant = tone || (on ? "success" : "warning");
  status.className = `ui-badge ui-badge--${variant}`;
  status.textContent = text;
  return status;
};

const copyURIButton = (user) => {
  const copy = document.createElement("button");
  copy.type = "button";
  copy.className = "ui-btn ui-btn--sm";
  copy.textContent = "复制 ss://";
  copy.addEventListener("click", async () => {
    try {
      await copyText(user.uri);
      markCopied(copy);
    } catch (error) {
      showFeedback(errorText(error), true);
    }
  });
  return copy;
};

const shareHint = (user) => {
  const hint = document.createElement("p");
  hint.className = "ui-help-text listen-share-hint";
  hint.textContent = user.enabled
    ? (user.reason || "暂时无法分享")
    : "停用后无法导入。再启用即可复制链接。";
  return hint;
};

const renderShare = (user) => {
  const wrap = document.createElement("div");
  wrap.className = "share-strip";
  if (user.share_available && user.uri) {
    wrap.append(copyURIButton(user), qrButton(user));
  } else {
    wrap.append(shareHint(user));
  }
  return wrap;
};

const userManageButtons = (user, listen = null) => {
  const actions = document.createElement("div");
  actions.className = "account-actions";
  const toggle = document.createElement("button");
  toggle.type = "button";
  toggle.className = "ui-btn ui-btn--ghost ui-btn--sm";
  toggle.dataset.mutate = "true";
  toggle.textContent = user.enabled ? "停用" : "再启用";
  toggle.addEventListener("click", (event) => mutateUser(user, user.enabled ? "disable" : "enable", false, event.currentTarget));
  const rotate = document.createElement("button");
  rotate.type = "button";
  rotate.className = "ui-btn ui-btn--ghost ui-btn--sm";
  rotate.dataset.mutate = "true";
  rotate.textContent = "轮换密钥";
  rotate.addEventListener("click", (event) => mutateUser(user, "rotate", true, event.currentTarget));
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "ui-btn ui-btn--ghost ui-btn--sm btn-danger-text";
  remove.dataset.mutate = "true";
  remove.textContent = "删除用户";
  const lastUser = Boolean(listen && (listen.users || []).length <= 1);
  remove.addEventListener("click", (event) => mutateUser(user, "delete", true, event.currentTarget, { lastUser }));
  actions.append(toggle, rotate, remove);
  return actions;
};

const renderUser = (user, { manage = false, compact = false, listen = null } = {}) => {
  const article = document.createElement("article");
  article.className = compact ? "account account--compact" : "account";
  article.dataset.id = user.id;
  article.dataset.enabled = user.enabled ? "true" : "false";
  const head = document.createElement("div");
  head.className = "account-head";
  const identity = document.createElement("div");
  identity.className = "account-identity";
  const name = document.createElement("strong");
  name.textContent = user.name || user.id;
  identity.append(name, renderStatusPill(user.enabled ? "启用" : "已停用", user.enabled));
  head.append(identity);
  article.append(head);
  if (manage) {
    const ops = document.createElement("div");
    ops.className = "account-ops";
    ops.append(renderShare(user), userManageButtons(user, listen));
    article.append(ops);
  } else {
    article.append(renderShare(user));
  }
  return article;
};

const primaryUser = (listen) => {
  const users = (listen && listen.users) || [];
  return users.find((user) => user && user.enabled && user.share_available && user.uri) || users[0] || null;
};

const listenFooterActions = (listen) => {
  const actions = document.createElement("div");
  actions.className = "dialog-actions listen-detail-actions";
  // 危险操作放左侧，与常用操作拉开距离；常用的追加用户放在最右。
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "ui-btn ui-btn--danger-soft ui-btn--sm";
  remove.dataset.mutate = "true";
  remove.textContent = "删除监听";
  remove.addEventListener("click", (event) => deleteListen(listen, event.currentTarget));
  actions.append(remove);
  const spacer = document.createElement("span");
  spacer.className = "ui-spacer";
  spacer.setAttribute("aria-hidden", "true");
  actions.append(spacer);
  if (isSS2022(listen.method)) {
    const rotateServer = document.createElement("button");
    rotateServer.type = "button";
    rotateServer.className = "ui-btn ui-btn--ghost ui-btn--sm";
    rotateServer.dataset.mutate = "true";
    rotateServer.textContent = "轮换 Server PSK";
    rotateServer.addEventListener("click", (event) => rotateServerPSK(listen, event.currentTarget));
    actions.append(rotateServer);
    const append = document.createElement("button");
    append.type = "button";
    append.className = "ui-btn ui-btn--sm";
    append.dataset.mutate = "true";
    append.textContent = "追加用户";
    append.addEventListener("click", () => appendUser(listen));
    actions.append(append);
  }
  return actions;
};

const renderListen = (listen) => {
  const card = document.createElement("article");
  card.className = "ui-card listen-card";
  card.dataset.id = listen.id;
  card.dataset.bound = listen.bound ? "true" : "false";
  const selected = Boolean(openListenID) && listen.id === openListenID;
  card.dataset.selected = selected ? "true" : "false";
  if (selected) card.setAttribute("aria-current", "true");

  const head = document.createElement("div");
  head.className = "listen-card__head";
  const titleRow = document.createElement("div");
  titleRow.className = "listen-card__title-row";
  const title = document.createElement("h3");
  title.className = "listen-card__title";
  title.textContent = listenTitle(listen);
  titleRow.append(title, renderStatusPill(listen.bound ? "运行中" : "未生效", listen.bound));
  const meta = document.createElement("p");
  meta.className = "listen-card__meta";
  const users = listen.users || [];
  const enabledUsers = users.filter((user) => user && user.enabled).length;
  const userText = !users.length
    ? "暂无用户"
    : enabledUsers === users.length
      ? `${users.length} 个用户`
      : `${enabledUsers}/${users.length} 个用户启用`;
  meta.textContent = [methodLabel(listen.method), userText].filter(Boolean).join(" · ");
  head.append(titleRow, meta);
  card.append(head);

  const endpoint = document.createElement("div");
  endpoint.className = "listen-endpoint";
  const address = document.createElement("span");
  address.className = "listen-endpoint__address";
  address.textContent = listenHostPort(listen) || `0.0.0.0:${listen.port}`;
  address.title = address.textContent;
  const protocol = document.createElement("span");
  protocol.className = "ui-badge ui-badge--plain listen-endpoint__protocol";
  protocol.textContent = "TCP + UDP";
  endpoint.append(address, protocol);
  card.append(endpoint);

  if (!listen.bound) {
    const note = document.createElement("p");
    note.className = "listen-binding-note";
    note.textContent = "未生效：端口尚未绑定，等节点应用后再分享。";
    card.append(note);
  }

  const actions = document.createElement("div");
  actions.className = "listen-card__actions";
  const first = primaryUser(listen);
  if (first && first.share_available && first.uri) {
    const copy = copyURIButton(first);
    copy.addEventListener("click", (event) => event.stopPropagation());
    const qr = qrButton(first);
    qr.addEventListener("click", (event) => event.stopPropagation());
    actions.append(copy, qr);
  } else if (first && listen.bound) {
    actions.append(shareHint(first));
  } else if (!first) {
    const hint = document.createElement("p");
    hint.className = "ui-help-text listen-share-hint";
    hint.textContent = isSS2022(listen.method) ? "还没有用户，打开管理追加。" : "没有可用账号，可删除后重建。";
    actions.append(hint);
  }
  const open = document.createElement("button");
  open.type = "button";
  open.className = "ui-btn ui-btn--ghost ui-btn--sm listen-card__manage";
  open.textContent = "管理";
  open.setAttribute("aria-label", `管理 ${listenTitle(listen)}`);
  open.addEventListener("click", (event) => {
    event.stopPropagation();
    openDetail(listen);
  });
  actions.append(open);
  card.append(actions);
  card.addEventListener("click", (event) => {
    if (event.target.closest("button")) return;
    if (window.getSelection && String(window.getSelection())) return;
    openDetail(listen);
  });
  return card;
};

const closeDetail = () => {
  openListenID = "";
  resetDetailPrompt();
  markSelectedCards();
  if (detailPanel && detailPanel.open) detailPanel.close();
};

const renderDetailSummary = (listen) => {
  if (!detailSummary) return;
  detailSummary.replaceChildren();
  const hostPort = listenHostPort(listen) || `0.0.0.0:${listen.port}`;
  const rows = [
    ["连接地址", hostPort, true],
    ["协议", "TCP + UDP", false],
  ];
  const list = document.createElement("dl");
  list.className = "detail-summary__list";
  rows.forEach(([term, value, mono]) => {
    const item = document.createElement("div");
    item.className = "detail-summary__item";
    const dt = document.createElement("dt");
    dt.textContent = term;
    const dd = document.createElement("dd");
    if (mono) dd.className = "ui-mono";
    dd.textContent = value;
    dd.title = value;
    item.append(dt, dd);
    list.append(item);
  });
  const copy = document.createElement("button");
  copy.type = "button";
  copy.className = "ui-btn ui-btn--secondary ui-btn--sm";
  copy.textContent = "复制地址";
  copy.addEventListener("click", async () => {
    try {
      await copyText(hostPort);
      markCopied(copy);
    } catch (error) {
      showFeedback(errorText(error), true);
    }
  });
  detailSummary.append(list, copy);
  if (!listen.bound) {
    const note = document.createElement("p");
    note.className = "listen-binding-note detail-summary__note";
    note.textContent = "未生效：端口尚未在节点上绑定，客户端暂时连不上；节点应用后自动生效。";
    detailSummary.append(note);
  }
  detailSummary.hidden = false;
};

const renderDetail = (listen) => {
  if (!detailPanel || !listen) return;
  openListenID = listen.id;
  if (detailTitle) detailTitle.textContent = listenTitle(listen);
  if (detailMeta) {
    const parts = [methodLabel(listen.method), listenShareHost(listen), listen.bound ? "运行中" : "未生效"].filter(Boolean);
    detailMeta.textContent = parts.join(" · ");
    detailMeta.hidden = !detailMeta.textContent;
  }
  renderDetailSummary(listen);
  const users = listen.users || [];
  if (detailUsersCount) detailUsersCount.textContent = String(users.length);
  if (detailUsersHint) {
    detailUsersHint.textContent = users.length
      ? (isSS2022(listen.method) ? "每个用户有独立密钥与链接，停用或轮换只影响该用户。" : "传统加密方式只支持单用户；需要多人共用请新建 SS2022 监听。")
      : (isSS2022(listen.method) ? "还没有用户，追加后即可分享 ss:// 链接。" : "该监听没有可用账号，可删除后重新创建。");
    detailUsersHint.hidden = false;
  }
  if (detailUsers) {
    detailUsers.replaceChildren();
    users.forEach((user) => detailUsers.append(renderUser(user, { manage: true, listen })));
  }
  if (detailActions) {
    const footer = listenFooterActions(listen);
    detailActions.replaceChildren(...Array.from(footer.children));
  }
  markSelectedCards();
  if (typeof detailPanel.showModal === "function") {
    if (!detailPanel.open) detailPanel.showModal();
  }
  syncSelectionActions();
};

const openDetail = (listen) => {
  renderDetail(listen);
};

const refreshOpenDetail = () => {
  if (!openListenID) return;
  const listen = listensCache.find((item) => item && item.id === openListenID);
  if (listen) renderDetail(listen);
  else closeDetail();
};

const listenSearchText = (listen) => [
  listenTitle(listen),
  listen && listen.port,
  listenHostPort(listen),
  methodLabel(listen && listen.method),
  ...((listen && listen.users) || []).map((user) => user && (user.name || user.id)),
].filter(Boolean).join(" ").toLowerCase();

const applyListenFilter = () => {
  if (!listNode) return;
  const showFilter = listensCache.length >= LISTEN_FILTER_MIN;
  if (listenFilterField) listenFilterField.hidden = !showFilter;
  const query = showFilter && listenFilterInput ? listenFilterInput.value.trim().toLowerCase() : "";
  let visible = 0;
  listNode.querySelectorAll(".listen-card").forEach((card) => {
    const listen = listensCache.find((item) => item && item.id === card.dataset.id);
    const match = !query || (listen && listenSearchText(listen).includes(query));
    card.hidden = !match;
    if (match) visible += 1;
  });
  if (listenFilterEmpty) listenFilterEmpty.hidden = !query || visible > 0;
};

if (listenFilterInput) {
  listenFilterInput.addEventListener("input", applyListenFilter);
  listenFilterInput.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && listenFilterInput.value) {
      event.preventDefault();
      listenFilterInput.value = "";
      applyListenFilter();
    }
  });
}

const renderListens = (listens, options = {}) => {
  if (!listNode) return;
  listensCache = listens || [];
  listNode.replaceChildren();
  listensCache.forEach((listen) => listNode.append(renderListen(listen)));
  applyListenFilter();
  if (countNode) {
    countNode.hidden = !listensCache.length;
    countNode.textContent = listensCache.length ? `${listensCache.length}` : "";
  }
  updateOverviewMetrics();
  syncListPanel();
  if (!options.keepDetail) refreshOpenDetail();
  syncSelectionActions();
  if (busy) setBusy(true);
};

const mutateUser = async (user, action, confirmDelete = false, control = null, { lastUser = false } = {}) => {
  if (busy || !canMutate()) return;
  const label = user.name || user.id;
  if (action === "disable") {
    const ok = await askConfirm({
      title: "停用用户",
      body: `停用「${label}」后，该用户的 ss:// 链接立即无法连接；可随时再启用。`,
      confirm: "停用",
      danger: true,
    });
    if (!ok) return;
  } else if (confirmDelete || action === "rotate") {
    const rotating = action === "rotate";
    const deleteBody = lastUser
      ? `「${label}」是该监听的最后一个用户。删除后不能恢复，端口仍保留但没人能连接；不再需要时可直接删除监听。`
      : `删除「${label}」后不能恢复，其 ss:// 链接会一起失效。`;
    const ok = await askConfirm(rotating
      ? { title: "轮换用户密钥", body: `轮换后「${label}」的旧链接和二维码立即失效，需要把新链接重新发给客户端。`, confirm: "轮换", danger: true }
      : { title: "删除用户", body: deleteBody, confirm: "删除", danger: true });
    if (!ok) return;
  }
  setBusy(true, control);
  try {
    await sendPluginJSON(`api/users/${encodeURIComponent(user.id)}/${action}`, mutateBody());
    await renderWorkspace();
    const message = action === "enable" ? "已启用该用户。" : action === "disable" ? "已停用该用户，链接已失效。" : action === "rotate" ? "已轮换用户密钥，旧分享已失效。" : "已删除用户。";
    showFeedback(message, false);
  } catch (error) {
    showFeedback(errorText(error), true);
  } finally {
    setBusy(false);
  }
};

const closeAppend = () => {
  pendingAppendListen = null;
  releaseDraft(appendDialog);
  showModalError(appendError, "");
  clearFormErrors(appendForm);
  if (appendForm) appendForm.reset();
  if (appendDialog && appendDialog.open) appendDialog.close();
};

const requestCloseAppend = () => requestCloseDraft(appendDialog, closeAppend);

const openAppend = (listen) => {
  if (!canMutate() || !listen) return;
  pendingAppendListen = listen;
  if (appendMeta) {
    appendMeta.textContent = `端口 ${listen.port} · ${methodLabel(listen.method)}`;
    appendMeta.hidden = !appendMeta.textContent;
  }
  if (appendForm) appendForm.reset();
  clearFormErrors(appendForm);
  showModalError(appendError, "");
  trackDraft(appendDialog, appendForm, closeAppend);
  if (appendDialog && typeof appendDialog.showModal === "function") {
    if (appendDialog.open) appendDialog.close();
    appendDialog.showModal();
  }
  if (appendName) appendName.focus();
};

const appendUser = (listen) => {
  openAppend(listen);
};

const deleteListen = async (listen, control = null) => {
  if (busy || !canMutate()) return;
  const ok = await askConfirm({
    title: "删除监听",
    body: `删除端口 ${listen.port} 后不能恢复；这个端口上的 ${(listen.users || []).length} 个用户与分享链接会一起失效。`,
    confirm: "删除",
    danger: true,
  });
  if (!ok) return;
  setBusy(true, control);
  try {
    if (openListenID === listen.id) closeDetail();
    await sendPluginJSON(`api/listens/${encodeURIComponent(listen.id)}/delete`, mutateBody());
    await renderWorkspace();
    showFeedback("已删除监听。", false);
  } catch (error) {
    showFeedback(errorText(error), true);
  } finally {
    setBusy(false);
  }
};

const rotateServerPSK = async (listen, control = null) => {
  if (busy || !canMutate()) return;
  const ok = await askConfirm({ title: "轮换 Server PSK", body: "轮换后该端口所有用户的旧链接和二维码立即失效，需要把新链接重新发给每个客户端。", confirm: "轮换", danger: true });
  if (!ok) return;
  setBusy(true, control);
  try {
    await sendPluginJSON(`api/listens/${encodeURIComponent(listen.id)}/rotate-server`, mutateBody());
    await renderWorkspace();
    showFeedback("已轮换 Server PSK，旧分享已失效。", false);
  } catch (error) {
    showFeedback(errorText(error), true);
  } finally {
    setBusy(false);
  }
};

const canMutate = () => {
  if (busy) return false;
  if (!selectedAgentID) {
    showStatus("请先选择一台节点。", true);
    return false;
  }
  if (!agentOnline) {
    showStatus("该节点离线，不能新增或改动监听。", true);
    return false;
  }
  if (executionReady !== true) {
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
  shareHostInput.dataset.saved = shareHostInput.value.trim();
  const source = String((execution && execution.share_host_source) || "");
  const autoHost = String((execution && execution.share_host_auto) || "").trim();
  let note = shareHostSourceLabel(source);
  if (source === "override" && autoHost) note = `${note}；自动地址为 ${autoHost}`;
  if (!source && !shareHostInput.value) note = "节点没有可用的域名或 IP，填写后客户端才能导入链接。";
  if (shareHostSource) {
    shareHostSource.textContent = note;
    shareHostSource.hidden = !note;
  }
  if (shareHostAuto) {
    shareHostAuto.hidden = source !== "override";
    shareHostAuto.title = autoHost ? `恢复为 ${autoHost}` : "恢复为节点自动地址";
  }
  syncSelectionActions();
};

const shareHostDirty = () => {
  if (!shareHostInput) return false;
  return shareHostInput.value.trim() !== String(shareHostInput.dataset.saved || "");
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
  if (workspaceMetrics) workspaceMetrics.hidden = true;
  setListenLoading(false);
  hideListenError();
  hideRoutingError();
  renderListens([]);
  renderExecutionBadge(null);
  showContext(kind);
  fillShareHost(null, []);
  syncShareHostBar(Boolean(selectedAgentID));
};

const escapeHTML = (value) => String(value || "").replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[character]));
const upstreamOptions = () => {
  const upstreams = routingCache.upstreams || [];
  const head = upstreams.length ? `<option value="">请选择上游</option>` : `<option value="">暂无上游，请先添加</option>`;
  return head + upstreams.map((upstream) => `<option value="${escapeHTML(upstream.id)}">${escapeHTML(upstream.id)} (${escapeHTML(upstream.host)}:${upstream.port})${upstream.enabled ? "" : "（已停用）"}</option>`).join("");
};

const upstreamReferences = (id) => {
  // 与服务端删除校验一致：任何规则或默认出口仍指向该上游时都不能删除。
  const rules = (routingCache.rules || []).filter((rule) => rule && rule.upstream_id === id).length;
  const asDefault = Boolean(id) && routingCache.default_upstream_id === id;
  return { rules, asDefault, total: rules + (asDefault ? 1 : 0) };
};

const ruleMatchesPreset = (rule, preset) => {
  if (!rule || !preset) return false;
  const attributes = ((rule.classification && rule.classification.attributes) || []).map((item) => item.name).join(",");
  return rule.source_id === preset.source_id &&
    rule.classification && rule.classification.kind === preset.kind &&
    rule.classification.name === preset.classification &&
    attributes === (preset.attribute || "");
};

const syncPresetButtons = () => {
  document.querySelectorAll("[data-preset]").forEach((button) => {
    const preset = ROUTE_PRESETS[button.dataset.preset];
    const exists = (routingCache.rules || []).some((rule) => ruleMatchesPreset(rule, preset));
    button.dataset.added = exists ? "true" : "false";
    button.title = exists ? "已有相同匹配的规则，可在表格中调整" : "用该模板新建规则";
  });
};

const defaultRouteLabel = (action, upstreamID) => {
  if (action === "upstream") return upstreamID ? `转发至上游 ${upstreamID}` : "转发至上游（未选择）";
  return action === "reject" ? "拒绝" : "直连";
};

const syncDefaultRouteState = () => {
  if (!routeDefaultAction || !routeSaveDefault) return;
  const action = routeDefaultAction.value;
  const upstreamID = action === "upstream" && routeDefaultUpstream ? routeDefaultUpstream.value : "";
  const savedAction = routingCache.default_action || "direct";
  const savedUpstream = savedAction === "upstream" ? String(routingCache.default_upstream_id || "") : "";
  const dirty = action !== savedAction || upstreamID !== savedUpstream;
  const incomplete = action === "upstream" && !upstreamID;
  const upstreamOption = routeDefaultAction.querySelector('option[value="upstream"]');
  const hasUpstreams = (routingCache.upstreams || []).length > 0;
  if (upstreamOption) {
    upstreamOption.disabled = !hasUpstreams && savedAction !== "upstream";
    upstreamOption.textContent = hasUpstreams ? "转发至指定上游" : "转发至指定上游（先添加上游）";
  }
  routeSaveDefault.disabled = busy || !dirty || incomplete;
  if (routeDefaultHint) {
    if (incomplete) routeDefaultHint.textContent = "请选择默认上游后再保存。";
    else if (dirty) routeDefaultHint.textContent = `有未保存的修改：当前生效的是「${defaultRouteLabel(savedAction, savedUpstream)}」。`;
    else routeDefaultHint.textContent = `当前生效：${defaultRouteLabel(savedAction, savedUpstream)}。`;
    routeDefaultHint.dataset.dirty = dirty ? "true" : "false";
  }
};

const routingIssue = (rule) => {
  if (rule.action !== "upstream") return "";
  const upstream = (routingCache.upstreams || []).find((item) => item.id === rule.upstream_id);
  if (!upstream) return "上游不存在";
  if (!upstream.enabled) return "上游已停用";
  if (!upstream.tcp && !upstream.udp) return "上游不支持 TCP/UDP";
  return "";
};

const syncDefaultUpstreamVisibility = () => {
  if (!routeDefaultAction || !routeDefaultUpstreamField) return;
  routeDefaultUpstreamField.hidden = routeDefaultAction.value !== "upstream";
  syncDefaultRouteState();
};

const syncRouteModalActionVisibility = () => {
  if (!routeActionSelect || !routeUpstreamField) return;
  const isUpstream = routeActionSelect.value === "upstream";
  const hasUpstreams = Boolean(routingCache.upstreams && routingCache.upstreams.length);
  routeUpstreamField.hidden = !isUpstream;
  if (routeUpstreamHint) routeUpstreamHint.hidden = !isUpstream || hasUpstreams;
  if (routeUpstreamSelect) routeUpstreamSelect.disabled = busy || !hasUpstreams;
  if (routeUpstreamSelect && isUpstream && !routeUpstreamSelect.value && hasUpstreams) {
    const enabled = routingCache.upstreams.find((item) => item && item.enabled) || routingCache.upstreams[0];
    routeUpstreamSelect.value = enabled.id;
  }
};

const uniqueRuleID = (base, ignoreIndex = -1) => {
  const clean = String(base || "rule")
    .toLowerCase()
    .replace(/!/g, "not-")
    .replace(/[^a-z0-9._:/-]+/g, "-")
    .replace(/-{2,}/g, "-")
    .replace(/^-+|-+$/g, "") || "rule";
  const existing = new Set((routingCache.rules || []).filter((_item, index) => index !== ignoreIndex).map((item) => item.id));
  if (!existing.has(clean)) return clean;
  let counter = 2;
  while (existing.has(`${clean}-${counter}`)) counter += 1;
  return `${clean}-${counter}`;
};

let editingRuleIndex = -1;
let editingUpstreamID = "";

const autoRuleID = () => {
  if (!routeIdInput || routeIdInput.dataset.auto !== "true") return;
  const classification = routeClassInput ? routeClassInput.value.trim() : "";
  const attribute = routeAttrInput ? routeAttrInput.value.trim() : "";
  const action = routeActionSelect ? routeActionSelect.value : "";
  routeIdInput.value = uniqueRuleID([classification || "rule", attribute, action].filter(Boolean).join("-"), editingRuleIndex);
};

const fillRoutePreset = (presetKey) => {
  const preset = ROUTE_PRESETS[presetKey];
  if (!preset || !routeForm) return;
  if (routeKindSelect) routeKindSelect.value = preset.kind;
  if (routeSourceInput) routeSourceInput.value = preset.source_id;
  if (routeClassInput) routeClassInput.value = preset.classification;
  if (routeAttrInput) routeAttrInput.value = preset.attribute || "";
  if (routeActionSelect) routeActionSelect.value = preset.action;
  if (routeIdInput) {
    routeIdInput.value = uniqueRuleID(preset.id, editingRuleIndex);
    routeIdInput.dataset.auto = "true";
  }
  syncRouteModalActionVisibility();
};

// parseSIP002URI mirrors ParseSIP002 in sip002.go: both SIP002 encodings
// (base64 userinfo and the fully encoded legacy form), #tag dropped, any
// query refused with plugin transports reported as unsupported.
const sip002Base64Decode = (encoded) => {
  if (!encoded || !/^[A-Za-z0-9+/\-_]+={0,2}$/.test(encoded)) return null;
  let normalized = encoded.replace(/-/g, "+").replace(/_/g, "/");
  while (normalized.length % 4 !== 0) normalized += "=";
  try {
    const binary = atob(normalized);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    return null;
  }
};

const parseSIP002URI = (input) => {
  const raw = String(input || "").trim();
  if (!raw.startsWith("ss://")) return { error: "不是有效的 ss:// 链接。" };
  let rest = raw.slice("ss://".length);
  const hash = rest.indexOf("#");
  if (hash >= 0) rest = rest.slice(0, hash);
  const queryIndex = rest.indexOf("?");
  if (queryIndex >= 0) {
    const params = new URLSearchParams(rest.slice(queryIndex + 1));
    rest = rest.slice(0, queryIndex);
    if (params.has("plugin")) return { error: "该链接附带插件传输参数，本面板不支持此类 ss:// 链接。" };
    if (Array.from(params.keys()).length > 0) return { error: "该链接带有不支持的查询参数。" };
  }
  if (!rest) return { error: "ss:// 链接内容为空。" };
  let method = "";
  let password = "";
  let hostport = "";
  if (rest.includes("@")) {
    const at = rest.indexOf("@");
    const decoded = sip002Base64Decode(rest.slice(0, at));
    hostport = rest.slice(at + 1);
    if (decoded === null) return { error: "链接的加密信息不是有效的 Base64。" };
    const separator = decoded.indexOf(":");
    if (separator <= 0 || separator === decoded.length - 1) return { error: "链接缺少加密方式或连接密钥。" };
    method = decoded.slice(0, separator);
    password = decoded.slice(separator + 1);
  } else {
    const decoded = sip002Base64Decode(rest);
    if (decoded === null) return { error: "链接不是有效的 Base64 编码。" };
    const separator = decoded.indexOf(":");
    const at = decoded.lastIndexOf("@");
    if (separator <= 0 || at <= separator || at === decoded.length - 1) return { error: "链接缺少加密方式、密钥或服务器地址。" };
    method = decoded.slice(0, separator);
    password = decoded.slice(separator + 1, at);
    hostport = decoded.slice(at + 1);
  }
  let host = "";
  let portText = "";
  if (hostport.startsWith("[")) {
    const close = hostport.indexOf("]");
    if (close < 0 || hostport[close + 1] !== ":") return { error: "服务器地址或端口不完整。" };
    host = hostport.slice(1, close);
    portText = hostport.slice(close + 2);
  } else {
    const colon = hostport.lastIndexOf(":");
    if (colon <= 0 || hostport.indexOf(":") !== colon) return { error: "服务器地址或端口不完整。" };
    host = hostport.slice(0, colon);
    portText = hostport.slice(colon + 1);
  }
  if (!host) return { error: "链接缺少服务器地址。" };
  const port = /^\d+$/.test(portText) ? Number(portText) : NaN;
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { error: "端口需为 1-65535 的整数。" };
  if (!Object.prototype.hasOwnProperty.call(METHOD_LABELS, method)) return { error: `不支持的加密方式「${method}」。` };
  return { method, password, host, port };
};

const showUpstreamImportHint = (message) => {
  if (!upstreamImportHint) return;
  upstreamImportHint.hidden = !message;
  upstreamImportHint.textContent = message || "";
};

const fillUpstreamFromSIP002 = (parsed) => {
  const assignments = { method: parsed.method, host: parsed.host, port: parsed.port, password: parsed.password };
  Object.entries(assignments).forEach(([name, value]) => {
    const input = formField(upstreamForm, name);
    if (input) input.value = value;
  });
  if (upstreamImportInput) {
    // The pasted URI embeds the password; clear it so the secret only lives
    // in the password field until the admin submits the normal create flow.
    upstreamImportInput.value = "";
    clearFieldError(upstreamImportInput);
  }
  showUpstreamImportHint("已从 ss:// 链接填充加密方式、地址、端口与密钥，请核对后提交。");
};

const applySIP002Paste = () => {
  if (!upstreamImportInput) return true;
  const value = upstreamImportInput.value.trim();
  if (!value) {
    clearFieldError(upstreamImportInput);
    showUpstreamImportHint("");
    return true;
  }
  const parsed = parseSIP002URI(value);
  if (parsed.error) {
    markFieldError(upstreamImportInput, parsed.error);
    showUpstreamImportHint("");
    return false;
  }
  fillUpstreamFromSIP002(parsed);
  return true;
};

const setUpstreamModalMode = (editing) => {
  if (upstreamDialogTitle) upstreamDialogTitle.textContent = editing ? "编辑上游节点" : "添加上游节点";
  if (upstreamDialogDesc) {
    upstreamDialogDesc.textContent = editing
      ? "修改上游节点地址、端口、加密方式或协议；连接密钥留空则沿用现有值。"
      : "配置远端 Shadowsocks 节点，供分流规则或默认路由转发使用。";
  }
  if (upstreamSubmit) upstreamSubmit.textContent = editing ? "保存上游" : "添加上游";
  const idInput = formField(upstreamForm, "id");
  if (idInput) idInput.disabled = editing;
  const passwordInput = formField(upstreamForm, "password");
  if (passwordInput) passwordInput.required = !editing;
  if (upstreamPasswordHint) upstreamPasswordHint.hidden = !editing;
};

const openUpstreamModal = (upstream = null) => {
  if (!upstreamDialog) return;
  if (upstreamForm) upstreamForm.reset();
  editingUpstreamID = upstream ? upstream.id : "";
  setUpstreamModalMode(Boolean(upstream));
  if (upstream) {
    const fields = { id: upstream.id, host: upstream.host, port: upstream.port, method: upstream.method };
    Object.entries(fields).forEach(([name, value]) => {
      const input = formField(upstreamForm, name);
      if (input && value !== undefined && value !== null) input.value = value;
    });
    const tcpInput = formField(upstreamForm, "tcp");
    const udpInput = formField(upstreamForm, "udp");
    if (tcpInput) tcpInput.checked = Boolean(upstream.tcp);
    if (udpInput) udpInput.checked = Boolean(upstream.udp);
  }
  clearFormErrors(upstreamForm);
  showModalError(upstreamError, "");
  trackDraft(upstreamDialog, upstreamForm, closeUpstreamModal);
  if (upstreamDialog.open) upstreamDialog.close();
  if (typeof upstreamDialog.showModal === "function") upstreamDialog.showModal();
};

const closeUpstreamModal = () => {
  releaseDraft(upstreamDialog);
  showModalError(upstreamError, "");
  showUpstreamImportHint("");
  clearFormErrors(upstreamForm);
  if (upstreamForm) upstreamForm.reset();
  editingUpstreamID = "";
  setUpstreamModalMode(false);
  if (upstreamDialog && upstreamDialog.open) upstreamDialog.close();
};

const requestCloseUpstreamModal = () => requestCloseDraft(upstreamDialog, closeUpstreamModal);

const setRouteModalMode = (editing) => {
  if (routeDialogTitle) routeDialogTitle.textContent = editing ? "编辑分流规则" : "添加分流规则";
  if (routeDialogDesc) {
    routeDialogDesc.textContent = editing
      ? "修改匹配条件或命中动作，保存后按原顺序生效。"
      : "选择数据集分类与命中后的处理动作，支持一键套用常见场景。";
  }
  if (routeSubmit) routeSubmit.textContent = editing ? "保存规则" : "添加规则";
};

const openRouteModal = (presetKey = "", editIndex = -1) => {
  if (!routeDialog) return;
  if (routeForm) routeForm.reset();
  const rule = editIndex >= 0 ? (routingCache.rules || [])[editIndex] : null;
  editingRuleIndex = rule ? editIndex : -1;
  setRouteModalMode(Boolean(rule));
  const options = upstreamOptions();
  if (routeUpstreamSelect) routeUpstreamSelect.innerHTML = options;
  if (rule) {
    const classification = rule.classification || {};
    if (routeKindSelect) routeKindSelect.value = classification.kind || "domain";
    if (routeSourceInput) routeSourceInput.value = rule.source_id || "";
    if (routeClassInput) routeClassInput.value = classification.name || "";
    if (routeAttrInput) routeAttrInput.value = ((classification.attributes || [])[0] || {}).name || "";
    if (routeActionSelect) routeActionSelect.value = rule.action || "direct";
    if (routeUpstreamSelect) routeUpstreamSelect.value = rule.upstream_id || "";
    if (routeIdInput) {
      routeIdInput.value = rule.id;
      routeIdInput.dataset.auto = "false";
    }
    syncRouteModalActionVisibility();
  } else if (presetKey && ROUTE_PRESETS[presetKey]) {
    fillRoutePreset(presetKey);
  } else {
    if (routeSourceInput) routeSourceInput.value = "geosite";
    if (routeClassInput) routeClassInput.value = "category-ai";
    if (routeIdInput) {
      routeIdInput.value = uniqueRuleID("ai-not-cn");
      routeIdInput.dataset.auto = "true";
    }
    syncRouteModalActionVisibility();
  }
  clearFormErrors(routeForm);
  showModalError(routeError, "");
  trackDraft(routeDialog, routeForm, closeRouteModal);
  if (routeDialog.open) routeDialog.close();
  if (typeof routeDialog.showModal === "function") routeDialog.showModal();
};

const closeRouteModal = () => {
  releaseDraft(routeDialog);
  showModalError(routeError, "");
  clearFormErrors(routeForm);
  if (routeForm) routeForm.reset();
  editingRuleIndex = -1;
  setRouteModalMode(false);
  if (routeDialog && routeDialog.open) routeDialog.close();
};

const requestCloseRouteModal = () => requestCloseDraft(routeDialog, closeRouteModal);

bindDraftDialog(createDialog, createForm, closeCreate);
bindDraftDialog(appendDialog, appendForm, closeAppend);
bindDraftDialog(upstreamDialog, upstreamForm, closeUpstreamModal);
bindDraftDialog(routeDialog, routeForm, closeRouteModal);

const tableCell = (text, className = "", label = "") => {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  if (label) cell.dataset.label = label;
  cell.textContent = text;
  return cell;
};

const renderRouting = (routing, routeStatus = []) => {
  routingCache = routing || { upstreams: [], rules: [], default_action: "direct" };
  routingCache.upstreams ||= [];
  routingCache.rules ||= [];
  if (routeStatus && routeStatus.length) routeStatusCache = routeStatus;

  const rulesCount = routingCache.rules.length;
  const upstreamsCount = routingCache.upstreams.length;
  if (routingCountNode) {
    routingCountNode.hidden = !rulesCount;
    routingCountNode.textContent = rulesCount ? `${rulesCount}` : "";
  }
  if (routeBadge) routeBadge.textContent = `${rulesCount} 条`;
  if (upstreamBadge) upstreamBadge.textContent = `${upstreamsCount} 个`;
  if (routeEmpty) routeEmpty.hidden = rulesCount > 0;
  if (upstreamEmpty) upstreamEmpty.hidden = upstreamsCount > 0;
  if (rulesTable) rulesTable.hidden = rulesCount === 0;
  if (upstreamsTable) upstreamsTable.hidden = upstreamsCount === 0;

  if (upstreamList) {
    upstreamList.replaceChildren();
    routingCache.upstreams.forEach((upstream) => {
      const row = document.createElement("tr");
      row.className = "route-row";
      row.dataset.id = upstream.id;

      const identity = document.createElement("td");
      identity.className = "route-upstream-identity";
      identity.dataset.label = "标识";
      const idText = document.createElement("strong");
      idText.className = "route-id";
      idText.textContent = upstream.id;
      // secret_ref 是内部密钥引用，只放进悬停提示，不占表格宽度。
      idText.title = upstream.secret_ref ? `密钥引用 ${upstream.secret_ref}@${upstream.secret_version}` : upstream.id;
      const refs = upstreamReferences(upstream.id);
      const usage = document.createElement("span");
      usage.className = "ui-help-text route-usage";
      usage.textContent = refs.total
        ? [refs.rules ? `${refs.rules} 条规则` : "", refs.asDefault ? "默认出口" : ""].filter(Boolean).join(" · ") + " 在用"
        : "未被引用";
      identity.append(idText, usage);

      const address = tableCell(`${upstream.host}:${upstream.port}`, "ui-table__mono route-address", "地址");
      address.title = address.textContent;

      const capability = document.createElement("td");
      capability.className = "route-capability";
      capability.dataset.label = "加密与协议";
      const methodText = document.createElement("span");
      methodText.className = "route-method";
      methodText.textContent = methodLabel(upstream.method);
      const protocolText = document.createElement("span");
      protocolText.className = "ui-help-text";
      protocolText.textContent = [upstream.tcp ? "TCP" : "", upstream.udp ? "UDP" : ""].filter(Boolean).join(" + ") || "未开启协议";
      capability.append(methodText, protocolText);

      const status = document.createElement("td");
      status.dataset.label = "状态";
      const statusWrap = document.createElement("div");
      statusWrap.className = "route-status";
      statusWrap.append(renderStatusPill(upstream.enabled ? "启用" : "停用", upstream.enabled));
      const testResult = document.createElement("span");
      testResult.className = "ui-help-text route-status__hint route-test-result";
      testResult.dataset.upstreamTest = upstream.id;
      testResult.hidden = true;
      statusWrap.append(testResult);
      status.append(statusWrap);

      const actions = document.createElement("td");
      actions.className = "ui-table__actions";
      actions.dataset.label = "操作";
      const probe = document.createElement("button");
      probe.type = "button";
      probe.className = "ui-btn ui-btn--ghost ui-btn--sm";
      probe.textContent = "测试";
      probe.setAttribute("aria-label", `测试上游 ${upstream.id} 连通性`);
      probe.title = `从当前节点探测上游 ${upstream.id}`;
      probe.onclick = (event) => testUpstream(upstream.id, event.currentTarget);
      const edit = document.createElement("button");
      edit.type = "button";
      edit.className = "ui-btn ui-btn--ghost ui-btn--sm";
      edit.textContent = "编辑";
      edit.setAttribute("aria-label", `编辑上游 ${upstream.id}`);
      edit.onclick = () => openUpstreamModal(upstream);
      const toggle = document.createElement("button");
      toggle.type = "button";
      toggle.className = "ui-btn ui-btn--ghost ui-btn--sm";
      toggle.textContent = upstream.enabled ? "停用" : "启用";
      toggle.onclick = (event) => mutateUpstream(upstream.id, upstream.enabled ? "disable" : "enable", event.currentTarget);
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "ui-btn ui-btn--ghost ui-btn--sm btn-danger-text";
      remove.textContent = "删除";
      remove.disabled = refs.total > 0;
      remove.title = refs.total ? "仍被分流规则或默认出口引用，先改掉引用再删除" : `删除上游 ${upstream.id}`;
      remove.onclick = (event) => mutateUpstream(upstream.id, "delete", event.currentTarget);
      actions.append(probe, edit, toggle, remove);

      row.append(identity, address, capability, status, actions);
      upstreamList.append(row);
    });
  }

  const options = upstreamOptions();
  if (routeUpstreamSelect) routeUpstreamSelect.innerHTML = options;
  if (routeDefaultUpstream) routeDefaultUpstream.innerHTML = options;
  if (routeDefaultAction) routeDefaultAction.value = routingCache.default_action || "direct";
  if (routeDefaultUpstream) routeDefaultUpstream.value = routingCache.default_upstream_id || "";
  syncDefaultUpstreamVisibility();
  syncRouteModalActionVisibility();

  if (routeList) {
    routeList.replaceChildren();
    routingCache.rules.forEach((rule, index) => {
      const row = document.createElement("tr");
      row.className = "route-row";
      row.dataset.id = rule.id;

      const order = tableCell(`#${index + 1}`, "route-order", "顺序");
      const identity = document.createElement("td");
      identity.dataset.label = "规则";
      const idText = document.createElement("strong");
      idText.className = "route-id";
      idText.textContent = rule.id;
      identity.append(idText);

      const attributes = (rule.classification.attributes || []).map((item) => item.name).join(",");
      const kindName = KIND_LABELS[rule.classification.kind] || rule.classification.kind;
      const match = document.createElement("td");
      match.className = "route-match";
      match.dataset.label = "匹配";
      const matchMain = document.createElement("span");
      matchMain.className = "route-match__main";
      matchMain.textContent = `${rule.source_id}:${rule.classification.name}`;
      matchMain.title = `数据源 ${rule.source_id} · ${kindName}:${rule.classification.name}${attributes ? ` [${attributes}]` : ""}`;
      const matchSub = document.createElement("span");
      matchSub.className = "ui-help-text";
      matchSub.textContent = [kindName, attributes ? `属性 ${attributes}` : ""].filter(Boolean).join(" · ");
      match.append(matchMain, matchSub);

      const actionCell = document.createElement("td");
      actionCell.dataset.label = "动作";
      actionCell.className = "route-action-cell";
      const actionText = ACTION_LABELS[rule.action] || rule.action;
      const actionBadge = document.createElement("span");
      const actionTone = rule.action === "reject" ? "danger" : rule.action === "upstream" ? "info" : "success";
      actionBadge.className = `ui-badge ui-badge--${actionTone} route-action`;
      actionBadge.textContent = actionText;
      actionCell.append(actionBadge);
      if (rule.upstream_id) {
        const target = document.createElement("span");
        target.className = "route-target";
        target.textContent = `→ ${rule.upstream_id}`;
        actionCell.append(target);
      }

      const applied = (routeStatus.length ? routeStatus : routeStatusCache).find((item) => item.rule_id === rule.id) || {};
      const rawIssue = applied.failure || routingIssue(rule);
      const issueLabel = FAILURE_LABELS[rawIssue] || rawIssue;
      const status = document.createElement("td");
      status.dataset.label = "状态";
      const statusWrap = document.createElement("div");
      statusWrap.className = "route-status";
      const issueTone = PARTIAL_FAILURES.has(rawIssue) ? "warning" : "danger";
      statusWrap.append(renderStatusPill(issueLabel || "规则就绪", !issueLabel, issueLabel ? issueTone : "success"));
      if (applied.version_digest) {
        const version = document.createElement("span");
        version.className = "ui-help-text route-status__hint";
        version.textContent = `版本 ${shortDigest(applied.version_digest)}`;
        version.title = applied.version_digest;
        statusWrap.append(version);
      }
      const hintText = rawIssue ? FAILURE_HINTS[rawIssue] || "" : "";
      if (hintText) {
        const hint = document.createElement("span");
        hint.className = "ui-help-text route-status__hint";
        hint.textContent = hintText;
        statusWrap.append(hint);
      }
      status.append(statusWrap);

      const actions = document.createElement("td");
      actions.className = "ui-table__actions";
      actions.dataset.label = "操作";
      const buttons = [
        { text: "↑", label: `上移规则 ${rule.id}`, title: "上移", run: (event) => moveRoute(index, -1, event.currentTarget), disabled: index === 0, icon: true },
        { text: "↓", label: `下移规则 ${rule.id}`, title: "下移", run: (event) => moveRoute(index, 1, event.currentTarget), disabled: index === routingCache.rules.length - 1, icon: true },
        { text: "编辑", label: `编辑规则 ${rule.id}`, run: () => openRouteModal("", index), disabled: false },
        { text: "删除", label: `删除规则 ${rule.id}`, run: (event) => removeRoute(index, event.currentTarget), disabled: false, danger: true },
      ];
      buttons.forEach((item) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = `ui-btn ui-btn--ghost ui-btn--sm${item.icon ? " route-move" : ""}${item.danger ? " btn-danger-text" : ""}`;
        button.textContent = item.text;
        button.setAttribute("aria-label", item.label);
        if (item.title) button.title = item.title;
        button.disabled = item.disabled;
        button.onclick = item.run;
        actions.append(button);
      });

      row.append(order, identity, match, actionCell, status, actions);
      routeList.append(row);
    });
  }

  syncPresetButtons();
  syncDefaultRouteState();
  updateOverviewMetrics();
  if (busy) setBusy(true);
};

const loadRouting = async () => {
  hideRoutingError();
  try {
    const payload = await panelJSON(`api/routing?agent_id=${encodeURIComponent(selectedAgentID || "")}`);
    routeStatusCache = payload.route_status || [];
    renderRouting(payload.routing, routeStatusCache);
  } catch (error) {
    if (error && error.denied) throw error;
    showRoutingError(errorText(error, "暂时无法读取规则与上游。刷新页面，或稍后重试。"));
  }
};

// 写入接口只回配置，不回运行状态；保存后静默拉一次，让新规则显示当前状态。
const refreshRouteStatus = async () => {
  try {
    const payload = await panelJSON(`api/routing?agent_id=${encodeURIComponent(selectedAgentID || "")}`);
    routeStatusCache = payload.route_status || [];
    renderRouting(payload.routing, routeStatusCache);
  } catch (_error) {
    // 配置已保存成功；状态刷新失败时保留现有显示，下次加载再更新。
  }
};

const saveRoutingRules = async () => {
  const payload = await sendPluginJSON("api/routing", { rules: routingCache.rules, default_action: routingCache.default_action || "direct", default_upstream_id: routingCache.default_upstream_id || "" });
  renderRouting(payload.routing);
  await refreshRouteStatus();
};

const shortDigest = (digest) => {
  const text = String(digest || "").trim();
  if (!text) return "无";
  const hex = text.includes(":") ? text.slice(text.lastIndexOf(":") + 1) : text;
  return hex.length > 12 ? `${hex.slice(0, 12)}…` : hex;
};

const REFRESH_SOURCE_LABELS = {
  updated: "已更新",
  latest: "已是最新",
  skipped: "未刷新",
  unresolved: "版本未知",
};

const describeRefreshSource = (source) => {
  const name = source.source_id || "?";
  if (source.status === "error") return `${name} 刷新失败`;
  const before = shortDigest(source.before_digest);
  const after = shortDigest(source.after_digest);
  const label = REFRESH_SOURCE_LABELS[source.status] || source.status || "未知";
  if (source.status === "updated") return `${name} ${before} → ${after}（${label}）`;
  return `${name} ${after}（${label}）`;
};

const showRouteRefreshStatus = (message, isError) => {
  if (!routeRefreshStatus) return;
  routeRefreshStatus.hidden = !message;
  routeRefreshStatus.textContent = message || "";
  routeRefreshStatus.dataset.error = isError ? "true" : "false";
};

const refreshDatasets = async (control = null) => {
  if (busy) return;
  setBusy(true, control, "刷新中…");
  try {
    const payload = await sendPluginJSON("api/routing/refresh", {});
    const report = payload.refresh || {};
    const parts = (report.sources || []).map(describeRefreshSource);
    const failedNodes = (report.nodes || [])
      .filter((node) => !node.routing_applied)
      .map((node) => `${node.agent_id}：${node.routing_error || "应用失败"}`);
    if (failedNodes.length) parts.push(`节点未应用 ${failedNodes.join("；")}`);
    const detail = [report.message || "", ...parts].filter(Boolean).join(" ");
    showRouteRefreshStatus(detail || "已刷新数据集。", report.mode === "reapply-only" || failedNodes.length > 0);
    showStatus(report.mode === "reapply-only" ? "宿主未授予数据集刷新权限，已重新应用当前绑定。" : report.message || "已刷新数据集。", false);
    await refreshRouteStatus();
  } catch (error) {
    showRouteRefreshStatus("", false);
    showStatus(errorText(error), true);
  } finally {
    setBusy(false);
  }
};

if (routeRefreshBtn) routeRefreshBtn.addEventListener("click", (event) => refreshDatasets(event.currentTarget));

const moveRoute = async (index, delta, control = null) => {
  if (busy) return;
  const next = index + delta;
  if (next < 0 || next >= routingCache.rules.length) return;
  const previous = routingCache.rules.slice();
  [routingCache.rules[index], routingCache.rules[next]] = [routingCache.rules[next], routingCache.rules[index]];
  const movedID = routingCache.rules[next].id;
  setBusy(true, control, "…");
  try {
    await saveRoutingRules();
    showStatus(`已把规则「${movedID}」移到第 ${next + 1} 位。`, false);
  } catch (error) {
    routingCache.rules = previous;
    renderRouting(routingCache);
    showStatus(errorText(error), true);
  } finally {
    setBusy(false);
  }
};

const removeRoute = async (index, control = null) => {
  if (busy) return;
  const target = routingCache.rules[index];
  const ok = await askConfirm({
    title: "删除分流规则",
    body: target
      ? `删除规则「${target.id}」后不能恢复；命中它的流量会改走后续规则或默认出口。`
      : "删除后不能恢复；命中它的流量会改走后续规则或默认出口。",
    confirm: "删除",
    danger: true,
  });
  if (!ok) return;
  const previous = routingCache.rules.slice();
  routingCache.rules.splice(index, 1);
  setBusy(true, control);
  try {
    await saveRoutingRules();
    showStatus("已删除分流规则。", false);
  } catch (error) {
    routingCache.rules = previous;
    renderRouting(routingCache);
    showStatus(errorText(error), true);
  } finally {
    setBusy(false);
  }
};

const UPSTREAM_TEST_LABELS = {
  "tcp-unsupported": "仅 UDP 上游不支持 TCP 探测",
  "upstream-auth-failed": "认证失败：密钥或加密方式与上游不匹配",
  "upstream-protocol-error": "协议错误：上游未返回有效的 Shadowsocks 响应",
  "upstream-timeout": "连接上游超时",
  "upstream-unavailable": "上游凭据或配置不可用",
  "upstream-connection-failed": "无法连接到上游地址",
  "agent-offline": "节点离线，无法发起探测",
  "probe-failed": "探测未能完成",
};

const showUpstreamTestResult = (id, message, isError) => {
  const node = upstreamList ? upstreamList.querySelector(`[data-upstream-test="${CSS.escape(id)}"]`) : null;
  if (!node) return;
  node.hidden = !message;
  node.textContent = message || "";
  node.dataset.error = isError ? "true" : "false";
};

const testUpstream = async (id, control = null) => {
  if (busy) return;
  setBusy(true, control, "测试中…");
  showUpstreamTestResult(id, "正在从节点探测上游…", false);
  try {
    const payload = await sendPluginJSON(`api/upstreams/${encodeURIComponent(id)}/test`, { agent_id: selectedAgentID });
    const result = payload.test || {};
    if (result.reachable) {
      const latency = Number.isFinite(result.rtt_ms) ? `，往返约 ${result.rtt_ms} ms` : "";
      showUpstreamTestResult(id, `可达${latency}`, false);
      showStatus(`上游「${id}」从该节点可达${latency}。`, false);
      return;
    }
    const label = UPSTREAM_TEST_LABELS[result.failure] || result.failure || "不可达";
    showUpstreamTestResult(id, label, true);
    showStatus(`上游「${id}」不可达：${label}`, true);
  } catch (error) {
    showUpstreamTestResult(id, errorText(error, "测试失败"), true);
    showStatus(errorText(error), true);
  } finally {
    setBusy(false);
  }
};

const mutateUpstream = async (id, action, control = null) => {
  if (busy) return;
  if (action === "disable") {
    const ok = await askConfirm({
      title: "停用上游节点",
      body: `停用「${id}」后，引用它的分流规则会暂时不可用；可随时再启用。`,
      confirm: "停用",
      danger: true,
    });
    if (!ok) return;
  }
  if (action === "delete") {
    const ok = await askConfirm({
      title: "删除上游节点",
      body: `删除「${id}」后不能恢复；已被规则引用的上游无法直接删除。`,
      confirm: "删除",
      danger: true,
    });
    if (!ok) return;
  }
  setBusy(true, control);
  try {
    const payload = await sendPluginJSON(`api/upstreams/${encodeURIComponent(id)}/${action}`, {});
    renderRouting(payload.routing);
    await refreshRouteStatus();
    const message = action === "delete" ? "已删除上游节点。" : action === "disable" ? "已停用上游节点。" : "已启用上游节点。";
    showStatus(message, false);
  } catch (error) {
    showStatus(errorText(error), true);
  } finally {
    setBusy(false);
  }
};

if (openUpstreamDialogBtn) openUpstreamDialogBtn.addEventListener("click", () => openUpstreamModal());
if (upstreamCancel) upstreamCancel.addEventListener("click", requestCloseUpstreamModal);
if (upstreamImportInput) {
  upstreamImportInput.addEventListener("change", applySIP002Paste);
  upstreamImportInput.addEventListener("input", () => {
    if (!upstreamImportInput.value.trim()) {
      clearFieldError(upstreamImportInput);
      showUpstreamImportHint("");
    }
  });
}
if (upstreamDialog) {
  upstreamDialog.addEventListener("click", (event) => {
    if (event.target === upstreamDialog) closeUpstreamModal();
  });
}

if (openRouteDialogBtn) openRouteDialogBtn.addEventListener("click", () => openRouteModal(""));
if (routeCancel) routeCancel.addEventListener("click", requestCloseRouteModal);
if (routeDialog) {
  routeDialog.addEventListener("click", (event) => {
    if (event.target === routeDialog) closeRouteModal();
  });
}

document.querySelectorAll("[data-preset]").forEach((btn) => {
  btn.addEventListener("click", () => openRouteModal(btn.dataset.preset));
});

document.querySelectorAll("[data-fill-preset]").forEach((btn) => {
  btn.addEventListener("click", () => fillRoutePreset(btn.dataset.fillPreset));
});

if (routeActionSelect) routeActionSelect.addEventListener("change", syncRouteModalActionVisibility);
if (routeDefaultAction) routeDefaultAction.addEventListener("change", syncDefaultUpstreamVisibility);

if (upstreamForm) upstreamForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy) return;
  clearFormErrors(upstreamForm);
  showModalError(upstreamError, "");
  // A still-filled import field means the admin pasted a link and submitted
  // before the change handler ran; a parse failure must not create anything.
  if (!applySIP002Paste()) {
    if (upstreamImportInput) upstreamImportInput.focus();
    return;
  }
  const form = new FormData(upstreamForm);
  const editing = editingUpstreamID !== "";
  const id = editing ? editingUpstreamID : String(form.get("id") || "").trim();
  const host = String(form.get("host") || "").trim();
  const port = Number(form.get("port") || 0);
  const method = String(form.get("method") || "");
  const password = String(form.get("password") || "").trim();
  const idInput = formField(upstreamForm, "id");
  const hostInput = formField(upstreamForm, "host");
  const portInput = formField(upstreamForm, "port");
  const passwordInput = formField(upstreamForm, "password");
  if (!id) {
    markFieldError(idInput, "请填写上游标识。");
    if (idInput) idInput.focus();
    return;
  }
  if (!editing && (routingCache.upstreams || []).some((item) => item && item.id === id)) {
    markFieldError(idInput, "该上游标识已存在，请换一个。");
    if (idInput) idInput.focus();
    return;
  }
  if (!host) {
    markFieldError(hostInput, "请填写服务器地址。");
    if (hostInput) hostInput.focus();
    return;
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    markFieldError(portInput, "端口需为 1-65535 的整数。");
    if (portInput) portInput.focus();
    return;
  }
  if (!editing && !password) {
    markFieldError(passwordInput, "请填写连接密钥。");
    if (passwordInput) passwordInput.focus();
    return;
  }
  setBusy(true, upstreamSubmit, editing ? "正在保存上游…" : "正在添加上游…");
  try {
    const request = { id, host, port, method, tcp: form.get("tcp") === "on", udp: form.get("udp") === "on" };
    let payload;
    if (editing) {
      // 密钥留空时后端沿用现有凭据；只在填写时随更新轮换。
      if (password) request.password = password;
      payload = await sendPluginJSON(`api/upstreams/${encodeURIComponent(id)}/update`, request);
    } else {
      request.password = password;
      payload = await sendPluginJSON("api/upstreams", request);
    }
    closeUpstreamModal();
    renderRouting(payload.routing);
    await refreshRouteStatus();
    showStatus(editing ? `已保存上游节点「${id}」的修改。` : `已添加上游节点「${id}」，现在可以在分流规则或默认出口中选用。`, false);
  } catch (error) {
    showModalError(upstreamError, errorText(error, editing ? "保存上游失败，请检查地址、端口和加密方式后重试。" : "添加上游失败，请检查标识、地址和密钥后重试。"));
    if (error && error.status === 400) markFieldError(editing ? hostInput : idInput, editing ? "字段无效，请检查后重试。" : "标识无效或已存在，请检查后重试。");
    else if (/端口/.test(String((error && error.message) || ""))) markFieldError(portInput, errorText(error));
  } finally {
    setBusy(false);
  }
});

if (routeForm) routeForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy) return;
  clearFormErrors(routeForm);
  showModalError(routeError, "");
  const form = new FormData(routeForm);
  const sourceID = String(form.get("source_id") || "").trim();
  const attribute = String(form.get("attribute") || "").trim();
  const classification = { name: String(form.get("classification") || "").trim(), kind: String(form.get("kind") || "") };
  if (attribute) classification.attributes = [{ name: attribute, boolean: true }];
  const action = String(form.get("action") || "");
  const editing = editingRuleIndex >= 0 && editingRuleIndex < (routingCache.rules || []).length;
  const ruleID = String(form.get("id") || "").trim() || uniqueRuleID(`${classification.name}-${action}`, editing ? editingRuleIndex : -1);
  if (!sourceID) {
    markFieldError(routeSourceInput, "请填写数据源 ID，例如 geosite 或 geoip。");
    if (routeSourceInput) routeSourceInput.focus();
    return;
  }
  if (!classification.name) {
    markFieldError(routeClassInput, "请填写分类名称，例如 category-ai 或 cn。");
    if (routeClassInput) routeClassInput.focus();
    return;
  }
  if ((routingCache.rules || []).some((rule, index) => rule && rule.id === ruleID && (!editing || index !== editingRuleIndex))) {
    markFieldError(routeIdInput, "该规则标识已存在，请换一个。");
    if (routeIdInput) routeIdInput.focus();
    return;
  }
  if (action === "upstream" && !String(form.get("upstream_id") || "")) {
    markFieldError(routeUpstreamSelect, (routingCache.upstreams || []).length ? "请选择要转发的上游节点。" : "还没有上游节点，请先添加上游或改为直连 / 拒绝。");
    if (routeUpstreamSelect && !routeUpstreamSelect.disabled) routeUpstreamSelect.focus();
    return;
  }
  const nextRule = { id: ruleID, source_id: sourceID, classification, action, ...(action === "upstream" ? { upstream_id: String(form.get("upstream_id") || "") } : {}) };
  const previous = routingCache.rules.slice();
  if (editing) routingCache.rules[editingRuleIndex] = nextRule;
  else routingCache.rules.push(nextRule);
  setBusy(true, routeSubmit, editing ? "正在保存…" : "正在添加规则…");
  try {
    await saveRoutingRules();
    closeRouteModal();
    showStatus(editing ? `已保存规则「${ruleID}」。` : `已添加分流规则「${ruleID}」，位于第 ${routingCache.rules.length} 位。`, false);
  } catch (error) {
    routingCache.rules = previous;
    renderRouting(routingCache);
    showModalError(routeError, errorText(error, "保存规则失败，请检查数据源、分类和上游后重试。"));
    if (error && error.status === 400) markFieldError(routeClassInput, "请确认数据源与分类名称存在后重试。");
  } finally {
    setBusy(false);
  }
});

if (routeIdInput) routeIdInput.addEventListener("input", () => {
  routeIdInput.dataset.auto = routeIdInput.value.trim() ? "false" : "true";
});
[routeClassInput, routeAttrInput].forEach((input) => {
  if (input) input.addEventListener("input", autoRuleID);
});
if (routeActionSelect) routeActionSelect.addEventListener("change", autoRuleID);
if (routeKindSelect) routeKindSelect.addEventListener("change", () => {
  // 域名类走 geosite，IP 类走 geoip；只在数据源仍是另一套默认值时自动切换，不覆盖自定义数据源。
  if (!routeSourceInput) return;
  const source = routeSourceInput.value.trim();
  const kind = routeKindSelect.value;
  if (kind === "domain" && source === "geoip") routeSourceInput.value = "geosite";
  else if ((kind === "country" || kind === "cidr") && source === "geosite") routeSourceInput.value = "geoip";
});

if (routeSaveDefault) routeSaveDefault.addEventListener("click", async () => {
  if (busy) return;
  const previous = { action: routingCache.default_action, upstream: routingCache.default_upstream_id };
  routingCache.default_action = routeDefaultAction.value;
  routingCache.default_upstream_id = routeDefaultAction.value === "upstream" ? routeDefaultUpstream.value : "";
  setBusy(true, routeSaveDefault, "正在保存…");
  try {
    await saveRoutingRules();
    showStatus(`已保存默认路由：${defaultRouteLabel(routingCache.default_action, routingCache.default_upstream_id)}。`, false);
  } catch (error) {
    routingCache.default_action = previous.action;
    routingCache.default_upstream_id = previous.upstream;
    showStatus(errorText(error), true);
  } finally {
    setBusy(false);
  }
});
if (routeDefaultUpstream) routeDefaultUpstream.addEventListener("change", syncDefaultRouteState);

const renderWorkspace = async () => {
  const seq = workspaceSeq + 1;
  workspaceSeq = seq;
  const agent = selectedAgent();
  agentOnline = isAgentOnline(agent);
  closeCreate();
  if (!selectedAgentID) {
    clearWorkspace(agentsCache.length ? "empty" : "undeployed");
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
  workspaceNode.hidden = false;
  setListenLoading(true);
  hideListenError();
  renderListens([], { keepDetail: true });
  let payload = null;
  try {
    payload = await panelJSON(`api/listens?agent_id=${encodeURIComponent(selectedAgentID)}`);
  } catch (error) {
    if (seq !== workspaceSeq) return;
    setListenLoading(false);
    if (error && error.denied) throw error;
    showListenError(errorText(error, "暂时无法读取监听列表。刷新页面，或稍后重试。"));
    if (openListenID) closeDetail();
    fillShareHost(execution, []);
    syncShareHostBar(true);
    return;
  }
  if (seq !== workspaceSeq) return;
  setListenLoading(false);
  renderListens(payload.listens);
  await loadRouting();
  fillShareHost(execution, payload.listens);
  syncShareHostBar(true);
  if (payload.error) showStatus(payload.error, true);
};

const loadAgents = async () => {
  const payload = await panelJSON("/panel-api/agents");
  const remotes = Array.isArray(payload.agents)
    ? payload.agents.filter((agent) => agent && agent.is_local !== true && agent.mode !== "local")
    : [];
  const plugin = await panelJSON("/panel-api/plugins/shadowsocks-server");
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
  const next = String(value || "");
  if (next === selectedAgentID) return;
  if (busy) {
    agentPicker.refresh(selectedAgentID);
    return;
  }
  const dirty = openDirtyDialog();
  if (dirty) {
    const ok = await askConfirm({
      title: "切换节点？",
      body: "当前对话框里有未保存的修改，切换节点会丢弃这些内容。",
      confirm: "丢弃并切换",
      cancel: "继续编辑",
      danger: true,
    });
    if (!ok) {
      agentPicker.refresh(selectedAgentID);
      return;
    }
    releaseDraft(dirty);
  }
  selectedAgentID = next;
  const url = new URL(window.location.href);
  if (selectedAgentID) url.searchParams.set("agent_id", selectedAgentID);
  else url.searchParams.delete("agent_id");
  window.history.replaceState({}, "", url);
  closeCreate();
  closeDetail();
  closeAppend();
  closeUpstreamModal();
  closeRouteModal();
  fillShareHost(null, []);
  syncShareHostBar(Boolean(selectedAgentID));
  try {
    await renderWorkspace();
  } catch (error) {
    showStatus(errorText(error), true);
  }
};

const openCreateFromButton = () => {
  if (!canMutate()) return;
  openCreate();
};
if (createToggle) createToggle.addEventListener("click", openCreateFromButton);
if (emptyCreate) emptyCreate.addEventListener("click", openCreateFromButton);

if (createCancel) createCancel.addEventListener("click", requestCloseCreate);
if (createDialog) {
  createDialog.addEventListener("click", (event) => {
    if (event.target === createDialog) closeCreate();
  });
  createDialog.addEventListener("close", () => {
    const trigger = createDialog._returnFocus;
    if (!trigger || typeof trigger.focus !== "function") return;
    let attempts = 0;
    const restore = () => {
      if (trigger.disabled && attempts < 20) {
        attempts += 1;
        window.setTimeout(restore, 50);
        return;
      }
      trigger.focus();
    };
    window.setTimeout(restore, 0);
  });
}
if (detailClose) detailClose.addEventListener("click", closeDetail);
if (detailPanel) {
  detailPanel.addEventListener("click", (event) => {
    if (event.target === detailPanel) closeDetail();
  });
  detailPanel.addEventListener("close", () => {
    if (!openListenID) return;
    openListenID = "";
    resetDetailPrompt();
    markSelectedCards();
  });
}
if (methodInput()) methodInput().addEventListener("change", syncServerPskField);
if (qrCopy) {
  qrCopy.addEventListener("click", async () => {
    try {
      await copyText(pendingQRURI);
      markCopied(qrCopy);
    } catch (error) {
      showStatus(errorText(error), true);
    }
  });
}
if (listenRetry) listenRetry.addEventListener("click", async () => {
  if (!selectedAgentID) return;
  try {
    await renderWorkspace();
  } catch (error) {
    showStatus(errorText(error), true);
  }
});
if (routingRetry) routingRetry.addEventListener("click", () => loadRouting());

const saveShareHost = async (host, message, control = null) => {
  if (busy || !canMutate()) return;
  setBusy(true, control);
  try {
    await sendPluginJSON("api/share-host", mutateBody({ host }));
    await renderWorkspace();
    showStatus(message, false);
  } catch (error) {
    showStatus(errorText(error), true);
  } finally {
    setBusy(false);
  }
};

if (shareHostSave) {
  shareHostSave.addEventListener("click", (event) => {
    const host = shareHostInput ? String(shareHostInput.value || "").trim() : "";
    saveShareHost(host, host ? "已更新连接地址，新链接已生效。" : "已恢复为节点自动地址。", event.currentTarget);
  });
}
if (shareHostInput) {
  shareHostInput.addEventListener("input", syncSelectionActions);
  shareHostInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.isComposing) {
      event.preventDefault();
      if (shareHostSave && !shareHostSave.disabled) shareHostSave.click();
    } else if (event.key === "Escape" && shareHostDirty()) {
      event.preventDefault();
      shareHostInput.value = String(shareHostInput.dataset.saved || "");
      syncSelectionActions();
    }
  });
}
if (shareHostAuto) {
  shareHostAuto.addEventListener("click", (event) => {
    saveShareHost("", "已恢复为节点自动地址。", event.currentTarget);
  });
}

if (appendCancel) appendCancel.addEventListener("click", requestCloseAppend);
if (appendDialog) {
  appendDialog.addEventListener("click", (event) => {
    if (event.target === appendDialog) closeAppend();
  });
}
if (appendForm) {
  appendForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) return;
    const listen = pendingAppendListen;
    if (!listen || !canMutate()) return;
    clearFormErrors(appendForm);
    showModalError(appendError, "");
    const name = String(new FormData(appendForm).get("name") || "").trim();
    setBusy(true, appendSubmit, "正在追加用户…");
    try {
      await sendPluginJSON(`api/listens/${encodeURIComponent(listen.id)}/users`, mutateBody({ name }));
      const listenID = listen.id;
      closeAppend();
      await renderWorkspace();
      const updated = listensCache.find((item) => item && item.id === listenID);
      if (updated) openDetail(updated);
      showFeedback("已追加用户，新的 ss:// 链接已生成。", false);
    } catch (error) {
      showModalError(appendError, errorText(error, "追加用户失败，请稍后重试。"));
    } finally {
      setBusy(false);
    }
  });
}

if (createForm) {
  createForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy || !canMutate()) return;
    clearFormErrors(createForm);
    showModalError(createError, "");
    const data = new FormData(createForm);
    const portValue = String(data.get("port") || "").trim();
    const port = Number(portValue);
    if (portValue && (!Number.isInteger(port) || port < 1 || port > 65535)) {
      const portInput = formField(createForm, "port");
      markFieldError(portInput, "端口需为 1-65535 的整数。");
      if (portInput) portInput.focus();
      return;
    }
    const body = mutateBody({
      name: String(data.get("name") || "").trim(),
      method: String(data.get("method") || "").trim(),
      password: String(data.get("password") || "").trim(),
      server_psk: String(data.get("server_psk") || "").trim(),
    });
    if (portValue) body.port = port;
    setBusy(true, createSubmit, "正在保存…");
    try {
      await sendPluginJSON("api/listens", body);
      closeCreate();
      showStatus("已保存监听，可在卡片上复制 ss:// 或查看二维码。", false);
      await renderWorkspace();
    } catch (error) {
      showModalError(createError, errorText(error, "新增监听失败，请检查端口和密钥后重试。"));
      if (/端口/.test(String((error && error.message) || ""))) {
        const portInput = formField(createForm, "port");
        markFieldError(portInput, "该节点已使用此端口或端口不可用，请换一个端口后重试。");
        if (portInput) portInput.focus();
      } else if (/密钥|加密/.test(String((error && error.message) || ""))) {
        markFieldError(formField(createForm, "password"), "密钥格式无效，请留空自动生成或检查后重试。");
      }
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
    if (unavailableNode) unavailableNode.hidden = false;
    if (unavailableDescNode) {
      unavailableDescNode.textContent = `${errorText(error, "暂时无法管理 Shadowsocks 服务。")}请刷新页面，或确认宿主与 shadowsocks-server 插件状态。`;
    }
  } finally {
    if (loadingNode) loadingNode.hidden = true;
  }
};

boot();
