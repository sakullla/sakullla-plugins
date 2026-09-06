const $ = (selector) => document.querySelector(selector);
const state = { config: null, node: "", payload: null, entries: [], entryRules: [] };

const authHeaders = () => {
  const headers = { "Content-Type": "application/json" };
  try {
    const session = localStorage.getItem("panel_session");
    const token = localStorage.getItem("panel_token");
    if (session) headers.Authorization = `Bearer ${session}`;
    else if (token) headers["X-Panel-Token"] = token;
  } catch (_) {}
  return headers;
};

const api = async (path, options = {}) => {
  const response = await fetch(path, { credentials: "same-origin", ...options, headers: { ...authHeaders(), ...(options.headers || {}) } });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || "管理请求失败");
  return payload;
};

const text = (value) => String(value ?? "").replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[character]));
const status = (message, failed = false) => { $("#status").textContent = message; $("#status").dataset.failed = failed ? "true" : "false"; };
const modeLabel = (mode) => mode === "enforce" ? "拦截" : mode === "observe" ? "观察" : "未设置";
const reasonLabel = (reason) => ({ 1: "来源未认证", 2: "数据不可用", 3: "分类缺失", 4: "预算超限", 8: "数据无效", 9: "地址族覆盖未知", 10: "已撤销" }[reason] || reason || "规则命中");

const render = (payload) => {
  state.payload = payload;
  state.config = payload.config;
  $("#workspace").hidden = false;
  const policy = payload.policy || {};
  const desired = policy.desired || {};
  const settings = desired.settings || {};
  $("#desired-mode").textContent = modeLabel(settings.default_mode);
  $("#default-action").value = state.config.default_action || "allow";
  const entry = payload.entry || {};
  const node = entry.node || {};
  $("#applied-mode").textContent = modeLabel(node.applied?.settings?.entry_mode || node.applied?.settings?.default_mode);
  $("#generation").textContent = node.generation || "尚未应用";
  $("#phase").textContent = node.phase || (payload.issues?.length ? "有检查故障" : "就绪");
  renderRules();
	const selectedToken = $("#entry-select").value;
	state.entries = Array.isArray(payload.entries) ? payload.entries : [];
	$("#entry-select").innerHTML = `<option value="">请选择入口</option>` + state.entries.map((snapshot) => `<option value="${text(snapshot.entry.token)}">${text(snapshot.entry.node_id)} · ${text(snapshot.entry.kind)} · ${text(snapshot.entry.id)}</option>`).join("");
	if (state.entries.some((snapshot) => snapshot.entry.token === selectedToken)) $("#entry-select").value = selectedToken;
  state.entryRules = Array.isArray(payload.entry_overlay?.rules) ? payload.entry_overlay.rules.map((rule) => structuredClone(rule)) : [];
  renderEntryRules();
	renderEntryClassifications(payload.provinces || []);
  renderProvinces(payload.provinces || []);
  renderDatasets(payload.datasets || [], payload.bindings || []);
  renderEvents(payload.events || []);
  status(payload.issues?.join("；") || "状态已更新");
};

const selectedEntry = () => state.entries.find((snapshot) => snapshot.entry.token === $("#entry-select").value)?.entry;

const renderEntryRules = () => {
  const root = $("#entry-rules");
  root.innerHTML = state.entryRules.length ? state.entryRules.map((rule, index) => `<li><div><strong>${text(rule.id)}</strong><small>${text(rule.action)} · ${text(rule.selector.type)} · ${text(rule.selector.value || `${rule.selector.dataset_id}/${rule.selector.classification_id}`)}</small></div><button data-entry-remove="${index}">删除</button></li>`).join("") : `<li class="empty">当前入口没有专属规则。</li>`;
  document.querySelectorAll("[data-entry-remove]").forEach((button) => button.onclick = async () => {
    state.entryRules.splice(Number(button.dataset.entryRemove), 1);
    try { await persistEntryRules(); } catch (error) { status(error.message, true); }
  });
};

const renderEntryClassifications = (provinces) => {
	const provinceNames = new Map(provinces.map((province) => [province.classification, province.name]));
	const options = (state.config?.datasets || []).flatMap((dataset) => (dataset.classifications || []).map((classification) => ({
		value: `${dataset.id}/${classification.id}`,
		label: `${provinceNames.get(classification.name) || classification.name} · ${dataset.id}/${classification.id} · ${classification.kind}`,
	})));
	$("#entry-classification").innerHTML = `<option value="">请选择已配置分类</option>` + options.map((option) => `<option value="${text(option.value)}">${text(option.label)}</option>`).join("");
};

const persistEntryRules = async () => {
	const entry = selectedEntry();
	if (!entry) throw new Error("请先选择 Host 已授权入口");
  await api("api/entry-rules", { method: "POST", body: JSON.stringify({ entry, rules: state.entryRules }) });
  await load();
};

const renderRules = () => {
  const rules = state.config?.rules || [];
  $("#rule-count").textContent = `${rules.length} 条`;
  $("#rules").innerHTML = rules.map((rule, index) => `<li><div><strong>${text(rule.id)}</strong><small>${text(rule.action)} · ${text(rule.selector.type)} · ${text(rule.selector.value || `${rule.selector.dataset_id}/${rule.selector.classification_id}`)}</small></div><button data-remove="${index}">删除</button></li>`).join("");
  document.querySelectorAll("[data-remove]").forEach((button) => button.onclick = () => { state.config.rules.splice(Number(button.dataset.remove), 1); renderRules(); });
};

const renderProvinces = (items) => {
  const selected = new Set((state.config?.province_whitelist || []).map((ref) => `${ref.dataset_id}/${ref.classification_id}`));
  const provinceDataset = (state.config?.datasets || []).find((dataset) => dataset.classifications.some((item) => item.kind === "region" && item.name.startsWith("cn-")));
  $("#provinces").innerHTML = items.map((province) => {
    const classification = provinceDataset?.classifications.find((item) => item.name === province.classification);
    const key = classification ? `${provinceDataset.id}/${classification.id}` : "";
    return `<label title="${text(province.classification)}"><input type="checkbox" data-province="${text(key)}" ${key && selected.has(key) ? "checked" : ""} ${key ? "" : "disabled"}>${text(province.name)}<small>${text(province.classification)}</small></label>`;
  }).join("");
};

const renderDatasets = (views, bindings) => {
  $("#datasets").innerHTML = views.length ? views.map((view) => {
    const binding = bindings.find((item) => item.source_id === view.definition.source_id) || {};
    const target = view.status || {};
    const version = view.versions[0] || {};
    return `<article class="dataset-card"><header><strong>${text(view.definition.id)}</strong><span class="badge">${text(target.phase || "未选择节点")}</span></header><p>${text(view.definition.source_id)} · ${text(version.revision || "Host 托管来源")}</p><dl><dt>期望</dt><dd>${text(target.desired || binding.desired?.spec?.version_digest || "—")}</dd><dt>已应用</dt><dd>${text(target.applied || "—")}</dd><dt>最近有效</dt><dd>${text(target.last_good || "—")}</dd><dt>许可</dt><dd>${text(version.license_url || "请在来源详情核验")}</dd><dt>归属</dt><dd>${text(version.attribution_text || version.attribution_url || "—")}</dd><dt>IPv4/IPv6</dt><dd>${text(`${version.coverage?.ipv4 || "—"} / ${version.coverage?.ipv6 || "—"}`)}</dd></dl><p class="error">${text(view.error || target.failure || "")}</p></article>`;
  }).join("") : `<p class="empty">尚未配置数据源。先在 Host 数据源管理中添加 V2Fly、Loyalsoldier 或 DB-IP 来源，再绑定不可变版本。</p>`;
};

const renderEvents = (events) => {
  $("#events").innerHTML = events.length ? events.map((event) => {
    const context = event.context || {};
    return `<li><div><strong>${text(event.code || "ip.policy")}</strong><small>${text(context.rule_id || event.rule_id || "未命名规则")} · ${text(context.mode || event.disposition || event.action)} · ${text(reasonLabel(context.reason || event.reason))}</small></div></li>`;
  }).join("") : `<li class="empty">暂无诊断事件。</li>`;
};

const load = async () => {
  state.node = $("#node-id").value.trim();
  const params = new URLSearchParams();
  if (state.node) params.set("node_id", state.node);
	const token = $("#entry-select").value;
	if (token) params.set("entry_token", token);
  status("正在读取实际状态…");
  try { render(await api(`api/state?${params}`)); } catch (error) { status(error.message, true); $("#workspace").hidden = false; }
};

const save = async (mode) => {
  state.config.default_action = $("#default-action").value;
  state.config.province_whitelist = [...document.querySelectorAll("[data-province]:checked")].map((item) => {
    const [dataset_id, classification_id] = item.dataset.province.split("/"); return { dataset_id, classification_id };
  });
  const current = state.payload?.policy?.desired?.settings?.default_mode || "observe";
  await api("api/config", { method: "POST", body: JSON.stringify({ mode: mode || current, config: state.config }) });
  await load();
};

$("#load").onclick = load;
$("#save").onclick = () => save().catch((error) => status(error.message, true));
document.querySelectorAll("[data-mode]").forEach((button) => button.onclick = () => save(button.dataset.mode).catch((error) => status(error.message, true)));
$("#rule-form").onsubmit = (event) => {
  event.preventDefault(); const data = new FormData(event.currentTarget);
  const type = String(data.get("type") || "");
  const selector = type === "classification" ? { type, dataset_id: String(data.get("dataset_id") || ""), classification_id: String(data.get("classification_id") || "") } : { type, value: String(data.get("value") || "") };
  state.config.rules.push({ id: String(data.get("id") || ""), action: String(data.get("action") || ""), selector });
  event.currentTarget.reset(); renderRules();
};

const entryMode = async (mode, reset = false) => {
  const entry = selectedEntry();
	if (!entry) throw new Error("请先选择 Host 已授权入口");
  await api("api/entry-mode", { method: "POST", body: JSON.stringify({ entry, mode, reset }) }); await load();
};
$("#entry-observe").onclick = () => entryMode("observe").catch((error) => status(error.message, true));
$("#entry-enforce").onclick = () => entryMode("enforce").catch((error) => status(error.message, true));
$("#entry-reset").onclick = () => entryMode("", true).catch((error) => status(error.message, true));
$("#entry-select").onchange = () => load();
$("#entry-rule-form").onsubmit = async (event) => {
  event.preventDefault(); const data = new FormData(event.currentTarget);
  if (state.entryRules.length >= 64) { status("每个入口最多 64 条规则", true); return; }
  const type = String(data.get("type") || "");
	const [dataset_id = "", classification_id = ""] = String(data.get("classification") || "").split("/");
  const selector = type === "classification" ? { type, dataset_id, classification_id } : { type, value: String(data.get("value") || "") };
  state.entryRules.push({ id: String(data.get("id") || ""), action: String(data.get("action") || ""), selector });
  try { await persistEntryRules(); event.currentTarget.reset(); } catch (error) { state.entryRules.pop(); status(error.message, true); }
};

$("#dataset-form").onsubmit = (event) => {
  event.preventDefault(); const data = new FormData(event.currentTarget);
  const datasetID = String(data.get("dataset_id") || ""), sourceID = String(data.get("source_id") || "");
  let dataset = state.config.datasets.find((item) => item.id === datasetID);
  if (!dataset) { dataset = { id: datasetID, source_id: sourceID, classifications: [] }; state.config.datasets.push(dataset); }
  dataset.classifications.push({ id: String(data.get("classification_id") || ""), name: String(data.get("classification_name") || ""), kind: String(data.get("classification_kind") || "") });
  event.currentTarget.reset(); renderProvinces(state.payload.provinces || []); renderDatasets(state.payload.datasets || [], state.payload.bindings || []); status("字典已加入草稿，请保存或绑定版本");
};

$("#binding-form").onsubmit = async (event) => {
  event.preventDefault(); const data = new FormData(event.currentTarget);
  const datasetID = String(data.get("dataset_id") || "");
  const dataset = state.config.datasets.find((item) => item.id === datasetID);
  if (!dataset) { status("字典 ID 不存在", true); return; }
  try {
    await api("api/binding", { method: "POST", body: JSON.stringify({ binding: { source_id: dataset.source_id, version_digest: String(data.get("version_digest") || ""), dataset_id: datasetID, node_ids: state.node ? [state.node] : [], mode: String(data.get("mode") || "observe"), config: state.config } }) });
    await load();
  } catch (error) { status(error.message, true); }
};

$("#source-form").onsubmit = async (event) => {
  event.preventDefault(); const data = new FormData(event.currentTarget);
  try {
    const action = String(data.get("action") || ""), sourceID = String(data.get("source_id") || "");
    const dataset = { action, source_id: sourceID, version_digest: String(data.get("version_digest") || "") };
    if (action === "put-source") dataset.source = { id: sourceID, name: String(data.get("name") || ""), url: String(data.get("url") || ""), format: String(data.get("format") || ""), license_url: String(data.get("license_url") || ""), refresh_interval_seconds: 86400 };
    await api("api/dataset", { method: "POST", body: JSON.stringify({ dataset }) });
    await load();
  } catch (error) { status(error.message, true); }
};

const requested = new URLSearchParams(location.search).get("node_id") || "";
$("#node-id").value = requested;
load();
