const $ = (selector) => document.querySelector(selector);
const state = {
  config: null,
  payload: null,
  node: "",
  token: "",
  agents: [],
  plugin: null,
  entries: [],
  labels: new Map(),
  dirty: false,
  busy: false,
  seq: 0,
  tab: "global",
  sources: [],
  versions: [],
  classes: [],
  classKeys: new Set(),
  catalogSeq: 0,
  cursor: "",
  page: 1,
  eventSeq: 0,
};
const authHeaders = () => {
  const headers = { "Content-Type": "application/json" };
  try {
    const session = localStorage.getItem("panel_session"),
      token = localStorage.getItem("panel_token");
    if (session) headers.Authorization = "Bearer " + session;
    else if (token) headers["X-Panel-Token"] = token;
  } catch {}
  return headers;
};
const api = async (path, options = {}) => {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: { ...authHeaders(), ...(options.headers || {}) },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok)
    throw Object.assign(
      new Error(
        response.status === 403
          ? "没有访问权限"
          : payload.error || payload.message || "请求失败，请重试",
      ),
      { status: response.status },
    );
  return payload;
};
const post = (path, body) =>
  api(path, { method: "POST", body: JSON.stringify(body) });
const esc = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const option = (value, label) =>
  '<option value="' + esc(value) + '">' + esc(label) + "</option>";
const status = (message, failed = false) => {
  $("#status").textContent = message;
  $("#status").dataset.failed = String(failed);
};
const modeLabel = (mode) =>
  ({ observe: "观察", enforce: "拦截", deny: "拦截" })[mode] || "未设置";
const phaseLabel = (phase) =>
  ({
    active: "已应用",
    applied: "已应用",
    ready: "已就绪",
    pending: "等待下发",
    preparing: "正在准备",
    applying: "正在应用",
    failed: "应用失败",
    offline: "节点离线",
    unavailable: "尚未应用",
    degraded: "状态异常",
  })[phase] || "等待状态";
const newID = (prefix) =>
  prefix + "-" + crypto.randomUUID().replaceAll("-", "").slice(0, 12);
const currentMode = () =>
  state.payload?.policy?.desired?.settings?.default_mode || "observe";
const agent = (id) => state.agents.find((a) => a.id === id);
const online = (a) => a?.status === "online" || a?.online === true;
const agentName = (a) =>
  a?.name && a.name !== a.id
    ? a.name
    : a?.is_local || a?.id === "local"
      ? "控制面板本机"
      : a?.ddns_domain || a?.last_seen_ip || "未命名节点";
const entryKey = (entry) => [entry.node_id, entry.kind, entry.id].join("/");
const entryName = (entry) =>
  state.labels.get(entryKey(entry)) ||
  ({
    "http-rule": "HTTP 入口",
    "tcp-rule": "TCP 监听",
    "udp-rule": "UDP 监听",
    "plugin-tcp": "插件 TCP 入口",
    "plugin-udp": "插件 UDP 入口",
  }[entry.kind] || "入口") + "（名称暂不可用）";
const selectedEntry = () =>
  state.entries.find((item) => item.entry.token === state.token)?.entry;
const sourceName = (id) =>
  state.sources.find((s) => s.source.id === id)?.source.name ||
  state.payload?.datasets?.find((v) => v.definition.source_id === id)?.name ||
  "地理数据";
const provinceName = (name) =>
  state.payload?.provinces?.find((p) => p.classification === name)?.name;
const countryNames = new Intl.DisplayNames(["zh-CN"], { type: "region" });
const classificationName = (c) =>
  provinceName(c.name) ||
  (c.kind === "country" && /^[a-z]{2}$/i.test(c.name)
    ? countryNames.of(c.name.toUpperCase())
    : null) ||
  c.display_name ||
  c.name;
const classificationLabel = (ref) => {
  const dataset = state.config?.datasets.find((d) => d.id === ref.dataset_id);
  const item = dataset?.classifications.find(
    (c) => c.id === ref.classification_id,
  );
  return item
    ? classificationName(item) + " · " + sourceName(dataset.source_id)
    : "分类已不可用";
};
const ruleLabel = (rule) =>
  rule.selector.type === "classification"
    ? classificationLabel(rule.selector)
    : rule.selector.value;
const markDirty = () => {
  state.dirty = true;
  $("#draft-status").textContent = "有未保存的全局修改";
};
const confirmAction = (title, message) =>
  new Promise((resolve) => {
    $("#confirm-title").textContent = title;
    $("#confirm-message").textContent = message;
    const dialog = $("#confirm-dialog");
    dialog.showModal();
    const done = () => resolve(dialog.returnValue === "ok");
    dialog.addEventListener("close", done, { once: true });
  });
$("#confirm-ok").onclick = () => $("#confirm-dialog").close("ok");
$("#confirm-cancel").onclick = () => $("#confirm-dialog").close("cancel");
const mutate = async (action) => {
  if (state.busy) return;
  if (state.payload?.access?.can_write === false) {
    status("没有修改策略的权限", true);
    return;
  }
  state.busy = true;
  const controls = [
    ...document.querySelectorAll(
      "#workspace input,#workspace select,#workspace button,#node-picker button,#load,#source-form input,#source-form select,#source-form button",
    ),
  ].map((node) => [node, node.disabled]);
  controls.forEach(([node]) => (node.disabled = true));
  try {
    await action();
  } catch (error) {
    status(error.message, true);
  } finally {
    controls.forEach(([node, disabled]) => (node.disabled = disabled));
    state.busy = false;
    updateWriteAccess();
  }
};
const updateWriteAccess = () => {
  const blocked =
    state.busy ||
    !state.payload?.ready ||
    state.payload?.access?.can_write === false;
  for (const id of ["save", "bind", "add-source"])
    $("#" + id).disabled =
      blocked ||
      (id === "bind" &&
        (!state.node || !state.classKeys.size || !$("#version-select").value));
  document
    .querySelectorAll("[data-mode]")
    .forEach((b) => (b.disabled = blocked));
  $("#entry-controls").disabled =
    blocked || !selectedEntry() || !online(agent(state.node));
};
const switchTab = (tab) => {
  state.tab = tab;
  document
    .querySelectorAll("[data-tab]")
    .forEach((b) =>
      b.setAttribute("aria-selected", String(b.dataset.tab === tab)),
    );
  for (const name of ["global", "entry", "data", "events"])
    $("#tab-" + name).hidden = name !== tab;
  if (tab === "data")
    loadSources().catch((e) => {
      $("#catalog-status").textContent =
        e.status === 403 ? "需要数据源管理权限才能选择或添加来源。" : e.message;
    });
  if (tab === "events") loadEvents();
};
document
  .querySelectorAll("[data-tab]")
  .forEach((b) => (b.onclick = () => switchTab(b.dataset.tab)));
$("#setup-provinces").onclick = () => switchTab("data");
const closePicker = () => {
  $("#node-menu").hidden = true;
  $("#node-trigger").setAttribute("aria-expanded", "false");
  $("#node-search").value = "";
  nodeFilter = "";
  document
    .querySelectorAll("[data-online]")
    .forEach((b) =>
      b.setAttribute("aria-pressed", String(b.dataset.online === "")),
    );
};
let nodeFilter = "";
const renderPicker = () => {
  $("#node-label").textContent = state.node
    ? agentName(agent(state.node))
    : "选择节点";
  $("#node-hint").innerHTML = state.agents.length
    ? "只显示当前 IP 策略的节点。"
    : '当前插件尚无可用节点。<a href="/plugins/ip-policy" target="_top">打开插件详情</a>';
  const query = $("#node-search").value.trim().toLowerCase();
  const rows = state.agents.filter(
    (a) =>
      (!nodeFilter || (online(a) ? "online" : "offline") === nodeFilter) &&
      [a.name, a.last_seen_ip, a.ddns_domain].some((v) =>
        String(v || "")
          .toLowerCase()
          .includes(query),
      ),
  );
  rows.sort(
    $("#node-sort").value === "name"
      ? (a, b) => agentName(a).localeCompare(agentName(b), "zh")
      : (a, b) =>
          (Date.parse(b.last_seen_at) || 0) - (Date.parse(a.last_seen_at) || 0),
  );
  $("#node-options").innerHTML = rows.length
    ? rows
        .map(
          (a) =>
            '<button type="button" role="option" aria-selected="' +
            (a.id === state.node) +
            '" data-node="' +
            esc(a.id) +
            '"><span class="dot ' +
            (online(a) ? "online" : "") +
            '"></span><span>' +
            esc(agentName(a)) +
            "</span><small>" +
            (online(a) ? "在线" : "离线") +
            "</small></button>",
        )
        .join("")
    : '<p class="hint">没有匹配的节点</p>';
  $("#node-options")
    .querySelectorAll("[data-node]")
    .forEach(
      (b) =>
        (b.onclick = () => {
          if (state.busy) return;
          state.node = b.dataset.node;
          state.token = "";
          state.page = 1;
          closePicker();
          renderPicker();
          const url = new URL(location.href);
          url.searchParams.set("agent_id", state.node);
          url.searchParams.delete("node_id");
          history.replaceState(null, "", url);
          load();
          if (state.tab === "events") loadEvents();
          updateWriteAccess();
        }),
    );
};
$("#node-trigger").onclick = () => {
  const open = $("#node-menu").hidden;
  $("#node-menu").hidden = !open;
  $("#node-trigger").setAttribute("aria-expanded", String(open));
  if (open) {
    renderPicker();
    $("#node-search").focus();
  }
};
$("#node-search").oninput = renderPicker;
$("#node-sort").onchange = renderPicker;
document.querySelectorAll("[data-online]").forEach(
  (b) =>
    (b.onclick = () => {
      nodeFilter = b.dataset.online;
      document
        .querySelectorAll("[data-online]")
        .forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
      renderPicker();
    }),
);
document.addEventListener("mousedown", (e) => {
  if (!$("#node-picker").contains(e.target)) closePicker();
});
$("#node-picker").onkeydown = (e) => {
  if (e.key === "Escape") {
    closePicker();
    $("#node-trigger").focus();
  }
  if (e.key === "ArrowDown" || e.key === "ArrowUp") {
    e.preventDefault();
    const rows = [...$("#node-options").querySelectorAll("button")];
    const i = rows.indexOf(document.activeElement);
    rows[
      (i + (e.key === "ArrowDown" ? 1 : -1) + rows.length) % rows.length
    ]?.focus();
  }
};
const loadEntryNames = async (node, seq, entries = []) => {
  if (!node) return;
  const paths = [
    ["http-rule", "rules"],
    ["l4", "l4-rules"],
  ];
  const results = await Promise.allSettled(
    paths.map(async ([kind, path]) => {
      const d = await api(
        "/panel-api/agents/" + encodeURIComponent(node) + "/" + path,
      );
      return (d.rules || []).map((r) => {
        const type =
          kind === "l4"
            ? String(r.protocol).toLowerCase() === "udp"
              ? "udp-rule"
              : "tcp-rule"
            : kind;
        const address =
          kind === "l4"
            ? (r.listen_host || r.listen_address || "0.0.0.0") +
              ":" +
              (r.listen_port || r.port || "—")
            : r.frontend_url;
        return [
          node + "/" + type + "/" + r.id,
          (kind === "l4"
            ? type.startsWith("tcp")
              ? "TCP · "
              : "UDP · "
            : "HTTP · ") +
            (r.name ? r.name + " · " : "") +
            (address || "地址暂不可用"),
        ];
      });
    }),
  );
  if (seq !== state.seq) return;
  for (const result of results)
    if (result.status === "fulfilled")
      for (const [key, label] of result.value) state.labels.set(key, label);
  const managed = entries.filter(
    (x) => x.entry.node_id === node && x.entry.kind.startsWith("plugin-"),
  );
  if (managed.length) {
    try {
      const list = await api("/panel-api/plugins");
      const details = await Promise.allSettled(
        (list.plugins || [])
          .filter((p) => p.runtime_kind !== "wasm-policy")
          .map((p) =>
            api("/panel-api/plugins/" + encodeURIComponent(p.plugin_id)),
          ),
      );
      if (seq !== state.seq) return;
      for (const result of details) {
        if (result.status !== "fulfilled") continue;
        const d = result.value;
        for (const snapshot of managed) {
          const entry = snapshot.entry,
            instance = d.instances?.find((i) => i.id === entry.id);
          if (!instance) continue;
          const title = d.package?.manifest?.name || "插件监听";
          state.labels.set(
            entryKey(entry),
            title +
              " · " +
              (entry.kind === "plugin-udp" ? "UDP" : "TCP") +
              " · " +
              agentName(agent(node)),
          );
        }
      }
    } catch {
      /* Keep an explicit unavailable label when metadata is not authorized. */
    }
  }
};
const renderSummary = () => {
  const node = state.payload?.entry?.node,
    settings = state.payload?.entry?.desired?.settings;
  $("#desired-mode").textContent = modeLabel(currentMode());
  $("#applied-mode").textContent = state.token
    ? modeLabel(
        node?.applied?.settings?.entry_mode ||
          node?.applied?.settings?.default_mode,
      )
    : "请先选择入口";
  $("#phase").textContent = !state.node
    ? "未选择节点"
    : !online(agent(state.node))
      ? "节点离线"
      : !state.token
        ? "请选择入口查看"
        : phaseLabel(node?.phase);
  $("#generation").textContent =
    state.token && node?.applied?.version?.revision
      ? "版本 " + node.applied.version.revision
      : "尚未应用";
  document
    .querySelectorAll("[data-mode]")
    .forEach((b) =>
      b.setAttribute("aria-pressed", String(b.dataset.mode === currentMode())),
    );
  const mode = settings?.entry_mode;
  $("#entry-mode-hint").textContent = mode
    ? "此入口单独使用" + modeLabel(mode) + "模式。"
    : "继承全局" + modeLabel(currentMode()) + "模式。";
  for (const [id, value] of [
    ["entry-reset", undefined],
    ["entry-observe", "observe"],
    ["entry-enforce", "enforce"],
  ])
    $("#" + id).setAttribute("aria-pressed", String(mode === value));
};
const renderEntries = () => {
  const entries = state.node
    ? state.entries.filter((x) => x.entry.node_id === state.node)
    : [];
  if (!entries.some((x) => x.entry.token === state.token)) state.token = "";
  $("#entry-select").innerHTML =
    option("", state.node ? "请选择域名或监听端口" : "请先选择节点") +
    entries.map((x) => option(x.entry.token, entryName(x.entry))).join("");
  $("#entry-select").value = state.token;
  $("#entry-hint").textContent = !state.node
    ? "先选择当前插件的节点，再设置该节点的入口。"
    : !entries.length
      ? "该节点没有可管理的入口。"
      : state.token
        ? "以下设置仅作用于 " + entryName(selectedEntry()) + "。"
        : "仅列出所选节点上本插件可管理的入口。";
  const rules = state.payload?.entry_overlay?.rules || [];
  renderRuleList($("#entry-rules"), rules, true);
  updateWriteAccess();
};
const renderRuleList = (root, rules, entry = false) => {
  root.innerHTML = rules.length
    ? rules
        .map(
          (r, i) =>
            "<li><div><strong>" +
            esc(ruleLabel(r)) +
            "</strong><small>" +
            (r.action === "deny" ? "拒绝访问" : "允许访问") +
            " · " +
            (r.selector.type === "ip"
              ? "单个 IP"
              : r.selector.type === "cidr"
                ? "IP 网段"
                : "地理分类") +
            '</small></div><button class="text-button" data-remove="' +
            i +
            '">删除</button></li>',
        )
        .join("")
    : '<li class="empty">' +
      (entry
        ? "没有入口专属规则，将继续使用全局规则。"
        : "尚未添加全局规则。") +
      "</li>";
  root.querySelectorAll("[data-remove]").forEach(
    (b) =>
      (b.onclick = () => {
        if (entry) {
          mutate(async () => {
            const next = structuredClone(rules);
            next.splice(Number(b.dataset.remove), 1);
            await post("api/entry-rules", {
              entry: selectedEntry(),
              rules: next,
            });
            await load();
          });
        } else {
          if (state.busy) return;
          state.config.rules.splice(Number(b.dataset.remove), 1);
          markDirty();
          renderRules();
        }
      }),
  );
};
const renderRules = () => {
  $("#rule-count").textContent = state.config.rules.length + " 条";
  renderRuleList($("#rules"), state.config.rules);
  const values = state.config.datasets
    .flatMap((d) =>
      d.classifications.map((c) =>
        option(
          d.id + "/" + c.id,
          classificationName(c) + " · " + sourceName(d.source_id),
        ),
      ),
    )
    .join("");
  for (const id of ["rule-classification", "entry-classification"]) {
    const old = $("#" + id).value;
    $("#" + id).innerHTML =
      option("", values ? "请选择已配置分类" : "尚未配置地理数据") + values;
    $("#" + id).value = old;
  }
  for (const form of [$("#rule-form"), $("#entry-rule-form")])
    updateRuleForm(form);
};
const updateRuleForm = (form) => {
  const type = form.elements.type.value,
    geo = type === "classification";
  form.querySelector("[data-value-field]").hidden = geo;
  form.querySelector("[data-class-field]").hidden = !geo;
  form.elements.value.required = !geo;
  form.elements.value.disabled = geo;
  form.elements.classification.required = geo;
  form.elements.classification.disabled = !geo;
  form.elements.value.placeholder =
    type === "cidr" ? "例如 192.0.2.0/24" : "例如 192.0.2.1";
  form.nextElementSibling.hidden =
    !geo || state.config?.datasets.some((d) => d.classifications.length);
};
const readRule = (form) => {
  const type = form.elements.type.value;
  let selector;
  if (type === "classification") {
    const [dataset_id, classification_id] =
      form.elements.classification.value.split("/");
    if (!dataset_id || !classification_id) throw new Error("请选择地理分类");
    selector = { type, dataset_id, classification_id };
  } else selector = { type, value: form.elements.value.value.trim() };
  return { id: newID("rule"), action: form.elements.action.value, selector };
};
for (const [id, isEntry] of [
  ["rule-form", false],
  ["entry-rule-form", true],
]) {
  const form = $("#" + id);
  form.elements.type.onchange = () => updateRuleForm(form);
  form.onsubmit = (e) => {
    e.preventDefault();
    if (!state.config || state.busy) return;
    mutate(async () => {
      const rule = readRule(form);
      if (isEntry) {
        if (!selectedEntry()) throw new Error("请先选择入口");
        const rules = [...(state.payload.entry_overlay?.rules || []), rule];
        if (rules.length > 64) throw new Error("每个入口最多 64 条规则");
        await post("api/entry-rules", { entry: selectedEntry(), rules });
        await load();
      } else {
        if (state.config.rules.length >= 256)
          throw new Error("最多 256 条全局规则");
        state.config.rules.push(rule);
        markDirty();
        renderRules();
      }
      form.reset();
      updateRuleForm(form);
    });
  };
}
const regionDatasets = () =>
  state.config.datasets.filter((d) =>
    d.classifications.some((c) => c.kind === "region" && provinceName(c.name)),
  );
const renderProvinces = () => {
  const datasets = regionDatasets();
  const old =
    $("#province-dataset").value ||
    state.config.province_whitelist[0]?.dataset_id;
  $("#province-empty").hidden = !!datasets.length;
  $("#province-settings").hidden = !datasets.length;
  $("#province-dataset").innerHTML = datasets
    .map((d) => option(d.id, sourceName(d.source_id)))
    .join("");
  if (datasets.some((d) => d.id === old)) $("#province-dataset").value = old;
  const dataset = datasets.find((d) => d.id === $("#province-dataset").value);
  const refs = new Set(
    state.config.province_whitelist.map(
      (r) => r.dataset_id + "/" + r.classification_id,
    ),
  );
  $("#provinces").innerHTML = (state.payload.provinces || [])
    .map((p) => {
      const c = dataset?.classifications.find(
          (c) => c.kind === "region" && c.name === p.classification,
        ),
        key = c ? dataset.id + "/" + c.id : "";
      return (
        '<label title="' +
        (key ? "" : "所选数据源未提供该省份") +
        '"><input type="checkbox" data-province="' +
        esc(key) +
        '" ' +
        (refs.has(key) ? "checked " : "") +
        (key ? "" : "disabled") +
        "><span>" +
        esc(p.name) +
        "</span></label>"
      );
    })
    .join("");
  $("#provinces")
    .querySelectorAll("input")
    .forEach(
      (input) =>
        (input.onchange = () => {
          const visible = new Set(
            [...$("#provinces").querySelectorAll("[data-province]")].map(
              (i) => i.dataset.province,
            ),
          );
          state.config.province_whitelist =
            state.config.province_whitelist.filter(
              (r) => !visible.has(r.dataset_id + "/" + r.classification_id),
            );
          for (const i of $("#provinces").querySelectorAll(":checked")) {
            const [dataset_id, classification_id] =
              i.dataset.province.split("/");
            state.config.province_whitelist.push({
              dataset_id,
              classification_id,
            });
          }
          markDirty();
          renderProvinceCount();
        }),
    );
  $("#province-coverage").textContent = dataset
    ? "按所选版本覆盖检查"
    : "尚未配置";
  $("#province-hint").textContent =
    "勾选后点击“保存全局配置”。未覆盖的 IPv4 / IPv6 地址无法确认省份，会被白名单拒绝；清空全部省份可停用白名单。";
  renderProvinceCount();
};
const renderProvinceCount = () => {
  const names = new Set(
    state.config.province_whitelist
      .map(
        (r) =>
          state.config.datasets
            .find((d) => d.id === r.dataset_id)
            ?.classifications.find((c) => c.id === r.classification_id)?.name,
      )
      .filter(Boolean),
  );
  const n = names.size;
  $("#province-count").textContent = n
    ? "已选择 " + n + " 个省份" + (state.dirty ? " · 尚未保存" : " · 已保存")
    : "未启用白名单 · 不限制省份";
};
$("#province-dataset").onchange = renderProvinces;
$("#province-all").onclick = () => {
  $("#provinces")
    .querySelectorAll("input:not(:disabled)")
    .forEach((i) => {
      i.checked = true;
    });
  $("#provinces input:not(:disabled)")?.dispatchEvent(new Event("change"));
};
$("#province-clear").onclick = () => {
  state.config.province_whitelist = [];
  markDirty();
  renderProvinces();
};
$("#default-action").onchange = () => {
  if (state.config) {
    state.config.default_action = $("#default-action").value;
    markDirty();
  }
};
const save = async (mode) => {
  if (!state.config) return;
  const nextMode = mode || currentMode();
  if (
    nextMode === "enforce" &&
    currentMode() !== "enforce" &&
    !(await confirmAction(
      "启用拦截模式",
      "命中拒绝规则或省份白名单之外的访问将被拒绝。此设置应用于所有使用本策略的入口。",
    ))
  )
    return;
  await post("api/config", { mode: nextMode, config: state.config });
  state.dirty = false;
  $("#draft-status").textContent = "配置已保存";
  await load();
  status("全局配置已保存");
};
$("#save").onclick = () => mutate(() => save());
document
  .querySelectorAll("[data-mode]")
  .forEach((b) => (b.onclick = () => mutate(() => save(b.dataset.mode))));
$("#entry-select").onchange = () => {
  if (state.busy) {
    $("#entry-select").value = state.token;
    return;
  }
  state.token = $("#entry-select").value;
  load();
};
for (const [id, mode, reset] of [
  ["entry-reset", "", true],
  ["entry-observe", "observe", false],
  ["entry-enforce", "enforce", false],
])
  $("#" + id).onclick = () =>
    mutate(async () => {
      const entry = selectedEntry();
      if (!entry) throw new Error("请先选择入口");
      if (
        reset &&
        (state.payload?.entry_overlay?.rules?.length || 0) > 0 &&
        !(await confirmAction(
          "恢复全局设置",
          "恢复继承会同时删除此入口的专属规则。是否继续？",
        ))
      )
        return;
      if (
        mode === "enforce" &&
        !(await confirmAction(
          "拦截此入口",
          "此入口将执行全局与专属规则中的拒绝结果。",
        ))
      )
        return;
      await post("api/entry-mode", { entry, mode, reset });
      await load();
    });
const load = async (initial) => {
  const seq = ++state.seq,
    node = state.node,
    token = state.token;
  const params = new URLSearchParams();
  if (node) params.set("node_id", node);
  if (token) params.set("entry_token", token);
  status("正在读取策略状态…");
  try {
    const payload = initial || (await api("api/state?" + params));
    await loadEntryNames(node, seq, payload.entries || []);
    if (seq !== state.seq) return;
    state.payload = payload;
    state.entries = Array.isArray(payload.entries) ? payload.entries : [];
    if (!state.dirty) state.config = structuredClone(payload.config);
    $("#workspace").hidden = false;
    $("#default-action").value = state.config.default_action;
    renderSummary();
    renderEntries();
    renderRules();
    renderProvinces();
    renderDatasets();
    status(
      payload.issues?.length
        ? payload.issues.join("；")
        : state.dirty
          ? "状态已更新，未保存的全局修改已保留。"
          : "状态已更新",
      !!payload.issues?.length,
    );
  } catch (error) {
    if (seq !== state.seq) return;
    $("#workspace").hidden = false;
    $("#phase").textContent = "状态读取失败";
    status(error.message, true);
  }
};
const loadAgents = async () => {
  const [all, plugin, payload] = await Promise.all([
    api("/panel-api/agents"),
    api("/panel-api/plugins/ip-policy"),
    api("api/state"),
  ]);
  state.plugin = plugin;
  const ids = new Set((plugin.instances || []).flatMap((i) => i.targets || []));
  for (const a of plugin.agent_statuses || [])
    if (a.target_scope === "active") ids.add(a.agent_id);
  // Automatic policy faces publish to Host-authorized entries rather than
  // management-process targets. Do not treat unrelated panel agents as targets.
  if (plugin.package?.runtime?.policy)
    for (const item of payload.entries || []) ids.add(item.entry.node_id);
  state.agents = (all.agents || []).filter((a) => ids.has(a.id));
  const requested =
    state.node ||
    new URLSearchParams(location.search).get("agent_id") ||
    new URLSearchParams(location.search).get("node_id");
  state.node = state.agents.some((a) => a.id === requested)
    ? requested
    : state.agents.length === 1
      ? state.agents[0].id
      : "";
  renderPicker();
  await load(state.node ? undefined : payload);
};
$("#load").onclick = () => {
  if (!state.busy) loadAgents().catch((e) => status(e.message, true));
};

const coverageLabel = (c) =>
  ({
    full: "完整",
    complete: "完整",
    partial: "部分",
    none: "无覆盖",
    unknown: "未知",
  })[c] || "未知";
const versionLabel = (v) =>
  v.revision ||
  (v.created_at
    ? new Date(v.created_at).toLocaleDateString("zh-CN")
    : "已校验版本");
const selectedSource = () =>
  state.sources.find((s) => s.source.id === $("#source-select").value);
const byteLabel = (bytes) =>
  Number.isFinite(bytes) && bytes >= 0
    ? (bytes / 1048576).toFixed(1) + " MiB"
    : "大小未提供";
const safeURL = (value) => {
  try {
    const u = new URL(value);
    return ["https:", "http:"].includes(u.protocol) ? u.href : "";
  } catch {
    return "";
  }
};
const loadSources = async (selected) => {
  const data = await api("/panel-api/datasets");
  state.sources = (data.sources || []).filter((s) =>
    ["geoip", "geo-mmdb", "cidr"].includes(s.source?.format),
  );
  const old = selected || $("#source-select").value;
  $("#source-select").innerHTML =
    option("", state.sources.length ? "选择数据源" : "尚未添加数据源") +
    state.sources.map((s) => option(s.source.id, s.source.name)).join("");
  if (state.sources.some((s) => s.source.id === old))
    $("#source-select").value = old;
  $("#catalog-status").textContent = state.sources.length
    ? "选择已有来源，或添加数据发布方提供的新来源。"
    : "尚无数据源。点击“添加数据源”，选择数据文件即可导入。";
  renderDatasets();
  renderRules();
  renderProvinces();
  if (selected || (!state.versions.length && $("#source-select").value))
    await loadVersions();
};
const renderVersionInfo = () => {
  const source = selectedSource(),
    version = state.versions.find(
      (v) => v.digest === $("#version-select").value,
    );
  if (!source) {
    $("#version-info").replaceChildren();
    return;
  }
  const license = safeURL(version?.license_url || source.source.license_url);
  $("#version-info").innerHTML =
    "<p>" +
    esc(source.source.name) +
    " · " +
    (version
      ? esc(versionLabel(version)) +
        " · 索引 " +
        byteLabel(version.index_bytes) +
        " · IPv4 " +
        coverageLabel(version.coverage?.ipv4) +
        " / IPv6 " +
        coverageLabel(version.coverage?.ipv6)
      : "尚无可用版本，先获取数据并完成校验。") +
    (license
      ? ' · <a href="' +
        esc(license) +
        '" target="_blank" rel="noopener noreferrer">查看许可</a>'
      : "") +
    '</p><div class="actions"><button type="button" id="refresh-source" class="secondary">获取最新版本</button><button type="button" id="reload-versions" class="text-button">刷新版本列表</button><button type="button" id="delete-version" class="text-button">删除未使用版本</button><button type="button" id="delete-source" class="text-button">删除未使用来源</button></div><p class="hint">手动获取版本，不在插件中另存副本。删除会检查使用和回退引用；仍被引用的数据不会删除。</p>' +
    (source.failure
      ? '<p class="error">上次获取未完成：' +
        esc(source.failure) +
        "。请检查下载地址和格式后重试。</p>"
      : "");
  $("#refresh-source").onclick = () =>
    mutate(async () => {
      await post("api/dataset", {
        dataset: { action: "refresh", source_id: source.source.id },
      });
      await loadSources(source.source.id);
      status("已请求获取最新版本。若尚未出现，请稍后刷新版本列表。");
    });
  $("#refresh-source").hidden = !source.source.url;
  $("#reload-versions").onclick = () =>
    loadVersions().catch((e) => status(e.message, true));
  $("#delete-version").disabled = !version;
  for (const [id, action] of [
    ["delete-version", "delete-version"],
    ["delete-source", "delete-source"],
  ])
    $("#" + id).onclick = () =>
      mutate(async () => {
        if (
          !(await confirmAction(
            action === "delete-version" ? "删除所选旧版本" : "删除共享数据源",
            action === "delete-version"
              ? "只删除不再使用且不用于回退的版本。系统会再次检查引用。"
              : "此来源属于共享目录。确认不再使用后删除；若其它插件或回退快照仍在引用，系统会拒绝删除。",
          ))
        )
          return;
        try {
          await post("/panel-api/datasets/control", {
            action,
            source_id: source.source.id,
            ...(action === "delete-version"
              ? { version_digest: version.digest }
              : {}),
          });
        } catch (e) {
          if (e.status === 409)
            throw new Error("该版本或来源仍被使用或用于回退，无法删除。");
          throw e;
        }
        $("#source-select").value =
          action === "delete-source" ? "" : source.source.id;
        state.versions = [];
        state.classes = [];
        state.classKeys.clear();
        await loadSources(
          action === "delete-source" ? undefined : source.source.id,
        );
        if (action === "delete-source") await loadVersions();
        status("已删除未使用数据。");
      });
};
const loadVersions = async () => {
  const seq = ++state.catalogSeq,
    source = $("#source-select").value;
  state.versions = [];
  state.classes = [];
  state.classKeys.clear();
  state.cursor = "";
  $("#version-select").innerHTML = option("", "正在读取版本…");
  $("#catalog-classes").replaceChildren();
  updateWriteAccess();
  if (!source) {
    $("#version-select").innerHTML = option("", "先选择数据源");
    renderVersionInfo();
    return;
  }
  try {
    const d = await api(
      "/panel-api/datasets/" +
        encodeURIComponent(source) +
        "/catalog?limit=100",
    );
    if (seq !== state.catalogSeq) return;
    state.versions = d.versions || [];
    $("#version-select").innerHTML =
      option("", "选择已校验版本") +
      state.versions
        .map((v) =>
          option(
            v.digest,
            versionLabel(v) +
              (v.digest === selectedSource()?.current_digest
                ? " · 当前版本"
                : ""),
          ),
        )
        .join("");
    if (state.versions.length)
      $("#version-select").value = state.versions.some(
        (v) => v.digest === selectedSource()?.current_digest,
      )
        ? selectedSource().current_digest
        : state.versions[0].digest;
    renderVersionInfo();
    await loadClasses();
  } catch (e) {
    if (seq !== state.catalogSeq) return;
    $("#version-select").innerHTML = option("", "版本读取失败");
    $("#catalog-status").textContent =
      e.status === 403 ? "没有查看数据版本的权限。" : e.message;
    renderVersionInfo();
  }
};
const loadClasses = async (append = false) => {
  const seq = ++state.catalogSeq,
    source = $("#source-select").value,
    version = $("#version-select").value;
  if (!append) {
    state.classes = [];
    state.classKeys.clear();
    state.cursor = "";
  }
  renderVersionInfo();
  if (!source || !version) {
    renderClasses();
    return;
  }
  const q = new URLSearchParams({ version_digest: version, limit: "100" });
  if (append && state.cursor) q.set("cursor", state.cursor);
  $("#bind").disabled = true;
  $("#more-classes").disabled = true;
  try {
    const d = await api(
      "/panel-api/datasets/" + encodeURIComponent(source) + "/catalog?" + q,
    );
    if (seq !== state.catalogSeq) return;
    const valid = (d.classifications || []).filter(
      (c) =>
        ["country", "region", "cidr"].includes(c.classification?.kind) &&
        !(c.classification.attributes || []).length,
    );
    const seen = new Set(
      state.classes.map(
        (c) => c.classification.kind + "/" + c.classification.name,
      ),
    );
    state.classes.push(
      ...valid.filter(
        (c) => !seen.has(c.classification.kind + "/" + c.classification.name),
      ),
    );
    state.cursor = d.next_cursor || "";
    const existing = state.config.datasets.find((x) => x.source_id === source);
    for (const c of state.classes)
      if (
        existing?.classifications.some(
          (x) =>
            x.kind === c.classification.kind &&
            x.name === c.classification.name,
        )
      )
        state.classKeys.add(
          c.classification.kind + "/" + c.classification.name,
        );
    renderClasses();
  } catch (e) {
    if (seq === state.catalogSeq) {
      $("#catalog-classes").textContent = e.message;
      status(e.message, true);
    }
  } finally {
    if (seq === state.catalogSeq) $("#more-classes").disabled = false;
  }
};
const renderClasses = () => {
  const q = $("#classification-search").value.trim().toLowerCase();
  const rows = state.classes.filter((c) =>
    [
      c.display_name,
      classificationName(c.classification),
      c.classification.name,
    ].some((v) =>
      String(v || "")
        .toLowerCase()
        .includes(q),
    ),
  );
  $("#catalog-classes").innerHTML = rows.length
    ? rows
        .map((c) => {
          const key = c.classification.kind + "/" + c.classification.name;
          return (
            '<label><input type="checkbox" value="' +
            esc(key) +
            '" ' +
            (state.classKeys.has(key) ? "checked" : "") +
            "><span>" +
            esc(
              classificationName({
                ...c.classification,
                display_name: c.display_name,
              }),
            ) +
            "<small>IPv4 " +
            coverageLabel(c.coverage?.ipv4) +
            " · IPv6 " +
            coverageLabel(c.coverage?.ipv6) +
            "</small></span></label>"
          );
        })
        .join("")
    : '<p class="hint">' +
      (state.classes.length
        ? "没有匹配的分类。"
        : "所选版本尚无可用分类。请先获取数据版本。") +
      "</p>";
  $("#catalog-classes")
    .querySelectorAll("input")
    .forEach(
      (i) =>
        (i.onchange = () => {
          if (i.checked) state.classKeys.add(i.value);
          else state.classKeys.delete(i.value);
          renderBindingHint();
        }),
    );
  $("#more-classes").hidden = !state.cursor;
  renderBindingHint();
};
const renderBindingHint = () => {
  $("#binding-hint").textContent =
    (!state.node ? "请先选择节点。" : "") +
    "已选择 " +
    state.classKeys.size +
    " 个分类。使用数据后，可在全局或入口规则中选择这些分类；省份分类同时用于省份白名单。已有配置分类会保留。";
  updateWriteAccess();
};
$("#source-select").onchange = () => loadVersions();
$("#version-select").onchange = () => loadClasses();
$("#more-classes").onclick = () => loadClasses(true);
$("#classification-search").oninput = renderClasses;
$("#select-province-classes").onclick = async () => {
  if (!$("#version-select").value) {
    status("请先选择数据源和版本", true);
    return;
  }
  const source = $("#source-select").value,
    version = $("#version-select").value;
  while (state.cursor) {
    const cursor = state.cursor;
    await loadClasses(true);
    if (
      source !== $("#source-select").value ||
      version !== $("#version-select").value
    )
      return;
    if (state.cursor === cursor) {
      status("分类加载未完成，请重试", true);
      return;
    }
  }
  for (const item of state.classes)
    if (
      item.classification.kind === "region" &&
      provinceName(item.classification.name)
    )
      state.classKeys.add("region/" + item.classification.name);
  renderClasses();
};
$("#clear-classes").onclick = () => {
  state.classKeys.clear();
  renderClasses();
};
$("#binding-form").onsubmit = (e) => {
  e.preventDefault();
  mutate(async () => {
    const source = selectedSource(),
      version = $("#version-select").value,
      node = state.node;
    if (!source || !version || !state.classKeys.size || !node)
      throw new Error("请选择节点、数据源、版本和分类");
    const config = structuredClone(state.config);
    let definition = config.datasets.find(
      (d) => d.source_id === source.source.id,
    );
    if (!definition) {
      if (config.datasets.length >= 4) throw new Error("最多使用 4 个数据源");
      definition = {
        id: newID("geo"),
        source_id: source.source.id,
        classifications: [],
      };
      config.datasets.push(definition);
    }
    for (const item of state.classes) {
      const c = item.classification;
      if (
        !state.classKeys.has(c.kind + "/" + c.name) ||
        definition.classifications.some(
          (x) => x.kind === c.kind && x.name === c.name,
        )
      )
        continue;
      definition.classifications.push({
        id: newID("class"),
        name: c.name,
        kind: c.kind,
      });
    }
    if (definition.classifications.length > 64)
      throw new Error("每个数据源最多选择 64 个分类");
    await post("api/binding", {
      binding: {
        source_id: source.source.id,
        version_digest: version,
        dataset_id: definition.id,
        node_ids: [node],
        mode: currentMode(),
        config,
      },
    });
    state.dirty = false;
    $("#draft-status").textContent = "配置已保存";
    await load();
    status("数据已绑定，分类现可用于规则和省份白名单。");
  });
};
const renderDatasets = () => {
  if (!state.config) return;
  const views = state.payload?.datasets || [],
    bindings = state.payload?.bindings || [];
  $("#datasets").innerHTML = state.config.datasets.length
    ? state.config.datasets
        .map((d) => {
          const view = views.find((v) => v.definition.id === d.id),
            binding = bindings.find((b) => b.source_id === d.source_id),
            version =
              view?.versions?.find(
                (v) => v.digest === binding?.desired?.spec?.version_digest,
              ) || view?.versions?.[0],
            current = view?.status;
          return (
            '<article class="dataset-card"><header><strong>' +
            esc(sourceName(d.source_id)) +
            '</strong><span class="badge">' +
            esc(state.node ? phaseLabel(current?.phase) : "未选择节点") +
            "</span></header><p>" +
            d.classifications.length +
            " 个分类 · " +
            d.classifications.filter(
              (c) => c.kind === "region" && provinceName(c.name),
            ).length +
            " 个大陆省份</p><dl><dt>使用版本</dt><dd>" +
            esc(version ? versionLabel(version) : "尚未绑定") +
            "</dd><dt>应用状态</dt><dd>" +
            esc(
              !state.node
                ? "选择节点查看"
                : current?.applied
                  ? "节点已应用"
                  : current?.failure
                    ? "应用失败"
                    : "等待节点应用",
            ) +
            "</dd><dt>用途</dt><dd>全局规则 / 入口规则" +
            (d.classifications.some(
              (c) => c.kind === "region" && provinceName(c.name),
            )
              ? " / 省份白名单"
              : "") +
            "</dd></dl>" +
            (view?.error
              ? '<p class="error">' + esc(view.error) + "</p>"
              : "") +
            '<button class="text-button" data-source-edit="' +
            esc(d.source_id) +
            '">查看分类 / 更换版本</button><details><summary>版本校验信息</summary><code>' +
            esc(binding?.desired?.spec?.version_digest || "尚无版本") +
            "</code></details></article>"
          );
        })
        .join("")
    : '<p class="empty-state">还没有使用地理数据。单 IP 和网段规则可直接配置；国家或省份规则需要先选择上方数据。</p>';
  $("#datasets")
    .querySelectorAll("[data-source-edit]")
    .forEach(
      (b) =>
        (b.onclick = () => {
          switchTab("data");
          loadSources(b.dataset.sourceEdit).catch((e) =>
            status(e.message, true),
          );
          $("#source-select").focus();
        }),
    );
};
$("#add-source").onclick = () => {
  $("#source-form").reset();
  $("#source-error").textContent = "";
  $("#source-dialog").showModal();
};
$("#source-close").onclick = () => $("#source-dialog").close();
$("#source-form").elements.file.onchange = () => {
  const file = $("#source-form").elements.file.files[0];
  if (!file) return;
  const form = $("#source-form");
  form.elements.name.value = file.name.replace(/\.[^.]+$/, "").slice(0, 128);
  const extension = file.name.split(".").at(-1).toLowerCase();
  if (extension === "mmdb") form.elements.format.value = "geo-mmdb";
  else if (extension === "dat") form.elements.format.value = "geoip";
  else if (extension === "txt") form.elements.format.value = "cidr";
};
$("#source-form").onsubmit = (e) => {
  e.preventDefault();
  if (state.busy) return;
  const form = e.currentTarget;
  const file = form.elements.file.files[0];
  if (!file || file.size === 0 || file.size > 128 * 1024 * 1024) {
    $("#source-error").textContent = "请选择非空且不超过 128 MiB 的数据文件。";
    return;
  }
  mutate(async () => {
    const id = newID("source");
    let created = false;
    const source = {
      id,
      name: form.elements.name.value.trim() || file.name.slice(0, 128),
      format: form.elements.format.value,
      license_url: form.elements.license_url.value.trim(),
      refresh_interval_seconds: 0,
    };
    try {
      status("正在校验所选文件…");
      const hash = await crypto.subtle.digest(
        "SHA-256",
        await file.arrayBuffer(),
      );
      const expected =
        "sha256:" +
        Array.from(new Uint8Array(hash), (b) =>
          b.toString(16).padStart(2, "0"),
        ).join("");
      await api("/panel-api/datasets/" + encodeURIComponent(id), {
        method: "PUT",
        body: JSON.stringify({ source, retrieval: { allow_private: false } }),
      });
      created = true;
      status("正在上传数据文件…");
      const uploaded = await api(
        "/panel-api/datasets/" + encodeURIComponent(id) + "/uploads",
        {
          method: "POST",
          headers: { "Content-Type": "application/octet-stream" },
          body: file,
        },
      );
      if (uploaded.artifact_digest !== expected)
        throw new Error("上传文件校验失败，请重新选择文件。");
      status("正在解析数据并建立索引…");
      await post("/panel-api/datasets/control", {
        action: "import",
        source_id: id,
        candidate: {
          revision: "import-" + Date.now(),
          artifact_digest: uploaded.artifact_digest,
          expected_digest: expected,
        },
      });
      $("#source-dialog").close();
      await loadSources(id);
      status("数据已导入。选择需要的分类后，点击“使用所选数据”。");
    } catch (error) {
      if (created) {
        try {
          await post("/panel-api/datasets/control", {
            action: "delete-source",
            source_id: id,
          });
        } catch {
          error = new Error(
            error.message + " 导入来源暂未清理，请在数据目录检查。",
          );
        }
      }
      $("#source-error").textContent = error.message;
      throw error;
    }
  });
};
const reasonLabel = (value) =>
  ({
    1: "无法确认来源身份",
    2: "地理数据暂不可用",
    3: "缺少所需分类",
    4: "检查超过资源预算",
    8: "数据格式无效",
    9: "该地址族没有覆盖数据",
    10: "授权已撤销",
    rule_matched: "命中 IP 策略规则",
    source_unauthenticated: "无法确认来源身份",
    dataset_unavailable: "地理数据暂不可用",
    classification_missing: "缺少所需分类",
    budget_exceeded: "检查超过资源预算",
    coverage_unknown: "该地址族没有覆盖数据",
  })[value] || (value ? "检查未完成" : "命中策略规则");
const renderEvents = (rows) => {
  const showTime = rows.some((row) => row.created_at);
  $("#tab-events th:first-child").hidden = !showTime;
  $("#events").innerHTML = rows
    .map((row) => {
      const e = row.metadata
        ? {
            ...row.metadata,
            action: row.metadata.action || row.result,
            created_at: row.created_at,
            code: row.action,
          }
        : row;
      const c = e.context || {},
        mode = e.disposition || e.action || c.mode;
      const result =
        mode === "deny" || mode === "denied" || mode === "enforce"
          ? "已拦截"
          : mode === "observe"
            ? "仅观察"
            : mode === "allow" || mode === "allowed"
              ? "已允许"
              : "检查异常";
      const target = state.entries.find(
        (x) =>
          x.entry.id === (c.entry_id || e.entry_id) &&
          x.entry.node_id === state.node,
      )?.entry;
      const rule = [
        ...(state.config?.rules || []),
        ...(state.payload?.entry_overlay?.rules || []),
      ].find((r) => r.id === (c.rule_id || e.rule_id));
      return (
        "<tr><td" +
        (showTime ? "" : " hidden") +
        ">" +
        esc(
          e.created_at
            ? new Date(e.created_at).toLocaleString("zh-CN")
            : "时间未提供",
        ) +
        "</td><td>" +
        esc(c.source_address || e.source_address || "未提供") +
        "</td><td>" +
        esc(target ? entryName(target) : e.site || "入口信息未提供") +
        "<small>" +
        esc(rule ? ruleLabel(rule) : "规则信息未提供") +
        '</small></td><td class="result-' +
        (result === "已拦截" ? "deny" : "observe") +
        '">' +
        result +
        "</td><td>" +
        esc(reasonLabel(c.reason || e.reason)) +
        "</td></tr>"
      );
    })
    .join("");
};
const renderEventPage = () => {
  const mode = $("#event-mode").value,
    search = $("#event-search").value.trim().toLowerCase();
  const rows = (state.recentEvents || []).filter((e) => {
    const value = e.disposition || e.action || e.context?.mode;
    const result = ["deny", "denied", "enforce"].includes(value)
      ? "deny"
      : value === "observe"
        ? "observe"
        : "skip";
    return (
      (!mode || mode === result) &&
      (!search || JSON.stringify(e).toLowerCase().includes(search))
    );
  });
  state.page = Math.max(
    1,
    Math.min(state.page, Math.max(1, Math.ceil(rows.length / 10))),
  );
  renderEvents(rows.slice((state.page - 1) * 10, state.page * 10));
  $("#events-empty").hidden = !!rows.length;
  $("#events-empty").textContent =
    "当前返回的最近记录中没有匹配事件。这里不是完整拦截历史，不能据此判断没有发生拦截。";
  $("#events-page").textContent =
    "最近记录 · 第 " +
    state.page +
    " / " +
    Math.max(1, Math.ceil(rows.length / 10)) +
    " 页 · " +
    rows.length +
    " 条";
  $("#events-prev").disabled = state.page <= 1;
  $("#events-next").disabled = state.page * 10 >= rows.length;
};
const loadEvents = async () => {
  const seq = ++state.eventSeq,
    node = state.node;
  $("#events-prev").disabled = true;
  $("#events-next").disabled = true;
  $("#events").replaceChildren();
  $("#events-empty").hidden = false;
  if (!node) {
    $("#events-empty").textContent = "先选择节点，再查看它的 IP 策略诊断记录。";
    return;
  }
  $("#events-empty").textContent = "正在读取最近记录…";
  try {
    const payload = await api(
      "api/state?" + new URLSearchParams({ node_id: node }),
    );
    if (seq !== state.eventSeq || node !== state.node) return;
    if (payload.issues?.some((issue) => issue.includes("诊断事件")))
      throw new Error("诊断记录暂时不可用，请稍后重试。");
    state.recentEvents = Array.isArray(payload.events) ? payload.events : [];
    state.page = 1;
    $("#event-retention").textContent =
      "仅显示现有接口返回的最近记录，下面的翻页只对本次结果分组；不代表完整历史。记录保存和清理由控制面板统一管理。";
    renderEventPage();
  } catch (error) {
    if (seq !== state.eventSeq) return;
    state.recentEvents = [];
    $("#events-empty").textContent = error.message;
    $("#event-retention").textContent =
      "读取未完成，不能据此判断是否发生拦截。";
  }
};
$("#events-refresh").onclick = loadEvents;
$("#events-prev").onclick = () => {
  state.page--;
  renderEventPage();
};
$("#events-next").onclick = () => {
  state.page++;
  renderEventPage();
};
$("#event-mode").onchange = () => {
  state.page = 1;
  renderEventPage();
};
$("#event-search").oninput = () => {
  state.page = 1;
  renderEventPage();
};
window.addEventListener("beforeunload", (e) => {
  if (state.dirty) {
    e.preventDefault();
    e.returnValue = "";
  }
});
loadAgents()
  .then(() =>
    loadSources().catch((error) => {
      $("#catalog-status").textContent =
        error.status === 403
          ? "需要数据源管理权限才能选择或添加来源。"
          : error.message;
    }),
  )
  .catch((error) => status(error.message, true));
