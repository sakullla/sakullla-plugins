const statusNode = document.querySelector("#panel-status");
const listenStatus = document.querySelector("#listen-status");
const listenHostPort = document.querySelector("#listen-hostport");
const copyHostPort = document.querySelector("#copy-hostport");
const hostPortRow = document.querySelector(".hostport-row");
const accountEmpty = document.querySelector("#account-empty");
const accountList = document.querySelector("#account-list");
const rotateServer = document.querySelector("#rotate-server-psk");

const showStatus = (message, isError) => {
  if (!statusNode) {
    return;
  }
  statusNode.hidden = !message;
  statusNode.textContent = message;
  statusNode.dataset.error = isError ? "true" : "false";
};

const copyText = async (value) => {
  if (!value) {
    throw new Error("没有可复制的内容");
  }
  await navigator.clipboard.writeText(value);
};

const sendJSON = async (path, body) => {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : "{}",
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || "操作失败");
  }
  return payload;
};

const familyLabel = (family) => (family === "ss2022" ? "SS2022" : "传统 SS");

const renderListen = (listen) => {
  if (!listenStatus || !listenHostPort || !copyHostPort || !hostPortRow) {
    return;
  }
  if (!listen || !listen.available) {
    listenStatus.textContent = listen && listen.reason ? listen.reason : "缺少对外地址";
    listenHostPort.textContent = "";
    hostPortRow.hidden = true;
    copyHostPort.hidden = true;
    return;
  }
  listenStatus.textContent = `当前对外监听 ${listen.host_port}（TCP 与 UDP 同一端口）`;
  listenHostPort.textContent = listen.host_port;
  hostPortRow.hidden = false;
  copyHostPort.hidden = false;
  copyHostPort.onclick = async () => {
    try {
      await copyText(listen.host_port);
      showStatus("已复制 host:port。", false);
    } catch (error) {
      showStatus(error.message, true);
    }
  };
};

const renderAccount = (account) => {
  const article = document.createElement("article");
  article.className = "account";
  article.dataset.id = account.id;
  article.dataset.enabled = account.enabled ? "true" : "false";

  const title = document.createElement("p");
  const identity = document.createElement("strong");
  identity.textContent = account.id;
  const status = document.createElement("span");
  status.className = account.enabled ? "status-on" : "status-off";
  status.textContent = account.enabled ? "启用" : "停用";
  title.append(identity, ` · ${familyLabel(account.family)} · `, document.createTextNode(account.method || ""), " · ", status);
  article.append(title);

  if (account.share_available) {
    const label = document.createElement("label");
    const uri = document.createElement("code");
    uri.className = "uri";
    uri.textContent = account.uri || "";
    label.append("SIP002 URI ", uri);
    const shareRow = document.createElement("div");
    shareRow.className = "share-row";
    const copy = document.createElement("button");
    copy.type = "button";
    copy.dataset.copyUri = "";
    copy.textContent = "复制 SIP002 URI";
    shareRow.append(copy);
    const qrCaption = document.createElement("p");
    qrCaption.textContent = "对应二维码";
    const qr = document.createElement("img");
    qr.className = "qr";
    qr.alt = "SIP002 二维码";
    qr.src = `api/accounts/${encodeURIComponent(account.id)}/qr.png`;
    article.append(label, shareRow, qrCaption, qr);
    copy.addEventListener("click", async () => {
      try {
        await copyText(account.uri);
        showStatus("已复制 SIP002 URI。", false);
      } catch (error) {
        showStatus(error.message, true);
      }
    });
  } else {
    const hint = document.createElement("p");
    hint.className = "hint";
    hint.textContent = account.reason || (account.enabled ? "分享不可用" : "停用账号不提供可导入 URI");
    article.append(hint);
  }

  const actions = document.createElement("div");
  actions.className = "actions";
  const toggle = document.createElement("form");
  toggle.method = "post";
  toggle.dataset.action = account.enabled ? "disable" : "enable";
  toggle.dataset.id = account.id;
  const toggleButton = document.createElement("button");
  toggleButton.type = "submit";
  toggleButton.textContent = account.enabled ? "停用" : "再启用";
  toggle.append(toggleButton);
  const rotate = document.createElement("form");
  rotate.method = "post";
  rotate.dataset.action = "rotate";
  rotate.dataset.id = account.id;
  const rotateButton = document.createElement("button");
  rotateButton.type = "submit";
  rotateButton.textContent = "轮换客户端密钥";
  rotate.append(rotateButton);
  actions.append(toggle, rotate);
  article.append(actions);
  article.querySelectorAll("form[data-action]").forEach((form) => {
    form.addEventListener("submit", onAction);
  });
  return article;
};

const renderPanel = (panel) => {
  renderListen(panel.listen);
  if (!accountList || !accountEmpty) {
    return;
  }
  accountList.replaceChildren();
  const accounts = panel.accounts || [];
  accountEmpty.hidden = accounts.length > 0;
  accounts.forEach((account) => {
    accountList.append(renderAccount(account));
  });
  if (rotateServer) {
    rotateServer.hidden = !panel.server_psk_version;
    rotateServer.dataset.version = panel.server_psk_version || "";
  }
};

const loadPanel = async () => {
  const response = await fetch("api/panel");
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || "服务未就绪");
  }
  renderPanel(payload);
};

const onAction = async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const action = form.dataset.action;
  try {
    if (action === "create") {
      await sendJSON("api/accounts", { family: form.dataset.family });
    } else if (action === "disable" || action === "enable" || action === "rotate") {
      await sendJSON(`api/accounts/${encodeURIComponent(form.dataset.id)}/${action}`, {});
    } else if (action === "rotate-server") {
      await sendJSON("api/server-psk/rotate", { expected_version: form.dataset.version || "" });
    }
    showStatus("已更新。", false);
    await loadPanel();
  } catch (error) {
    showStatus(error.message, true);
  }
};

document.querySelectorAll("form[data-action]").forEach((form) => {
  form.addEventListener("submit", onAction);
});

loadPanel().catch((error) => {
  showStatus(error.message, true);
  if (listenStatus) {
    listenStatus.textContent = error.message;
  }
});
