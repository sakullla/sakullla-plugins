const statusNode = document.querySelector("#mapping-status");

const showStatus = (message, isError) => {
  if (!statusNode) {
    return;
  }
  statusNode.hidden = !message;
  statusNode.textContent = message;
  statusNode.dataset.error = isError ? "true" : "false";
};

const confirmAction = (suffix, action) => window.confirm(`确认对 ${suffix} 执行${action}？取消不会更改映射。`);

const newOperationKey = () => {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return `operation/ui/${Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("")}`;
};

const sendJSON = async (path, body) => {
  const response = await fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-NRE-Operation-Key": newOperationKey(),
    },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || "保存失败");
  }
  return payload;
};

document.querySelectorAll("form[data-action]").forEach((form) => {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const action = form.dataset.action;
    const current = form.dataset.suffix || "";
    const data = new FormData(form);
    const suffix = String(data.get("suffix") || current).trim();
    const token = String(data.get("token") || "");
    if ((action === "delete" || action === "rotate" || action === "rename") && !confirmAction(current, form.querySelector("button").textContent)) {
      showStatus("已取消，映射未更改。", false);
      return;
    }
    try {
      if (action === "create") {
        await sendJSON("api/mappings", { suffix, token });
      } else if (action === "rename") {
        await sendJSON(`api/mappings/${encodeURIComponent(current)}/rename`, { suffix, confirm: current });
      } else if (action === "rotate") {
        await sendJSON(`api/mappings/${encodeURIComponent(current)}/rotate`, { token, confirm: current });
      } else if (action === "delete") {
        await sendJSON(`api/mappings/${encodeURIComponent(current)}/delete`, { confirm: current });
      }
      window.location.reload();
    } catch (error) {
      showStatus(error.message, true);
    }
  });
});
