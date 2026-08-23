const publicBase = () => {
  const origin = window.location.origin.replace(/\/$/, "");
  let pathname = String(window.location.pathname || "/");
  pathname = pathname.replace(/\/index\.html$/i, "");
  pathname = pathname.replace(/\/+$/, "");
  return origin + pathname;
};
const dohUrl = publicBase() + "/dns-query";

const urlNode = document.querySelector("#doh-url");
if (urlNode) {
  urlNode.textContent = dohUrl;
}

const copyButton = document.querySelector("#copy-doh-url");
const statusNode = document.querySelector("#copy-status");

const showStatus = (message, isError) => {
  if (!statusNode) {
    return;
  }
  statusNode.hidden = !message;
  statusNode.textContent = message || "";
  statusNode.dataset.error = isError ? "true" : "false";
};

const copyText = async (text) => {
  const value = String(text || "");
  if (!value) {
    return;
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  throw new Error("当前环境无法复制");
};

if (copyButton) {
  copyButton.addEventListener("click", async () => {
    try {
      await copyText(dohUrl);
      showStatus("已复制。", false);
    } catch (_error) {
      showStatus("当前环境无法复制，请手动选择地址。", true);
    }
  });
}
