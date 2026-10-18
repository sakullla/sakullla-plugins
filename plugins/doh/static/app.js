/* DoH endpoint page.
   The endpoint URL is derived from the page's own origin and pathname; the
   shared ui-kit owns theme resolution and clipboard/toast behaviour. */

const publicBase = () => {
  const origin = window.location.origin.replace(/\/$/, "");
  let pathname = String(window.location.pathname || "/");
  pathname = pathname.replace(/\/index\.html$/i, "");
  pathname = pathname.replace(/\/+$/, "");
  return origin + pathname;
};

const dohUrl = publicBase() + "/dns-query";

const urlNode = document.querySelector("#doh-url");
const copyButton = document.querySelector("#copy-doh-url");
const statusNode = document.querySelector("#copy-status");

if (urlNode) {
  urlNode.textContent = dohUrl;
}

const showStatus = (message, state) => {
  if (!statusNode) {
    return;
  }
  statusNode.hidden = !message;
  statusNode.textContent = message || "";
  if (state) {
    statusNode.dataset.state = state;
  } else {
    delete statusNode.dataset.state;
  }
};

const copyText = (text) => {
  if (window.NREUI && typeof window.NREUI.copyText === "function") {
    return Promise.resolve(window.NREUI.copyText(text));
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    return navigator.clipboard.writeText(text).then(
      () => true,
      () => false
    );
  }
  return Promise.resolve(false);
};

const setBusy = (busy) => {
  if (!copyButton) {
    return;
  }
  if (window.NREUI && typeof window.NREUI.setBusy === "function") {
    window.NREUI.setBusy(copyButton, busy);
    return;
  }
  copyButton.disabled = busy;
};

const selectUrl = () => {
  if (!urlNode) {
    return;
  }
  const selection = window.getSelection ? window.getSelection() : null;
  if (!selection) {
    return;
  }
  const range = document.createRange();
  range.selectNodeContents(urlNode);
  selection.removeAllRanges();
  selection.addRange(range);
};

if (urlNode) {
  urlNode.title = "点击全选";
  urlNode.addEventListener("click", selectUrl);
}

if (copyButton) {
  copyButton.addEventListener("click", async () => {
    setBusy(true);
    try {
      const copied = await copyText(dohUrl);
      if (copied) {
        showStatus("已复制地址。", "success");
      } else {
        selectUrl();
        showStatus("复制失败，请手动选择地址。", "error");
      }
    } catch (_error) {
      selectUrl();
      showStatus("复制失败，请手动选择地址。", "error");
    } finally {
      setBusy(false);
    }
  });
}
