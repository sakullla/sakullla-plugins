// Runs before first paint so dark-mode visitors never see a light flash.
// A saved choice wins; otherwise the operating-system preference is used.
(function () {
  var theme = null;
  try {
    theme = window.localStorage.getItem("accelerator-sources.theme");
  } catch (_error) {
    theme = null;
  }
  if (theme !== "light" && theme !== "dark") {
    theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  document.documentElement.setAttribute("data-theme", theme);
})();
