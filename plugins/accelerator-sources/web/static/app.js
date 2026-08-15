const views = { search: document.querySelector('#search-view'), offline: document.querySelector('#offline-view') };
document.querySelectorAll('nav button').forEach((button) => button.addEventListener('click', () => {
  Object.entries(views).forEach(([name, view]) => { view.hidden = name !== button.dataset.view; });
  document.querySelectorAll('nav button').forEach((item) => item.setAttribute('aria-pressed', item === button ? 'true' : 'false'));
}));

document.querySelector('#search-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const results = document.querySelector('#results');
  results.textContent = '正在搜索...';
  try {
    const response = await fetch(`/api/search?q=${encodeURIComponent(document.querySelector('#query').value)}`);
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || '搜索失败');
    const entries = Array.isArray(payload.results) ? payload.results : [];
    results.replaceChildren(...entries.map((entry) => {
      const row = document.createElement('button');
      row.type = 'button';
      row.className = 'result';
      row.textContent = `${entry.repo_name || entry.name}${entry.short_description ? ` · ${entry.short_description}` : ''}`;
      row.addEventListener('click', () => { document.querySelector('#images').value = entry.repo_name || entry.name; document.querySelector('nav button[data-view="offline"]').click(); });
      return row;
    }));
  } catch (error) { results.textContent = error.message; }
});

document.querySelector('#offline-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const output = document.querySelector('#download');
  output.textContent = '正在准备...';
  const images = document.querySelector('#images').value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
  try {
    const response = await fetch('/api/offline/prepare', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ images, platform: document.querySelector('#platform').value }) });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || '准备失败');
    const link = document.createElement('a');
    link.href = payload.download_url;
    link.textContent = '下载 Docker 离线包';
    output.replaceChildren(link);
  } catch (error) { output.textContent = error.message; }
});
