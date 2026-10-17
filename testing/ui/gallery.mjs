// Chinese contact sheet for one capture run. Filtering is inlined so the
// gallery can be opened from the filesystem without a server.
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

export const manifestName = "capture-ui-manifest.json";

const escapeHtml = (value) => String(value).replace(/[&<>"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[char]);

const themeLabel = { light: "浅色 light", dark: "深色 dark" };

const cell = (value) => String(value ?? "").replaceAll("|", "\\|").replaceAll("\n", " ");

const option = (value, label) => `<option value="${escapeHtml(value)}">${escapeHtml(label)}</option>`;

export function buildGallery(report) {
  const titles = new Map(report.captures.map((item) => [`${item.plugin}\0${item.scene}`, item.title || item.scene]));
  const sceneOptions = [];
  const seenScenes = new Set();
  for (const item of report.selected) {
    for (const name of item.scenes) {
      if (seenScenes.has(name)) continue;
      seenScenes.add(name);
      const title = titles.get(`${item.plugin}\0${name}`) || name;
      sceneOptions.push(option(name, `${title}（${name}）`));
    }
  }
  const cards = report.captures.filter((item) => item.file).map((item) => {
    const keywords = [item.plugin, item.scene, item.title, item.theme, item.width].join(" ").toLowerCase();
    const issues = item.issues.map((issue) => `<small class="issue">${escapeHtml(issue)}</small>`).join("");
    return `<figure class="${item.issues.length ? "bad" : ""}" data-plugin="${escapeHtml(item.plugin)}" data-scene="${escapeHtml(item.scene)}" data-theme="${escapeHtml(item.theme)}" data-width="${escapeHtml(item.width)}" data-keywords="${escapeHtml(keywords)}"><a href="${escapeHtml(item.file)}" target="_blank" rel="noopener"><img loading="lazy" src="${escapeHtml(item.file)}" alt="${escapeHtml(`${item.plugin} ${item.title} ${item.theme} ${item.width}`)}"></a><figcaption><b>${escapeHtml(item.plugin)}</b> ${escapeHtml(item.title)}<small>${escapeHtml(item.scene)} · ${escapeHtml(item.theme)} · ${item.width}px</small>${issues}</figcaption></figure>`;
  }).join("");
  const status = report.success
    ? `本次结果：通过。${report.imageCount} 张图片，0 项失败。`
    : `本次结果：有失败。${report.imageCount} 张图片，${report.failureCount} 项失败。`;
  const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>UI 捕获</title><style>
body{margin:0;background:#f4f5f8;color:#1b1f2a;font:15px/1.5 system-ui,"Microsoft YaHei",sans-serif}header{position:sticky;top:0;z-index:2;padding:20px 4vw;background:#fff;border-bottom:1px solid #e1e4ec}h1{font-size:22px;margin:0 0 8px}#status{margin:0;color:#3c4456}.filters{display:flex;flex-wrap:wrap;gap:10px;align-items:end;margin-top:14px}label{display:grid;gap:5px;font-size:13px;color:#3c4456}select,input,button{font:inherit;padding:8px 10px;border:1px solid #c9ceda;border-radius:8px;background:#fff;color:#1b1f2a;max-width:100%;box-sizing:border-box}select{max-width:min(280px,80vw)}button{cursor:pointer}input{width:220px}.links{display:flex;gap:16px;align-items:center;margin-top:12px}a{color:#1d4ed8}#count{color:#3c4456}main{padding:24px 4vw;display:grid;grid-template-columns:repeat(auto-fit,minmax(min(280px,100%),1fr));gap:20px}figure{margin:0;padding:12px;border:1px solid #e1e4ec;border-radius:12px;background:#fff;min-width:0}figure.bad{border-color:#e5484d}img{width:100%;height:320px;object-fit:contain;object-position:top;background:#f7f8fb;border-radius:8px}figcaption{padding-top:10px;overflow-wrap:anywhere}small{display:block;color:#5b6375;margin-top:4px}.issue{color:#c62a2f}#empty{padding:8px 4vw 24px}[hidden]{display:none!important}</style></head><body><header><h1>UI 捕获</h1><p id="status">${escapeHtml(status)}</p><form class="filters" id="filters"><label>插件<select id="plugin" aria-label="插件"><option value="">全部插件</option>${report.selected.map((item) => option(item.plugin, item.plugin)).join("")}</select></label><label>场景<select id="scene" aria-label="场景"><option value="">全部场景</option>${sceneOptions.join("")}</select></label><label>主题<select id="theme" aria-label="主题"><option value="">全部主题</option>${report.themes.map((theme) => option(theme, themeLabel[theme] || theme)).join("")}</select></label><label>宽度<select id="width" aria-label="宽度"><option value="">全部宽度</option>${report.widths.map((width) => option(String(width), `${width}px`)).join("")}</select></label><label>关键词<input id="query" type="search" placeholder="插件、场景或标题" aria-label="关键词"></label><button type="reset">重置</button></form><div class="links"><output id="count" aria-live="polite"></output><a href="index.html">画廊</a><a href="README.md">说明</a><a href="${manifestName}">捕获清单</a></div></header><p id="empty" hidden>没有匹配的图片，请调整筛选或重置。</p><main>${cards}</main><script>
const ids=["plugin","scene","theme","width","query"];
const controls=ids.map((id)=>document.getElementById(id));
const cards=[...document.querySelectorAll("figure")];
function filter(){
  const query=controls[4].value.trim().toLowerCase();
  let count=0;
  for(const card of cards){
    const hidden=controls.slice(0,4).some((control,index)=>control.value&&card.dataset[ids[index]]!==control.value)||!card.dataset.keywords.includes(query);
    card.hidden=hidden;
    if(!hidden)count+=1;
  }
  document.getElementById("count").textContent="显示 "+count+" / "+cards.length+" 张";
  document.getElementById("empty").hidden=count!==0;
}
controls.forEach((control)=>control.addEventListener("input",filter));
document.getElementById("filters").addEventListener("submit",(event)=>event.preventDefault());
document.getElementById("filters").addEventListener("reset",()=>setTimeout(filter,0));
filter();
</script></body></html>\n`;

  const groups = [];
  for (const item of report.selected) {
    for (const name of item.scenes) {
      const rows = report.captures.filter((capture) => capture.plugin === item.plugin && capture.scene === name);
      const title = titles.get(`${item.plugin}\0${name}`) || name;
      const issues = [...new Set(rows.flatMap((row) => row.issues))];
      if (!rows.length) issues.push("缺少图片");
      const links = rows.filter((row) => row.file).map((row) => `[${row.theme} ${row.width}](${row.file})`).join(" · ") || "—";
      groups.push(`| ${cell(item.plugin)} | ${cell(`${title}（${name}）`)} | ${cell(issues.length ? issues.join("；") : "通过")} | ${links} |`);
    }
  }
  const readme = `# UI 捕获

[浏览画廊](index.html) · [捕获清单](${manifestName})

命令：

\`\`\`sh
${report.invocation}
\`\`\`

本次 ${report.imageCount} 张图片，${report.failureCount} 项失败。

| 插件 | 场景 | 结果 | 图片 |
| --- | --- | --- | --- |
${groups.join("\n")}
`;

  const manifest = {
    capturedAt: report.capturedAt,
    invocation: report.invocation,
    themes: report.themes,
    widths: report.widths,
    selected: report.selected,
    missing: report.missing,
    success: report.success,
    imageCount: report.imageCount,
    failureCount: report.failureCount,
    captures: report.captures.filter((item) => item.file).map((item) => ({
      plugin: item.plugin,
      scene: item.scene,
      title: item.title,
      theme: item.theme,
      width: item.width,
      height: item.height,
      file: item.file,
      issues: item.issues,
    })),
    failures: report.failures,
  };
  return { html, readme, manifest: `${JSON.stringify(manifest, null, 2)}\n` };
}

export async function writeGallery(out, report) {
  const built = buildGallery(report);
  await mkdir(out, { recursive: true });
  await writeFile(join(out, "index.html"), built.html);
  await writeFile(join(out, "README.md"), built.readme);
  await writeFile(join(out, manifestName), built.manifest);
}
