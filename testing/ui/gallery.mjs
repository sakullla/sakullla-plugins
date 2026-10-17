// Chinese contact sheet for one capture run. Filtering is inlined so the
// gallery can be opened from the filesystem without a server. Variants of one
// plugin scene share a group; groups with a failure or a missing image come first.
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

export const manifestName = "capture-ui-manifest.json";

const escapeHtml = (value) => String(value).replace(/[&<>"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[char]);

const themeLabel = { light: "浅色 light", dark: "深色 dark" };

const cell = (value) => String(value ?? "").replaceAll("|", "\\|").replaceAll("\n", " ");

const option = (value, label) => `<option value="${escapeHtml(value)}">${escapeHtml(label)}</option>`;

const sceneKey = (plugin, scene) => `${plugin}\0${scene}`;

const compareVariants = (report) => {
  const themeIndex = new Map((report.themes || []).map((theme, index) => [theme, index]));
  const widthIndex = new Map((report.widths || []).map((width, index) => [Number(width), index]));
  return (left, right) => {
    const byTheme = (themeIndex.get(left.theme) ?? 1000) - (themeIndex.get(right.theme) ?? 1000);
    if (byTheme) return byTheme;
    return (widthIndex.get(Number(left.width)) ?? 1000) - (widthIndex.get(Number(right.width)) ?? 1000);
  };
};

const uniqueIssues = (rows) => {
  const issues = [];
  for (const row of rows) {
    for (const issue of row.issues || []) {
      if (!issues.includes(issue)) issues.push(issue);
    }
  }
  return issues;
};

function sceneGroups(report) {
  const titles = new Map(report.captures.map((item) => [sceneKey(item.plugin, item.scene), item.title || item.scene]));
  const order = compareVariants(report);
  const groups = [];
  for (const item of report.selected) {
    for (const name of item.scenes) {
      const rows = report.captures
        .filter((capture) => capture.plugin === item.plugin && capture.scene === name)
        .slice()
        .sort(order);
      const issues = uniqueIssues(rows);
      const missing = (report.missing || []).some((entry) => entry.plugin === item.plugin && entry.scene === name);
      if ((missing || !rows.length || rows.some((row) => !row.file)) && !issues.includes("缺少图片")) issues.push("缺少图片");
      groups.push({
        plugin: item.plugin,
        scene: name,
        title: titles.get(sceneKey(item.plugin, name)) || name,
        rows,
        issues,
        failed: issues.length > 0,
      });
    }
  }
  return groups.filter((group) => group.failed).concat(groups.filter((group) => !group.failed));
}

const figure = (item) => {
  const keywords = [item.plugin, item.scene, item.title, item.theme, item.width].join(" ").toLowerCase();
  const issues = (item.issues || []).map((issue) => `<small class="issue">${escapeHtml(issue)}</small>`).join("");
  const alt = `${item.plugin} ${item.title} ${item.theme} ${item.width}`;
  const failed = (item.issues || []).length ? "bad" : "";
  return `<figure class="${failed}" data-plugin="${escapeHtml(item.plugin)}" data-scene="${escapeHtml(item.scene)}" data-theme="${escapeHtml(item.theme)}" data-width="${escapeHtml(item.width)}" data-keywords="${escapeHtml(keywords)}"><a class="view" href="${escapeHtml(item.file)}" data-alt="${escapeHtml(alt)}"><img loading="lazy" src="${escapeHtml(item.file)}" alt="${escapeHtml(alt)}"></a><figcaption><b>${escapeHtml(item.plugin)}</b> ${escapeHtml(item.title)}<small>${escapeHtml(item.scene)} · ${escapeHtml(item.theme)} · ${item.width}px</small>${issues}</figcaption></figure>`;
};

const groupHtml = (group) => {
  const cards = group.rows.filter((row) => row.file).map(figure).join("");
  const reasons = group.issues.map((issue) => `<p class="issue">${escapeHtml(issue)}</p>`).join("");
  return `<section class="scene${group.failed ? " bad" : ""}" data-group="1" data-plugin="${escapeHtml(group.plugin)}" data-scene="${escapeHtml(group.scene)}"><h2>${escapeHtml(group.plugin)} ${escapeHtml(group.title)}<small>${escapeHtml(group.scene)}</small></h2>${reasons}<div class="variants">${cards}</div></section>`;
};

export function buildGallery(report) {
  const groups = sceneGroups(report);
  const titles = new Map(report.captures.map((item) => [sceneKey(item.plugin, item.scene), item.title || item.scene]));
  const sceneOptions = [];
  const seenScenes = new Set();
  for (const item of report.selected) {
    for (const name of item.scenes) {
      if (seenScenes.has(name)) continue;
      seenScenes.add(name);
      const title = titles.get(sceneKey(item.plugin, name)) || name;
      sceneOptions.push(option(name, `${title}（${name}）`));
    }
  }
  const status = report.success
    ? `本次结果：通过。${report.imageCount} 张图片，0 项失败。`
    : `本次结果：有失败。${report.imageCount} 张图片，${report.failureCount} 项失败。`;
  const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>UI 捕获</title><style>
body{margin:0;background:#f4f5f8;color:#1b1f2a;font:15px/1.5 system-ui,"Microsoft YaHei",sans-serif}header{position:sticky;top:0;z-index:2;padding:20px 4vw;background:#fff;border-bottom:1px solid #e1e4ec}h1{font-size:22px;margin:0 0 8px}#status{margin:0;color:#3c4456}.filters{display:flex;flex-wrap:wrap;gap:10px;align-items:end;margin-top:14px}label{display:grid;gap:5px;font-size:13px;color:#3c4456}select,input,button{font:inherit;padding:8px 10px;border:1px solid #c9ceda;border-radius:8px;background:#fff;color:#1b1f2a;max-width:100%;box-sizing:border-box}select{max-width:min(280px,80vw)}button{cursor:pointer}input{width:220px}.links{display:flex;gap:16px;align-items:center;margin-top:12px}a{color:#1d4ed8}#count{color:#3c4456}main{padding:24px 4vw;display:flex;flex-direction:column;gap:28px}section.scene{padding:16px;border:1px solid #e1e4ec;border-radius:16px;background:#fff;min-width:0}section.scene.bad{border-color:#e5484d}section.scene h2{margin:0;font-size:18px}section.scene h2 small{display:block;color:#5b6375;font-weight:400}.variants{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(280px,100%),1fr));gap:20px;margin-top:12px}figure{margin:0;padding:12px;border:1px solid #e1e4ec;border-radius:12px;background:#fbfbfd;min-width:0}figure.bad{border-color:#e5484d}figure img{width:100%;height:320px;object-fit:contain;object-position:top;background:#f7f8fb;border-radius:8px}figcaption{padding-top:10px;overflow-wrap:anywhere}small{display:block;color:#5b6375;margin-top:4px}.issue{color:#c62a2f}#empty{padding:8px 4vw 24px}#viewer{position:fixed;inset:0;z-index:5;overflow:auto;background:#111;padding:0 0 24px}#viewer img{display:block;width:100%;height:auto;background:#fff}#viewer button{display:block;margin:12px 16px}[hidden]{display:none!important}</style></head><body><header><h1>UI 捕获</h1><p id="status">${escapeHtml(status)}</p><form class="filters" id="filters"><label>插件<select id="plugin" aria-label="插件"><option value="">全部插件</option>${report.selected.map((item) => option(item.plugin, item.plugin)).join("")}</select></label><label>场景<select id="scene" aria-label="场景"><option value="">全部场景</option>${sceneOptions.join("")}</select></label><label>主题<select id="theme" aria-label="主题"><option value="">全部主题</option>${report.themes.map((theme) => option(theme, themeLabel[theme] || theme)).join("")}</select></label><label>宽度<select id="width" aria-label="宽度"><option value="">全部宽度</option>${report.widths.map((width) => option(String(width), `${width}px`)).join("")}</select></label><label>关键词<input id="query" type="search" placeholder="插件、场景或标题" aria-label="关键词"></label><button type="reset">重置</button></form><div class="links"><output id="count" aria-live="polite"></output><a href="index.html">画廊</a><a href="README.md">说明</a><a href="${manifestName}">捕获清单</a></div></header><p id="empty" hidden>没有匹配的图片，请调整筛选或重置。</p><main>${groups.map(groupHtml).join("")}</main><div id="viewer" hidden><button type="button" id="viewer-close">关闭</button><img id="viewer-image" alt=""><button type="button" id="viewer-close-end">关闭</button></div><script>
const ids=["plugin","scene","theme","width","query"];
const controls=ids.map((id)=>document.getElementById(id));
const cards=[...document.querySelectorAll("figure")];
const groups=[...document.querySelectorAll("section[data-group]")];
const viewer=document.getElementById("viewer");
const viewerImage=document.getElementById("viewer-image");
function filter(){
  const query=controls[4].value.trim().toLowerCase();
  let count=0;
  for(const card of cards){
    const hidden=controls.slice(0,4).some((control,index)=>control.value&&card.dataset[ids[index]]!==control.value)||!card.dataset.keywords.includes(query);
    card.hidden=hidden;
    if(!hidden)count+=1;
  }
  for(const group of groups){
    const own=cards.filter((card)=>card.dataset.plugin===group.dataset.plugin&&card.dataset.scene===group.dataset.scene);
    if(!own.length){
      const pluginOk=!controls[0].value||group.dataset.plugin===controls[0].value;
      const sceneOk=!controls[1].value||group.dataset.scene===controls[1].value;
      group.hidden=!pluginOk||!sceneOk||Boolean(controls[2].value||controls[3].value||query);
    }else{
      group.hidden=!own.some((card)=>!card.hidden);
    }
  }
  document.getElementById("count").textContent="显示 "+count+" / "+cards.length+" 张";
  const shown=groups.length?groups.some((group)=>!group.hidden):count!==0;
  document.getElementById("empty").hidden=shown;
}
function closeViewer(){viewer.hidden=true;}
controls.forEach((control)=>control.addEventListener("input",filter));
document.getElementById("filters").addEventListener("submit",(event)=>event.preventDefault());
document.getElementById("filters").addEventListener("reset",()=>setTimeout(filter,0));
for(const link of document.querySelectorAll("a.view")){
  link.addEventListener("click",(event)=>{
    event.preventDefault();
    viewer.scrollTop=0;
    viewerImage.setAttribute("src",link.getAttribute("href"));
    viewerImage.alt=link.dataset.alt||"";
    viewer.hidden=false;
    viewer.scrollTop=0;
  });
}
document.getElementById("viewer-close").addEventListener("click",closeViewer);
document.getElementById("viewer-close-end").addEventListener("click",closeViewer);
filter();
</script></body></html>\n`;

  const readmeRows = groups.map((group) => {
    const links = group.rows.filter((row) => row.file).map((row) => `[${row.theme} ${row.width}](${row.file})`).join(" · ") || "—";
    const result = group.issues.length ? group.issues.join("；") : "通过";
    return `| ${cell(group.plugin)} | ${cell(`${group.title}（${group.scene}）`)} | ${cell(result)} | ${links} |`;
  });
  const readme = `# UI 捕获

[浏览画廊](index.html) · [捕获清单](${manifestName})

命令：

\`\`\`sh
${report.invocation}
\`\`\`

本次 ${report.imageCount} 张图片，${report.failureCount} 项失败。

| 插件 | 场景 | 结果 | 图片 |
| --- | --- | --- | --- |
${readmeRows.join("\n")}
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
