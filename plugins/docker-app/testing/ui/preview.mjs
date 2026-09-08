import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve, extname } from "node:path";
import { createOperationsState, handleOperationsRequest } from "./fixtures/operations.mjs";
import { createResourcesState, handleResourcesRequest } from "./fixtures/resources.mjs";
import { agents, makeApp, engineFor } from "./fixtures/workspace.mjs";

// This server has no Docker, SSH or production API connections. State is in memory.
const assets = new URL("../../assets/ui/", import.meta.url);
const operations = createOperationsState();
const resources = createResourcesState();
const port = Number(process.argv[process.argv.indexOf("--port") + 1]) || 4173;
const live2dRoot = resolve(fileURLToPath(new URL("../../../../dist/docker-app-live2d-preview/",import.meta.url)));

function reset() {
  operations.reset(); resources.reset();
  const first = operations.apps[0];
  first.id = first.name = "miaospeed";
  first.ports = [8765]; first.services = ["frpc", "miaospeed"]; first.rules = [];
  first.service_images = [
    {name:"frpc",image:"fatedier/frpc:v0.71.0",tag:"v0.71.0",candidates:[],ignored:[],lock_options:[{id:"minor",label:"次版本",constraint:"^0.71.0"}]},
    {name:"miaospeed",image:"airportr/miaospeed:latest",tag:"latest",update:true,default_tag:"latest",candidates:[{tag:"latest",digest:true}],ignored:[]},
  ];
  first.compose = 'services:\n  frpc:\n    image: fatedier/frpc:v0.71.0\n    restart: unless-stopped\n  miaospeed:\n    image: airportr/miaospeed:latest\n    ports:\n      - "8765:8765"\n    restart: unless-stopped\n';
  first.version = "airportr/miaospeed:latest"; first.notice = "有新版本";
  operations.apps[1].id = operations.apps[1].name = "sakura-web";
  operations.apps[1].rules = [{ref:"web",domain:"sakura.example.test",port:8080,enabled:true}];
  operations.apps[2].id = operations.apps[2].name = "redis-cache";
  operations.apps[2].status = "已停止"; operations.apps[2].ports = [6379];
  operations.apps[2].service_images = [{name:"redis",image:"redis:7.4-alpine",tag:"7.4-alpine",candidates:[],ignored:[]}];
  operations.apps[2].services = ["redis"];
  operations.apps[2].actions = [{id:"start",label:"启动"},{id:"delete",label:"删除"}];
  operations.apps.push(makeApp("media-library","node-b"));
  for (const app of operations.apps) {
    resources.filesByOwner.set(`${app.agent_id}/${app.id}`, new Map([[".",null],["compose.yaml",app.compose],["config",null],["config/settings.txt","# Local preview configuration\n"]]));
  }
  resources.logs = {web:"[preview] nginx is ready\n[preview] GET / 200\n",frpc:"[preview] connection established\n",miaospeed:"[preview] service listening on :8765\n",redis:"[preview] cache ready\n"};
}
reset();

const previewControls = `<details id="local-preview-tools" style="position:fixed;left:12px;bottom:12px;z-index:100;background:var(--color-bg-surface);color:var(--color-text-secondary);border:1px solid var(--color-border-default);border-radius:12px;padding:7px 10px;font:12px system-ui;white-space:nowrap;width:max-content;max-width:calc(100vw - 24px);box-shadow:0 4px 20px #23133712"><summary style="cursor:pointer;min-height:28px;line-height:28px">预览工具</summary><div style="display:flex;align-items:center;gap:8px;padding-top:8px">
  <span style="white-space:nowrap">模拟预览</span><select aria-label="预览主题" id="preview-theme" style="font:inherit;min-height:28px;padding:4px;width:76px;flex:0 0 76px"><option value="light">浅色</option><option value="dark">夜空</option></select><button type="button" id="preview-reset" style="font:inherit;min-height:28px;padding:4px 8px;width:auto;white-space:nowrap">重置</button>
</div></details><style>@media(max-width:520px){body:has(#local-preview-tools[open]) #companion-assistant{visibility:hidden}}</style><script>
const themePicker = document.querySelector('#preview-theme');
themePicker.value = localStorage.getItem('theme') === 'sakura-night' ? 'dark' : 'light';
themePicker.addEventListener('change', () => {localStorage.setItem('theme', themePicker.value === 'dark' ? 'sakura-night' : 'business'); document.documentElement.dataset.theme = themePicker.value;});
document.querySelector('#preview-reset').addEventListener('click', async () => {await fetch('/__preview/reset',{method:'POST'}); location.reload();});
</script>`;

const server = createServer(async (request, response) => {
  const json = (value, status = 200) => { response.writeHead(status, {"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store"}); response.end(JSON.stringify(value)); };
  try {
    const url = new URL(request.url, `http://127.0.0.1:${port}`);
    if (url.pathname === "/__preview/live2d-runner.js") {
      response.writeHead(200,{"Content-Type":"text/javascript; charset=utf-8","Cache-Control":"no-store"});
      return response.end(await readFile(new URL("live2d-preview.js",import.meta.url)));
    }
    if (url.pathname === "/__preview/portrait-runner.js") {
      response.writeHead(200,{"Content-Type":"text/javascript; charset=utf-8","Cache-Control":"no-store"});
      return response.end(await readFile(new URL("portrait-preview.js",import.meta.url)));
    }
    if (url.pathname.startsWith("/__preview/live2d/")) {
      const relative=decodeURIComponent(url.pathname.slice("/__preview/live2d/".length));
      if (!/^[a-zA-Z0-9_][a-zA-Z0-9_./-]*$/.test(relative) || relative.split("/").includes("..")) return json({error:"Not found"},404);
      const content=await readFile(resolve(live2dRoot,relative));
      const type={".js":"text/javascript",".json":"application/json",".png":"image/png",".webp":"image/webp"}[extname(relative)]||"application/octet-stream";
      response.writeHead(200,{"Content-Type":type,"Cache-Control":"no-store"});return response.end(content);
    }
    if (url.pathname === "/__preview/reset" && request.method === "POST") {reset(); return json({accepted:true});}
    if (url.pathname === "/panel-api/agents") return json({agents:agents.map((a,i) => ({...a,name:i===0?"debian-jnp12（预览）":a.name}))});
    if (url.pathname === "/panel-api/plugins/docker-app") return json({instances:[{targets:agents.map(a=>a.id)}]});
    if (url.pathname === "/api/engine") return json({engine:engineFor(url.searchParams.get("agent_id"))});
    if (["/api/apps", "/api/apps/preview"].includes(url.pathname) && request.method === "POST") {
      let wire = ""; for await (const chunk of request) wire += chunk;
      const body = JSON.parse(wire || "{}");
      if (!body.compose?.includes("services:")) return json({error:"请填写包含 services 的 Compose 配置。"},422);
      if (url.pathname.endsWith("preview")) return json({preview:{digest:"local-preview",items:[]}});
      const existing = operations.apps.find(a=>a.id===body.id);
      const app = makeApp(body.id,body.agent_id,{...existing,compose:body.compose,env:body.env || existing?.env || "",auto_update:body.auto_update});
      operations.apps = [...operations.apps.filter(a=>a.id!==body.id),app];
      resources.filesByOwner.set(`${app.agent_id}/${app.id}`,new Map([[".",null],["compose.yaml",app.compose]]));
      return json({apps:operations.apps});
    }
    resources.apps = operations.apps;
    const record = {};
    if (/\/(files|logs|http-rule|http-rule-delete)$/.test(url.pathname) && await handleResourcesRequest({url,request,json,state:resources,record})) return;
    if (await handleOperationsRequest({url,request,json,state:operations,record})) {
      for (const app of operations.apps) {
        if (app.service_images?.length && !app.service_images.some(s=>s.update)) {
          app.notice = ""; app.actions = app.actions.filter(a=>a.id!=="update");
          for (const service of app.service_images) {service.candidates=[]; service.default_tag="";}
        }
      }
      return;
    }
    const name = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
    if (!["index.html","app.js","style.css"].includes(name) || request.method !== "GET") return json({error:"Not found"},404);
    let content = await readFile(new URL(name, assets),"utf8");
    if (name === "index.html") {
      const renderer=url.searchParams.get("companion")==="live2d" ? "live2d" : "portrait";
      content = content.replace("</body>", previewControls+`<script src="/__preview/${renderer}-runner.js" defer></script></body>`);
    }
    response.writeHead(200,{"Content-Type":name.endsWith("js")?"text/javascript; charset=utf-8":name.endsWith("css")?"text/css; charset=utf-8":"text/html; charset=utf-8","Cache-Control":"no-store"}); response.end(content);
  } catch (error) {json({error:String(error.message)},500);}
});
server.listen(port,"127.0.0.1",()=>console.log(`Docker app preview: http://127.0.0.1:${port}/?agent_id=node-a\nAssets: ${fileURLToPath(assets)}\nMock data only. Ctrl+C to stop.`));
