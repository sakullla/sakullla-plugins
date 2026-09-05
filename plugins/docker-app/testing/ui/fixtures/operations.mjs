import { makeApp } from "./workspace.mjs";

const services = () => [
  { name:"web", image:"nginx:1.27", tag:"1.27", update:true, default_tag:"1.28", candidates:[{tag:"1.28"},{tag:"2.0",major:true}], lock:"", lock_options:[{id:"minor",label:"1.x",constraint:"^1.27"}], ignored:["1.26"] },
  { name:"db", image:"postgres:16", tag:"16", update:true, default_tag:"17", candidates:[{tag:"17",major:true}], lock:"", lock_options:[{id:"current",label:"16.x",constraint:"^16.0"}], ignored:[] },
];
const actions = (history = true) => [
  {id:"stop",label:"停止"},{id:"restart",label:"重启"},{id:"update",label:"更新"},
  ...(history ? [{id:"rollback",label:"回滚"}] : []),{id:"delete",label:"删除"},
];
const seedApps = () => [
  makeApp("alpha", "node-a", {services:["web","db"], service_images:services(), actions:actions(), rules:[{ref:"entry-alpha",domain:"alpha.example.test",port:8080,enabled:true}]}),
  makeApp("single", "node-a", {service_images:[services()[0]], actions:actions(false)}),
  makeApp("steady", "node-a", {service_images:[{...services()[0], candidates:[], default_tag:"", update:false, lock:"^1.27"}], actions:[{id:"stop",label:"停止"},{id:"delete",label:"删除"}]}),
];

export const createOperationsState = () => {
  const state = { reset() {
    Object.assign(this, {
      apps:seedApps(), calls:[], applied:[], listError:false, actionError:"", deleteMode:"", riskDigests:[], previewError:false,
      cleanupPreview:{preview:true,empty:false,status:"success",images:"闲置镜像 120 MB",builder_cache:"构建缓存 80 MB"},
      cleanupResult:{accepted:true,status:"success",images_status:"success",builder_cache_status:"success",images:"已释放 120 MB",builder_cache:"已释放 80 MB"},
    });
  }};
  state.reset();
  return state;
};

export async function handleOperationsRequest({url,request,json,state,record}) {
  if (url.pathname === "/api/apps" && request.method === "GET") {
    if (state.listError === "partial") json({apps:state.apps,error:"入口信息读取失败，应用数据已保留。"});
    else if (state.listError) json({error:"列表刷新失败。"},500);
    else json({apps:state.apps.filter((app) => app.agent_id === url.searchParams.get("agent_id"))});
    return true;
  }
  if (url.pathname === "/api/disk-cleanup" && request.method === "GET") {
    if (state.previewError) json({error:"无法读取磁盘占用。"},500);
    else json({cleanup:state.cleanupPreview});
    return true;
  }
  if (/^\/api\/apps\/[^/]+$/.test(url.pathname) && request.method === "GET") {
    const app = state.apps.find((app) => app.id === decodeURIComponent(url.pathname.split("/")[3]));
    json(app ? {app} : {error:"应用已不存在。"},app ? 200 : 404);
    return true;
  }
  if (request.method !== "POST" || !url.pathname.startsWith("/api/")) return false;
  let raw = "";
  for await (const chunk of request) raw += chunk;
  const body = raw ? JSON.parse(raw) : {};
  if (url.pathname === "/api/disk-cleanup") {
    state.calls.push({id:"node-a",action:"disk-cleanup",body});
    json(state.cleanupResult === null ? {accepted:true} : {cleanup:state.cleanupResult});
    return true;
  }
  const [, , , encoded, action] = url.pathname.split("/");
  const id = decodeURIComponent(encoded || "");
  const app = state.apps.find((app) => app.id === id);
  record.action = action;
  state.calls.push({id,action,body});
  if (!app) { json({error:"应用已不存在。"},404); return true; }
  if (state.actionError) { json({error:state.actionError},500); return true; }
  if (action === "update") {
    if (state.riskDigests.length) {
      if (body.confirm === state.riskDigests[0]) state.riskDigests.shift();
      if (state.riskDigests.length) {
        const digest = state.riskDigests[0];
        json({error:"请确认当前风险摘要。",preview:{digest,items:[{kind:"host-mount",target:`fixture-${digest}`}] }},409);
        return true;
      }
    }
    for (const selected of body.services || []) {
      const service = app.service_images.find((service) => service.name === selected.name);
      service.tag = selected.tag;
      service.image = `${service.image.split(":")[0]}:${selected.tag}`;
      service.update = false;
    }
    for (const [name, lock] of Object.entries(body.locks || {})) app.service_images.find((service) => service.name === name).lock = lock;
    for (const ignored of body.ignore || []) {
      const service = app.service_images.find((service) => service.name === ignored.service);
      service.ignored = ignored.clear ? service.ignored.filter((tag) => tag !== ignored.tag) : [...new Set([...service.ignored,ignored.tag])];
    }
    if (body.services?.length && !app.actions.some((action) => action.id === "rollback")) app.actions.push({id:"rollback",label:"回滚"});
    app.version = app.service_images[0].image;
  } else if (action === "rollback") {
    if (!app.actions.some((item) => item.id === "rollback")) { json({error:"没有可回滚的部署记录。"},409); return true; }
    app.version = "nginx:1.26";
    app.service_images[0].image = app.version;
  } else if (action === "delete") {
    if (state.deleteMode === "rules-failed") { json({error:"HTTP 规则删除失败，请检查规则是否仍存在和目标 Agent 状态"},500); return true; }
    app.rules = [];
    if (state.deleteMode === "after-rules") { json({error:"入口规则已按宿主结果删除，但应用仍在。请刷新后重试删除应用"},500); return true; }
    if (state.deleteMode === "app-failed") { json({error:"删除应用失败，请检查目标 Agent 的 Docker 状态和 Compose 工作目录"},500); return true; }
    state.apps = state.apps.filter((item) => item !== app);
  } else if (["start","stop","restart"].includes(action)) {
    app.status = action === "stop" ? "已停止" : "运行中";
    app.actions = app.actions.filter((item) => !["start","stop"].includes(item.id));
    app.actions.unshift({id:action === "stop" ? "start" : "stop",label:action === "stop" ? "启动" : "停止"});
  } else { json({error:"Unexpected fixture action"},400); return true; }
  state.applied.push({id,action,body});
  json({apps:state.apps});
  return true;
}
