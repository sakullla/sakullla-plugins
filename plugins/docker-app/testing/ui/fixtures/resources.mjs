import { makeApp } from "./workspace.mjs";

export function createResourcesState() {
  const state = { reset() {
    Object.assign(this, {
      files:new Map([[".",null],["docs",null],["docs/config.txt","initial text\n"],["root.txt","root text\n"],["binary.bin","\u0000binary"],["large.txt","x".repeat(1048577)]]),
      calls:[], logsCalls:[], readError:false, writeError:false, listError:false, listErrorOwner:"", listErrorAfterMkdir:false, rulesError:false, rulesWriteError:false, rulesErrorAfterWrite:false,
      logs:{web:"web ready\n",worker:"worker ready\n"}, logsError:false,
      apps:[
        makeApp("alpha","node-a",{ports:[8080,9090],services:["web","worker"],rules:[
          {ref:"web-entry",domain:"http://web.example.test/media",port:8080,enabled:true},
          {ref:"api-entry",domain:"https://api.example.test",port:9090,enabled:true},
          {ref:"disabled-entry",domain:"disabled.example.test",port:9090,enabled:false},
        ]}),
        makeApp("no-ports","node-a",{ports:[],services:[],compose:"services:\n  web:\n    image: nginx\n",rules:[]}),
        makeApp("bravo","node-b"),
      ],
    });
    this.filesByOwner = new Map([
      ["node-a/alpha",this.files],
      ["node-b/bravo",new Map([[".",null],["root.txt","bravo original\n"]])],
      ["node-a/no-ports",new Map([[".",null],["root.txt","other application original\n"]])],
    ]);
  }};
  state.reset(); return state;
}

export async function handleResourcesRequest({url,request,json,state,record}) {
  const project = (app) => state.rulesError ? {...app,rules:[],rules_error:"HTTP 规则列表读取失败，请重试。"} : app;
  if (url.pathname === "/api/apps" && request.method === "GET") {
    json({apps:state.apps.filter((app) => app.agent_id === url.searchParams.get("agent_id")).map(project), ...(state.rulesError ? {error:"HTTP 规则列表读取失败，请重试。"} : {})});
    return true;
  }
  if (!url.pathname.startsWith("/api/apps/")) return false;
  const [, , , id, action] = url.pathname.split("/");
  const app = state.apps.find((app) => app.id === decodeURIComponent(id));
  if (!app) { json({error:"应用已不存在。"},404); return true; }
  if (request.method === "GET" && !action) { json({app:project(app)}); return true; }
  if (request.method !== "POST") return false;
  let raw = ""; for await (const chunk of request) raw += chunk;
  const body = raw ? JSON.parse(raw) : {};
  record.action = body.action || action;
  state.calls.push({id,action,body});
  if (action === "logs") {
    state.logsCalls.push({service:body.service,at:Date.now()});
    if (state.logsError) json({error:"日志读取失败，请重试。"},500);
    else json({logs:state.logs[body.service] || ""});
    return true;
  }
  if (action === "files") {
    const owner = `${app.agent_id}/${app.id}`;
    const files = state.filesByOwner.get(owner);
    const path = body.path;
    if (!path || path.startsWith("/") || path.includes("..") || path.includes(":")) { json({error:"只能使用应用工作区内的相对路径"},400); return true; }
    if (body.action === "list") {
      if (state.listError || state.listErrorOwner === owner) { json({error:"目录读取失败。"},500); return true; }
      const prefix = path === "." ? "" : path + "/";
      const entries = [...files.entries()].filter(([name]) => name !== path && name.startsWith(prefix) && !name.slice(prefix.length).includes("/"))
        .map(([name,content]) => ({name:name.slice(prefix.length),path:name,dir:content === null,size:content?.length}));
      json({path,entries}); return true;
    }
    if (body.action === "read") {
      if (state.readError) json({error:"文件读取失败。"},500);
      else if (!files.has(path)) json({error:"文件不存在。"},404);
      else json({content:files.get(path)});
      return true;
    }
    if (state.writeError) { json({error:"文件写入失败。"},500); return true; }
    if (body.action === "mkdir") { files.set(path,null); if (state.listErrorAfterMkdir) state.listError = true; }
    else if (body.action === "write") files.set(path,body.content);
    else if (body.action === "delete") {
      for (const name of [...files.keys()]) if (name === path || name.startsWith(path+"/")) files.delete(name);
    } else { json({error:"Unknown fixture file operation"},400); return true; }
    json({accepted:true}); return true;
  }
  if (action === "http-rule" || action === "http-rule-delete") {
    if (state.rulesWriteError) { json({error:action === "http-rule" ? "入口创建失败。" : "入口删除失败。"},500); return true; }
    if (action === "http-rule") app.rules.push({ref:"created-entry",domain:body.domain,port:body.port,enabled:true});
    else app.rules = app.rules.filter((rule) => rule.ref !== body.rule_ref);
    if (state.rulesErrorAfterWrite) state.rulesError = true;
    json({apps:state.apps.map(project)}); return true;
  }
  json({error:"Unexpected resource fixture action"},400); return true;
}
