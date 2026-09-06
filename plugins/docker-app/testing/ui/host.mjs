import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { readFile, writeFile, mkdir, mkdtemp, rm } from "node:fs/promises";
import { resolve, join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";

const requiredScenes=["candidate","host-entry","themes","node","risk-cancel","deploy","compose","lifecycle","files","http","logs","update","rollback","delete","cleanup","final-candidate"];
const requiredShots=["list","deployment","detail","compose","files","logs","confirmation"];
const sha=(bytes)=>createHash("sha256").update(bytes).digest("hex");

export async function runHost({Page,eventually,findBrowser,repo,assets}) {
  const output=resolve(repo,"dist/docker-app-ui-validation/host");
  await mkdir(output,{recursive:true});
  const report={kind:"real-host-browser",suite:"host",started_at:new Date().toISOString(),results:[],screenshots:[],required_scenes:requiredScenes};
  let token="",browser,profile,root,page,contextId;
  const clients=[];
  const sanitize=(value)=>token ? String(value).split(token).join("[redacted]").split(encodeURIComponent(token)).join("[redacted]") : String(value);
  const persist=async()=>writeFile(resolve(output,"../host.json"),JSON.stringify(report,null,2)+"\n");
  try {
    const flag=process.argv.indexOf("--host-config");
    const configRef=process.env.NRE_UI_HOST_CONFIG || (flag>=0 ? process.argv[flag+1] : "");
    if (!configRef) throw new Error("Set NRE_UI_HOST_CONFIG to an explicit public host configuration; no host is assumed.");
    const config=JSON.parse(await readFile(resolve(configRef),"utf8"));
    for (const field of ["hostURL","agentID","packageDigest","baseImage","appPrefix","httpDomain"]) if (!config[field]) throw new Error(`Host configuration lacks ${field}`);
    if (config.disposableAgent!==true) throw new Error("Host acceptance requires an explicitly disposable Agent for deletion and cleanup.");
    if (!/^[a-z0-9-]{1,32}$/.test(config.appPrefix)) throw new Error("appPrefix must be a bounded lowercase namespace.");
    const host=new URL(config.hostURL);
    if (!Number.isInteger(config.publishedPort) || config.publishedPort<1024 || config.publishedPort>65535) throw new Error("A dedicated publishedPort is required.");
    if (config.tokenEnv) token=process.env[config.tokenEnv] || "";
    else if (config.tokenContainer?.name && config.tokenContainer?.env) {
      const result=spawnSync("docker",["inspect",config.tokenContainer.name],{encoding:"utf8",windowsHide:true});
      if (result.status!==0) throw new Error("Configured token container is unavailable.");
      const prefix=config.tokenContainer.env+"=";
      token=JSON.parse(result.stdout)[0].Config.Env.find((value)=>value.startsWith(prefix))?.slice(prefix.length) || "";
    }
    if (!token) throw new Error("No token was supplied by the explicit environment/container reference.");
    const api=async(path)=>{
      const url=new URL(path,host);
      const response=await fetch(url,{headers:{"X-Panel-Token":token},signal:AbortSignal.timeout(120000)});
      if (!response.ok) throw new Error(`Host GET ${url.pathname} failed (${response.status}).`);
      return response.json();
    };
    const routes=await api("/panel-api/plugin-ui-routes");
    const route=routes.routes?.find((item)=>item.plugin_id===(config.pluginID || "docker-app"));
    if (!route?.href) throw new Error("The configured host has no Docker app UI route.");
    const ui=new URL(route.href,host);
    if (ui.origin!==host.origin) throw new Error("Plugin UI must use the configured host origin.");
    const appURL=(suffix="")=>new URL(suffix,ui).href;
    const appID=`${config.appPrefix}-${Date.now().toString(36)}`;
    report.host={url:host.origin,ui_route:ui.pathname,agent_id:config.agentID,source_commit:config.hostSourceCommit,compatibility_patch:config.compatibilityPatch,disposable_agent:true};
    report.app_id=appID;
    report.source_commit=spawnSync("git",["rev-parse","HEAD"],{cwd:repo,encoding:"utf8",windowsHide:true}).stdout.trim();
    const fingerprint=createHash("sha256");
    for (const name of ["index.html","app.js","style.css"]) fingerprint.update(await readFile(resolve(assets,name)));
    report.assets_sha256=fingerprint.digest("hex");
    const scene=async(name,run)=>{console.log(`HOST ${name}: running`);const result=await run();report.results.push({name,status:"passed",result});await persist();console.log(`HOST ${name}: passed`);};
    const verifyCandidate=async()=>{
      const plugin=await api("/panel-api/plugins/docker-app");
      assert.equal(plugin.plugin.active_package_digest,config.packageDigest,"active package digest must match the explicit candidate");
      const agent=plugin.agent_statuses?.find((item)=>item.agent_id===config.agentID && item.current_state==="active");
      assert.equal(agent?.package_digest,config.packageDigest,"Agent must execute the same candidate");
      assert.ok(plugin.instances?.some((instance)=>instance.targets?.includes(config.agentID)),"test Agent must be explicitly targeted");
      const files=[];
      for (const name of ["index.html","app.js","style.css"]) {
        const response=await fetch(appURL(name==="index.html" ? "" : name),{headers:{"X-Panel-Token":token},cache:"no-store"});
        assert.equal(response.status,200);
        const served=Buffer.from(await response.arrayBuffer()),local=await readFile(resolve(assets,name));
        assert.equal(sha(served),sha(local),`served ${name} is not the local candidate`);files.push({name,sha256:sha(local)});
      }
      return {package_digest:config.packageDigest,version:plugin.package.version,files};
    };
    await scene("candidate",async()=>{
      const result=await verifyCandidate();report.candidate=result;
      const engine=await api(appURL(`api/engine?agent_id=${encodeURIComponent(config.agentID)}`));
      assert.equal(engine.engine?.ready,true,"test Agent Docker must be ready");
      const initial=await api(appURL(`api/apps?agent_id=${encodeURIComponent(config.agentID)}`));
      assert.equal(initial.apps?.length || 0,0,"dedicated Agent has managed apps; preserve and resolve leftovers explicitly");
      return {...result,engine_version:engine.engine.version};
    });

    const executable=await findBrowser();profile=await mkdtemp(join(tmpdir(),"nre-host-ui-"));
    browser=spawn(executable,["--headless=new","--no-first-run","--no-default-browser-check","--remote-debugging-port=0",`--user-data-dir=${profile}`,"about:blank"],{stdio:"ignore",windowsHide:true});
    browser.once("error",()=>{report.browser_start_failed=true;});
    let port,path;
    await eventually(async()=>{try{[port,path]=(await readFile(join(profile,"DevToolsActivePort"),"utf8")).trim().split("\n");return !!path;}catch{return false;}},"host browser debugger");
    const connect=async(url)=>{
      const socket=new WebSocket(url);await new Promise((done,fail)=>{socket.addEventListener("open",done,{once:true});socket.addEventListener("error",fail,{once:true});});
      const client=new Page(socket);clients.push(client);return client;
    };
    root=await connect(`ws://127.0.0.1:${port}${path}`);
    ({browserContextId:contextId}=await root.send("Target.createBrowserContext",{}));
    const newPage=async()=>{
      const target=await root.send("Target.createTarget",{url:"about:blank",browserContextId:contextId});
      const list=await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      const client=await connect(list.find((item)=>item.id===target.targetId).webSocketDebuggerUrl);client.targetId=target.targetId;
      await client.send("Runtime.enable");await client.send("Page.enable");await client.send("Network.enable");await client.send("Network.setCacheDisabled",{cacheDisabled:true});
      // Normal host authentication in a disposed incognito context. Never written to reports or a persistent browser profile.
      await client.send("Page.addScriptToEvaluateOnNewDocument",{source:`if(location.origin===${JSON.stringify(host.origin)}) localStorage.setItem('panel_token',${JSON.stringify(token)});`});
      await client.send("Network.setCookie",{name:"nre_panel_token",value:token,url:host.href,path:"/panel-api",sameSite:"Strict"});
      await client.send("Emulation.setDeviceMetricsOverride",{width:1440,height:1000,deviceScaleFactor:1,mobile:false});return client;
    };
    page=await newPage();
    const requests=[];
    page.socket.addEventListener("message",({data})=>{
      const event=JSON.parse(data);if(event.method!=="Network.requestWillBeSent") return;
      const request=event.params.request,url=new URL(request.url);
      if(url.origin===host.origin && url.pathname.startsWith(ui.pathname+"api/")) requests.push({method:request.method,path:url.pathname});
    });
    const go=async(client,url)=>{const before=client.navigations;await client.send("Page.navigate",{url});await eventually(()=>client.navigations>before,"host document committed",30000);};
    const text=(selector)=>page.evaluate(`document.querySelector(${JSON.stringify(selector)}).textContent`);
    const fill=async(selector,value)=>{await page.click(selector);await page.evaluate("document.activeElement.select()");await page.send("Input.insertText",{text:value});};
    const idle=()=>eventually(()=>page.evaluate(`!document.querySelector('.agent-search-select__trigger')?.disabled`),"host controls restored",180000);
    const outcome=async(expected)=>eventually(async()=>{
      const result=await page.evaluate(`({state:document.querySelector('#app-status').dataset.state,text:document.querySelector('#app-status').textContent,busy:document.querySelector('.agent-search-select__trigger').disabled})`);
      if(!result.busy && ["failed","partial"].includes(result.state)) throw new Error(`Host operation: ${result.text}`);
      return !result.busy && result.state==="succeeded" && result.text.includes(expected);
    },`host operation ${expected}`,180000);
    const confirm=async(yes,id="confirm")=>{
      await page.waitVisible(`#${id}-dialog`);await page.click(`#${id}-${yes ? (id==="update" ? "confirm" : "ok") : "cancel"}`);
      await eventually(async()=>!(await page.visible(`#${id}-dialog`)),"host confirmation closed");await page.evaluate("new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))");
    };
    const capture=async(category,name=category)=>{
      assert.equal(await page.evaluate(`Array.from(document.querySelectorAll('textarea[name="env"]')).every(node=>!node.value)`),true,"never capture submitted env contents");
      const theme=await page.evaluate("document.documentElement.dataset.theme");
      const viewport=await page.evaluate("({width:innerWidth,height:innerHeight,clientWidth:document.documentElement.clientWidth})");
      const shot=await page.send("Page.captureScreenshot",{format:"png",captureBeyondViewport:false});
      const ref=`dist/docker-app-ui-validation/host/${name}-${theme}-${viewport.width}.png`;
      await writeFile(resolve(repo,ref),Buffer.from(shot.data,"base64"));report.screenshots.push({category,ref,theme,viewport,package_digest:config.packageDigest,assets_sha256:report.assets_sha256,source:"real-host"});await persist();
    };
    const themePage=await newPage();await go(themePage,host.href);
    await eventually(()=>themePage.visible(".theme-trigger"),"actual host theme control",30000);
    const setTheme=async(theme)=>{
      await root.send("Target.activateTarget",{targetId:themePage.targetId});
      await themePage.click(".theme-trigger");
      const label=theme==="dark" ? "夜樱" : "晴空";
      const index=await themePage.evaluate(`Array.from(document.querySelectorAll('.theme-option__label')).findIndex(node=>node.textContent===${JSON.stringify(label)})`);
      assert.ok(index>=0,"host must expose the supported theme");
      await themePage.click(`.theme-option:nth-of-type(${index+1})`);
      await root.send("Target.activateTarget",{targetId:page.targetId});
      if(await page.evaluate("!!document.querySelector('#app-loading')")) await eventually(()=>page.evaluate(`document.documentElement.dataset.theme===${JSON.stringify(theme)}`),"real host theme synchronized");
    };
    const variants=async(category,name=category)=>{
      for(const [theme,width] of [["light",1440],["dark",1440],["dark",375]]) {
        await setTheme(theme);await page.send("Emulation.setDeviceMetricsOverride",{width,height:1000,deviceScaleFactor:1,mobile:false});
        await page.evaluate("window.scrollTo(0,0)");
        assert.ok(await page.evaluate("document.documentElement.scrollWidth<=document.documentElement.clientWidth+1"),"host viewport has no page overflow");
        await capture(category,name);
      }
    };
    await setTheme("dark");
    await scene("host-entry",async()=>{
      await go(page,new URL("/plugins/docker-app",host).href);
      await eventually(()=>page.visible('[data-test="plugin-open-manage"]'),"actual host plugin management link",30000);
      await page.click('[data-test="plugin-open-manage"]');
      await eventually(()=>page.evaluate(`!!document.querySelector('#app-loading')?.hidden`),"hosted plugin loaded",60000);
      assert.equal(new URL(await page.evaluate("location.href")).pathname,ui.pathname);
      return {mount:"standalone-hosted-page",route:ui.pathname,authentication:"normal bootstrap credentials in disposed incognito context"};
    });
    await scene("themes",async()=>{
      assert.equal(await page.evaluate("document.documentElement.dataset.theme"),"dark","initial page inherits stored actual host theme");
      await setTheme("light");await setTheme("dark");return {initial:"dark",dynamic:["business → light","sakura-night → dark"],source:"actual host ThemeSelector in same incognito context"};
    });
    await scene("node",async()=>{
      await page.click(".agent-search-select__trigger");await page.click('.agent-search-select__option:first-child');await page.waitVisible("#app-node-empty");
      await page.click(".agent-search-select__trigger");const {agents}=await api("/panel-api/agents");const agent=agents.find((item)=>item.id===config.agentID);
      const index=await page.evaluate(`Array.from(document.querySelectorAll('.agent-search-select__option')).findIndex(node=>node.querySelector('.agent-search-select__option-name')?.textContent===${JSON.stringify(agent.name || agent.hostname || agent.id)})`);
      assert.ok(index>=0,"explicit test Agent must be selectable");await page.click(`.agent-search-select__option:nth-child(${index+1})`);await page.waitVisible("#app-empty");
      await variants("list");return {agent_id:config.agentID};
    });
    const yaml=`services:\n  web:\n    image: ${config.baseImage}\n    ports:\n      - "${config.publishedPort}:80"\n`;
    await scene("risk-cancel",async()=>{
      await page.click("#deploy-toggle");await page.waitVisible("#create-form");await fill('#create-form input[name="id"]',appID);
      await fill('#create-form textarea[name="compose"]',yaml+"    privileged: true\n");
      const before=requests.filter((request)=>request.method==="POST" && request.path===ui.pathname+"api/apps").length;
      await page.click("#create-submit");await page.waitVisible("#confirm-dialog");await variants("confirmation","risk-cancel");await confirm(false);await idle();
      assert.equal(requests.filter((request)=>request.method==="POST" && request.path===ui.pathname+"api/apps").length,before);return {cancelled_without_deployment:true};
    });
    await scene("deploy",async()=>{
      await fill('#create-form textarea[name="compose"]',yaml);await variants("deployment");await page.click("#create-submit");await outcome("已部署应用");
      await page.waitVisible(`[data-id="${appID}"]`);await capture("list","deployed-list");await page.click(`[data-id="${appID}"] [data-action="detail"]`);await page.waitVisible("#app-detail");await variants("detail");
      const result=await api(appURL(`api/apps/${appID}`));return {id:result.app.id,agent_id:result.app.agent_id,status:result.app.status,version:result.app.version};
    });
    const appState=async()=> (await api(appURL(`api/apps/${appID}`))).app;
    const docker=async(args,input)=>{
      if (!config.agentContainer) throw new Error("Explicit agentContainer is required for isolated runtime inspection and cleanup preparation.");
      const result=spawnSync("docker",["exec",...(input ? ["-i"] : []),config.agentContainer,"docker",...args],{input,encoding:"utf8",windowsHide:true,timeout:120000,maxBuffer:8*1024*1024});
      if(result.status!==0) throw new Error(`Dedicated Agent Docker command failed: ${args[0]}`);
      return result.stdout;
    };
    const runtimeImage=async()=>{
      const ids=(await docker(["ps","-aq","--filter",`label=com.docker.compose.project=${appID}`,"--filter","label=com.docker.compose.service=web"])).trim().split(/\s+/).filter(Boolean);
      assert.equal(ids.length,1,"exactly the test application's web container must exist");
      const container=JSON.parse(await docker(["inspect",ids[0]]))[0];
      return {id:container.Id,image_id:container.Image,running:container.State.Running,project:container.Config.Labels["com.docker.compose.project"],service:container.Config.Labels["com.docker.compose.service"]};
    };
    await scene("compose",async()=>{
      await page.click('#detail-nav [data-section="compose"]');
      const before=await appState();
      await fill('#compose-form textarea[name="compose"]',"services: [");await page.click("#compose-submit");
      await eventually(()=>page.evaluate(`document.querySelector('#compose-feedback').dataset.state==='failed' && !document.querySelector('.agent-search-select__trigger').disabled`),"actual invalid Compose rejected",60000);
      assert.equal(await page.evaluate(`document.querySelector('#compose-form textarea[name="compose"]').value`),"services: [");
      assert.equal((await appState()).compose,before.compose,"invalid input must not change existing app");
      await capture("compose","compose-validation-failure");
      const edited=yaml+"    restart: unless-stopped\n";
      await fill('#compose-form textarea[name="compose"]',edited);await variants("compose");
      await page.click("#compose-submit");await outcome("已更新应用");
      return {invalid_input_retained:true,compose_sha256:sha((await appState()).compose)};
    });
    await scene("lifecycle",async()=>{
      const transitions=[];
      for(const [action,label,expectedStatus,expectedRunning] of [["stop","已停止应用","已停止",false],["start","已启动应用","运行中",true],["restart","已重启应用","运行中",true]]) {
        await page.click(`#detail-${action}`);await outcome(label);
        const state=await appState();assert.equal(state.status,expectedStatus,`${action} must report the expected application status`);
        const runtime=await runtimeImage();assert.equal(runtime.project,appID,`${action} must inspect the exact test project`);assert.equal(runtime.service,"web",`${action} must inspect the exact web service`);assert.equal(runtime.running,expectedRunning,`${action} must change the actual dedicated-Agent container state`);
        transitions.push({action,status:state.status,runtime});
      }
      return {transitions};
    });
    await scene("files",async()=>{
      await page.click('#detail-nav [data-section="files"]');
      await eventually(()=>page.evaluate(`["ready","empty"].includes(document.querySelector('#files-status').dataset.state)`),"actual Agent directory listed",60000);
      await page.click("#files-mkdir");await page.waitVisible("#files-mkdir-dialog");await fill("#files-mkdir-name","evidence");
      await page.click('#files-mkdir-form button[type="submit"]');await outcome("已新建目录");
      await page.click('[data-path="evidence"] .files-name');await eventually(()=>page.evaluate(`document.querySelector('#files-status').dataset.state==='empty'`),"new Agent directory is empty",30000);
      await page.click("#files-new-text");await page.waitVisible("#files-new-dialog");await fill("#files-new-name","notes.txt");
      await page.click('#files-new-form button[type="submit"]');await page.waitVisible("#files-editor");
      await fill("#files-editor textarea","Docker app UI host validation\n");await page.click("#files-save");await outcome("已保存工作区文件");await variants("files","file-editor");
      await page.click("#files-editor-close");await page.waitVisible("#files-browser");
      const downloadDir=await mkdtemp(join(output,"downloads-"));
      await root.send("Browser.setDownloadBehavior",{browserContextId:contextId,behavior:"allow",downloadPath:downloadDir});
      await page.click("#files-download");
      await eventually(async()=>{try{return await readFile(join(downloadDir,"notes.txt"),"utf8")==="Docker app UI host validation\n";}catch{return false;}},"actual Agent file downloaded",30000);
      const upload=join(output,"upload.txt");await writeFile(upload,"host upload evidence\n");
      await page.send("Page.setInterceptFileChooserDialog",{enabled:true});await page.click("#files-upload");
      const document=await page.send("DOM.getDocument",{});const input=await page.send("DOM.querySelector",{nodeId:document.root.nodeId,selector:"[data-files-input]"});
      await page.send("DOM.setFileInputFiles",{nodeId:input.nodeId,files:[upload]});await outcome("已上传工作区文件");
      await page.waitVisible('[data-path="evidence/upload.txt"]');await variants("files","file-browser");
      await page.click('[data-path="evidence/upload.txt"] .files-name');
      await page.click("#files-delete");await confirm(false);await idle();assert.ok(await page.visible('[data-path="evidence/upload.txt"]'));
      await page.click("#files-delete");await confirm(true);await outcome("已删除工作区文件");
      return {directory:"evidence",file:"evidence/notes.txt",download_verified:true,upload_and_delete_verified:true,delete_cancel_verified:true};
    });
    await scene("http",async()=>{
      await page.click('#detail-nav [data-section="http"]');await page.waitVisible(".http-form");
      await fill('.http-form input[name="domain"]',config.httpDomain);
      await page.evaluate(`document.querySelector('.http-form select[name="port"]').value=${JSON.stringify(String(config.publishedPort))}`);
      const before=requests.filter((request)=>request.method==="POST" && request.path.endsWith("/http-rule")).length;
      await page.click('.http-form button[type="submit"]');await confirm(false);await idle();
      assert.equal(requests.filter((request)=>request.method==="POST" && request.path.endsWith("/http-rule")).length,before);
      await page.click('.http-form button[type="submit"]');await confirm(true);await outcome("已创建 HTTP 规则");
      const app=await appState();const rule=app.rules.find((rule)=>Number(rule.port)===config.publishedPort);
      assert.ok(rule?.ref,"host must return the actual rule ref");
      const linkSelector=`[data-rule-ref="${rule.ref}"] a.http-rule-open`;
      const actualURL=await page.evaluate(`document.querySelector(${JSON.stringify(linkSelector)}).href`);
      assert.equal(new URL(actualURL).host,new URL(config.httpDomain).host);
      await eventually(async()=>{try{return (await fetch(actualURL,{signal:AbortSignal.timeout(3000)})).status===200;}catch{return false;}},"real HTTP ingress becomes reachable",60000);
      const oldTargets=new Set((await root.send("Target.getTargets")).targetInfos.map((item)=>item.targetId));
      await page.click(linkSelector);
      let visit;
      await eventually(async()=>{visit=(await root.send("Target.getTargets")).targetInfos.find((item)=>!oldTargets.has(item.targetId) && item.url.startsWith(config.httpDomain));return !!visit;},"actual entry opened in a browser tab");
      const targets=await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();const visitor=await connect(targets.find((item)=>item.id===visit.targetId).webSocketDebuggerUrl);
      await eventually(()=>visitor.evaluate(`document.readyState!=='loading' && !!document.body?.innerText.includes('Welcome to nginx')`),"real nginx response rendered",30000);
      await root.send("Target.closeTarget",{targetId:visit.targetId});await root.send("Target.activateTarget",{targetId:page.targetId});
      await variants("http","http-entry");return {rule_ref:rule.ref,published_port:config.publishedPort,visit_url:actualURL,actual_browser_response:"Welcome to nginx",cancel_verified:true};
    });
    await scene("logs",async()=>{
      await page.click('#detail-nav [data-section="logs"]');
      await eventually(()=>page.evaluate(`document.querySelector('#logs-view').textContent.length>0 && document.querySelector('#logs-status').dataset.error==='false'`),"actual service log snapshot",60000);
      await page.click("#logs-pause");const count=requests.filter((request)=>request.path.endsWith("/logs")).length;
      await delay(4300);assert.equal(requests.filter((request)=>request.path.endsWith("/logs")).length,count,"paused host logs issue no new poll");
      await variants("logs");await page.click("#logs-pause");
      await eventually(()=>requests.filter((request)=>request.path.endsWith("/logs")).length>count,"host log polling resumes",10000);
      return {service:await page.evaluate("document.querySelector('#logs-service').value"),snapshot_nonempty:true,pause_verified:true,resume_verified:true};
    });
    let originalRuntime;
    await scene("update",async()=>{
      if(!config.updateTag) throw new Error("An explicit pre-pulled updateTag is required.");
      await page.click('#detail-nav [data-section="overview"]');
      await eventually(async()=>{
        if(await page.evaluate(`document.querySelector('.service-candidates')?.textContent.includes(${JSON.stringify(config.updateTag)})`)) return true;
        if(await page.evaluate(`!document.querySelector('.agent-search-select__trigger').disabled`)) await page.click("#workspace-refresh");
        await delay(1000);return false;
      },"real registry candidate available",180000);
      originalRuntime=await runtimeImage();assert.equal(originalRuntime.running,true);
      const selectTarget=async()=>{
        await page.click('#detail-overview [data-action="update"]');await page.waitVisible("#update-dialog");
        assert.equal(await page.evaluate(`!!document.querySelector('select[name="target-web"] option[value="${config.updateTag}"]')`),true,"the target must be offered by the real backend");
        await page.evaluate(`(() => {const selector=document.querySelector('select[name="target-web"]');selector.value=${JSON.stringify(config.updateTag)};selector.dispatchEvent(new Event('change',{bubbles:true}));})()`);
      };
      const before=requests.filter((request)=>request.method==="POST" && request.path.endsWith("/update")).length;
      await selectTarget();await variants("confirmation","update-confirm");await confirm(false,"update");await idle();
      assert.equal(requests.filter((request)=>request.method==="POST" && request.path.endsWith("/update")).length,before);
      await selectTarget();await confirm(true,"update");await outcome("已更新所选服务");
      const after=await runtimeImage();assert.equal(after.running,true);assert.notEqual(after.image_id,originalRuntime.image_id,"update changes the actual running image");
      assert.equal(requests.filter((request)=>request.method==="POST" && request.path.endsWith("/update")).length,before+1);
      return {selected_service:"web",selected_tag:config.updateTag,before:originalRuntime,after,cancel_verified:true};
    });
    await scene("rollback",async()=>{
      const registry=config.floatingRegistry;
      if(!registry?.image || !registry.beforeManifest || !registry.afterManifest || !registry.manifestURL || !registry.mediaType) throw new Error("A real controllable same-tag registry is required for digest-update rollback; tag changes intentionally clear history.");
      const manifestURL=new URL(registry.manifestURL);
      assert.ok(registry.image.startsWith(manifestURL.host+"/") && !manifestURL.username && !manifestURL.password,"registry preparation is confined to the explicit image repository");
      const publish=async(manifest)=>{
        const result=spawnSync("docker",["exec",config.agentContainer,"curl","--fail","--silent","--show-error","-X","PUT","-H","Content-Type: "+registry.mediaType,"--data-binary","@"+manifest,registry.manifestURL],{encoding:"utf8",windowsHide:true,timeout:60000});
        if(result.status!==0) throw new Error("Explicit test registry manifest preparation failed.");
      };
      assert.equal(/^\d+(?:\.\d+){0,2}$/.test(registry.image.split(":").at(-1)),false,"digest rollback requires a non-semver floating tag");
      // Real registry test setup: cache A locally, then publish B before the UI
      // deployment. Compose reuses the explicit local A tag, while the first
      // post-deployment observation sees B remotely without waiting for the
      // five-minute observation cache to expire.
      await publish(registry.beforeManifest);await docker(["pull",registry.image]);
      await publish(registry.afterManifest);
      await page.click('#detail-nav [data-section="compose"]');
      const floating=`services:\n  web:\n    image: ${registry.image}\n    ports:\n      - "${config.publishedPort}:80"\n`;
      await fill('#compose-form textarea[name="compose"]',floating);await page.click("#compose-submit");await outcome("已更新应用");
      const beforeDigestUpdate=await runtimeImage();
      assert.equal(await page.visible('#detail-overview [data-action="rollback"]'),false,"Compose save clears rollback history according to the backend contract");
      await page.click('#detail-nav [data-section="overview"]');
      await eventually(async()=>{
        const app=await appState();
        if(app.service_images?.some((service)=>service.name==="web" && service.candidates?.some((candidate)=>candidate.digest))) {
          await page.click("#workspace-refresh");return true;
        }
        await page.click("#workspace-refresh");await delay(1000);return false;
      },"real floating tag digest change detected",180000);
      await page.waitVisible('#detail-overview [data-action="update"]');
      await page.click('#detail-overview [data-action="update"]');await page.waitVisible("#update-dialog");
      assert.equal(await page.evaluate(`!!document.querySelector('select[name="target-web"] option[data-digest="true"]')`),true,"UI offers the real same-tag digest update");
      await capture("confirmation","digest-update-confirm");await confirm(true,"update");await outcome("已更新所选服务");
      const digestUpdated=await runtimeImage();assert.notEqual(digestUpdated.image_id,beforeDigestUpdate.image_id,"same-tag digest update actually replaces A with B");
      await page.waitVisible('#detail-overview [data-action="rollback"]');
      await page.click('#detail-overview [data-action="rollback"]');await page.waitVisible("#confirm-dialog");
      assert.match(await text("#confirm-body"),/上一部署版本/);await capture("confirmation","rollback-confirm");
      await confirm(false);await idle();
      await page.click('#detail-overview [data-action="rollback"]');await confirm(true);await outcome("已回滚应用");
      const restored=await runtimeImage();assert.equal(restored.running,true);assert.equal(restored.image_id,beforeDigestUpdate.image_id,"rollback restores the actual prior image");
      return {registry:registry.image,before_digest:registry.beforeDigest,after_digest:registry.afterDigest,before:beforeDigestUpdate,updated:digestUpdated,restored,cancel_verified:true,preparation:"real TLS registry manifest A/B publication; actual UI deployment, digest update and rollback"};
    });
    await scene("delete",async()=>{
      const before=requests.filter((request)=>request.method==="POST" && request.path.endsWith("/delete")).length;
      await page.click('#detail-overview [data-action="delete"]');await variants("confirmation","delete-confirm");await confirm(false);await idle();
      assert.equal(requests.filter((request)=>request.method==="POST" && request.path.endsWith("/delete")).length,before);
      await page.click('#detail-overview [data-action="delete"]');await confirm(true);await outcome("已删除应用");
      const listed=await api(appURL(`api/apps?agent_id=${encodeURIComponent(config.agentID)}`));
      assert.equal(listed.apps?.length || 0,0);
      assert.equal((await docker(["ps","-aq","--filter",`label=com.docker.compose.project=${appID}`])).trim(),"","test containers are removed");
      return {app_removed:true,containers_removed:true,associated_rules_handled_by_plugin:true,cancel_verified:true};
    });
    await scene("cleanup",async()=>{
      // Test setup only, on the explicitly disposable Agent. It is not counted as UI success.
      const prepared=await docker(["build","--label",`nre.ui.validation=${appID}`,"--label","purpose=disposable-cleanup-acceptance","-"],"FROM scratch\nLABEL fixture=host-cleanup\n");
      const images=(await docker(["images","-q","--filter","dangling=true","--filter",`label=nre.ui.validation=${appID}`])).trim().split(/\s+/).filter(Boolean);
      assert.ok(images.length>0,"a dedicated dangling image must exist for the nonempty cleanup scenario");
      report.preparation={kind:"disposable-test-setup",dangling_images:images,build_completed:!!prepared || images.length>0};
      const before=requests.filter((request)=>request.method==="POST" && request.path.endsWith("/disk-cleanup")).length;
      await page.click("#disk-cleanup");await page.waitVisible("#confirm-dialog");
      assert.ok(await page.visible("#confirm-ok"),"cleanup preview must be nonempty for prepared image");
      await variants("confirmation","cleanup-confirm");await confirm(false);await idle();
      assert.equal(requests.filter((request)=>request.method==="POST" && request.path.endsWith("/disk-cleanup")).length,before);
      await page.click("#disk-cleanup");await confirm(true);await outcome("总体状态");
      assert.equal((await docker(["images","-q","--filter","dangling=true","--filter",`label=nre.ui.validation=${appID}`])).trim(),"","UI cleanup removes the prepared dangling image");
      const message=await text("#app-status");assert.match(message,/镜像：完成/);assert.match(message,/构建缓存：完成/);
      return {cancel_verified:true,prepared_images_removed:true,steps:["images completed","builder cache completed"]};
    });
    await scene("final-candidate",verifyCandidate);
    assert.deepEqual(page.errors,[],"hosted plugin produced no uncaught browser exceptions");
    const missing=requiredScenes.filter((name)=>!report.results.some((result)=>result.name===name && result.status==="passed"));
    const missingShots=requiredShots.filter((category)=>!report.screenshots.some((shot)=>shot.category===category));
    if(missing.length || missingShots.length) throw new Error(`Host acceptance incomplete: scenes=${missing.join(",")}; screenshots=${missingShots.join(",")}. Test app ${appID} retained for continuation.`);
    for(const category of requiredShots) for(const [theme,width] of [["light",1440],["dark",1440],["dark",375]]) {
      assert.ok(report.screenshots.some((shot)=>shot.category===category && shot.theme===theme && shot.viewport.width===width),`missing actual ${category}/${theme}/${width} screenshot`);
    }
    report.status="passed";
  } catch(error) {report.status="failed";report.error=sanitize(error.message);process.exitCode=1;console.error(report.error);}
  finally {
    report.finished_at=new Date().toISOString();await persist();
    if(root && contextId) {try{await root.send("Target.disposeBrowserContext",{browserContextId:contextId});}catch{}}
    if(root) {try{await root.send("Browser.close");}catch{}}
    for(const client of clients) client.socket.close();if(browser && browser.exitCode===null) browser.kill();
    if(profile?.startsWith(join(tmpdir(),"nre-host-ui-"))) await rm(profile,{recursive:true,force:true,maxRetries:8,retryDelay:200}).catch(()=>{});
    token="";
  }
}
