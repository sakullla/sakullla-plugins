import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile,writeFile,mkdir,mkdtemp,rm } from "node:fs/promises";
import { join,resolve } from "node:path";
import { tmpdir } from "node:os";
import { setTimeout as delay } from "node:timers/promises";

export async function runCompanion({Page,eventually,findBrowser,repo}) {
  const profile=await mkdtemp(join(tmpdir(),"nre-companion-browser-"));
  const output=resolve(repo,"dist/docker-app-ui-validation/companion");
  await mkdir(output,{recursive:true});
  const browser=spawn(await findBrowser(),["--headless=new","--no-first-run","--no-default-browser-check","--enable-unsafe-swiftshader","--remote-debugging-port=0",`--user-data-dir=${profile}`,"about:blank"],{stdio:"ignore",windowsHide:true});
  let page;
  try {
    let port;
    await eventually(async()=>{try{port=(await readFile(join(profile,"DevToolsActivePort"),"utf8")).split("\n")[0];return !!port;}catch{return false;}},"companion browser");
    const tabs=await(await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    const socket=new WebSocket(tabs.find(t=>t.type==="page").webSocketDebuggerUrl);
    await new Promise((resolve,reject)=>{socket.addEventListener("open",resolve,{once:true});socket.addEventListener("error",reject,{once:true});});
    page=new Page(socket);
    await page.send("Runtime.enable");await page.send("Page.enable");
    await page.send("Emulation.setDeviceMetricsOverride",{width:1440,height:1000,deviceScaleFactor:1,mobile:false});
    await page.send("Page.navigate",{url:"http://127.0.0.1:4173/?agent_id=node-a&companion=live2d"});
    await eventually(()=>page.evaluate(`document.querySelector('#companion-assistant')?.dataset.renderer === 'live2d'`),"Live2D model renders",60000);
    await delay(600);
    const capture=async name=>{const shot=await page.send("Page.captureScreenshot",{format:"png"});await writeFile(join(output,`${name}.png`),Buffer.from(shot.data,"base64"));return shot.data;};
    const first=await capture("desktop-idle-1");await delay(900);const second=await capture("desktop-idle-2");
    assert.notEqual(first,second,"model changes between idle frames");
    console.log("PASS Live2D renders and idle frames change");
    await page.click("#companion-toggle");
    await eventually(()=>page.evaluate(`!!document.querySelector('#companion-assistant').dataset.lastInteraction`),"tap starts a model motion");
    assert.equal(await page.visible("#companion-panel"),false);
    console.log("PASS character tap plays motion without opening settings");
    await page.click("#companion-tools");await page.waitVisible("#companion-panel");
    await page.click("#companion-pause");
    assert.equal(await page.evaluate(`document.querySelector('#companion-assistant').dataset.motion`),"paused");
    await page.key("Escape");
    assert.equal(await page.visible("#companion-panel"),false);
    await delay(200);const paused=await capture("desktop-paused");await delay(900);
    assert.equal(paused,await capture("desktop-paused-2"),"paused model stays still");
    console.log("PASS settings pause actual rendering and Escape closes settings");
    for(const width of [320,375,430]) {
      await page.send("Emulation.setDeviceMetricsOverride",{width,height:900,deviceScaleFactor:1,mobile:false});
      await delay(200);
      await page.click("#companion-toggle");
      const bounds=await page.evaluate(`(() => {const a=document.querySelector('#companion-toggle').getBoundingClientRect(),p=document.querySelector('#local-preview-tools').getBoundingClientRect();return {overlap:a.left<p.right&&a.right>p.left&&a.top<p.bottom&&a.bottom>p.top,left:a.left,right:a.right,bottom:a.bottom,width:innerWidth,height:innerHeight,overflow:document.documentElement.scrollWidth>document.documentElement.clientWidth};})()`);
      assert.equal(bounds.overlap,false,`preview controls do not cover model at ${width}: ${JSON.stringify(bounds)}`);
      assert.ok(bounds.left>=0&&bounds.right<=bounds.width&&bounds.bottom<=bounds.height);
      assert.equal(bounds.overflow,false);
      await capture(`mobile-${width}`);
    }
    await page.click("#companion-tools");await page.click("#companion-minimize");
    assert.equal(await page.evaluate(`document.querySelector('#companion-assistant').dataset.minimized`),"true");
    await page.click("#companion-toggle");assert.equal(await page.evaluate(`document.querySelector('#companion-assistant').dataset.minimized`),"false");
    console.log("PASS mobile placement, no overlap, minimize and restore");
    await page.send("Emulation.setDeviceMetricsOverride",{width:1440,height:1000,deviceScaleFactor:1,mobile:false});
    await page.send("Page.navigate",{url:"http://127.0.0.1:4173/?agent_id=node-a"});
    await eventually(()=>page.evaluate(`document.querySelector('#companion-assistant')?.dataset.renderer==='portrait'`),"reference portrait loaded");
    assert.ok(await page.evaluate(`document.querySelector('.companion-portrait').naturalWidth >= 900`),"portrait retains high resolution source pixels");
    await eventually(()=>page.evaluate(`Number(document.querySelector('#companion-assistant').dataset.expressionFrames)>=3`),"matching expression frames preloaded");
    await eventually(()=>page.evaluate(`Number(document.querySelector('#companion-assistant').dataset.blinkCount)>0`),"automatic portrait blink",8000);
    await page.click("#companion-toggle");
    assert.equal(await page.evaluate(`document.querySelector('#companion-assistant').dataset.expression`),"wink");
    await eventually(()=>page.evaluate(`document.querySelector('#companion-assistant').dataset.expression==='idle'`),"tap expression returns to idle");
    console.log("PASS generated portrait blinks automatically and responds with a matching wink");
    await page.send("Network.enable");
    await page.send("Network.setCacheDisabled",{cacheDisabled:true});
    await page.send("Network.clearBrowserCache");
    await page.send("Network.emulateNetworkConditions",{offline:true,latency:0,downloadThroughput:0,uploadThroughput:0});
    try {
      await page.click("#companion-toggle");
      await page.evaluate(`document.querySelector('.companion-portrait').decode()`);
      assert.ok(await page.evaluate(`document.querySelector('.companion-portrait').naturalWidth>=900`),"preloaded expression stays visible when server is unreachable");
      await eventually(()=>page.evaluate(`document.querySelector('#companion-assistant').dataset.expression==='idle'`),"offline expression returns to idle");
      await page.evaluate(`document.querySelector('.companion-portrait').decode()`);
      await capture("portrait-offline");
      console.log("PASS loaded portrait and expressions survive an unreachable preview server");
    } finally {
      await page.send("Network.emulateNetworkConditions",{offline:false,latency:0,downloadThroughput:-1,uploadThroughput:-1});
    }
    await capture("reference-desktop");
    for(const width of [320,375]) {
      await page.send("Emulation.setDeviceMetricsOverride",{width,height:900,deviceScaleFactor:1,mobile:false});
      await page.evaluate("new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))");
      await page.click("#companion-toggle");
      await capture(`reference-mobile-${width}`);
      assert.ok(await page.evaluate(`(() => {const a=document.querySelector('#companion-toggle').getBoundingClientRect(),p=document.querySelector('#local-preview-tools').getBoundingClientRect();return a.left>=p.right&&a.right<=innerWidth;})()`),"preview controls remain separate from portrait");
    }
    await page.click("#companion-tools");
    await page.evaluate(`document.querySelectorAll('.companion-shortcuts button')[2].click()`);
    await page.waitVisible(".portrait-dialog");
    console.log("PASS high resolution reference portrait, mobile no overlap and enlarged view");
    assert.deepEqual(page.errors,[]);
  } finally {
    if(page) {await page.send("Browser.close").catch(()=>{});page.socket.close();}
    if(browser.exitCode===null)browser.kill();
    if(profile.startsWith(join(tmpdir(),"nre-companion-browser-")))await rm(profile,{recursive:true,force:true,maxRetries:8,retryDelay:200}).catch(()=>{});
  }
}
