import assert from "node:assert/strict";

function contrast(foreground,background) {
  const luminance = (text) => text.match(/[\d.]+/g).slice(0,3).map(Number).map((x) => x/255)
    .map((x) => x <= 0.04045 ? x/12.92 : ((x+0.055)/1.055)**2.4).reduce((sum,x,i) => sum+x*[0.2126,0.7152,0.0722][i],0);
  const a=luminance(foreground), b=luminance(background); return (Math.max(a,b)+0.05)/(Math.min(a,b)+0.05);
}

export async function runExperience({page,test,navigate,capture,eventually,origin}) {
  await test("packaged companion loads without preview routes and keeps frames offline",async () => {
    await page.send("Emulation.setDeviceMetricsOverride",{width:1440,height:900,deviceScaleFactor:1,mobile:false});
    await navigate("?agent_id=node-a");
    await eventually(()=>page.evaluate(`document.querySelector('#companion-assistant')?.dataset.expressionFrames==='3'`),"packaged expression frames loaded");
    const resources=await page.evaluate(`performance.getEntriesByType('resource').map(entry=>new URL(entry.name).pathname)`);
    for (const name of ["companion.js","companion-idle.webp","companion-blink.webp","companion-wink.webp"]) assert.ok(resources.includes('/'+name),`packaged asset ${name} loaded`);
    assert.ok(!resources.some(path=>path.startsWith('/__preview/')),"companion needs no development server routes");
    await page.send("Network.enable");
    await page.send("Network.emulateNetworkConditions",{offline:true,latency:0,downloadThroughput:0,uploadThroughput:0});
    try {
      await page.click("#companion-toggle");
      await page.evaluate(`document.querySelector('.companion-portrait').decode()`);
      assert.equal(await page.evaluate(`document.querySelector('#companion-assistant').dataset.expression`),"wink");
      await eventually(()=>page.evaluate(`document.querySelector('#companion-assistant').dataset.expression==='idle'`),"offline return to idle");
      await page.evaluate(`document.querySelector('.companion-portrait').decode()`);
    } finally {
      await page.send("Network.emulateNetworkConditions",{offline:false,latency:0,downloadThroughput:-1,uploadThroughput:-1});
    }
    await capture("packaged-companion",1440);
  });

  await test("mobile header keeps node names on one line and the companion docks outside it",async () => {
    await navigate("?agent_id=node-a");
    await page.evaluate(`(() => {const label=document.querySelector('.agent-search-select__label');label.textContent='debian-jnp12（预览）';})()`);
    for (const width of [320,375,430]) {
      await page.send("Emulation.setDeviceMetricsOverride",{width,height:900,deviceScaleFactor:1,mobile:false});
      const bounds=await page.evaluate(`(() => {const box=s=>document.querySelector(s).getBoundingClientRect(), header=box('.page-head'), art=box('#companion-toggle'), copy=box('.page-head-copy'), node=box('.page-head-agent'), label=box('.agent-search-select__label');return {within:art.left>=0&&art.right<=innerWidth&&art.bottom<=innerHeight,apart:node.top>=copy.bottom&&art.top>=header.bottom,line:label.height,lineHeight:parseFloat(getComputedStyle(document.querySelector('.agent-search-select__label')).lineHeight),height:header.height,overflow:document.documentElement.scrollWidth>document.documentElement.clientWidth};})()`);
      assert.ok(bounds.within&&bounds.apart,`illustration stays clear at ${width}: ${JSON.stringify(bounds)}`);
      assert.ok(bounds.line<=bounds.lineHeight+1,`node name remains one line at ${width}`);
      assert.ok(bounds.height<260,`header remains compact at ${width}`);
      assert.equal(bounds.overflow,false);
      await capture("mobile-header",width);
    }
  });

  await test("same-origin host theme changes propagate and unknown themes fall back safely",async () => {
    await page.send("Page.navigate",{url:origin+"/theme-frame.html"});
    await eventually(() => page.evaluate(`document.querySelector('iframe')?.contentDocument?.querySelector('#app-loading')?.hidden === true`),"embedded fixture loaded");
    const theme = () => page.evaluate(`document.querySelector('iframe').contentDocument.documentElement.dataset.theme`);
    assert.equal(await theme(),"dark");
    for (const [host,expected] of [["business","light"],["neko-dark","dark"],["unknown-host-theme","light"],["sakura-night","dark"]]) {
      await page.evaluate(`document.documentElement.dataset.theme=${JSON.stringify(host)}`);
      await eventually(async () => await theme() === expected,`dynamic ${host} theme`);
    }
  });

  await test("standalone plugin follows the actual host theme storage across tabs",async () => {
    await navigate("?agent_id=node-a");
    const tab = await page.send("Target.createTarget",{url:origin+"/theme-writer.html"});
    const {sessionId} = await page.send("Target.attachToTarget",{targetId:tab.targetId,flatten:true});
    try {
      for (const [stored,expected] of [["sakura-night","dark"],["business","light"]]) {
        const result = await page.send("Runtime.evaluate",{expression:`localStorage.setItem('theme',${JSON.stringify(stored)})`},sessionId);
        assert.equal(result.exceptionDetails,undefined);
        await eventually(() => page.evaluate(`document.documentElement.dataset.theme === ${JSON.stringify(expected)}`),"cross-tab host theme synchronization");
      }
    } finally { await page.send("Target.closeTarget",{targetId:tab.targetId}); }
  });

  await test("keyboard navigation moves focus into the new view and dialogs retain focus",async () => {
    await navigate("?agent_id=node-a"); await page.waitVisible('[data-id="alpha"]');
    await page.evaluate(`document.querySelector('#workspace-refresh').focus()`);
    let focused = false;
    for (let i=0;i<20;i+=1) {
      await page.key("Tab");
      focused = await page.evaluate(`document.activeElement.matches('.app-card[data-id="alpha"]')`);
      if (focused) break;
    }
    assert.ok(focused,"application information row is keyboard reachable");
    await page.key("Enter"); await page.waitVisible("#app-detail");
    assert.ok(await page.evaluate(`document.querySelector('#app-detail').contains(document.activeElement) && document.activeElement.getClientRects().length > 0`),"opening detail moves focus into the new view");
    await page.click('#detail-overview [data-action="delete"]'); await page.waitVisible("#confirm-dialog");
    for (let i=0;i<8;i+=1) {
      await page.key("Tab",{shift:i%2 === 0});
      assert.ok(await page.evaluate(`document.querySelector('#confirm-dialog').contains(document.activeElement)`),"native dialog traps keyboard focus");
    }
    await page.key("Escape"); await eventually(() => page.evaluate(`!document.querySelector('.agent-search-select__trigger').disabled && !document.querySelector('#confirm-dialog').open`),"cancel completed");
    assert.equal(await page.evaluate(`document.activeElement.dataset.action`),"delete");
    await page.click("#detail-back"); await page.waitVisible("#app-list");
    assert.ok(await page.evaluate(`document.querySelector('#app-workspace').contains(document.activeElement) && document.activeElement.getClientRects().length > 0`),"returning to list restores visible focus");
  });

  await test("log toolbar controls stay readable on the toolbar background", async () => {
    await navigate("?agent_id=node-a");
    await page.click('[data-id="alpha"] [data-action="detail"]'); await page.waitVisible("#app-detail");
    await page.click('#detail-nav [data-section="logs"]'); await page.waitVisible(".logs-toolbar");
    for (const theme of ["light","dark"]) {
      await page.evaluate(`localStorage.removeItem("theme"); document.documentElement.dataset.theme=${JSON.stringify(theme)}`);
      await eventually(() => page.evaluate(`document.documentElement.dataset.theme === ${JSON.stringify(theme)}`),"log toolbar theme applied");
      const colors = await page.evaluate(`(() => {
        const bar = document.querySelector(".logs-toolbar");
        const bg = getComputedStyle(bar).backgroundColor;
        return {
          bg,
          btn: getComputedStyle(document.querySelector("#logs-refresh")).color,
          pause: getComputedStyle(document.querySelector("#logs-pause")).color,
          label: getComputedStyle(bar.querySelector("label")).color,
          select: getComputedStyle(document.querySelector("#logs-service")).color,
        };
      })()`);
      assert.ok(contrast(colors.btn, colors.bg) >= 4.5, `refresh contrast ${theme}: ${JSON.stringify(colors)}`);
      assert.ok(contrast(colors.pause, colors.bg) >= 4.5, `pause contrast ${theme}: ${JSON.stringify(colors)}`);
      assert.ok(contrast(colors.label, colors.bg) >= 4.5, `service label contrast ${theme}: ${JSON.stringify(colors)}`);
      assert.ok(contrast(colors.select, colors.bg) >= 4.5, `service select contrast ${theme}: ${JSON.stringify(colors)}`);
    }
    await capture("logs-toolbar", 1440);
  });

  await test("light/dark and narrow/desktop layouts keep readable text and reachable controls",async () => {
    await navigate("?agent_id=node-a");
    for (const theme of ["light","dark"]) {
      await page.evaluate(`localStorage.removeItem('theme'); document.documentElement.dataset.theme=${JSON.stringify(theme)}`);
      await eventually(() => page.evaluate(`document.documentElement.dataset.theme === ${JSON.stringify(theme)}`),"fixture theme applied");
      for (const width of [1440,375]) {
        assert.equal((await capture(`list-${theme}`,width)).theme,theme);
        const colors=await page.evaluate(`({fg:getComputedStyle(document.body).color,bg:getComputedStyle(document.body).backgroundColor})`);
        assert.ok(contrast(colors.fg,colors.bg)>=4.5,"body text contrast remains readable");
        assert.ok(await page.evaluate(`document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1`),"no viewport overflow");
        await page.click("#deploy-toggle"); await page.waitVisible("#create-form");
        await page.key("Tab");
        assert.ok(await page.evaluate(`document.querySelector('#create-form').contains(document.activeElement)`),"deployment form is keyboard reachable");
        assert.equal((await capture(`deployment-${theme}`,width)).theme,theme);
        await page.click("#create-cancel"); await page.waitVisible("#app-list");
      }
    }
  });
}
