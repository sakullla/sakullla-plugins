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
    const before=await page.evaluate(`({frames:document.querySelector('#companion-assistant')?.dataset.expressionFrames || "0",webp:performance.getEntriesByType('resource').filter(entry=>entry.name.endsWith('.webp')).length,min:document.querySelector('#companion-assistant')?.dataset.minimized})`);
    assert.equal(before.min,"true","companion starts collapsed");
    assert.equal(before.webp,0,"first screen downloads no artwork");
    await page.click("#companion-toggle");
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
    assert.equal(await theme(),"sakura-night");
    for (const [host,expected] of [["business","business"],["neko-dark","neko-dark"],["unknown-host-theme","light"],["sakura-night","sakura-night"]]) {
      await page.evaluate(`localStorage.setItem('theme',${JSON.stringify(host)}); document.documentElement.dataset.theme=${JSON.stringify(host)}`);
      await eventually(async () => await theme() === expected,`dynamic ${host} theme`);
    }
  });

  await test("standalone plugin follows the actual host theme storage across tabs",async () => {
    await navigate("?agent_id=node-a");
    const tab = await page.send("Target.createTarget",{url:origin+"/theme-writer.html"});
    const {sessionId} = await page.send("Target.attachToTarget",{targetId:tab.targetId,flatten:true});
    await eventually(async () => {
      const probe = await page.send("Runtime.evaluate", { expression: "location.origin", returnByValue: true }, sessionId);
      return probe.result?.value === origin;
    }, "theme writer tab committed");
    try {
      for (const [stored,expected] of [["sakura-night","sakura-night"],["business","business"]]) {
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

  await test("every control keeps a 44px target at 390 and each tab stays reachable", async () => {
    await navigate("?agent_id=node-a"); await page.waitVisible('[data-id="alpha"]');
    await page.send("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: false });
    try {
      await page.click('[data-id="alpha"] [data-action="detail"]'); await page.waitVisible("#app-detail");
      const wiring = await page.evaluate(`(() => [...document.querySelectorAll('#detail-nav [role="tab"]')].every((tab) => {
        const panel = document.getElementById(tab.getAttribute('aria-controls'));
        return tab.id && panel && panel.getAttribute('role') === 'tabpanel' && panel.getAttribute('aria-labelledby') === tab.id;
      }))()`);
      assert.equal(wiring, true, "each tab controls a panel that points back at it");
      for (const section of ["overview", "compose", "files", "logs", "http", "backup"]) {
        await page.evaluate(`document.querySelector('#detail-nav [data-section="${section}"]').scrollIntoView({ block: 'nearest', inline: 'center' })`);
        await page.click(`#detail-nav [data-section="${section}"]`);
        await eventually(() => page.evaluate(`document.querySelector('#detail-nav [aria-selected="true"]')?.dataset.section === ${JSON.stringify(section)}`), `section ${section} active`);
        const state = await page.evaluate(`(() => {
          const small = [];
          for (const el of document.querySelectorAll('#app-workspace button, #app-workspace a[href], #app-workspace select, #app-workspace [role="tab"], .page-head button, .page-head .agent-search-select__trigger')) {
            const rect = el.getBoundingClientRect();
            if (!rect.width || !rect.height) continue;
            if (el.closest('[hidden]') || el.classList.contains('ui-sr-only') || el.type === 'checkbox' || el.type === 'radio') continue;
            if (rect.width < 43.5 || rect.height < 43.5) small.push({id: el.id || el.className.toString().slice(0, 40), w: Math.round(rect.width), h: Math.round(rect.height)});
          }
          const active = document.querySelector('#detail-nav [aria-selected="true"]');
          const tab = active.getBoundingClientRect(), nav = document.querySelector('#detail-nav').getBoundingClientRect();
          return {small, overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
            inside: tab.left >= nav.left - 1 && tab.right <= nav.right + 1, tabIndex: active.tabIndex};
        })()`);
        assert.deepEqual(state.small, [], `44px targets in ${section}: ${JSON.stringify(state.small)}`);
        assert.equal(state.overflow, 0, `no horizontal overflow in ${section}`);
        assert.ok(state.inside, `the active tab is scrolled into view in ${section}`);
        assert.equal(state.tabIndex, 0, `only the active tab is in the tab order for ${section}`);
      }
      const origins = await page.evaluate(`[...new Set(performance.getEntriesByType('resource').map((entry) => new URL(entry.name).origin))]`);
      assert.deepEqual(origins, [await page.evaluate("location.origin")], `only same-origin resources load: ${JSON.stringify(origins)}`);
      await capture("touch-targets", 390);

      // R11: the tablet width keeps the same sections without sideways scroll.
      await page.send("Emulation.setDeviceMetricsOverride", { width: 768, height: 900, deviceScaleFactor: 1, mobile: false });
      for (const section of ["overview", "compose", "files", "logs", "http", "backup"]) {
        await page.evaluate(`document.querySelector('#detail-nav [data-section="${section}"]').scrollIntoView({ block: 'nearest', inline: 'center' })`);
        await page.click(`#detail-nav [data-section="${section}"]`);
        await eventually(() => page.evaluate(`document.querySelector('#detail-nav [aria-selected="true"]')?.dataset.section === ${JSON.stringify(section)}`), `section ${section} active at 768`);
        const tablet = await page.evaluate(`(() => {
          const active = document.querySelector('#detail-nav [aria-selected="true"]');
          const tab = active.getBoundingClientRect(), nav = document.querySelector('#detail-nav').getBoundingClientRect();
          return {
            overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
            inside: tab.left >= nav.left - 1 && tab.right <= nav.right + 1,
          };
        })()`);
        assert.equal(tablet.overflow, 0, `no horizontal overflow at 768 in ${section}`);
        assert.ok(tablet.inside, `the active tab stays inside the strip at 768 in ${section}`);
      }
      await capture("tablet-layout", 768);
    } finally {
      await page.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false });
    }
  });

  await test("page tokens resolve with the kit tokens under every host theme", async () => {
    await navigate("?agent_id=node-a"); await page.waitVisible('.app-card');
    const tab = await page.send("Target.createTarget", { url: origin + "/theme-writer.html" });
    const { sessionId } = await page.send("Target.attachToTarget", { targetId: tab.targetId, flatten: true });
    await eventually(async () => {
      const probe = await page.send("Runtime.evaluate", { expression: "location.origin", returnByValue: true }, sessionId);
      return probe.result?.value === origin;
    }, "theme writer tab committed");
    const seen = [];
    try {
      for (const host of ["fresh-green", "sakura-day", "sakura-night", "neko-dark", "business"]) {
        await page.send("Runtime.evaluate", { expression: `localStorage.setItem('theme',${JSON.stringify(host)})` }, sessionId);
        await eventually(() => page.evaluate(`document.documentElement.dataset.theme === ${JSON.stringify(host)}`), `host theme ${host}`);
        const tokens = await page.evaluate(`(() => {
          const card = document.querySelector('#app-list .app-card');
          const read = (node, prop) => getComputedStyle(node)[prop];
          return {
            theme: document.documentElement.dataset.theme,
            cardBorder: read(card, 'borderTopColor'),
            cardSurface: read(card, 'backgroundColor'),
            body: read(document.body, 'backgroundColor'),
            text: read(document.body, 'color'),
          };
        })()`);
        assert.equal(tokens.theme, host);
        assert.match(tokens.cardBorder, /^(?:rgba?|oklab|oklch|lab|lch|color)\(/, `page border token resolves under ${host}: ${JSON.stringify(tokens)}`);
        assert.ok(!/^rgba\(0, 0, 0, 0\)$/.test(tokens.cardBorder), `the page border never degrades to transparent under ${host}`);
        assert.match(tokens.cardSurface, /^(?:rgba?|oklab|oklch|lab|lch|color)\(/, `page surface token resolves under ${host}: ${JSON.stringify(tokens)}`);
        assert.match(tokens.body, /^(?:rgba?|oklab|oklch|lab|lch|color)\(/, `kit canvas token resolves under ${host}: ${JSON.stringify(tokens)}`);
        assert.ok(contrast(tokens.text, tokens.body) >= 4.5, `body contrast under ${host}: ${JSON.stringify(tokens)}`);
        seen.push(tokens);
      }
      assert.ok(new Set(seen.map((token) => token.body)).size > 1, "the kit canvas follows the host theme");
      assert.ok(new Set(seen.map((token) => token.text)).size > 1, "kit text colours follow the host theme");
    } finally {
      await page.send("Target.closeTarget", { targetId: tab.targetId });
      await page.evaluate(`localStorage.removeItem('theme'); document.documentElement.dataset.theme = 'light'`);
    }
  });

  await test("reduced motion removes drawer and dialog movement", async () => {
    await page.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "reduce" }] });
    try {
      await navigate("?agent_id=node-a"); await page.waitVisible('[data-id="alpha"]');
      await page.click("#deploy-toggle"); await page.waitVisible("#create-form");
      const motion = await page.evaluate(`(() => {
        const moving = document.getAnimations().filter((animation) => (animation.effect?.getKeyframes?.() || []).some((frame) => /translate|scale|matrix/.test(String(frame.transform || ''))));
        return {moving: moving.length, drawer: getComputedStyle(document.querySelector('#app-create')).animationName, reduced: matchMedia('(prefers-reduced-motion: reduce)').matches};
      })()`);
      assert.equal(motion.reduced, true, "the reduced-motion preference is visible to the page");
      assert.equal(motion.moving, 0, `no translation or scale animation runs: ${JSON.stringify(motion)}`);
      assert.equal(motion.drawer, "none", "the drawer opens without an entrance animation");
      await page.click("#create-cancel"); await page.waitVisible("#app-list");
    } finally {
      await page.send("Emulation.setEmulatedMedia", { features: [] });
    }
  });
}
