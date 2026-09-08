import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";

export async function runOperations({page,test,navigate,hold,state,capture,eventually}) {
  const text = (selector) => page.evaluate(`document.querySelector(${JSON.stringify(selector)}).textContent`);
  const idle = () => eventually(() => page.evaluate(`!document.querySelector('.agent-search-select__trigger').disabled`), "operation controls restored");
  const status = (expected) => eventually(() => page.evaluate(`document.querySelector('#app-status').dataset.state === ${JSON.stringify(expected)}`), `operation ${expected}`);
  const reset = async (id = "alpha") => {
    state.reset(); await navigate("?agent_id=node-a"); await page.waitVisible(`[data-id="${id}"]`);
    await page.click(`[data-id="${id}"] [data-action="detail"]`); await page.waitVisible("#app-detail");
  };
  const dialog = async (id = "confirm") => page.waitVisible(`#${id}-dialog`);
  const close = async (ok, id = "confirm") => {
    await dialog(id);
    const sequence = await page.evaluate(`(() => {
      const dialog = document.querySelector(${JSON.stringify(`#${id}-dialog`)});
      const next = Number(dialog.dataset.testCloseSequence || 0) + 1;
      dialog.addEventListener("close", () => { dialog.dataset.testCloseSequence = String(next); }, {once:true});
      return next;
    })()`);
    await page.click(`#${id}-${ok ? (id === "update" ? "confirm" : "ok") : "cancel"}`);
    await eventually(() => page.evaluate(`Number(document.querySelector(${JSON.stringify(`#${id}-dialog`)}).dataset.testCloseSequence || 0) >= ${sequence}`), "dialog close event");
    await page.evaluate("new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))");
  };
  const choose = async (selector, value) => {
    await page.evaluate(`(() => {const field=document.querySelector(${JSON.stringify(selector)}); field.value=${JSON.stringify(value)}; field.dispatchEvent(new Event('change',{bubbles:true}));})()`);
  };
  const update = () => page.click('#detail-overview [data-action="update"]');
  const policy = () => page.click('#detail-overview [data-action="service-policy"][data-service="web"]');
  const cancelEsc = async (id = "confirm") => { await dialog(id); await page.key("Escape"); await eventually(async () => !(await page.visible(`#${id}-dialog`)), "Escape closes dialog"); await idle(); };

  await test("view and refresh never update images; lifecycle follows actual actions", async () => {
    await reset(); await page.click("#workspace-refresh");
    await eventually(() => page.visible('#detail-overview [data-action="update"]'), "refreshed detail");
    assert.equal(state.calls.length,0);
    const pending = hold("/api/apps/alpha/stop");
    await page.click("#detail-stop"); await eventually(() => pending.seen, "stop pending");
    assert.equal(await page.evaluate(`document.querySelector('#detail-stop').disabled`),true);
    pending.release(); await status("succeeded"); await idle();
    assert.ok(await page.visible("#detail-start")); assert.equal(await page.visible("#detail-stop"),false);
    await page.click("#detail-start"); await status("succeeded"); await idle();
    await page.click("#detail-restart"); await status("succeeded"); await idle();
    assert.deepEqual(state.applied.map((call) => call.action),["stop","start","restart"]);
  });

  await test("version and policy edits are drafts until confirmation", async () => {
    await reset();
    const overview = await text("#detail-overview");
    for (const word of ["nginx:1.27","候选","忽略"]) assert.ok(overview.includes(word), `overview missing ${word}`);
    assert.equal(overview.includes("锁定：未锁定"), false, "empty lock line is hidden");
    assert.equal(overview.includes("忽略：无"), false, "empty ignore line is hidden");
    assert.equal(await page.evaluate(`document.querySelectorAll('#detail-overview select[name^="lock-"]').length`),0,"overview does not mutate policy on selection");
    await update(); await dialog("update");
    await page.click('input[name="update-db"]');
    await choose('select[name="target-web"]',"2.0");
    await choose('select[name="lock-web"]',"^1.27");
    await capture("versions",1440); await capture("versions",375);
    await close(false,"update"); await idle();
    assert.equal(state.calls.length,0);
    await update(); await dialog("update");
    assert.equal(await page.evaluate(`document.querySelector('input[name="update-db"]').checked`),true);
    assert.equal(await page.evaluate(`document.querySelector('select[name="lock-web"]').value`),"");
    await cancelEsc("update"); assert.equal(state.calls.length,0);
    await update(); await dialog("update");
    await page.click('input[name="update-db"]');
    await close(true,"update"); await status("succeeded"); await idle();
    assert.deepEqual(state.applied[0].body,{services:[{name:"web",tag:"1.28"}]});
    const app = state.apps.find((app) => app.id === "alpha");
    assert.equal(app.service_images[0].image,"nginx:1.28");
    assert.equal(app.service_images[1].image,"postgres:16","unselected service remains unchanged");
  });

  await test("no candidates still permits confirmed policy changes; no history hides rollback", async () => {
    await reset("steady");
    assert.equal(await page.visible('#detail-overview [data-action="update"]'),false);
    assert.equal(await page.visible('#detail-overview [data-action="rollback"]'),false);
    assert.match(await text(".rollback-unavailable"),/当前没有可用/);
    await policy(); await dialog("update");
    assert.equal(await page.evaluate(`document.querySelector('input[name="update-web"]').disabled`),true);
    await choose('select[name="lock-web"]',"");
    await page.click('input[data-clear-ignore="true"]');
    await close(false,"update"); await idle(); assert.equal(state.calls.length,0);
    await policy(); await dialog("update");
    await choose('select[name="lock-web"]',""); await page.click('input[data-clear-ignore="true"]');
    await close(true,"update"); await status("succeeded"); await idle();
    assert.deepEqual(state.applied[0].body,{locks:{web:""},ignore:[{service:"web",tag:"1.26",clear:true}]});
    assert.equal(state.apps.find((app) => app.id === "steady").service_images[0].image,"nginx:1.27");
    await reset("single"); await update(); await close(true,"update"); await status("succeeded"); await idle();
    assert.deepEqual(state.applied[0].body.services,[{name:"web",tag:"1.28"}]);
  });

  await test("floating digest candidates are selectable from app and individual service updates", async () => {
    for (const entry of ["update", "service"]) {
      state.reset();
      state.apps[0].service_images[1] = {name:"db", image:"example/worker:latest", tag:"latest", update:true, default_tag:"latest", candidates:[{tag:"latest",digest:true}]};
      await navigate("?agent_id=node-a"); await page.click('[data-id="alpha"] [data-action="detail"]'); await page.waitVisible("#app-detail");
      if (entry === "update") await update();
      else await page.click('#detail-overview [data-action="service-update"][data-service="db"]');
      await dialog("update");
      if (entry === "update") await page.click('input[name="update-web"]');
      assert.equal(await page.evaluate(`document.querySelector('input[name="update-db"]').checked`), true);
      await page.click('select[name="target-db"]'); await page.key("Escape");
      assert.equal(await page.evaluate(`document.querySelector('select[name="target-db"]').value`), "latest");
      await close(true,"update"); await status("succeeded"); await idle();
      assert.deepEqual(state.applied[0].body.services,[{name:"db",tag:"latest"}]);
    }
  });

  await test("application cards bound service previews and keep complete details reachable", async () => {
    state.reset();
    const images = Array.from({length:20}, (_, i) => ({name:`service-${i}`,image:`registry.example.test/${"namespace/".repeat(15)}worker-${i}:latest`}));
    Object.assign(state.apps[0], {service_images:images, services:images.map(s => s.name)});
    await navigate("?agent_id=node-a"); await page.waitVisible('[data-id="alpha"]');
    for (const width of [1440,375]) {
      await capture("bounded-services",width);
      const box = await page.evaluate(`(() => {const card=document.querySelector('[data-id="alpha"]'), preview=card.querySelector('[data-app-image]'); return {rows:preview.querySelectorAll('.app-card-image-row').length,height:preview.getBoundingClientRect().height,width:card.getBoundingClientRect().width,rem:parseFloat(getComputedStyle(document.documentElement).fontSize),copy:preview.textContent,overflow:document.documentElement.scrollWidth>document.documentElement.clientWidth};})()`);
      assert.equal(box.rows,2); assert.ok(box.height < box.rem*10); assert.ok(box.width <= width); assert.equal(box.overflow,false); assert.match(box.copy,/另有 18 个服务/);
    }
    await page.click('[data-id="alpha"] [data-action="detail"]'); await page.waitVisible("#app-detail");
    assert.equal(await page.evaluate(`document.querySelectorAll('#detail-overview .overview-service').length`),20);
  });

  await test("version policy cannot accidentally update a service image", async () => {
    await reset(); await policy(); await dialog("update");
    assert.equal(await page.visible('input[name="update-web"]'),false);
    assert.equal(await text("#update-title"),"版本策略");
    assert.equal(await text("#update-confirm"),"保存策略");
    await choose('select[name="lock-web"]',"^1.27");
    await close(true,"update"); await status("succeeded"); await idle();
    assert.deepEqual(state.applied[0].body,{locks:{web:"^1.27"}});
    assert.equal(state.apps[0].service_images[0].image,"nginx:1.27");
  });

  await test("inventory searches services and images and filters status without mutations", async () => {
    state.reset(); state.apps[2].status="已停止";
    await navigate("?agent_id=node-a"); await page.waitVisible('[data-id="alpha"]');
    await page.evaluate(`(() => {const search=document.querySelector('#app-search'); search.value='postgres'; search.dispatchEvent(new Event('input',{bubbles:true}));})()`);
    assert.equal(await page.visible('[data-id="alpha"]'),true);
    assert.equal(await page.visible('[data-id="single"]'),false);
    await page.evaluate(`(() => {const search=document.querySelector('#app-search'); search.value='missing-image'; search.dispatchEvent(new Event('input',{bubbles:true}));})()`);
    assert.equal(await page.visible('#app-no-results'),true);
    await page.evaluate(`(() => {const search=document.querySelector('#app-search'); search.value=''; search.dispatchEvent(new Event('input',{bubbles:true}));})()`);
    await choose('#app-filter','stopped');
    assert.equal(await page.visible('[data-id="steady"]'),true);
    assert.equal(await page.visible('[data-id="alpha"]'),false);
    assert.equal(state.calls.length,0);
    await page.selectAgent('node-b');
    assert.equal(await page.evaluate(`document.querySelector('#app-filter').value`),'all');
  });

  await test("rollback identifies current and prior deployment and cancellation never submits", async () => {
    await reset();
    for (const mode of ["cancel","escape","confirm"]) {
      await page.click('#detail-overview [data-action="rollback"]'); await dialog();
      assert.match(await text("#confirm-body"),/节点.*alpha.*\n当前镜像：.*\n目标：.*上一部署版本/);
      if (mode === "escape") await cancelEsc();
      else await close(mode === "confirm");
      await idle();
      assert.equal(state.applied.length,mode === "confirm" ? 1 : 0);
    }
    assert.equal(state.applied[0].action,"rollback");
    assert.equal(state.apps[0].version,"nginx:1.26");
  });

  await test("changed server risk digests require fresh confirmation and cancellation applies nothing", async () => {
    await reset(); state.riskDigests = ["risk-a","risk-b"];
    await update(); await close(true,"update"); await dialog();
    assert.match(await text("#confirm-body"),/节点.*节点 A.*应用 alpha/);
    assert.match(await text("#confirm-body"),/fixture-risk-a/);
    await close(true); await dialog(); assert.match(await text("#confirm-body"),/fixture-risk-b/);
    await capture("risk-confirm",375); await close(false); await idle();
    assert.equal(state.applied.length,0);
    assert.deepEqual(state.calls.map((call) => call.body.confirm),[undefined,"risk-a"]);
    state.riskDigests = ["risk-a","risk-b"];
    await update(); await close(true,"update"); await close(true); await close(true); await status("succeeded"); await idle();
    assert.equal(state.applied.length,1);
    assert.equal(state.applied[0].body.confirm,"risk-b");
  });

  await test("successful lifecycle actions report a separate refresh failure without resubmission", async () => {
    for (const action of ["stop","restart","update","rollback","delete"]) {
      await reset(); state.listError = true;
      if (["stop","restart"].includes(action)) await page.click(`#detail-${action}`);
      else {
        await page.click(`#detail-overview [data-action="${action}"]`);
        await close(true, action === "update" ? "update" : "confirm");
      }
      await status("partial"); await idle();
      assert.match(await text("#app-status"),/已.*刷新失败/);
      assert.equal(state.applied.length,1);
      assert.equal(state.calls.length,1);
      state.listError = false; await page.click("#workspace-refresh");
      await delay(100); assert.equal(state.calls.length,1);
    }
    await reset(); state.listError = "partial";
    await page.click("#detail-stop"); await status("partial"); await idle();
    assert.match(await text("#app-status"),/已停止.*刷新失败/);
    assert.equal(state.applied.length,1);
    assert.ok(await page.visible("#app-detail"), "usable application data stays visible after a partial read");
  });

  await test("deletion explains linked rules and distinguishes rule, app and partial failures", async () => {
    await reset();
    await page.click('#detail-overview [data-action="delete"]'); await dialog();
    assert.match(await text("#confirm-body"),/关联 HTTP 规则.*\n当前显示的入口：alpha.example.test/);
    await capture("delete-confirm",1440); await close(false); await idle(); assert.equal(state.calls.length,0);
    await page.click('#detail-overview [data-action="delete"]'); await cancelEsc(); assert.equal(state.calls.length,0);
    for (const mode of ["rules-failed","after-rules","app-failed"]) {
      await reset(); state.deleteMode = mode;
      if (mode === "app-failed") state.apps[0].rules = [];
      await page.click('#detail-overview [data-action="delete"]'); await close(true);
      await status(mode === "after-rules" ? "partial" : "failed"); await idle();
      const message = await text("#app-status");
      assert.match(message,mode === "rules-failed" ? /HTTP 规则删除失败/ : mode === "after-rules" ? /规则已.*删除，但应用仍在/ : /删除应用失败/);
      assert.equal(state.apps.some((app) => app.id === "alpha"),true);
      assert.equal(state.applied.length,0);
      if (mode === "rules-failed") assert.equal(state.apps[0].rules.length,1);
      if (mode === "after-rules") assert.equal(state.apps[0].rules.length,0);
    }
  });

  await test("cleanup preview, empty state and repeated cancellations never submit", async () => {
    await reset(); await page.click("#detail-back");
    for (const mode of ["empty","cancel","escape","cancel"]) {
      state.cleanupPreview.empty = mode === "empty";
      await page.click("#disk-cleanup"); await dialog();
      assert.match(await text("#confirm-title"),/节点 A/);
      if (mode === "empty") assert.equal(await page.visible("#confirm-ok"),false);
      if (mode === "escape") await cancelEsc(); else await close(false);
      await idle(); assert.equal(state.calls.length,0);
    }
    state.previewError = true; await page.click("#disk-cleanup"); await status("failed"); await idle();
    assert.equal(state.calls.length,0);
  });

  await test("cleanup step results distinguish partial and success; accepted alone is insufficient", async () => {
    for (const mode of ["partial","success","accepted-only"]) {
      await reset(); await page.click("#detail-back");
      if (mode === "partial") Object.assign(state.cleanupResult,{status:"partial",builder_cache_status:"failed",builder_cache:"缓存清理失败。"});
      if (mode === "accepted-only") state.cleanupResult = null;
      await page.click("#disk-cleanup"); await dialog();
      if (mode === "partial") await capture("cleanup-confirm",375);
      await close(true); await status(mode === "partial" ? "partial" : mode === "success" ? "succeeded" : "failed"); await idle();
      assert.equal(state.calls.length,1);
      assert.deepEqual(state.calls[0].body,{agent_id:"node-a",confirm:true});
      const message = await text("#app-status");
      if (mode === "partial") { assert.match(message,/镜像：完成/); assert.match(message,/构建缓存：失败/); }
      if (mode === "accepted-only") assert.match(message,/未获得可确认的清理结果/);
    }
  });

  await test("old refresh cannot change an operation target during confirmation or submission", async () => {
    await reset();
    const oldList = hold("/api/apps?agent_id=node-a");
    await page.click("#workspace-refresh"); await eventually(() => oldList.seen,"old refresh held");
    await page.click('#detail-overview [data-action="delete"]'); await dialog();
    assert.equal(await page.evaluate(`document.querySelector('.agent-search-select__trigger').disabled`),true);
    oldList.release(); await delay(150);
    assert.match(await text("#confirm-body"),/应用 alpha/);
    const deletion = hold("/api/apps/alpha/delete");
    await close(true); await eventually(() => deletion.seen,"deletion held");
    deletion.release(); await status("succeeded"); await idle();
    assert.deepEqual(state.applied.map((call) => [call.id,call.action]),[["alpha","delete"]]);
  });
}
