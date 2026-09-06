import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile, readFile } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

export async function runResources({page,test,navigate,hold,state,capture,eventually,outputDir}) {
  await mkdir(outputDir,{recursive:true});
  const downloads = await mkdtemp(join(outputDir,"downloads-"));
  await page.send("Browser.setDownloadBehavior",{behavior:"allow",downloadPath:downloads});
  await page.send("Page.setInterceptFileChooserDialog",{enabled:true});
  const text = (selector) => page.evaluate(`document.querySelector(${JSON.stringify(selector)}).textContent`);
  const value = (selector) => page.evaluate(`document.querySelector(${JSON.stringify(selector)}).value`);
  const idle = () => eventually(() => page.evaluate(`!document.querySelector('.agent-search-select__trigger').disabled`),"controls restored");
  const status = (kind) => eventually(() => page.evaluate(`document.querySelector('#app-status').dataset.state === ${JSON.stringify(kind)}`),`${kind} feedback`);
  const fill = async (selector,content) => { await page.click(selector); await page.evaluate("document.activeElement.select()"); await page.send("Input.insertText",{text:content}); };
  const choose = (selector,selected) => page.evaluate(`(() => {const input=document.querySelector(${JSON.stringify(selector)});input.value=${JSON.stringify(selected)};input.dispatchEvent(new Event('change',{bubbles:true}));})()`);
  const close = async (yes) => {
    await page.waitVisible("#confirm-dialog"); await page.click(yes ? "#confirm-ok" : "#confirm-cancel");
    await eventually(async () => !(await page.visible("#confirm-dialog")),"dialog closed");
    await page.evaluate("new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))");
  };
  const reset = async (section = "files", id = "alpha", configure = () => {}) => {
    state.reset(); configure();
    await navigate("?agent_id=node-a"); await page.waitVisible(`[data-id="${id}"]`);
    await page.click(`[data-id="${id}"] [data-action="detail"]`); await page.waitVisible("#app-detail");
    await page.click(`#detail-nav [data-section="${section}"]`);
    await page.waitVisible(`#detail-${section}`);
    if (section === "files") await page.waitVisible('[data-path="docs"]');
  };
  const file = (path) => `[data-path="${path}"] .files-name`;
  const fileWrites = () => state.calls.filter((call) => call.action === "files" && ["write","mkdir","delete"].includes(call.body.action));
  const ruleWrites = () => state.calls.filter((call) => call.action.startsWith("http-rule"));
  const attach = async (path) => {
    const root = await page.send("DOM.getDocument",{});
    const input = await page.send("DOM.querySelector",{nodeId:root.root.nodeId,selector:"[data-files-input]"});
    await page.send("DOM.setFileInputFiles",{nodeId:input.nodeId,files:[path]});
  };

  await test("files support directory navigation, explicit selection, editing and download", async () => {
    await reset();
    await page.click(file("docs")); await page.waitVisible('[data-path="docs/config.txt"]');
    assert.match(await text("#files-breadcrumb"),/工作区.*docs/);
    const reads = state.calls.filter((call) => call.body.action === "read").length;
    await page.click(file("docs/config.txt"));
    assert.equal(state.calls.filter((call) => call.body.action === "read").length,reads,"selection alone never reads");
    await page.click("#files-edit"); await page.waitVisible("#files-editor");
    await fill("#files-editor textarea","changed text\n");
    await page.click("#files-editor-close"); await close(false);
    assert.equal(await value("#files-editor textarea"),"changed text\n");
    await page.evaluate(`(() => {
      const node = document.querySelector("#files-editor textarea");
      node.focus();
      node.setSelectionRange(0, 0);
    })()`);
    await page.key("Tab");
    assert.equal((await value("#files-editor textarea")).startsWith("  changed"), true, "Tab indents the file editor");
    await page.key("Tab", {shift:true});
    assert.equal(await value("#files-editor textarea"), "changed text\n");
    await page.key("s", {ctrl:true}); await status("succeeded"); await idle();
    assert.equal(state.files.get("docs/config.txt"),"changed text\n");
    await capture("file-editor",1440); await capture("file-editor",375);
    await page.click("#files-editor-close"); await page.waitVisible("#files-browser");
    await page.click("#files-download");
    await eventually(async () => {try{return (await readFile(join(downloads,"config.txt"),"utf8")) === "changed text\n";}catch{return false;}},"downloaded actual file content");
    await page.click("#files-up"); await page.waitVisible('[data-path="root.txt"]');
    assert.equal(await text("#files-breadcrumb"),"工作区");
    await page.click(file("compose.yaml"));
    assert.equal(await page.evaluate(`document.querySelector('[data-path="compose.yaml"]').getAttribute("aria-selected")`),"true");
    assert.equal(await page.evaluate(`document.querySelector('[data-path="root.txt"]').getAttribute("aria-selected")`),"false");
    assert.match(await text("#files-selected"), /compose.yaml/);
    const marks = await page.evaluate(`(() => {
      const paint = (path) => {
        const style = getComputedStyle(document.querySelector('[data-path="' + path + '"] .files-list-name'), "::before");
        return {image:style.backgroundImage, color:style.backgroundColor};
      };
      return {selected:paint("compose.yaml"), other:paint("root.txt")};
    })()`);
    assert.notEqual(marks.selected.image, "none", "selected compose.yaml checks the leading control");
    assert.equal(marks.other.image, "none", "unselected rows stay unchecked");
    await page.evaluate(`document.querySelector('[data-path="docs"]').click()`);
    assert.equal(await page.evaluate(`document.querySelector('[data-path="docs"]').getAttribute("aria-selected")`),"true");
    assert.ok(await page.evaluate(`getComputedStyle(document.querySelector('[data-path="docs"] .files-list-name'), "::before").backgroundImage !== "none"`), "selected directory checks the leading control");
  });

  await test("file creation, upload, deletion and cancellation keep relative targets", async () => {
    await reset();
    await page.click("#files-mkdir"); await page.waitVisible("#files-mkdir-dialog");
    await fill("#files-mkdir-name","new-dir"); await page.click('#files-mkdir-form button[type="submit"]');
    await idle(); await page.waitVisible('[data-path="new-dir"]');
    await page.click(file("new-dir")); await eventually(() => page.evaluate(`document.querySelector('#files-status').dataset.state === 'empty'`),"empty directory");
    await page.click("#files-new-text"); await page.waitVisible("#files-new-dialog");
    await fill("#files-new-name","new.txt"); await page.click('#files-new-form button[type="submit"]'); await page.waitVisible("#files-editor");
    await fill("#files-editor textarea","new file\n"); await page.click("#files-save"); await status("succeeded"); await idle();
    await page.click("#files-editor-close"); await page.waitVisible('[data-path="new-dir/new.txt"]');
    const uploadPath = join(outputDir,"upload.txt"); await writeFile(uploadPath,"uploaded text\n");
    await page.click("#files-upload"); await attach(uploadPath); await status("succeeded"); await idle();
    assert.equal(state.files.get("new-dir/upload.txt"),"uploaded text\n");
    await page.click(file("new-dir/upload.txt"));
    const before = fileWrites().length;
    await page.click("#files-delete"); await close(false); await idle(); assert.equal(fileWrites().length,before);
    await page.click("#files-delete"); await page.waitVisible("#confirm-dialog"); await page.key("Escape"); await idle();
    assert.equal(fileWrites().length,before);
    await page.click("#files-delete"); await close(true); await idle();
    assert.equal(state.files.has("new-dir/upload.txt"),false);
    assert.ok(fileWrites().every((call) => !call.body.path.startsWith("/") && !call.body.path.includes(":")));
  });

  await test("file limits and read/write/list failures remain distinct and preserve drafts", async () => {
    await reset();
    for (const path of ["large.txt","binary.bin"]) {
      await page.click(file(path)); await page.click("#files-edit"); await status("failed");
      await eventually(() => text("#files-status").then((message) => (path === "large.txt" ? /1MiB/ : /不适合文本编辑/).test(message)),"file type or size rejection");
      assert.equal(await page.visible("#files-editor"),false);
      assert.match(await text("#files-status"),path === "large.txt" ? /1MiB/ : /不适合文本编辑/);
    }
    const before = fileWrites().length;
    for (const [name,content] of [["too-big.txt","x".repeat(1048577)],["invalid.bin",Buffer.from([255,0,12])]]) {
      const path = join(outputDir,name); await writeFile(path,content);
      await page.click("#files-upload"); await attach(path); await status("failed"); await idle();
    }
    assert.equal(fileWrites().length,before,"invalid uploads never send write requests");
    await page.click("#files-new-text"); await page.waitVisible("#files-new-dialog");
    await fill("#files-new-name","../../escape.txt"); await page.click('#files-new-form button[type="submit"]');
    assert.match(await text('#files-new-dialog [data-dialog-feedback]'),/相对路径/);
    await page.click('#files-new-dialog [data-dialog-close]');
    state.readError = true; await page.click(file("root.txt")); await page.click("#files-edit"); await status("failed");
    await eventually(() => text("#files-status").then((message) => message.includes("读取文件失败")),"file read failure received");
    assert.match(await text("#files-status"),/读取文件失败/);
    state.readError = false; await page.click("#files-edit"); await page.waitVisible("#files-editor");
    await fill("#files-editor textarea","retain on failed write\n"); state.writeError = true;
    await page.click("#files-save"); await status("failed"); await idle();
    assert.equal(await value("#files-editor textarea"),"retain on failed write\n");
    await page.click("#files-editor-close"); await close(true);
    state.listError = true; await page.click("#files-refresh"); await status("failed");
    await eventually(() => page.evaluate(`document.querySelector('#files-list').dataset.stale === 'true'`),"directory marked as stale");
    assert.equal(await page.evaluate(`document.querySelector('#files-list').dataset.stale`),"true");
    assert.ok(await page.visible('[data-path="root.txt"]'),"failed list preserves labelled old data");
  });

  await test("long file paths and text scroll within their own regions", async () => {
    const long = "directory-".repeat(12);
    await reset("files","alpha",() => {state.files.set(long,null);state.files.set(`${long}/long.txt`,"long-token-".repeat(1000));});
    await page.click(file(long)); await page.waitVisible(`[data-path="${long}/long.txt"]`);
    for (const width of [1440,375]) {
      await capture("files",width);
      assert.ok(await page.evaluate(`document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1`));
    }
    await page.click(file(`${long}/long.txt`)); await page.click("#files-edit"); await page.waitVisible("#files-editor");
    assert.ok(await page.evaluate(`document.querySelector('#files-editor textarea').scrollWidth > document.querySelector('#files-editor textarea').clientWidth`));
    assert.ok(await page.evaluate(`document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1`));
  });

  await test("failed listing for a new owner cannot reuse or operate old file rows", async () => {
    for (const [agent,id] of [["node-b","bravo"],["node-a","no-ports"]]) {
      await reset();
      await page.click(file("root.txt"));
      await page.evaluate(`window.oldFileRow = document.querySelector('[data-path="root.txt"] .files-name')`);
      state.listErrorOwner = `${agent}/${id}`;
      if (agent === "node-b") { await page.selectAgent(agent); await page.waitVisible('[data-id="bravo"]'); }
      else { await page.click("#detail-back"); await page.waitVisible('[data-id="no-ports"]'); }
      await page.click(`[data-id="${id}"] [data-action="detail"]`); await page.waitVisible("#app-detail");
      await page.click('#detail-nav [data-section="files"]');
      await eventually(() => page.evaluate(`document.querySelector('#files-status').dataset.state === 'failed'`),"new owner listing failed");
      assert.equal(await page.evaluate(`document.querySelectorAll('#files-list li').length`),0,`${agent}/${id} must not show alpha files`);
      await page.evaluate(`window.oldFileRow.click()`);
      for (const control of ["files-edit","files-download","files-delete"]) assert.equal(await page.evaluate(`document.querySelector('#${control}').disabled`),true,"detached old row cannot select a target in the new owner");
      assert.equal(fileWrites().length,0);
      const expected = agent === "node-b" ? "bravo original\n" : "other application original\n";
      assert.equal(state.filesByOwner.get(`${agent}/${id}`).get("root.txt"),expected);
      state.listErrorOwner = ""; await page.click("#files-refresh"); await page.waitVisible('[data-path="root.txt"]');
      await page.click(file("root.txt")); await page.click("#files-edit"); await page.waitVisible("#files-editor");
      assert.equal(await value("#files-editor textarea"),expected,"same-name file comes from the selected owner");
      assert.equal(fileWrites().length,0);
    }
  });

  await test("same-owner directory snapshots and stale row callbacks retain their path identity", async () => {
    await reset("files","alpha",() => state.files.set("docs/root.txt","nested original\n"));
    await page.evaluate(`window.oldFileRow = document.querySelector('[data-path="root.txt"] .files-name')`);
    state.listError = true; await page.click(file("docs"));
    await eventually(() => page.evaluate(`document.querySelector('#files-list').dataset.stale === 'true'`),"same-owner failed navigation keeps a labelled snapshot");
    assert.ok(await page.visible('[data-path="root.txt"]'));
    assert.equal(await text("#files-breadcrumb"),"工作区");
    state.listError = false; await page.click(file("docs")); await page.waitVisible('[data-path="docs/root.txt"]');
    await page.evaluate(`window.oldFileRow.click()`);
    assert.equal(await page.evaluate(`document.querySelector('#files-delete').disabled`),true,"old root row cannot select in the newer directory snapshot");
    await page.click(file("docs/root.txt")); await page.click("#files-edit"); await page.waitVisible("#files-editor");
    assert.equal(await value("#files-editor textarea"),"nested original\n");
    assert.equal(await text("#files-editor-name"),"docs/root.txt");
    await page.click('#detail-nav [data-section="overview"]');
    await page.evaluate(`window.oldFileRow.click()`);
    assert.equal(fileWrites().length,0);
  });

  await test("mkdir success remains explicit when its directory refresh fails", async () => {
    await reset(); state.listErrorAfterMkdir = true;
    await page.click("#files-mkdir"); await page.waitVisible("#files-mkdir-dialog");
    await fill("#files-mkdir-name","created-before-refresh-failure"); await page.click('#files-mkdir-form button[type="submit"]');
    await idle();
    assert.equal(state.files.has("created-before-refresh-failure"),true);
    assert.equal(await page.evaluate(`document.querySelector('#app-status').dataset.state`),"partial");
    assert.match(await text("#app-status"),/已创建.*刷新失败/);
    assert.equal(fileWrites().filter((call) => call.body.action === "mkdir").length,1);
    state.listError = false; await page.click("#files-refresh"); await page.waitVisible('[data-path="created-before-refresh-failure"]');
    assert.equal(fileWrites().filter((call) => call.body.action === "mkdir").length,1);
  });

  await test("file dialogs and pending choosers keep their directory target", async () => {
    await reset();
    const pending = hold("/api/apps/alpha/files");
    await page.click(file("docs")); await eventually(() => pending.seen,"directory navigation held");
    await page.click("#files-mkdir"); await page.waitVisible("#files-mkdir-dialog");
    await fill("#files-mkdir-name","pinned-parent");
    pending.release(); await delay(150);
    await page.click('#files-mkdir-form button[type="submit"]'); await idle();
    assert.equal(state.files.has("pinned-parent"),true);
    assert.equal(state.files.has("docs/pinned-parent"),false);

    await reset();
    const upload = join(outputDir,"directory-bound-upload.txt"); await writeFile(upload,"fixture content\n");
    await page.click("#files-upload");
    await page.click(file("docs")); await page.waitVisible('[data-path="docs/config.txt"]');
    await attach(upload); await delay(150);
    assert.equal(fileWrites().length,0,"directory change cancels the older chooser target");
  });

  await test("a file chooser from an old node cannot upload into the new context", async () => {
    await reset();
    const path = join(outputDir,"node-bound-upload.txt"); await writeFile(path,"fixture content\n");
    const before = fileWrites().length;
    await page.click("#files-upload");
    await page.selectAgent("node-b"); await page.waitVisible('[data-id="bravo"]');
    await attach(path); await delay(150);
    assert.equal(fileWrites().length,before);
    assert.equal(await value("#agent-select"),"node-b");
  });

  await test("logs distinguish empty, failure and retained snapshots and reject old services", async () => {
    await reset("logs"); await eventually(() => text("#logs-view").then((value) => value.includes("web ready")),"initial web snapshot");
    const previous = await text("#logs-view");
    state.logsError = true; await page.click("#logs-refresh"); await eventually(() => page.evaluate(`document.querySelector('#logs-status').dataset.error === 'true'`),"failed snapshot");
    assert.equal(await text("#logs-view"),previous);
    assert.match(await text("#logs-status"),/保留上次快照/);
    state.logsError = false;
    const old = hold("/api/apps/alpha/logs"); await page.click("#logs-refresh"); await eventually(() => old.seen,"held old web snapshot"); old.detach();
    await choose("#logs-service","worker"); await eventually(() => text("#logs-view").then((value) => value.includes("worker ready")),"new worker snapshot");
    old.release(); await delay(150); assert.match(await text("#logs-view"),/worker ready/); assert.doesNotMatch(await text("#logs-view"),/web ready/);
    state.logs.worker = ""; await page.click("#logs-refresh"); await page.waitVisible("#logs-empty");
    assert.equal(await text("#logs-view"),"");
    state.logs.worker = "worker ready\n"; await page.click("#logs-refresh"); await eventually(() => text("#logs-view").then((value) => value.includes("worker ready")),"snapshot restored");
    await capture("logs",1440); await capture("logs",375);
    await reset("logs","alpha",() => {state.logsError = true;});
    await eventually(() => text("#logs-status").then((message) => message.includes("日志读取失败")),"initial log read failure");
    assert.equal(await text("#logs-view"),"");
    assert.equal(await page.visible("#logs-empty"),false,"first-read failure is not an empty successful snapshot");
    await reset("logs","no-ports");
    assert.match(await text("#logs-status"),/没有可查看的服务/);
    assert.equal(state.logsCalls.length,0);
  });

  await test("logs poll every four seconds and pause/leave invalidate in-flight reads", async () => {
    await reset("logs"); await eventually(() => state.logsCalls.length >= 1,"first snapshot read");
    const first = state.logsCalls.at(-1).at;
    await eventually(() => state.logsCalls.length >= 2,"four-second poll",7000);
    assert.ok(state.logsCalls.at(-1).at - first >= 3500,"poll is a four-second snapshot interval");
    const previous = await text("#logs-view");
    const held = hold("/api/apps/alpha/logs"); state.logs.web = "must-not-overwrite-paused\n";
    await page.click("#logs-refresh"); await eventually(() => held.seen,"held snapshot before pause");
    await page.click("#logs-pause"); held.release(); await delay(150);
    assert.equal(await text("#logs-view"),previous);
    const pausedCount = state.logsCalls.length; await delay(4300); assert.equal(state.logsCalls.length,pausedCount);
    await page.click("#logs-refresh"); await eventually(() => state.logsCalls.length === pausedCount + 1,"manual snapshot while paused");
    assert.equal(await page.evaluate(`document.querySelector('#logs-pause').getAttribute('aria-pressed')`),"true");
    await page.click("#logs-pause"); await eventually(() => text("#logs-view").then((value) => value.includes("must-not-overwrite-paused")),"resume snapshot");
    await page.click('#detail-nav [data-section="overview"]');
    const leftCount = state.logsCalls.length; await delay(4300); assert.equal(state.logsCalls.length,leftCount);
  });

  await test("hidden browser document suspends polling and resumes when visible", async () => {
    await reset("logs"); await eventually(() => state.logsCalls.length > 0,"initial snapshot");
    const {targetInfo} = await page.send("Target.getTargetInfo",{});
    const other = await page.send("Target.createTarget",{url:"about:blank"});
    await page.send("Target.activateTarget",{targetId:other.targetId});
    await eventually(() => page.evaluate(`document.visibilityState === 'hidden'`),"browser tab becomes hidden");
    const hiddenCount = state.logsCalls.length; await delay(4300); assert.equal(state.logsCalls.length,hiddenCount);
    await page.send("Target.closeTarget",{targetId:other.targetId}); await page.send("Target.activateTarget",{targetId:targetInfo.targetId});
    await eventually(() => state.logsCalls.length > hiddenCount,"visible tab resumes snapshot");
  });

  await test("HTTP entries identify domains, ports, enabled state and actual visit URLs", async () => {
    await reset("http");
    const main = '[data-rule-ref="web-entry"]';
    const api = '[data-rule-ref="api-entry"]';
    assert.match(await text(main),/8080.*访问目标：http:\/\/web.example.test\/media/);
    assert.equal(await page.evaluate(`document.querySelector('${main} a').href`),"http://web.example.test/media");
    assert.match(await text(api),/9090/);
    assert.equal(await page.evaluate(`document.querySelector('${api} a').href`),"https://api.example.test/");
    assert.match(await text('[data-rule-ref="disabled-entry"]'),/已停用/);
    assert.equal(await page.visible('[data-rule-ref="disabled-entry"] a'),false);
    await capture("http-entries",1440); await capture("http-entries",375);
    await reset("http","no-ports");
    assert.ok(await page.visible(".http-empty")); assert.ok(await page.visible(".http-no-ports"));
    assert.equal(await page.visible(".http-form"),false);
  });

  await test("HTTP read failure is independent and retry preserves usable application data", async () => {
    await reset("http","alpha",() => {state.rulesError = true;});
    assert.match(await text("#http-feedback"),/读取失败/);
    assert.equal(await page.visible(".http-empty"),false,"read failure must not claim an empty rule list");
    assert.ok(await page.visible("#detail-title"));
    await fill('.http-form input[name="domain"]',"draft.example.test");
    state.rulesError = false; await page.click('[data-action="refresh-http"]'); await page.waitVisible('[data-rule-ref="web-entry"]');
    assert.equal(await value('.http-form input[name="domain"]'),"draft.example.test");
    assert.equal(await page.visible("#http-feedback"),false);
  });

  await test("HTTP create/delete cancel, failure and successful refresh follow the host result", async () => {
    await reset("http");
    await choose('.http-form select[name="port"]',"9090"); await fill('.http-form input[name="domain"]',"new.example.test");
    await page.click('.http-form button[type="submit"]'); await close(false); await idle(); assert.equal(ruleWrites().length,0);
    state.rulesWriteError = true; await page.click('.http-form button[type="submit"]'); await close(true); await status("failed"); await idle();
    assert.equal(await value('.http-form input[name="domain"]'),"new.example.test"); assert.equal(state.apps[0].rules.length,3);
    state.rulesWriteError = false; await page.click('.http-form button[type="submit"]'); await close(true); await status("succeeded"); await idle();
    assert.deepEqual(ruleWrites().at(-1).body,{domain:"new.example.test",port:9090});
    await page.waitVisible('[data-rule-ref="created-entry"]');
    const remove = '[data-rule-ref="created-entry"] [data-action="delete-http"]';
    const before = ruleWrites().length;
    await page.click(remove); await close(false); await idle(); assert.equal(ruleWrites().length,before);
    state.rulesWriteError = true; await page.click(remove); await close(true); await status("failed"); await idle();
    assert.ok(await page.visible('[data-rule-ref="created-entry"]'));
    state.rulesWriteError = false; await page.click(remove); await close(true); await status("succeeded"); await idle();
    assert.equal(await page.visible('[data-rule-ref="created-entry"]'),false);
    state.rulesErrorAfterWrite = true;
    await fill('.http-form input[name="domain"]',"partial.example.test"); await page.click('.http-form button[type="submit"]'); await close(true); await status("partial"); await idle();
    assert.match(await text("#app-status"),/已创建.*刷新失败/);
    assert.ok(state.apps[0].rules.some((rule) => rule.domain === "partial.example.test"));
  });
}
