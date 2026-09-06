import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";

export async function runCompose({ page, test, navigate, hold, requests, state, capture, eventually }) {
  const yaml = 'services:\n  web:\n    image: nginx:1.27\n';
  const draftYAML = 'services:\n  draft:\n    image: nginx:1.28\n';
  const value = (selector) => page.evaluate(`document.querySelector(${JSON.stringify(selector)}).value`);
  const text = (selector) => page.evaluate(`document.querySelector(${JSON.stringify(selector)}).textContent`);
  const fill = async (selector, content) => {
    await page.click(selector);
    await page.evaluate("document.activeElement.select()");
    await page.send("Input.insertText", { text: content });
  };
  const reset = async () => {
    Object.assign(state, { previewError:"", saveError:"", listError:false, detailError:false, risk:false, fileError:false, fileListError:false });
    await navigate("?agent_id=node-a"); await page.waitVisible('[data-id="alpha"]');
  };
  const create = async () => { await page.click("#deploy-toggle"); await page.waitVisible("#create-form"); };
  const detail = async () => {
    await page.click('[data-id="alpha"] [data-action="detail"]'); await page.waitVisible("#app-detail");
    await page.click('#detail-nav [data-section="compose"]'); await page.waitVisible("#compose-form");
  };
  const confirm = async (ok) => {
    await page.waitVisible("#confirm-dialog");
    await page.click(ok ? "#confirm-ok" : "#confirm-cancel");
    await eventually(async () => !(await page.visible("#confirm-dialog")), "confirmation closed");
    await page.evaluate("new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))");
  };
  const formState = async (form, expected) => eventually(
    () => page.evaluate(`document.querySelector(${JSON.stringify(form + " [data-form-feedback]")}).dataset.state === ${JSON.stringify(expected)}`),
    `${form} reports ${expected}`);

  await test("complete deployment editor, template protection and node context", async () => {
    await reset(); await create();
    assert.match(await text("#create-context"), /节点 A/);
    assert.equal(await page.evaluate(`document.querySelector('#create-form input[name="auto_update"]').checked`), false);
    await page.click('[data-template="site"]');
    assert.match(await value('#create-form textarea[name="compose"]'), /nginx/);
    await fill('#create-form input[name="id"]', "draft-template");
    await fill('#create-form textarea[name="compose"]', draftYAML);
    await page.click('[data-template="media"]'); await confirm(false);
    assert.equal(await value('#create-form textarea[name="compose"]'), draftYAML);
    await page.click('[data-template="media"]'); await confirm(true);
    assert.match(await value('#create-form textarea[name="compose"]'), /jellyfin/);
    assert.equal(await value('#create-form input[name="id"]'), "draft-template");
    await capture("deployment", 1440); await capture("deployment", 375);
    await page.click("#create-back"); await confirm(false);
    assert.ok(await page.visible("#create-form"));
  });

  await test("deployment dirty navigation, refresh and browser unload protection", async () => {
    await reset(); await create();
    await fill('#create-form input[name="id"]', "navigation-draft");
    await fill('#create-form textarea[name="compose"]', draftYAML);
    for (const trigger of [() => page.click("#create-cancel"), () => page.click("#workspace-refresh"), () => page.selectAgent("node-b")]) {
      await trigger(); await confirm(false);
      assert.ok(await page.visible("#create-form"));
      assert.equal(await value('#create-form textarea[name="compose"]'), draftYAML);
      assert.equal(await value("#agent-select"), "node-a");
    }
    const previous = page.javascriptDialogs.length;
    await navigate("?agent_id=node-a");
    assert.ok(page.javascriptDialogs.slice(previous).includes("beforeunload"), "dirty document requests native unload confirmation");
    await page.waitVisible('[data-id="alpha"]');
    await create(); await fill('#create-form textarea[name="compose"]', yaml);
    await page.selectAgent("node-b"); await confirm(true); await page.waitVisible('[data-id="bravo"]');
    assert.equal(await value("#agent-select"), "node-b");
    assert.equal(await page.visible("#create-form"), false);
  });

  await test("required and invalid Compose feedback preserves inputs", async () => {
    await reset(); await create();
    const previews = state.previewCount;
    await page.click("#create-submit"); await formState("#create-form", "failed");
    assert.equal(state.previewCount, previews, "missing required input must not issue preview");
    await fill('#create-form input[name="id"]', "invalid-compose");
    await fill('#create-form textarea[name="compose"]', "invalid yaml");
    await page.click("#create-submit"); await formState("#create-form", "failed");
    await eventually(() => state.previewCount === previews + 1, "invalid Compose preview completed");
    assert.equal(await value('#create-form textarea[name="compose"]'), "invalid yaml");
    await fill('#create-form textarea[name="compose"]', 'services:\n  web:\n    image: nginx\n    environment:\n      VALUE: ${REQUIRED_VALUE:?required}\n');
    await page.click("#create-submit"); await eventually(() => text("#create-feedback").then((message) => message.includes("环境变量")), "required environment feedback");
    assert.match(await value('#create-form textarea[name="compose"]'), /REQUIRED_VALUE/);
  });

  await test("template deployment succeeds with automatic updates off", async () => {
    await reset(); await create();
    await page.click('[data-template="site"]');
    await fill('#create-form input[name="id"]', "template-site");
    const saves = state.saveCount;
    await page.click("#create-submit"); await page.waitVisible('[data-id="template-site"]');
    assert.equal(state.saveCount, saves + 1);
    assert.equal(state.lastSave.auto_update, false);
    assert.match(state.lastSave.compose, /nginx:1.27/);
    assert.equal(await page.visible("#create-form"), false);
  });

  await test("failed deployment retains env without browser persistence", async () => {
    await reset(); await create();
    const env = "FIXTURE_VALUE=memory-only-marker";
    await fill('#create-form input[name="id"]', "failed-save");
    await fill('#create-form textarea[name="compose"]', yaml);
    await fill('#create-form textarea[name="env"]', env);
    state.saveError = "节点部署失败，请稍后重试。";
    await page.click("#create-submit"); await formState("#create-form", "failed");
    assert.equal(await value('#create-form textarea[name="env"]'), env);
    assert.equal(await value('#create-form textarea[name="compose"]'), yaml);
    assert.equal(state.lastSave.agent_id, "node-a");
    assert.equal(state.lastSave.env, env);
    assert.equal(await page.evaluate(`JSON.stringify([Object.entries(localStorage),Object.entries(sessionStorage)]).includes('memory-only-marker')`), false);
    assert.equal((await text("#app-status")).includes("memory-only-marker"), false);
  });

  await test("busy confirmation sends once and success survives refresh failure", async () => {
    await reset(); await create();
    await fill('#create-form input[name="id"]', "saved-once");
    await fill('#create-form textarea[name="compose"]', yaml);
    await fill('#create-form textarea[name="env"]', "FIXTURE_VALUE=memory-only-marker");
    state.risk = true;
    const saves = state.saveCount;
    const pending = hold("/api/apps/preview");
    await page.click("#create-submit"); await eventually(() => pending.seen, "preview held");
    assert.equal(await page.evaluate(`document.querySelector('#create-submit').disabled`), true);
    assert.equal(await page.evaluate(`document.querySelector('.agent-search-select__trigger').disabled`), true);
    // Enter in the disabled form cannot submit a second request.
    await page.key("Enter");
    pending.release(); await page.waitVisible("#confirm-dialog");
    await confirm(false);
    assert.equal(state.saveCount, saves);
    assert.equal(await value('#create-form textarea[name="env"]'), "FIXTURE_VALUE=memory-only-marker");
    await page.click("#create-submit"); await page.waitVisible("#confirm-dialog");
    state.listError = true;
    await confirm(true);
    await eventually(() => page.evaluate(`document.querySelector('#app-status').dataset.state === 'partial'`), "success with refresh failure");
    assert.equal(state.saveCount, saves + 1);
    assert.match(await text("#app-status"), /已部署.*刷新失败/);
    assert.equal(await value('#create-form textarea[name="env"]'), "");
    assert.equal(await page.visible("#create-form"), false);
    state.listError = false;
    await page.click("#workspace-refresh"); await page.waitVisible('[data-id="saved-once"]');
    assert.equal(state.saveCount, saves + 1, "refresh never repeats submission");
  });

  await test("Compose draft survives section changes and cancelled leaving or refresh", async () => {
    await reset(); await detail();
    await fill('#compose-form textarea[name="compose"]', draftYAML);
    await page.click('#detail-nav [data-section="overview"]');
    await page.click('#detail-nav [data-section="compose"]');
    assert.equal(await value('#compose-form textarea[name="compose"]'), draftYAML);
    for (const trigger of [() => page.click("#detail-back"), () => page.click("#workspace-refresh"), () => page.selectAgent("node-b")]) {
      await trigger(); await confirm(false);
      assert.equal(await value('#compose-form textarea[name="compose"]'), draftYAML);
      assert.equal(await value("#agent-select"), "node-a");
      assert.ok(await page.visible("#compose-form"));
    }
    await capture("compose-editor", 1440); await capture("compose-editor", 375);
    await page.click("#workspace-refresh"); await confirm(true); await page.waitVisible("#compose-form");
    await eventually(() => value('#compose-form textarea[name="compose"]').then((v) => v !== draftYAML), "confirmed refresh replaces draft");
  });

  await test("code editors indent with Tab and save Compose with Ctrl+S", async () => {
    await reset(); await create();
    await fill('#create-form textarea[name="compose"]', yaml);
    await page.evaluate(`(() => {
      const node = document.querySelector('#create-form textarea[name="compose"]');
      node.focus();
      node.setSelectionRange(0, 0);
    })()`);
    await page.key("Tab");
    assert.equal(await value('#create-form textarea[name="compose"]'), `  ${yaml}`, "Tab inserts a two-space indent");
    assert.ok(await page.evaluate(`document.activeElement.matches('#create-form textarea[name="compose"]')`), "Tab keeps focus in the editor");
    await page.key("Tab", {shift:true});
    assert.equal(await value('#create-form textarea[name="compose"]'), yaml);
    assert.ok(await page.evaluate(`document.activeElement.matches('#create-form textarea[name="compose"]')`), "Shift+Tab keeps focus in the editor");
    await page.click("#create-cancel"); await confirm(true); await page.waitVisible("#app-list");
    await detail();
    await fill('#compose-form textarea[name="compose"]', draftYAML);
    await page.key("s", {ctrl:true});
    await formState("#compose-form", "succeeded");
    assert.equal(state.lastSave.compose, draftYAML);
  });

  await test("Compose failures retain env; successful save persists env and resets baseline", async () => {
    await reset(); await detail();
    await fill('#compose-form textarea[name="compose"]', draftYAML);
    await fill('#compose-form textarea[name="env"]', "FIXTURE_VALUE=compose-memory-marker");
    state.saveError = "保存失败，请检查配置。";
    await page.click("#compose-submit"); await formState("#compose-form", "failed");
    assert.equal(await value('#compose-form textarea[name="env"]'), "FIXTURE_VALUE=compose-memory-marker");
    state.saveError = ""; state.listError = true;
    const saves = state.saveCount;
    await page.click("#compose-submit"); await formState("#compose-form", "partial");
    assert.equal(state.saveCount, saves + 1);
    assert.equal(await value('#compose-form textarea[name="env"]'), "FIXTURE_VALUE=compose-memory-marker");
    assert.equal(await page.visible("#compose-dirty"), false);
    state.listError = false;
    await page.click("#workspace-refresh"); await page.waitVisible("#compose-form");
    await fill('#compose-form textarea[name="env"]', "");
    await page.click("#compose-submit"); await eventually(() => state.saveCount === saves + 2, "second save with blank env");
    assert.equal(state.lastSave.env, "", "blank env is forwarded for server-side reuse");
    await eventually(() => page.evaluate(`document.querySelector('#app-status').dataset.state === 'succeeded'`), "save success feedback");
    assert.equal(await value('#compose-form textarea[name="env"]'), "FIXTURE_VALUE=compose-memory-marker", "detail refresh restores reused env");
    await page.click("#detail-back"); await page.waitVisible("#app-list");
    assert.equal(await page.visible("#confirm-dialog"), false, "successful baseline needs no discard confirmation");
  });

  await test("edits made during list or detail refresh keep their values and dirty baseline", async () => {
    for (const [path, failure] of [["/api/apps?agent_id=node-a", false], ["/api/apps/alpha", false], ["/api/apps/alpha", true]]) {
      await reset(); await detail();
      const pending = hold(path);
      await page.click("#workspace-refresh"); await eventually(() => pending.seen, `held refresh ${path}`);
      const fresh = 'services:\n  freshdraft:\n    image: nginx:1.29\n';
      const env = "FIXTURE_REFRESH=retain-in-memory";
      await fill('#compose-form textarea[name="compose"]', fresh);
      await fill('#compose-form textarea[name="env"]', env);
      await page.click('#compose-form input[name="auto_update"]');
      const enabled = await page.evaluate(`document.querySelector('#compose-form input[name="auto_update"]').checked`);
      const saves = state.saveCount;
      state.detailError = failure;
      pending.release(); await delay(150);
      assert.equal(await value('#compose-form textarea[name="compose"]'), fresh, `YAML remains after ${path}`);
      assert.equal(await value('#compose-form textarea[name="env"]'), env, `env remains after ${path}`);
      assert.equal(await page.evaluate(`document.querySelector('#compose-form input[name="auto_update"]').checked`), enabled);
      assert.ok(await page.visible("#compose-dirty"), "late response must not capture the new draft as saved");
      assert.equal(await page.visible("#confirm-dialog"), false, "preserving the newer input needs no prompt");
      assert.equal(state.saveCount, saves);
      await page.click("#detail-back"); await confirm(false);
      assert.equal(await value('#compose-form textarea[name="compose"]'), fresh);
      assert.equal(await value('#compose-form textarea[name="env"]'), env);
    }
  });

  await test("late file read cannot replace a newer file draft", async () => {
    await reset(); await detail();
    await page.click('#detail-nav [data-section="files"]'); await page.waitVisible('[data-path="config.txt"]');
    await page.click('[data-path="config.txt"] .files-name');
    const pending = hold("/api/apps/alpha/files");
    await page.click("#files-edit"); await eventually(() => pending.seen, "held old file read");
    await page.click("#files-new-text"); await page.waitVisible("#files-new-dialog");
    await fill("#files-new-name", "draft.txt");
    await page.click('#files-new-form button[type="submit"]'); await page.waitVisible("#files-editor");
    await fill("#files-editor textarea", "new file draft\n");
    pending.release(); await delay(150);
    assert.equal(await value("#files-editor textarea"), "new file draft\n");
    assert.match(await text("#files-editor-name"), /draft.txt/);
    assert.ok(await page.visible("#files-dirty"));
  });

  await test("older reads cannot invalidate a pending Compose save or confirmation", async () => {
    for (const [oldPath, phase, outcome] of [
      ["/api/apps?agent_id=node-a", "save", "success"],
      ["/api/apps/alpha", "save", "success"],
      ["/api/apps?agent_id=node-a", "preview", "success"],
      ["/api/apps/alpha", "confirmation", "success"],
      ["/api/apps?agent_id=node-a", "confirmation", "cancel"],
      ["/api/apps/alpha", "save", "failure"],
    ]) {
      await reset(); await detail();
      const oldRead = hold(oldPath);
      await page.click("#workspace-refresh"); await eventually(() => oldRead.seen, "old refresh held before save");
      await fill('#compose-form textarea[name="compose"]', 'services:\n  saved:\n    image: nginx:1.30\n');
      const draftEnv = `FIXTURE_SAVE=${phase}-${outcome}-${oldPath}`;
      await fill('#compose-form textarea[name="env"]', draftEnv);
      const saves = state.saveCount;
      const write = hold("/api/apps");
      const preview = phase === "preview" ? hold("/api/apps/preview") : null;
      state.risk = phase === "confirmation";
      state.saveError = outcome === "failure" ? "保存失败，请稍后重试。" : "";
      await page.click("#compose-submit");
      if (phase === "preview") await eventually(() => preview.seen, "save preview held");
      else if (phase === "confirmation") await page.waitVisible("#confirm-dialog");
      else await eventually(() => write.seen, "save response held");
      oldRead.release(); await delay(150);
      if (preview) preview.release();
      if (phase === "confirmation") await confirm(outcome !== "cancel");
      if (outcome !== "cancel") await eventually(() => write.seen, "one save request reached server");
      write.release();
      await eventually(() => page.evaluate(`document.querySelector('#compose-submit').disabled === false`), "save controls restored");
      assert.equal(state.saveCount, saves + (outcome === "cancel" ? 0 : 1));
      if (outcome === "success") {
        assert.equal(await value('#compose-form textarea[name="env"]'), draftEnv, `successful env restore with old ${oldPath} during ${phase}`);
        assert.equal(await page.visible("#compose-dirty"), false);
        assert.equal(await page.evaluate(`document.querySelector('#app-status').dataset.state`), "succeeded");
        assert.match(await text("#app-status"), /已更新/);
      } else {
        assert.equal(await value('#compose-form textarea[name="env"]'), draftEnv);
        assert.ok(await page.visible("#compose-dirty"), `unsaved env stays dirty with old ${oldPath} during ${phase}/${outcome}`);
        await formState("#compose-form", outcome === "cancel" ? "cancelled" : "failed");
      }
    }
  });

  await test("deployment and file saves also supersede older workspace reads", async () => {
    await reset(); await detail();
    const oldList = hold("/api/apps?agent_id=node-a");
    await page.click("#workspace-refresh"); await eventually(() => oldList.seen, "old list held before deployment");
    await page.click("#detail-back");
    await create();
    await fill('#create-form input[name="id"]', "overlap-deploy");
    await fill('#create-form textarea[name="compose"]', yaml);
    await fill('#create-form textarea[name="env"]', "FIXTURE_SAVE=deployment-memory");
    const saves = state.saveCount;
    const deployment = hold("/api/apps");
    await page.click("#create-submit"); await eventually(() => deployment.seen, "deployment response held");
    oldList.release(); await delay(150);
    assert.ok(await page.visible("#create-form"));
    assert.equal(await page.evaluate(`document.querySelector('#create-submit').disabled`), true);
    deployment.release(); await page.waitVisible('[data-id="overlap-deploy"]');
    await eventually(() => page.evaluate(`document.querySelector('#app-status').dataset.state === 'succeeded'`), "deployment success");
    assert.equal(state.saveCount, saves + 1);
    assert.equal(await value('#create-form textarea[name="env"]'), "");
    assert.equal(await page.visible("#create-dirty"), false);

    await reset(); await detail();
    await page.click('#detail-nav [data-section="files"]'); await page.waitVisible('[data-path="config.txt"]');
    await page.click('[data-path="config.txt"] .files-name'); await page.click("#files-edit"); await page.waitVisible("#files-editor");
    const oldDetail = hold("/api/apps/alpha");
    await page.click("#workspace-refresh"); await eventually(() => oldDetail.seen, "old detail held before file save");
    await fill("#files-editor textarea", "file saved during refresh\n");
    const writes = requests.filter((request) => request.action === "write").length;
    const fileSave = hold("/api/apps/alpha/files");
    await page.click("#files-save"); await eventually(() => fileSave.seen, "file save held");
    oldDetail.release(); await delay(150);
    fileSave.release();
    await eventually(() => page.evaluate(`document.querySelector('#files-save').disabled === false`), "file controls restored");
    assert.equal(state.file, "file saved during refresh\n");
    assert.equal(requests.filter((request) => request.action === "write").length, writes + 1);
    assert.equal(await page.visible("#files-dirty"), false);
    assert.equal(await page.evaluate(`document.querySelector('#app-status').dataset.state`), "succeeded");
    assert.match(await text("#files-editor-name"), /config.txt/);
  });

  await test("file editing uses the shared draft guard and failed saves retain input", async () => {
    await reset(); await detail();
    await page.click('#detail-nav [data-section="files"]'); await page.waitVisible('[data-path="config.txt"]');
    await page.click('[data-path="config.txt"] .files-name'); await page.click("#files-edit"); await page.waitVisible("#files-editor");
    await fill("#files-editor textarea", "file draft\n");
    await page.click("#detail-back"); await confirm(false);
    assert.equal(await value("#files-editor textarea"), "file draft\n");
    await page.click('#detail-nav [data-section="compose"]'); await confirm(false);
    assert.ok(await page.visible("#files-editor"));
    state.fileError = true;
    await page.click("#files-save"); await eventually(() => text("#app-status").then((v) => v.includes("文件保存失败")), "file failure");
    assert.equal(await value("#files-editor textarea"), "file draft\n");
    state.fileError = false;
    state.fileListError = true;
    await page.click("#files-save"); await eventually(() => state.file === "file draft\n", "file saved");
    await eventually(() => page.evaluate(`document.querySelector('#detail-back').disabled === false`), "file save controls restored");
    assert.equal(await page.evaluate(`document.querySelector('#app-status').dataset.state`), "partial");
    assert.equal(await page.visible("#files-dirty"), false);
    state.fileListError = false;
    await page.click("#detail-back"); await page.waitVisible("#app-list");
    assert.equal(await page.visible("#confirm-dialog"), false);
    assert.equal(requests.filter((r) => /install|configure$/.test(r.path)).length, 0);
  });
}
