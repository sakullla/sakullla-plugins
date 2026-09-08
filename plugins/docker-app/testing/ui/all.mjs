import { UI_ASSETS } from "./assets.mjs";
import { spawn } from "node:child_process";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createHash } from "node:crypto";

export async function runAll({runner,repo,assets}) {
  const started = new Date().toISOString();
  const digest = createHash("sha256");
  for (const name of UI_ASSETS) digest.update(await readFile(resolve(assets,name)));
  const fingerprint = digest.digest("hex");
  const suites = ["workspace","compose","operations","resources","experience"];
  const report = {kind:"fixture-browser-aggregate",suite:"all",started_at:started,assets_sha256:fingerprint,results:[]};
  let failed = false;
  for (const suite of suites) {
    const exit = await new Promise((done) => {
      const child = spawn(process.execPath,[runner,"--suite",suite],{stdio:"inherit",windowsHide:true});
      child.once("error",() => done(-1)); child.once("exit",(code) => done(code ?? -1));
    });
    let evidence;
    try { evidence = JSON.parse(await readFile(resolve(repo,`dist/docker-app-ui-validation/${suite}.json`),"utf8")); } catch {}
    const passed = exit === 0 && evidence?.status === "passed" && evidence.suite === suite
      && evidence.started_at >= started && evidence.assets_sha256 === fingerprint && evidence.results?.length > 0;
    report.results.push({suite,status:passed ? "passed" : "failed",exit_code:exit,checks:evidence?.results?.length || 0,ref:`dist/docker-app-ui-validation/${suite}.json`});
    if (!passed) failed = true;
  }
  report.finished_at = new Date().toISOString(); report.status = failed ? "failed" : "passed";
  await mkdir(resolve(repo,"dist/docker-app-ui-validation"),{recursive:true});
  await writeFile(resolve(repo,"dist/docker-app-ui-validation/all.json"),JSON.stringify(report,null,2)+"\n");
  if (failed) throw new Error("Required browser suite missing, stale or failed; inspect all.json.");
}
