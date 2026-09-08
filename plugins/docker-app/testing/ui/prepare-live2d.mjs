import { mkdir, writeFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

// Download official sample data for local evaluation, outside the shipped package.
const output = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../dist/docker-app-live2d-preview");
const revision = "b1de66b0b1f1cb881d95fb6158622aeb6a2827bd";
const base = `https://raw.githubusercontent.com/Live2D/CubismWebSamples/${revision}/Samples/Resources/Hiyori/`;
const inventory = [];
async function download(name, url) {
  const response = await fetch(url, {signal:AbortSignal.timeout(60000)});
  if (!response.ok) throw new Error(`${response.status}: ${url}`);
  const data = Buffer.from(await response.arrayBuffer());
  const target = resolve(output, name);
  await mkdir(dirname(target), {recursive:true});
  await writeFile(target, data);
  inventory.push({name,url,sha256:createHash("sha256").update(data).digest("hex"),bytes:data.length});
  console.log(`Downloaded ${name} (${data.length} bytes)`);
  return data;
}
const model = JSON.parse(await download("Hiyori/Hiyori.model3.json",base+"Hiyori.model3.json"));
const refs = model.FileReferences;
const files = [refs.Moc, ...refs.Textures, refs.Physics, refs.Pose, refs.UserData, refs.DisplayInfo, ...Object.values(refs.Motions).flat().map(m=>m.File)].filter(Boolean);
const resources = [
  ...files.map(name=>[`Hiyori/${name}`,base+name]),
  ["pixi.min.js","https://cdn.jsdelivr.net/npm/pixi.js@6.5.10/dist/browser/pixi.min.js"],
  ["cubism4.min.js","https://cdn.jsdelivr.net/npm/pixi-live2d-display@0.4.0/dist/cubism4.min.js"],
  ["live2dcubismcore.min.js","https://cubism.live2d.com/sdk-web/cubismcore/live2dcubismcore.min.js"],
];
for (let i=0;i<resources.length;i+=4) await Promise.all(resources.slice(i,i+4).map(([name,url])=>download(name,url)));
await writeFile(resolve(output,"sources.json"),JSON.stringify({revision,usage:"Local preview only; not included in official plugin packages",model:"Hiyori Momose © Live2D Inc.",terms:"https://www.live2d.com/en/learn/sample/model-terms/",license:"https://www.live2d.com/eula/live2d-free-material-license-agreement_en.html",files:inventory},null,2)+"\n");
console.log(`Prepared local Live2D preview in ${output}`);
