import { mountCompanion } from "/companion.js";
const artwork = await fetch("/__preview/live2d/reference/character.json").then(r=>r.ok?r.json():null).catch(()=>null);
await mountCompanion({
  assetBase: new URL("/__preview/live2d/reference/", location.href),
  image: "character.webp",
  expressions: artwork?.expressions || {},
  title: artwork?.title || "本地立绘预览",
  note: artwork?.note || "本地素材预览。",
});
