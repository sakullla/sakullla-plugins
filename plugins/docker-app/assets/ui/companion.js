// Package-owned companion artwork. Expression frames are not a Live2D mesh.
export async function mountCompanion({
  assetBase = new URL(".", import.meta.url),
  image = "companion-idle.webp",
  expressions = {blink:"companion-blink.webp",wink:"companion-wink.webp"},
  title = "看板娘",
  note = "",
} = {}) {
  if(document.readyState==="loading")await new Promise(resolve=>document.addEventListener("DOMContentLoaded",resolve,{once:true}));
  const companion=document.querySelector("#companion-assistant"),toggle=document.querySelector("#companion-toggle");
  companion.dataset.renderer="loading";
  // A decoded HTTP URL can be fetched again when assigned to another image.
  // Keep validated image bytes locally so animation survives a server outage.
  const imageURLs=new Set();
  const loadImage=async path=>{
    const response=await fetch(new URL(path,assetBase));
    if(!response.ok)throw new Error("Portrait image is unavailable");
    const url=URL.createObjectURL(await response.blob());
    const decoded=new Image();decoded.src=url;
    try {await decoded.decode();} catch(error) {URL.revokeObjectURL(url);throw error;}
    imageURLs.add(url);
    return decoded;
  };
  window.addEventListener("pagehide",event=>{
    if(!event.persisted)for(const url of imageURLs)URL.revokeObjectURL(url);
  });
  let portrait;
  try {portrait=await loadImage(image);}
  catch {companion.dataset.renderer="failed";return;}
  portrait.className="companion-portrait";portrait.alt="";portrait.draggable=false;
  toggle.querySelector(".console-companion")?.remove();toggle.prepend(portrait);companion.dataset.renderer="portrait";
  document.querySelector("#companion-title").textContent=title;
  if(note){const credit=document.createElement("p");credit.className="companion-credit";credit.textContent=note;document.querySelector("#companion-panel").append(credit);}
  const zoom=document.createElement("button");zoom.type="button";zoom.className="btn-secondary";zoom.textContent="放大立绘";
  document.querySelector(".companion-shortcuts").append(zoom);
  const dialog=document.createElement("dialog");dialog.className="portrait-dialog";dialog.setAttribute("aria-label","高清立绘");
  const full=portrait.cloneNode();full.className="portrait-dialog-image";
  const close=document.createElement("button");close.type="button";close.className="btn-secondary";close.textContent="关闭";
  dialog.append(full,close);document.body.append(dialog);
  close.addEventListener("click",()=>dialog.close());zoom.addEventListener("click",()=>{dialog.showModal();close.focus();});
  let paused=matchMedia("(prefers-reduced-motion: reduce)").matches;
  const frames={idle:portrait.src};
  await Promise.all(Object.entries(expressions).map(async ([name,file])=>{
    if(!["idle","blink","wink"].includes(name)||!/^[a-zA-Z0-9_-]+\.webp$/.test(file))return;
    try {const frame=await loadImage(file);frames[name]=frame.src;}
    catch { /* Keep the usable neutral portrait. */ }
  }));
  companion.dataset.expressionFrames=String(Object.keys(frames).length);
  let blinkTimer,restoreTimer,taps=0,blinkCount=0;
  const setFrame=name=>{portrait.src=frames[name] || frames.idle;companion.dataset.expression=name;};
  const visible=()=>!document.hidden&&companion.dataset.minimized!=="true"&&!document.querySelector("dialog[open]");
  const clear=()=>{clearTimeout(blinkTimer);clearTimeout(restoreTimer);};
  const scheduleBlink=()=>{
    clearTimeout(blinkTimer);
    if(paused||!visible()||!frames.blink)return;
    blinkTimer=setTimeout(()=>{
      if(paused||!visible())return;
      setFrame("blink");companion.dataset.blinkCount=String(++blinkCount);
      restoreTimer=setTimeout(()=>{setFrame("idle");scheduleBlink();},145);
    },2800+Math.random()*2500);
  };
  const sync=()=>{clear();setFrame("idle");companion.dataset.motion=paused?"paused":"playing";scheduleBlink();};
  document.addEventListener("companion-motion",()=>{
    if(paused||!visible())return;
    clear();
    if(frames.wink&&frames.blink){
      setFrame(taps++%2 ? "blink" : "wink");
      companion.dataset.lastInteraction=String(Date.now());
      restoreTimer=setTimeout(()=>{setFrame("idle");scheduleBlink();},850);
    } else {
      portrait.animate([{transform:"translateY(0)"},{transform:"translateY(-4px)",offset:.4},{transform:"translateY(0)"}],{duration:450,easing:"ease-in-out"});
      scheduleBlink();
    }
  });
  document.addEventListener("companion-pause",event=>{paused=event.detail.paused;sync();});
  document.addEventListener("visibilitychange",sync);
  new MutationObserver(sync).observe(companion,{attributes:true,attributeFilter:["data-minimized"]});
  new MutationObserver(sync).observe(document.body,{subtree:true,attributes:true,attributeFilter:["open"]});
  const preference=matchMedia("(prefers-reduced-motion: reduce)");
  preference.addEventListener("change",()=>{paused=preference.matches;sync();});
  sync();
}

if (!document.querySelector('meta[name="nre-companion-preview"]')) {
  mountCompanion();
}
