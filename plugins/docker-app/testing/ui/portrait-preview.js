// Local artwork study. Static artwork is kept distinct from a rigged model.
(async () => {
  if(document.readyState==="loading")await new Promise(resolve=>document.addEventListener("DOMContentLoaded",resolve,{once:true}));
  const companion=document.querySelector("#companion-assistant"),toggle=document.querySelector("#companion-toggle");
  companion.dataset.renderer="loading";
  // A decoded HTTP URL can be fetched again when assigned to another image.
  // Keep validated image bytes locally so animation survives a server outage.
  const imageURLs=new Set();
  const loadImage=async path=>{
    const response=await fetch(path);
    if(!response.ok)throw new Error("Portrait image is unavailable");
    const url=URL.createObjectURL(await response.blob());
    const image=new Image();image.src=url;
    try {await image.decode();} catch(error) {URL.revokeObjectURL(url);throw error;}
    imageURLs.add(url);
    return image;
  };
  window.addEventListener("pagehide",event=>{
    if(!event.persisted)for(const url of imageURLs)URL.revokeObjectURL(url);
  });
  let portrait;
  try {portrait=await loadImage("/__preview/live2d/reference/character.webp");}
  catch {companion.dataset.renderer="failed";return;}
  portrait.className="companion-portrait";portrait.alt="";portrait.draggable=false;
  const artwork=await fetch("/__preview/live2d/reference/character.json").then(r=>r.ok?r.json():null).catch(()=>null);
  toggle.querySelector(".console-companion")?.remove();toggle.prepend(portrait);companion.dataset.renderer="portrait";
  document.querySelector("#companion-title").textContent=artwork?.title || "白发猫耳 · 立绘预览";
  const note=document.createElement("p");note.className="companion-credit";note.textContent=artwork?.note || "使用你提供的高清参考图，当前为未绑定骨骼的立绘预览。";
  document.querySelector("#companion-panel").append(note);
  const zoom=document.createElement("button");zoom.type="button";zoom.className="btn-secondary";zoom.textContent="放大立绘";
  document.querySelector(".companion-shortcuts").append(zoom);
  const dialog=document.createElement("dialog");dialog.className="portrait-dialog";dialog.setAttribute("aria-label","高清立绘预览");
  const full=portrait.cloneNode();full.className="portrait-dialog-image";
  const close=document.createElement("button");close.type="button";close.className="btn-secondary";close.textContent="关闭";
  dialog.append(full,close);document.body.append(dialog);
  close.addEventListener("click",()=>dialog.close());zoom.addEventListener("click",()=>{dialog.showModal();close.focus();});
  let paused=matchMedia("(prefers-reduced-motion: reduce)").matches;
  const frames={idle:portrait.src};
  await Promise.all(Object.entries(artwork?.expressions || {}).map(async ([name,file])=>{
    if(!["idle","blink","wink"].includes(name)||!/^[a-zA-Z0-9_-]+\.webp$/.test(file))return;
    try {const frame=await loadImage(`/__preview/live2d/reference/${file}`);frames[name]=frame.src;}
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
})();
