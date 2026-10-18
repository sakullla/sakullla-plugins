// Package-owned companion artwork. Expression frames are not a Live2D mesh.
// Artwork is fetched only after the helper is expanded, so the first screen
// never downloads the large portrait or expression frames.
export async function mountCompanion({
  assetBase = new URL(".", import.meta.url),
  image = "companion-idle.webp",
  expressions = {blink:"companion-blink.webp",wink:"companion-wink.webp"},
  title = "看板娘",
  note = "",
} = {}) {
  if(document.readyState==="loading")await new Promise(resolve=>document.addEventListener("DOMContentLoaded",resolve,{once:true}));
  const companion=document.querySelector("#companion-assistant"),toggle=document.querySelector("#companion-toggle");
  if(!companion||!toggle)return;
  companion.dataset.renderer="idle";
  const panel=document.querySelector("#companion-panel");
  document.querySelector("#companion-title").textContent=title;
  if(note){const credit=document.createElement("p");credit.className="companion-credit";credit.textContent=note;panel.append(credit);}
  const zoom=document.createElement("button");zoom.type="button";zoom.className="ui-btn ui-btn--secondary ui-btn--sm";zoom.textContent="放大立绘";
  document.querySelector(".companion-shortcuts").append(zoom);
  const dialog=document.createElement("dialog");dialog.className="ui-dialog portrait-dialog";dialog.setAttribute("aria-label","高清立绘");
  const full=document.createElement("img");full.className="portrait-dialog-image";full.alt="";
  const close=document.createElement("button");close.type="button";close.className="ui-btn ui-btn--secondary";close.textContent="关闭";
  dialog.append(full,close);document.body.append(dialog);
  close.addEventListener("click",()=>dialog.close());
  zoom.addEventListener("click",()=>{if(!full.getAttribute("src"))return;dialog.showModal();close.focus();});

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

  let portrait,loading,loaded=false;
  let paused=matchMedia("(prefers-reduced-motion: reduce)").matches;
  const frames={};
  let blinkTimer,restoreTimer,taps=0,blinkCount=0;
  const setFrame=name=>{if(!portrait)return;portrait.src=frames[name] || frames.idle;companion.dataset.expression=name;};
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
  const sync=()=>{clear();if(!loaded)return;setFrame("idle");companion.dataset.motion=paused?"paused":"playing";scheduleBlink();};
  const load=async()=>{
    if(loaded)return;
    if(loading)return loading;
    loading=(async()=>{
      try {portrait=await loadImage(image);}
      catch {companion.dataset.renderer="failed";return;}
      portrait.className="companion-portrait";portrait.alt="";portrait.draggable=false;
      toggle.querySelector(".console-companion")?.remove();toggle.prepend(portrait);
      full.src=portrait.src;full.alt="";
      frames.idle=portrait.src;
      companion.dataset.renderer="portrait";
      await Promise.all(Object.entries(expressions).map(async ([name,file])=>{
        if(!["idle","blink","wink"].includes(name)||!/^[a-zA-Z0-9_-]+\.webp$/.test(file))return;
        try {const frame=await loadImage(file);frames[name]=frame.src;}
        catch { /* Keep the usable neutral portrait. */ }
      }));
      loaded=true;
      companion.dataset.expressionFrames=String(Object.keys(frames).length);
      sync();
    })();
    return loading;
  };

  document.addEventListener("companion-expand",()=>{load();});
  document.addEventListener("companion-motion",()=>{
    if(!loaded){load();return;}
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
  if(companion.dataset.minimized!=="true")load();
}

if (!document.querySelector('meta[name="nre-companion-preview"]')) {
  mountCompanion();
}
