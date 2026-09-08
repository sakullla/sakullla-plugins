// Local artwork study. Static artwork is kept distinct from a rigged model.
(async () => {
  if(document.readyState==="loading")await new Promise(resolve=>document.addEventListener("DOMContentLoaded",resolve,{once:true}));
  const companion=document.querySelector("#companion-assistant"),toggle=document.querySelector("#companion-toggle");
  companion.dataset.renderer="loading";
  const portrait=new Image();portrait.className="companion-portrait";portrait.alt="";portrait.draggable=false;
  portrait.src="/__preview/live2d/reference/character.webp";
  try {await portrait.decode();} catch {companion.dataset.renderer="failed";return;}
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
  companion.dataset.motion=paused?"paused":"playing";
  document.addEventListener("companion-motion",()=>{
    if(paused)return;
    portrait.animate([{transform:"translateY(0)"},{transform:"translateY(-7px) rotate(-2deg)",offset:.4},{transform:"translateY(0)"}],{duration:650,easing:"ease-in-out"});
  });
  document.addEventListener("companion-pause",event=>{paused=event.detail.paused;companion.dataset.motion=paused?"paused":"playing";});
})();
