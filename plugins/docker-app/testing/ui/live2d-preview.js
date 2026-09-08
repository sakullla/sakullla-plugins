(async () => {
  const ready = () => document.readyState === "loading" ? new Promise(resolve => document.addEventListener("DOMContentLoaded",resolve,{once:true})) : Promise.resolve();
  await ready();
  const companion = document.querySelector("#companion-assistant");
  const toggle = document.querySelector("#companion-toggle");
  if (!companion || !toggle) return;
  companion.dataset.renderer = "loading";
  const loadScript = (file) => new Promise((resolve,reject) => {
    const script=document.createElement("script"); script.src=`/__preview/live2d/${file}`; script.onload=resolve; script.onerror=()=>reject(new Error(`Cannot load ${file}`)); document.head.append(script);
  });
  let app, model;
  try {
    await loadScript("live2dcubismcore.min.js");
    await loadScript("pixi.min.js");
    await loadScript("cubism4.min.js");
    PIXI.live2d.config.sound=false;
    const canvas=document.createElement("canvas"); canvas.className="companion-canvas"; canvas.setAttribute("aria-hidden","true");
    toggle.prepend(canvas);
    app=new PIXI.Application({view:canvas,width:220,height:360,backgroundAlpha:0,antialias:true,resolution:Math.min(devicePixelRatio||1,2),autoDensity:true,autoStart:false});
    model=await PIXI.live2d.Live2DModel.from("/__preview/live2d/Hiyori/Hiyori.model3.json",{autoInteract:false,autoUpdate:false,motionPreload:"ALL"});
    app.stage.addChild(model);
    const natural={width:model.width,height:model.height};
    const resize=()=>{
      if (companion.dataset.minimized==="true") return;
      const bounds=toggle.getBoundingClientRect();
      app.renderer.resize(bounds.width,bounds.height);
      const scale=Math.min(bounds.width/natural.width,bounds.height/natural.height)*.96;
      model.scale.set(scale);model.position.set((bounds.width-model.width)/2,bounds.height-model.height);
      app.renderer.render(app.stage);
    };
    let paused=matchMedia("(prefers-reduced-motion: reduce)").matches;
    const syncPlayback=()=>{
      const hidden=document.hidden || companion.dataset.minimized==="true" || !!document.querySelector("dialog[open]");
      if(paused||hidden) app.stop(); else app.start();
      companion.dataset.motion=paused?"paused":"playing";
    };
    app.ticker.maxFPS=30;
    app.ticker.add(()=>model.update(app.ticker.elapsedMS));
    new ResizeObserver(resize).observe(toggle);
    new MutationObserver(syncPlayback).observe(companion,{attributes:true,attributeFilter:["data-minimized"]});
    new MutationObserver(syncPlayback).observe(document.body,{subtree:true,attributes:true,attributeFilter:["open"]});
    document.addEventListener("visibilitychange",syncPlayback);
    document.addEventListener("pointermove",event=>{
      if(paused||matchMedia("(pointer: coarse)").matches) return;
      const rect=canvas.getBoundingClientRect(); model.focus(event.clientX-rect.left,event.clientY-rect.top);
    },{passive:true});
    document.addEventListener("companion-motion",()=>{
      if(paused) return;
      model.motion("TapBody",0,3);
      companion.dataset.lastInteraction=String(Date.now());
    });
    document.addEventListener("companion-pause",event=>{paused=event.detail.paused;syncPlayback();});
    const preference=matchMedia("(prefers-reduced-motion: reduce)");
    preference.addEventListener("change",()=>{paused=preference.matches;syncPlayback();});
    companion.dataset.renderer="live2d";
    toggle.querySelector(".console-companion")?.remove();
    resize(); syncPlayback();
    document.querySelector("#companion-title").textContent="Hiyori · 看板娘";
    const attribution=document.createElement("p"); attribution.className="companion-credit";
    attribution.innerHTML='Hiyori Momose © Live2D Inc. · <a href="https://www.live2d.com/en/learn/sample/model-terms/" target="_blank" rel="noopener noreferrer">模型授权</a>';
    document.querySelector("#companion-panel").append(attribution);
  } catch(error) {
    companion.dataset.renderer="failed";
    document.querySelector("#companion-copy").textContent="看板娘模型加载失败，刷新页面可重试。应用管理仍可正常使用。";
    console.error("Live2D preview:",error);
    app?.destroy(true);
  }
})();
