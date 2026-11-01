/* 휴대폰용 비공개 사이트(GitHub Pages)에서만 쓰임: 데이터 파일(.bin)을 비밀번호로 풀어서 보여 줌.
   암호화 = gzip 압축 후 AES-256-GCM, 키 = PBKDF2-SHA256(비밀번호, salt). 만드는 쪽은 collector/publish.py.
   PC 에서 docs/ 를 그냥 열 때는 window.KD_ENC 가 없어서 아무 일도 하지 않음. */
(function(){
"use strict";
const E=window.KD_ENC;if(!E)return;
const b64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const LS="kd_enc_key_"+E.salt.slice(0,10);
let key=null,manifest=null;
const manifestPath="data/manifest.json";
const cacheReady=(async()=>{try{return await caches.open("kd-encrypted-v1-"+E.salt)}catch{return null}})();
const cacheUrl=path=>new URL(path,location.href).href;
async function cached(path){try{return await (await cacheReady)?.match(cacheUrl(path))}catch{return null}}
async function save(path,response){try{const c=await cacheReady;if(!c)return false;await c.put(cacheUrl(path),response);return true}catch{return false}}
async function prune(m){
  try{
    const c=await cacheReady;if(!c||typeof c.keys!=="function")return;
    const keep=new Set([cacheUrl(manifestPath),cacheUrl("data/check.bin?snapshot="+m.auth),...Object.entries(m.files).map(([name,hash])=>cacheUrl("data/"+name.replace(/\.js$/,".bin")+"?snapshot="+hash))]);
    await Promise.all((await c.keys()).filter(r=>!keep.has(r.url)).map(r=>c.delete(r)));
  }catch{}
}
function validManifest(m){
  return m&&m.v===1&&/^[a-f0-9]{64}$/.test(m.auth)&&m.files&&typeof m.files==="object"&&
    /^[a-f0-9]{64}$/.test(m.files["dates.js"])&&
    Object.entries(m.files).every(([name,hash])=>/^[\w.-]+\.js$/.test(name)&&/^[a-f0-9]{64}$/.test(hash))&&
    (m.latest===null||/^\d{4}-\d{2}-\d{2}$/.test(m.latest));
}
async function readManifest(fresh=false){
  if(!fresh){try{const hit=await cached(manifestPath);if(hit){const m=await hit.json();if(validManifest(m))return m}}catch{}}
  const response=await fetch(manifestPath,{cache:"no-store"});
  if(!response.ok)throw new Error("자료 목록을 불러오지 못했습니다.");
  const m=await response.json();if(!validManifest(m))throw new Error("자료 목록을 확인하지 못했습니다.");
  return m;
}
const snapshotReady=(async()=>{manifest=await readManifest();return manifest})();
// 최초 비밀번호 화면이 뜨기 전에 네트워크가 실패해도 미처리 오류를 만들지 않는다.
snapshotReady.catch(()=>{});
const sha=async data=>Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",data)),v=>v.toString(16).padStart(2,"0")).join("");

async function derive(pw){
  const base=await crypto.subtle.importKey("raw",new TextEncoder().encode(pw),"PBKDF2",false,["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2",salt:b64(E.salt),iterations:E.iter,hash:"SHA-256"},base,{name:"AES-GCM",length:256},true,["decrypt"]);
}
async function dec(buf){
  const u=new Uint8Array(buf);
  const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv:u.slice(0,12)},key,u.slice(12));
  return await new Response(new Blob([pt]).stream().pipeThrough(new DecompressionStream("gzip"))).text();
}
async function fetchDec(path,m=manifest){
  if(!m)m=await snapshotReady;
  const name=path.split("/").pop().replace(/\.bin$/,".js");
  const auth=path==="data/check.bin",hash=auth?m.auth:m.files[name];
  if(!hash)throw new Error("저장된 자료에 없는 항목입니다. 새로고침을 눌러주세요.");
  const cacheKey=path+"?snapshot="+hash,hit=await cached(cacheKey);
  if(hit){try{return await dec(await hit.arrayBuffer())}catch{try{await (await cacheReady)?.delete(cacheUrl(cacheKey))}catch{}}}
  const r=await fetch(path,{cache:"no-cache"});if(!r.ok)throw new Error(path);
  const buf=await r.arrayBuffer(),code=await dec(buf);
  const actual=await sha(auth?buf:new TextEncoder().encode(code));
  if(actual!==hash)throw new Error("서버 자료가 변경됐습니다. 새로고침을 눌러주세요.");
  await save(cacheKey,new Response(buf));return code;
}
async function check(){try{return (await fetchDec("data/check.bin"))==="kdash-ok"}catch(e){return false}}

/* 페이지의 데이터 로더가 이걸 부름: "data/2026-10-16.js?v=1" → data/2026-10-16.bin 을 풀어서 실행 */
window.kdEncLoad=async src=>{
  const code=await fetchDec(src.replace(/\?.*$/,"").replace(/\.js$/,".bin"));
  const s=document.createElement("script");s.textContent=code;document.head.appendChild(s);s.remove();
};
// 새 목록·확인 파일·최신 거래일을 모두 확인한 뒤에만 저장된 목록을 교체한다.
window.kdEncRefresh=async()=>{
  const next=await readManifest(true);
  try{if(await fetchDec("data/check.bin",next)!=="kdash-ok")throw new Error("비밀번호를 확인해주세요.")}
  catch(e){
    if(e.name==="OperationError"&&next.auth!==manifest?.auth){
      await save(manifestPath,new Response(JSON.stringify(next)));localStorage.removeItem(LS);location.reload();
    }
    throw e;
  }
  await fetchDec("data/dates.bin",next);
  if(next.latest)await fetchDec("data/"+next.latest+".bin",next);
  const saved=await save(manifestPath,new Response(JSON.stringify(next),{headers:{"Content-Type":"application/json"}}));
  if(await cacheReady&&!saved)throw new Error("새 자료를 저장하지 못했습니다. 기존 자료를 유지합니다.");
  manifest=next;await prune(next);return next;
};
window.kdEncLock=async()=>{try{localStorage.removeItem(LS);await (await cacheReady)?.delete(cacheUrl(manifestPath))}catch(e){}location.reload()};

window.kdEncReady=(async()=>{
  await snapshotReady;
  try{const j=localStorage.getItem(LS);
    if(j){key=await crypto.subtle.importKey("jwk",JSON.parse(j),{name:"AES-GCM"},true,["decrypt"]);if(await check()){await save(manifestPath,new Response(JSON.stringify(manifest)));return}localStorage.removeItem(LS)}}catch(e){}
  if(document.readyState==="loading")await new Promise(r=>addEventListener("DOMContentLoaded",r));
  const box=document.createElement("div");
  box.setAttribute("style","position:fixed;inset:0;z-index:100;display:flex;align-items:center;justify-content:center;padding:16px;background:var(--bg,#0f141b)");
  box.innerHTML=`<form style="width:100%;max-width:340px;background:var(--panel,#161d27);border:1px solid var(--line,#2a3544);border-radius:12px;padding:20px;display:grid;gap:12px;color:var(--fg,#e6ebf2);font-family:var(--font,sans-serif)">
    <div style="font-weight:700;font-size:17px">기관 수급 레이더 🔒</div>
    <input type="password" autocomplete="current-password" placeholder="비밀번호" aria-label="비밀번호" required
      style="font:inherit;font-size:16px;padding:10px 12px;border-radius:8px;border:1px solid var(--line,#2a3544);background:var(--panel2,#1b2430);color:inherit">
    <label style="font-size:13px;color:var(--muted,#9aa6b8);display:flex;gap:6px;align-items:center"><input type="checkbox" checked> 이 기기에서 기억</label>
    <button style="font:inherit;font-weight:700;padding:10px;border-radius:8px;border:0;background:var(--accent,#7fb0ea);color:var(--panel,#161d27);cursor:pointer">열기</button>
    <div class="err" role="alert" style="font-size:13px;color:var(--risk,#ff7c84);min-height:1em"></div></form>`;
  document.body.appendChild(box);
  const f=box.querySelector("form"),pw=f.querySelector("input[type=password]"),rem=f.querySelector("input[type=checkbox]"),btn=f.querySelector("button"),err=f.querySelector(".err");
  pw.focus();
  await new Promise(done=>{f.onsubmit=async e=>{
    e.preventDefault();btn.disabled=true;btn.textContent="확인 중…";err.textContent="";
    try{key=await derive(pw.value)}catch(x){key=null}
    if(key&&await check()){
      if(rem.checked){try{localStorage.setItem(LS,JSON.stringify(await crypto.subtle.exportKey("jwk",key)))}catch(x){}}
      await save(manifestPath,new Response(JSON.stringify(manifest)));
      box.remove();done();
    }else{err.textContent="비밀번호가 맞지 않습니다.";btn.disabled=false;btn.textContent="열기";pw.select()}
  }});
})();
})();
