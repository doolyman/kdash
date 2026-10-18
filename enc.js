/* 휴대폰용 비공개 사이트(GitHub Pages)에서만 쓰임: 데이터 파일(.bin)을 비밀번호로 풀어서 보여 줌.
   암호화 = gzip 압축 후 AES-256-GCM, 키 = PBKDF2-SHA256(비밀번호, salt). 만드는 쪽은 collector/publish.py.
   PC 에서 docs/ 를 그냥 열 때는 window.KD_ENC 가 없어서 아무 일도 하지 않음. */
(function(){
"use strict";
const E=window.KD_ENC;if(!E)return;
const b64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const LS="kd_enc_key_"+E.salt.slice(0,10);
let key=null;

async function derive(pw){
  const base=await crypto.subtle.importKey("raw",new TextEncoder().encode(pw),"PBKDF2",false,["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2",salt:b64(E.salt),iterations:E.iter,hash:"SHA-256"},base,{name:"AES-GCM",length:256},true,["decrypt"]);
}
async function dec(buf){
  const u=new Uint8Array(buf);
  const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv:u.slice(0,12)},key,u.slice(12));
  return await new Response(new Blob([pt]).stream().pipeThrough(new DecompressionStream("gzip"))).text();
}
async function fetchDec(path){const r=await fetch(path,{cache:"no-cache"});if(!r.ok)throw new Error(path);return dec(await r.arrayBuffer())}
async function check(){try{return (await fetchDec("data/check.bin"))==="kdash-ok"}catch(e){return false}}

/* 페이지의 데이터 로더가 이걸 부름: "data/2026-10-16.js?v=1" → data/2026-10-16.bin 을 풀어서 실행 */
window.kdEncLoad=async src=>{
  const code=await fetchDec(src.replace(/\?.*$/,"").replace(/\.js$/,".bin"));
  const s=document.createElement("script");s.textContent=code;document.head.appendChild(s);s.remove();
};
window.kdEncLock=()=>{try{localStorage.removeItem(LS)}catch(e){}location.reload()};

window.kdEncReady=(async()=>{
  try{const j=localStorage.getItem(LS);
    if(j){key=await crypto.subtle.importKey("jwk",JSON.parse(j),{name:"AES-GCM"},true,["decrypt"]);if(await check())return;localStorage.removeItem(LS)}}catch(e){}
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
      box.remove();done();
    }else{err.textContent="비밀번호가 맞지 않습니다.";btn.disabled=false;btn.textContent="열기";pw.select()}
  }});
})();
})();
