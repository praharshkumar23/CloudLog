/* ============================================================
 * CloudLog — 14-auth-and-crypto.js
 * Access control, AES-256 case encryption, lock screen, locked-copy export, boot.
 * Part of index.html; assembled by build.js. Do not add a <script> wrapper.
 * ============================================================ */
var AUTH_KEY="cloudlog_auth_v1";
var __BAKED_AUTH = null;/*BAKE*/   // when this file is exported as a "locked copy", the admin's code config is baked in here so it travels with the file
function __authStore(){ try{ return JSON.parse((typeof localStorage!=="undefined"&&localStorage.getItem(AUTH_KEY))||"null"); }catch(e){ return null; } }
function __authSave(o){ try{ if(typeof localStorage!=="undefined") localStorage.setItem(AUTH_KEY, JSON.stringify(o)); }catch(e){} }
function sha256Hex(str){
  var enc=new TextEncoder().encode(str);
  return crypto.subtle.digest("SHA-256", enc).then(function(buf){
    return Array.from(new Uint8Array(buf)).map(function(b){return b.toString(16).padStart(2,"0");}).join("");
  });
}
function deriveAesKey(pass, salt){
  var enc=new TextEncoder();
  return crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]).then(function(km){
    return crypto.subtle.deriveKey({name:"PBKDF2", salt:salt, iterations:210000, hash:"SHA-256"}, km,
      {name:"AES-GCM", length:256}, false, ["encrypt","decrypt"]);
  });
}
function encryptText(plain, pass){
  var salt=crypto.getRandomValues(new Uint8Array(16)), iv=crypto.getRandomValues(new Uint8Array(12));
  return deriveAesKey(pass, salt).then(function(key){
    return crypto.subtle.encrypt({name:"AES-GCM", iv:iv}, key, new TextEncoder().encode(plain));
  }).then(function(ct){
    var out=new Uint8Array(16+12+ct.byteLength); out.set(salt,0); out.set(iv,16); out.set(new Uint8Array(ct),28);
    var b=""; out.forEach(function(x){ b+=String.fromCharCode(x); });
    return "CLENC1:"+btoa(b);
  });
}
function decryptText(blob, pass){
  if(blob.indexOf("CLENC1:")!==0) return Promise.reject(new Error("not an encrypted CloudLog file"));
  var raw=atob(blob.slice(7)), u=new Uint8Array(raw.length);
  for(var i=0;i<raw.length;i++) u[i]=raw.charCodeAt(i);
  var salt=u.slice(0,16), iv=u.slice(16,28), ct=u.slice(28);
  return deriveAesKey(pass, salt).then(function(key){
    return crypto.subtle.decrypt({name:"AES-GCM", iv:iv}, key, ct);
  }).then(function(pt){ return new TextDecoder().decode(pt); });
}
/* --- code management --- */
function authIsConfigured(){ var a=__authStore(); return !!(a&&a.adminHash); }
function authSetupAdmin(code){ return sha256Hex(code).then(function(h){ var a=__authStore()||{codes:[]}; a.adminHash=h; a.codes=a.codes||[]; __authSave(a); }); }
function authAddCode(label, code){ return sha256Hex(code).then(function(h){ var a=__authStore(); if(!a) return; a.codes.push({label:label||"analyst", hash:h, created:new Date().toISOString()}); __authSave(a); }); }
function authRevokeCode(idx){ var a=__authStore(); if(a&&a.codes[idx]){ a.codes.splice(idx,1); __authSave(a); } }
function authListCodes(){ var a=__authStore(); return (a&&a.codes)||[]; }
function authVerify(code){
  var a=__authStore(); if(!a) return Promise.resolve({ok:true, role:"open"});
  return sha256Hex(code).then(function(h){
    if(h===a.adminHash) return {ok:true, role:"admin"};
    if((a.codes||[]).some(function(c){return c.hash===h;})) return {ok:true, role:"analyst"};
    return {ok:false};
  });
}
function authDisable(){ try{ if(typeof localStorage!=="undefined") localStorage.removeItem(AUTH_KEY); }catch(e){} }
var AUTH_SESSION={ unlocked:false, role:"open", code:"" };
/* --- lock screen (browser only) --- */
function showLock(){
  var lk=document.getElementById("lockScreen"); if(!lk) return;
  lk.classList.add("on");
  var inp=document.getElementById("lockCode"); if(inp){ inp.value=""; try{ inp.focus(); }catch(e){} }
}
function hideLock(){ var lk=document.getElementById("lockScreen"); if(lk) lk.classList.remove("on"); }
function tryUnlock(){
  var inp=document.getElementById("lockCode"), msg=document.getElementById("lockMsg");
  var code=(inp&&inp.value)||"";
  authVerify(code).then(function(r){
    if(r.ok){ AUTH_SESSION.unlocked=true; AUTH_SESSION.role=r.role; AUTH_SESSION.code=code; hideLock(); renderAuthPanel(); }
    else if(msg){ msg.textContent="Wrong code. Try again."; }
  });
}
/* --- admin panel rendering --- */
function renderAuthPanel(){
  var host=document.getElementById("authPanel"); if(!host) return;
  var _lo=document.getElementById("logoutBtn"); if(_lo) _lo.style.display=(typeof authIsConfigured==="function"&&authIsConfigured())?"":"none";
  if(!authIsConfigured()){
    host.innerHTML='<div class="auth-row"><b>Access control is OFF.</b> Set an admin code to require login and enable case encryption.</div>'
      +'<div class="auth-row"><input id="auSetCode" type="password" placeholder="Choose admin code (min 6 chars)"/><button class="btn btn-primary" id="auSetBtn">Enable protection</button></div>'
      +'<div class="auth-note">Honest note: the login screen protects use of the tool in a browser; someone with the file itself can bypass it. Saved-case <b>encryption</b> is the strong part — without a code, saved files are unreadable (AES-256-GCM).</div>';
    var b=document.getElementById("auSetBtn"); if(b) b.onclick=function(){ var c=(document.getElementById("auSetCode")||{}).value||""; if(c.length<6){ alert("Use at least 6 characters."); return; } authSetupAdmin(c).then(function(){ AUTH_SESSION.unlocked=true; AUTH_SESSION.role="admin"; AUTH_SESSION.code=c; renderAuthPanel(); alert("Protection enabled. Your admin code is set — don't lose it; encrypted cases can't be recovered without a code."); }); };
    return;
  }
  if(AUTH_SESSION.role!=="admin"){
    host.innerHTML='<div class="auth-row">Access control is <b>ON</b>. You are logged in as <b>'+esc(AUTH_SESSION.role)+'</b>. Only the admin can manage access codes.</div>';
    return;
  }
  var rows=authListCodes().map(function(c,i){ return '<div class="auth-code-row"><span><b>'+esc(c.label)+'</b> <span class="muted small">added '+esc((c.created||"").slice(0,10))+'</span></span><button class="btn btn-outline au-revoke" data-i="'+i+'">revoke</button></div>'; }).join("") || '<div class="muted small">No analyst codes yet.</div>';
  host.innerHTML='<div class="auth-row"><b>Access control: ON</b> (you are admin)</div>'
    +'<div class="auth-sub">Give access to someone: create a code for them</div>'
    +'<div class="auth-row"><input id="auLabel" placeholder="Name / label (e.g. rahul-analyst)"/><input id="auCode" type="password" placeholder="Their login code (min 6 chars)"/><button class="btn btn-primary" id="auAddBtn">Create code</button></div>'
    +'<div class="auth-sub">Active analyst codes</div>'+rows
    +'<div class="auth-row" style="margin-top:10px;"><button class="btn btn-primary" id="auExport">📤 Export locked copy to share</button><button class="btn btn-outline" id="auLockNow">Lock now</button><button class="btn btn-outline" id="auDisable">Turn protection off</button></div>'
    +'<div class="auth-note">Codes are stored only as SHA-256 hashes. Saved cases are encrypted with the code of whoever saves them (AES-256-GCM, PBKDF2 210k) — share the code with whoever must open the file. <b>Export locked copy</b> creates a shareable index.html that opens locked with these codes baked in (no loaded logs included).</div>';
  var ab=document.getElementById("auAddBtn"); if(ab) ab.onclick=function(){ var l=(document.getElementById("auLabel")||{}).value||"", c=(document.getElementById("auCode")||{}).value||""; if(c.length<6){ alert("Use at least 6 characters."); return; } authAddCode(l,c).then(function(){ renderAuthPanel(); alert("Code created for "+(l||"analyst")+". Share it with them — they enter it on the lock screen."); }); };
  host.querySelectorAll(".au-revoke").forEach(function(b){ b.onclick=function(){ authRevokeCode(+this.getAttribute("data-i")); renderAuthPanel(); }; });
  var ln=document.getElementById("auLockNow"); if(ln) ln.onclick=function(){ AUTH_SESSION.unlocked=false; AUTH_SESSION.role="open"; AUTH_SESSION.code=""; showLock(); };
  var ex=document.getElementById("auExport"); if(ex) ex.onclick=buildLockedCopy;
  var dis=document.getElementById("auDisable"); if(dis) dis.onclick=function(){ if(confirm("Turn off protection? The lock screen and code list will be removed. Previously saved encrypted cases stay encrypted.")){ authDisable(); renderAuthPanel(); } };
}
/* export a "locked copy": a fresh index.html with the admin's codes baked in + no loaded data */
function buildLockedCopy(){
  var store=__authStore();
  if(!store||!store.adminHash){ alert("Set an admin code first, then export."); return; }
  if(AUTH_SESSION.role!=="admin"){ alert("Only the admin can export a locked copy."); return; }
  if(typeof DOMParser==="undefined"){ alert("This browser can't export here — open the file locally and try again."); return; }
  try{
    var doc=new DOMParser().parseFromString(document.documentElement.outerHTML,"text/html");
    // strip any loaded logs / analysis so the shared file ships clean (no data leaks into it)
    ["tbody","plainSummary","summaryContent","viewCount","filterChip","huntResults","huntStats","huntActive",
     "inspBody","analystContent","attackMapSvg","chainList","chainsContent","detectionsList","mapLegend","modernChain","navSrc"]
      .forEach(function(id){ var e=doc.getElementById(id); if(e) e.innerHTML=""; });
    ["mEvents","mActors","mIps","mDetections","navTotal"].forEach(function(id){ var e=doc.getElementById(id); if(e) e.textContent="0"; });
    var mS=doc.getElementById("mSource"); if(mS) mS.textContent="None";
    var mSp=doc.getElementById("mSpan"); if(mSp) mSp.textContent="—";
    // bake the code config (SHA-256 hashes only) into the script so it opens locked on any machine
    var sc=doc.getElementById("cloudlog-main"); if(!sc){ alert("Could not prepare file."); return; }
    var baked=JSON.stringify(store).replace(/</g,"\\u003c");
    sc.textContent=sc.textContent.replace(/var __BAKED_AUTH = [\s\S]*?;\/\*BAKE\*\//, "var __BAKED_AUTH = "+baked+";/*BAKE*/");
    downloadBlob("<!doctype html>\n"+doc.documentElement.outerHTML, "text/html", "cloudlog-locked.html");
    alert("Exported cloudlog-locked.html. Share this file — it opens LOCKED and only your codes unlock it.\n\nBaked in: your admin + analyst codes (as SHA-256 hashes only).\nNot included: any loaded logs or cases.\n\nHonest note: a client-side lock is strong deterrence, not tamper-proof — the encryption on saved .clenc cases is the hard guarantee.");
  }catch(e){ alert("Export failed: "+e.message); }
}
/* boot: show lock if configured (browser only) */
if (typeof document!=="undefined" && document.addEventListener && typeof crypto!=="undefined" && crypto.subtle) {
  document.addEventListener("DOMContentLoaded", function(){
    try{
      if (__BAKED_AUTH && !__authStore()) { __authSave(__BAKED_AUTH); }   // shared "locked copy": seed the baked codes on first open
      if(authIsConfigured()){ showLock(); }
      renderAuthPanel();
      var ub=document.getElementById("lockBtn"); if(ub) ub.onclick=tryUnlock;
      var li=document.getElementById("lockCode"); if(li) li.addEventListener("keydown", function(e){ if(e.key==="Enter") tryUnlock(); });
    }catch(e){}
  });
}


