/* ============================================================
 * CloudLog — 08-hunt.js
 * The Hunt workbench: filters, presets, breakdowns, export.
 * Part of index.html; assembled by build.js. Do not add a <script> wrapper.
 * ============================================================ */
function huntGV(id){ var e=document.getElementById(id); return e?String(e.value||""):""; }
function huntCache(r,prop,keys){
  if(r[prop]!==undefined) return r[prop];
  var v=lookupKeys(flatOf(r),keys); var sv=(v==null?"":String(v));
  try{ Object.defineProperty(r,prop,{value:sv,enumerable:false,configurable:true,writable:true}); }catch(e){ r[prop]=sv; }
  return sv;
}
function huntEid(r){ return huntCache(r,"__eid",["event_id","eventid","eventcode","event_code","record_id","recordid","signature_id","sid","id"]); }
function huntEtype(r){ return huntCache(r,"__etype",["event_type","eventtype","signature","alert_name","rule_description","description","type","name"]); }
function huntBlob(r){
  if(r.__hb!==undefined) return r.__hb;
  var s=((r.time||"")+" "+(r.actor||"")+" "+(r.action||"")+" "+(r.ip||"")+" "+(r.source||"")+" "+huntEid(r)+" "+huntEtype(r)+" "+rawStr(r)).toLowerCase();
  try{ Object.defineProperty(r,"__hb",{value:s,enumerable:false,configurable:true,writable:true}); }catch(e){ r.__hb=s; }
  return s;
}
function huntFilters(){
  return { text:huntGV("huntText").toLowerCase().trim(), eid:huntGV("huntEid").toLowerCase().trim(),
    type:huntGV("huntType").toLowerCase().trim(), ip:huntGV("huntIp").toLowerCase().trim(),
    actor:huntGV("huntActor").toLowerCase().trim(), sev:huntGV("huntSev"), source:huntGV("huntSource"),
    from:huntGV("huntFrom")?Date.parse(huntGV("huntFrom")):null, to:huntGV("huntTo")?Date.parse(huntGV("huntTo")):null };
}
function huntMatch(r,f){
  if(f.sev && severityOf(r)!==f.sev) return false;
  if(f.source && r.source!==f.source) return false;
  if(typeof window!=="undefined" && window.__huntExt && classifyIp(r.ip||"")!=="public") return false;
  if(f.eid){ var eid=huntEid(r).toLowerCase(); if(!eid) return false;
    if(/^\d+$/.test(f.eid)){ if(eid!==f.eid) return false; }        // numeric Event ID -> exact match (no "1 matches everything")
    else if(eid.indexOf(f.eid)<0) return false; }                    // non-numeric (e.g. GuardDuty type) -> contains
  if(f.type && huntEtype(r).toLowerCase().indexOf(f.type)<0) return false;
  if(f.ip && String(r.ip||"").toLowerCase().indexOf(f.ip)<0) return false;
  if(f.actor && String(r.actor||"").toLowerCase().indexOf(f.actor)<0) return false;
  if(f.text && huntBlob(r).indexOf(f.text)<0) return false;
  if(f.from||f.to){ var t=Date.parse(r.time); if(isNaN(t)) return false; if(f.from&&t<f.from) return false; if(f.to&&t>f.to) return false; }  // no-timestamp events excluded from a time-window hunt
  return true;
}
function huntTopN(map,n){ return Object.keys(map).map(function(k){return [k,map[k]];}).sort(function(a,b){return b[1]-a[1];}).slice(0,n); }
function huntPiv(field,v){ if(v==null||v===""||v==="-"||v==="unknown") return esc(v==null?"":String(v)||"-"); var e=esc(String(v)); return '<span class="pivot" data-hunt-field="'+field+'" data-hunt-val="'+e+'" title="Filter to '+e+'">'+e+'</span>'; }
var HUNT_FIELD_INPUT={ text:"huntText", eid:"huntEid", type:"huntType", ip:"huntIp", actor:"huntActor", sev:"huntSev", source:"huntSource", from:"huntFrom", to:"huntTo" };
function huntSetField(field,val){ var id=HUNT_FIELD_INPUT[field]; var el=id&&document.getElementById(id); if(el){ el.value=val; renderHunt(); } }
function huntClearField(field){
  if(field==="__ext"){ if(typeof window!=="undefined") window.__huntExt=false; renderHunt(); return; }
  var id=HUNT_FIELD_INPUT[field]; var el=id&&document.getElementById(id); if(el){ el.value=""; renderHunt(); }
}
function huntClearAll(){ Object.keys(HUNT_FIELD_INPUT).forEach(function(k){var e=document.getElementById(HUNT_FIELD_INPUT[k]);if(e)e.value="";}); if(typeof window!=="undefined") window.__huntExt=false; renderHunt(); }
function huntActiveBar(f){
  var host=document.getElementById("huntActive"); if(!host) return;
  var items=[];
  if(f.text) items.push(["text","keyword",f.text]);
  if(f.eid) items.push(["eid","event id",f.eid]);
  if(f.type) items.push(["type","type",f.type]);
  if(f.ip) items.push(["ip","ip",f.ip]);
  if(f.actor) items.push(["actor","user",f.actor]);
  if(f.sev) items.push(["sev","severity",f.sev]);
  if(f.source) items.push(["source","source",f.source]);
  if(huntGV("huntFrom")) items.push(["from","from",huntGV("huntFrom").replace("T"," ")]);
  if(huntGV("huntTo")) items.push(["to","to",huntGV("huntTo").replace("T"," ")]);
  if(typeof window!=="undefined" && window.__huntExt) items.push(["__ext","","external IPs only"]);
  host.innerHTML=items.map(function(it){ return '<span class="hunt-af">'+(it[1]?esc(it[1])+": ":"")+'<b>'+esc(it[2])+'</b><span class="af-x" data-af-clear="'+it[0]+'" title="remove">\u2715</span></span>'; }).join("");
}
function huntDownload(kind){
  var m=(typeof window!=="undefined"&&window.__huntMatches)||[]; if(!m.length) return;
  var row=function(r){ return { time:r.time, severity:severityOf(r), event_id:huntEid(r), event_type:huntEtype(r), actor:r.actor, ip:r.ip, action:r.action, source:r.source }; };
  var data,mime,ext;
  if(kind==="json"){ data=JSON.stringify(m.map(row),null,2); mime="application/json"; ext="json"; }
  else { var cols=["time","severity","event_id","event_type","actor","ip","action","source"];
    var esc2=function(s){s=String(s==null?"":s).replace(/"/g,'""'); return /[",\n]/.test(s)?'"'+s+'"':s;};
    data=cols.join(",")+"\n"+m.map(function(r){var o=row(r);return cols.map(function(c){return esc2(o[c]);}).join(",");}).join("\n"); mime="text/csv"; ext="csv"; }
  try{ var blob=new Blob([data],{type:mime}), url=URL.createObjectURL(blob), a=document.createElement("a"); a.href=url; a.download="cloudlog-hunt."+ext; document.body.appendChild(a); a.click(); setTimeout(function(){URL.revokeObjectURL(url);a.remove();},100); }catch(e){}
}
function renderHunt(){
  var host=document.getElementById("huntResults"); if(!host) return;
  var all=state.logs||[];
  var srcSel=document.getElementById("huntSource");
  if(srcSel && srcSel.getAttribute("data-n")!==String(all.length)){
    var srcs={}; all.forEach(function(r){ if(r.source) srcs[r.source]=1; });
    srcSel.innerHTML='<option value="">Any source</option>'+Object.keys(srcs).map(function(s){return '<option>'+esc(s)+'</option>';}).join("");
    srcSel.setAttribute("data-n",String(all.length));
  }
  var chipHost=document.getElementById("huntChips");
  if(chipHost && !chipHost.getAttribute("data-init")){
    chipHost.innerHTML=[['sev','malicious','Malicious only','hc-sig'],['sev','suspicious','Suspicious only',''],
      ['text','fail','Failed logins',''],['text','powershell','PowerShell',''],['text','mimikatz','Credential dump','hc-sig'],
      ['__topip','','Top attacker IP',''],['__ext','','External IPs only',''],['__clear','','Clear',''] ]
      .map(function(c){ return '<span class="hunt-chip '+c[3]+'" data-chip-field="'+c[0]+'" data-chip-val="'+esc(c[1])+'">'+esc(c[2])+'</span>'; }).join("");
    chipHost.setAttribute("data-init","1");
  }
  var f=huntFilters();
  huntActiveBar(f);
  var matches=all.filter(function(r){ return huntMatch(r,f); });
  var sev={malicious:0,suspicious:0,info:0}, ipc={}, acc={}, eidc={}, typc={};
  matches.forEach(function(r){ sev[severityOf(r)]++;
    if(r.ip&&r.ip!=="-"&&r.ip!=="0.0.0.0")ipc[r.ip]=(ipc[r.ip]||0)+1;
    if(r.actor&&r.actor!=="unknown"&&r.actor!=="-")acc[r.actor]=(acc[r.actor]||0)+1;
    var eid=huntEid(r); if(eid) eidc[eid]=(eidc[eid]||0)+1;
    var ty=huntEtype(r); if(ty) typc[ty]=(typc[ty]||0)+1; });
  var statsEl=document.getElementById("huntStats");
  var statBlock=function(title,field,top){ return '<div class="hunt-stat"><h4>'+title+'</h4>'+(top.length?top.map(function(x){var lbl=x[0].length>26?x[0].slice(0,26)+"\u2026":x[0];return '<div class="hs-row" data-hunt-field="'+field+'" data-hunt-val="'+esc(x[0])+'"><span>'+esc(lbl)+'</span><b>'+x[1]+'</b></div>';}).join(""):'<div class="hs-row">\u2014</div>')+'</div>'; };
  if(statsEl) statsEl.innerHTML=
    '<div class="hunt-stat"><h4>Verdict</h4>'
    +'<div class="hs-row" data-hunt-field="sev" data-hunt-val="malicious"><span style="color:#ff8098">Malicious</span><b>'+sev.malicious+'</b></div>'
    +'<div class="hs-row" data-hunt-field="sev" data-hunt-val="suspicious"><span style="color:#ffca7a">Suspicious</span><b>'+sev.suspicious+'</b></div>'
    +'<div class="hs-row" data-hunt-field="sev" data-hunt-val="info"><span style="color:#6ff0c2">Info</span><b>'+sev.info+'</b></div></div>'
    +statBlock("Top event types","type",huntTopN(typc,5))
    +statBlock("Top event IDs","eid",huntTopN(eidc,5))
    +statBlock("Top IPs","ip",huntTopN(ipc,5))
    +statBlock("Top users","actor",huntTopN(acc,5));
  var cnt=document.getElementById("huntCount"); if(cnt) cnt.textContent=matches.length.toLocaleString()+" of "+all.length.toLocaleString()+" events match";
  if(typeof window!=="undefined") window.__huntMatches=matches;
  if(!all.length){ host.innerHTML='<p class="empty-note">Load logs, then filter here to investigate on your own.</p>'; return; }
  if(!matches.length){ host.innerHTML='<p class="empty-note">No events match these filters. Remove a chip above, or hit Clear.</p>'; return; }
  var rows=matches.slice(0,300).map(function(r,i){ var sv=severityOf(r); var ty=huntEtype(r);
    return "<tr class='"+"hunt-row"+"' data-hi='"+i+"'><td>"+sevBadge(sv, r)+"</td><td>"+formatTime(r.time)+"</td><td>"+huntPiv("eid",huntEid(r))+"</td><td>"+huntPiv("type",ty.length>28?ty.slice(0,28)+"\u2026":ty)+"</td><td>"+huntPiv("actor",r.actor)+"</td><td>"+huntPiv("ip",r.ip)+"</td><td>"+esc(r.action)+"</td><td><span class='source-tag'>"+esc(r.source)+"</span></td></tr>";
  }).join("");
  host.innerHTML="<table><thead><tr><th>Verdict</th><th>Time</th><th>Event ID</th><th>Type</th><th>User</th><th>IP</th><th>Action</th><th>Source</th></tr></thead><tbody>"+rows+"</tbody></table>"
    +(matches.length>300?'<div class="hunt-more">Showing first 300 of '+matches.length.toLocaleString()+" \u2014 narrow the filters to see the rest.</div>":"");
}
(function huntWire(){
  if(typeof document==="undefined"||!document.getElementById) return;
  ["huntText","huntEid","huntType","huntIp","huntActor"].forEach(function(id){ var e=document.getElementById(id); if(e){ var d; e.oninput=function(){ clearTimeout(d); d=setTimeout(renderHunt,200); }; } });
  ["huntSev","huntSource","huntFrom","huntTo"].forEach(function(id){ var e=document.getElementById(id); if(e) e.onchange=renderHunt; });
  var ec=document.getElementById("huntExportCsv"); if(ec) ec.onclick=function(){huntDownload("csv");};
  var ej=document.getElementById("huntExportJson"); if(ej) ej.onclick=function(){huntDownload("json");};
  var cl=document.getElementById("huntClear"); if(cl) cl.onclick=huntClearAll;
  document.querySelectorAll(".hunt-presets .hp").forEach(function(b){
    b.onclick=function(){
      var kind=this.getAttribute("data-preset");
      huntClearAll();
      if(kind==="failed"){ var t=document.getElementById("huntText"); if(t) t.value="fail"; }
      else if(kind==="attacks"){ var s1=document.getElementById("huntSev"); if(s1) s1.value="malicious"; }
      else if(kind==="review"){ var s2=document.getElementById("huntSev"); if(s2) s2.value="suspicious"; }
      else if(kind==="external"){ if(typeof window!=="undefined") window.__huntExt=true; }
      else if(kind==="powershell"){ var ty=document.getElementById("huntType"); if(ty) ty.value="powershell"; }
      else if(kind==="admin"){ var a=document.getElementById("huntActor"); if(a) a.value="admin"; }
      renderHunt();
    };
  });
  document.addEventListener("click", function(e){
    if(!e.target||!e.target.closest) return;
    var afx=e.target.closest("[data-af-clear]");
    if(afx){ huntClearField(afx.getAttribute("data-af-clear")); return; }
    var chip=e.target.closest("[data-chip-field]");
    if(chip){ var fld=chip.getAttribute("data-chip-field"), val=chip.getAttribute("data-chip-val");
      if(fld==="__clear") huntClearAll();
      else if(fld==="__topip"){ var c={}; (state.logs||[]).forEach(function(r){ if(r.ip&&classifyIp(r.ip)==="public")c[r.ip]=(c[r.ip]||0)+1; }); var t=huntTopN(c,1)[0]; if(t) huntSetField("ip",t[0]); }
      else if(fld==="__ext"){ if(typeof window!=="undefined") window.__huntExt=!window.__huntExt; renderHunt(); }
      else huntSetField(fld,val);
      switchToTab("hunt"); return; }
    var hrow=e.target.closest(".hunt-row");
    if(hrow && !e.target.closest("[data-hunt-field]")){ var mi=+hrow.getAttribute("data-hi"); var mm=(typeof window!=="undefined"&&window.__huntMatches)||[]; if(mm[mi]) openInspector(mm[mi]); return; }
    var hf=e.target.closest("[data-hunt-field]");
    var ph=document.getElementById("panel-hunt");
    if(hf && ph && ph.classList && ph.classList.contains("active")) huntSetField(hf.getAttribute("data-hunt-field"), hf.getAttribute("data-hunt-val"));
  });
  document.addEventListener("keydown", function(e){
    var ph=document.getElementById("panel-hunt"); if(!ph||!ph.classList||!ph.classList.contains("active")) return;
    var tag=(e.target&&e.target.tagName)||""; if(/INPUT|SELECT|TEXTAREA/.test(tag)) return;
    if(e.key==="/"){ e.preventDefault(); var t=document.getElementById("huntText"); if(t)t.focus(); }
    else if(e.key==="m") huntSetField("sev","malicious");
    else if(e.key==="s") huntSetField("sev","suspicious");
    else if(e.key==="a") huntSetField("sev","");
    else if(e.key==="c") huntClearAll();
  });
})();






