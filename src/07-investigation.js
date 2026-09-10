/* ============================================================
 * CloudLog — 07-investigation.js
 * Pivoting + event/incident inspectors (the investigation drawers).
 * Part of index.html; assembled by build.js. Do not add a <script> wrapper.
 * ============================================================ */
function pivotSpan(v){
  if (!v || v === "-" || v === "unknown") return esc(v || "-");
  var e = esc(String(v));
  return '<span class="pivot" data-pivot="'+e+'" data-pivot-label="'+e+'" title="Click to see all events for '+e+'">'+e+'</span>';
}
function pivotTo(value, label){
  if (!value || value === "-") return;
  var sb = document.getElementById("search"); if (sb) sb.value = value;
  var chip = document.getElementById("filterChip");
  if (chip) chip.innerHTML = '<span class="filter-chip">Showing events for <b>'+esc(label||value)+'</b><span class="chip-x" onclick="clearPivot()">clear \u2715</span></span>';
  if (typeof applyFilter === "function") applyFilter();
  switchToTab("timeline");
  closeInspector();
  if (typeof window !== "undefined" && window.scrollTo) window.scrollTo(0, 0);
}
function clearPivot(){
  var sb = document.getElementById("search"); if (sb) sb.value = "";
  var chip = document.getElementById("filterChip"); if (chip) chip.innerHTML = "";
  if (typeof applyFilter === "function") applyFilter();
}
// ---- Event Inspector drawer: click any event -> clean, labelled detail view ----
/* Per-log-type "Key fields": surface the fields an analyst actually needs (Windows/Sysmon/Linux),
   instead of leaving them buried in raw JSON. */
var LOGON_TYPES = {"2":"2 — Interactive (at keyboard)","3":"3 — Network (share/SMB)","4":"4 — Batch (scheduled task)","5":"5 — Service","7":"7 — Unlock","8":"8 — NetworkCleartext","9":"9 — NewCredentials (runas)","10":"10 — RemoteInteractive (RDP)","11":"11 — CachedInteractive"};
function keyFieldsHtml(ev){
  var f = flatOf(ev);
  function g(){ for(var i=0;i<arguments.length;i++){ var v=f[arguments[i]]; if(v!=null&&v!=="") return String(v); } return ""; }
  var rows=[];
  function add(label,val,mono){ if(val) rows.push('<div class="insp-row"><div class="insp-k">'+esc(label)+'</div><div class="insp-v'+(mono?' kf-mono':'')+'">'+esc(String(val).slice(0,220))+'</div></div>'); }
  add("Host", g("computer_name","computername","computer","hostname","host","workstation","device","machinename","dvchost"));
  var lt=g("logontype","logon_type"); if(lt) add("Logon type", LOGON_TYPES[lt]||lt);
  add("Target user", g("targetusername"));
  add("Process", g("image","newprocessname","process_name","processname","exe"), true);
  add("Command line", g("commandline","command_line","cmdline","process_command_line"), true);
  add("Parent process", g("parentimage","parentprocessname","parent_process"), true);
  add("Script block", g("scriptblocktext"), true);
  add("Target file", g("targetfilename"), true);
  var dip=g("destinationip","dest_ip","destip"); var dpt=g("destinationport","dest_port","destport");
  if(dip) add("Destination", dip+(dpt?":"+dpt:""));
  add("Service", g("servicename"));
  add("Failure status", g("status","failurereason"));
  add("Hashes", g("hashes","sha256","sha1","md5"), true);
  add("Rule / signature", g("rulename","signature","alertname"));
  if(!rows.length) return "";
  return '<div class="insp-sub">Key fields</div>'+rows.join("");
}
function openInspector(ev){
  if (!ev) return;
  var d = document.getElementById("inspector"), b = document.getElementById("inspectorBackdrop"), body = document.getElementById("inspBody");
  if (!d || !body) return;
  var ttl = document.getElementById("inspTitle"); if (ttl) ttl.textContent = "Event details";
  var sv = severityOf(ev);
  var eid = (typeof huntEid === "function") ? huntEid(ev) : "";
  var ety = (typeof huntEtype === "function") ? huntEtype(ev) : "";
  function row(k,v){ if (v==null || v==="" || v==="-") return ""; return '<div class="insp-row"><div class="insp-k">'+esc(k)+'</div><div class="insp-v">'+v+'</div></div>'; }
  var ipBtn = (ev.ip && ev.ip!=="-" && ev.ip!=="0.0.0.0") ? '<button class="btn btn-outline" data-pivot="'+esc(ev.ip)+'" data-pivot-label="'+esc(ev.ip)+'">\uD83D\uDD0D See all events from '+esc(ev.ip)+'</button>' : '';
  var acBtn = (ev.actor && ev.actor!=="unknown" && ev.actor!=="-") ? '<button class="btn btn-outline" data-pivot="'+esc(ev.actor)+'" data-pivot-label="'+esc(ev.actor)+'">\uD83D\uDD0D See all events from '+esc(ev.actor)+'</button>' : '';
  var why = (typeof severityExplain === "function") ? severityExplain(ev).reason : "";
  body.innerHTML =
      row("Verdict", sevBadge(sv))
    + row("Why this verdict", '<span class="insp-why">'+esc(why)+'</span><div class="muted small" style="margin-top:3px;">Check this reason against the raw event below \u2014 if it is wrong, use the verdict buttons in Investigate or add an allow/block rule.</div>')
    + row("Time", esc(formatTime(ev.time)))
    + row("Event ID", esc(eid))
    + keyFieldsHtml(ev)
    + row("Type", esc(ety))
    + row("User", esc(ev.actor||"-"))
    + row("IP", esc(ev.ip||"-"))
    + row("Action", esc(ev.action||"-"))
    + row("Source", esc(ev.source||"-"))
    + ((ipBtn||acBtn) ? '<div class="insp-actions">'+ipBtn+acBtn+'</div>' : '')
    + '<details class="insp-raw" open><summary>Raw event</summary><pre>'+esc(JSON.stringify(ev.raw||ev, null, 2))+'</pre></details>';
  d.classList.add("open"); if (b) b.classList.add("open");
}
/* ---- Investigation aids for the incident drawer: turn a pile of correlated events into the things an
   analyst actually needs — the story, the answers to the standard questions, the blast radius, the
   ATT&CK techniques seen, other incidents this attacker touched, and the IOCs to block. ---- */
function _hostOf(e){ var f=flatOf(e); return lookupKeys(f,["computer_name","computername","computer","hostname","host","dest_host","instanceid","device","machinename","dvchost"]) || ""; }
function _txt(e){ return ((e.action||"")+" "+rawStr(e)).toLowerCase(); }
// A step-by-step narrative: consecutive near-identical events are collapsed ("5x failed logon").
function buildAttackStory(chain){
  var evs=(chain.events||[]).filter(function(e){ return e.time && !isNaN(Date.parse(e.time)); })
          .sort(function(a,b){ return new Date(a.time)-new Date(b.time); });
  if(!evs.length) return [];
  var steps=[], cur=null;
  evs.forEach(function(e){
    var stage=classifyStage(e), key=stage+"|"+String(e.action||"").replace(/\d+/g,"#").slice(0,40)+"|"+(e.actor||"");
    if(cur && cur.key===key && (new Date(e.time)-new Date(cur.last))<10*60*1000){ cur.n++; cur.last=e.time; return; }
    cur={ key:key, n:1, first:e.time, last:e.time, stage:stage, action:String(e.action||"").slice(0,90), actor:e.actor, ip:e.ip, sev:severityOf(e) };
    steps.push(cur);
  });
  return steps;
}
// The standard IR questions, answered from the evidence with the snippet that answers them.
function investigationChecklist(chain){
  var blob=(chain.events||[]).map(_txt).join("\n");
  var hosts={}; (chain.events||[]).forEach(function(e){ var h=_hostOf(e); if(h) hosts[String(h)]=1; });
  function q(question, re, yesNote, noNote){ var m=blob.match(re); return { q:question, yes:!!m, evidence:m?("'"+m[0].slice(0,50)+"'"):"", note:m?yesNote:noNote }; }
  return [
    q("Did the attacker authenticate successfully?", /\b4624\b|logon success|login success|accepted (password|publickey)|authenticated|consolelogin/, "a successful logon is present \u2014 treat the account as compromised", "no successful logon seen \u2014 may be attempts only"),
    q("Was credential access observed?", /lsass|mimikatz|sekurlsa|procdump|dumpert|ntds\.dit|secretsdump|hashdump|comsvcs.*minidump|kerberoast/, "credentials were likely harvested \u2014 rotate them", "no credential-dumping activity seen"),
    q("Did it spread to other hosts (lateral movement)?", /psexec|psexesvc|smbexec|wmic.*node|\\\\admin\$|lateral|winrm|\brdp\b.*(login|logon|connect)|type\s*3\b.*4624/, "movement to another host is indicated", "no lateral movement seen"),
    q("Was persistence established?", /currentversion\\run|run key|schtasks|scheduled task|new-service|sc create|startup folder|\bcron\b|persistence/, "a persistence mechanism was set \u2014 it survives reboot/password change", "no persistence seen"),
    q("Was data moved or exfiltrated?", /exfil|large transfer|bytes_out|upload(ed)? to|to (s3|dropbox|mega|pastebin)|rclone|\bscp\b .*@/, "data left the environment \u2014 scope what", "no outbound data movement seen"),
    q("Were defenses tampered with (logs cleared, AV disabled)?", /wevtutil|clear-eventlog|\b1102\b|disable.?(defender|antivirus|realtime|firewall|logging)|set-mppreference|tamper/, "anti-forensics \u2014 assume telemetry is incomplete", "no defense tampering seen"),
    { q:"How many hosts were touched?", yes:Object.keys(hosts).length>1, evidence:Object.keys(hosts).length?Object.keys(hosts).slice(0,6).join(", "):"", note:Object.keys(hosts).length>1?"multi-host \u2014 contain all of them":(Object.keys(hosts).length?"single host":"no host field in these events") }
  ];
}
function blastRadius(chain){
  var hosts={}; (chain.events||[]).forEach(function(e){ var h=_hostOf(e); if(h) hosts[String(h)]=1; });
  return { hosts:Object.keys(hosts), users:(chain.actors||[]).filter(function(a){ return classifyIp(a)!=="public"; }), ips:chain.ips||[], domains:chain.domains||[], hashes:chain.hashes||[] };
}
// ATT&CK techniques whose detections include events from THIS incident (signal rules only).
function techniquesObserved(chain){
  var set={}; (chain.events||[]).forEach(function(e){ set[rawStr(e)+"|"+e.time+"|"+e.action]=1; });
  var dets=runDetections(state.logs||[]), out={};
  dets.forEach(function(d){ if(d.rule.meta) return;
    if((d.events||[]).some(function(e){ return set[rawStr(e)+"|"+e.time+"|"+e.action]; })) out[d.rule.id]=d.rule.name; });
  return Object.keys(out).map(function(id){ return { id:id, name:out[id] }; });
}
// Other incidents that share an actor / public IP / hash with this one — the attacker's wider footprint.
function relatedIncidents(chain){
  var all=correlateChains(state.logs||[], 24*3600*1000);
  var mine={}; (chain.actors||[]).forEach(function(a){ mine["a:"+a]=1; }); (chain.ips||[]).forEach(function(i){ mine["i:"+i]=1; }); (chain.hashes||[]).forEach(function(h){ mine["h:"+h]=1; });
  var out=[];
  all.forEach(function(c,i){ if(c===chain || (c.start===chain.start && c.size===chain.size && c.events[0]===chain.events[0])) return;
    var shared=[]; (c.actors||[]).forEach(function(a){ if(mine["a:"+a]) shared.push(a); }); (c.ips||[]).forEach(function(x){ if(mine["i:"+x]) shared.push(x); }); (c.hashes||[]).forEach(function(h){ if(mine["h:"+h]) shared.push(h.slice(0,10)+"\u2026"); });
    if(shared.length) out.push({ idx:i, size:c.size, shared:shared.slice(0,3), stages:c.stages||[] });
  });
  return out.slice(0,5);
}
function iocText(chain){ var b=blastRadius(chain); return [].concat(b.ips, b.domains, b.hashes).join("\n"); }
function copyIocs(chain){
  var t=iocText(chain); if(!t) return;
  try{ if(navigator && navigator.clipboard) navigator.clipboard.writeText(t); else { var ta=document.createElement("textarea"); ta.value=t; document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove(); } }catch(e){}
  var m=document.getElementById("iocCopyMsg"); if(m){ m.textContent="copied "+t.split("\n").length+" indicator(s)"; setTimeout(function(){ m.textContent=""; }, 2500); }
}
function openIncidentInspector(c){
  if (!c) return;
  var d = document.getElementById("inspector"), b = document.getElementById("inspectorBackdrop"), body = document.getElementById("inspBody");
  if (!d || !body) return;
  var dc = (typeof decisionCard === "function") ? decisionCard(c) : {};
  var ttl = document.getElementById("inspTitle"); if (ttl) ttl.textContent = "Incident details";
  function row(k,v){ if (v==null || v==="" ) return ""; return '<div class="insp-row"><div class="insp-k">'+esc(k)+'</div><div class="insp-v">'+v+'</div></div>'; }
  function pivots(arr){ if(!arr||!arr.length) return ""; return arr.slice(0,15).map(function(v){ var e=esc(String(v)); return '<span class="pivot" data-pivot="'+e+'" data-pivot-label="'+e+'">'+e+'</span>'; }).join(" "); }
  var stages = (c.stages && c.stages.length) ? c.stages.map(function(s){ return '<span class="stage-pill">'+esc(s)+'</span>'; }).join(' <span class="arrow">\u2192</span> ') : "";
  var earlyStages = (c.stages||[]).filter(function(s){ return /recon|discovery|initial access|credential/i.test(s); });
  var earlyBanner = earlyStages.length
    ? '<div class="insp-early">\u26a0 Early kill-chain stage present ('+earlyStages.map(esc).join(", ")+'). Recon / initial-access / credential activity is how intrusions begin \u2014 investigate before dismissing, even if severity looks low.</div>'
    : "";
  var evs = c.events || [];
  window.__inspEvents = evs;
  // ---- attack timeline reconstruction (DFIR core): entry point, first->last seen, duration ----
  var timed = evs.filter(function(e){ return e.time && !isNaN(Date.parse(e.time)); })
                 .sort(function(a,b){ return new Date(a.time) - new Date(b.time); });
  var entry = timed[0] || evs[0];
  var entryIdx = evs.indexOf(entry);
  var tlRow = "";
  if (timed.length >= 2) {
    var t0=new Date(timed[0].time), t1=new Date(timed[timed.length-1].time);
    var mins=Math.round((t1-t0)/60000);
    var dur = mins<1 ? "under a minute" : mins<60 ? mins+" min" : mins<2880 ? (mins/60).toFixed(1)+" h" : Math.round(mins/1440)+" days";
    tlRow = row("Attack timeline", esc(formatTime(timed[0].time))+' <span class="arrow">\u2192</span> '+esc(formatTime(timed[timed.length-1].time))+' <span class="muted">('+esc(dur)+', '+evs.length+' events)</span>');
  }
  var entryRow = entry ? row("Entry point (first event)",
      '<span class="insp-ev" data-ev-idx="'+entryIdx+'" style="display:inline-flex;max-width:100%;">'
      + '<span class="ie-t">'+esc(formatTime(entry.time))+'</span> '
      + '<span class="stage-pill">'+esc((typeof classifyStage==="function"?classifyStage(entry):"") )+'</span> '
      + '<span class="ie-a">'+esc(String(entry.action||"").slice(0,70))+'</span></span>'
      + '<div class="muted small" style="margin-top:3px;">Investigate backward from here \u2014 how did this first event get in?</div>') : "";
  var evRows = evs.slice(0,50).map(function(e,i){ return '<div class="insp-ev" data-ev-idx="'+i+'"><span class="ie-t">'+esc(formatTime(e.time))+'</span> '+sevBadge(severityOf(e))+' <span class="ie-a">'+esc(String(e.action||"").slice(0,80))+'</span></div>'; }).join("");
  var steps = (dc.steps && dc.steps.length) ? '<ol class="insp-steps">'+dc.steps.map(function(s){ return '<li>'+esc(s)+'</li>'; }).join("")+'</ol>' : "";
  body.innerHTML =
      earlyBanner
    + row("Priority", '<span class="dc-pri '+(dc.pClass||"")+'">'+esc(dc.priority||"")+'</span>')
    + row("Risk", (dc.risk!=null?esc(String(dc.risk))+' / 100':""))
    + row("Confidence", (dc.confidence!=null?esc(String(dc.confidence))+'%':""))
    + row("Scenario", dc.scenario ? esc(dc.scenario.name) + ' <span class="muted">('+dc.scenario.confidence+'% match)</span>' : "")
    + row("Kill chain", stages)
    + tlRow
    + entryRow
    + row("Recommended action", esc(dc.action||""))
    + row("Users", pivots(c.actors))
    + row("IPs", pivots(c.ips))
    + row("Domains", pivots(c.domains))
    + (function(){
        // ---- Attack story: the incident as numbered steps, consecutive repeats collapsed ----
        var story=buildAttackStory(c);
        var storyHtml = story.length ? '<div class="insp-sub">Attack story \u2014 what happened, in order</div><ol class="insp-story">'
          + story.slice(0,15).map(function(s){ return '<li><span class="ie-t">'+esc(formatTime(s.first))+'</span> <span class="stage-pill">'+esc(s.stage)+'</span> '+sevBadge(s.sev)+' <span class="story-a">'+(s.n>1?'<b>'+s.n+'\u00d7</b> ':'')+esc(s.action)+'</span>'+(s.actor&&s.actor!=="unknown"?' <span class="muted">by '+esc(s.actor)+'</span>':'')+(s.ip&&s.ip!=="-"?' <span class="muted">from '+esc(s.ip)+'</span>':'')+'</li>'; }).join("")
          + (story.length>15?'<li class="muted">\u2026 and '+(story.length-15)+' more step(s)</li>':'') + '</ol>' : "";
        // ---- Investigation checklist: the standard IR questions, answered from the evidence ----
        var chk=investigationChecklist(c);
        var chkHtml='<div class="insp-sub">Investigation checklist \u2014 answered from the evidence</div><div class="insp-chk">'
          + chk.map(function(x){ return '<div class="chk-row '+(x.yes?'chk-yes':'chk-no')+'"><span class="chk-mark">'+(x.yes?'\u2714':'\u2013')+'</span><div><b>'+esc(x.q)+'</b> <span class="chk-ans">'+(x.yes?'Yes':'No')+'</span>'+(x.evidence?' <span class="muted">('+esc(x.evidence)+')</span>':'')+'<div class="muted small">'+esc(x.note)+'</div></div></div>'; }).join("") + '</div>';
        // ---- Blast radius + techniques + related incidents + copy IOCs ----
        var br=blastRadius(c);
        var brHtml='<div class="insp-sub">Blast radius</div><div class="insp-br">'
          + '<span><b>'+br.hosts.length+'</b> host'+(br.hosts.length===1?'':'s')+(br.hosts.length?': '+br.hosts.slice(0,5).map(esc).join(", ")+(br.hosts.length>5?' \u2026':''):'')+'</span>'
          + '<span><b>'+br.users.length+'</b> account'+(br.users.length===1?'':'s')+'</span><span><b>'+br.ips.length+'</b> external IP'+(br.ips.length===1?'':'s')+'</span><span><b>'+br.domains.length+'</b> domain'+(br.domains.length===1?'':'s')+'</span><span><b>'+br.hashes.length+'</b> file hash'+(br.hashes.length===1?'':'es')+'</span></div>';
        var tech=techniquesObserved(c);
        var techHtml = tech.length ? '<div class="insp-sub">ATT&amp;CK techniques observed in this incident</div><div class="insp-tech">'+tech.map(function(t){ return '<span class="mitre-tag">'+esc(t.id)+' \u00b7 '+esc(t.name)+'</span>'; }).join(" ")+'</div>' : "";
        var rel=relatedIncidents(c);
        var relHtml = rel.length ? '<div class="insp-sub">Related incidents \u2014 same attacker / IP / file elsewhere</div><div class="insp-rel">'+rel.map(function(r){ return '<div class="rel-row"><b>Incident #'+(r.idx+1)+'</b> <span class="muted">('+r.size+' events'+(r.stages.length?', '+esc(r.stages.slice(0,3).join(" \u2192 ")):'')+')</span> \u2014 shares <span class="pivot" data-pivot="'+esc(r.shared[0])+'" data-pivot-label="'+esc(r.shared[0])+'">'+esc(r.shared.join(", "))+'</span></div>'; }).join("")+'</div>' : "";
        var iocs=iocText(c);
        var copyHtml = iocs ? '<div class="insp-actions" style="margin-top:12px;"><button class="btn btn-outline" id="iocCopyBtn">\u2398 Copy '+iocs.split("\n").length+' IOC'+(iocs.split("\n").length===1?'':'s')+' for blocking</button><span id="iocCopyMsg" class="muted small"></span></div>' : "";
        return storyHtml + chkHtml + brHtml + techHtml + relHtml + copyHtml;
      })()
    + (steps ? '<div class="insp-sub">Investigation steps</div>'+steps : "")
    + (evRows ? '<div class="insp-sub">Events in this incident ('+evs.length+') \u2014 click one for full detail</div><div class="insp-evs">'+evRows+'</div>' : "");
  var cb=document.getElementById("iocCopyBtn"); if(cb) cb.onclick=function(){ copyIocs(c); };
  d.classList.add("open"); if (b) b.classList.add("open");
}
function closeInspector(){ var d=document.getElementById("inspector"), b=document.getElementById("inspectorBackdrop"); if(d)d.classList.remove("open"); if(b)b.classList.remove("open"); }
if (typeof document !== "undefined" && document.addEventListener) {
  document.addEventListener("click", function(e){
    if (e.target && (e.target.id==="inspClose" || e.target.id==="inspectorBackdrop")) { closeInspector(); return; }
    var ie = e.target && e.target.closest ? e.target.closest(".insp-ev") : null;
    if (ie){ var idx=+ie.getAttribute("data-ev-idx"); var evs=(typeof window!=="undefined"&&window.__inspEvents)||[]; if(evs[idx]) openInspector(evs[idx]); }
  });
  document.addEventListener("keydown", function(e){ if (e.key==="Escape") closeInspector(); });
}
if (typeof document !== "undefined" && document.addEventListener) {
  document.addEventListener("click", function(e){
    var t = e.target && e.target.closest ? e.target.closest("[data-pivot]") : null;
    if (t) { e.stopPropagation(); e.preventDefault(); pivotTo(t.getAttribute("data-pivot"), t.getAttribute("data-pivot-label")); }
  }, true);  // capture phase so it wins over row/card click handlers
}

// ===== Hunt: self-service investigation workbench (user-driven, precise filtering) =====





