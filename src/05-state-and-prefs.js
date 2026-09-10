/* ============================================================
 * CloudLog — 05-state-and-prefs.js
 * Analyst state, persistence, clear/logout, custom-rule engine, runDetections.
 * Part of index.html; assembled by build.js. Do not add a <script> wrapper.
 * ============================================================ */
var CUSTOM_RULES = [];
var IOC_BLOCKLIST = new Set();
var ALLOWLIST = new Set();
var YARA_RULES = [];
var MEMORY_BAD = new Set();   // IOCs confirmed malicious by analyst in past incidents (investigation memory)
var VERDICTS = {};            // incident signature -> {verdict, note, ts}
var ASSET_CRITICALITY = {};   // hostname/ip (lower) -> level 1..10 (analyst override)

/* ---- Persist analyst knowledge (block/allow lists, custom rules, memory, asset criticality)
        across sessions, so you don't re-enter IPs and rules every time. Logs are NOT stored. ---- */
var PREFS_KEY = "cloudlog_prefs_v1";
/* Detections depend on CUSTOM_RULES / IOC_BLOCKLIST / ALLOWLIST / MEMORY_BAD. Every mutation of
   those flows through savePrefs(), so this is the one choke point where the detection cache MUST
   be invalidated — otherwise a worker-cached big file keeps showing stale detections after you
   add a rule or block an IP. */
function invalidateDetectionCache(){
  if (typeof window !== "undefined") { window.__DET_CACHE = null; window.__DET_CACHE_LIST = null; }
}
function savePrefs(){
  invalidateDetectionCache();
  try {
    if (typeof localStorage === "undefined") return;
    localStorage.setItem(PREFS_KEY, JSON.stringify({
      blocklist: Array.from(IOC_BLOCKLIST), allowlist: Array.from(ALLOWLIST),
      customRules: CUSTOM_RULES, memoryBad: Array.from(MEMORY_BAD), assetCriticality: ASSET_CRITICALITY
    }));
  } catch (e) {}
}
function loadPrefs(){
  try {
    if (typeof localStorage === "undefined") return;
    var d = JSON.parse(localStorage.getItem(PREFS_KEY) || "null"); if (!d) return;
    IOC_BLOCKLIST = new Set(d.blocklist || []);
    ALLOWLIST = new Set(d.allowlist || []);
    CUSTOM_RULES = Array.isArray(d.customRules) ? d.customRules : [];
    MEMORY_BAD = new Set(d.memoryBad || []);
    ASSET_CRITICALITY = d.assetCriticality || {};
    // reflect into the input boxes if present
    var bl=document.getElementById("blText"); if(bl) bl.value=Array.from(IOC_BLOCKLIST).join("\n");
    var al=document.getElementById("alText"); if(al) al.value=Array.from(ALLOWLIST).join("\n");
    var ac=document.getElementById("acText"); if(ac) ac.value=Object.keys(ASSET_CRITICALITY).map(function(k){return k+","+ASSET_CRITICALITY[k];}).join("\n");
    if (typeof renderCustomRuleList === "function") renderCustomRuleList();
  } catch (e) {}
}
function clearSavedPrefs(){
  try { if (typeof localStorage !== "undefined") localStorage.removeItem(PREFS_KEY); } catch (e) {}
  IOC_BLOCKLIST=new Set(); ALLOWLIST=new Set(); CUSTOM_RULES=[]; MEMORY_BAD=new Set(); ASSET_CRITICALITY={};
  ["blText","alText","acText"].forEach(function(id){ var e=document.getElementById(id); if(e) e.value=""; });
  if (typeof renderCustomRuleList === "function") renderCustomRuleList();
  if (typeof applyFilter === "function") applyFilter();
}
/* ---- Clear the currently loaded log (keeps your saved IPs/rules) ---- */
/* When the DATASET changes (new upload / sample), all investigation state from the old
   dataset must be dropped — a stale IP filter from the previous log makes the new one
   look empty ("Showing 0 of 4") and the pill/search reference entities that no longer exist. */
function resetViewState(){
  var sb=document.getElementById("search"); if(sb) sb.value="";
  var chip=document.getElementById("filterChip"); if(chip) chip.innerHTML="";
  if (typeof closeInspector === "function") closeInspector();
  if (typeof window !== "undefined") { window.__DET_CACHE=null; window.__DET_CACHE_LIST=null; }
  if (typeof huntClearAll === "function") { try { huntClearAll(); } catch(e){} }
}
function clearLogs(){
  if (!state.logs.length) { return; }
  if (typeof confirm === "function" && !confirm("Clear the loaded log and reset the view?\n\nYour saved block/allow lists and rules are kept.")) return;
  state.logs = []; state.filtered = []; state.source = "None"; state.detections = [];
  if (typeof window !== "undefined") { window.__DET_CACHE = null; window.__DET_CACHE_LIST = null; }
  var sb=document.getElementById("search"); if(sb) sb.value="";
  var chip=document.getElementById("filterChip"); if(chip) chip.innerHTML="";
  if (typeof closeInspector === "function") closeInspector();
  render([]);
  if (typeof switchToTab === "function") switchToTab("summary");   // land on the welcome screen so the reset is visible
  if (typeof window !== "undefined" && window.refreshMyStats) window.refreshMyStats();
}
/* ---- Log out: end the session and return to the lock screen ---- */
function doLogout(){
  if (typeof AUTH_SESSION === "undefined") return;
  AUTH_SESSION.unlocked=false; AUTH_SESSION.role="open"; AUTH_SESSION.code="";
  if (typeof authIsConfigured==="function" && authIsConfigured() && typeof showLock==="function") showLock();
  else if (typeof alert==="function") alert("No access code is set. Set an admin code in the Access control panel to enable login/logout.");
}
function guessCriticality(name){
  var n=String(name||"").toLowerCase();
  if(/\bdc\d*\b|domain.?controller|\bad(ds)?\b|\bkdc\b/.test(n)) return {level:10, source:"guessed: domain controller"};
  if(/prod|sql|oracle|\bdb\b|database|payment|finance|hsm|vault|backup/.test(n)) return {level:9, source:"guessed: production/data"};
  if(/server|srv|\bweb\b|api|app|gateway|firewall|vpn|dns/.test(n)) return {level:7, source:"guessed: server/infra"};
  if(/workstation|laptop|desktop|\bwks\b|user|hr|exec|ceo|cfo/.test(n)) return {level:5, source:"guessed: workstation"};
  if(/lab|test|\bdev\b|sandbox|staging|\bqa\b|demo|temp/.test(n)) return {level:2, source:"guessed: lab/test"};
  return {level:0, source:"unknown"};
}
function assetCriticalityFor(name){
  var n=String(name||"").toLowerCase();
  if(ASSET_CRITICALITY[n]!=null) return {level:ASSET_CRITICALITY[n], source:"analyst override"};
  return guessCriticality(n);
}
function parseAssetList(text){
  var map={}; (text||"").split(/[\r\n]+/).forEach(function(line){
    var m=line.split(/[,\t;]/); if(m.length>=2){ var name=m[0].trim().toLowerCase(); var lvl=parseInt(m[1],10); if(name && name[0]!=="#" && lvl>=1 && lvl<=10) map[name]=lvl; }
  }); return map;
}
var LAST_YARA_TEXT = "";
function eventIocValues(ev){ var io=extractIocs(ev); return io.ips.concat(io.domains,io.urls,io.hashes); }
function eventInAllowlist(ev){
  if (ev.ip && ALLOWLIST.has(String(ev.ip).toLowerCase())) return true;
  if (ev.actor && ALLOWLIST.has(String(ev.actor).toLowerCase())) return true;
  return eventIocValues(ev).some(function(v){ return ALLOWLIST.has(String(v).toLowerCase()); });
}
function eventHitsBlocklist(ev){
  if (ev.ip && (IOC_BLOCKLIST.has(String(ev.ip).toLowerCase()) || MEMORY_BAD.has(String(ev.ip).toLowerCase()))) return true;
  return eventIocValues(ev).some(function(v){ v=String(v).toLowerCase(); return IOC_BLOCKLIST.has(v) || MEMORY_BAD.has(v); });
}
function parseIocList(text){ var out=[]; (text||"").split(/[\r\n,;]+/).forEach(function(line){ var v=line.trim().toLowerCase().replace(/^hxxp/,"http").replace(/\[\.\]/g,"."); if(v && v[0]!=="#") out.push(v); }); return out; }
function parseYara(text){
  LAST_YARA_TEXT = text || "";
  var rules=[], re=/rule\s+([A-Za-z0-9_]+)\s*(?::[^{]*)?\{([\s\S]*?)\}\s*(?=rule\s|$)/g, m;
  while((m=re.exec(text))){
    var body=m[2], strings=[];
    var sm=body.match(/strings:\s*([\s\S]*?)(?:condition:|$)/i);
    if(sm){ var sb=sm[1], tm, rm;
      var tre=/\$(\w+)\s*=\s*"((?:[^"\\]|\\.)*)"[ \t]*([a-z ]*)/gi;
      while((tm=tre.exec(sb))){ strings.push({id:tm[1], value:tm[2].replace(/\\"/g,'"'), isRegex:false, nocase:/nocase/i.test(tm[3])}); }
      var rre=/\$(\w+)\s*=\s*\/((?:[^\/\\]|\\.)*)\/\s*(\w*)/g;
      while((rm=rre.exec(sb))){ strings.push({id:rm[1], value:rm[2], isRegex:true, nocase:/i/.test(rm[3])}); }
    }
    var cm=body.match(/condition:\s*([\s\S]*?)$/i);
    rules.push({ name:m[1], strings:strings, condition:(cm?cm[1]:"any of them").trim().replace(/\s+/g," "), hexOnly: strings.length===0 && /\{[0-9a-f?\s]+\}/i.test(body) });
  }
  return rules;
}
function matchYara(rule, hayOrig){
  if(!rule.strings.length) return false;
  var hayLower=hayOrig.toLowerCase(), hits={}, count=0;
  rule.strings.forEach(function(st){ var ok=false;
    if(st.isRegex){ try{ ok=new RegExp(st.value, st.nocase?"i":"").test(hayOrig);}catch(e){ok=false;} }
    else { ok = st.nocase ? hayLower.indexOf(st.value.toLowerCase())>=0 : hayOrig.indexOf(st.value)>=0; }
    if(ok){ hits[st.id]=1; count++; } });
  var cond=(rule.condition||"").toLowerCase();
  if(/all of them/.test(cond)) return count===rule.strings.length;
  var nOf=cond.match(/(\d+)\s+of them/); if(nOf) return count>=+nOf[1];
  if(/any of them/.test(cond)) return count>=1;
  var refs=cond.match(/\$\w+/g);
  if(refs){ var ids=refs.map(function(r){return r.slice(1);}); return /\band\b/.test(cond)? ids.every(function(i){return hits[i];}) : ids.some(function(i){return hits[i];}); }
  return count>=1;
}
function safeRegex(p){ try { return new RegExp(p, "i"); } catch(e){ return null; } }
function runCustomRule(cr, evts){
  var re = cr.isRegex ? safeRegex(cr.pattern) : null;
  var pat = (cr.pattern||"").toLowerCase();
  return evts.filter(function(e){
    var hay = ((e.action||"") + " " + rawStr(e)).toLowerCase();
    return re ? re.test(hay) : (pat && hay.indexOf(pat) >= 0);
  });
}
function runDetections(evts) {
  var found = [];
  CUSTOM_RULES.forEach(function(cr){
    var m = runCustomRule(cr, evts);
    if (m.length) found.push({ rule:{ id:"CUSTOM", name:cr.name, title:cr.name, sev:cr.sev,
      desc:"Custom rule — matches " + (cr.isRegex ? "/"+cr.pattern+"/i" : '"'+cr.pattern+'"'),
      suggestion:"User-defined detection rule." }, events:m });
  });
  if (IOC_BLOCKLIST.size){ var bl = evts.filter(eventHitsBlocklist);
    if (bl.length) found.push({ rule:{ id:"IOC-LIST", name:"Known-bad IOC", title:"Matched your imported IOC blocklist", sev:"high",
      desc:"Event contains an indicator from your imported known-bad list.", suggestion:"Treat as confirmed — block the indicator and investigate affected hosts." }, events:bl }); }
  YARA_RULES.forEach(function(y){
    var m = evts.filter(function(e){ var ho=(e.action||"")+" "+rawStr(e); return matchYara(y, ho); });
    if (m.length) found.push({ rule:{ id:"YARA", name:y.name, title:"YARA: "+y.name, sev:"high",
      desc:"Matched YARA rule strings (string-subset engine).", suggestion:"Review matched events and confirm the rule's intent." }, events:m }); });
  MITRE_RULES.forEach(function(rule) {
    if (rule.match) {
      var matches = evts.filter(rule.match);
      if (matches.length) found.push({ rule:rule, events:matches });
    }
    if (rule.group) {
      var groups = rule.group(evts);
      groups.forEach(function(g){ found.push({ rule:rule, events:g.events, actor:g.actor }); });
    }
  });
  // Stateful sequence detections (behaviour over time), merged with the atomic/signature findings.
  Array.prototype.push.apply(found, runStatefulDetections(evts));
  return found;
}

/* Stateful Sequence Engine — matches ordered behaviour over time per entity, catching attacks that
   are invisible line-by-line: brute-force-then-execute, or log-clearing right after discovery. Each
   rule is an ordered list of step-predicates that one actor must trigger in order, within a window.
   O(n) single pass over time-sorted events; safe inside the worker. */
var STATEFUL_RULES = [
  // ATO stays a TIGHT gap: a fail->success->execute burst is only high-fidelity when it's fast;
  // spread over hours it's ambiguous (busy admins do this), so we don't force-fire it there.
  { id:"SEQ-ATO", name:"Brute-force \u2192 success \u2192 execution (Account Takeover)", sev:"high", gapMs:15*60*1000,
    steps:[ function(t){ return /fail(ed)?\s*log|4625|auth.*fail|invalid (user|password)|brute|spray/.test(t); },
            function(t){ return /4624|logon success|login success|authenticated|\bsignin\b|accepted (password|publickey)/.test(t); },
            function(t){ return /powershell|cmd\.exe|\b4688\b|process create|wmic|mimikatz|whoami|net user|net group|net localgroup/.test(t); } ],
    desc:"One entity failed authentication, then authenticated successfully, then executed shell/discovery commands in quick succession \u2014 a confirmed account-takeover sequence, not three unrelated events.",
    suggestion:"Treat as active compromise: lock the account, kill live sessions, and hunt what the shell did next." },
  // These two combos are rarely benign at ANY speed, so they use a generous per-step gap and will
  // catch "low and slow" progression (the sliding window resets each time the entity advances a step).
  { id:"SEQ-ANTIFORENSIC", name:"Discovery \u2192 log clearing (anti-forensics)", sev:"high", gapMs:6*3600*1000,
    steps:[ function(t){ return /whoami|net user|net group|nltest|systeminfo|ipconfig|arp -a|net view|discovery|reconnaissance/.test(t); },
            function(t){ return /clear.?ev|wevtutil\s+cl|1102|event log.*(clear|delet)|clearlog|remove.*eventlog|log clear/.test(t); } ],
    desc:"An endpoint ran discovery commands and later cleared its event logs \u2014 attackers wipe logs to hide what discovery revealed. Either event alone is minor; together they are a strong hands-on-keyboard signal at any tempo.",
    suggestion:"Escalate to P1. Preserve remaining logs/memory immediately and treat the host as compromised." },
  { id:"SEQ-HOK", name:"Execution \u2192 credential access \u2192 lateral movement", sev:"high", gapMs:4*3600*1000,
    steps:[ function(t){ return /powershell|cmd\.exe|\b4688\b|wmic|mshta|rundll32/.test(t); },
            function(t){ return /lsass|mimikatz|sekurlsa|procdump.*lsass|dumpert|cred/.test(t); },
            function(t){ return /psexec|psexesvc|\b4624\b.*type\s*3|wmic.*node|smbexec|lateral|admin\$/.test(t); } ],
    desc:"Code execution, then credential theft, then movement to another host \u2014 the classic hands-on-keyboard progression toward domain compromise, tracked even when the attacker moves slowly.",
    suggestion:"Contain the source host and any hosts it reached; reset exposed credentials and hunt for persistence." },
  // Gaining privilege and then switching off the security tooling is defence-evasion with intent:
  // admins rarely disable Defender/EDR/logging in the minutes after a role or privilege change.
  { id:"SEQ-PRIVDISABLE", name:"Privilege change \u2192 security tooling disabled", sev:"high", gapMs:2*3600*1000,
    steps:[ function(t){ return /privilege escalation|\b4672\b|add member to role|attachuserpolicy|attachrolepolicy|net localgroup administrators.*\/add|net group.*domain admins.*\/add|getsystem|uac bypass|\brunas\b|setiampolicy|elevat/.test(t); },
            function(t){ return /disable.?(defender|antivirus|realtimemonitoring|firewall|logging|edr|av\b)|set-mppreference.*-disable|disablerealtimemonitoring|netsh advfirewall set .*off|sc (stop|config) .*(defend|sense|edr|sysmon|splunk|falcon|cylance|sentinel)|taskkill.*(msmpeng|sense|cb\.exe|cylance|xagt)|wevtutil (cl|sl).*\/e:false|clear-eventlog|stop-service .*(defend|sense|sysmon)|tamper protection/.test(t); } ],
    desc:"An entity gained or changed privileges and then disabled security tooling (Defender/EDR/firewall/logging) shortly after \u2014 the attacker is switching off the alarms right after getting the keys. Either step alone can be admin work; the ordered pair is a strong intrusion signal.",
    suggestion:"Treat as active hands-on intrusion: re-enable protections, isolate the host, and audit what ran while tooling was off." },
  // Bulk outbound data right after a credential dump is exfiltration of the harvest.
  { id:"SEQ-CREDEXFIL", name:"Credential dump \u2192 large outbound transfer (exfiltration)", sev:"high", gapMs:6*3600*1000,
    steps:[ function(t){ return /lsass|mimikatz|sekurlsa|procdump.*lsass|dumpert|nanodump|ntds\.dit|secretsdump|hashdump|comsvcs.*minidump/.test(t); },
            function(t){ return /exfil|large transfer|bytes_out|bytes_sent|upload(ed)? to|to (s3|dropbox|mega\.nz|pastebin|transfer\.sh|anonfiles)|\brclone\b|\bscp\b .*@|curl .*(-t|--upload-file)|invoke-webrequest.*-method post|\bmega\b.*(put|upload)|data (transfer|staging)/.test(t); } ],
    desc:"Credentials were dumped and then a large or cloud-bound outbound transfer followed \u2014 consistent with exfiltrating the harvested credentials/data. Credential access followed by movement of data is a late-stage, high-impact pattern.",
    suggestion:"Assume the dumped credentials are compromised: rotate them, block the destination, and scope what data left." }
];
function runStatefulDetections(evts){
  var sorted = evts.slice().filter(function(e){ return e.time && !isNaN(Date.parse(e.time)); })
                           .sort(function(a,b){ return new Date(a.time)-new Date(b.time); });
  var active = {}; // key -> { step, lastTime, events, boundKeys, boundActor }
  var findings = [];
  sorted.forEach(function(ev){
    var t = new Date(ev.time).getTime();
    var pubIp = (ev.ip && ev.ip !== "-" && ev.ip !== "0.0.0.0" && classifyIp(ev.ip) === "public") ? ev.ip : null;
    // normalize() falls back to actor=IP when no username is present; for sequence-binding we only
    // want a REAL username (so a spray with no user keys on IP, and the account is bound later when
    // the successful logon reveals it — which is exactly what defeats the pivot-off-IP evasion).
    var actor = (ev.actor && ev.actor !== "unknown" && ev.actor !== "-" && String(ev.actor).toLowerCase() !== String(ev.ip||"").toLowerCase()) ? String(ev.actor).toLowerCase() : null;
    var text = (ev.action + " " + rawStr(ev)).toLowerCase();
    STATEFUL_RULES.forEach(function(rule){
      // find an in-window tracker under EITHER this entity's actor key or its public-IP key
      var lookKeys = [];
      if (actor) lookKeys.push(rule.id + "|actor:" + actor);
      if (pubIp) lookKeys.push(rule.id + "|ip:" + pubIp);
      var tr = null, trKey = null;
      for (var i=0;i<lookKeys.length;i++){
        var k = lookKeys[i], a = active[k];
        if (a){ if (t - a.lastTime <= rule.gapMs){ tr = a; trKey = k; break; } else delete active[k]; }
      }
      var step = tr ? tr.step : 0;
      if (rule.steps[step](text)){
        if (!tr){
          tr = { step:0, lastTime:t, events:[], boundKeys:{}, boundActor:actor };
          trKey = pubIp ? (rule.id + "|ip:" + pubIp) : (rule.id + "|actor:" + actor);
          active[trKey] = tr; tr.boundKeys[trKey] = 1;
        }
        tr.events.push(ev); tr.step++; tr.lastTime = t;
        // bind the ACTOR to this tracker the first time we learn it, so the sequence follows the
        // compromised account after the spray pivots off the source IP. Only bind if this tracker
        // has no actor yet (prevents a different user's event hijacking someone else's tracker).
        if (actor){
          if (!tr.boundActor) tr.boundActor = actor;                       // the first real account seen owns this tracker
          if (actor === tr.boundActor){ var ak = rule.id + "|actor:" + actor; if (!tr.boundKeys[ak]){ active[ak] = tr; tr.boundKeys[ak] = 1; } }
          // a different account never gets bound -> no cross-actor contamination
        }
        if (tr.step === rule.steps.length){
          findings.push({ rule:{ id:rule.id, name:rule.name, title:rule.name, sev:rule.sev, desc:rule.desc, suggestion:rule.suggestion },
                          events:tr.events.slice(), actor: tr.boundActor || pubIp || "unknown" });
          Object.keys(tr.boundKeys).forEach(function(bk){ delete active[bk]; });
        }
      }
    });
  });
  return findings;
}

/* ---------- Main render ---------- */





