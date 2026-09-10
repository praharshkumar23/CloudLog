/* ============================================================
 * CloudLog — 13-decisions-and-cases.js
 * Scenario recognition, decision cards, case management, renderInvestigate, save/load.
 * Part of index.html; assembled by build.js. Do not add a <script> wrapper.
 * ============================================================ */
function sequenceSignals(chain){
  var evs = (chain.events||[]).filter(function(e){ return e.time && !isNaN(Date.parse(e.time)); })
                              .sort(function(a,b){ return new Date(a.time)-new Date(b.time); });
  var WINDOW = 10*60*1000;  // 10 minutes
  var out = { takeover:false, windowMin:null };
  function txt(e){ return (e.action+" "+rawStr(e)).toLowerCase(); }
  for (var i=0;i<evs.length;i++){
    if (!/fail(ed)?\s*log|4625|auth.*fail|invalid (user|password)|brute|spray/.test(txt(evs[i]))) continue;
    var start = new Date(evs[i].time), sawSuccess=false;
    for (var j=i+1;j<evs.length;j++){
      if (new Date(evs[j].time)-start > WINDOW) break;
      var tj = txt(evs[j]);
      if (!sawSuccess && /4624|logon success|login success|authenticated|\bsignin\b|accepted (password|publickey)/.test(tj)) sawSuccess=true;
      else if (sawSuccess && /powershell|cmd\.exe|\b4688\b|process create|wmic|mimikatz|whoami|net user|net group|net localgroup|reg add|schtasks/.test(tj)){
        out.takeover=true; out.windowMin=Math.max(1, Math.round((new Date(evs[j].time)-start)/60000)); return out;
      }
    }
  }
  return out;
}

function recognizeScenario(chain, blob, stages, f) {
  var cands = [];
  var failLogin = /fail(ed)?\s*log|4625|invalid (user|password)|auth.*fail/.test(blob);
  var okLogin = /4624|logon success|login success|authenticated|\bsignin\b/.test(blob);
  var mfa = /mfa|multi-?factor|otp|password (change|reset)|new device/.test(blob);
  var lateral = /lateral|psexec|smb|wmi|remote (exec|desktop)|rdp/.test(blob);
  var encrypt = /encrypt|ransom|\.locked|shadowcopy|vssadmin/.test(blob);
  var webatk = /union select|sqlmap|<script>|\.\.\/|traversal|xss|or 1=1|etc\/passwd/.test(blob);
  var scanner = chain.events.some(function(e){ return e.isScanner; }) || /nmap|nikto|masscan|dirb|gobuster/.test(blob);
  var exfil = /large transfer|exfil|bytes_out|data transfer|s3.*(download|getobject)|zip|\.rar/.test(blob) || stages.indexOf("Exfiltration") >= 0;

  var beacon = /beacon|gate\.php|c2\b/.test(blob) || (stages.indexOf("Command and Control") >= 0);
  var dgaDns = chain.events.some(function(e){ return e.raw && e.raw.dns && (isRareTld(e.raw.dns) || looksDGA(e.raw.dns)); });
  var seq = sequenceSignals(chain);
  if (failLogin && (okLogin || mfa || f.hasPriv)) cands.push({ name:"Account Takeover", confidence: 55 + (okLogin?15:0) + (mfa?15:0) + (f.hasPriv?15:0) });
  if (seq.takeover) cands.push({ name:"Account Takeover (confirmed sequence)", confidence: 90, note:"failed logins \u2192 success \u2192 code execution within "+seq.windowMin+" min" });
  if ((f.hasCred || /powershell|cmd\.exe|mimikatz/.test(blob)) && (lateral || encrypt)) cands.push({ name:"Ransomware / Hands-on-keyboard", confidence: 50 + (encrypt?25:0) + (lateral?15:0) + (f.hasCred?10:0) });
  if (webatk) cands.push({ name:"Web Application Exploitation", confidence: 55 + (f.sev.malicious?20:0) + (scanner?10:0) });
  if (exfil && (f.hasCred || f.hasPriv || f.sev.malicious || beacon)) cands.push({ name:"Data Exfiltration", confidence: 50 + (f.hasCred?15:0) + 10 });
  if (scanner && !webatk) cands.push({ name:"Reconnaissance / Scanning", confidence: 45 + (chain.size>10?15:0) });
  if (beacon || dgaDns) cands.push({ name:"Malware / C2 Activity", confidence: 55 + (beacon?20:0) + (dgaDns?10:0) + (exfil?10:0) });
  if (f.hasMalware) cands.push({ name:"Malware / C2 Activity", confidence: 55 + (chain.ips.length?10:0) });
  if (!cands.length) return null;
  cands.sort(function(a,b){ return b.confidence - a.confidence; });
  var top = cands[0]; top.confidence = Math.min(92, top.confidence);
  return top;
}

// Entity Risk Engine — score each user / IP by fused signals across all their events
function computeEntityRisk(list) {
  var ent = {}; // key -> {type,name,mal,sus,fail,scanner,cred,priv,block,events}
  function get(type, name){ var k=type+"|"+name; return ent[k]||(ent[k]={type:type,name:name,mal:0,sus:0,fail:0,scanner:0,cred:0,priv:0,block:0,count:0}); }
  list.forEach(function(e){
    var sev=severityOf(e), blob=((e.action||"")+" "+rawStr(e)).toLowerCase();
    var subjects=[];
    if(e.actor && e.actor!=="unknown" && e.actor!=="-") subjects.push(["user",String(e.actor)]);
    extractIocs(e).ips.forEach(function(ip){ if(classifyIp(ip)==="public") subjects.push(["ip",ip]); });
    subjects.forEach(function(pair){
      var o=get(pair[0],pair[1]); o.count++;
      if(sev==="malicious") o.mal++; else if(sev==="suspicious") o.sus++;
      if(/fail(ed)?\s*log|4625|invalid (user|password)/.test(blob)) o.fail++;
      if(e.isScanner||/nmap|nikto|sqlmap|masscan/.test(blob)) o.scanner++;
      if(/lsass|mimikatz|sekurlsa|secretsdump|ntds\.dit|hashdump|credential dump|dumping cred|procdump.*lsass|comsvcs.*minidump/.test(blob)) o.cred++;
      if(/privilege|persistence|admin|sudo|role/.test(blob)) o.priv++;
      if((IOC_BLOCKLIST.size||MEMORY_BAD.size) && eventHitsBlocklist(e)) o.block++;
    });
  });
  return Object.keys(ent).map(function(k){
    var o=ent[k], ev=[];
    var score=Math.min(100, o.mal*18 + o.sus*5 + Math.min(o.fail,10)*4 + (o.cred?15:0) + (o.priv?12:0) + (o.block?30:0) + (o.scanner?8:0));
    if(o.block) ev.push("on known-bad / memory list");
    if(o.mal) ev.push(o.mal+" malicious event(s)");
    if(o.fail>=3) ev.push(o.fail+" failed logins");
    if(o.cred) ev.push("credential-access activity");
    if(o.priv) ev.push("privilege/persistence activity");
    if(o.scanner) ev.push("scanner/recon tooling");
    if(!ev.length) ev.push(o.count+" event(s), no strong signal");
    var conf=Math.min(95, 35 + ev.length*12);
    return { type:o.type, name:o.name, score:score, confidence:conf, evidence:ev };
  }).filter(function(x){ return x.score>0; }).sort(function(a,b){ return b.score-a.score; });
}

function decisionCard(chain) {
  var evs = chain.events || [];
  var sev = { malicious:0, suspicious:0, info:0 };
  evs.forEach(function (e) { sev[severityOf(e)]++; });
  var blob = evs.map(function (e) { return (e.action||"") + " " + rawStr(e); }).join(" ").toLowerCase();
  var stages = chain.stages || [];
  var hasPriv = stages.some(function (s) { return /privilege|persistence/i.test(s); });
  var hasCred = /lsass|mimikatz|sekurlsa|secretsdump|ntds\.dit|hashdump|credential dump|dumping cred|procdump.*lsass|comsvcs.*minidump/.test(blob);
  var hasMalware = /malware|trojan|ransom|backdoor|\bc2\b|exploit/.test(blob);
  var killPct = Math.round(Math.min(1, stages.length / 5) * 100);

  var evidence = [];
  if (sev.malicious) evidence.push(sev.malicious + " event(s) flagged malicious");
  if (chain.ips.length) evidence.push(chain.ips.length + " public IP(s)");
  if (chain.hashes.length) evidence.push(chain.hashes.length + " file hash(es)");
  if (stages.length >= 2) evidence.push("multi-stage (" + stages.join(" \u2192 ") + ")");
  if (hasCred) evidence.push("credential-access activity");
  if (hasPriv) evidence.push("privilege/persistence activity");
  if (!evidence.length) evidence.push("single low-signal event");

  // priority (mirrors real SOC triage table): P1 = confirmed/serious compromise, not just attempted probes
  var priority;
  var multiStage = stages.length >= 3;
  var confirmed = hasMalware || (sev.malicious && (hasCred || hasPriv || multiStage));
  if (confirmed) priority = "P1";                                       // malware/C2, or malicious + credential/privilege/multi-stage
  else if (sev.malicious || hasPriv || hasCred) priority = "P2";        // malicious attempt or priv/cred signal -> investigate
  else if (sev.suspicious >= 3 || stages.length >= 2) priority = "P3";  // suspicious cluster / recon -> review
  else if (sev.suspicious) priority = "P3";
  else priority = "Ignore";
  // pClass computed after risk reconciliation below

  // counter-evidence: reasons this might be benign — the accuracy differentiator
  var counter = [];
  if (!chain.ips.length) counter.push("no public IPs — internal-only activity");
  if (chain.size === 1) counter.push("single event — no corroboration");
  if (ALLOWLIST.size && evs.some(function(e){ return eventInAllowlist(e); })) counter.push("involves allow-listed (known-good) entity");
  if (/\bsafe\b|\bbenign\b|signed|trusted publisher|approved|maintenance window|whitelist/.test(blob)) counter.push("benign/approved indicators present");
  if (!sev.malicious && chain.events.every(function(e){ return e.isScanner; })) counter.push("scanner noise only — no successful exploitation");

  var scenario = recognizeScenario(chain, blob, stages, { hasPriv:hasPriv, hasCred:hasCred, hasMalware:hasMalware, sev:sev });

  // Asset criticality (auto-guess + analyst override) — DC brute force outranks lab-VM
  var critLevel = 0, critSource = "unknown", critAsset = "";
  var names = (chain.actors||[]).concat(chain.ips||[]);
  evs.forEach(function(e){ var h=e.raw&&(e.raw.host||e.raw.hostname||e.raw.instanceId||e.raw.computer||e.raw.dest_host||e.raw.target); if(h) names.push(String(h)); });
  names.forEach(function(nm){ var a=assetCriticalityFor(nm); if(a.level>critLevel){ critLevel=a.level; critSource=a.source; critAsset=nm; } });
  if(!critLevel){ critLevel=5; critSource="default (medium)"; }

  // Auditable, additive confidence breakdown
  var confParts=[];
  var blockHit = (IOC_BLOCKLIST.size||MEMORY_BAD.size) && evs.some(eventHitsBlocklist);
  if(blockHit) confParts.push({label:"known-bad / memory IOC match", pts:30});
  if(sev.malicious) confParts.push({label:sev.malicious+" malicious event(s)", pts:25});
  if(hasCred) confParts.push({label:"credential-access activity", pts:15});
  if(hasPriv) confParts.push({label:"privilege/persistence activity", pts:15});
  if(scenario) confParts.push({label:"scenario match: "+scenario.name, pts:10});
  if(stages.length>=2) confParts.push({label:"multi-stage chain", pts:10});
  if(chain.ips.length) confParts.push({label:"public IP involved", pts:8});
  if(critLevel>=9) confParts.push({label:"high-criticality asset ("+critAsset+")", pts:12});
  counter.forEach(function(c){ confParts.push({label:c, pts:-13}); });
  var confidence = Math.max(15, Math.min(95, confParts.reduce(function(a,pp){return a+pp.pts;}, 25)));

  var baseRisk = Math.min(sev.malicious,3)*20 + Math.min(sev.suspicious,12)*6 + stages.length*8 + (hasCred?15:0) + (hasPriv?15:0);  // cap volume: 50 probes != 50x risk
  // Confirmed-exploit floor: a malicious-verdict web shell / RCE (Log4Shell, ProxyShell, command
  // injection, deserialization) is a P1 on its own — it needs no multi-stage ramp-up, so the
  // volume-based score above under-rates it (a lone web shell was scoring risk ~10 / P3). Gated on a
  // HIGH-fidelity signature AND a malicious verdict (a blocked/suspicious probe won't qualify), and
  // incidents are already correlated per source IP, so this is one P1 per attacker, not per request.
  var hasConfirmedExploit = sev.malicious > 0 &&
    /web.?shell|china.?chopper|<\?php[^>]*\b(system|exec|eval|passthru|shell_exec)\b|\.php\?(cmd|c|pass|x)=|\$\{jndi:|log4shell|proxyshell|proxylogon|deserializ|\bognl\b|spring4shell|;\s*(cat|id|whoami|nc|bash)\b|\|\s*(bash|sh|nc)\b|runtime\.getruntime\(\)\.exec/i.test(blob);
  if (hasConfirmedExploit) baseRisk = Math.max(baseRisk, 80);
  if (counter.length && !hasConfirmedExploit) baseRisk = Math.max(5, baseRisk - counter.length*10);  // a confirmed exploit's "single event" isn't exculpatory
  var risk = Math.min(100, Math.round(baseRisk * (0.6 + critLevel/12.5)));  // crit10 -> x1.4, crit5 -> x1.0, crit2 -> x0.76
  risk = Math.min(risk, Math.round(45 + confidence * 0.55));  // risk = impact x certainty: low confidence caps risk (no "risk 100 / conf 22")
  if (hasConfirmedExploit) { risk = Math.max(risk, 72); priority = "P1"; }   // floor a confirmed exploit at P1
  else {
    // reconcile priority with final risk so they can't contradict (no "P1 / risk 15")
    if (priority === "P1" && risk < 40) priority = "P2";
    if (priority === "P2" && risk < 18) priority = "P3";
    if (priority === "P3" && risk < 6) priority = "Ignore";
  }
  var pClass = { P1:"dc-p1", P2:"dc-p2", P3:"dc-p3", Ignore:"dc-ig" }[priority];
  var action = priority === "P1" ? "Contain now — isolate host & reset credentials"
    : priority === "P2" ? "Investigate now"
    : priority === "P3" ? "Monitor / rate-limit the source"
    : "Low priority — review when time permits";

  var steps = [], actors = (chain.actors||[]).filter(function (a) { return a && a !== "unknown"; });
  if (hasCred || hasPriv) actors.slice(0,3).forEach(function (a) { steps.push("Reset credentials for " + a + " and revoke active sessions"); });
  (chain.ips||[]).slice(0,3).forEach(function (ip) { steps.push("Block / investigate source IP " + ip); });
  (chain.hashes||[]).slice(0,2).forEach(function (h) { steps.push("Search EDR for file hash " + h.slice(0,16) + "\u2026"); });
  if (stages.length >= 2) steps.push("Reconstruct the timeline and pull EDR telemetry on affected hosts");
  if (!steps.length) steps.push("Review events in context and confirm against baseline before acting");

  return { priority:priority, pClass:pClass, risk:risk, confidence:confidence, killPct:killPct, action:action, evidence:evidence, counter:counter, scenario:scenario, linkedBy:chain.linkedBy, confParts:confParts, critLevel:critLevel, critSource:critSource, critAsset:critAsset, steps:steps.slice(0,5) };
}
function incidentSig(c){ return (c.start||"")+"|"+c.size+"|"+((c.ips&&c.ips[0])||(c.actors&&c.actors[0])||""); }

/* ================= Case management (investigation lifecycle) ================= */
var CASES = {};        // caseId -> case
var SIG_CASE = {};     // incidentSig -> caseId
var CASE_SEQ = 1;
var CASE_STATUSES = ["New","Investigating","Escalated","Contained","Closed"];
function nowStr(){ return new Date().toISOString().slice(0,19).replace("T"," ") + "Z"; }
function newCaseId(){ return "CASE-" + new Date().getUTCFullYear() + "-" + String(CASE_SEQ++).padStart(4,"0"); }
function ensureCase(sig, incident){
  if (SIG_CASE[sig] && CASES[SIG_CASE[sig]]) return CASES[SIG_CASE[sig]];
  var d = decisionCard(incident);
  var id = newCaseId();
  CASES[id] = { id:id, sigs:[sig], status:"New", owner:"", verdict:"", timeline:[{ts:nowStr(), text:"Case auto-opened — "+d.priority+", risk "+d.risk+(d.scenario?", scenario "+d.scenario.name:"")}],
    snapshot:{ priority:d.priority, risk:d.risk, confidence:d.confidence, action:incident.events&&incident.events[0]?incident.events[0].action:"", scenario:d.scenario?d.scenario.name:"", linkedBy:d.linkedBy, ips:incident.ips||[], actors:incident.actors||[], hashes:incident.hashes||[], domains:incident.domains||[], evidence:d.evidence, counter:d.counter } };
  SIG_CASE[sig] = id;
  return CASES[id];
}
function caseByInc(idx){ var c=(window.__incidents||[])[idx]; if(!c) return null; return ensureCase(incidentSig(c), c); }
function logCase(kase, text){ kase.timeline.push({ts:nowStr(), text:text}); }
function setCaseStatus(idx, status){ var k=caseByInc(idx); if(!k) return; if(k.status!==status){ k.status=status; logCase(k,"Status → "+status); applyFilter(); } }
function setCaseOwner(idx, owner){ var k=caseByInc(idx); if(!k) return; k.owner=owner; logCase(k,"Owner set to "+(owner||"(unassigned)")); }
function addCaseComment(idx, text){ if(!text) return; var k=caseByInc(idx); if(!k) return; logCase(k,"Comment: "+text); applyFilter(); }
function mergeSelectedCases(){
  var checks = Array.prototype.slice.call(document.querySelectorAll(".case-check:checked"));
  if(checks.length<2){ alert("Tick 'select' on at least two incidents to merge."); return; }
  var incs = (window.__incidents||[]);
  var ids = checks.map(function(ch){ var k=caseByInc(+ch.getAttribute("data-inc")); return k?k.id:null; }).filter(Boolean);
  ids = ids.filter(function(v,i){ return ids.indexOf(v)===i; });
  if(ids.length<2){ alert("Those are already the same case."); return; }
  var target = CASES[ids[0]];
  for(var i=1;i<ids.length;i++){ var src=CASES[ids[i]]; if(!src) continue;
    src.sigs.forEach(function(sg){ SIG_CASE[sg]=target.id; if(target.sigs.indexOf(sg)<0) target.sigs.push(sg); });
    src.timeline.forEach(function(t){ target.timeline.push(t); });
    delete CASES[ids[i]];
  }
  logCase(target, "Merged "+(ids.length-1)+" case(s) into this one ("+target.sigs.length+" incidents)");
  applyFilter();
}
function splitCase(idx){
  var k=caseByInc(idx); if(!k||k.sigs.length<2){ alert("This case has a single incident — nothing to split."); return; }
  var keep=k.sigs[0]; var rest=k.sigs.slice(1);
  k.sigs=[keep]; logCase(k,"Split — "+rest.length+" incident(s) moved to new case(s)");
  rest.forEach(function(sg){ var id=newCaseId(); CASES[id]={id:id,sigs:[sg],status:k.status,owner:k.owner,verdict:"",timeline:[{ts:nowStr(),text:"Split from "+k.id}],snapshot:k.snapshot}; SIG_CASE[sg]=id; });
  applyFilter();
}
function exportEvidence(idx){
  var k=caseByInc(idx); if(!k) return;
  var sn=k.snapshot||{}, e2=esc;
  var iocs=[].concat((sn.ips||[]).map(function(x){return["IP",x];}),(sn.domains||[]).map(function(x){return["domain",x];}),(sn.hashes||[]).map(function(x){return["hash",x];}));
  var html="<!doctype html><html><head><meta charset=utf-8><title>Evidence Package "+e2(k.id)+"</title><style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:820px;margin:30px auto;color:#12141f;padding:0 16px;}h1{font-size:20px;}h2{font-size:14px;margin-top:24px;border-bottom:2px solid #eee;padding-bottom:4px;}table{width:100%;border-collapse:collapse;font-size:13px;}td,th{padding:6px 8px;border-bottom:1px solid #eee;text-align:left;}.k{display:inline-block;padding:2px 10px;border-radius:20px;font-weight:700;font-size:12px;background:#eef;} .muted{color:#888;}</style></head><body>"
    +"<h1>Investigation Evidence Package</h1>"
    +"<p><span class=k>"+e2(k.id)+"</span> · Status: <b>"+e2(k.status)+"</b> · Owner: <b>"+e2(k.owner||"unassigned")+"</b> · Verdict: <b>"+e2(k.verdict||"—")+"</b></p>"
    +"<p class=muted>Exported "+nowStr()+" · "+k.sigs.length+" incident(s) in this case</p>"
    +"<h2>Assessment</h2><p>Priority <b>"+e2(sn.priority||"")+"</b>, risk <b>"+e2(sn.risk||"")+"</b>, confidence <b>"+e2(sn.confidence||"")+"%</b>"+(sn.scenario?", likely scenario <b>"+e2(sn.scenario)+"</b>":"")+".</p>"
    +"<p><b>Trigger:</b> "+e2(sn.action||"")+"</p>"
    +"<p><b>Evidence:</b> "+((sn.evidence||[]).map(e2).join("; ")||"—")+"</p>"
    +"<p><b>Counter-evidence:</b> "+((sn.counter||[]).length?sn.counter.map(e2).join("; "):"none noted")+"</p>"
    +"<h2>Indicators</h2><table><tr><th>Type</th><th>Indicator</th></tr>"+(iocs.length?iocs.map(function(r){return "<tr><td>"+r[0]+"</td><td>"+e2(r[1])+"</td></tr>";}).join(""):"<tr><td colspan=2 class=muted>none</td></tr>")+"</table>"
    +"<h2>Investigation timeline</h2><table><tr><th>Time (UTC)</th><th>Action</th></tr>"+k.timeline.map(function(t){return "<tr><td class=muted>"+e2(t.ts)+"</td><td>"+e2(t.text)+"</td></tr>";}).join("")+"</table>"
    +"<p class=muted style='margin-top:26px'>Generated by CloudLog · built by Praharsh · heuristic triage, verify against source systems.</p></body></html>";
  downloadBlob(html, "text/html", k.id+"-evidence.html");
}
function casesOverviewHtml(incs){
  incs.forEach(function(c){ ensureCase(incidentSig(c), c); });
  var counts={}; CASE_STATUSES.forEach(function(s){counts[s]=0;});
  var seen={}; incs.forEach(function(c){ var k=CASES[SIG_CASE[incidentSig(c)]]; if(k&&!seen[k.id]){ seen[k.id]=1; counts[k.status]=(counts[k.status]||0)+1; } });
  var pills=CASE_STATUSES.map(function(s){ return '<span class="case-pill cs-'+s.toLowerCase()+'">'+s+': '+counts[s]+'</span>'; }).join("");
  return '<div class="entity-risk"><h3>Cases <span class="muted" style="font-weight:400;font-size:11px;">(auto-created per incident — work them below)</span></h3>'
    + '<div style="margin-bottom:8px;">'+pills+'</div>'
    + '<button class="btn btn-outline" id="mergeCasesBtn" style="padding:6px 12px;font-size:12px;">Merge selected</button> '
    + '<span class="muted small">Tick "select" on two or more incidents, then merge. Split is on multi-incident cases.</span></div>';
}
function decisionCardHtml(c, idx) {
  var d = decisionCard(c);
  var pivIoc = (c.ips && c.ips[0]) || (c.actors && c.actors[0]) || "";
  var kase = ensureCase(incidentSig(c), c);
  var v = { verdict: kase.verdict };
  var vb = function(val,label){ return '<button class="vbtn'+(kase.verdict===val?" on":"")+'" data-inc="'+idx+'" data-v="'+val+'">'+label+'</button>'; };
  var stageDet = classifyStageDetail((c.events&&c.events[0])||{});
  var statusSel = '<select class="case-status" data-inc="'+idx+'">'+CASE_STATUSES.map(function(st){return '<option'+(kase.status===st?" selected":"")+'>'+st+'</option>';}).join("")+'</select>';
  var caseBar = '<div class="case-bar"><span class="case-id">'+esc(kase.id)+'</span>'+statusSel
    + '<input class="case-owner" data-inc="'+idx+'" placeholder="owner" value="'+esc(kase.owner||"").replace(/"/g,"&quot;")+'"/>'
    + '<label class="case-merge"><input type="checkbox" class="case-check" data-inc="'+idx+'"/> select</label>'
    + (kase.sigs.length>1?'<button class="btn btn-outline case-split" data-inc="'+idx+'" style="padding:4px 9px;font-size:11.5px;">split ('+kase.sigs.length+')</button>':'')
    + '<button class="btn btn-outline case-export" data-inc="'+idx+'" style="padding:4px 9px;font-size:11.5px;">Export evidence</button></div>';
  var tl = '<details class="dc-steps"><summary>Investigation timeline ('+kase.timeline.length+')</summary><ul class="case-tl">'
    + kase.timeline.map(function(t){return '<li><span class="muted">'+esc(t.ts)+'</span> — '+esc(t.text)+'</li>';}).join("")
    + '</ul><div class="dc-note" style="margin-top:6px;"><input class="case-comment" data-inc="'+idx+'" placeholder="Add comment / action taken…"/><button class="btn btn-outline case-comment-btn" data-inc="'+idx+'" style="padding:6px 12px;font-size:12px;">Add</button></div></details>';
  return '<div class="decision-card ' + d.pClass + '">' + caseBar +
    '<div class="dc-top"><span class="dc-pri ' + d.pClass + '">' + d.priority + '</span>' +
    '<span class="dc-metric">Risk <b>' + d.risk + '</b></span>' +
    '<span class="dc-metric">Confidence <b>' + d.confidence + '%</b></span>' +
    '<span class="dc-metric">Kill-chain <b>' + d.killPct + '%</b></span>' +
    '<span class="dc-action">\u2192 ' + esc(d.action) + '</span>' + (pivIoc ? '<span class="pivot" style="margin-left:10px;font-size:12.5px;" data-pivot="'+esc(pivIoc)+'" data-pivot-label="'+esc(pivIoc)+'">\uD83D\uDD0D see all its events</span>' : '') + '<button class="btn btn-outline dc-inspect" data-inspect-inc="'+idx+'" style="margin-left:8px;font-size:12px;padding:5px 11px;">\uD83D\uDD0E Investigate</button>' + '</div>' +
    (d.scenario ? '<div class="dc-scenario">Likely scenario: <b>' + esc(d.scenario.name) + '</b> <span class="muted">(' + d.scenario.confidence + '% match)</span></div>' : '') +
    '<div class="dc-linked">MITRE tactic: <b>' + esc(stageDet.stage) + '</b> <span class="muted">(' + esc(stageDet.why) + ')</span></div>' +
    '<div class="dc-why"><b>Why:</b> ' + d.evidence.map(esc).join(" \u00b7 ") + '</div>' +
    (d.counter && d.counter.length ? '<div class="dc-counter"><b>Counter-evidence:</b> ' + d.counter.map(esc).join(" \u00b7 ") + '</div>' : '') +
    (d.linkedBy ? '<div class="dc-linked">Events linked by: <b>' + esc(d.linkedBy) + '</b></div>' : '') +
    '<div class="dc-linked">Asset criticality: <b>' + d.critLevel + '/10</b> <span class="muted">(' + esc(d.critSource) + (d.critAsset?" — "+esc(d.critAsset):"") + ')</span></div>' +
    '<details class="dc-steps"><summary>Confidence breakdown (' + d.confidence + '%)</summary><div class="conf-bd">' +
      d.confParts.map(function(pp){ var pos=pp.pts>=0; return '<div class="conf-row"><span class="'+(pos?"cp-pos":"cp-neg")+'">'+(pos?"+":"")+pp.pts+'</span> '+esc(pp.label)+'</div>'; }).join("") +
      '<div class="conf-row conf-total"><span>= '+d.confidence+'%</span> final confidence (base 25)</div></div></details>' +
    '<div class="dc-verdict"><span class="muted small">Verdict:</span> ' + vb("TP","True Positive") + vb("FP","False Positive") + vb("Benign","Benign") + (kase.verdict ? '<span class="vlabel">saved: '+esc(kase.verdict)+'</span>' : '') + '</div>' +
    tl +
    '<details class="dc-steps"><summary>Recommended steps</summary><ol>' +
      d.steps.map(function (x) { return "<li>" + esc(x) + "</li>"; }).join("") + '</ol></details>' +
  '</div>';
}
function markVerdict(idx, verdict){
  var c=(window.__incidents||[])[idx]; if(!c) return;
  var k=ensureCase(incidentSig(c), c); k.verdict=verdict; logCase(k, "Verdict set: "+verdict);
  if(verdict==="TP"){
    (c.ips||[]).forEach(function(x){ MEMORY_BAD.add(String(x).toLowerCase()); });
    (c.domains||[]).forEach(function(x){ MEMORY_BAD.add(String(x).toLowerCase()); });
    (c.hashes||[]).forEach(function(x){ MEMORY_BAD.add(String(x).toLowerCase()); }); if(typeof savePrefs==="function") savePrefs();
  }
  applyFilter();
}

function baselineHtml(list){
  var rep=baselineReport(list);
  if(!rep.length) return '<div class="entity-risk"><h3>Observed Behavior Baseline</h3><p class="muted small">Not enough per-user activity in this dataset to build a baseline (need \u22655 events per user). This is an in-dataset baseline, not historical UEBA.</p></div>';
  var rows=rep.slice(0,6).map(function(r){
    return '<tr><td><b>'+esc(r.actor)+'</b></td><td>'+r.topHours.map(function(h){return String(h).padStart? String(h).padStart(2,"0")+":00":h+":00";}).join(", ")+'</td><td>'+r.commonIps.slice(0,2).map(esc).join(", ")+'</td><td class="'+(r.deviations.length?"cp-neg":"muted")+'">'+(r.deviations.length? r.deviations.map(esc).join("; ") : "no notable deviation")+'</td></tr>';
  }).join("");
  return '<div class="entity-risk"><h3>Observed Behavior Baseline <span class="muted" style="font-weight:400;font-size:11px;">(in-dataset only \u2014 not historical UEBA)</span></h3>'
    + '<table class="er-table"><thead><tr><th>User</th><th>Usual hours (UTC)</th><th>Usual IPs</th><th>Deviations</th></tr></thead><tbody>'
    + rows + '</tbody></table></div>';
}
function entityRiskHtml(list){
  var er = computeEntityRisk(list).slice(0, 8);
  if(!er.length) return "";
  var rows = er.map(function(e){
    var cls = e.score>=70?"dc-p1":e.score>=40?"dc-p2":"dc-p3";
    return '<tr><td><span class="er-badge '+cls+'">'+e.score+'</span></td><td>'+esc(e.type)+'</td><td><b>'+esc(e.name)+'</b></td><td>'+e.confidence+'%</td><td class="muted">'+e.evidence.map(esc).join(" \u00b7 ")+'</td></tr>';
  }).join("");
  var erBlock = '<div class="entity-risk"><h3>Entity Risk \u2014 highest-risk users &amp; IPs</h3>'
    + '<table class="er-table"><thead><tr><th>Risk</th><th>Type</th><th>Entity</th><th>Conf.</th><th>Why</th></tr></thead><tbody>'
    + rows + '</tbody></table></div>';
  return erBlock + baselineHtml(list);
}

function helpPanelHtml(){
  return '<details class="help-panel"><summary>\u2139\ufe0f How to read this tab (plain English)</summary>'
   + '<div class="help-grid">'
   + '<div><b>Funnel</b><br>How many raw events/alerts were collapsed into a few real investigations. Higher "% noise reduced" = more analyst time saved.</div>'
   + '<div><b>Case</b><br>Each incident is a case you can work: set a status (New \u2192 Investigating \u2192 Escalated \u2192 Contained \u2192 Closed), assign an owner, add comments, and export an evidence file.</div>'
   + '<div><b>Priority</b><br>P1 = act now, P2 = investigate, P3 = monitor. Based on severity, kill-chain progress, and asset importance.</div>'
   + '<div><b>Risk / Confidence</b><br>Risk = how bad if real. Confidence = how sure (built from evidence minus counter-evidence \u2014 open the breakdown to see the math).</div>'
   + '<div><b>MITRE tactic</b><br>What the attacker was trying to do (e.g. Credential Access), decided from the event\u2019s context, not just a keyword.</div>'
   + '<div><b>Counter-evidence</b><br>Reasons it might be benign (internal-only, allow-listed, single event). These lower the confidence \u2014 like a real analyst weighing both sides.</div>'
   + '<div><b>Evidence Graph</b><br>How entities connect (user logged_into host, host connected_to IP). Click a node to trace its links.</div>'
   + '<div><b>Verdict + Memory</b><br>Mark True/False Positive. Confirmed-bad indicators are remembered and auto-flagged next time.</div>'
   + '</div></details>';
}

function consolidationStats(list){
  var det = runDetections(list);
  var alertEvents = 0, uniq = {};
  det.forEach(function(d){ alertEvents += d.events.length; d.events.forEach(function(e){ uniq[d.rule.id+"|"+(e.actor||"")+"|"+(e.ip||"")]=1; }); });
  var investigations = correlateChains(list).length;
  var reduction = alertEvents > 0 ? Math.max(0, Math.round((1 - investigations/alertEvents)*100)) : 0;
  return { events:list.length, alerts:alertEvents, dedup:Object.keys(uniq).length, investigations:investigations, reduction:reduction };
}
function consolidationHtml(list){
  var c = consolidationStats(list);
  var step = function(num,lbl,cls){ return '<div class="fn-step '+(cls||"")+'"><div class="fn-num">'+num+'</div><div class="fn-lbl">'+lbl+'</div></div>'; };
  return '<div class="funnel">'
    + step(c.events.toLocaleString(),"events") + '<span class="fn-arrow">\u2192</span>'
    + step(c.alerts.toLocaleString(),"raw alerts") + '<span class="fn-arrow">\u2192</span>'
    + step(c.dedup.toLocaleString(),"deduped") + '<span class="fn-arrow">\u2192</span>'
    + step(c.investigations,"investigations","fn-final")
    + '<div class="fn-save"><b>'+c.reduction+'%</b><span>noise reduced</span></div></div>';
}

function renderInvestigate(list) {
  var chainsEl = document.getElementById("chainsContent"), iocEl = document.getElementById("iocContent");
  if (!chainsEl || !iocEl) return;
  if (!list || !list.length) {
    chainsEl.innerHTML = '<p class="empty-note">Load logs to auto-correlate attack chains.</p>';
    iocEl.innerHTML = '<p class="empty-note">Load logs to extract indicators.</p>'; return;
  }

  // --- correlated attack chains ---
  var chains = correlateChains(list, (window.__chainWindowH || 24) * 3600 * 1000);
  if (!chains.length) chainsEl.innerHTML = '<p class="empty-note">No multi-event chains found (events share no common IP/actor/hash within the window).</p>';
  else { var shownChains = chains.slice(0, 12); window.__incidents = shownChains;
    chainsEl.innerHTML = helpPanelHtml() + consolidationHtml(list) + casesOverviewHtml(shownChains) + entityRiskHtml(list) + shownChains.map(function (c, i) {
    var sc = c.risk >= 60 ? "sev-high" : c.risk >= 30 ? "sev-medium" : "sev-low";
    var span = c.start ? (formatTime(new Date(c.start)) + " → " + formatTime(new Date(c.end))) : "no timestamps";
    return '<div class="chain-card">' + decisionCardHtml(c, i) +
      '<div class="chain-card-top"><b>Incident #' + (i + 1) + '</b> <span class="sev ' + sc + '">risk ' + c.risk + '</span>' +
      '<span class="muted small">' + c.size + ' events · ' + span + '</span></div>' +
      (c.stages.length ? '<div class="chain-stages">' + c.stages.map(function (s) { return '<span class="stage-pill">' + esc(s) + '</span>'; }).join(' <span class="arrow">→</span> ') + '</div>' : '') +
      '<div class="chain-ent">' +
        (c.actors.length ? '<span><b>actors:</b> ' + c.actors.map(esc).join(", ") + '</span>' : '') +
        (c.ips.length ? '<span><b>public IPs:</b> ' + c.ips.map(esc).join(", ") + '</span>' : '') +
        (c.hashes.length ? '<span><b>hashes:</b> ' + c.hashes.length + '</span>' : '') +
        (c.domains.length ? '<span><b>domains:</b> ' + c.domains.slice(0, 4).map(esc).join(", ") + '</span>' : '') +
      '</div></div>';
  }).join("");
    chainsEl.querySelectorAll(".vbtn").forEach(function(b){ b.onclick=function(){ markVerdict(+this.getAttribute("data-inc"), this.getAttribute("data-v")); }; });
    chainsEl.querySelectorAll(".dc-inspect").forEach(function(b){ b.onclick=function(ev){ if(ev&&ev.stopPropagation)ev.stopPropagation(); openIncidentInspector((window.__incidents||[])[+this.getAttribute("data-inspect-inc")]); }; });
    chainsEl.querySelectorAll(".case-status").forEach(function(sel){ sel.onchange=function(){ setCaseStatus(+this.getAttribute("data-inc"), this.value); }; });
    chainsEl.querySelectorAll(".case-owner").forEach(function(inp){ inp.onchange=function(){ setCaseOwner(+this.getAttribute("data-inc"), this.value); }; });
    chainsEl.querySelectorAll(".case-comment-btn").forEach(function(btn){ btn.onclick=function(){ var inp=this.parentNode.querySelector(".case-comment"); addCaseComment(+this.getAttribute("data-inc"), inp?inp.value.trim():""); }; });
    chainsEl.querySelectorAll(".case-split").forEach(function(btn){ btn.onclick=function(){ splitCase(+this.getAttribute("data-inc")); }; });
    chainsEl.querySelectorAll(".case-export").forEach(function(btn){ btn.onclick=function(){ exportEvidence(+this.getAttribute("data-inc")); }; });
    var mb=document.getElementById("mergeCasesBtn"); if(mb) mb.onclick=mergeSelectedCases;
  }

  // --- IOC table ---
  var iocs = aggregateIocs(list);
  if (!iocs.length) { iocEl.innerHTML = '<p class="empty-note">No indicators extracted.</p>'; return; }
  var rows = iocs.slice(0, 300).map(function (o, idx) {
    var gate = safeToEnrich(o.type, o.value);
    var extra = o.type === "ip" ? (" <span class='ip-class ip-" + classifyIp(o.value) + "'>" + classifyIp(o.value) + "</span>")
      : o.type === "hash" ? (" <span class='ip-class'>" + (hashType(o.value) || "?") + "</span>") : "";
    var enrichCell = gate.ok
      ? "<button class='btn btn-outline enrich-btn' data-type='" + o.type + "' data-val='" + esc(o.value) + "' data-idx='" + idx + "' style='padding:5px 10px;font-size:12px;'>Enrich</button>"
      : "<span class='muted small' title='" + esc(gate.reason || "") + "'>🔒 not sent</span>";
    return "<tr data-type='" + o.type + "' data-safe='" + (gate.ok?"1":"0") + "' data-flagged='0'><td>" + iocIcon(o.type) + " <b>" + o.type + "</b>" + extra + "</td><td class='ioc-val'>" + esc(o.value) + "</td><td>" + o.count +
      "</td><td>" + (o.first ? formatTime(new Date(o.first)) : "-") + "</td><td class='enrich-cell' id='enrich-" + idx + "'>" + enrichCell + "</td></tr>";
  }).join("");
  var toolbar = "<div class='ioc-toolbar'>" +
    "<select id='iocFilter'><option value='all'>Show: all</option><option value='flagged'>Flagged only</option><option value='safe'>Enrichable only</option><option value='notsent'>Not-sent only</option></select> " +
    "<button class='btn btn-outline' id='enrichAllBtn' style='padding:6px 12px;font-size:12px;'>Enrich all safe</button> " +
    "<label style='font-size:12.5px;display:inline-flex;align-items:center;gap:5px;'><input type='checkbox' id='autoEnrich' checked/> Auto-enrich flagged on load</label> " +
    "<span id='iocFilterMsg' class='muted small'></span></div>";
  iocEl.innerHTML = toolbar + "<table class='ioc-table'><thead><tr><th>Type</th><th>Indicator</th><th>Count</th><th>First seen</th><th>Threat intel</th></tr></thead><tbody>" + rows + "</tbody></table>" +
    (iocs.length > 300 ? "<p class='muted small' style='margin-top:8px;'>Showing top 300 of " + iocs.length + " indicators.</p>" : "");

  iocEl.querySelectorAll(".enrich-btn").forEach(function (b) {
    b.onclick = function () { enrichRow(this.getAttribute("data-type"), this.getAttribute("data-val"), this.getAttribute("data-idx")); };
  });
  var f = document.getElementById("iocFilter"); if (f) f.onchange = applyIocFilter;
  var ea = document.getElementById("enrichAllBtn"); if (ea) ea.onclick = enrichAllSafe;
  maybeAutoEnrich(list);
}

// Auto-enrich ONLY indicators the log already flagged (severity != info),
// capped and throttled — never enrich the whole log (rate limits + opsec).
var __autoEnrichSig = null;
function maybeAutoEnrich(list) {
  var box = document.getElementById("autoEnrich");
  if (!box || !box.checked) return;
  if (!(PROXY.ok || anyBrowserKeys())) return;          // only when intel is live
  var sig = (list ? list.length : 0) + "|" + (state.source || "");
  if (sig === __autoEnrichSig) return;                   // once per dataset, not per filter
  __autoEnrichSig = sig;
  // set of indicator values that appear in malicious/suspicious events
  var prio = {};
  (list || []).forEach(function (ev) {
    if (severityOf(ev) === "info") return;
    var io = extractIocs(ev);
    io.ips.concat(io.domains, io.urls, io.hashes).forEach(function (v) { prio[v] = 1; });
  });
  var btns = Array.prototype.slice.call(document.querySelectorAll(".enrich-btn"))
    .filter(function (b) { return prio[b.getAttribute("data-val")]; });
  var CAP = 25; btns = btns.slice(0, CAP);
  var msg = document.getElementById("iocFilterMsg");
  if (!btns.length) return;
  var i = 0;
  (function step() {
    if (i >= btns.length) { if (msg) msg.textContent = "Auto-enriched " + btns.length + " flagged indicator(s)" + (Object.keys(prio).length > CAP ? " (capped at " + CAP + " to respect rate limits)" : "") + "."; return; }
    var b = btns[i++]; if (msg) msg.textContent = "Auto-enriching flagged " + i + " / " + btns.length + " …";
    try { enrichRow(b.getAttribute("data-type"), b.getAttribute("data-val"), b.getAttribute("data-idx")); } catch (e) {}
    setTimeout(step, 700); /* gentle throttle */
  })();
}

function applyIocFilter() {
  var sel = document.getElementById("iocFilter"); if (!sel) return;
  var v = sel.value;
  var rows = document.querySelectorAll("#iocContent tbody tr");
  Array.prototype.forEach.call(rows, function (tr) {
    var safe = tr.getAttribute("data-safe") === "1", flagged = tr.getAttribute("data-flagged") === "1";
    var show = v === "all" || (v === "flagged" && flagged) || (v === "safe" && safe) || (v === "notsent" && !safe);
    tr.style.display = show ? "" : "none";
  });
}

function enrichAllSafe() {
  var msg = document.getElementById("iocFilterMsg");
  var btns = Array.prototype.slice.call(document.querySelectorAll(".enrich-btn"));
  if (!btns.length) { if (msg) msg.textContent = "No enrichable (public) indicators."; return; }
  if (!PROXY.ok && !anyBrowserKeys()) { if (msg) msg.textContent = "In-browser mode: Geo/ASN will run for IPs. Add keys above or start the proxy for full enrichment."; }
  var i = 0;
  (function step() {
    if (i >= btns.length) { if (msg) msg.textContent = "Enrichment requested for " + btns.length + " indicators. Mind provider rate limits (e.g. VirusTotal free ≈ 4/min)."; return; }
    var b = btns[i++]; if (msg) msg.textContent = "Enriching " + i + " / " + btns.length + " …";
    try { enrichRow(b.getAttribute("data-type"), b.getAttribute("data-val"), b.getAttribute("data-idx")); } catch (e) {}
    setTimeout(step, 450); /* throttle ~2.2/s; increase for stricter free tiers */
  })();
}

function browserKeys() {
  var g = function (id) { var e = document.getElementById(id); return e && e.value.trim() ? e.value.trim() : null; };
  return { vt:g("bk_vt"), abuse:g("bk_abuse"), otx:g("bk_otx"), urlscan:g("bk_urlscan"), gsb:g("bk_gsb"), greynoise:g("bk_greynoise"), shodan:g("bk_shodan") };
}
function anyBrowserKeys() { var k = browserKeys(); for (var x in k) if (k[x]) return true; return false; }
function jget(url, headers) { return fetch(url, { headers: headers || {} }).then(function (r) { return r.json(); }); }
function blocked(name) { return { service: name, found: false, malicious: null, detail: "browser blocked (CORS) — run the local proxy for this source" }; }

// Direct in-browser enrichment. Geo is keyless & CORS-friendly; others attempt and
// fail gracefully with a clear message if the browser blocks them.
function geoLookup(ip) {
  // try providers in order; each may be CORS-blocked/rate-limited, so fall through
  return jget("https://ipapi.co/" + encodeURIComponent(ip) + "/json/").then(function (j) {
    if (j && j.country_name) return { service:"Geo/ASN", found:true, malicious:null, detail:[j.country_name, j.org, j.asn].filter(Boolean).join(" \u00b7 ") };
    throw 0;
  }).catch(function () {
    return jget("https://ipwho.is/" + encodeURIComponent(ip)).then(function (j) {
      if (!j || j.success === false) throw 0; var c = j.connection || {};
      return { service:"Geo/ASN", found:true, malicious:null, detail:[j.country, c.isp || c.org, c.asn ? ("AS"+c.asn) : ""].filter(Boolean).join(" \u00b7 ") + ((j.security && (j.security.anonymous||j.security.proxy)) ? " [anon/proxy]" : "") };
    });
  }).catch(function () {
    return jget("https://get.geojs.io/v1/ip/geo/" + encodeURIComponent(ip) + ".json").then(function (j) {
      if (j && j.country) return { service:"Geo/ASN", found:true, malicious:null, detail:[j.country, j.organization_name || j.organization].filter(Boolean).join(" \u00b7 ") };
      throw 0;
    });
  }).catch(function () { return { service:"Geo/ASN", found:false, __failed:true, detail:"geo providers unreachable from browser" }; });
}
function directEnrich(type, value) {
  var k = browserKeys(), jobs = [];
  if (type === "ip") {
    jobs.push(geoLookup(value));
  }
  if (k.vt) { var vp = type==="ip"?"ip_addresses/"+value:type==="domain"?"domains/"+value:type==="hash"?"files/"+value:type==="url"?"urls/"+btoa(value).replace(/=+$/,"").replace(/\+/g,"-").replace(/\//g,"_"):null;
    if (vp) jobs.push(jget("https://www.virustotal.com/api/v3/"+vp, {"x-apikey":k.vt}).then(function(j){ var st=j&&j.data&&j.data.attributes&&j.data.attributes.last_analysis_stats; return {service:"VirusTotal",found:!!st,malicious:st?st.malicious:null,detail:st?(st.malicious+" malicious / "+(st.malicious+st.harmless+st.undetected+st.suspicious)+" engines"):(j.error?j.error.message:"no data")}; }).catch(function(){ return blocked("VirusTotal"); })); }
  if (k.abuse && type==="ip") jobs.push(jget("https://api.abuseipdb.com/api/v2/check?ipAddress="+encodeURIComponent(value)+"&maxAgeInDays=90",{Key:k.abuse,Accept:"application/json"}).then(function(j){ var d=j&&j.data; return {service:"AbuseIPDB",found:!!d,malicious:d?d.abuseConfidenceScore:null,detail:d?(d.abuseConfidenceScore+"% confidence, "+d.totalReports+" reports"):"no data"}; }).catch(function(){ return blocked("AbuseIPDB"); }));
  if (k.otx) { var seg=type==="ip"?"IPv4/"+value:type==="domain"?"domain/"+value:type==="hash"?"file/"+value:type==="url"?"url/"+encodeURIComponent(value):null;
    if (seg) jobs.push(jget("https://otx.alienvault.com/api/v1/indicators/"+seg+"/general",{"X-OTX-API-KEY":k.otx}).then(function(j){ var pc=j&&j.pulse_info&&j.pulse_info.count; return {service:"OTX",found:pc!==undefined,malicious:pc||0,detail:(pc||0)+" threat pulse(s)"}; }).catch(function(){ return blocked("OTX"); })); }
  if (k.greynoise && type==="ip") jobs.push(jget("https://api.greynoise.io/v3/community/"+value,{key:k.greynoise,Accept:"application/json"}).then(function(j){ return {service:"GreyNoise",found:!!j,malicious:j&&j.classification==="malicious"?1:0,detail:j?((j.classification||"unknown")+(j.noise?" — internet noise":"")):"no data"}; }).catch(function(){ return blocked("GreyNoise"); }));
  if (k.shodan && type==="ip") jobs.push(jget("https://api.shodan.io/shodan/host/"+value+"?key="+encodeURIComponent(k.shodan)).then(function(j){ return {service:"Shodan",found:!!j.ports,malicious:null,detail:j.ports?((j.org||"?")+" — ports "+j.ports.slice(0,10).join(",")):(j.error||"no data")}; }).catch(function(){ return blocked("Shodan"); }));
  if (k.urlscan && type!=="hash") { var q=type==="ip"?"ip:"+value:type==="domain"?"domain:"+value:'page.url:"'+value+'"'; jobs.push(jget("https://urlscan.io/api/v1/search/?q="+encodeURIComponent(q)+"&size=1",{"API-Key":k.urlscan}).then(function(j){ var t=j&&j.total; return {service:"urlscan",found:t>0,malicious:null,detail:(t||0)+" historical scan(s)"}; }).catch(function(){ return blocked("urlscan"); })); }
  if (!jobs.length) return Promise.resolve({ results: [] });
  return Promise.all(jobs).then(function (results) { return { results: results.filter(Boolean) }; });
}
function renderVerdicts(cell, type, value, d) {
  var results = (d && d.results) || [];
  // split real answers from browser/CORS failures so we don't spam red errors
  var good = results.filter(function (r) { return r.found && !r.__failed && !/browser blocked/i.test(r.detail || ""); });
  var failed = results.length - good.length;
  var anyBad = good.some(function (r) { return r.malicious && r.malicious > 0; });
  var tr = cell.parentNode; if (tr && tr.tagName === "TR") tr.setAttribute("data-flagged", anyBad ? "1" : "0");
  var html = good.map(function (r) {
    var bad = (r.malicious && r.malicious > 0);
    return "<div class='verdict " + (bad ? "verdict-bad" : "verdict-ok") + "'><b>" + esc(r.service) + ":</b> " + esc(r.detail || "found") + "</div>";
  }).join("");
  if (failed > 0) html += "<div class='muted small' style='margin:3px 0;'>" + failed + " live source(s) unavailable in-browser (CORS) — start the proxy for verdicts. Links:</div>";
  else if (!good.length) html += "<div class='muted small' style='margin:3px 0;'>Open in provider:</div>";
  cell.innerHTML = html + deepLinks(type, value);
}

function enrichRow(type, value, idx) {
  var cell = document.getElementById("enrich-" + idx); if (!cell) return;
  var gate = safeToEnrich(type, value);
  if (!gate.ok) { cell.innerHTML = "<span class='muted small'>🔒 " + esc(gate.reason) + "</span>"; return; }

  if (PROXY.ok) {
    cell.innerHTML = "<span class='muted small'>querying " + (PROXY.services.length || "") + " service(s)…</span>";
    fetch(PROXY.url + "/enrich?type=" + encodeURIComponent(type) + "&value=" + encodeURIComponent(value))
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.blocked) { cell.innerHTML = "<span class='muted small'>🔒 " + esc(d.reason) + "</span>"; return; }
        if (!d.results || !d.results.length) { cell.innerHTML = "<span class='muted small'>no services configured</span>" + deepLinks(type, value); return; }
        var anyBad = (d.results || []).some(function (r) { return r.malicious && r.malicious > 0; });
        var tr = cell.parentNode; if (tr && tr.tagName === "TR") tr.setAttribute("data-flagged", anyBad ? "1" : "0");
        cell.innerHTML = d.results.map(function (r) {
          var bad = (r.malicious && r.malicious > 0);
          return "<div class='verdict " + (bad ? "verdict-bad" : "verdict-ok") + "'><b>" + esc(r.service) + ":</b> " + esc(r.detail || (r.found ? "found" : "no data")) + "</div>";
        }).join("") + deepLinks(type, value);
      })
      .catch(function () { cell.innerHTML = "<span class='muted small'>proxy error</span>" + deepLinks(type, value); });
  } else if (anyBrowserKeys() || type === "ip") {
    cell.innerHTML = "<span class='muted small'>querying (in-browser)…</span>";
    directEnrich(type, value).then(function (d) { renderVerdicts(cell, type, value, d); })
      .catch(function () { cell.innerHTML = deepLinks(type, value); });
  } else {
    cell.innerHTML = "<div class='muted small' style='margin-bottom:4px;'>Open in provider (nothing sent by the tool):</div>" + deepLinks(type, value);
  }
}

function deepLinks(type, value) {
  var links = enrichmentLinks(type, value);
  var html = "<div class='deeplinks'>";
  Object.keys(links).forEach(function (name) { html += "<a href='" + esc(links[name]) + "' target='_blank' rel='noopener' class='dl'>" + esc(name) + " ↗</a>"; });
  return html + "</div>";
}


function downloadBlob(content, mime, name){ var a=document.createElement("a"); a.href=URL.createObjectURL(new Blob([content],{type:mime})); a.download=name; document.body.appendChild(a); a.click(); a.remove(); }

/* ---- Save / Load case (investigation persistence) ---- */
function saveCase(){
  if(!state.logs.length){ alert("Nothing to save — load a log first."); return; }
  var data={ tool:"CloudLog", version:1, savedAt:new Date().toISOString(), source:state.source, eventCount:state.logs.length, customRules:CUSTOM_RULES, iocBlocklist:Array.from(IOC_BLOCKLIST), allowlist:Array.from(ALLOWLIST), yaraText:LAST_YARA_TEXT, verdicts:VERDICTS, memoryBad:Array.from(MEMORY_BAD), assetCriticality:ASSET_CRITICALITY, cases:CASES, sigCase:SIG_CASE, caseSeq:CASE_SEQ, logs:state.logs };
  var json=JSON.stringify(data);
  var fname="cloudlog-case-"+new Date().toISOString().slice(0,10);
  if (typeof authIsConfigured==="function" && authIsConfigured() && AUTH_SESSION.unlocked && AUTH_SESSION.code && typeof crypto!=="undefined" && crypto.subtle){
    encryptText(json, AUTH_SESSION.code).then(function(enc){
      downloadBlob(enc, "application/octet-stream", fname+".clenc");
      alert("Case saved ENCRYPTED (AES-256-GCM) with your access code. Anyone opening it needs a valid code.");
    }).catch(function(){ downloadBlob(json, "application/json", fname+".json"); });
    return;
  }
  downloadBlob(json, "application/json", fname+".json");
}
function loadCase(file){
  var r=new FileReader();
  r.onload=function(){
    var txt=r.result;
    function apply(jsonText){ try{ var d=JSON.parse(jsonText);
      if(!d.logs||!Array.isArray(d.logs)){ alert("Not a valid CloudLog case file."); return; }
      state.logs=d.logs; state.source=d.source||"Loaded case"; invalidateDetectionCache(); CUSTOM_RULES=d.customRules||[];
      IOC_BLOCKLIST=new Set(d.iocBlocklist||[]); ALLOWLIST=new Set(d.allowlist||[]); YARA_RULES=d.yaraText?parseYara(d.yaraText):[]; VERDICTS=d.verdicts||{}; MEMORY_BAD=new Set(d.memoryBad||[]); ASSET_CRITICALITY=d.assetCriticality||{}; CASES=d.cases||{}; SIG_CASE=d.sigCase||{}; CASE_SEQ=d.caseSeq||1; if(document.getElementById("acText")) document.getElementById("acText").value=Object.keys(ASSET_CRITICALITY).map(function(k){return k+","+ASSET_CRITICALITY[k];}).join("\n");
      if(document.getElementById("blText")) document.getElementById("blText").value=(d.iocBlocklist||[]).join("\n");
      if(document.getElementById("alText")) document.getElementById("alText").value=(d.allowlist||[]).join("\n");
      if(document.getElementById("yaraText")) document.getElementById("yaraText").value=d.yaraText||"";
      applyFilter(); renderCustomRuleList();
      alert("Loaded case: "+d.logs.length+" events"+(CUSTOM_RULES.length?", "+CUSTOM_RULES.length+" custom rule(s)":"")+".");
    }catch(e){ alert("Could not read case file: "+e.message); } }
    if (String(txt).indexOf("CLENC1:")===0){
      var code = (AUTH_SESSION.unlocked && AUTH_SESSION.code) ? AUTH_SESSION.code : (prompt("This case is encrypted. Enter the access code it was saved with:")||"");
      if(!code){ alert("No code entered — cannot decrypt."); return; }
      decryptText(String(txt), code).then(apply).catch(function(){
        var again = prompt("Wrong code (or corrupted file). Try another code, or Cancel:");
        if(again) decryptText(String(txt), again).then(apply).catch(function(){ alert("Could not decrypt with that code."); });
      });
      return;
    }
    apply(txt);
  };
  r.readAsText(file);
}

/* ---- Custom detection rules ---- */
function renderCustomRuleList(){
  var sv=document.getElementById("crSaved"); if(sv) sv.textContent=CUSTOM_RULES.length+" rule"+(CUSTOM_RULES.length===1?"":"s")+" saved";
  var el=document.getElementById("crList"); if(!el) return;
  el.innerHTML = CUSTOM_RULES.length ? (CUSTOM_RULES.map(function(cr,i){
    return "<div class='cr-item'><b>"+esc(cr.name)+"</b> <span class='muted'>["+cr.sev+"] "+(cr.isRegex?"/"+esc(cr.pattern)+"/":esc(cr.pattern))+"</span> <button data-i='"+i+"'>remove</button></div>";
  }).join("") + "<div style='margin-top:8px;'><button class='btn btn-outline' id='crClearAll' style='padding:5px 11px;font-size:12px;'>Clear all rules</button></div>") : "<span class='muted small'>No custom rules yet.</span>";
  el.querySelectorAll("button[data-i]").forEach(function(b){ b.onclick=function(){ CUSTOM_RULES.splice(+this.getAttribute("data-i"),1); savePrefs(); if(window.refreshMyStats)window.refreshMyStats(); renderCustomRuleList(); applyFilter(); }; });
  var ca=document.getElementById("crClearAll"); if(ca) ca.onclick=function(){ if(typeof confirm!=="function"||confirm("Remove all "+CUSTOM_RULES.length+" custom rule(s)? Your block/allow lists are kept.")){ CUSTOM_RULES.length=0; savePrefs(); if(window.refreshMyStats)window.refreshMyStats(); renderCustomRuleList(); applyFilter(); } };
}
function addCustomRule(){
  var name=(document.getElementById("crName").value||"").trim();
  var pat=(document.getElementById("crPattern").value||"").trim();
  var sev=document.getElementById("crSev").value;
  var isRegex=document.getElementById("crRegex").checked;
  var msg=document.getElementById("crMsg");
  if(!name||!pat){ msg.textContent="Enter a name and a pattern."; return; }
  if(isRegex && !safeRegex(pat)){ msg.textContent="Invalid regex."; return; }
  CUSTOM_RULES.push({ name:name, pattern:pat, sev:sev, isRegex:isRegex }); savePrefs(); if(window.refreshMyStats)window.refreshMyStats();
  document.getElementById("crName").value=""; document.getElementById("crPattern").value="";
  msg.textContent="Rule added and applied.";
  renderCustomRuleList(); applyFilter();
}
function testCustomRule(){
  var pat=(document.getElementById("crPattern").value||"").trim();
  var isRegex=document.getElementById("crRegex").checked;
  var msg=document.getElementById("crMsg");
  if(!pat){ msg.textContent="Enter a pattern to test."; return; }
  if(isRegex && !safeRegex(pat)){ msg.textContent="Invalid regex."; return; }
  var m=runCustomRule({pattern:pat,isRegex:isRegex}, state.filtered.length?state.filtered:state.logs);
  msg.textContent="Matches "+m.length+" event(s) in the current data.";
}

/* ---- Incident report (downloadable HTML) ---- */
function generateReport(){
  var list=state.filtered.length?state.filtered:state.logs;
  if(!list.length){ alert("Load a log first."); return; }
  var sev={malicious:0,suspicious:0,info:0}; list.forEach(function(e){ sev[severityOf(e)]++; });
  var chains=correlateChains(list);
  var det=runDetections(list);
  var iocs=aggregateIocs(list).slice(0,25);
  var esc2=function(x){ return String(x==null?"":x).replace(/[&<>]/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;"}[c];}); };
  var incidentRows=chains.slice(0,15).map(function(c,i){ var d=decisionCard(c);
    return "<tr><td>#"+(i+1)+"</td><td><b>"+d.priority+"</b></td><td>"+d.risk+"</td><td>"+d.confidence+"%</td><td>"+esc2(d.action)+"</td><td>"+esc2(d.evidence.join("; "))+"</td></tr>"; }).join("");
  var iocRows=iocs.map(function(o){ return "<tr><td>"+o.type+"</td><td>"+esc2(o.value)+"</td><td>"+o.count+"</td></tr>"; }).join("");
  var detRows=aggregateDetections(det).slice(0,25).map(function(x){ return "<tr><td>"+esc2(x.rule.title||x.rule.name)+"</td><td>"+esc2(x.rule.id)+"</td><td>"+x.rule.sev+"</td><td>"+x.events.length+(x.groups>1?" ("+x.groups+" sources)":"")+"</td></tr>"; }).join("");
  var html="<!doctype html><html><head><meta charset=utf-8><title>Incident Report</title><style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:900px;margin:30px auto;color:#171a24;padding:0 16px;}h1{font-size:22px;}h2{font-size:15px;margin-top:26px;border-bottom:2px solid #eee;padding-bottom:4px;}table{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px;}th,td{text-align:left;padding:7px 9px;border-bottom:1px solid #eee;vertical-align:top;}th{color:#666;font-size:11px;text-transform:uppercase;}.k{display:inline-block;padding:2px 10px;border-radius:20px;font-weight:700;font-size:12px;margin-right:8px;}.mal{background:#fdeced;color:#dc2626;}.sus{background:#fff4e0;color:#b3720b;}.inf{background:#eef0f5;color:#666;}.muted{color:#8a8fa3;font-size:12px;}</style></head><body>"
    +"<h1>Security Log Incident Report</h1>"
    +"<p class=muted>Generated "+new Date().toISOString().replace('T',' ').slice(0,19)+" UTC · Source: "+esc2(state.source)+" · "+list.length.toLocaleString()+" events analyzed</p>"
    +"<h2>Summary</h2><p><span class='k mal'>Malicious "+sev.malicious+"</span><span class='k sus'>Suspicious "+sev.suspicious+"</span><span class='k inf'>Info "+sev.info+"</span></p>"
    +"<p class=muted>"+chains.length+" correlated incident(s), "+det.length+" detection group(s).</p>"
    +"<h2>Prioritized Incidents</h2><table><tr><th>#</th><th>Priority</th><th>Risk</th><th>Conf.</th><th>Recommended action</th><th>Why</th></tr>"+(incidentRows||"<tr><td colspan=6 class=muted>No correlated incidents.</td></tr>")+"</table>"
    +"<h2>Detections</h2><table><tr><th>Rule</th><th>ID</th><th>Severity</th><th>Events</th></tr>"+(detRows||"<tr><td colspan=4 class=muted>None.</td></tr>")+"</table>"
    +"<h2>Top Indicators</h2><table><tr><th>Type</th><th>Indicator</th><th>Count</th></tr>"+(iocRows||"<tr><td colspan=3 class=muted>None.</td></tr>")+"</table>"
    +"<p class=muted style='margin-top:30px'>Generated by CloudLog. Heuristic triage — verify against source systems before acting.</p></body></html>";
  downloadBlob(html, "text/html", "incident-report-"+new Date().toISOString().slice(0,10)+".html");
}

(function(){
  var g=function(id){return document.getElementById(id);};
  if(g("saveCaseBtn")) g("saveCaseBtn").onclick=saveCase;
  if(g("clearLogBtn")) g("clearLogBtn").onclick=clearLogs;
  if(g("logoutBtn")) g("logoutBtn").onclick=doLogout;
  loadPrefs();   // restore saved block/allow lists, rules, memory across sessions
  // ---- sidebar "My rules & IOCs" ----
  function refreshMyStats(){ var e=g("navMyStats"); if(e) e.textContent=CUSTOM_RULES.length+" rules \u00b7 "+IOC_BLOCKLIST.size+" blocked \u00b7 "+ALLOWLIST.size+" allowed"; }
  window.refreshMyStats=refreshMyStats; refreshMyStats();
  if(g("navAddRule")) g("navAddRule").onclick=function(){ if(window.openSettingsModal) window.openSettingsModal("modalRule"); var nm=g("crName"); if(nm){ try{ nm.focus(); }catch(e){} } };
  // Settings modals: compact sidebar buttons open a large centered dialog with room to type
  function openSettingsModal(id){ var m=document.getElementById(id); if(m){ m.classList.add("open"); if(id==="modalAuth" && typeof renderAuthPanel==="function") renderAuthPanel(); } }
  function closeSettingsModal(id){ var m=document.getElementById(id); if(m) m.classList.remove("open"); }
  window.openSettingsModal=openSettingsModal;
  document.querySelectorAll(".settings-open").forEach(function(b){ b.onclick=function(){ openSettingsModal(this.getAttribute("data-modal")); }; });
  document.querySelectorAll(".modal-x").forEach(function(b){ b.onclick=function(){ closeSettingsModal(this.getAttribute("data-close")); }; });
  document.querySelectorAll(".modal-overlay").forEach(function(o){ o.addEventListener("click", function(e){ if(e.target===o) o.classList.remove("open"); }); });
  document.addEventListener("keydown", function(e){ if(e.key==="Escape") document.querySelectorAll(".modal-overlay.open").forEach(function(o){ o.classList.remove("open"); }); });
  function exportPrefs(){
    downloadBlob(JSON.stringify({ tool:"CloudLog", kind:"prefs", exportedAt:new Date().toISOString(), customRules:CUSTOM_RULES, iocBlocklist:Array.from(IOC_BLOCKLIST), allowlist:Array.from(ALLOWLIST), assetCriticality:ASSET_CRITICALITY }, null, 2), "application/json", "cloudlog-rules-iocs.json");
  }
  function importPrefsFile(ev){
    var f=ev.target.files && ev.target.files[0]; if(!f) return;
    var r=new FileReader();
    r.onload=function(){
      try{
        var d=JSON.parse(r.result);
        var rules=d.customRules||[], bl=d.iocBlocklist||d.blocklist||[], al=d.allowlist||[];
        var added=0;
        rules.forEach(function(cr){ if(cr&&cr.name&&cr.pattern&&!CUSTOM_RULES.some(function(x){return x.name===cr.name&&x.pattern===cr.pattern;})){ CUSTOM_RULES.push({name:String(cr.name),pattern:String(cr.pattern),sev:cr.sev==="high"?"high":cr.sev==="low"?"low":"medium",isRegex:!!cr.isRegex}); added++; } });
        bl.forEach(function(x){ IOC_BLOCKLIST.add(String(x).toLowerCase()); });
        al.forEach(function(x){ ALLOWLIST.add(String(x).toLowerCase()); });
        if(d.assetCriticality) Object.keys(d.assetCriticality).forEach(function(k){ ASSET_CRITICALITY[k]=d.assetCriticality[k]; });
        savePrefs(); if(typeof refreshMyStats==="function") refreshMyStats();
        if(typeof renderCustomRuleList==="function") renderCustomRuleList();
        var blT=g("blText"); if(blT) blT.value=Array.from(IOC_BLOCKLIST).join("\n");
        var alT=g("alText"); if(alT) alT.value=Array.from(ALLOWLIST).join("\n");
        applyFilter();
        alert("Imported: "+added+" new rule(s), "+bl.length+" blocked IOC(s), "+al.length+" allow entr(ies). Merged with your existing saved data.");
      }catch(e){ alert("Could not import: "+e.message); }
      ev.target.value="";
    };
    r.readAsText(f);
  }
  if(g("navExportPrefs")) g("navExportPrefs").onclick=exportPrefs;
  if(g("navImportPrefs")) g("navImportPrefs").onchange=importPrefsFile;
  if(g("crExport")) g("crExport").onclick=exportPrefs;
  if(g("crImport")) g("crImport").onchange=importPrefsFile;
  if(g("loadCaseInput")) g("loadCaseInput").onchange=function(e){ if(e.target.files[0]) loadCase(e.target.files[0]); };
  if(g("reportBtn")) g("reportBtn").onclick=generateReport;
  if(g("crAdd")) g("crAdd").onclick=addCustomRule;
  if(g("crTest")) g("crTest").onclick=testCustomRule;
  function fileToTa(fileId, taId){ var f=g(fileId); if(!f) return; f.onchange=function(e){ var file=e.target.files[0]; if(!file) return; var r=new FileReader(); r.onload=function(){ g(taId).value=r.result; }; r.readAsText(file); }; }
  fileToTa("blFile","blText"); fileToTa("alFile","alText"); fileToTa("yaraFile","yaraText"); fileToTa("acFile","acText");
  if(g("acApply")) g("acApply").onclick=function(){ ASSET_CRITICALITY=parseAssetList(g("acText").value); savePrefs(); g("acMsg").textContent=Object.keys(ASSET_CRITICALITY).length+" asset(s) set & saved."; applyFilter(); };
  if(g("blApply")) g("blApply").onclick=function(){ var it=parseIocList(g("blText").value); IOC_BLOCKLIST=new Set(it); savePrefs(); if(window.refreshMyStats)window.refreshMyStats(); g("blMsg").textContent=it.length+" IOC(s) loaded & saved."; applyFilter(); };
  if(g("alApply")) g("alApply").onclick=function(){ var it=parseIocList(g("alText").value); ALLOWLIST=new Set(it); savePrefs(); if(window.refreshMyStats)window.refreshMyStats(); g("alMsg").textContent=it.length+" allow-list entr(ies) loaded & saved."; applyFilter(); };
  if(g("yaraApply")) g("yaraApply").onclick=function(){ YARA_RULES=parseYara(g("yaraText").value); var hx=YARA_RULES.filter(function(r){return r.hexOnly;}).length; g("yaraMsg").textContent=YARA_RULES.length+" rule(s) parsed"+(hx?" ("+hx+" hex-only skipped)":"")+"."; applyFilter(); };
})();

render([]);
try { checkProxy(); } catch(e) {}


/* ===== CYBER UI — live micro-interactions (visual only; lightweight) ===== */
(function(){
  if(typeof requestAnimationFrame==="undefined"||typeof document==="undefined"||!document.body){ return; }
  var reduce=(window.matchMedia && matchMedia('(prefers-reduced-motion:reduce)').matches);
  function chip(){ var bar=document.querySelector('.topbar-actions'); if(!bar||document.querySelector('.eng-status'))return;
    var c=document.createElement('span'); c.className='eng-status';
    c.innerHTML='<span class="pip"></span><span class="eng-txt">Engine active</span>';
    bar.insertBefore(c,bar.firstChild); }
  function setChip(t){ var e=document.querySelector('.eng-status .eng-txt'); if(e)e.textContent=t; }
  function countUp(el){
    var target=(el.textContent||"").trim(), num=parseFloat(target.replace(/[, ]/g,''));
    if(isNaN(num)||reduce||el.__animating||el.__shown===num) return;
    el.__shown=num; el.__animating=true;
    var s=performance.now(), dur=520, sfx=target.replace(/[0-9.,\s-]/g,'');
    function step(t){ var p=Math.min(1,(t-s)/dur), v=Math.round(num*(1-Math.pow(1-p,3)));
      el.textContent=v.toLocaleString()+sfx;
      if(p<1) requestAnimationFrame(step); else { el.textContent=target; el.__animating=false; } }
    requestAnimationFrame(step);
  }
  function hook(){
    document.querySelectorAll('.metric-value,.small-value').forEach(function(el){
      if(!el.__hooked){ el.__hooked=true;
        if(window.MutationObserver) new MutationObserver(function(){ if(!el.__animating) countUp(el); }).observe(el,{childList:true,characterData:true,subtree:true});
        countUp(el);
      }
    });
    var ev=document.getElementById('mEvents');
    if(ev){ var v=(ev.textContent||"").trim(); if(v&&v!=="0") setChip(v+" events analyzed"); }
  }
  function init(){ try{ chip(); hook(); }catch(e){} }
  if(document.readyState!=='loading') init(); else document.addEventListener('DOMContentLoaded',init);
  if(typeof setInterval!=="undefined") setInterval(function(){ try{ hook(); }catch(e){} }, 2500);
})();


/* ===== Inline Web Worker: engine off-main-thread with automatic sync fallback ===== */
(function(){
  // ---- WORKER SIDE: same script, running inside the Worker (no DOM) ----
  if (__IS_WORKER) {
    self.onmessage = function(ev){
      var d = ev.data || {};
      try {
        if (d.st) {
          try { ALLOWLIST = new Set(d.st.allowlist || []); } catch(e){}
          try { IOC_BLOCKLIST = new Set(d.st.blocklist || []); } catch(e){}
          try { MEMORY_BAD = new Set(d.st.memoryBad || []); } catch(e){}
          CUSTOM_RULES = d.st.customRules || CUSTOM_RULES;
          VERDICTS = d.st.verdicts || VERDICTS;
          ASSET_CRITICALITY = d.st.assetCriticality || ASSET_CRITICALITY;
          if (d.st.yaraText) { try { YARA_RULES = parseYara(d.st.yaraText); } catch(e){} }
        }
        var logs = parseAnyLog(d.raw, d.source);
        var dets = runDetections(logs);
        // sanitize for structured-clone: strip rule.match (a function) and replace event refs with indices
        var idx = new Map(); logs.forEach(function(e,i){ idx.set(e,i); });
        var detsSafe = dets.map(function(dd){
          return { rule: { id:dd.rule.id, name:dd.rule.name, sev:dd.rule.sev, title:dd.rule.title, desc:dd.rule.desc, suggestion:dd.rule.suggestion },
                   evi: (dd.events||[]).map(function(e){ return idx.has(e)?idx.get(e):-1; }).filter(function(x){ return x>=0; }) };
        });
        self.postMessage({ ok:true, logs:logs, dets:detsSafe });
      } catch(err) {
        self.postMessage({ ok:false, error:String((err && err.message) || err) });
      }
    };
    return; // worker does nothing else
  }

  // main-thread side: build the worker from this script's own text, with a sync fallback
  var _worker = null, _workerBroken = false;
  function getWorker(){
    if (_worker || _workerBroken) return _worker;
    try {
      if (typeof Worker === "undefined" || typeof Blob === "undefined" || typeof URL === "undefined" || !URL.createObjectURL) { _workerBroken = true; return null; }
      var el = document.getElementById("cloudlog-main");
      var src = el && el.textContent;
      if (!src || src.length < 1000) { _workerBroken = true; return null; }
      var blob = new Blob([src], { type: "application/javascript" });
      _worker = new Worker(URL.createObjectURL(blob));
      return _worker;
    } catch(e){ _workerBroken = true; return null; }
  }
  function snapshotState(){
    return { allowlist: (typeof ALLOWLIST!=="undefined")?Array.from(ALLOWLIST):[],
             blocklist: (typeof IOC_BLOCKLIST!=="undefined")?Array.from(IOC_BLOCKLIST):[],
             memoryBad: (typeof MEMORY_BAD!=="undefined")?Array.from(MEMORY_BAD):[],
             customRules: (typeof CUSTOM_RULES!=="undefined")?CUSTOM_RULES:[],
             verdicts: (typeof VERDICTS!=="undefined")?VERDICTS:{},
             assetCriticality: (typeof ASSET_CRITICALITY!=="undefined")?ASSET_CRITICALITY:{},
             yaraText: (typeof LAST_YARA_TEXT!=="undefined")?LAST_YARA_TEXT:"" };
  }
  // analyze off-thread; onDone(logs); falls back to sync parse on any failure/timeout
  window.__analyzeAsync = function(raw, source, onDone, onProgress){
    var w = getWorker();
    if (!w) { onDone(parseAnyLog(raw, source), false); return; }
    var settled = false;
    var to = setTimeout(function(){ if(settled) return; settled=true; try{ onDone(parseAnyLog(raw, source), false); }catch(e){ onDone([], false); } }, 20000);
    w.onmessage = function(ev){
      if (settled) return; settled = true; clearTimeout(to);
      var r = ev.data || {};
      if (!r.ok) { try{ onDone(parseAnyLog(raw, source), false); }catch(e){ onDone([], false); } return; }
      // rehydrate detection cache so render() doesn't recompute on the main thread
      try {
        var logs = r.logs || [];
        if (r.dets) {
          r.dets.forEach(function(dd){ dd.events = (dd.evi||[]).map(function(i){ return logs[i]; }).filter(Boolean); });
          window.__DET_CACHE_LIST = logs; window.__DET_CACHE = r.dets;
        }
        onDone(logs, true);
      } catch(e){ onDone(parseAnyLog(raw, source), false); }
    };
    w.onerror = function(){ if(settled) return; settled=true; clearTimeout(to); _workerBroken=true; try{ onDone(parseAnyLog(raw, source), false); }catch(e){ onDone([], false); } };
    if (onProgress) onProgress();
    try { w.postMessage({ raw: raw, source: source, st: snapshotState() }); }
    catch(e){ if(!settled){ settled=true; clearTimeout(to); onDone(parseAnyLog(raw, source), false); } }
  };
})();

/* runDetections cache hook: reuse worker-computed detections for the full dataset so
   the first render doesn't repeat the heavy detection pass on the main thread. */
if (typeof __IS_WORKER === "undefined" || !__IS_WORKER) {
  var __rd_orig = runDetections;
  runDetections = function(evts){
    // applyFilter always produces a NEW array (state.logs.filter), so compare by content
    // identity (same length + same first/last element refs), not array reference.
    var cl = (typeof window !== "undefined") ? window.__DET_CACHE_LIST : null;
    if (cl && window.__DET_CACHE && evts && evts.length === cl.length && evts.length > 0
        && evts[0] === cl[0] && evts[evts.length-1] === cl[cl.length-1]) return window.__DET_CACHE;
    var res = __rd_orig(evts);
    // populate the cache on full-dataset computes so repeat calls in the same render
    // (consolidation stats, analyst view, summary) are free; invalidated via savePrefs()
    if (typeof window !== "undefined" && evts && state && state.logs && evts.length === state.logs.length && evts.length > 200) {
      window.__DET_CACHE = res; window.__DET_CACHE_LIST = evts;
    }
    return res;
  };
  // Memoize correlateChains: renderChain/renderSummary/renderAttackMap/renderAnalyst/renderInvestigate
  // each call it on the same dataset within one render — without this it recomputed ~5x (huge on big logs).
  var __cc_orig = correlateChains, __ccCache = null, __ccKey = "";
  correlateChains = function(list, windowMs){
    var key = (list && list.length ? list.length+"|"+((list[0]&&list[0].time)||"")+"|"+((list[list.length-1]&&list[list.length-1].time)||"") : "0") + "|" + (windowMs||"");
    if (__ccCache && __ccKey === key) return __ccCache;
    __ccCache = __cc_orig(list, windowMs); __ccKey = key; return __ccCache;
  };
}


/* ===== Access control + encryption =====
   HONEST SECURITY MODEL (stated to the user in the UI too):
   - The lock screen controls WHO CAN USE this copy of the tool in a browser. Because the tool is
     a client-side file, a determined person with the file itself can bypass the UI lock — it is
     access control and deterrence, not tamper-proof security.
   - The genuinely strong part is CASE ENCRYPTION: saved cases are encrypted with AES-256-GCM,
     key derived from the passcode via PBKDF2 (210k iterations). Without the code, a saved case
     file is unreadable. Codes themselves are stored only as SHA-256 hashes.                     */





