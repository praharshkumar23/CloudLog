/* ============================================================
 * CloudLog — 10-analyst-and-ai.js
 * Written analyst briefing + optional BYO-key AI, with redaction. Includes esc().
 * Part of index.html; assembled by build.js. Do not add a <script> wrapper.
 * ============================================================ */
var KILLCHAIN = ["Reconnaissance","Initial Access","Execution","Privilege / Persistence","Discovery / C2","Exfiltration","Impact","Other"];

/* ---------- LOCAL analyst (deterministic, offline, zero-dependency) ---------- */
function generateAnalystReport(events, detections) {
  if (!events || !events.length) return null;

  // risk score: strongest single-event XDR score + detection pressure
  var maxXdr = 0, sumXdr = 0;
  events.forEach(function (e) { var s = buildXdrScore(e); maxXdr = Math.max(maxXdr, s); sumXdr += s; });
  var highs = detections.filter(function (d) { return d.rule.sev === "high"; }).length;
  var meds = detections.filter(function (d) { return d.rule.sev === "medium"; }).length;
  var risk = Math.min(100, Math.round(maxXdr * 0.7 + highs * 18 + meds * 7));
  var verdict = risk >= 70 ? { label: "CRITICAL", cls: "sev-high" }
    : risk >= 40 ? { label: "ELEVATED", cls: "sev-high" }
    : risk >= 15 ? { label: "GUARDED", cls: "sev-medium" }
    : { label: "LOW", cls: "sev-low" };

  // window
  var times = events.map(function (e) { return new Date(e.time).getTime(); }).filter(function (t) { return !isNaN(t); }).sort(function (a, b) { return a - b; });
  var t0 = times.length ? new Date(times[0]) : null, t1 = times.length ? new Date(times[times.length - 1]) : null;

  // entities
  var actorCount = {}, ipCount = {};
  events.forEach(function (e) {
    if (e.actor && e.actor !== "unknown" && e.actor !== "-") actorCount[e.actor] = (actorCount[e.actor] || 0) + 1;
    if (e.ip && ["-", "internal", "0.0.0.0", ""].indexOf(e.ip) === -1) ipCount[e.ip] = (ipCount[e.ip] || 0) + 1;
  });
  var topActors = rankObj(actorCount, 4), topIps = rankObj(ipCount, 4);

  // tactics observed, in kill-chain order
  var stageSet = {};
  events.forEach(function (e) { stageSet[classifyStage(e)] = 1; });
  var tactics = KILLCHAIN.filter(function (s) { return stageSet[s] && s !== "Other"; });

  // narrative (built from the actual data, not a template stuffed with fluff)
  var lead = topActors[0] ? topActors[0].k : "an unidentified actor";
  var leadIp = topIps[0] ? topIps[0].k : null;
  var span = computeSpan(events);
  var patternGroups = {}; detections.forEach(function (d) { patternGroups[d.rule.title] = (patternGroups[d.rule.title] || 0) + 1; });
  var patternKeys = Object.keys(patternGroups).sort(function (a, b) { return patternGroups[b] - patternGroups[a]; });
  var patternSummary = patternKeys.map(function (t) { return esc(t) + " (×" + patternGroups[t] + ")"; }).join(", ");
  var narrative =
    events.length.toLocaleString() + " event" + (events.length === 1 ? "" : "s") +
    (t0 ? " between " + formatTime(t0) + " and " + formatTime(t1) + " (span " + span + ")" : "") +
    " across " + countKeys(events, "source") + " source(s). The most active principal was " +
    "<b>" + esc(lead) + "</b>" + (leadIp ? " (top source IP <b>" + esc(leadIp) + "</b>)" : "") + ". " +
    (tactics.length
      ? "Observed activity spans the kill-chain phases: <b>" + tactics.join(" → ") + "</b>. "
      : "No clear multi-stage progression was detected. ") +
    (detections.length
      ? "Correlation surfaced " + detections.length + " detection" + (detections.length === 1 ? "" : "s") + " across " + patternKeys.length + " pattern type" + (patternKeys.length === 1 ? "" : "s") + ": " + patternSummary + ". "
      : "No known-bad correlation patterns fired on this dataset. ") +
    (function(){ var cs = consolidationStats(events); return cs.alerts ? "Consolidation reduced " + cs.alerts.toLocaleString() + " raw alert(s) to " + cs.investigations + " investigation(s) (" + cs.reduction + "% noise reduced), saving the analyst that much triage." : ""; })();

  // recommended actions — dedup detection fixes, high severity first
  var seen = {}, actions = [];
  detections.slice().sort(function (a, b) { var o = { high: 0, medium: 1, low: 2 }; return o[a.rule.sev] - o[b.rule.sev]; })
    .forEach(function (d) { var f = d.rule.suggestion; if (f && !seen[f]) { seen[f] = 1; actions.push({ sev: d.rule.sev, text: f }); } });
  if (!actions.length) actions.push({ sev: "low", text: "No automated actions required. Confirm this activity matches expected baselines and archive for reference." });

  return {
    risk: risk, verdict: verdict, narrative: narrative,
    window: t0 ? (formatTime(t0) + "  →  " + formatTime(t1)) : "no timestamps",
    tactics: tactics, topActors: topActors, topIps: topIps,
    findings: (function () {
      var groups = {}, order = { high:0, medium:1, low:2 };
      detections.forEach(function (d) {
        var key = d.rule.id + "|" + d.rule.title;
        var g = groups[key] || (groups[key] = { title:d.rule.title, id:d.rule.id, sev:d.rule.sev, n:0, instances:0, actors:{} });
        g.n += d.events.length; g.instances++;
        if (order[d.rule.sev] < order[g.sev]) g.sev = d.rule.sev;
        if (d.actor && d.actor !== "unknown" && d.actor !== "-") g.actors[d.actor] = (g.actors[d.actor] || 0) + d.events.length;
      });
      return Object.keys(groups).map(function (k) {
        var g = groups[k], acts = Object.keys(g.actors).sort(function (a, b) { return g.actors[b] - g.actors[a]; });
        return { title:g.title, id:g.id, sev:g.sev, n:g.n, instances:g.instances, actorCount:acts.length, actorsShown:acts.slice(0, 8), moreActors:Math.max(0, acts.length - 8) };
      }).sort(function (a, b) { return (order[a.sev] - order[b.sev]) || (b.n - a.n); });
    })(),
    actions: actions,
    confidence: detections.length ? "Medium–High" : "Low",
    caveat: "Rule-based on-device reasoning over " + events.length.toLocaleString() + " event(s). Verify against source systems before acting; this is decision support, not a verdict."
  };
}
function rankObj(o, n) { return Object.keys(o).map(function (k) { return { k: k, n: o[k] }; }).sort(function (a, b) { return b.n - a.n; }).slice(0, n); }
function countKeys(arr, key) { var s = {}; arr.forEach(function (e) { s[e[key]] = 1; }); return Object.keys(s).length; }
// HTML-escape for BOTH text and attribute contexts. Log data is untrusted (attacker-controlled),
// and esc() output is interpolated into quoted HTML attributes (data-pivot, title, value, …), so
// quotes MUST be escaped or a crafted field could break out of the attribute (stored XSS).
function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"'`]/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" }[c];
  });
}

function renderAnalyst(list, detections) {
  var el = document.getElementById("analystContent");
  if (!el) return;
  var r = generateAnalystReport(list, detections);
  if (!r) { el.innerHTML = '<p class="empty-note">Load a log source to generate an AI analyst report.</p>'; return; }
  var actionsHtml = r.actions.map(function (a) {
    var sc = a.sev === "high" ? "sev-high" : a.sev === "medium" ? "sev-medium" : "sev-low";
    return '<li><span class="sev ' + sc + '">' + a.sev + '</span> ' + esc(a.text) + '</li>';
  }).join("");
  var findHtml = r.findings.length ? r.findings.map(function (f) {
    var sc = f.sev === "high" ? "sev-high" : f.sev === "medium" ? "sev-medium" : "sev-low";
    var who = f.actorsShown.length ? ' across ' + f.actorCount + ' account(s): ' + f.actorsShown.map(esc).join(", ") + (f.moreActors ? ' +' + f.moreActors + ' more' : '') : '';
    var txt = (f.title + " " + f.id + " " + f.actorsShown.join(" ")).toLowerCase();
    return '<li data-sev="' + f.sev + '" data-text="' + esc(txt) + '"><span class="sev ' + sc + '">' + f.sev + '</span> <b>' + esc(f.title) + '</b> <span class="muted">· ' + esc(f.id) + ' · ' + f.n + ' event(s)' + (f.instances > 1 ? ' in ' + f.instances + ' groups' : '') + esc(who) + '</span></li>';
  }).join("") : '<li class="muted">No correlation findings.</li>';
  var entHtml =
    '<div class="ai-ent"><h4>Top actors</h4>' + (r.topActors.length ? r.topActors.map(function (x) { return '<div class="ai-chip">' + esc(x.k) + ' <b>' + x.n + '</b></div>'; }).join("") : '<span class="muted">none</span>') + '</div>' +
    '<div class="ai-ent"><h4>Top source IPs</h4>' + (r.topIps.length ? r.topIps.map(function (x) { return '<div class="ai-chip">' + esc(x.k) + ' <b>' + x.n + '</b></div>'; }).join("") : '<span class="muted">none</span>') + '</div>';

  el.innerHTML =
    '<div class="ai-report">' +
      '<div class="ai-verdict">' +
        '<div class="ai-gauge"><div class="ai-gauge-num">' + r.risk + '</div><div class="ai-gauge-lbl">RISK</div></div>' +
        '<div><span class="sev ' + r.verdict.cls + '" style="font-size:13px;">' + r.verdict.label + '</span>' +
        '<div class="muted small" style="margin-top:6px;">Window: ' + esc(r.window) + ' · Confidence: ' + r.confidence + '</div></div>' +
      '</div>' +
      '<h3 class="ai-h">Incident summary</h3><p class="ai-narr">' + r.narrative + '</p>' +
      '<div class="ai-cols">' +
        '<div><h3 class="ai-h">Key findings <span class="muted small">(' + r.findings.length + ' grouped)</span></h3>' +
          '<div class="ai-filter"><select id="findSev"><option value="all">All severities</option><option value="high">High only</option><option value="medium">Medium &amp; up</option></select>' +
          '<input type="text" id="findSearch" placeholder="filter by rule or account…"/></div>' +
          '<ul class="ai-list" id="findList">' + findHtml + '</ul></div>' +
        '<div><h3 class="ai-h">Recommended actions</h3><ul class="ai-list">' + actionsHtml + '</ul></div>' +
      '</div>' +
      '<h3 class="ai-h">Entities</h3><div class="ai-ents">' + entHtml + '</div>' +
      '<p class="ai-caveat">⚠ ' + esc(r.caveat) + '</p>' +
    '</div>';
  (function(){
    var sev=document.getElementById("findSev"), q=document.getElementById("findSearch"), ul=document.getElementById("findList");
    if(!ul) return;
    function apply(){
      var sv=sev?sev.value:"all", term=(q?q.value:"").toLowerCase().trim();
      var order={high:0,medium:1,low:2};
      ul.querySelectorAll("li[data-sev]").forEach(function(li){
        var s=li.getAttribute("data-sev"), t=li.getAttribute("data-text")||"";
        var okSev = sv==="all" || (sv==="high"&&s==="high") || (sv==="medium"&&order[s]<=1);
        var okTerm = !term || t.indexOf(term)>=0;
        li.style.display = (okSev && okTerm) ? "" : "none";
      });
    }
    if(sev) sev.onchange=apply; if(q) q.oninput=apply;
  })();
}

/* ---------- REDACTION (what may leave the browser if the user opts in) ---------- */
function redactIp(ip) { if (!ip || ip === "-") return ip; var m = /^(\d+)\.(\d+)\.\d+\.\d+$/.exec(ip); return m ? m[1] + "." + m[2] + ".x.x" : "x.x.x.x"; }
function redactActor(a) {
  if (!a || a === "unknown" || a === "-") return a;
  if (/@/.test(a)) { var p = a.split("@"); return "***@" + p[1]; }
  if (a.length <= 2) return "**";
  return a[0] + "***" + a[a.length - 1];
}
function buildRedactedContext(events, detections) {
  var actionCount = {}, srcCount = {};
  events.forEach(function (e) { actionCount[e.action] = (actionCount[e.action] || 0) + 1; srcCount[e.source] = (srcCount[e.source] || 0) + 1; });
  var stageSet = {}; events.forEach(function (e) { stageSet[classifyStage(e)] = 1; });
  return {
    note: "REDACTED AGGREGATE — no raw log bodies, IPs masked to /16, identities masked.",
    totalEvents: events.length,
    timeSpan: computeSpan(events),
    sources: srcCount,
    killChainStages: Object.keys(stageSet).filter(function (s) { return s !== "Other"; }),
    topActionsMasked: rankObj(actionCount, 8).map(function (x) { return { action: x.k, count: x.n }; }),
    topActorsMasked: rankObj(countBy(events, "actor"), 5).map(function (x) { return { actor: redactActor(x.k), count: x.n }; }),
    topIpsMasked: rankObj(countBy(events, "ip"), 5).map(function (x) { return { ip: redactIp(x.k), count: x.n }; }),
    detections: detections.map(function (d) { return { name: d.rule.title, mitre: d.rule.id, severity: d.rule.sev, matched: d.events.length }; })
  };
}
function countBy(arr, key) { var s = {}; arr.forEach(function (e) { var k = e[key]; if (k && k !== "-" && k !== "unknown" && k !== "") s[k] = (s[k] || 0) + 1; }); return s; }

function refreshRedactionPreview() {
  var pre = document.getElementById("aiPayloadPreview");
  if (!pre) return;
  var ctx = buildRedactedContext(state.filtered || [], state.detections || []);
  pre.textContent = JSON.stringify(ctx, null, 2);
}

/* ---------- OPTIONAL cloud Q&A (bring-your-own-key) ---------- */
var AI_PROVIDERS = {
  anthropic: { label:"Anthropic — Claude", keyHint:"sk-ant-...", keyLabel:"Your Anthropic API key (in memory only, never saved)",
    models:["claude-sonnet-5","claude-opus-4-8","claude-haiku-4-5-20251001"],
    build:function(key,model,sys,user){ return { url:"https://api.anthropic.com/v1/messages",
      headers:{"content-type":"application/json","x-api-key":key,"anthropic-version":"2023-06-01","anthropic-dangerous-direct-browser-access":"true"},
      body:JSON.stringify({model:model,max_tokens:900,system:sys,messages:[{role:"user",content:user}]}) }; },
    parse:function(j){ return (j.content||[]).filter(function(b){return b.type==="text";}).map(function(b){return b.text;}).join("\n").trim(); } },
  openai: { label:"OpenAI — ChatGPT", keyHint:"sk-...", keyLabel:"Your OpenAI API key (in memory only, never saved)",
    models:["gpt-4o-mini","gpt-4o","gpt-4.1","o4-mini"],
    build:function(key,model,sys,user){ return { url:"https://api.openai.com/v1/chat/completions",
      headers:{"content-type":"application/json","authorization":"Bearer "+key},
      body:JSON.stringify({model:model,max_tokens:900,messages:[{role:"system",content:sys},{role:"user",content:user}]}) }; },
    parse:function(j){ return (j.choices&&j.choices[0]&&j.choices[0].message&&j.choices[0].message.content||"").trim(); } },
  gemini: { label:"Google — Gemini", keyHint:"AIza...", keyLabel:"Your Google AI Studio API key (in memory only, never saved)",
    models:["gemini-2.0-flash","gemini-2.5-flash","gemini-2.5-pro","gemini-1.5-pro"],
    build:function(key,model,sys,user){ return { url:"https://generativelanguage.googleapis.com/v1beta/models/"+encodeURIComponent(model)+":generateContent?key="+encodeURIComponent(key),
      headers:{"content-type":"application/json"},
      body:JSON.stringify({systemInstruction:{parts:[{text:sys}]},contents:[{role:"user",parts:[{text:user}]}],generationConfig:{maxOutputTokens:900}}) }; },
    parse:function(j){ try{ return j.candidates[0].content.parts.map(function(p){return p.text||"";}).join("").trim(); }catch(e){ return ""; } } }
};
function currentProvider(){ var el=document.getElementById("aiProvider"); return (el&&AI_PROVIDERS[el.value])?el.value:"anthropic"; }
function updateProviderUI(){
  var pid=currentProvider(), P=AI_PROVIDERS[pid];
  var keyEl=document.getElementById("aiKey"), lbl=document.getElementById("aiKeyLabel"),
      model=document.getElementById("aiModel"), hint=document.getElementById("aiModelHint"), dl=document.getElementById("aiModelList");
  if(lbl) lbl.textContent=P.keyLabel; if(keyEl) keyEl.placeholder=P.keyHint;
  if(model) model.value=P.models[0]; if(hint) hint.textContent="(editable — type any model your key supports)";
  if(dl) dl.innerHTML=P.models.map(function(m){return "<option value='"+m+"'></option>";}).join("");
}
function askCloudAI() {
  var keyEl=document.getElementById("aiKey"), qEl=document.getElementById("aiQuestion"),
      modelEl=document.getElementById("aiModel"), out=document.getElementById("aiAnswer"), btn=document.getElementById("aiAskBtn");
  var pid=currentProvider(), P=AI_PROVIDERS[pid];
  var key=keyEl.value.trim(), q=qEl.value.trim(), model=(modelEl.value||P.models[0]).trim();
  if(!key){ out.innerHTML='<span style="color:#b91c1c;">Enter your '+esc(P.label)+' API key first. It stays in memory only and is never saved.</span>'; return; }
  if(!q){ out.innerHTML='<span style="color:#b91c1c;">Type a question about the current events.</span>'; return; }
  if(!(state.filtered&&state.filtered.length)){ out.innerHTML='<span style="color:#b91c1c;">Load a log source first.</span>'; return; }

  var ctx=buildRedactedContext(state.filtered, state.detections);
  var sys="You are a senior SOC analyst. You are given a REDACTED aggregate summary of security events (no raw logs, IPs masked, identities masked). Answer the analyst's question concisely and practically. If the summary lacks detail, say so and suggest what to pull from the source system. Never fabricate specific IPs, usernames, or timestamps beyond what is provided.";
  var userMsg="Redacted incident summary:\n"+JSON.stringify(ctx)+"\n\nQuestion: "+q;

  var reqSpec; try { reqSpec=P.build(key,model,sys,userMsg); } catch(e){ out.innerHTML='<span style="color:#b91c1c;">Could not build request.</span>'; return; }
  btn.disabled=true; btn.textContent="Analyzing…";
  out.innerHTML='<span class="muted">Contacting '+esc(P.label)+' ('+esc(model)+') with the redacted summary shown above…</span>';

  fetch(reqSpec.url,{method:"POST",headers:reqSpec.headers,body:reqSpec.body})
  .then(function(r){ return r.json().then(function(j){ return {ok:r.ok,j:j}; }); })
  .then(function(res){
    if(!res.ok){ var msg=(res.j&&res.j.error&&(res.j.error.message||res.j.error))||("HTTP error "+JSON.stringify(res.j).slice(0,300)); out.innerHTML='<span style="color:#b91c1c;">'+esc(P.label)+' API error: '+esc(String(msg))+'</span>'; return; }
    var text=P.parse(res.j);
    out.innerHTML='<div class="ai-answer-body">'+esc(text||"(empty response)").replace(/\n/g,"<br/>")+'</div>';
  })
  .catch(function(err){ out.innerHTML='<span style="color:#b91c1c;">Request failed: '+esc(String(err.message||err))+'. From a local file, browser CORS may block direct API calls — serve over http or use a hosted deployment.</span>'; })
  .finally(function(){ btn.disabled=false; btn.textContent="Ask (sends redacted summary)"; });
}

/* ---------- wiring ---------- */
(function () {
  var toggle = document.getElementById("aiPreviewToggle");
  if (toggle) toggle.onclick = function () {
    var pre = document.getElementById("aiPayloadPreview");
    var hidden = pre.classList.contains("hidden");
    if (hidden) { refreshRedactionPreview(); pre.classList.remove("hidden"); toggle.textContent = "▾ Hide what will be sent"; }
    else { pre.classList.add("hidden"); toggle.textContent = "▸ Preview exactly what will be sent"; }
  };
  var ask = document.getElementById("aiAskBtn");
  if (ask) ask.onclick = askCloudAI;
  var prov = document.getElementById("aiProvider");
  if (prov) prov.onchange = updateProviderUI;
  try { updateProviderUI(); } catch(e) {}
})();


/* ==== IOC INTEL ==== */
/* ============================================================================
   THREAT INTEL CORE  (pure, testable)
   - Extract IOCs from events (IPs, domains, URLs, file hashes, emails)
   - Classify IPs (public vs private/reserved) and hashes (md5/sha1/sha256)
   - Gate what is SAFE to send to third parties (never leak internal space)
   - Build enrichment targets for VirusTotal / AbuseIPDB / OTX / urlscan / GSB
   - Auto-correlate events into attack chains by shared IOC + time
   ========================================================================== */

/* ---------- IP classification (RFC1918/loopback/linklocal/CGNAT/reserved) ---------- */





