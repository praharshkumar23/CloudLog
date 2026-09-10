/* ============================================================
 * CloudLog — 06-render.js
 * Tab rendering: metrics, detections, chain, evidence graph, summary, welcome.
 * Part of index.html; assembled by build.js. Do not add a <script> wrapper.
 * ============================================================ */
function render(list) {
  var full = state.logs || [];
  var viewList = list || full;                 // table view = filtered (search / pivot); analysis stays on the full dataset
  var isFiltered = viewList.length !== full.length;

  // metric tiles always reflect the full loaded dataset (filtering an IP must not shrink your totals) ----
  var actors = {}, ips = {};
  full.forEach(function(r){ actors[r.actor]=1; ips[r.ip]=1; });
  document.getElementById("mEvents").textContent = full.length.toLocaleString();
  document.getElementById("mActors").textContent = Object.keys(actors).length;
  document.getElementById("mIps").textContent = Object.keys(ips).length;
  document.getElementById("mSource").textContent = state.source;
  var _nt=document.getElementById("navTotal"); if(_nt) _nt.textContent=full.length.toLocaleString();
  var _ns=document.getElementById("navSrc"); if(_ns) _ns.textContent=(full.length?state.source:"no logs yet");
  var spanEl = document.getElementById("mSpan");
  if (spanEl) spanEl.textContent = computeSpan(full);

  // ---- "showing N of TOTAL" caption above the table when a filter is active ----
  var vc = document.getElementById("viewCount");
  if (vc) vc.innerHTML = isFiltered
    ? 'Showing <b>'+viewList.length.toLocaleString()+'</b> of '+full.length.toLocaleString()+' events (filter active)<span class="vc-clear" onclick="clearPivot()">show all \u2715</span>'
    : '';

  // ---- events TABLE reflects the current filter ----
  var tbody = document.getElementById("tbody");
  if (!full.length) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="6">No events loaded. Upload a file or pick a source from the sidebar.</td></tr>';
    state.filtered = [];
  } else if (!viewList.length) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="6">No events match this filter. Use "show all" above to clear it.</td></tr>';
    state.filtered = [];
  } else {
    var sortedList = viewList.slice().sort(function(a,b){
      return state.sortDesc ? new Date(b.time) - new Date(a.time) : new Date(a.time) - new Date(b.time);
    });
    state.filtered = sortedList;
    // DOM safety: injecting tens of thousands of <tr> nodes crashes the browser's layout engine.
    // Triage works on the top of a sorted/filtered list, so render a bounded window and tell the
    // analyst the real total + how to narrow. (analysis always runs on the full dataset; this caps
    // only what the events TABLE paints.)
    var ROW_CAP = 1000;
    var capped = sortedList.length > ROW_CAP;
    var toRender = capped ? sortedList.slice(0, ROW_CAP) : sortedList;
    var rows = "";
    toRender.forEach(function(r, i) {
      var _sv = severityOf(r);
      rows += "<tr data-i='"+i+"' data-sev='"+_sv+"'><td>"+sevBadge(_sv, r)+"</td><td>"+formatTime(r.time)+"</td><td>"+pivotSpan(r.actor)+"</td><td>"+esc(r.action)+"</td><td>"+pivotSpan(r.ip)+"</td><td><span class='source-tag'>"+esc(r.source)+"</span></td></tr>";
    });
    if (capped) {
      rows += "<tr class='row-cap-note'><td colspan='6'>Showing the first <b>"+ROW_CAP.toLocaleString()+"</b> of <b>"+sortedList.length.toLocaleString()+"</b> matching events. Narrow with search, a pivot, or the Hunt tab to see specific events \u2014 all analysis still runs on the full dataset.</td></tr>";
    }
    tbody.innerHTML = rows;
    applyTimeSeverityFilter();
    var _sf=document.getElementById("sevFilter"); if(_sf) _sf.onchange=applyTimeSeverityFilter;
    tbody.querySelectorAll("tr[data-i]").forEach(function(tr){
      tr.onclick = function(){ openInspector(state.filtered[this.getAttribute("data-i")]); };
    });
  }

  // ---- all analysis runs on the FULL dataset, so filtering never disrupts detections/summary/investigation ----
  // ---- all analysis stays on the FULL dataset; clicking/filtering never disrupts totals or investigation ----
  var detections = runDetections(full);
  // tile counts DISTINCT findings (one per rule), matching the cards on the Detections tab —
  // raw per-group counts made the tile read "63" while the tab showed 12 cards.
  var __sigIds = {};
  detections.forEach(function(d){ if(!(d.rule && d.rule.meta)) __sigIds[d.rule.id] = 1; });
  var signalCount = Object.keys(__sigIds).length;
  document.getElementById("mDetections").textContent = signalCount;
  state.detections = detections;
  renderPlainSummary(full, detections);            // the headline card is always kept fresh (cheap)
  // Lazy tab rendering: only build the tab you're looking at; the heavy ones (Investigate,
  // AI Analyst, Attack Chain, Evidence Graph, detailed Summary) render when you open them.
  __tabData = { full: full, detections: detections };
  __tabRendered = {};
  renderActiveTab();
}
var __tabData = null, __tabRendered = {};
function renderTab(name){
  if (!__tabData || __tabRendered[name]) return;
  var full = __tabData.full, detections = __tabData.detections;
  try {
    if (name === "detections") renderDetections(detections);
    else if (name === "chain") renderChain(full);
    else if (name === "summary") renderSummary(full, detections);
    else if (name === "map") renderAttackMap(full);
    else if (name === "ai") renderAnalyst(full, detections);
    else if (name === "investigate") renderInvestigate(full);
    // "timeline" table + "summary" plain card are already built in render(); "hunt" has its own renderer
  } catch(e){}
  __tabRendered[name] = true;
}
function renderActiveTab(){
  var active = document.querySelector(".tab-panel.active");
  var name = active ? String(active.id||"").replace("panel-","") : "summary";
  renderTab(name);
}

/* ---------- Detections (clickable, expandable) ---------- */
// Group-based rules (e.g. brute force, path probing) emit one detection per source, which
// would otherwise show as dozens of identical-named rows. Aggregate by rule id for display.
function aggregateDetections(detections){
  var byId={}, order=[];
  detections.forEach(function(d){
    var id=d.rule.id;
    if(!byId[id]){ byId[id]={rule:d.rule, events:[], groups:0, actors:{}}; order.push(id); }
    var b=byId[id]; b.events=b.events.concat(d.events||[]); b.groups++;
    if(d.actor) b.actors[d.actor]=1;
  });
  return order.map(function(id){ var a=byId[id]; a.sources=Object.keys(a.actors).length; return a; });
}
function renderDetections(detectionsRaw) {
  var detections = aggregateDetections(detectionsRaw);
  var el = document.getElementById("detectionsList");
  if (!detections.length) { el.innerHTML = '<p class="empty-note">No suspicious patterns detected in the current dataset.</p>'; return; }
  // signal first; verdict-echo meta rules (TI-*/GD-*) collapse at the bottom so they don't drown real findings
  var signal = detections.filter(function(d){ return !d.rule.meta; });
  var echoes = detections.filter(function(d){ return d.rule.meta; });
  detections = signal.concat(echoes);
  var htmlOut = "";
  var echoStarted = false;
  detections.forEach(function(d, idx) {
    if (d.rule.meta && !echoStarted) {
      echoStarted = true;
      var echoEv = 0; echoes.forEach(function(x){ echoEv += (x.events?x.events.length:0); });
      htmlOut += '<details class="echo-wrap"><summary>Source-verdict echoes — '+echoes.length+' rule(s), '+echoEv.toLocaleString()+' events. These repeat the malicious/suspicious verdict already shown on each event; the real findings are above.</summary>';
    }
    var sevClass = d.rule.sev === "high" ? "sev-high" : d.rule.sev === "medium" ? "sev-medium" : "sev-low";
    var evRows = d.events.slice(0, 20).map(function(e){
      return "<tr><td>" + formatTime(e.time) + "</td><td>" + pivotSpan(e.actor) + "</td><td>" + pivotSpan(e.ip) + "</td><td>" + esc(e.action) + "</td></tr>";
    }).join("");
    htmlOut += '<div class="detection-item" data-idx="'+idx+'">'
      + '<div class="detection-top" style="cursor:pointer;">'
      + '<span class="detection-title">' + d.rule.title + '</span>'
      + '<span class="sev ' + sevClass + '">' + d.rule.sev + '</span> ' + fidelityBadge(d.rule.id, d.rule.name)
      + '</div>'
      + '<div><span class="mitre-tag">MITRE ' + d.rule.id + ' - ' + d.rule.name + '</span> ' + frameworkTagsHtml(d.rule.id, d.rule.name) + '</div>'
      + '<p class="detection-desc">' + d.rule.desc + ' Matched ' + d.events.length + ' event(s)' + (d.groups > 1 ? ' across <b>'+d.groups+'</b> source(s)' : (d.actors && Object.keys(d.actors)[0] ? ' for actor <b>'+Object.keys(d.actors)[0]+'</b>' : '')) + (d.events[0] ? ' - Stage: <b>' + classifyStage(d.events[0]) + '</b>' : '') + '. <span style="color:#6d5ff0; font-weight:600; cursor:pointer;" class="detection-toggle">Click to view matched events &#9662;</span></p>'
      + '<div class="suggestion-box"><b>Suggested action:</b> ' + d.rule.suggestion + '</div>'
      + '<div class="detection-events hidden" style="margin-top:10px; max-height:260px; overflow:auto; border-top:1px solid #eee; padding-top:10px;">'
      + '<table style="width:100%; font-size:12.5px; border-collapse:collapse;"><thead><tr style="text-align:left; color:#666;"><th>Time</th><th>Actor</th><th>IP</th><th>Action</th></tr></thead><tbody>' + evRows + '</tbody></table>'
      + (d.events.length > 20 ? '<p style="color:#999; font-size:12px; margin-top:6px;">Showing first 20 of ' + d.events.length + ' matched events.</p>' : '')
      + '</div>'
      + '</div>';
  });
  if (echoStarted) htmlOut += '</details>';
  el.innerHTML = htmlOut;
  el.querySelectorAll(".detection-item").forEach(function(item){
    var toggle = item.querySelector(".detection-toggle");
    var body = item.querySelector(".detection-events");
    var top = item.querySelector(".detection-top");
    var open = function(){
      var isHidden = body.classList.contains("hidden");
      body.classList.toggle("hidden");
      if (toggle) toggle.innerHTML = isHidden ? "Hide matched events &#9652;" : "Click to view matched events &#9662;";
    };
    if (toggle) toggle.onclick = open;
    if (top) top.onclick = open;
  });
}

/* ---------- Connected chain (fixed string bug) ---------- */
function renderChain(list) {
  var modern = document.getElementById("modernChain");
  var legacy = document.getElementById("chainList");
  if (!list.length) {
    if (modern) modern.innerHTML = '<p class="empty-note">No chain yet. Load a log source to build the sequence.</p>';
    if (legacy) legacy.innerHTML = '<p class="empty-note">No activity chain yet. Load a log source to build the sequence.</p>';
    return;
  }
  var sorted = list.slice().sort(function(a,b){ return new Date(a.time) - new Date(b.time); });
  var edges = [];
  var htmlNodes = "";
  for (var i=0;i<sorted.length;i++) {
    var r = sorted[i];
    var tags = [];
    if (r.ip && r.ip !== "-") tags.push("IP");
    if ((r.urls||[]).length) tags.push("URL");
    if ((r.cmds||[]).length) tags.push("CMD");
    if ((r.domains||[]).length) tags.push("DNS");
    if ((r.hashes||[]).length) tags.push("HASH");
    if (r.attackTag) tags.push(r.attackTag);
    if (i > 0) {
      var p = sorted[i-1];
      var rs = [];
      if (p.ip && r.ip && p.ip === r.ip) rs.push("same IP");
      if (p.actor && r.actor && p.actor === r.actor) rs.push("same actor");
      if (rs.length) edges.push((i) + " \u2192 " + (i+1) + " (" + rs.join(", ") + ")");
    }
    var stage = classifyStage(r);
    var _nsev = severityOf(r);
    var scoreClass = _nsev === "malicious" ? "sev-high" : _nsev === "suspicious" ? "sev-medium" : "sev-low";
    htmlNodes += '<div class="node-card" data-i="'+i+'" data-stage="'+stage+'">'
      + '<div class="node-top"><b>'+formatTime(r.time)+'</b><span class="node-source">'+esc(r.source)+'</span></div>'
      + '<div class="node-main">'+esc(r.action||"event")+'</div>'
      + '<div class="node-meta">'+esc(r.actor||"unknown")+' \u2022 '+esc(r.ip||"-")+'</div>'
      + formatIndicators(r)
      + '<div class="node-stage">' + stage + '</div>'
      + '<div class="node-tags">' + tags.map(function(t){ return '<span class="node-tag">'+t+'</span>'; }).join(" ") + ' <span class="sev '+scoreClass+'">'+_nsev+'</span></div>'
      + '</div>';
  }
  if (modern) modern.innerHTML = '<div class="modern-chain">'+htmlNodes+'</div>' + (edges.length ? '<div class="chain-summary">Connected sequence:<br/>' + edges.slice(0,10).join("<br/>") + '</div>' : '<div class="chain-summary">No direct links found. Use IP, actor, URL, command, domain, or hash matches to connect nodes.</div>');
  if (legacy) legacy.innerHTML = sorted.map(function(r){ return '<div class="chain-item"><span class="chain-dot"></span><div class="chain-body"><strong>' + esc(r.action) + '</strong><span class="muted">' + formatTime(r.time) + ' &middot; actor: ' + esc(r.actor||"-") + ' &middot; ip: ' + esc(r.ip||"-") + ' &middot; source: ' + esc(r.source) + '</span></div></div>'; }).join("");
  if (modern) modern.querySelectorAll(".node-card").forEach(function(card){
    card.onclick = function(){
      var i = parseInt(this.getAttribute("data-i"),10);
      var item = sorted[i];
      openInspector(item);
      switchToTab("timeline");
    };
  });
}

/* ---------- Attack Map: SVG graph with arrows, stage colors, severity borders ---------- */
function renderAttackMap(list) {
  var svg = document.getElementById("attackMapSvg");
  var legend = document.getElementById("mapLegend");
  var info = document.getElementById("egInfo");
  if (!svg) return;
  svg.innerHTML = "";
  if (!list.length) {
    svg.setAttribute("height", 120);
    svg.innerHTML = '<text x="20" y="50" fill="#8a8fa3" font-size="13">No data yet. Load a log source to build the evidence graph.</text>';
    if (legend) legend.innerHTML = ""; if (info) info.innerHTML = "";
    return;
  }
  var g = buildEvidenceGraph(list);
  if (!g.nodes.length) {
    svg.setAttribute("height", 120);
    svg.innerHTML = '<text x="20" y="50" fill="#8a8fa3" font-size="13">No linkable entities found in this data.</text>';
    return;
  }
  var cols = ["user","ip","host","domain","hash"];
  var colLabel = { user:"Users", ip:"IPs", host:"Hosts", domain:"Domains", hash:"Hashes" };
  var byType = {}; cols.forEach(function(c){ byType[c]=[]; });
  g.nodes.forEach(function(n){ if(byType[n.type]) byType[n.type].push(n); });
  var activeCols = cols.filter(function(c){ return byType[c].length; });
  var W = Math.max(780, activeCols.length*190);
  var colGap = W/(activeCols.length+1);
  var maxRows = Math.max.apply(null, activeCols.map(function(c){ return byType[c].length; }));
  var rowGap = 44, topPad = 58;
  var H = Math.max(300, topPad + maxRows*rowGap + 30);
  svg.setAttribute("viewBox", "0 0 "+W+" "+H);
  svg.setAttribute("height", Math.min(H, 720));
  svg.setAttribute("preserveAspectRatio","xMidYMin meet");
  var pos = {};
  activeCols.forEach(function(c,ci){
    var x = colGap*(ci+1);
    var nodes = byType[c].sort(function(a,b){ return b.risk-a.risk || b.count-a.count; });
    var startY = topPad + (maxRows - nodes.length)*rowGap/2;
    nodes.forEach(function(n,ri){ pos[n.id] = { x:x, y:startY+ri*rowGap }; });
  });
  var parts = [];
  var TYPE_COL = { user:"#7c6cff", ip:"#2fe6e0", host:"#35c9a0", domain:"#4f8cff", hash:"#e0b341", email:"#f472b6", process:"#c084fc" };
  activeCols.forEach(function(c,ci){ var x = colGap*(ci+1);
    parts.push('<text x="'+x+'" y="32" text-anchor="middle" font-size="12" font-weight="700" fill="'+(TYPE_COL[c]||"#9fb0d8")+'">'+colLabel[c]+' ('+byType[c].length+')</text>'); });
  g.edges.forEach(function(e){ var a=pos[e.a], b=pos[e.b]; if(!a||!b) return;
    var mx=(a.x+b.x)/2;
    parts.push('<path class="eg-edge" data-a="'+esc(e.a)+'" data-b="'+esc(e.b)+'" data-verb="'+esc(e.verb||"accessed")+'" d="M'+a.x+','+a.y+' C'+mx+','+a.y+' '+mx+','+b.y+' '+b.x+','+b.y+'" fill="none" stroke="#5f6b92" stroke-width="'+Math.min(3,0.7+e.weight/4).toFixed(1)+'" opacity="0.28"><title>'+esc(e.verb||"accessed")+'</title></path>'); });
  g.nodes.forEach(function(n){ var p=pos[n.id]; if(!p) return;
    var fill = TYPE_COL[n.type] || "#8a93b5";               // colour = WHAT the entity is (type)
    var ring = n.risk>=70 ? "#ff4d6d" : n.risk>=40 ? "#ffb454" : "rgba(255,255,255,.55)"; // ring = HOW risky
    var ringW = n.risk>=70 ? 3.2 : n.risk>=40 ? 2.6 : 1.8;
    var r = Math.min(17, 7+Math.sqrt(n.count));            // size = HOW MANY events
    var lbl = n.label.length>24 ? n.label.slice(0,24)+"\u2026" : n.label;
    var glow = n.risk>=70 ? '<circle cx="'+p.x+'" cy="'+p.y+'" r="'+(r+5).toFixed(1)+'" fill="#ff4d6d" opacity="0.18"/>' : "";
    parts.push('<g class="eg-node" data-id="'+esc(n.id)+'" style="cursor:pointer">'
      + glow
      + '<circle cx="'+p.x+'" cy="'+p.y+'" r="'+r.toFixed(1)+'" fill="'+fill+'" stroke="'+ring+'" stroke-width="'+ringW+'"><title>'+esc(n.label)+' ('+n.type+') · '+n.count+' events · risk '+n.risk+'</title></circle>'
      + '<text x="'+(p.x+r+5)+'" y="'+(p.y+4)+'" font-size="11" fill="#cfd8f5">'+esc(lbl)+'</text></g>'); });
  svg.innerHTML = parts.join("");
  var nodeById = {}; g.nodes.forEach(function(nn){ nodeById[nn.id]=nn; });
  var adj = {}; g.edges.forEach(function(e){ (adj[e.a]=adj[e.a]||{})[e.b]=e.verb; (adj[e.b]=adj[e.b]||{})[e.a]=e.verb; });
  svg.querySelectorAll(".eg-node").forEach(function(nd){
    nd.onclick = function(ev){ ev.stopPropagation();
      var id = this.getAttribute("data-id");
      var keep = {}; keep[id]=1; Object.keys(adj[id]||{}).forEach(function(k){ keep[k]=1; });
      svg.querySelectorAll(".eg-node").forEach(function(x){ x.style.opacity = keep[x.getAttribute("data-id")]?"1":"0.12"; });
      svg.querySelectorAll(".eg-edge").forEach(function(x){ var a=x.getAttribute("data-a"),b=x.getAttribute("data-b"); var on=(a===id||b===id); x.style.opacity=on?"0.95":"0.04"; x.setAttribute("stroke", on?"#2fe6e0":"#5f6b92"); });
      var node = g.nodes.filter(function(n){ return n.id===id; })[0];
      if(info && node){
        var conns = Object.keys(adj[id]||{}).slice(0,6).map(function(k){ var nb=nodeById[k]; return "<span class='eg-rel'>"+esc(adj[id][k])+"</span> "+esc(nb?nb.label:k); }).join(", ");
        info.innerHTML = "<b>"+esc(node.label)+"</b> <span class='muted'>("+node.type+")</span> — "+node.count+" event(s), risk "+node.risk+". <b>Connections:</b> "+(conns||"none");
      }
    };
  });
  svg.onclick = function(e){ if(e.target===svg||e.target.tagName==="text"){ svg.querySelectorAll(".eg-node").forEach(function(x){ x.style.opacity="1"; }); svg.querySelectorAll(".eg-edge").forEach(function(x){ x.style.opacity="0.28"; x.setAttribute("stroke","#5f6b92"); }); if(info) info.innerHTML="Click any entity to trace its connections across the investigation."; } };
  if(info) info.innerHTML = "Click any entity to trace its connections across the investigation." + (g.truncated ? " <span class='muted'>(showing top 45 entities by risk)</span>" : "");
  if(legend) legend.innerHTML = '<b style="color:#9fb0d8">Colour = type:</b> '
    + '<span class="map-legend-item"><span class="map-legend-dot" style="background:#7c6cff"></span>User</span>'
    + '<span class="map-legend-item"><span class="map-legend-dot" style="background:#2fe6e0"></span>IP</span>'
    + '<span class="map-legend-item"><span class="map-legend-dot" style="background:#35c9a0"></span>Host</span>'
    + '<span class="map-legend-item"><span class="map-legend-dot" style="background:#4f8cff"></span>Domain</span>'
    + '<span class="map-legend-item"><span class="map-legend-dot" style="background:#e0b341"></span>Hash</span>'
    + ' &nbsp;·&nbsp; <b style="color:#9fb0d8">Ring = risk:</b> '
    + '<span class="map-legend-item"><span class="map-legend-dot" style="background:#0d1322;border:2px solid #ff4d6d"></span>High</span>'
    + '<span class="map-legend-item"><span class="map-legend-dot" style="background:#0d1322;border:2px solid #ffb454"></span>Medium</span>'
    + ' &nbsp;·&nbsp; <b style="color:#9fb0d8">Size = event count</b>';
}
function pairVerb(ta, tb, ctx){
  var pair = [ta, tb].sort().join("-");
  if (pair.indexOf("hash") >= 0) return ctx.dump ? "dumped_creds_via" : "executed";
  if (pair === "domain-ip") return "resolved_to";
  if (pair === "host-ip" || pair === "ip-user") return ctx.login ? "logged_in_from" : "connected_to";
  if (pair === "host-user" || pair === "user-user") return ctx.login ? "logged_into" : (ctx.dump ? "dumped_creds_on" : "accessed");
  if (pair.indexOf("domain") >= 0) return ctx.download ? "downloaded_from" : "accessed";
  return "accessed";
}
function buildEvidenceGraph(list) {
  var nodes = {}, edges = {};
  function nid(t,v){ return t+":"+v; }
  function addNode(t,v){ var id=nid(t,v); var n=nodes[id]||(nodes[id]={id:id,type:t,label:v,count:0,risk:0}); n.count++; return id; }
  list.slice(0,4000).forEach(function(e){
    var sev=severityOf(e); var risky = sev==="malicious"?70:sev==="suspicious"?45:10;
    var t=((e.action||"")+" "+rawStr(e)).toLowerCase();
    var ctx = { login:/logon|login|signin|authenticat|\b4624\b|accepted (password|publickey)/.test(t),
      dump:/lsass|mimikatz|sekurlsa|minidump|credential dump/.test(t),
      download:/download|downloadstring|wget|curl|urlcache|invoke-webrequest/.test(t) };
    var ents=[];
    if(e.actor && e.actor!=="unknown" && e.actor!=="-") ents.push(addNode("user",String(e.actor)));
    var io=extractIocs(e);
    io.ips.forEach(function(ip){ ents.push(addNode("ip",ip)); });
    io.domains.forEach(function(d){ ents.push(addNode("domain",d)); });
    io.hashes.forEach(function(h){ ents.push(addNode("hash",h)); });
    var host=e.raw&&(e.raw.host||e.raw.hostname||e.raw.instanceId||e.raw.computer);
    if(host) ents.push(addNode("host",String(host)));
    ents.forEach(function(id){ nodes[id].risk=Math.max(nodes[id].risk,risky); });
    for(var i=0;i<ents.length;i++) for(var j=i+1;j<ents.length;j++){
      if(ents[i]===ents[j]) continue;
      var key = ents[i]<ents[j] ? ents[i]+"|"+ents[j] : ents[j]+"|"+ents[i];
      var verb = pairVerb(ents[i].split(":")[0], ents[j].split(":")[0], ctx);
      var ed = edges[key]||(edges[key]={a:key.split("|")[0], b:key.split("|")[1], weight:0, verbs:{}}); ed.weight++; ed.verbs[verb]=(ed.verbs[verb]||0)+1;
    }
  });
  var allNodes = Object.keys(nodes).map(function(k){ return nodes[k]; }).sort(function(a,b){ return (b.risk-a.risk)||(b.count-a.count); });
  var CAP=45, keep={}; allNodes.slice(0,CAP).forEach(function(n){ keep[n.id]=1; });
  var edgeList = Object.keys(edges).map(function(k){ var e=edges[k]; e.verb=Object.keys(e.verbs).sort(function(x,y){return e.verbs[y]-e.verbs[x];})[0]||"accessed"; return e; }).filter(function(e){ return keep[e.a]&&keep[e.b]; });
  return { nodes: allNodes.filter(function(n){ return keep[n.id]; }), edges: edgeList, truncated: allNodes.length>CAP };
}

/* ---------- Summary ---------- */
function topN(list, keyFn, n) {
  var counts = {};
  list.forEach(function(r){
    var k = keyFn(r);
    if (!k) return;
    counts[k] = (counts[k]||0) + 1;
  });
  return Object.keys(counts).map(function(k){ return {key:k, count:counts[k]}; })
    .sort(function(a,b){ return b.count - a.count; }).slice(0, n);
}

function gotoDetection(ruleId){
  if (typeof switchToTab === "function") switchToTab("detections");
  setTimeout(function(){
    var items = document.querySelectorAll("#detectionsList .detection-item");
    var target = null;
    items.forEach(function(it){ if(!target && (it.textContent||"").indexOf(ruleId) >= 0) target = it; });
    if (target){
      var top = target.querySelector(".detection-top"); if (top && top.click) { try { top.click(); } catch(e){} }  // expand its events
      try { target.scrollIntoView({behavior:"smooth", block:"center"}); } catch(e){}
      target.classList.add("det-flash"); setTimeout(function(){ target.classList.remove("det-flash"); }, 1600);
    } else {
      var host = document.getElementById("detectionsList"); if (host && host.scrollIntoView) try { host.scrollIntoView({behavior:"smooth", block:"start"}); } catch(e){}
    }
  }, 60);
}
if (typeof document !== "undefined" && document.addEventListener) {
  document.addEventListener("click", function(e){
    if (!e.target || !e.target.closest) return;
    var det = e.target.closest("[data-goto-det]");
    if (det && document.getElementById("plainSummary") && document.getElementById("plainSummary").contains(det)) {
      gotoDetection(det.getAttribute("data-goto-det")); return;
    }
    var go = e.target.closest("[data-goto]");
    if (go && document.getElementById("plainSummary") && document.getElementById("plainSummary").contains(go)) {
      if (typeof switchToTab === "function") switchToTab(go.getAttribute("data-goto"));
      if (typeof window !== "undefined" && window.scrollTo) window.scrollTo(0,0);
    }
  });
}
function renderWelcome(){
  var host=document.getElementById("plainSummary"); if(!host) return;
  host.innerHTML=
    "<div class='welcome-card'>"
    + "<div class='welcome-title'>Welcome to CloudLog</div>"
    + "<div class='welcome-sub'>A single-file security log triage tool that runs entirely in your browser \u2014 nothing is sent anywhere.</div>"
    + "<div class='welcome-steps'>"
    +   "<div class='ws'><span class='ws-n'>1</span><div><b>Load a log</b><br>Click <b>Upload log</b> above, or pick a sample source in the sidebar.</div></div>"
    +   "<div class='ws'><span class='ws-n'>2</span><div><b>Read the summary</b><br>You'll get a plain-English verdict: what looks like an attack, and what to do first.</div></div>"
    +   "<div class='ws'><span class='ws-n'>3</span><div><b>Investigate</b><br>Open <b>Investigate</b>, hit \uD83D\uDD0E on an incident, and click any IP or user to follow the trail.</div></div>"
    + "</div>"
    + "<div class='welcome-note'>Supports JSON, CSV, syslog, CEF, Apache, Zeek, AWS GuardDuty, Windows/Sysmon, Splunk/Wazuh/Sentinel. It's a heuristic triage assistant \u2014 it flags common, known attack patterns to help you look faster; it doesn't replace a SIEM.</div>"
    + "</div>";
}
function renderPlainSummary(list, detections){
  var host = document.getElementById("plainSummary"); if (!host) return;
  if (!list || !list.length) { renderWelcome(); return; }
  var mal=0, sus=0, info=0;
  list.forEach(function(r){ var v=severityOf(r); if(v==="malicious")mal++; else if(v==="suspicious")sus++; else info++; });
  var L = mal>0 ? { lvl:"High risk", color:"#ff4d6d", head:"Active threats found — worth acting on now." }
        : sus>0 ? { lvl:"Needs a look", color:"#ffb454", head:"Some suspicious activity to review." }
        : { lvl:"Looks clean", color:"#3ce0a0", head:"Nothing dangerous stood out." };
  // top real findings (skip the generic severity/threat-intel rules; use plain names)
  var agg = {};
  (detections||[]).forEach(function(d){ var k=d.rule.id; if(/^GD-|^TI-/.test(k)) return;
    if(!agg[k]) agg[k]={ id:k, name:d.rule.name, sugg:d.rule.suggestion||"", n:0 };
    agg[k].n += (d.events?d.events.length:1); });
  var top = Object.keys(agg).map(function(k){return agg[k];}).sort(function(a,b){return b.n-a.n;}).slice(0,3);
  var story = "We looked at <b class='ps-link' data-goto='timeline' title='See all events in the Timeline'>"+list.length.toLocaleString()+"</b> event"+(list.length>1?"s":"")+" from <b>"+esc(state.source)+"</b>. "
    + (mal? "<b class='ps-link' data-goto='detections' style='color:#ff8098' title='See the flagged detections'>"+mal.toLocaleString()+"</b> look like real attacks. " : "")
    + (sus? "<b class='ps-link' data-goto='detections' style='color:#ffca7a' title='See the flagged detections'>"+sus.toLocaleString()+"</b> "+(sus>1?"are":"is")+" suspicious and worth a look. " : "")
    + "<b class='ps-link' data-goto='timeline' style='color:#6ff0c2' title='See all events in the Timeline'>"+info.toLocaleString()+"</b> look normal.";
  var findings = top.length
    ? "<div class='plain-h'>Top things we found <span class='muted' style='text-transform:none;font-weight:400'>(click one for detail)</span></div><ul class='plain-list'>"
      + top.map(function(t){ return "<li class='ps-link' data-goto-det='"+esc(t.id)+"'><b>"+esc(t.name)+"</b> — seen "+t.n+" time"+(t.n>1?"s":"")+"."+(t.sugg?" "+esc(t.sugg):"")+"</li>"; }).join("")
      + "</ul>"
    : "";
  var next = mal>0
    ? ["Open the <b>Investigate</b> tab — incidents are ranked by priority (P1 = most urgent).",
       "In the <b>Evidence Graph</b>, the biggest dots with a red ring are the riskiest.",
       "Confirm each real attack in your own systems before you act on it."]
    : sus>0
    ? ["Skim the <b>Detections</b> tab to see what was flagged and why.",
       "Use the <b>Timeline</b> to see the order things happened in.",
       "If something is harmless, thumbs-down the row so it's ignored next time."]
    : ["Nothing urgent — you can still browse the <b>Timeline</b> to see activity.",
       "If you expected attacks, double-check you loaded the right log file."];
  var nextHtml = "<div class='plain-h'>What to do next</div><ul class='plain-list plain-next'>"
    + next.map(function(s){ return "<li>"+s+"</li>"; }).join("") + "</ul>";

  // ---- SOC gap #1: tell the analyst what they CAN'T see (triage on incomplete data) ----
  var n = list.length, cov = { time:0, actor:0, ip:0, host:0 };
  list.forEach(function(r){
    if (r.time && !isNaN(new Date(r.time).getTime())) cov.time++;
    if (r.actor && r.actor!=="unknown" && r.actor!=="-") cov.actor++;
    if (r.ip && r.ip!=="-" && r.ip!=="0.0.0.0") cov.ip++;
    var f=flatOf(r); if (lookupKeys(f,["host","hostname","computer","dest_host","instanceid","device"])!=null) cov.host++;
  });
  var pct = function(x){ return Math.round(100*x/n); };
  var warn = [];
  if (pct(cov.time) < 80) warn.push("only <b>"+pct(cov.time)+"%</b> have a usable timestamp — timeline & time-window correlation are partial");
  if (pct(cov.actor) < 50) warn.push("only <b>"+pct(cov.actor)+"%</b> name a user — identity correlation is limited");
  if (pct(cov.ip) < 50) warn.push("only <b>"+pct(cov.ip)+"%</b> have an IP — network correlation is limited");
  var covHtml = "<div class='plain-h'>What this data can (and can't) tell you</div>"
    + "<div class='plain-cov'>Coverage: <b>"+pct(cov.time)+"%</b> time · <b>"+pct(cov.actor)+"%</b> user · <b>"+pct(cov.ip)+"%</b> IP · <b>"+pct(cov.host)+"%</b> host."
    + (warn.length ? " <span class='plain-warn'>\u26a0 "+warn.join("; ")+". Some events can't be fully correlated — don't read absence of a link as absence of activity.</span>" : " Good coverage across the key fields.")
    + "</div>";

  // ---- SOC gap #2: early kill-chain events get bulk-dismissed. Surface them explicitly. ----
  var earlyRe = /recon|discovery|scan|probe|initial access|credential access|brute|password spray|enumerat/i;
  var earlyDet = {};
  (detections||[]).forEach(function(d){
    var sev = d.rule.sev;
    if ((sev==="medium"||sev==="low"||!sev) && earlyRe.test((d.rule.name||"")+" "+(d.rule.id||"")))
      earlyDet[d.rule.id] = { name:d.rule.name, n:(earlyDet[d.rule.id]?earlyDet[d.rule.id].n:0)+(d.events?d.events.length:1) };
  });
  var earlyList = Object.keys(earlyDet).map(function(k){return earlyDet[k];}).sort(function(a,b){return b.n-a.n;}).slice(0,4);
  var earlyHtml = earlyList.length
    ? "<div class='plain-h'>\u26a0 Early-stage activity — don't dismiss these</div><div class='plain-early'>These are low/medium severity, but recon, scanning and credential-testing are <b>how intrusions begin</b>. Bulk-closing them is the most common way SOCs miss a breach:<ul class='plain-list'>"
      + earlyList.map(function(t){ return "<li><b>"+esc(t.name)+"</b> \u2014 "+t.n+" event"+(t.n>1?"s":"")+"</li>"; }).join("") + "</ul></div>"
    : "";

  host.innerHTML = "<div class='plain-card'>"
    + "<div class='plain-verdict'><span class='plain-dot' style='color:"+L.color+";background:"+L.color+"'></span>"
    + "<span class='plain-level' style='color:"+L.color+"'>"+L.lvl+"</span></div>"
    + "<div class='plain-headline'>"+L.head+"</div>"
    + "<div class='plain-story'>"+story+"</div>" + findings + earlyHtml + nextHtml + covHtml + "</div>";
}
function renderSummary(list, detections) {
  var el = document.getElementById("summaryContent");
  if (!list.length) {
    el.innerHTML = '<p class="empty-note">No log loaded yet. Upload a file or pick a sample source from the sidebar.</p>';
    return;
  }

  var times = list.map(function(r){ return new Date(r.time).getTime(); }).filter(function(t){ return !isNaN(t); });
  var earliest = times.length ? formatTime(new Date(arrMin(times)).toISOString()) : "-";
  var latest = times.length ? formatTime(new Date(arrMax(times)).toISOString()) : "-";

  var actorsTop = topN(list, function(r){ return r.actor; }, 5);
  var actionsTop = topN(list, function(r){ return r.action; }, 5);
  var ipsTop = topN(list, function(r){ return r.ip; }, 5);

  var highCount = 0, medCount = 0, lowCount = 0;
  detections.forEach(function(d){
    if (d.rule.sev === "high") highCount += d.events.length;
    else if (d.rule.sev === "medium") medCount += d.events.length;
    else lowCount += d.events.length;
  });

  var overviewRows = [
    ["Source", state.source],
    ["Total events", list.length.toLocaleString()],
    ["Unique actors", Object.keys(list.reduce(function(a,r){a[r.actor]=1;return a;},{})).length],
    ["Unique IPs", Object.keys(list.reduce(function(a,r){a[r.ip]=1;return a;},{})).length],
    ["Earliest event", earliest],
    ["Latest event", latest],
    ["Detections found", detections.length]
  ].map(function(row){
    return '<div class="summary-row"><span>'+row[0]+'</span><span>'+row[1]+'</span></div>';
  }).join("");

  var sevRows = ''
    + '<div class="summary-row"><span>High severity events</span><span class="summary-badge high">'+highCount+'</span></div>'
    + '<div class="summary-row"><span>Medium severity events</span><span class="summary-badge medium">'+medCount+'</span></div>'
    + '<div class="summary-row"><span>Low severity events</span><span class="summary-badge low">'+lowCount+'</span></div>';

  var actorList = actorsTop.length
    ? actorsTop.map(function(a){ return '<li><span>'+a.key+'</span><span>'+a.count+'</span></li>'; }).join("")
    : '<li><span>No actor data</span></li>';
  var actionList = actionsTop.length
    ? actionsTop.map(function(a){ return '<li><span>'+a.key+'</span><span>'+a.count+'</span></li>'; }).join("")
    : '<li><span>No action data</span></li>';
  var ipList = ipsTop.length
    ? ipsTop.map(function(a){ return '<li><span>'+a.key+'</span><span>'+a.count+'</span></li>'; }).join("")
    : '<li><span>No IP data</span></li>';

  var topDetections = detections.slice().sort(function(a,b){
    var order = {high:0, medium:1, low:2};
    return order[a.rule.sev] - order[b.rule.sev];
  }).slice(0, 5).map(function(d){
    return '<li style="cursor:pointer;" class="summary-jump-detection"><span>'+d.rule.title+'</span><span class="summary-badge '+d.rule.sev+'">'+d.rule.sev.toUpperCase()+' &middot; '+d.events.length+'</span></li>';
  }).join("") || '<li><span>No suspicious patterns detected</span></li>';

  var stages = {};
  list.forEach(function(r){ var k = classifyStage(r); stages[k] = (stages[k]||0) + 1; });
  var stageRows = Object.keys(stages).sort(function(a,b){ return stages[b]-stages[a]; }).map(function(k){ return '<div class="summary-row"><span>'+k+'</span><span>'+stages[k]+'</span></div>'; }).join("");

  el.innerHTML =
    '<div class="summary-grid">'
    + '<div class="summary-block"><h3>Overview</h3>' + overviewRows + '</div>'
    + '<div class="summary-block"><h3>Detection Severity Breakdown</h3>' + sevRows + '</div>'
    + '<div class="summary-block"><h3>Top Actors</h3><ul class="summary-list">' + actorList + '</ul></div>'
    + '<div class="summary-block"><h3>Top Actions</h3><ul class="summary-list">' + actionList + '</ul></div>'
    + '<div class="summary-block"><h3>Top Source IPs</h3><ul class="summary-list">' + ipList + '</ul></div>'
    + '<div class="summary-block"><h3>Top Detections (click to inspect)</h3><ul class="summary-list">' + topDetections + '</ul></div>'
    + '<div class="summary-block"><h3>Stage Breakdown</h3>' + stageRows + '</div>'
    + '<div class="summary-block"><h3>Event Classification</h3><div class="summary-row"><span>Malicious</span><span>' + list.filter(function(r){ return severityOf(r)==="malicious"; }).length + '</span></div><div class="summary-row"><span>Suspicious</span><span>' + list.filter(function(r){ return severityOf(r)==="suspicious"; }).length + '</span></div><div class="summary-row"><span>Informational</span><span>' + list.filter(function(r){ return severityOf(r)==="info"; }).length + '</span></div></div>'
    + '</div>';

  el.querySelectorAll(".summary-jump-detection").forEach(function(li){
    li.onclick = function(){ switchToTab("detections"); };
  });
}

/* ---------- Tab switching ---------- */
// ---- click-to-pivot: click any IP/user anywhere -> filter to its events with a clear chip ----





