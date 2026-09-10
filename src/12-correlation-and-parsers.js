/* ============================================================
 * CloudLog — 12-correlation-and-parsers.js
 * Incident correlation (union-find) + text parsers (syslog/CEF/kv/pcap).
 * Part of index.html; assembled by build.js. Do not add a <script> wrapper.
 * ============================================================ */
function correlateChains(events, windowMs) {
  windowMs = windowMs || 24 * 3600 * 1000;
  var nodes = events.map(function (ev, i) {
    var ioc = extractIocs(ev);
    var t = new Date(ev.time).getTime();
    return { i: i, ev: ev, t: isNaN(t) ? null : t,
      keys: buildLinkKeys(ev, ioc), ioc: ioc };
  });
  // union-find
  var parent = nodes.map(function (_, i) { return i; });
  function find(x) { while (parent[x] !== x) { parent[x] = parent[parent[x]]; x = parent[x]; } return x; }
  function union(a, b) { parent[find(a)] = find(b); }
  // index by key -> list of node indices
  var idx = {};
  nodes.forEach(function (n) { n.keys.forEach(function (k) { (idx[k] = idx[k] || []).push(n.i); }); });
  // distinct source identity (source IP, else actor) per key — used to detect "hub" indicators
  var keySrc = {};
  nodes.forEach(function (n) {
    var src = (n.ev.ip && n.ev.ip !== "-" && n.ev.ip !== "0.0.0.0") ? n.ev.ip : n.ev.actor;
    n.keys.forEach(function (k) { (keySrc[k] = keySrc[k] || new Set()).add(src || "?"); });
  });
  // an indicator shared by a huge fraction of events is NOT a pivot (e.g. google.com,
  // a NAT egress IP). Only correlate on indicators rare enough to be meaningful, and
  // link time-adjacent members within the window (O(n), not O(n^2) all-pairs).
  // Strong, specific pivots (public IP, file hash) can legitimately be shared by an
  // entire single-source attack, so give them a high cap. Domains/actors keep a tighter
  // cap since they're more likely to be shared infrastructure/NAT.
  Object.keys(idx).forEach(function (k) {
    var list = idx[k];
    var isSourceKey = k.indexOf("ip:") === 0 || k.indexOf("actor:") === 0 || k.indexOf("pguid:") === 0 || k.indexOf("logon:") === 0 || k.indexOf("sess:") === 0;
    // A destination indicator (domain / hash / url) shared across many DISTINCT sources is
    // shared infrastructure (a popular malicious referrer, CDN, common malware host) — merging
    // on it lumps unrelated attackers into one giant incident. Only source-based keys, or
    // destination keys touched by a handful of sources, are valid single-incident pivots.
    var srcCount = 0; var _ss = keySrc[k]; if (_ss) _ss.forEach(function (s) { if (s && s !== "?" && s !== "unknown") srcCount++; });
    if (!isSourceKey && srcCount > 6) return;
    var strong = k.indexOf("ip:") === 0 || k.indexOf("hash:") === 0 || k.indexOf("pguid:") === 0 || k.indexOf("logon:") === 0 || k.indexOf("sess:") === 0;
    var cap = strong ? Math.max(200, Math.floor(nodes.length * 0.9)) : Math.max(15, Math.floor(nodes.length * 0.15));
    if (list.length < 2 || list.length > cap) return;              // too rare or too common
    var withT = list.slice().sort(function (a, b) { return (nodes[a].t || 0) - (nodes[b].t || 0); });
    for (var a = 1; a < withT.length; a++) {
      var na = nodes[withT[a - 1]], nb = nodes[withT[a]];
      // Deterministic lineage keys (process GUID, logon ID, session ID) identify the SAME
      // process/session with certainty — so they link regardless of the time gap. This defeats
      // "low and slow" evasion: an attacker who idles 26h inside one session stays one incident.
      // Weaker keys (shared public IP / actor via NAT) keep the sliding-window guard to avoid
      // merging unrelated activity that merely shares an address.
      var lineage = k.indexOf("pguid:") === 0 || k.indexOf("logon:") === 0 || k.indexOf("sess:") === 0;
      if (lineage || na.t === null || nb.t === null || Math.abs(na.t - nb.t) <= windowMs) union(withT[a - 1], withT[a]);
    }
  });
  // gather components
  var groups = {};
  nodes.forEach(function (n) { var r = find(n.i); (groups[r] = groups[r] || []).push(n); });
  var chains = Object.keys(groups).map(function (r) {
    var g = groups[r].sort(function (a, b) { return (a.t || 0) - (b.t || 0); });
    var ips = {}, actors = {}, hashes = {}, domains = {}, stages = {}, risk = 0;
    g.forEach(function (n) {
      n.ioc.ips.forEach(function (x) { if (classifyIp(x) === "public") ips[x] = 1; });
      if (n.ev.actor && n.ev.actor !== "unknown" && n.ev.actor !== "-") actors[n.ev.actor] = 1;
      n.ioc.hashes.forEach(function (x) { hashes[x] = 1; });
      n.ioc.domains.forEach(function (x) { domains[x] = 1; });
      if (typeof classifyStage === "function") stages[classifyStage(n.ev)] = 1;
      if (typeof buildXdrScore === "function") risk = Math.max(risk, buildXdrScore(n.ev));
    });
    return {
      size: g.length, events: g.map(function (n) { return n.ev; }),
      ips: Object.keys(ips), actors: Object.keys(actors), hashes: Object.keys(hashes), domains: Object.keys(domains),
      stages: sortStagesCanonical(Object.keys(stages).filter(function (s) { return s !== "Other"; })),
      risk: risk,
      start: g[0].t ? new Date(g[0].t).toISOString() : null,
      end: g[g.length - 1].t ? new Date(g[g.length - 1].t).toISOString() : null,
      linkedBy: (Object.keys(ips).length === 1 ? "public IP " + Object.keys(ips)[0]
        : Object.keys(actors).length === 1 ? "actor " + Object.keys(actors)[0]
        : Object.keys(hashes).length === 1 ? "file hash " + Object.keys(hashes)[0].slice(0,12) + "\u2026"
        : Object.keys(domains).length === 1 ? "domain " + Object.keys(domains)[0]
        : Object.keys(ips)[0] ? "public IP " + Object.keys(ips)[0]
        : Object.keys(actors)[0] ? "actor " + Object.keys(actors)[0]
        : "shared indicator")
    };
  });
  // biggest / riskiest first; drop singletons with no IOCs from "chains" view
  return chains.filter(function (c) {
      var hasMal = c.events.some(function (e) { return severityOf(e) === "malicious"; });
      return c.size > 1 || c.ips.length || c.hashes.length || hasMal;   // keep standalone malicious events as incidents too
    }).sort(function (a, b) { return (b.risk + b.size * 10) - (a.risk + a.size * 10); });
}
var BENIGN_DOMAIN = /(^|\.)(google|gstatic|googleapis|microsoft|windows|office|live|apple|icloud|amazonaws|cloudfront|akamai|cloudflare|azure|fastly|mozilla|ubuntu|debian|github|gvt1|doubleclick)\.[a-z.]+$/i;
function buildLinkKeys(ev, ioc) {
  var keys = [];
  if (ev.actor && ev.actor !== "unknown" && ev.actor !== "-" && classifyIp(ev.actor) !== "public") keys.push("actor:" + ev.actor);
  ioc.ips.forEach(function (ip) { if (classifyIp(ip) === "public") keys.push("ip:" + ip); });
  ioc.hashes.forEach(function (h) { keys.push("hash:" + h); });
  ioc.domains.forEach(function (d) { if (!BENIGN_DOMAIN.test(d) && !/\.(local|lan|internal|corp|arpa)$/i.test(d)) keys.push("dom:" + d); });
  // --- lineage: system-generated IDs are deterministic pivots (proving, not guessing) ---
  // A child's ParentProcessGuid equals its parent's ProcessGuid, so emitting both under one
  // "pguid:" namespace links parent→child deterministically via union-find.
  var f = flatOf(ev);
  var pg  = lookupKeys(f, ["processGuid","process_guid","processguid","procguid"]);
  var ppg = lookupKeys(f, ["parentProcessGuid","parent_process_guid","parentprocessguid","parentguid"]);
  var lg  = lookupKeys(f, ["logonId","logon_id","targetLogonId","target_logon_id","subjectLogonId","logonguid","logon_guid"]);
  var sid = lookupKeys(f, ["sessionId","session_id","sessionguid"]);
  if (pg)  keys.push("pguid:" + pg);
  if (ppg) keys.push("pguid:" + ppg);
  // A logon ID (LUID) is only unique WITHIN one machine, and well-known system LUIDs (0x3e7 SYSTEM,
  // 0x3e4/0x3e5 service accounts) are IDENTICAL on every Windows host. Namespacing by host and
  // dropping the well-known LUIDs stops unrelated machines merging into one giant incident.
  var host = lookupKeys(f, ["computer_name","computername","computer","host","hostname","dvc","dvchost","machinename"]) || "";
  var hostPfx = host ? (String(host).toLowerCase().trim() + "/") : "";
  var WELL_KNOWN_LUIDS = { "0x3e7":1,"0x3e4":1,"0x3e5":1,"0x3e6":1,"0x0":1,"0":1,"999":1,"998":1,"997":1,"996":1 };
  if (lg) { var cleanLg = String(lg).toLowerCase().trim(); if (!WELL_KNOWN_LUIDS[cleanLg]) keys.push("logon:" + hostPfx + cleanLg); }
  if (sid && String(sid) !== "0") keys.push("sess:" + (hostPfx + String(sid)));
  return keys;
}

/* ---------- aggregate all IOCs across a dataset (for the Investigate table) ---------- */
function aggregateIocs(events) {
  var bag = {}; // key "type|value" -> {type,value,count,first,last}
  events.forEach(function (ev) {
    var ioc = extractIocs(ev), t = new Date(ev.time).getTime();
    var push = function (type, value) {
      var k = type + "|" + value, b = bag[k] || (bag[k] = { type: type, value: value, count: 0, first: null, last: null });
      b.count++; if (!isNaN(t)) { if (b.first === null || t < b.first) b.first = t; if (b.last === null || t > b.last) b.last = t; }
    };
    ioc.ips.forEach(function (v) { push("ip", v); });
    ioc.domains.forEach(function (v) { push("domain", v); });
    ioc.urls.forEach(function (v) { push("url", v); });
    ioc.hashes.forEach(function (v) { push("hash", v); });
    ioc.emails.forEach(function (v) { push("email", v); });
  });
  return Object.keys(bag).map(function (k) { return bag[k]; }).sort(function (a, b) { return b.count - a.count; });
}

/*x*/if (false && typeof module !== "undefined") module.exports = { classifyIp, hashType, extractIocs, safeToEnrich, enrichmentLinks, correlateChains, aggregateIocs, isInternalHost };

/* ==== ANY-LOG PARSER ==== */
/* ============================================================================
   parseAnyLog(raw, source) -> [{time,actor,action,ip,source,urls,cmds,emails,
   hashes,domains,raw}]  Handles JSON + non-JSON text so DNS/VPN/SSH/HTTPS/
   syslog/firewall logs upload directly. Falls back to line parsing when the
   file is not a single JSON document.
   ========================================================================== */
function pcap_ip4(dv,o){ return dv.getUint8(o)+"."+dv.getUint8(o+1)+"."+dv.getUint8(o+2)+"."+dv.getUint8(o+3); }
function pcap_dns(dv,o,end){ try{ var p=o+12,name=[],g=0; while(p<end&&g++<64){ var len=dv.getUint8(p); if(len===0)break; if((len&0xc0)===0xc0)break; var x=""; for(var i=0;i<len&&p+1+i<end;i++) x+=String.fromCharCode(dv.getUint8(p+1+i)); name.push(x); p+=len+1; } return name.join("."); }catch(e){ return null; } }
function pcap_ascii(dv,o,end){ var x=""; for(var i=o;i<end&&i<o+900;i++){ var c=dv.getUint8(i); x+=(c>=9&&c<127)?String.fromCharCode(c):"."; } return x; }
function pcap_http(dv,o,end){ try{ var x=pcap_ascii(dv,o,end); var m=x.match(/^(GET|POST|PUT|HEAD|DELETE|OPTIONS)\s+(\S+)\s+HTTP/); if(!m)return null; var host=(x.match(/Host:\s*([^\r\n]+)/i)||[])[1]||""; var ua=(x.match(/User-Agent:\s*([^\r\n]+)/i)||[])[1]||""; return {method:m[1],path:m[2],host:host.trim(),ua:ua.trim()}; }catch(e){ return null; } }
function pcap_tcpHdr(dv,o){ return ((dv.getUint8(o+12)>>4)&0x0f)*4; }
function isRareTld(d){ return /\.(top|xyz|tk|gq|ml|cf|ga|work|click|country|kim|loan|men|zip|mov)$/i.test(String(d||"")); }
function looksDGA(d){ var labels=String(d||"").split("."); for(var i=0;i<labels.length-1;i++){ var l=labels[i].toLowerCase(); if(l.length>=10){ var digits=(l.match(/[0-9]/g)||[]).length, vowels=(l.match(/[aeiou]/g)||[]).length; if(digits>=2 || vowels/l.length<0.25) return true; } } return false; }
// Parse a classic libpcap capture (ArrayBuffer) into normalized events.
function parsePcap(ab){
  var dv=new DataView(ab); if(ab.byteLength<24) return {events:[],err:"file too small to be a pcap"};
  var magic=dv.getUint32(0,false), le, nano=false;
  if(magic===0xa1b2c3d4) le=false; else if(magic===0xd4c3b2a1) le=true;
  else if(magic===0xa1b23c4d){le=false;nano=true;} else if(magic===0x4d3cb2a1){le=true;nano=true;}
  else if(magic===0x0a0d0d0a) return {events:[],err:"This is a pcapng file — CloudLog currently reads classic .pcap. Re-save as pcap (Wireshark: File \u2192 Export Specified Packets \u2192 .pcap)."};
  else return {events:[],err:"Not a recognizable pcap file (bad magic number)."};
  var off=24, events=[], guard=0;
  while(off+16<=ab.byteLength && guard++<200000){
    var tsSec=dv.getUint32(off,le), tsFrac=dv.getUint32(off+4,le), inclLen=dv.getUint32(off+8,le); off+=16;
    if(inclLen<=0||off+inclLen>ab.byteLength) break;
    var ps=off;
    try{
      var ethType=dv.getUint16(ps+12,false), ipOff=ps+14;
      if(ethType===0x8100){ ipOff=ps+18; ethType=dv.getUint16(ps+16,false); }
      if(ethType===0x0800){
        var ihl=(dv.getUint8(ipOff)&0x0f)*4, proto=dv.getUint8(ipOff+9);
        var src=pcap_ip4(dv,ipOff+12), dst=pcap_ip4(dv,ipOff+16), l4=ipOff+ihl;
        var sport=null,dport=null,extra={},action;
        var pn=proto===6?"TCP":proto===17?"UDP":proto===1?"ICMP":("proto"+proto);
        if(proto===6||proto===17){ sport=dv.getUint16(l4,false); dport=dv.getUint16(l4+2,false); }
        if(proto===17&&(sport===53||dport===53)){ var q=pcap_dns(dv,l4+8,ps+inclLen); action="DNS query "+(q||"?"); extra.dns=q; }
        else if(proto===6&&(dport===80||sport===80)){ var h=pcap_http(dv,l4+pcap_tcpHdr(dv,l4),ps+inclLen); if(h){ action=h.method+" "+h.host+h.path; extra.host=h.host; extra.ua=h.ua; } else action=pn+" "+src+":"+sport+" \u2192 "+dst+":"+dport; }
        else action=pn+" "+src+":"+sport+" \u2192 "+dst+":"+dport;
        var secs=nano?(tsSec+tsFrac/1e9):(tsSec+tsFrac/1e6);
        events.push({time:new Date(secs*1000).toISOString(),actor:src,ip:dst,action:action,source:"PCAP",raw:Object.assign({src_ip:src,dst_ip:dst,src_port:sport,dst_port:dport,proto:pn,bytes:inclLen},extra)});
      }
    }catch(e){}
    off=ps+inclLen;
  }
  return {events:events};
}
function b64ToArrayBuffer(b64){ var bin=atob(b64), len=bin.length, bytes=new Uint8Array(len); for(var i=0;i<len;i++) bytes[i]=bin.charCodeAt(i); return bytes.buffer; }

function parseAnyLog(raw, source) {
  // 1) JSON document or JSON array -> existing normalize()
  try { var j = JSON.parse(raw); return normalize(j, source); } catch (e) {}
  // 2) NDJSON / JSONL
  var lines = raw.split(/\r?\n/).filter(function (l) { return l.trim(); });
  if (lines.length && lines[0].trim()[0] === "{") {
    var objs = [], allJson = true;
    for (var i = 0; i < lines.length; i++) { try { objs.push(JSON.parse(lines[i])); } catch (e) { allJson = false; break; } }
    if (allJson && objs.length) return normalize(objs, source);
  }
  // 3) CSV / TSV with a header row -> objects -> normalize()
  if (looksLikeDelimited(raw)) {
    var objs2 = parseDelimited(raw);
    if (objs2.length) return normalize(objs2, source);
  }
  // 4) line-oriented text formats
  return lines.map(function (l) { return parseLogLine(l, source); }).filter(Boolean);
}
function looksLikeDelimited(raw){
  var first = (raw.split(/\r?\n/)[0] || "");
  var delim = first.indexOf(",")>=0 ? "," : (first.indexOf("\t")>=0 ? "\t" : null);
  if (!delim) return false;
  var cells = first.split(delim);
  if (cells.length < 3) return false;
  var headerish = cells.filter(function(c){ return /^[a-z0-9_.\- ]+$/i.test(c.trim()) && c.trim().length>0; }).length;
  return headerish >= cells.length * 0.6;   // header row is mostly plain column names
}
function parseDelimited(raw){
  var text = raw.replace(/\r\n/g,"\n").replace(/\r/g,"\n");
  var delim = (text.split("\n")[0].indexOf("\t")>=0 && text.split("\n")[0].indexOf(",")<0) ? "\t" : ",";
  var rows=[], row=[], cur="", inq=false;
  for (var i=0;i<text.length;i++){ var c=text[i];
    if (inq){ if(c==='"'){ if(text[i+1]==='"'){cur+='"';i++;} else inq=false; } else cur+=c; }
    else { if(c==='"') inq=true; else if(c===delim){ row.push(cur); cur=""; } else if(c==="\n"){ row.push(cur); rows.push(row); row=[]; cur=""; } else cur+=c; }
  }
  if (cur!=="" || row.length){ row.push(cur); rows.push(row); }
  if (rows.length < 2) return [];
  var hdr = rows[0].map(function(h){ return h.trim(); });
  var out=[];
  for (var r=1;r<rows.length;r++){
    if (rows[r].length===1 && rows[r][0]==="") continue;
    var o={}, has=false;
    for (var c2=0;c2<hdr.length;c2++){ var v=rows[r][c2]; if (v!==undefined){ v=v.trim(); if(v!==""){ o[hdr[c2]]=v; has=true; } } }
    if (has) out.push(o);
  }
  return out;
}

function parseLogLine(line, source) {
  var ev;
  if (/^CEF:\d/.test(line)) ev = fromCef(line);
  else if (/^\S+ \S+ \S+ \[.+\] "/.test(line)) ev = fromClf(line);
  else if (/(^|\s)\w+=("[^"]*"|\S+)/.test(line) && line.split("=").length > 2 && !/:\s/.test(line.slice(0, 20))) ev = fromKv(line);
  else ev = fromSyslog(line);
  ev.source = source || detectTextSource(line, ev);
  return decorate(ev, line);
}

/* enrich the event with extracted indicators + guessed action semantics */
function decorate(ev, line) {
  ev.raw = ev.raw || { message: line };
  ev.urls = ev.urls || (line.match(/https?:\/\/[^\s"'<>)]+/gi) || []);
  ev.emails = ev.emails || (line.match(/\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi) || []).map(function (s) { return s.toLowerCase(); });
  ev.hashes = ev.hashes || (line.match(/\b[A-Fa-f0-9]{64}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{32}\b/g) || []);
  ev.cmds = ev.cmds || [];
  ev.domains = ev.domains || [];
  if (!ev.ip || ev.ip === "-") {
    var pm = line.match(/(?:\bfrom|rhost=|\bsrc=|client)\s*=?\s*((?:\d{1,3}\.){3}\d{1,3})/i);
    if (pm) ev.ip = pm[1];
    else { var m = line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/); ev.ip = m ? m[0] : "-"; }
  }
  if (!ev.actor || /^(unknown|user|for|from|invalid|illegal|\-)$/i.test(ev.actor)) {
    // allow domain-qualified (CORP\user) and UPN (user@domain) names, not just the bare account
    var um = line.match(/\bfor (?:invalid user |illegal user )?([a-zA-Z0-9][a-zA-Z0-9_.\-@\\]{1,45}) from\b/i)
          || line.match(/\bsession (?:opened|closed) for user ([a-zA-Z0-9][a-zA-Z0-9_.\-@\\]{1,45})/i)
          || line.match(/\buser[= ]([a-zA-Z0-9][a-zA-Z0-9_.\-@\\]{1,45})\b/i)
          || line.match(/\bruser=([a-zA-Z0-9][a-zA-Z0-9_.\-@\\]{1,45})\b/);
    if (um && um[1] && !/^(unknown|from|for)$/i.test(um[1])) ev.actor = um[1];
  }
  if (!ev.actor) ev.actor = "unknown";
  if (!ev.action) ev.action = line.slice(0, 80);
  if (!ev.time) ev.time = deepFindDate(line) || "";
  return ev;
}

function detectTextSource(line, ev) {
  if (/sshd|ssh2|Failed password|Accepted password/i.test(line)) return "SSH";
  if (/openvpn|wireguard|anyconnect|vpn|tunnel established|peer connection/i.test(line)) return "VPN";
  if (/named\[|query:|dnsmasq|resolver|IN A |IN AAAA |NXDOMAIN/i.test(line)) return "DNS";
  if (/CEF:|deny|accept|firewall|%ASA-/i.test(line)) return "Firewall";
  if (/GET |POST |HTTP\/1|nginx|apache/i.test(line)) return "Web";
  return "Syslog";
}

/* ---- format parsers (compact) ---- */
function fromSyslog(line) {
  var o = { raw: { message: line } }, l = line, m;
  var pri = /^<(\d{1,3})>/.exec(l); if (pri) l = l.slice(pri[0].length);
  if ((m = /^(\w{3}\s+\d+\s\d\d:\d\d:\d\d)\s(\S+)\s([^:\[]+)(?:\[(\d+)\])?:?\s?(.*)$/.exec(l))) {
    o.time = isoFromBsd(m[1]); o.raw = { host: m[2], app: m[3], message: m[5] }; l = m[5]; o.app = m[3];
  } else if ((m = /^(\d{4}-\d\d-\d\dT[\d:.\-+Z]+)\s(\S+)\s(\S+?):?\s(.*)$/.exec(l))) {
    o.time = m[1]; o.raw = { host: m[2], app: m[3], message: m[4] }; l = m[4]; o.app = m[3];
  } else { o.raw = { message: l }; }
  // SSH / VPN / DNS semantics from the message body
  var um = /invalid user (\S+)/i.exec(l) || /user=(\S+)/i.exec(l) || /(?:for|user|by)\s+(\S+?)(?:\s+from|\s|$)/i.exec(l);
  if (um) o.actor = um[1];
  // source IP: prefer explicit from/rhost/src/client markers over a bare first IP
  var ipm = /(?:\bfrom|rhost=|\bsrc=|\bsrc\b|client)\s*=?\s*((?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]{2,}:[0-9A-Fa-f:]*[0-9A-Fa-f])/i.exec(l);
  if (ipm) { var _sc = ipm[1].replace(/[.:]+$/, ""); var _scl = classifyIp(_sc); if (_scl !== "invalid" && _scl !== "n/a") o.ip = _sc; }
  var dm = /query:\s+(\S+)|resolving\s+'?([a-z0-9.-]+\.[a-z]{2,})/i.exec(l); if (dm) { o.domains = [(dm[1] || dm[2]).toLowerCase()]; }
  o.action = ((o.app ? o.app + ": " : "") + l).slice(0, 240);
  return o;
}
function fromClf(line) {
  var m = /^(\S+) \S+ (\S+) \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?/.exec(line);
  if (!m) return { raw: { message: line } };
  var req = (m[4] || "").split(" ");
  return { time: isoFromClf(m[3]), actor: m[2] === "-" ? "" : m[2], ip: m[1], action: (req[0] || "") + " " + (req[1] || ""),
    raw: { method: req[0], path: req[1], status: +m[5], ua: m[8] || "", ref: m[7] || "" } };
}
function fromCef(line) {
  var body = line.slice(4), parts = body.split("|");
  var o = { raw: { message: line, vendor: parts[1], product: parts[2], name: parts[5], severity: parts[6] } };
  var ext = parts.slice(7).join("|"), re = /(\w+)=((?:[^=]|=(?!\S+=))*?)(?=\s\w+=|$)/g, m, kv = {};
  while ((m = re.exec(ext))) kv[m[1]] = m[2].trim();
  o.ip = kv.src || kv.dvc || "-"; o.actor = kv.suser || kv.duser || ""; o.action = (parts[1] || "") + " " + (parts[5] || "");
  if (kv.rt && /^\d+$/.test(kv.rt)) o.time = new Date(+kv.rt).toISOString();
  o.raw.fields = kv; return o;
}
function fromKv(line) {
  var o = { raw: { message: line } }, re = /(\w[\w.]*)=("([^"]*)"|\S+)/g, m, kv = {};
  while ((m = re.exec(line))) kv[m[1]] = m[3] !== undefined ? m[3] : m[2];
  o.time = kv.ts || kv.time || kv.timestamp || ""; o.actor = kv.user || kv.actor || kv.username || "";
  o.ip = kv.ip || kv.src || kv.src_ip || kv.clientip || "-"; o.action = kv.action || kv.msg || kv.event || line.slice(0, 80);
  o.raw = kv; return o;
}
function isoFromBsd(s) { var M = { Jan:0,Feb:1,Mar:2,Apr:3,May:4,Jun:5,Jul:6,Aug:7,Sep:8,Oct:9,Nov:10,Dec:11 };
  var m = /^(\w{3})\s+(\d+)\s(\d\d):(\d\d):(\d\d)/.exec(s); if (!m || M[m[1]] === undefined) return "";
  var d = new Date(Date.UTC(new Date().getUTCFullYear(), M[m[1]], +m[2], +m[3], +m[4], +m[5])); return isNaN(d) ? "" : d.toISOString(); }
function isoFromClf(s) { var M = { Jan:0,Feb:1,Mar:2,Apr:3,May:4,Jun:5,Jul:6,Aug:7,Sep:8,Oct:9,Nov:10,Dec:11 };
  var m = /^(\d{2})\/(\w{3})\/(\d{4}):(\d\d):(\d\d):(\d\d)/.exec(s); if (!m) return "";
  var d = new Date(Date.UTC(+m[3], M[m[2]], +m[1], +m[4], +m[5], +m[6])); return isNaN(d) ? "" : d.toISOString(); }

/*x*/if (false && typeof module !== "undefined") module.exports = { parseAnyLog: null, parseLogLine, fromSyslog, fromClf, fromCef, fromKv };

/* ==== INVESTIGATE UI ==== */
/* ============================================================================
   INVESTIGATE UI  — IOC table, auto attack-chain correlation, enrichment.
   Live enrichment goes through the local proxy if it is running; otherwise it
   falls back to one-click deep links (no keys, nothing sent by the tool).
   ========================================================================== */
var PROXY = { url: "http://localhost:8787", ok: false, services: [] };

function checkProxy() {
  var ctrl = new AbortController(); var t = setTimeout(function () { ctrl.abort(); }, 1200);
  fetch(PROXY.url + "/health", { signal: ctrl.signal })
    .then(function (r) { return r.json(); })
    .then(function (j) { PROXY.ok = !!j.ok; PROXY.services = j.services || []; paintProxyStatus(); })
    .catch(function () { PROXY.ok = false; paintProxyStatus(); })
    .finally(function () { clearTimeout(t); });
}
function paintProxyStatus() {
  var el = document.getElementById("proxyStatus"); if (!el) return;
  if (PROXY.ok) el.innerHTML = '<span style="color:#166534;">● Local threat-proxy connected</span> — live enrichment via: <b>' + (PROXY.services.join(", ") || "no keys set") + '</b>';
  else el.innerHTML = '<span style="color:#8a8fa3;">○ No local proxy</span> — <b>in-browser mode</b>: Geo/ASN works with no key; add keys above for the rest (VirusTotal/AbuseIPDB/OTX/Shodan/GreyNoise are usually CORS-blocked in-browser, so run <code>node threat-proxy.js</code> for those). Deep links always available.';
}

function iocIcon(type) { return { ip: "🌐", domain: "🔗", url: "🌍", hash: "#️⃣", email: "✉" }[type] || "•"; }

// ---- Decision support: turn a correlated incident into ONE actionable card ----
function computeBaselines(list){
  var per={}; // actor -> {hours:{}, ips:{}, count}
  list.forEach(function(e){
    var a=e.actor; if(!a||a==="unknown"||a==="-") return;
    var o=per[a]||(per[a]={hours:{},ips:{},count:0}); o.count++;
    var t=new Date(e.time); if(!isNaN(t)){ var h=t.getUTCHours(); o.hours[h]=(o.hours[h]||0)+1; }
    (extractIocs(e).ips).forEach(function(ip){ o.ips[ip]=(o.ips[ip]||0)+1; });
    if(e.ip) o.ips[e.ip]=(o.ips[e.ip]||0)+1;
  });
  return per;
}
function baselineReport(list){
  var per=computeBaselines(list), out=[];
  Object.keys(per).forEach(function(a){
    var o=per[a]; if(o.count<5) return;                 // need enough events to be meaningful
    var hrs=Object.keys(o.hours).map(Number).sort(function(x,y){return o.hours[y]-o.hours[x];});
    var ips=Object.keys(o.ips).sort(function(x,y){return o.ips[y]-o.ips[x];});
    var topHours=hrs.slice(0,3), commonIps=ips.slice(0,3);
    // deviations: hours/ips seen only rarely (<10% of activity)
    var devs=[];
    hrs.forEach(function(h){ if(o.hours[h]/o.count < 0.06 && topHours.indexOf(h)<0) devs.push("activity at "+String(h).padStart(2,"0")+":00 UTC (unusual for this user)"); });
    ips.forEach(function(ip){ if(o.ips[ip]/o.count < 0.06 && commonIps.indexOf(ip)<0) devs.push("new/rare source IP "+ip); });
    out.push({ actor:a, count:o.count, topHours:topHours, commonIps:commonIps, deviations:devs.slice(0,4) });
  });
  return out.sort(function(a,b){ return b.deviations.length - a.deviations.length; });
}

/* Time-windowed sequence detection. recognizeScenario tests co-occurrence within a correlated chain;
   this verifies the ORDER and the WINDOW — the difference between "these events share an IP" and
   "failed logins, THEN a success, THEN code execution, all inside 10 minutes" (a confirmed account
   takeover, not a coincidence). Operates on the chain's already-grouped, time-sorted events. */





