/* ============================================================
 * CloudLog — 01-core-utils.js
 * Core helpers: time formatting, field-key maps, object flattening, IOC/type guards, inline-worker bootstrap.
 * Part of index.html; assembled by build.js. Do not add a <script> wrapper.
 * ============================================================ */
/* ===== Inline Web Worker bootstrap =====
   This exact script also runs inside a Web Worker (see the worker manager near the end).
   In a worker there is no DOM, so detect that context and stub document/window with a
   permissive proxy — every main-thread UI wiring statement then safely no-ops, while all
   the engine functions (parseAnyLog/runDetections/correlateChains/aggregateIocs) still load.
   One source of truth: the worker runs the same code that runs on the main thread. */
var __IS_WORKER = (typeof importScripts === "function" && typeof self !== "undefined" && typeof document === "undefined");
if (__IS_WORKER) {
  var __domStub = new Proxy(function(){}, {
    get: function(t, p){ if(p==="length") return 0; if(p===Symbol.toPrimitive) return function(){return "";}; return __domStub; },
    apply: function(){ return __domStub; }, set: function(){ return true; }, construct: function(){ return __domStub; }
  });
  self.document = __domStub;
  self.window = self;
}

var state = { logs: [], filtered: [], source: "None", detections: [], sortDesc: true };

function formatTime(t) {
  if (!t) return "-";
  var d = new Date(t);
  if (isNaN(d.getTime())) return String(t);
  var pad = function(n){ return n < 10 ? "0"+n : n; };
  return d.getUTCFullYear() + "-" + pad(d.getUTCMonth()+1) + "-" + pad(d.getUTCDate()) + " " + pad(d.getUTCHours()) + ":" + pad(d.getUTCMinutes()) + ":" + pad(d.getUTCSeconds());
}

function arrMin(a){ var m=Infinity; for(var i=0;i<a.length;i++){ if(a[i]<m) m=a[i]; } return m; }
function arrMax(a){ var m=-Infinity; for(var i=0;i<a.length;i++){ if(a[i]>m) m=a[i]; } return m; }
function computeSpan(list) {
  var times = list.map(function(r){ return new Date(r.time).getTime(); }).filter(function(t){ return !isNaN(t); });
  if (!times.length) return "-";
  var min = arrMin(times), max = arrMax(times);
  var diffMs = max - min;
  if (diffMs <= 0) return "single moment";
  var mins = Math.round(diffMs / 60000);
  if (mins < 60) return mins + "m";
  var hrs = Math.round(mins / 60);
  if (hrs < 48) return hrs + "h";
  return Math.round(hrs / 24) + "d";
}

/* ---------- Field key dictionaries for generic normalization ---------- */
var TIME_KEYS = ["eventTime","time","published","timestamp","@timestamp","creationTime","createdDateTime","date","datetime","event_time","ts","occurredAt","logTime"];
var ACTOR_KEYS = ["targetUserName","subjectUserName","samAccountName","userName","userPrincipalName","userAccount","displayName","caller","user","username","principalEmail","account","accountName","actorId","initiatedBy","identity","recipient","sender","srcUser","sourceUser","who","performedBy","clientName","srcuser","common_name","email"];
var ACTION_KEYS = ["eventName","operationName","eventType","methodName","action","activity","operation","ruleName","ruleDescription","wazuhRuleDesc","signature","alert","query","qname","question","request","command","event","message","description","title","name","type","category"];
var IP_KEYS = ["sourceIPAddress","callerIpAddress","ipAddress","ip","clientIp","srcIp","remoteIp","source_ip","clientIP","ipAddr","client","client_ip","clientAddr","src","src_ip","from","peer","query_source","remote_addr","remoteAddress"];

function getPath(obj, path) {
  var parts = path.split(".");
  var cur = obj;
  for (var i=0;i<parts.length;i++) {
    if (cur && typeof cur === "object" && parts[i] in cur) cur = cur[parts[i]];
    else return undefined;
  }
  return cur;
}

function _normKey(k){ return String(k).toLowerCase().replace(/[^a-z0-9]/g,""); }
// Flatten an object (top level + up to 2 nested levels) into { normalizedKey: value },
// so SourceIP / source_ip / data.source_ip all resolve the same way. Shallower keys win.
function flattenObj(obj){
  var out={};
  (function walk(o,d){
    if(!o||typeof o!=="object"||d>2) return;
    var nested=[];
    for(var k in o){ if(k==="__flat") continue; var v=o[k];
      if(v&&typeof v==="object"&&!Array.isArray(v)) nested.push(v);
      else { var nk=_normKey(k); if(!(nk in out)&&v!==undefined&&v!==null&&v!=="") out[nk]=v; }
    }
    for(var i=0;i<nested.length;i++) walk(nested[i],d+1);
  })(obj,0);
  return out;
}
function lookupKeys(flat, keys){ for(var i=0;i<keys.length;i++){ var nk=_normKey(keys[i]); if(nk in flat) return flat[nk]; } return undefined; }
// Cache the flattened raw on the event (non-enumerable) so severityOf/rules don't re-recurse it 3-4x per event.
function flatOf(ev){
  if (!ev || typeof ev !== "object") return flattenObj((ev && ev.raw) || {});
  if (ev.__flat) return ev.__flat;
  var f = flattenObj(ev.raw || {});
  try { Object.defineProperty(ev, "__flat", { value: f, enumerable: false, configurable: true, writable: true }); }
  catch (e) { ev.__flat = f; }
  return f;
}
function rawStr(e){
  if (e && e.__rawstr != null) return e.__rawstr;
  var s = JSON.stringify((e && e.raw) || {});
  if (e && typeof e === "object") { try { Object.defineProperty(e,"__rawstr",{value:s,enumerable:false,configurable:true,writable:true}); } catch(_){ e.__rawstr=s; } }
  return s;
}
function firstKey(obj, keys) {
  var flat = flattenObj(obj);
  var hit = lookupKeys(flat, keys);
  if (hit !== undefined) return hit;
  for (var i=0;i<keys.length;i++) {
    if (keys[i].indexOf(".") >= 0) {
      var found = getPath(obj, keys[i]);
      if (found !== undefined && found !== null && found !== "") return found;
    }
  }
  return "";
}

function extractArray(input) {
  if (Array.isArray(input)) return input;
  if (input && typeof input === "object") {
    var wrapperKeys = ["Records","records","events","Events","findings","Findings","logs","Logs","items","Items","data","Data","results","Results"];
    for (var i=0;i<wrapperKeys.length;i++) {
      if (Array.isArray(input[wrapperKeys[i]])) return input[wrapperKeys[i]];
    }
    return [input];
  }
  return [];
}

/* ---------- Indicator extraction (IPs, URLs, commands, domains, hashes, emails) ---------- */
function isLikelyUrl(s) { return typeof s === "string" && /https?:\/\/|www\./i.test(s); }
function isLikelyCommand(s) { return typeof s === "string" && /(bash|sh|cmd|powershell|curl|wget|nc|netcat|sqlmap|nikto|nmap|python|perl|ruby|php)\b/i.test(s); }
function isLikelyEmail(s) { return typeof s === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s); }
function isLikelyHash(s) { return typeof s === "string" && /^[A-Fa-f0-9]{32,64}$/.test(s); }
function isLikelyDomain(s) { return typeof s === "string" && /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(s) && !/\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|html?|php|jsp|aspx?|cgi|pl|py|rb|json|xml|txt|csv|pdf|zip|gz|tar|mp[34]|webp|min|dll|exe|sh|bat|ps1)$/i.test(s); }

function normalizeIndicators(x) {
  var vals = [];
  function walk(v) {
    if (typeof v === "string") vals.push(v);
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object") for (var k in v) walk(v[k]);
  }
  walk(x);
  return {
    urls: vals.filter(isLikelyUrl).slice(0, 10),
    cmds: vals.filter(isLikelyCommand).slice(0, 10),
    emails: vals.filter(isLikelyEmail).slice(0, 10),
    hashes: vals.filter(isLikelyHash).slice(0, 10),
    domains: vals.filter(isLikelyDomain).slice(0, 10)
  };
}

function formatIndicators(r) {
  var parts = [];
  if (r.urls && r.urls.length) parts.push("Links: " + r.urls.slice(0,3).join(", "));
  if (r.cmds && r.cmds.length) parts.push("Commands: " + r.cmds.slice(0,3).join(", "));
  if (r.domains && r.domains.length) parts.push("Domains: " + r.domains.slice(0,3).join(", "));
  if (r.hashes && r.hashes.length) parts.push("Hashes: " + r.hashes.slice(0,3).join(", "));
  if (r.emails && r.emails.length) parts.push("Emails: " + r.emails.slice(0,3).join(", "));
  return parts.length ? '<div class="indicator-box">' + parts.map(function(p){ return "<div>"+p+"</div>"; }).join("") + "</div>" : "";
}

/* ---------- Stage classification / XDR scoring ---------- */





