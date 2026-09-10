/* ============================================================
 * CloudLog — 02-severity-stages.js
 * Severity rating + MITRE kill-chain stage classification.
 * Part of index.html; assembled by build.js. Do not add a <script> wrapper.
 * ============================================================ */
function severityRating(ev){
  var f = flatOf(ev);
  var lvl = f.level != null ? +f.level : (f.rulelevel != null ? +f.rulelevel : null);
  if (lvl != null && !isNaN(lvl)) { if (lvl >= 10) return "malicious"; if (lvl >= 6) return "suspicious"; if (lvl <= 3) return "info"; }
  var sv = String(f.severity || f.alertseverity || f.priority || "").toLowerCase();
  if (/\bcritical\b/.test(sv)) return "malicious";
  if (/\bhigh\b/.test(sv)) return "suspicious";
  if (/\bmedium\b/.test(sv)) return "suspicious";                 // Medium is still worth surfacing
  if (/\b(low|info|informational)\b/.test(sv)) return "info";     // source rated it low
  return null;
}
/* severityExplain returns BOTH the verdict and the reason, walking the SAME fixed order of checks
   severityOf has always used. Every verdict the tool shows is therefore checkable: the analyst can
   see exactly which evidence produced it. severityOf() is a thin wrapper so behaviour cannot drift. */
function severityExplain(ev) {
  var R = function(v, why){ return { verdict:v, reason:why }; };
  if (ALLOWLIST.size && eventInAllowlist(ev)) return R("info", "entity is on your allow-list (known-good)");
  if (IOC_BLOCKLIST.size && eventHitsBlocklist(ev)) return R("malicious", "matches your imported known-bad IOC list / investigation memory");
  var _fl0 = flatOf(ev);
  var _st0 = String(_fl0.status || _fl0.verdict || _fl0.result || _fl0.disposition || "").toLowerCase();
  if (/^(safe|clean|benign|allowed|no.?threat|not.?malicious|whitelisted)$/.test(_st0)) return R("info", "the source itself marked it '"+_st0+"'");
  var _f = flatOf(ev);
  var _at = String(_f.actiontaken || _f.action || "").toLowerCase() + " " + String(ev.action || "").toLowerCase();
  var _bm = _at.match(/\bblock|blocked|denied|\bdeny\b|prevented|dropped|quarantin|\breject|sinkhole|blackhole|terminated|isolated|contained|mitigated|neutralized/);
  if (_bm && severityRating(ev) !== "malicious") return R("suspicious", "the control already "+_bm[0]+" it (mitigated) \u2014 shown for awareness, not as an active incident");
  var text = ((ev.action || "") + " " + JSON.stringify(ev.raw || {})).toLowerCase();
  var risk = (ev.raw && ev.raw.risk != null && !isNaN(+ev.raw.risk)) ? +ev.raw.risk : null;
  var rating = severityRating(ev);
  var _hm = text.match(/\bmalicious\b|\bmalware\b|\bbackdoor\b|\btrojan\b|\bransom|\bc2\b|\bexploit\b|mimikatz|sekurlsa|cobalt ?strike|meterpreter|comsvcs.*minidump|lsass.*(dump|minidump)|procdump.*lsass/);
  if (_hm) return R("malicious", "hard indicator in the event text: '"+_hm[0].slice(0,40)+"'");
  if (rating === "malicious") return R("malicious", "the source rated it Critical / severity level \u2265 10");
  var _ph = payloadHits((ev.action || "") + " " + JSON.stringify(ev.raw || {}));
  var _phHigh = _ph.filter(function(s){ return s.sev === "high"; });
  if (_phHigh.length) return R("malicious", "high-severity attack payload signature: "+_phHigh.map(function(x){return x.name;}).slice(0,2).join(", "));
  if (risk != null && risk >= 80) return R("malicious", "source risk score "+risk+" (\u2265 80)");
  if (typeof ev.severity === "number" && ev.severity >= 7) return R("malicious", "source severity "+ev.severity+" (\u2265 7)");
  if (ev.attackTag && ev.attackTag !== "Sensitive Path Probe" && ev.attackTag !== "WordPress Probe") return R("malicious", "web attack pattern in the request: "+ev.attackTag);
  if (risk != null && risk >= 50) return R("suspicious", "source risk score "+risk+" (50\u201379)");
  if (typeof ev.severity === "number" && ev.severity >= 4) return R("suspicious", "source severity "+ev.severity+" (4\u20136)");
  if (ev.attackTag || ev.isScanner) return R("suspicious", ev.isScanner ? "request came from a known scanner user-agent" : "probing pattern in the request: "+ev.attackTag);
  if (rating === "suspicious") return R("suspicious", "the source rated it High/Medium / severity level 6\u20139");
  if (_ph.length) return R("suspicious", "attack payload signature (medium): "+_ph.map(function(x){return x.name;}).slice(0,2).join(", "));
  if (ev && ev.raw){ var dq=ev.raw.dns||"", ua=ev.raw.ua||"";
    if (dq && (isRareTld(dq)||looksDGA(dq))) return R("suspicious", "DNS query to a "+(looksDGA(dq)?"DGA-looking":"rare-TLD")+" domain: "+dq);
    if (/msie [67]\.0|python-requests|\bcurl\b|\bwget\b/i.test(ua)) return R("suspicious", "unusual HTTP user-agent: "+String(ua).slice(0,40));
    if (/gate\.php|\/upload\.php/i.test(ev.action||"")) return R("suspicious", "request to a known C2/dropper-style endpoint (gate.php / upload.php)"); }
  var _sm = text.match(/\bsuspicious\b|brute|traversal|injection|\bxss\b|nikto|sqlmap|nmap|masscan|probe|unexpected|anomal|unauthorized|denied|\bfail(ed)?\b|powershell.*(-enc|-e |-encodedcommand|-nop|-w hidden|hidden)|regsvr32.*(scrobj|\/i:http)|rundll32.*(javascript|minidump)|certutil.*-urlcache|currentversion\\run|\bpersistence\b|\.hta\b|whoami|net user .*\/add/);
  if (_sm) return R("suspicious", "suspicious keyword in the event text: '"+_sm[0].slice(0,40)+"'");
  return R("info", "no indicators matched \u2014 looks like normal telemetry");
}
function severityOf(ev) { return severityExplain(ev).verdict; }
function sevBadge(sev, ev) { var m = { malicious:"sev-high", suspicious:"sev-medium", info:"sev-low" };
  var tip = (ev && typeof severityExplain === "function") ? " title='" + esc(severityExplain(ev).reason) + "'" : "";
  return "<span class='sev " + (m[sev]||"sev-low") + "'" + tip + ">" + sev + "</span>"; }
function sevColor(sev) { return sev === "malicious" ? "#dc2626" : sev === "suspicious" ? "#f59e0b" : "#9ca3af"; }
function applyTimeSeverityFilter() {
  var sel = document.getElementById("sevFilter"); if (!sel) return;
  var v = sel.value, rows = document.querySelectorAll("#tbody tr[data-sev]");
  Array.prototype.forEach.call(rows, function(tr){ var sev = tr.getAttribute("data-sev"); tr.style.display = (v === "all" || sev !== "info") ? "" : "none"; });
}

// Context-aware MITRE tactic mapping. The SAME tool maps to different tactics by
// intent — e.g. powershell+lsass => Credential Access, powershell+whoami => Discovery,
// powershell -enc hidden => Defense Evasion, plain powershell => Execution.
// Order matters: specific intent is checked before the generic tool.
var KILL_ORDER = ["Reconnaissance","Initial Access","Execution","Persistence","Privilege Escalation","Defense Impairment","Stealth","Credential Access","Discovery","Lateral Movement","Collection","Command and Control","Exfiltration","Impact"];
function sortStagesCanonical(arr){
  return (arr||[]).slice().sort(function(a,b){
    var ia=KILL_ORDER.indexOf(a), ib=KILL_ORDER.indexOf(b);
    return (ia<0?99:ia) - (ib<0?99:ib);
  });
}
var STAGE_RULES = [
  ["Credential Access", /lsass|mimikatz|sekurlsa|minidump|hashdump|kerberoast|dcsync|ntds\.dit|\bsam\b|secretsdump|credential dump|dump.*password/],
  ["Impact", /ransom|\bencrypt|\.locked\b|vssadmin.*delete|shadowcopy.*delete|\bwiper\b|defac|destroy|bcdedit/],
  ["Exfiltration", /exfil|bytes_out|large transfer|upload to|to (s3|dropbox|mega|pastebin)|data (transfer|staging).*out|scp .*@/],
  ["Lateral Movement", /psexec|wmiexec|smbexec|pass-the-hash|\blateral\b|remote (desktop|service|exec)|\bwinrm\b|\brdp\b .*conn/],
  ["Persistence", /currentversion\\run|scheduled task|schtasks|new-service|sc create|autostart|startup folder|\bcron\b|persistence|run key/],
  ["Privilege Escalation", /getsystem|uac bypass|token (manipulation|impersonat)|setuid|privilege::debug|elevat|\bsudo\b|assigned (admin|role)|privilege escalation/],
  ["Defense Impairment", /disable (defender|av|antivirus|firewall|logging|security)|clear (event ?log|logs)|wevtutil|stop (service|edr)|kill (av|edr)|tamper/],
  ["Stealth", /\bamsi\b|obfuscat|-enc\b|-encodedcommand|-w hidden|-nop|regsvr32|rundll32|mshta|base64|masquerad|process injection|createremotethread|timestomp|indicator removal/],
  ["Discovery", /whoami|net (user|group|view|localgroup)|nltest|systeminfo|ipconfig|arp -a|tasklist|\bnet1\b|ldapsearch|bloodhound|adfind|enum|discovery/],
  ["Command and Control", /\bbeacon\b|\bc2\b|cobalt ?strike|meterpreter|reverse shell|dns tunnel|\/i:http|\.sct\b|callback|implant/],
  ["Collection", /screenshot|keylog|clipboard|\bcollect(ion)?\b|recording|archive .*(collect|staging)/],
  ["Execution", /process create|\.exe\b|powershell|cmd\.exe|\bbash\b|wscript|cscript|\bmacro\b|invoke-|python |perl |execution/],
  ["Initial Access", /phish|exploit|drive-by|sql ?injection|union select|traversal|\.\.\/|\bxss\b|brute|failed login|logon|signin|4625|4624|accepted (password|publickey)|consolelogin|authenticat/],
  ["Reconnaissance", /\bnmap\b|masscan|nikto|dirb|gobuster|port scan|\bprobe\b|\brecon\b|\bscan\b/]
];
function classifyStageDetail(r) {
  var s = ((r.action || "") + " " + JSON.stringify(r.raw || {})).toLowerCase();
  for (var i = 0; i < STAGE_RULES.length; i++) {
    var m = s.match(STAGE_RULES[i][1]);
    if (m) return { stage: STAGE_RULES[i][0], why: 'matched "' + m[0] + '"' };
  }
  return { stage: "Other", why: "no distinctive tactic signal" };
}
function classifyStage(r) { return classifyStageDetail(r).stage; }

function inferSignals(r) {
  var signals = [];
  if (r.ip && r.ip !== "-") signals.push("IP");
  if ((r.urls || []).length) signals.push("URL");
  if ((r.cmds || []).length) signals.push("CMD");
  if ((r.domains || []).length) signals.push("DNS");
  if ((r.hashes || []).length) signals.push("HASH");
  if (r.status !== undefined) signals.push("HTTP");
  return signals;
}

function buildXdrScore(r) {
  var score = 0;
  var text = ((r.action || "") + " " + JSON.stringify(r.raw || {})).toLowerCase();
  if (/malicious|exploit|backdoor|trojan|privilege|credential|brute|sqli|xss|traversal|exfil|dos|denial/.test(text)) score += 40;
  if ((r.urls || []).length) score += 10;
  if ((r.cmds || []).length) score += 15;
  if ((r.hashes || []).length) score += 10;
  if ((r.domains || []).length) score += 10;
  if (r.severity) score += Math.min(50, Math.round(r.severity * 5));
  if (r.status && (r.status >= 400 || r.status === 302 || r.status === 401 || r.status === 403 || r.status === 404 || r.status === 503)) score += 5;
  return Math.min(100, score);
}

function stageColor(stage) {
  var map = {
    "Initial Access": "#2563eb",
    "Execution": "#7c3aed",
    "Privilege / Persistence": "#c026d3",
    "Discovery / C2": "#0891b2",
    "Exfiltration": "#ea580c",
    "Impact": "#dc2626",
    "Reconnaissance": "#65a30d",
    "Other": "#6b7280"
  };
  return map[stage] || "#6b7280";
}

function severityColor(score) {
  if (score >= 70) return "#dc2626";
  if (score >= 40) return "#f59e0b";
  return "#16a34a";
}

/* ---------- GuardDuty parser ---------- */





