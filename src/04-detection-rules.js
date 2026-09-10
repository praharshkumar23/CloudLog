/* ============================================================
 * CloudLog — 04-detection-rules.js
 * The MITRE-mapped detection rule set + payload signatures.
 * Part of index.html; assembled by build.js. Do not add a <script> wrapper.
 * ============================================================ */
/* Detection FIDELITY (true-positive likelihood) — distinct from severity (impact-if-true).
   High-fidelity = specific tool/IOC signatures that are almost never benign (mimikatz, wmic process
   call create). Low-fidelity = heuristic/behavioral signals that often have innocent explanations
   (off-hours login, volume outlier). Analysts triage on BOTH: high-severity + high-fidelity = act now;
   high-severity + low-fidelity = verify first. This mirrors Sigma `level` / Elastic risk vs severity. */
function fidelityFor(ruleId, ruleName){
  var k = String(ruleId||"")+" "+String(ruleName||"");
  // LOW fidelity: behavioral / statistical / context-dependent — needs analyst confirmation
  if (/^BEH-|behavior|off-?hours|volume|rare|outlier|impossible travel|multi-ip|user-agent|referrer|rate abuse|forced brows|enum/i.test(k)) return "low";
  // HIGH fidelity: specific tool names, exact exploit sigs, credential-dumpers, known C2 frameworks
  if (/^SEQ-|takeover|anti-forensic|hands-on|\u2192|mimikatz|lsass|sekurlsa|procdump|dumpert|wmic.*process call|wmi remote|^T1047|psexec|lateral tool|cobalt|mshta|bitsadmin|certutil|lolbin|web shell|log4shell|proxyshell|reverse shell|kerberoast|pass-the-hash|\bIOC\b|known-bad|ransomware|crypto min/i.test(k)) return "high";
  // otherwise MEDIUM: pattern-based rules with some room for benign matches
  return "medium";
}
function fidelityBadge(ruleId, ruleName){
  var f = fidelityFor(ruleId, ruleName);
  var lbl = f==="high" ? "high-fidelity" : f==="low" ? "heuristic" : "medium-fidelity";
  return '<span class="fid-tag fid-'+f+'" title="Detection fidelity — how likely this is a true positive (separate from impact severity)">'+lbl+'</span>';
}

/* Framework mappings. ATT&CK IDs are exact per rule; NIST CSF 2.0 subcategories and MITRE D3FEND
   countermeasures are curated at the technique-family level (all IDs are real, verifiable framework
   identifiers). Matched top-to-bottom on the rule id; first hit wins, else a sensible default. */
var FRAMEWORK_MAP = [
  [/^SEQ-ATO|takeover/i,             ["DE.AE-02","DE.CM-03","RS.MI-01"], ["D3-UBA","D3-RTSD"]],       // account takeover sequence
  [/^SEQ-ANTIFORENSIC|anti-forensic|log clear/i, ["DE.AE-02","PR.PS-04","RS.AN-03"], ["D3-FA","D3-UBA"]], // log tampering after recon
  [/^SEQ-HOK|hands-on/i,             ["DE.AE-03","DE.CM-01","RS.MI-01"], ["D3-RTSD","D3-PMAD","D3-NTA"]], // hands-on-keyboard chain
  [/^SEQ-PRIVDISABLE|tooling disabled/i, ["DE.AE-02","PR.PS-01","RS.MI-01"], ["D3-UBA","D3-PA"]],        // priv change -> security tooling off
  [/^SEQ-CREDEXFIL|credential dump.*transfer/i, ["DE.AE-03","PR.DS-01","RS.MI-01"], ["D3-PMAD","D3-NTA","D3-CSPP"]], // cred dump -> exfil
  [/^T1110|brute|spray/i,            ["PR.AA-05","DE.CM-01","DE.AE-02"], ["D3-ISVA","D3-UBA"]],       // brute force / spray
  [/^T1003|mimikatz|lsass|cred/i,    ["DE.CM-03","PR.AA-01","RS.MI-02"], ["D3-PMAD","D3-PA"]],        // credential access
  [/^T1055/i,                        ["DE.CM-09","DE.AE-02"],            ["D3-PMAD","D3-PSMD"]],       // process injection
  [/^T1047|^T1570|^T1021|^T1550|psexec|lateral/i, ["DE.CM-01","DE.AE-03","RS.MI-01"], ["D3-RTSD","D3-NTA"]], // lateral movement
  [/^T1218|^T1059|lolbin|powershell|shell/i, ["DE.CM-09","DE.AE-02"],    ["D3-PA","D3-SFA"]],          // execution / LOLBin
  [/^T1105|dropper|ingress/i,        ["DE.CM-01","DE.CM-09"],            ["D3-FA","D3-NTA"]],          // ingress tool transfer
  [/^T1566|phish/i,                  ["DE.CM-01","PR.AT-01","DE.AE-02"],["D3-NTA"]],                   // phishing
  [/^T1071|c2|beacon|dns tunnel|^T1568/i, ["DE.CM-01","DE.AE-02","RS.AN-03"], ["D3-NTA","D3-DNSTA","D3-CSPP"]], // C2 / exfil channel
  [/^T1547|^T1136|^T1098|persist|run key|account/i, ["DE.CM-03","PR.AA-01"], ["D3-UBA","D3-SFA"]],     // persistence / accounts
  [/^T1595|^T1046|recon|scan|enum|forced brows/i, ["DE.CM-01","ID.RA-01"], ["D3-NTA","D3-ISVA"]],      // recon / scanning
  [/^T1486|^T1496|ransom|mining|hijack/i, ["DE.CM-09","RC.RP-01","RS.MI-02"], ["D3-FA","D3-UBA"]],     // impact
  [/^T1041|^T1048|^T1530|exfil|data from/i, ["DE.CM-01","PR.DS-01","DE.AE-06"], ["D3-NTA","D3-CSPP"]], // exfiltration
  [/^T1190|^T1505|^T1083|sql|xss|ssrf|xxe|ssti|rce|web shell|traversal|lfi|deser|graphql/i, ["DE.CM-01","PR.PS-05","DE.AE-02"], ["D3-WSAA","D3-NTA"]], // web app attacks
  [/^T1078|impossible travel|valid account|iam|multi-ip/i, ["DE.CM-03","DE.CM-06","PR.AA-05"], ["D3-UBA","D3-RTSD"]], // identity / cloud
  [/^T1552|metadata|cloud cred/i,    ["DE.CM-06","PR.AA-01"],            ["D3-UBA"]],                   // cloud credential
  [/^BEH-|behavior/i,                ["DE.AE-02","DE.CM-03"],            ["D3-UBA"]],                   // behavioral
  [/^TI-|^IOC|^NIDS|^GD-|indicator|signature/i, ["DE.CM-01","RS.AN-03"],["D3-NTA"]],                   // threat-intel / IDS
  [/^T1548|privilege|access control|mass assign/i, ["DE.CM-03","PR.AA-05"], ["D3-UBA"]],               // priv-esc / access
  [/^T1499|rate|exhaust/i,           ["DE.CM-01","DE.AE-02"],            ["D3-ISVA"]]                   // DoS / rate abuse
];
function frameworksFor(ruleId, ruleName){
  var key = String(ruleId||"") + " " + String(ruleName||"");
  for (var i=0;i<FRAMEWORK_MAP.length;i++){ if (FRAMEWORK_MAP[i][0].test(key)) return { csf:FRAMEWORK_MAP[i][1], d3fend:FRAMEWORK_MAP[i][2] }; }
  return { csf:["DE.CM-01","DE.AE-02"], d3fend:["D3-NTA"] };  // sensible detection default
}
function frameworkTagsHtml(ruleId, ruleName){
  var f = frameworksFor(ruleId, ruleName);
  var csf = f.csf.map(function(c){ return '<span class="fw-tag fw-csf" title="NIST CSF 2.0">'+esc(c)+'</span>'; }).join("");
  var d3f = f.d3fend.map(function(d){ return '<span class="fw-tag fw-d3f" title="MITRE D3FEND countermeasure">'+esc(d)+'</span>'; }).join("");
  return csf + d3f;
}

var MITRE_RULES = [
  { id:"TI-MAL", meta:true, name:"Flagged Malicious (source verdict)", test:null,
    match:function(e){ return severityOf(e) === "malicious"; },
    title:"Indicator flagged malicious", sev:"high",
    desc:"The source log, a threat feed, or a matched attack pattern flagged this event as malicious (scanner verdict MALICIOUS, GuardDuty severity >= 7, or an exploit signature).",
    suggestion:"Treat as a confirmed lead: block the indicator, isolate the affected host/identity, and pivot on the IOC in the Investigate tab." },
  { id:"TI-SUS", meta:true, name:"Flagged Suspicious (needs review)", test:null,
    match:function(e){ return severityOf(e) === "suspicious"; },
    title:"Suspicious activity requiring review", sev:"medium",
    desc:"Anomalous activity or a partial risk-pattern match (scanner tooling, failed auth, medium-severity finding, or a SUSPICIOUS verdict) that is not confirmed malicious.",
    suggestion:"Review in context; confirm against baseline before escalating or dismissing." },
  { id:"T1110", name:"Brute Force", test:null,
    group:function(evts){
      var byKey = {};
      evts.forEach(function(e){
        if (/fail|invalid user|authentication failure|failed password/i.test(e.action||"")) {
          var ipOk = e.ip && e.ip !== "-" && /^\d{1,3}(\.\d{1,3}){3}$/.test(e.ip);
          var key = ipOk ? e.ip : e.actor;               // one IP spraying many users = brute force
          if (key && key !== "unknown") (byKey[key]=byKey[key]||[]).push(e);
        }
      });
      var out = [];
      for (var k in byKey) if (byKey[k].length >= 3) out.push({actor:k, count:byKey[k].length, events:byKey[k]});
      return out;
    },
    title:"Repeated failed logins (possible brute force)", sev:"high",
    desc:"Three or more failed login attempts detected for the same actor in a short window.",
    suggestion:"Lock or reset the account, enforce MFA, and block the source IP if it is not recognized." },
  { id:"T1098", name:"Account Manipulation", test:null,
    match:function(e){ var t=(e.action+" "+rawStr(e)).toLowerCase(); return /attachuserpolicy|add member to role|setiampolicy|update user|iam change|cloud iam|attachrolepolicy|privileges? (assigned|granted)/.test(t); },
    title:"Privilege or role modification detected", sev:"high",
    desc:"An account's permissions, group membership, or IAM policy was changed, which can indicate privilege escalation.",
    suggestion:"Verify the change was authorized via change management. Review the resulting permission set immediately." },
  { id:"T1136", name:"Create Account / Access Key", test:null,
    match:function(e){ return /createaccesskey|createuser|create account/i.test(e.action); },
    title:"New credential or account created", sev:"medium",
    desc:"A new access key or account was created, which attackers commonly use to maintain persistence.",
    suggestion:"Confirm this was requested through an approved ticket. Rotate or revoke unrecognized keys." },
  { id:"T1003", name:"Credential Dumping (Mimikatz / LSASS)", test:null,
    match:function(e){ var t=(e.action+" "+rawStr(e)).toLowerCase(); return /lsass|mimikatz|sekurlsa|comsvcs.*minidump|procdump.*lsass|lsass\.dmp|dumpert|nanodump|(reg(\.exe)?\s+save|copy|type)\s+.*(hklm.{0,4}sam|config[\/\\]sam|\\sam\b)|vssadmin.*create.*shadow/.test(t); },
    title:"Credential-dumping activity detected", sev:"high",
    desc:"A process accessed LSASS memory or ran a known credential-dumping tool (Mimikatz, comsvcs MiniDump, procdump). Classic step toward domain compromise.",
    suggestion:"Isolate the host immediately, capture memory for forensics, reset exposed credentials, and hunt the parent process chain." },

  { id:"T1047", name:"WMI Remote Execution", test:null,
    match:function(e){ var t=(e.action+" "+rawStr(e)).toLowerCase();
      return (/\bwmic\b/.test(t) && /process\s+call\s+create/.test(t))
          || (/\/node:\S+/.test(t) && /process\s+call\s+create/.test(t))
          || /win32_process.*\.create\(/.test(t)
          || /invoke-wmimethod.*-name\s+create/.test(t); },
    title:"Remote process creation via WMI", sev:"high",
    desc:"WMI was used to spawn a process (wmic … process call create / Win32_Process.Create). A common hands-on-keyboard execution and lateral-movement technique that evades many process-tree defenses.",
    suggestion:"Confirm whether the source host/account is authorised for remote admin. Review the created process and correlate with logons on the target." },

  { id:"T1218", name:"LOLBin Abuse (signed-binary proxy execution)", test:null,
    match:function(e){ var t=(e.action+" "+rawStr(e)).toLowerCase();
      return /mshta\b.*(vbscript|javascript|http)/.test(t)
        || /rundll32\b.*(javascript:|\.sct|scrobj|shell32\.dll,shellexec_rundll.*http|url\.dll,\S*openurl\s+http|http)/.test(t)
        || /regsvr32\b.*(scrobj|\/i:http|\/u )/.test(t)
        || /certutil\b.*(-urlcache|-decode|-encode|urlcache)/.test(t)
        || /\bbitsadmin\b.*\/transfer/.test(t)
        || /\bmshta\b vbscript/.test(t); },
    title:"Living-off-the-land binary used to run code or download payloads", sev:"high",
    desc:"A trusted signed Windows binary (mshta, rundll32, regsvr32, certutil, bitsadmin) was invoked in a way that proxies code execution or downloads a payload — a hallmark of defence evasion and ingress tool transfer.",
    suggestion:"Treat as malicious unless tied to known software deployment. Pull the full command line, the downloaded artefact, and the parent process." },

  { id:"T1570", name:"Lateral Tool Transfer / PsExec", test:null,
    match:function(e){ var t=(e.action+" "+rawStr(e)).toLowerCase(); return /psexec|psexesvc|paexec|\\\\admin\\$\\\\|smbexec|\\bwinrs\b/.test(t); },
    title:"Remote-execution / lateral-movement tooling (PsExec-class)", sev:"high",
    desc:"PsExec-style remote execution or a copy to an ADMIN$ share was observed — attackers use these to move laterally and run payloads across hosts.",
    suggestion:"Verify the admin activity is sanctioned. Map source→destination hosts and check for a spreading pattern." },

  { id:"T1105", name:"Ingress Tool Transfer (download utility)", test:null,
    match:function(e){ var t=(e.action+" "+rawStr(e)).toLowerCase();
      return (/certutil.*http|bitsadmin.*\/transfer|(curl|wget)\s+https?:\/\/\S+\.(exe|dll|ps1|sh|bin)|powershell.*downloadfile|invoke-webrequest.*-outfile/.test(t)); },
    title:"File downloaded to host via a command-line utility", sev:"medium",
    desc:"A command-line tool fetched a remote file (certutil/bitsadmin/curl/wget/PowerShell). Frequently how second-stage tooling and payloads are pulled onto a beachhead.",
    suggestion:"Identify the downloaded file and its source, and check whether it was executed afterwards." },

  { id:"T1566.001", name:"Phishing Indicator", test:null,
    match:function(e){ var t=(e.action+" "+rawStr(e)).toLowerCase(); return /phishing (email|e-mail|mail|campaign|attachment|link)|spearphish|malicious attachment|suspicious attachment|email.*phishing|\bfrom:.*phish|subject:.*(invoice|verify your|account locked)/.test(t) && !/\/\?ref=|uri=|\bget \//.test(t); },
    title:"Phishing / malicious email indicator", sev:"medium",
    desc:"An email was flagged as phishing or carrying a malicious attachment/link — the most common initial-access vector.",
    suggestion:"Confirm delivery and whether the user interacted. Pull related auth events for the recipient to catch follow-on compromise." },

  { id:"T1110.003", name:"Password Spray / RDP Brute Force", test:null,
    match:function(e){ var t=(e.action+" "+rawStr(e)).toLowerCase(); return /password spray|rdp brute|brute[- ]?force/.test(t) || (/failed logon|4625|authentication failure/.test(t) && /rdp|logontype[=: ]*10|remoteinteractive/.test(t)); },
    title:"Password spraying or RDP brute-force", sev:"high",
    desc:"Repeated authentication failures consistent with password spraying or RDP brute-forcing — a high-volume initial-access and credential-access technique.",
    suggestion:"Identify the source IP(s) and targeted accounts, block the source, and check for any subsequent successful logon from the same origin." },

  { id:"T1071.001", name:"Command & Control (outbound beacon)", test:null,
    match:function(e){ var t=(e.action+" "+rawStr(e)).toLowerCase();
      if(/c2 |c2$|command.and.control|beacon|cobalt.?strike|reverse.?shell|meterpreter|empire\b/.test(t)) return true;
      var f=flatOf(e); var dp=String(f["destinationport"]||f["dest_port"]||f["destport"]||f["dport"]||"");
      if(/^(4444|4445|1337|31337|9001|5555|6666|6667|12345|50050|8888)$/.test(dp)) return true;
      if(/\b(cobalt|beacon|evil|malware|c2server|badguy)[a-z0-9.\-]*\.(ru|cn|top|xyz|tk|su|info|com|net)\b/.test(t)) return true;
      return false; },
    title:"Command-and-control / beaconing activity", sev:"high",
    desc:"Outbound traffic or tooling consistent with C2 \u2014 beaconing, reverse shell, a known C2 framework, a hostile destination domain, or a port commonly used by malware (4444, 1337, 9001, 50050 \u2026). Indicates an active foothold talking to an operator.",
    suggestion:"Isolate the host and hunt the implant. Note: C2 over 443 that looks like normal HTTPS needs threat-intel or beaconing analysis \u2014 this rule intentionally does not flag standard web ports (80/443/8080/8443)." },
  { id:"T1055.001", name:"Process Injection (unsigned module from writable path)", test:null,
    match:function(e){ var t=(e.action+" "+rawStr(e)).toLowerCase(); var f=flatOf(e);
      var unsigned=(String(f["signed"])==="false"||/signed[=: ]*false|unsigned/.test(t));
      var img=String(f["image"]||f["imageloaded"]||f["targetfilename"]||"").toLowerCase();
      var badPath=/\\users\\public\\|\\temp\\|\\appdata\\|\\programdata\\|\\windows\\temp\\/.test(img+" "+t);
      var isDll=/\.dll\b/.test(img+" "+t);
      var imageLoad=/image load|imageload|sysmon.*image/.test(t)||String(f["event_code"]||f["eventid"]||"")==="7";
      return /process hollow|hollowing|reflective|injectremote|createremotethread|setwindowshookex|writeprocessmemory/.test(t)
          || (imageLoad && unsigned && isDll && badPath); },
    title:"Process injection / unsigned module load from a writable directory", sev:"high",
    desc:"An unsigned DLL was loaded from a user-writable path (Public/Temp/AppData/ProgramData), or a classic injection API was used (CreateRemoteThread, WriteProcessMemory, reflective load). Common process-hollowing / DLL-sideloading behaviour to run code inside a trusted process.",
    suggestion:"Identify the loading process and the module origin; unsigned code from writable paths inside a signed process is high-signal. Capture the DLL and the parent chain." },

  { id:"T1059.001", name:"Suspicious PowerShell", test:null,
    match:function(e){ var t=(e.action+" "+rawStr(e)).toLowerCase(); return /powershell/.test(t) && /-enc|-e |-encodedcommand|-nop|-w hidden|hidden|downloadstring|iex\(/.test(t); },
    title:"Obfuscated / encoded PowerShell", sev:"high",
    desc:"PowerShell executed with encoding or hidden-window flags — commonly used to run obfuscated payloads.",
    suggestion:"Decode the command line, identify the payload, and check for follow-on process creation and network connections." },
  { id:"T1059.004", name:"Linux Shell Execution (LOLBin)", test:null,
    match:function(e){ var t=(e.action+" "+(e.cmds||[]).join(" ")+" "+rawStr(e)).toLowerCase();
      return /base64\s+(?:-d|--decode)[^\n|]*\|\s*(?:ba)?sh\b|(?:curl|wget)\s+[^\n|;]*\|\s*(?:ba|z|a)?sh\b|(?:curl|wget)\s+[^\n|;]*\|\s*(?:python[0-9]?|perl|ruby)\b|\|\s*(?:ba)?sh\s+-[a-z]*s|python[0-9]?\s+-c\s+['"][^'"]*(?:socket|subprocess|os\.system|pty)|perl\s+-e\s+['"][^'"]*socket|\bmkfifo\b[^\n]*\|\s*(?:ba)?sh|\bnc\b\s+-[a-z]*e\b|\/dev\/tcp\//.test(t); },
    title:"Linux living-off-the-land execution", sev:"high",
    desc:"A command piped a download or base64-decoded blob straight into a shell/interpreter (e.g. curl|sh, wget|python, base64 -d|bash) or opened a reverse shell — a very common cloud/Linux initial-execution pattern.",
    suggestion:"Capture the full command line and parent process, identify what was downloaded, and check for outbound connections and persistence (cron, systemd, rc.local)." },
  // ---- GuardDuty native taxonomy → MITRE (gated on the GuardDuty `type` field, so no effect on other log sources) ----
  { id:"T1595", name:"Reconnaissance / Port Scan", test:null,
    match:function(e){ return e.isScanner===true || /(?:^|:)Recon:|Portscan|PortProbe/i.test((e.raw&&e.raw.type)||""); },
    title:"Reconnaissance (port scan / probe)", sev:"medium",
    desc:"GuardDuty flagged scanning or port-probing — an external host mapping exposed services before an attack.",
    suggestion:"Identify the source IP and country, confirm which ports were probed, and verify exposed services are intended." },
  { id:"T1496", name:"Resource Hijacking (Crypto Mining)", test:null,
    match:function(e){ return /CryptoCurrency:|BitcoinTool/i.test((e.raw&&e.raw.type)||""); },
    title:"Crypto-mining activity", sev:"high",
    desc:"GuardDuty detected cryptocurrency-mining indicators — a strong sign the instance is compromised and being used to mine.",
    suggestion:"Isolate the instance, inspect running processes and outbound connections, and rebuild from a known-good image." },
  { id:"T1071-C2", name:"Command & Control (Backdoor)", test:null,
    match:function(e){ return /Backdoor:|C&CActivity|DGADomain/i.test((e.raw&&e.raw.type)||""); },
    title:"C2 / backdoor communication", sev:"high",
    desc:"GuardDuty observed command-and-control or backdoor traffic from the resource.",
    suggestion:"Isolate the host, block the C2 IP/domain, and hunt for the implant and its persistence mechanism." },
  { id:"T1530", name:"Data from Cloud Storage (S3)", test:null,
    match:function(e){ return /\bS3\/(BucketAnonymousAccessGranted|MaliciousIPCaller|PolicyAs|ServerAccessLoggingDisabled|AnomalousBehavior)/i.test((e.raw&&e.raw.type)||""); },
    title:"Suspicious S3 access / exposure", sev:"medium",
    desc:"GuardDuty flagged anonymous/malicious access to an S3 bucket or a risky bucket policy — a data-exposure risk.",
    suggestion:"Review the bucket policy and ACL, confirm public access is intended, and check S3 access logs for exfiltration." },
  { id:"T1078-IAM", name:"Valid Accounts / Unauthorized IAM", test:null,
    match:function(e){ return /IAMUser\/(MaliciousIPCaller|UnauthorizedAccess|AnomalousBehavior)|InstanceCredentialExfiltration/i.test((e.raw&&e.raw.type)||""); },
    title:"Unauthorized IAM / credential use", sev:"high",
    desc:"GuardDuty flagged IAM activity from a malicious/unknown source or anomalous credential use — possible stolen credentials.",
    suggestion:"Rotate the affected credentials, review CloudTrail for the principal's recent actions, and enforce MFA." },
  { id:"T1547.001", name:"Run Key Persistence", test:null,
    match:function(e){ var t=(e.action+" "+rawStr(e)).toLowerCase(); return /currentversion\\run|\brun key\b|schtasks|scheduled task|new-service|sc create|startup folder/.test(t); },
    title:"Registry Run-key persistence", sev:"medium",
    desc:"A program registered itself to auto-start via a Run key — a common persistence mechanism.",
    suggestion:"Verify the referenced binary is legitimate; if not, remove the key and the payload." },
  { id:"T1071.001-B", name:"C2 Beaconing (behavioral)", test:null,
    group:function(evts){
      var by={};
      evts.forEach(function(e){ var r=e.raw||{}; var dst=r.dst_ip||e.ip; if((e.source==="PCAP"||r.dst_ip) && dst && classifyIp(dst)==="public"){ (by[dst]=by[dst]||[]).push(e); } });
      var out=[]; for(var k in by){ if(by[k].length>=6) out.push({actor:k,count:by[k].length,events:by[k]}); }
      return out;
    },
    title:"Repeated outbound connections to one host (possible C2 beacon)", sev:"high",
    desc:"A host made many outbound connections to the same external IP at a steady cadence \u2014 a hallmark of command-and-control beaconing.",
    suggestion:"Identify the process/host generating the traffic, block the destination, and inspect for implant persistence." },
  { id:"T1568", name:"Suspicious DNS (DGA / rare TLD)", test:null,
    match:function(e){ var d=(e.raw&&e.raw.dns)||""; if(!d) return false; return isRareTld(d)||looksDGA(d); },
    title:"DNS query to suspicious domain (DGA or rare TLD)", sev:"medium",
    desc:"A DNS lookup targeted an algorithmically-generated-looking name or a TLD frequently abused by malware.",
    suggestion:"Check what process issued the query and whether the domain resolves to known-bad infrastructure." },
  { id:"T1041", name:"Data Exfiltration (large POST)", test:null,
    match:function(e){ var r=e.raw||{}; var dst=r.dst_ip; return /(^|\s)POST\s/i.test(e.action||"") && dst && classifyIp(dst)==="public"; },
    title:"Outbound POST to external host (possible exfiltration)", sev:"high",
    desc:"An HTTP POST carried data to an external server \u2014 a common data-exfiltration or C2-upload pattern.",
    suggestion:"Inspect the payload size and destination; correlate with beaconing to the same host." },
  { id:"T1071-UA", name:"Suspicious User-Agent", test:null,
    match:function(e){ var ua=(e.raw&&e.raw.ua)||""; var dst=e.raw&&e.raw.dst_ip; return /msie [67]\.0|\bcurl\b|\bwget\b|python-requests|libwww|winhttp|powershell/i.test(ua) && dst && classifyIp(dst)==="public"; },
    title:"Unusual HTTP User-Agent to external host", sev:"medium",
    desc:"The HTTP User-Agent is one commonly used by malware or automated tooling rather than a normal browser.",
    suggestion:"Correlate with the destination reputation and the requesting host." },
  { id:"T1110.001", name:"Brute Force (RDP/SSH)", test:null,
    match:function(e){ var t=(e.action+" "+rawStr(e)).toLowerCase(); return /brute.?force|\bt1110\.001\b|hydra|h05t.?scan/.test(t) && !/password spray/.test(t); },
    title:"Brute-force authentication attempts", sev:"high",
    desc:"Repeated failed authentications against a service (RDP/SSH/Windows), consistent with credential brute forcing.",
    suggestion:"Block the source, check for any successful login after the failures, and review exposed services." },
  { id:"T1566", name:"Phishing", test:null,
    match:function(e){
      var raw=e.raw||{}; var f=flattenObj(raw);
      var et=String(f.event_type||f.eventtype||f.category||f.mitre_technique||f.alert_name||"").toLowerCase();
      var emailCtx = !!(f.sender||f.recipient||f.subject||f.messageid||f.message_id||f.mailfrom||f.rcptto) ||
                     /mail|smtp|exchange|o365|office 365|defender for office|proofpoint|mimecast/i.test(String(f.source||f.product||f.log_source||f.vendor||""));
      var t=(e.action+" "+JSON.stringify(raw)).toLowerCase();
      // explicit phishing label / technique / email attachment — not merely a URL containing "phishing"
      if (/\bt1566\b|phishing email|malicious attachment|credential.?harvest/.test(t)) return true;
      if (et.indexOf("phish")>=0) return true;
      if (emailCtx && /phish|spoof|\.xlsm|\.docm/.test(t)) return true;
      return false;
    },
    title:"Phishing email / malicious attachment", sev:"medium",
    desc:"An inbound email showed phishing characteristics (spoofed sender, malicious attachment, or credential-harvest link).",
    suggestion:"Confirm the recipient did not open the attachment/link; pull the message and check for others in the campaign." },
  { id:"T1071.004", name:"DNS Tunneling", test:null,
    match:function(e){ var t=(e.action+" "+rawStr(e)).toLowerCase(); return /dns tunnel|\bt1071\.004\b/.test(t) || (e.raw && +e.raw.query_count>=100); },
    title:"DNS tunneling (data over DNS)", sev:"high",
    desc:"An unusually high volume of DNS queries or long/encoded subdomains suggests data is being tunneled over DNS.",
    suggestion:"Identify the host and domain, block the resolver path, and inspect for the exfiltrated data." },
  { id:"T1558.003", name:"Kerberoasting", test:null,
    match:function(e){ var t=(e.action+" "+rawStr(e)).toLowerCase(); return /kerberoast|kerberos.*tgs.*(rc4|0x17|encryption)|service ticket.*rc4|\bt1558\.003\b/.test(t); },
    title:"Kerberoasting (service ticket request)", sev:"high",
    desc:"A Kerberos TGS request pattern consistent with harvesting service tickets for offline password cracking.",
    suggestion:"Review the requesting account, rotate affected service-account passwords, and check for weak SPN passwords." },
  { id:"T1055", name:"Process Injection", test:null,
    match:function(e){ var t=(e.action+" "+rawStr(e)).toLowerCase(); return /process injection|createremotethread|\bt1055\b|reflective (dll|load)|hollow/.test(t); },
    title:"Process injection", sev:"high",
    desc:"A process wrote to or created a thread in another process's memory space \u2014 a stealthy code-execution technique.",
    suggestion:"Identify source and target process, capture memory, and hunt for the injected payload." },
  { id:"T1021.002", name:"Lateral Movement (PsExec/SMB)", test:null,
    match:function(e){ var t=(e.action+" "+rawStr(e)).toLowerCase(); return /psexec|psexesvc|paexec|\\\\[^\\]+\\admin\$|smbexec|\bwinrs\b|\bt1021\.002\b|\bt1570\b/.test(t); },
    title:"Lateral movement (PsExec / admin share)", sev:"high",
    desc:"Remote execution via SMB/PsExec-style tooling, commonly used to move between hosts.",
    suggestion:"Map source\u2192target, verify the account, and check both hosts for follow-on activity." },
  { id:"T1078", name:"Impossible Travel", test:null,
    match:function(e){ var t=(e.action+" "+rawStr(e)).toLowerCase(); return /impossible travel|t1078\b/.test(t); },
    title:"Impossible travel (geographically improbable logins)", sev:"high",
    desc:"The same account authenticated from distant locations within a time window too short to travel \u2014 a strong account-compromise signal.",
    suggestion:"Force re-authentication, review the sessions, and check for token theft or credential compromise." },
  { id:"T1486", name:"Ransomware", test:null,
    match:function(e){ var t=(e.action+" "+rawStr(e)).toLowerCase(); return /ransomware|\bt1486\b|mass file (encrypt|rename)|\.locked\b|shadowcopy delete/.test(t) || (e.raw && +e.raw.files_affected>=50); },
    title:"Ransomware / mass file encryption", sev:"high",
    desc:"A process encrypted or renamed a large number of files, or matched known ransomware behavior.",
    suggestion:"Isolate the host immediately, preserve a sample, identify patient zero, and check backups before recovery." },
  { id:"T1046", name:"Port / Network Scan", test:null,
    match:function(e){ var t=(e.action+" "+rawStr(e)).toLowerCase(); return /port scan|network scan|\bt1046\b/.test(t) || (e.raw && +e.raw.ports_scanned>=20); },
    title:"Port / service scanning", sev:"medium",
    desc:"A host probed many ports/services, consistent with reconnaissance before an attack.",
    suggestion:"Confirm whether the source is an authorized scanner; if not, block and watch for follow-on exploitation." },
  { id:"T1548", name:"Privilege Escalation", test:null,
    match:function(e){ var t=(e.action+" "+rawStr(e)).toLowerCase(); return /privilege escalation|\bt1548\b|\bt1068\b|getsystem|uac bypass|sudo abuse/.test(t); },
    title:"Privilege escalation", sev:"high",
    desc:"Activity consistent with elevating from a normal user to administrative/SYSTEM privileges.",
    suggestion:"Identify how elevation occurred, review what ran as the elevated context, and patch the vector." },
  { id:"T1105-DROP", name:"Dropper (executable written to disk)", test:null,
    match:function(e){ var f=flatOf(e); var path=String(f.filepath||f.targetfilename||f.image||e.action||"").toLowerCase(); return /file create|dropped|downloaded/.test((e.action||"").toLowerCase()+" "+JSON.stringify(f)) && /\.(exe|dll|ps1|scr|bat|hta|vbs)\b/.test(path) && /\\temp\\|\\public\\|\\programdata\\|\\appdata\\|\/tmp\/|\\downloads\\/.test(path); },
    title:"Executable written to a suspicious path (possible dropper)", sev:"medium",
    desc:"A binary or script was created in a world-writable / staging location commonly used to stage malware.",
    suggestion:"Hash the file and check reputation; identify the writing process and whether it ran." },
  { id:"NIDS", name:"IDS/IPS Signature Alert", test:null,
    match:function(e){ var f=flatOf(e); return (f.signature||f.signatureid||f.signature_id!==undefined) && /ids|ips|snort|suricata|signature|alert/.test((e.action+" "+JSON.stringify(f)).toLowerCase()); },
    title:"Network IDS/IPS signature triggered", sev:"medium",
    desc:"An intrusion-detection signature fired on this traffic. The signature itself names the suspected activity.",
    suggestion:"Read the signature, confirm it isn't a known false positive, and pivot on the source/destination." },
  { id:"T1071-IND", name:"C2 Indicator (domain/infrastructure)", test:null,
    match:function(e){ var t=(e.action+" "+rawStr(e)).toLowerCase(); return /\.onion\b|cobalt.?strike|\bcobalt.?beacon|command.?and.?control|\bc2 (outbound|server|channel)|reverse.?https beacon/.test(t); },
    title:"Connection to known C2 infrastructure pattern", sev:"high",
    desc:"The destination matches command-and-control infrastructure patterns (Tor .onion, Cobalt Strike beacon, named C2).",
    suggestion:"Block the destination, isolate the host, and hunt for the implant and its persistence." },
  { id:"T1048", name:"Data Exfiltration (volume)", test:null,
    match:function(e){ var t=(e.action+" "+rawStr(e)).toLowerCase(); return /data exfil|exfiltration|\bt1048\b/.test(t) || (e.raw && (+e.raw.bytes_sent>=1000000 || +e.raw.bytes_transferred>=1000000)); },
    title:"Data exfiltration (large transfer)", sev:"high",
    desc:"A large or anomalous outbound data transfer was observed, consistent with data theft.",
    suggestion:"Identify the destination and data, block the channel, and scope what was exposed." },
  { id:"T1078.004", name:"Rapid Multi-IP Login", test:null,
    group:function(evts){
      var byActor = {};
      evts.forEach(function(e){ if (/login/i.test(e.action) && !/fail/i.test(e.action)) (byActor[e.actor]=byActor[e.actor]||[]).push(e); });
      var out = [];
      for (var k in byActor) {
        var list = byActor[k];
        for (var i=1;i<list.length;i++) {
          if (list[i].ip !== list[i-1].ip) {
            var t1 = new Date(list[i-1].time).getTime(), t2 = new Date(list[i].time).getTime();
            if (Math.abs(t2-t1) < 1000*60*30) out.push({actor:k, events:[list[i-1], list[i]]});
          }
        }
      }
      return out;
    },
    title:"Same account logged in from 2 IPs within 30 min", sev:"medium",
    desc:"The same account authenticated from two different IPs within 30 minutes. Geographic distance is NOT computed, so a phone-plus-wifi user can trigger this. Confirm with geo/ASN enrichment before treating as takeover.",
    suggestion:"Check the two IPs' geo/ASN in the Investigate tab; if far apart, force a password reset and revoke sessions." },
  { id:"GD-HIGH", meta:true, name:"GuardDuty High Severity Finding", test:null,
    match:function(e){ return e.source === "GuardDuty" && typeof e.severity === "number" && e.severity >= 7; },
    title:"High severity GuardDuty finding", sev:"high",
    desc:"AWS GuardDuty flagged this finding with a severity score of 7.0 or higher, indicating a likely active threat (e.g. backdoor, exfiltration, or privilege escalation).",
    suggestion:"Isolate the affected resource, rotate any exposed credentials, and review CloudTrail logs for the account around the finding time." },
  { id:"GD-MED", meta:true, name:"GuardDuty Medium Severity Finding", test:null,
    match:function(e){ return e.source === "GuardDuty" && typeof e.severity === "number" && e.severity >= 4 && e.severity < 7; },
    title:"Medium severity GuardDuty finding", sev:"medium",
    desc:"AWS GuardDuty flagged this finding with a medium severity score (4.0-6.9), warranting review but not necessarily an active compromise.",
    suggestion:"Review the finding details and confirm whether the activity matches expected behavior for this resource." },
  { id:"T1190", name:"SQL Injection Attempt", test:null,
    match:function(e){ return e.attackTag === "SQL Injection"; },
    title:"SQL injection attempt detected", sev:"high",
    desc:"A request URI contained SQL injection patterns (e.g. UNION SELECT, OR 1=1), indicating an attempt to exploit an application database via an exposed endpoint.",
    suggestion:"Block the source IP at the WAF/firewall, patch the vulnerable endpoint with parameterized queries, and audit the database for unauthorized access." },
  { id:"T1190-XSS", name:"Cross-Site Scripting Attempt", test:null,
    match:function(e){ return e.attackTag === "XSS"; },
    title:"Cross-site scripting (XSS) attempt detected", sev:"high",
    desc:"A request contained script injection patterns (e.g. <script>, onerror=), indicating an attempt to inject client-side code.",
    suggestion:"Sanitize and encode all user input on output, apply a Content-Security-Policy header, and block the source IP if repeated." },
  { id:"T1083", name:"Path Traversal / File Disclosure", test:null,
    match:function(e){ return e.attackTag === "Path Traversal"; },
    title:"Path traversal attempt detected", sev:"high",
    desc:"A request attempted to access files outside the web root (e.g. ../../etc/passwd), which can expose sensitive system files.",
    suggestion:"Validate and normalize all file path input, restrict the web server process's filesystem permissions, and block the source IP." },
  { id:"T1110-WEB", name:"Repeated Sensitive Path Probing", test:null,
    group:function(evts){
      var byActor = {};
      evts.forEach(function(e){ if (e.attackTag === "Sensitive Path Probe" || e.attackTag === "WordPress Probe") { (byActor[e.actor]=byActor[e.actor]||[]).push(e); } });
      var out = [];
      for (var k in byActor) if (byActor[k].length >= 2) out.push({actor:k, count:byActor[k].length, events:byActor[k]});
      return out;
    },
    title:"Repeated probing of admin/sensitive paths", sev:"medium",
    desc:"The same source IP repeatedly requested admin panels, config files, or other sensitive paths, suggesting directory brute-forcing or reconnaissance.",
    suggestion:"Block or CAPTCHA-gate the source IP, restrict admin panel access by IP allowlist, and enable rate limiting." },
  { id:"T1071-WEB", name:"Suspicious Referrer / Malicious Redirect Chain", test:null,
    match:function(e){ return e.raw && typeof e.raw.referrer === "string" && /phishing|malicious|spam/i.test(e.raw.referrer); },
    title:"Traffic from known malicious/phishing referrer", sev:"medium",
    desc:"Requests arrived with a referrer header pointing to a known malicious or spam domain, often indicating referral spam or a phishing redirect chain.",
    suggestion:"Block the referring domain at the WAF, and review whether any user sessions originated from that referrer for account compromise." },

  /* ===== Behavioral layer (deterministic, explainable, low severity) =====
     These flag statistical oddities that signatures can't: they are HINTS, not verdicts.
     Each has strict guards so they stay quiet on benign/uniform logs.                 */
  { id:"BEH-VOL", name:"Behavior: Volume Outlier", test:null,
    group:function(evts){
      if (evts.length < 200) return [];                                    // too small to baseline
      var by={}; evts.forEach(function(e){ var k=(e.ip&&e.ip!=="-")?e.ip:(e.actor!=="unknown"?e.actor:null); if(k)(by[k]=by[k]||[]).push(e); });
      var keys=Object.keys(by); if(keys.length<8) return [];               // need a population to compare against
      var counts=keys.map(function(k){return by[k].length;}).sort(function(a,b){return a-b;});
      var median=counts[Math.floor(counts.length/2)]||1;
      var out=[];
      keys.forEach(function(k){
        var n=by[k].length;
        if (n>=30 && n>=10*median && n < evts.length*0.6)                  // 10x median, >=30 events, not "the whole log"
          out.push({actor:k, count:n, events:by[k].slice(0,200), note:n+" events vs median "+median});
      });
      return out.sort(function(a,b){return b.count-a.count;}).slice(0,3);  // top 3 only
    },
    title:"Entity with unusually high activity volume", sev:"low",
    desc:"One IP/user generated 10x or more the median activity of comparable entities in this log. High volume alone is not an attack (crawlers, batch jobs), but paired with any other signal it often marks scanners, brute forcing, or data staging.",
    suggestion:"Check what this entity was doing: if it also appears in brute-force/scan detections treat it as an attacker; if it is a known crawler or service account, allowlist it." },

  { id:"BEH-OFFHRS", name:"Behavior: Off-hours Authentication", test:null,
    group:function(evts){
      var timed=evts.filter(function(e){ return e.time && !isNaN(Date.parse(e.time)); });
      if (timed.length < 300) return [];
      var dayShare=timed.filter(function(e){ var h=new Date(e.time).getUTCHours(); return h>=6&&h<=23; }).length/timed.length;
      if (dayShare < 0.7) return [];                                       // no clear diurnal pattern -> can't call anything "off-hours"
      var hits=timed.filter(function(e){
        var h=new Date(e.time).getUTCHours();
        return h>=0&&h<6 && /login|logon|sign[- ]?in|sudo|su |ssh|rdp|vpn|password|privilege|admin/i.test(e.action||"");
      });
      if (!hits.length) return [];
      var by={}; hits.forEach(function(e){ var k=(e.actor!=="unknown"&&e.actor)?e.actor:(e.ip||"?"); (by[k]=by[k]||[]).push(e); });
      return Object.keys(by).map(function(k){ return {actor:k, count:by[k].length, events:by[k].slice(0,100)}; })
        .sort(function(a,b){return b.count-a.count;}).slice(0,3);
    },
    title:"Authentication activity in the quiet hours", sev:"low",
    desc:"Login/privilege activity occurred between 00:00-06:00 UTC in a log whose activity is otherwise clearly daytime-shaped. Attackers favor quiet hours; so do legitimate on-call admins and cron jobs.",
    suggestion:"Confirm whether this account is expected to work at that hour (on-call, automation). If not, verify the session and source IP." },

  { id:"BEH-RARE", name:"Behavior: Rare Process / Agent", test:null,
    group:function(evts){
      var vals={}, tot=0;
      var pick=function(e){ var f=flatOf(e); return lookupKeys(f,["process_name","processname","image","user_agent","useragent","ua","tool","program"]); };
      evts.forEach(function(e){ var v=pick(e); if(v){ v=String(v).slice(0,80); (vals[v]=vals[v]||[]).push(e); tot++; } });
      var names=Object.keys(vals);
      if (tot < 100 || names.length < 8) return [];                        // need diversity to judge rarity
      var out=[];
      names.forEach(function(v){
        if (vals[v].length===1 && !/mozilla|chrome|safari|curl|wget|python-requests|googlebot|bingbot/i.test(v))
          out.push({actor:v, count:1, events:vals[v]});
      });
      return out.slice(0,5);                                               // cap: a hint list, not a flood
    },
    title:"Process or agent seen only once", sev:"low",
    desc:"In a log with many distinct processes/user-agents, these appeared exactly once. One-off binaries and odd agents are how droppers, custom tooling, and hands-on-keyboard activity often first show up.",
    suggestion:"Check the file path, signer, and parent process (or requesting IP for an agent). Once-off is only suspicious if you can't explain it." }
];

// ── OWASP / raw-payload signatures ──────────────────────────────────────────
// The rules above classify *labeled* SIEM alerts. These catch raw attack PAYLOADS
// as they appear in WAF / proxy / web-server logs (URLs, bodies, headers).
var PAYLOAD_SIGS = [
  { id:"T1190-SQLI", name:"SQL Injection", sev:"high", re:/('|%27)\s*(or|and)\s*['"(]?\d|union(?:\s*all\s*|\s*|\()select|union\s*\(|;\s*drop\s+table|\bsleep\s*\(|waitfor\s+delay|xp_cmdshell|information_schema|@@version|\bor\s*1\s*=\s*1\b|extractvalue\s*\(|\bconvert\s*\(\s*int|\b0x27\b|benchmark\s*\(|'\s*--|\badmin'\s*--|'\s*\|\||\d'\s*=\s*'\d|procedure\s+analyse/i },
  { id:"T1059-XSS", name:"Cross-Site Scripting (XSS)", sev:"high", re:/<script|onerror\s*=|onload\s*=|javascript:|<svg[\/ >]|<img\s+src\s*=\s*x|onfocus\s*=|<iframe|document\.cookie|\balert\s*\(|onclick\s*=|<body\s+on|<input[^>]+onfocus/i },
  { id:"T1059-CMDI", name:"Command Injection", sev:"high", re:/;\s*(cat|ls|id|whoami|uname|nc|bash|sh|curl|wget|ping|type|dir|net)\b|\|\s*(whoami|id|bash|sh|nc|cat|type)\b|\$\([a-z]|`[a-z][\w .\-\/]*`|&&\s*(curl|wget|ping|nc|bash)|&\s*(type\s+[a-z]:|type\s+%|dir\s+[a-z]:|systeminfo\b|net\s+user\s+\/)|nc\s+-e|\/bin\/(ba)?sh\b|\|\|\s*ping|%0a\/bin|type\s+c:\\|win\.ini/i },
  { id:"T1083-LFI", name:"Path Traversal / LFI", sev:"high", re:/\.\.[\/\\]\.\.[\/\\]|%2e%2e[%2f\/]|\/etc\/(passwd|shadow|hosts|group)|\.\.%c0%af|php:\/\/filter|file:\/\/\/etc|\/proc\/self\/|(\.\.[\/\\]){2,}|\/var\/log\/|boot\.ini|win\.ini|(\.\.|%2e%2e)[\/\\%].*system32/i },
  { id:"T1190-SSRF", name:"SSRF (OWASP A01)", sev:"high", re:/169\.254\.169\.254|metadata\.google\.internal|computemetadata|gopher:\/\/|dict:\/\/|http:\/\/(localhost|127\.0\.0\.1|\[::1\])|:6379\b|:11211\b/i },
  { id:"T1190-XXE", name:"XML External Entity (XXE)", sev:"high", re:/<!entity|<!doctype[^>]*\[|system\s+["']file:|expect:\/\/|<!entity\s+%\s+\w+\s+system/i },
  { id:"T1190-SSTI", name:"Server-Side Template Injection", sev:"high", re:/\{\{\s*[\w'".*()\[\]]+\s*\}\}|\$\{\s*\d+\s*[*+]\s*\d+\s*\}|<%=\s*\d|#\{\s*\d|__class__|__mro__|__subclasses__|T\(java\.lang|config\.items\(\)/i },
  { id:"T1190-INJ", name:"LDAP / NoSQL Injection", sev:"high", re:/\)\(uid=\*|\)\(&\)|\{\s*["']?\$ne["']?\s*:|\{\s*["']?\$gt["']?\s*:|\[\$ne\]|\[\$gt\]|\$where\b|'\s*;\s*return\s+true/i },
  { id:"T1190-DESER", name:"Insecure Deserialization", sev:"high", re:/\brO0AB[A-Za-z0-9+\/]|O:\d+:"[a-z]|__proto__\[|!!python\/object|objectinputstream|java\.lang\.processbuilder|__reduce__/i },
  { id:"T1190-RCE", name:"Exploit / RCE (Log4Shell, ProxyShell, etc.)", sev:"high", re:/\$\{jndi:(ldap|rmi|dns|ldaps)|class\.module\.classloader|\(\)\s*\{\s*:\s*;\s*\}\s*;|autodiscover\.json\?@|x-beresource|vpns\/cfg\/smb|\$\{env:|\$\{lower:|\$\{::-/i },
  { id:"T1505.003", name:"Web Shell", sev:"high", re:/<\?php\s|eval\s*\(\s*\$_(post|get|request)|system\s*\(\s*\$_|assert\s*\(\s*\$_|\bc99\b|\bb374k\b|china.?chopper|antsword|weevely|(cmd|shell|webshell)\.(jsp|aspx|php)|runtime\.getruntime\(\)\.exec|\.php\?(cmd|pass|c|x)=/i },
  { id:"T1190-CRLF", name:"CRLF / HTTP Response Splitting", sev:"medium", re:/%0d%0a[a-z]|%0aset-cookie|%0acontent-length|\r\n(set-cookie|content-length)/i },
  { id:"T1595-SCAN", name:"Scanner / Recon Tool", sev:"medium", re:/\bsqlmap\b|\bnikto\b|nmap scripting|\bmasscan\b|gobuster|dirbuster|feroxbuster|wpscan|\bnessus\b|acunetix|burp\s?suite|\bhydra\b|zaproxy|\bnuclei\b|\bffuf\b/i },
  { id:"T1552-CLOUD", name:"Cloud Credential / Metadata Access", sev:"high", re:/\/latest\/(meta-data|api\/token)|computemetadata\/v1|\.aws\/credentials|\.git\/config|\bs3:\/\/|sts:assumerole|assume-role|kubectl\s+get\s+secrets|\blistbuckets\b/i },
  { id:"T1059-REVSHELL", name:"Reverse Shell", sev:"high", re:/nc\s+-e\s|bash\s+-i\b|\bsh\s+-i\b|\/bin\/bash\s+-c|mkfifo|bash\s+>&\s*\/dev\/tcp|>&\s*\/dev\/tcp|0<&\d|reverse\s+shell|fsockopen|socket\.socket|import\s+socket,subprocess|downloadstring|new-object\s+net\.webclient|\/dev\/tcp\//i },
  { id:"T1550-PTH", name:"Pass-the-Hash / Ticket Abuse", sev:"high", re:/pass-the-hash|pass-the-ticket|golden\s+ticket|\bkrbtgt\b|credential\s+stuffing|overpass-the-hash|silver\s+ticket/i },
  { id:"T1190-REDIR", name:"Open Redirect", sev:"medium", re:/[?&](next|url|redirect|returnurl|return_url|dest|destination|continue|out|go|u)=(https?%3a|https?:)?(\/\/|%2f%2f)|=https?:\/\/[a-z0-9.\-]+@/i },
  { id:"T1083-FILE", name:"Sensitive File / Path Access", sev:"high", re:/\/\.(env|git|svn|ssh|aws|htpasswd|htaccess|ds_store)\b|\/wp-config|\/web\.config|\/config\/(database|secrets|application)|\/(backup|dump|db|database)\.sql|\/actuator\/(env|heapdump|health|beans)|\/phpinfo|\/server-status|\bid_rsa\b|composer\.lock|\/debug\.log|\/manager\/html|\/api\/internal/i },
  { id:"T1548-MASSASSIGN", name:"Mass Assignment / Privilege Param", sev:"high", re:/["']?(isadmin|is_admin|is_superuser)["']?\s*[:=]\s*["']?(true|1)|["']?role["']?\s*[:=]\s*["']?(admin|administrator|root|superuser)|account_type["']?\s*[:=]\s*["']?admin|["']?privilege["']?\s*[:=]\s*["']?root|["']permissions["']\s*:\s*\[\s*["']\*|role=administrator/i },
  { id:"T1550-JWT", name:"JWT / Token Attack", sev:"high", re:/eyj[a-z0-9]{4,}\.eyj|["']?alg["']?\s*:\s*["']?none|jwt\s+(alg\s+)?none|alg[:\s]*none|jwt.{0,30}(tampered|forged|bypass|confusion)|kid.{0,12}(sql|inject|\.\.|\/dev)|hs256.{0,12}rs256|rs256.{0,12}hs256|session\s+fixation|token[\-\s]replay|jwt\s+signature/i },
  { id:"T1190-VERB", name:"HTTP Verb / Method Abuse", sev:"medium", re:/^\s*(trace|connect|propfind|track|move|copy)\s+\S|\b(put|delete)\s+\/(shell|api\/users\/\d|admin)|\bxst\b|options\s+\/admin|connect\s+\S+:\d+/i },
  { id:"T1190-SMUGGLE", name:"Request Smuggling / Host Header Injection", sev:"high", re:/transfer-encoding[\s\S]{0,60}(content-length|transfer-encoding)|content-length[\s\S]{0,60}transfer-encoding|x-forwarded-host:\s*[a-z0-9.\-]*(evil|attacker)|host:\s*(evil|attacker|localhost)\b|\bcl\.te\b|\bte\.cl\b|\bte\.te\b|request\s+smuggl|http\s+desync|host header (injection|poison)/i },
  { id:"T1190-PROTO", name:"Prototype Pollution", sev:"high", re:/__proto__|["']?constructor["']?\s*[:\[]\s*[\{"']?prototype|constructor\.prototype|constructor\[.{0,4}prototype/i },
  { id:"T1190-GRAPHQL", name:"GraphQL Abuse / Introspection", sev:"medium", re:/__schema\s*\{|introspection|__type\s*[\(\{]|mutation\s*\{[^}]*(delete|drop|admin|remove)|query\s*\{[^}]*id\s*:\s*["'][^"']*(or |union|=|1=1)|graphql[\s\S]{0,40}(batch|nested|alias|1000)|[?&]limit=9{4,}/i },
  { id:"T1190-CVE", name:"Known CVE Exploit Pattern", sev:"high", re:/\/mifs\/\.;\/|guestaccess\.cgi|telerik\.web\.ui|\/api\/v2\/cli|\+\+resource\+\+|\/remote\/login|\/cgi-bin\/\.%2e|rest_route=\/wp\/v2\/users|catalog\/\.\.\/|\bmoveit\b|goanywhere|confluence|cve-\d{4}-\d{3,}|class\.module\.classloader|\bognl\b|@java\.lang\.runtime|human2\.aspx|fgt_lang\?lang=|totp\/user-backup|multipart\/form-data.\)|allow_url_include|struts2?|%\{\(#|spring4shell/i },
  { id:"T1548-BAC", name:"Broken Access Control", sev:"medium", re:/\/api\/v\d\/admin|\/admin[\/\s].{0,45}(role=(user|guest)|unauthorized|user=guest)|(role=(user|guest)|user=guest).{0,45}\/admin|privilege escalation.{0,20}(horizontal|vertical)|vertical privilege/i },
  { id:"T1595-ENUM", name:"Forced Browsing / Enumeration", sev:"medium", re:/forced browsing|\benumeration\b|iterating\s+\d|mass data (scraping|scrap)|user(name)?\s+enum|sequential\s+(id|enum)|cross-tenant|cross-user|\bby user_?\s*\d|accessed by user\s+\d|\bidor\b|\bbola\b/i },
  { id:"T1499-RATE", name:"Rate Abuse / Resource Exhaustion", sev:"medium", re:/\d{3,}\s*requests?\s*(\/|per)\s*min|rate abuse|excessive data|\d{4,}\s+(login|requests)|api rate|\bdos\b|denial of service/i },
  { id:"T1190-CSVI", name:"CSV / Formula Injection", sev:"medium", re:/[=+\-@](cmd\s*\||hyperlink\s*\(|importxml\s*\(|importdata\s*\(|webservice\s*\(|msexcel\||\bdde\b)|@sum\([^)]*\)\s*[*+]/i },
  { id:"T1048-TUNNEL", name:"Data Exfiltration / Tunneling", sev:"high", re:/dns\s+tunnel|icmp\s+tunnel|data\s+exfil|exfiltrat|exfil\s+over|to\s+(dropbox|mega\.nz|pastebin|transfer\.sh|anonfiles)|\d{3,}\s?(mb|gb)\s+(post|upload|to\b)|\d{3,}\s+txt\s+quer|base64\s+encoded\s+exfil/i },
  { id:"T1071-C2FW", name:"C2 Framework / Beacon", sev:"high", re:/cobalt\s?strike|meterpreter|\bsliver\b|\bhavoc\b|\bmythic\b|powershell\s+empire|empire\s+(stager|launcher)|brute\s?ratel|posh.?c2|reverse_tcp|badger|apollo\s+agent|\bimplant\b|\bstager\b/i },
  { id:"T1059-XPATH", name:"XPath Injection", sev:"high", re:/\/\/\w+\[[^\]]*(text\(\)|position\(\)|'1'='1')|count\(\/\/|'\s*or\s*'1'='1'\s*or\s*''='|'\s*or\s*position\(\)/i }
];
// Canonicalize input the way a WAF does, to defeat encoding/obfuscation evasion:
// recursive URL-decode (double/triple encoding), entity-decode, strip inline comments,
// resolve Log4Shell lookups, collapse whitespace.
function normalizeForDetection(t, keepPlus){
  var s = String(t || "");
  for (var i=0;i<3;i++){
    var d;
    try { d = decodeURIComponent(keepPlus ? s : s.replace(/\+/g," ")); }
    catch(e){ d = s.replace(/%([0-9a-fA-F]{2})/g,function(m,h){ try{return String.fromCharCode(parseInt(h,16));}catch(_){return m;} }); }
    if (d === s) break; s = d;
  }
  s = s.replace(/&lt;/gi,"<").replace(/&gt;/gi,">").replace(/&quot;/gi,'"')
       .replace(/&#x([0-9a-fA-F]+);/g,function(m,c){ try{return String.fromCharCode(parseInt(c,16));}catch(e){return m;} })
       .replace(/&#(\d+);/g,function(m,c){ try{return String.fromCharCode(parseInt(c,10));}catch(e){return m;} });
  s = s.replace(/\/\*!(?:\d+)?([\s\S]*?)\*\//g," $1 ");                    // /*!50000UNION*/ -> UNION (keep content)
  s = s.replace(/\/\*[\s\S]*?\*\//g,"");                                    // UNI/**/ON -> UNION (remove entirely)
  s = s.replace(/\$\{[^{}]*?:-([^{}]*)\}/g,"$1").replace(/\$\{(?:lower|upper):([^{}]*)\}/gi,"$1"); // ${::-j}, ${lower:j}
  s = s.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g,"");  // strip NUL + control chars (%00 truncation evasion)
  s = s.replace(/[\t\r\n\u00a0\u2000-\u200b]+/g," ");
  return s.toLowerCase();
}
function sigProbe(e){
  if (e && e.__probe) return e.__probe;                                  // cache: the 30 payload-sig rules all call this per event
  var raw=(e.action||"")+" "+rawStr(e);
  var p = raw + " \n " + normalizeForDetection(raw) + " \n " + normalizeForDetection(raw,true);
  if (e && typeof e === "object") { try { Object.defineProperty(e,"__probe",{value:p,enumerable:false,configurable:true,writable:true}); } catch(_){ e.__probe=p; } }
  return p;
}
function payloadHits(text){
  var probe = text + " \n " + normalizeForDetection(text) + " \n " + normalizeForDetection(text,true);
  var out=[]; for(var i=0;i<PAYLOAD_SIGS.length;i++){ if(PAYLOAD_SIGS[i].re.test(probe)) out.push(PAYLOAD_SIGS[i]); } return out;
}
PAYLOAD_SIGS.forEach(function(sig){
  MITRE_RULES.push({ id:sig.id, name:sig.name, test:null,
    match:function(e){ return sig.re.test(sigProbe(e)); },
    title:sig.name+" pattern in request", sev:sig.sev,
    desc:"A raw "+sig.name+" pattern was seen in the request URL, body, or headers (after decoding).",
    suggestion:"Confirm whether the request succeeded, block the source, and check for follow-on activity." });
});






