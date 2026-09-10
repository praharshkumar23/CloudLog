/* Self-contained detection smoke test — no external data, safe for CI.
 * Verifies the detection engine end to end on tiny embedded logs:
 *   - a signature detection fires (mimikatz / credential dumping)
 *   - the stateful sequence engine fires on an ordered attack and stays silent on benign activity
 *   - a completely benign log produces zero malicious verdicts (false-positive guard)
 * Usage: node tests/detection_smoke.js [path-to-index.html]
 */
const fs = require('fs');
function mkEl(){return {setAttribute(){},getAttribute(){return null;},style:{},classList:{add(){},remove(){},contains:()=>false},innerHTML:"",textContent:"",value:"",querySelectorAll:()=>({forEach(){}}),addEventListener(){},getContext(){return{};},closest:()=>null};}
global.document={getElementById:mkEl,querySelector:mkEl,querySelectorAll:()=>({forEach(){}}),createElement:mkEl,createElementNS:mkEl,addEventListener(){},body:{appendChild(){}},readyState:"complete"};
global.window={addEventListener(){}};global.matchMedia=()=>({matches:false,addEventListener(){}});global.requestAnimationFrame=()=>0;global.localStorage={getItem:()=>null,setItem(){}};
global.fetch=()=>Promise.reject();global.AbortController=function(){this.abort=()=>{};this.signal={};};global.btoa=s=>Buffer.from(s).toString("base64");global.atob=b=>Buffer.from(b,"base64").toString("binary");

const path = process.argv[2] || "index.html";
const src = fs.readFileSync(path,"utf8").match(/<script id="cloudlog-main">([\s\S]*)<\/script>/)[1];
new Function(src+";globalThis.__={parseAnyLog,severityOf,runDetections,runStatefulDetections};")();
const T = globalThis.__;

let pass=0, fail=0;
const ck=(n,c,x)=>{ if(c) pass++; else { fail++; console.log("  FAIL", n, x||""); } };

// 1) signature: credential dumping fires
const cred = T.parseAnyLog(JSON.stringify([
  {timestamp:"2026-05-01T10:00:00Z", command_line:"mimikatz.exe sekurlsa::logonpasswords", user:"attacker", source_ip:"10.0.0.9"}
]),"auto");
ck("signature-cred-dumping-fires", T.runDetections(cred).some(d=>/T1003|credential/i.test(d.rule.id+d.rule.name)));

// 2) stateful: ordered account-takeover sequence fires
const ato = T.parseAnyLog(JSON.stringify([
  {timestamp:"2026-05-01T10:00:00Z", event_type:"Failed Login", event_code:4625, user:"jdoe"},
  {timestamp:"2026-05-01T10:00:30Z", event_type:"Logon Success", event_code:4624, user:"jdoe"},
  {timestamp:"2026-05-01T10:01:00Z", command_line:"powershell -enc SQBFAFgA", event_code:4688, user:"jdoe"}
]),"auto");
ck("stateful-ATO-fires", T.runStatefulDetections(ato).some(d=>d.rule.id==="SEQ-ATO"));

// 3) stateful FP guard: out-of-order (exec before login) must NOT fire
const oo = T.parseAnyLog(JSON.stringify([
  {timestamp:"2026-05-01T10:00:00Z", command_line:"powershell", event_code:4688, user:"svc"},
  {timestamp:"2026-05-01T10:05:00Z", event_type:"Failed Login", event_code:4625, user:"svc"}
]),"auto");
ck("stateful-out-of-order-silent", !T.runStatefulDetections(oo).some(d=>d.rule.id==="SEQ-ATO"));

// 4) benign log: zero malicious verdicts
const benign = T.parseAnyLog(JSON.stringify([
  {timestamp:"2026-05-01T09:00:00Z", event_type:"Logon Success", event_code:4624, user:"alice"},
  {timestamp:"2026-05-01T09:05:00Z", command_line:"powershell Get-Process", user:"alice"},
  {timestamp:"2026-05-01T09:10:00Z", message:"scheduled backup completed", event_type:"Info"}
]),"auto");
ck("benign-zero-malicious", benign.filter(e=>T.severityOf(e)==="malicious").length===0);

console.log("DETECTION SMOKE: PASS "+pass+" / FAIL "+fail);
process.exit(fail?1:0);
