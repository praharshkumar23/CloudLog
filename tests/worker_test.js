// Inline Web Worker parity test: runs the script in a simulated Worker scope (self===global,
// importScripts present, no document) and confirms the worker's parse+detect output matches
// the synchronous path exactly. Verifies engine correctness DOM-less; browser Blob/Worker
// plumbing is covered by the runtime sync fallback. Run: node worker_test.js [work.html]
const fs=require('fs'), {execSync}=require('child_process');
const FILE=process.argv[2]||'index.html';
const src=fs.readFileSync(FILE,'utf8').match(/<script id="cloudlog-main">([\s\S]*)<\/script>/)[1];
const raw=JSON.stringify([
  {timestamp:"2026-05-01T10:00:00Z",event_type:"Reverse Shell",severity:"Critical",command_line:"mimikatz sekurlsa::logonpasswords",source_ip:"192.168.56.105",user:"john"},
  {timestamp:"2026-05-01T10:00:01Z",event_type:"login",severity:"Info",source_ip:"10.0.0.5",user:"svc"},
  {timestamp:"2026-05-01T10:00:02Z",event_type:"web",severity:"High",command_line:"GET /?id=1 UNION SELECT pw FROM users",source_ip:"8.8.8.8",user:"x"},
  {timestamp:"2026-05-01T10:00:03Z",event_type:"scan",severity:"Medium",command_line:"nmap -sS 10.0.0.0/24",source_ip:"45.9.1.2",user:"y"}
]);
let pass=0,fail=0; const ck=(n,c)=>{ if(c)pass++; else{fail++;console.log("  FAIL",n);} };

// --- worker scope ---
global.self=global; global.importScripts=function(){}; let posted=null; global.postMessage=m=>{posted=m;};
new Function(src+'; globalThis.__WK=(typeof __IS_WORKER!=="undefined")&&__IS_WORKER; globalThis.__ONMSG=self.onmessage;')();
ck("detects-worker-context", global.__WK===true);
ck("onmessage-installed", typeof global.__ONMSG==="function");
global.__ONMSG({data:{raw:raw,source:"auto",st:{allowlist:[],blocklist:[],customRules:[],verdicts:{},assetCriticality:{},memoryBad:[]}}});
ck("worker-ok", posted&&posted.ok===true);
ck("worker-parsed", posted&&posted.logs&&posted.logs.length===4);
ck("dets-cloneable-no-fn", posted&&posted.dets&&posted.dets.every(d=>typeof d.rule.match==="undefined"&&Array.isArray(d.evi)));
const wIds=(posted&&posted.dets?posted.dets.map(d=>d.rule.id).sort():[]);

// --- sync baseline in a clean child (document defined => __IS_WORKER false) ---
fs.writeFileSync('/tmp/_syncbase.js',`
const fs=require('fs');const el=()=>({setAttribute(){},style:{},classList:{add(){},remove(){},contains(){return true}},querySelectorAll:()=>[],parentNode:null,appendChild(){},value:"",innerHTML:"",textContent:"",getContext:()=>({})});
global.document={getElementById:el,querySelectorAll:()=>[],querySelector:el,createElement:el,createElementNS:el,addEventListener(){},body:{appendChild(){}}};global.window={addEventListener(){}};global.fetch=()=>Promise.reject();global.AbortController=function(){this.abort=()=>{};this.signal={};};global.btoa=s=>Buffer.from(s).toString("base64");global.atob=b=>Buffer.from(b,"base64").toString("binary");global.alert=()=>{};
const src=fs.readFileSync(${JSON.stringify(FILE)},'utf8').match(/<script id="cloudlog-main">([\\s\\S]*)<\\/script>/)[1];
new Function(src+';globalThis.__S={parseAnyLog,runDetections};')();
const T=globalThis.__S;const logs=T.parseAnyLog(${JSON.stringify(raw)},"auto");
console.log(JSON.stringify({logs:logs.length,dets:T.runDetections(logs).map(d=>d.rule.id).sort()}));`);
const sync=JSON.parse(execSync('node /tmp/_syncbase.js').toString());
ck("logs-match-sync", posted.logs.length===sync.logs);
ck("detset-matches-sync", JSON.stringify(wIds)===JSON.stringify(sync.dets));

console.log("WORKER PARITY: PASS "+pass+" / FAIL "+fail);
process.exit(fail?1:0);
