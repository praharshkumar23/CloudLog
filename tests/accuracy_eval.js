const fs=require('fs');
function mkEl(){return {setAttribute(){},getAttribute(){return null;},style:{},classList:{add(){},remove(){},contains:()=>false},innerHTML:"",textContent:"",value:"",querySelectorAll:()=>({forEach(){}}),addEventListener(){},getContext(){return{};},closest:()=>null};}
global.document={getElementById:mkEl,querySelector:mkEl,querySelectorAll:()=>({forEach(){}}),createElement:mkEl,createElementNS:mkEl,addEventListener(){},body:{appendChild(){}},readyState:"complete"};
global.window={addEventListener(){}};global.matchMedia=()=>({matches:false,addEventListener(){}});global.requestAnimationFrame=()=>0;global.localStorage={getItem:()=>null,setItem(){}};
global.fetch=()=>Promise.reject();global.AbortController=function(){this.abort=()=>{};this.signal={};};global.btoa=s=>Buffer.from(s).toString("base64");global.atob=b=>Buffer.from(b,"base64").toString("binary");
const src=fs.readFileSync(''+ (process.argv[2]||'index.html') +'','utf8').match(/<script id="cloudlog-main">([\s\S]*)<\/script>/)[1];
new Function(src+";globalThis.__={parseAnyLog,severityOf,MITRE_RULES,runDetections};")();
const T=globalThis.__;
// Requires a labeled dataset (fields: severity, mitre_technique, lab_attack). Not shipped in the
// repo (it is lab data). Pass a path as argv[3], or place it at ./dataset/labeled.json. Skips cleanly
// in CI when absent so the pipeline stays green without private data.
const DS = process.argv[3] || "./dataset/labeled.json";
if (!fs.existsSync(DS)) { console.log("accuracy_eval: no labeled dataset at "+DS+" — skipped (provide one to measure recall/precision)."); process.exit(0); }
const raw=JSON.parse(fs.readFileSync(DS,"utf8"));
const truth=raw.map(e=>({sev:e.severity, tech:e.mitre_technique}));
const blind=raw.map(e=>{const c={...e};delete c.severity;delete c.mitre_technique;delete c.lab_attack;return c;});
const ev=T.parseAnyLog(JSON.stringify(blind),"auto");
// "caught" = event severity flagged OR any detection rule matches this specific event
function caught(e){
  if(T.severityOf(e)!=="info") return true;
  for(var i=0;i<T.MITRE_RULES.length;i++){ var r=T.MITRE_RULES[i]; if(r.match){ try{ if(r.match(e)) return true; }catch(x){} } }
  return false;
}
let TP=0,FP=0,FN=0,TN=0,amb=0;
ev.forEach((e,i)=>{ const g=truth[i]; const f=caught(e);
  if(g.sev==="Critical"||g.sev==="High"){ f?TP++:FN++; }
  else if(g.sev==="Info"){ f?FP++:TN++; } else amb++; });
const prec=TP/(TP+FP||1),rec=TP/(TP+FN||1),f1=2*prec*rec/((prec+rec)||1),fpr=FP/(FP+TN||1);
console.log("DETECTION (rules+severity):  TP="+TP+" FP="+FP+" FN="+FN+" TN="+TN);
console.log("  Precision="+(prec*100).toFixed(1)+"%  Recall="+(rec*100).toFixed(1)+"%  F1="+(f1*100).toFixed(1)+"%  FPR="+(fpr*100).toFixed(1)+"%");
const byTech={};
ev.forEach((e,i)=>{const t=truth[i].tech;if(!t)return;byTech[t]=byTech[t]||{n:0,c:0};byTech[t].n++;if(caught(e))byTech[t].c++;});
console.log("\nPER-TECHNIQUE RECALL:");
Object.entries(byTech).sort((a,b)=>b[1].n-a[1].n).forEach(([t,v])=>{const r=100*v.c/v.n;console.log("  "+t.padEnd(12)+" "+v.c+"/"+v.n+" ("+r.toFixed(0)+"%)"+(r<80?"  <-- weak":""));});
