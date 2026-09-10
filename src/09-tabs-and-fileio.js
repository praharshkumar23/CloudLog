/* ============================================================
 * CloudLog — 09-tabs-and-fileio.js
 * Tab switching, file upload, filtering, downloads, settings-modal wiring.
 * Part of index.html; assembled by build.js. Do not add a <script> wrapper.
 * ============================================================ */
function switchToTab(name) {
  document.querySelectorAll(".tab").forEach(function(t){t.classList.remove("active");});
  document.querySelectorAll(".tab-panel").forEach(function(p){p.classList.remove("active");});
  var tab = document.querySelector('.tab[data-tab="'+name+'"]');
  if (tab) tab.classList.add("active");
  var panel = document.getElementById("panel-"+name);
  if (panel) panel.classList.add("active");
  if (typeof renderTab === "function") renderTab(name);   // lazy: build heavy tab content on first open
  if (name === "hunt" && typeof renderHunt === "function") renderHunt();
}
function switchToSummaryTab() { switchToTab("summary"); }

document.querySelectorAll(".tab").forEach(function(tab){
  tab.onclick = function(){ switchToTab(this.getAttribute("data-tab")); };
});

/* ---------- File loading with visible error handling ---------- */
function showUploadError(msg) {
  var el = document.getElementById("uploadError");
  if (!el) return;
  if (!msg) { el.classList.add("hidden"); el.textContent = ""; return; }
  el.textContent = msg;
  el.classList.remove("hidden");
}

function loadFile(file) {
  showUploadError("");
  var name = (file.name || "").toLowerCase();
  var source = name.indexOf("guardduty")>=0 ? "GuardDuty"
    : (name.indexOf("apache")>=0 || name.indexOf("access")>=0) ? "Apache"
    : name.indexOf("azure")>=0 ? "Azure"
    : name.indexOf("okta")>=0 ? "Okta"
    : name.indexOf("gcp")>=0 ? "GCP"
    : name.indexOf("win")>=0 ? "Windows"
    : (name.indexOf("aws")>=0 || name.indexOf("cloudtrail")>=0) ? "AWS"
    : "Generic";

  var isPcap = /\.(pcap|pcapng|cap)$/i.test(name);
  var reader = new FileReader();
  reader.onerror = function(){
    showUploadError("Could not read the file. Please try again or check the file is not corrupted.");
  };
  reader.onload = function(e){
    try {
      if (isPcap) {
        var res = parsePcap(e.target.result);
        if (res.err) { showUploadError(res.err); return; }
        state.source = "PCAP"; state.logs = res.events; __autoEnrichSig = null;
        if (!state.logs.length) showUploadError("The capture was read but no IPv4 packets were found to analyze.");
      } else {
        state.source = source;
        var _text = e.target.result;
        // Large files: run the engine in the inline Web Worker so the UI never freezes.
        // Any failure (no Worker support, worker error, timeout) falls back to sync inside __analyzeAsync.
        if (_text && _text.length > 300000 && typeof window.__analyzeAsync === "function") {
          var _t0 = document.getElementById("dropzone"); if (_t0) { try { _t0.setAttribute("data-busy","1"); } catch(e){} }
          window.__analyzeAsync(_text, source, function(logs){
            state.logs = logs; __autoEnrichSig = null; resetViewState();
            if (_t0) { try { _t0.removeAttribute("data-busy"); } catch(e){} }
            if (!state.logs.length) showUploadError("The file was read but no events could be extracted. Check that it contains an array of log objects.");
            applyFilter(); switchToSummaryTab();
          });
          return;   // async path renders in the callback
        }
        state.logs = parseAnyLog(_text, source); __autoEnrichSig = null; resetViewState();
        if (!state.logs.length) showUploadError("The file was read but no events could be extracted. Check that it contains an array of log objects.");
      }
      applyFilter();
      switchToSummaryTab();
    } catch (err) {
      showUploadError("Something went wrong while analyzing this file: " + err.message);
    }
  };
  if (isPcap) reader.readAsArrayBuffer(file); else reader.readAsText(file);
}

function applyFilter() {
  var q = document.getElementById("search").value.toLowerCase().trim();
  var list = q ? state.logs.filter(function(r){
    var text = (r.time+" "+r.actor+" "+r.action+" "+r.ip).toLowerCase();
    return text.indexOf(q) >= 0;
  }) : state.logs;   // no query -> the full dataset itself (keeps detection cache warm)
  render(list);
}

document.getElementById("fileInput").onchange = function(e){ if (e.target.files[0]) loadFile(e.target.files[0]); };
var __searchDeb; document.getElementById("search").oninput = function(){ clearTimeout(__searchDeb); __searchDeb = setTimeout(applyFilter, 250); };  // debounced: rebuild once typing stops

var sortBtn = document.getElementById("sortToggle");
if (sortBtn) {
  sortBtn.onclick = function(){
    state.sortDesc = !state.sortDesc;
    sortBtn.innerHTML = state.sortDesc ? "&#8595; Newest first" : "&#8593; Oldest first";
    applyFilter();
  };
}

var PCAP_SAMPLE_B64="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MCkNCkNvbm5lY3Rpb246IGNsb3NlDQoNCjOYg2ZgrgoAsgAAALIAAAAAESIzRFWqu8zd7v8IAEUAAKQAAQAAQAZcfQoAADItk+YRwTYAUAAAAAAAAAAAUBggAN9pAABHRVQgL2dhdGUucGhwP2lkPTEwMDcgSFRUUC8xLjENCkhvc3Q6IGtkN2Yzang5cXoyLnRvcA0KVXNlci1BZ2VudDogTW96aWxsYS80LjAgKGNvbXBhdGlibGU7IE1TSUUgNi4wKQ0KQ29ubmVjdGlvbjogY2xvc2UNCg0KUZiDZmCuCgBLBQAASwUAAAARIjNEVaq7zN3u/wgARQAFPQABAABABlfkCgAAMi2T5hHBXABQAAAAAAAAAABQGCAA3fQAAFBPU1QgL3VwbG9hZC5waHAgSFRUUC8xLjENCkhvc3Q6IGtkN2Yzang5cXoyLnRvcA0KVXNlci1BZ2VudDogTW96aWxsYS80LjANCkNvbnRlbnQtTGVuZ3RoOiA5MDAwMDANCg0KQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBU5iDZmCuCgA2AAAANgAAAAARIjNEVaq7zN3u/wgARQAAKAABAABABpmfCgAAMo76SAS/6wG7AAAAAAAAAABQAiAA7QsAAFSYg2ZgrgoANgAAADYAAAAAESIzRFWqu8zd7v8IAEUAACgAAQAAQAaZnwoAADKO+kgEwdYBuwAAAAAAAAAAUAIgAOsgAABVmINmYK4KADYAAAA2AAAAABEiM0RVqrvM3e7/CABFAAAoAAEAAEAGmZ8KAAAyjvpIBMDwAbsAAAAAAAAAAFACIADsBgAA";
document.querySelectorAll("[data-sample]").forEach(function(btn){
  btn.onclick = function(){
    var key = this.getAttribute("data-sample");
    // never silently wipe a loaded log with a sample
    if (state.logs.length && typeof confirm === "function" &&
        !confirm("You already have "+state.logs.length.toLocaleString()+" events loaded ("+state.source+").\n\nReplace them with the '"+(this.textContent||key).trim()+"' SAMPLE data?")) return;
    resetViewState();
    showUploadError("");
    if (key === "pcap") {
      var res = parsePcap(b64ToArrayBuffer(PCAP_SAMPLE_B64));
      if (res.err) { showUploadError(res.err); return; }
      state.source = "PCAP"; state.logs = res.events;
      applyFilter(); switchToSummaryTab(); return;
    }
    var names = {aws:"AWS", azure:"Azure", okta:"Okta", gcp:"GCP", windows:"Windows", generic:"Generic", guardduty:"GuardDuty", apache:"Apache", edr:"Sysmon"};
    state.source = names[key];
    state.logs = samples[key];
    applyFilter();
    switchToSummaryTab();
  };
});

function download(content, mime, name) {
  var a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([content], {type:mime}));
  a.download = name; a.click();
}
document.getElementById("exportCsv").onclick = function(){
  function csvCell(v){ v = v==null?"":String(v); if(/^[=+\-@\t\r]/.test(v)) v="'"+v; if(/[",\n\r]/.test(v)) v='"'+v.replace(/"/g,'""')+'"'; return v; }
  var rows = ["time,actor,action,ip,source"];
  state.filtered.forEach(function(r){ rows.push([r.time,r.actor,r.action,r.ip,r.source].map(csvCell).join(",")); });
  download(rows.join("\n"), "text/csv", "cloud-logs.csv");
};

/* ============================================================================
   AI ANALYST  —  local-first triage + optional opt-in redacted cloud Q&A
   Design rule for a privacy tool: nothing leaves the browser unless the user
   explicitly opts in, provides their own key, and can see the redacted payload.
   ========================================================================== */






