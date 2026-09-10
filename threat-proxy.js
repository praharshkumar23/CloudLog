#!/usr/bin/env node
/* ============================================================================
   threat-proxy.js  —  local threat-intel enrichment proxy for CloudLog
   WHY THIS EXISTS: browsers cannot call VirusTotal/AbuseIPDB/OTX/urlscan directly
   (no CORS) and you must never ship API keys inside client-side HTML. This tiny
   proxy runs on YOUR machine, keeps keys in env vars, enforces the private-IP
   block server-side too, caches results, and lets the local tool call it.

   RUN:
     export VT_KEY=...            # VirusTotal v3
     export ABUSEIPDB_KEY=...     # AbuseIPDB v2
     export OTX_KEY=...           # AlienVault OTX
     export URLSCAN_KEY=...       # urlscan.io (passive search)
     export GSB_KEY=...           # Google Safe Browsing v4
     node threat-proxy.js         # listens on http://localhost:8787
   Only services whose key is set are queried. Zero npm dependencies.
   ========================================================================== */
const http = require("http");
const https = require("https");
const { URL } = require("url");

const PORT = process.env.PORT || 8787;
const KEYS = { vt: process.env.VT_KEY, abuse: process.env.ABUSEIPDB_KEY, otx: process.env.OTX_KEY, urlscan: process.env.URLSCAN_KEY, gsb: process.env.GSB_KEY,
               greynoise: process.env.GREYNOISE_KEY, shodan: process.env.SHODAN_KEY, abusech: process.env.ABUSECH_KEY };
const GEO_ENABLED = process.env.GEO !== "0"; // free keyless ip-api geo/ASN, on by default
const cache = new Map(); // type|value -> {ts, data}
const TTL = 30 * 60 * 1000;

function isPrivateIp(ip) {
  const p = ip.split("."); if (p.length !== 4) return true;
  const n = p.map(Number); if (n.some(x => isNaN(x) || x < 0 || x > 255)) return true;
  if (n[0] === 10) return true;
  if (n[0] === 172 && n[1] >= 16 && n[1] <= 31) return true;
  if (n[0] === 192 && n[1] === 168) return true;
  if (n[0] === 127 || n[0] === 0) return true;
  if (n[0] === 169 && n[1] === 254) return true;
  if (n[0] === 100 && n[1] >= 64 && n[1] <= 127) return true;
  if (n[0] >= 224) return true;
  return false;
}

function req(method, urlStr, headers, body) {
  return new Promise((resolve) => {
    const u = new URL(urlStr);
    const lib = u.protocol === "http:" ? http : https;
    const opts = { method, hostname: u.hostname, port: u.port || undefined, path: u.pathname + u.search, headers: headers || {} };
    const r = lib.request(opts, (res) => {
      let d = ""; res.on("data", c => d += c);
      res.on("end", () => { let j; try { j = JSON.parse(d); } catch (e) { j = { raw: d.slice(0, 400) }; } resolve({ status: res.statusCode, json: j }); });
    });
    r.on("error", (e) => resolve({ status: 0, json: { error: String(e.message) } }));
    if (body) r.write(body);
    r.end();
  });
}

async function enrich(type, value) {
  const key = type + "|" + value, hit = cache.get(key);
  if (hit && Date.now() - hit.ts < TTL) return hit.data;
  const results = [];

  if (type === "ip" && isPrivateIp(value)) {
    const data = { blocked: true, reason: "private/reserved IP — refused server-side", results: [] };
    cache.set(key, { ts: Date.now(), data }); return data;
  }

  // VirusTotal
  if (KEYS.vt) {
    let path = type === "ip" ? "ip_addresses/" + value : type === "domain" ? "domains/" + value
      : type === "hash" ? "files/" + value : type === "url" ? "urls/" + Buffer.from(value).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_") : null;
    if (path) { const r = await req("GET", "https://www.virustotal.com/api/v3/" + path, { "x-apikey": KEYS.vt });
      const st = r.json && r.json.data && r.json.data.attributes && r.json.data.attributes.last_analysis_stats;
      results.push({ service: "VirusTotal", found: r.status === 200, malicious: st ? st.malicious : null, harmless: st ? st.harmless : null, detail: st ? (st.malicious + "/" + (st.malicious + st.harmless + st.undetected + st.suspicious) + " engines flagged") : (r.json.error ? r.json.error.message : "no data") }); }
  }
  // AbuseIPDB (ip only)
  if (KEYS.abuse && type === "ip") {
    const r = await req("GET", "https://api.abuseipdb.com/api/v2/check?ipAddress=" + encodeURIComponent(value) + "&maxAgeInDays=90", { Key: KEYS.abuse, Accept: "application/json" });
    const d = r.json && r.json.data;
    results.push({ service: "AbuseIPDB", found: !!d, malicious: d ? d.abuseConfidenceScore : null, detail: d ? (d.abuseConfidenceScore + "% confidence, " + d.totalReports + " reports, " + (d.countryCode || "?") + (d.isp ? ", " + d.isp : "")) : "no data" });
  }
  // OTX
  if (KEYS.otx) {
    const seg = type === "ip" ? "IPv4/" + value : type === "domain" ? "domain/" + value : type === "hash" ? "file/" + value : type === "url" ? "url/" + encodeURIComponent(value) : null;
    if (seg) { const r = await req("GET", "https://otx.alienvault.com/api/v1/indicators/" + seg + "/general", { "X-OTX-API-KEY": KEYS.otx });
      const pc = r.json && r.json.pulse_info && r.json.pulse_info.count;
      results.push({ service: "OTX", found: r.status === 200, malicious: pc || 0, detail: (pc || 0) + " threat pulse(s)" + (r.json.pulse_info && r.json.pulse_info.pulses && r.json.pulse_info.pulses[0] ? " e.g. " + r.json.pulse_info.pulses[0].name : "") }); }
  }
  // urlscan (passive search)
  if (KEYS.urlscan && type !== "hash") {
    const q = type === "ip" ? "ip:" + value : type === "domain" ? "domain:" + value : "page.url:\"" + value + "\"";
    const r = await req("GET", "https://urlscan.io/api/v1/search/?q=" + encodeURIComponent(q) + "&size=1", { "API-Key": KEYS.urlscan });
    const total = r.json && r.json.total;
    results.push({ service: "urlscan", found: total > 0, malicious: null, detail: (total || 0) + " historical scan(s)" + (r.json.results && r.json.results[0] ? ", last verdict: " + (r.json.results[0].verdicts && r.json.results[0].verdicts.overall && r.json.results[0].verdicts.overall.malicious ? "malicious" : "clean") : "") });
  }
  // Google Safe Browsing (url/domain)
  if (KEYS.gsb && (type === "url" || type === "domain")) {
    const target = type === "url" ? value : "http://" + value;
    const body = JSON.stringify({ client: { clientId: "cloudlog", clientVersion: "1.0" }, threatInfo: { threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"], platformTypes: ["ANY_PLATFORM"], threatEntryTypes: ["URL"], threatEntries: [{ url: target }] } });
    const r = await req("POST", "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + encodeURIComponent(KEYS.gsb), { "Content-Type": "application/json" }, body);
    const matched = r.json && r.json.matches && r.json.matches.length;
    results.push({ service: "SafeBrowsing", found: true, malicious: matched ? 1 : 0, detail: matched ? "FLAGGED: " + r.json.matches.map(m => m.threatType).join(", ") : "no match (clean)" });
  }

  // GreyNoise Community (ip) — scanner/benign-noise classification (huge triage signal)
  if (KEYS.greynoise && type === "ip") {
    const r = await req("GET", "https://api.greynoise.io/v3/community/" + value, { key: KEYS.greynoise, Accept: "application/json" });
    const j = r.json || {};
    results.push({ service: "GreyNoise", found: r.status === 200, malicious: j.classification === "malicious" ? 1 : 0,
      detail: j.noise !== undefined ? (j.classification || "unknown") + (j.name ? " (" + j.name + ")" : "") + (j.noise ? " — internet background noise" : "") : (j.message || "no data") });
  }
  // Shodan (ip) — exposed services / org
  if (KEYS.shodan && type === "ip") {
    const r = await req("GET", "https://api.shodan.io/shodan/host/" + value + "?key=" + encodeURIComponent(KEYS.shodan), {});
    const j = r.json || {};
    results.push({ service: "Shodan", found: r.status === 200, malicious: null,
      detail: j.ports ? (j.org || "?") + " — ports " + (j.ports.slice(0, 12).join(",")) + (j.os ? " (" + j.os + ")" : "") : (j.error || "no data") });
  }
  // abuse.ch ThreatFox (ip/domain/url/hash) — community IOC database
  if (KEYS.abusech && type !== "ip") {
    const r = await req("POST", "https://threatfox-api.abuse.ch/api/v1/", { "Content-Type": "application/json", "Auth-Key": KEYS.abusech }, JSON.stringify({ query: "search_ioc", search_term: value }));
    const j = r.json || {}; const hit = j.query_status === "ok" && j.data && j.data.length;
    results.push({ service: "ThreatFox", found: !!hit, malicious: hit ? 1 : 0, detail: hit ? (j.data[0].malware_printable || j.data[0].threat_type) + " (conf " + j.data[0].confidence_level + "%)" : "no match" });
  }
  // abuse.ch MalwareBazaar (hash)
  if (KEYS.abusech && type === "hash") {
    const r = await req("POST", "https://mb-api.abuse.ch/api/v1/", { "Content-Type": "application/x-www-form-urlencoded", "Auth-Key": KEYS.abusech }, "query=get_info&hash=" + encodeURIComponent(value));
    const j = r.json || {}; const hit = j.query_status === "ok" && j.data && j.data.length;
    results.push({ service: "MalwareBazaar", found: !!hit, malicious: hit ? 1 : 0, detail: hit ? (j.data[0].signature || j.data[0].file_type || "known sample") : "not in corpus" });
  }
  // ip-api geo/ASN (ip) — free, keyless; flags hosting/proxy
  if (GEO_ENABLED && type === "ip") {
    const r = await req("GET", "http://ip-api.com/json/" + value + "?fields=status,country,regionName,isp,org,as,proxy,hosting,mobile", {});
    const j = r.json || {};
    if (j.status === "success") results.push({ service: "Geo/ASN", found: true, malicious: null,
      detail: [j.country, j.isp || j.org, j.as].filter(Boolean).join(" · ") + (j.hosting ? " [hosting]" : "") + (j.proxy ? " [proxy/VPN]" : "") });
  }

  const data = { blocked: false, results };
  cache.set(key, { ts: Date.now(), data });
  return data;
}

http.createServer(async (rq, rs) => {
  rs.setHeader("Access-Control-Allow-Origin", "*");
  rs.setHeader("Access-Control-Allow-Headers", "*");
  if (rq.method === "OPTIONS") { rs.writeHead(204); return rs.end(); }
  const u = new URL(rq.url, "http://localhost");
  if (u.pathname === "/health") { rs.writeHead(200, { "Content-Type": "application/json" }); return rs.end(JSON.stringify({ ok: true, services: Object.keys(KEYS).filter(k => KEYS[k]).concat(GEO_ENABLED ? ["geo"] : []) })); }
  if (u.pathname === "/enrich") {
    const type = u.searchParams.get("type"), value = u.searchParams.get("value");
    if (!type || !value) { rs.writeHead(400); return rs.end(JSON.stringify({ error: "type and value required" })); }
    try { const data = await enrich(type, value); rs.writeHead(200, { "Content-Type": "application/json" }); rs.end(JSON.stringify(data)); }
    catch (e) { rs.writeHead(500); rs.end(JSON.stringify({ error: String(e.message) })); }
    return;
  }
  rs.writeHead(404); rs.end("not found");
}).listen(PORT, () => {
  const on = Object.keys(KEYS).filter(k => KEYS[k]);
  console.log("CloudLog threat-proxy on http://localhost:" + PORT);
  console.log("Active services:", on.length ? on.join(", ") : "NONE (set VT_KEY / ABUSEIPDB_KEY / OTX_KEY / URLSCAN_KEY / GSB_KEY / GREYNOISE_KEY / SHODAN_KEY / ABUSECH_KEY — Geo/ASN works with no key)");
});
