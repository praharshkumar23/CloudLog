/* ============================================================
 * CloudLog — 11-iocs-and-enrichment.js
 * IP/CIDR/TLD classification, IOC extraction, safe enrichment links.
 * Part of index.html; assembled by build.js. Do not add a <script> wrapper.
 * ============================================================ */
function ipToLong(ip) { var p = ip.split("."); if (p.length !== 4) return null; var n = 0; for (var i = 0; i < 4; i++) { var o = +p[i]; if (isNaN(o) || o < 0 || o > 255) return null; n = n * 256 + o; } return n >>> 0; }
function inCidr(long, base, bits) { var mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0; return (long & mask) === (ipToLong(base) & mask); }
function classifyIp(ip) {
  if (!ip || ["-", "internal", "", "0.0.0.0"].indexOf(ip) !== -1) return "n/a";
  if (/:/.test(ip)) { // crude IPv6
    if (/^fe80:/i.test(ip)) return "linklocal";
    if (/^(::1)$/.test(ip)) return "loopback";
    if (/^f[cd][0-9a-f]{2}:/i.test(ip)) return "private"; // ULA
    return "public";
  }
  var L = ipToLong(ip); if (L === null) return "invalid";
  if (inCidr(L, "10.0.0.0", 8) || inCidr(L, "172.16.0.0", 12) || inCidr(L, "192.168.0.0", 16)) return "private";
  if (inCidr(L, "127.0.0.0", 8)) return "loopback";
  if (inCidr(L, "169.254.0.0", 16)) return "linklocal";
  if (inCidr(L, "100.64.0.0", 10)) return "cgnat";
  if (inCidr(L, "224.0.0.0", 4) || inCidr(L, "240.0.0.0", 4)) return "reserved";
  return "public";
}

/* ---------- hash + host classification ---------- */
function hashType(h) { if (!/^[A-Fa-f0-9]+$/.test(h)) return null; return h.length === 32 ? "md5" : h.length === 40 ? "sha1" : h.length === 64 ? "sha256" : null; }
var INTERNAL_TLDS = /\.(local|internal|corp|lan|home|intranet|localdomain|test|invalid|example)$/i;
function isInternalHost(host) { return INTERNAL_TLDS.test(host) || classifyIp(host) === "private" || /^[^.]+$/.test(host); }

/* ---------- extract IOCs from one normalized event ---------- */
var RE = {
  ip: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  ip6: /(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,6}(?::[A-Fa-f0-9]{1,4}){1,6}|::(?:ffff(?::0{1,4})?:)?(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[A-Fa-f0-9]{1,4}:){1,4}:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[A-Fa-f0-9]{1,4}:){1,7}:|::(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4}|::1\b/g,
  url: /\bhttps?:\/\/[^\s"'<>)]+/gi,
  hash: /\b[A-Fa-f0-9]{64}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{32}\b/g,
  email: /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi,
  domain: /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi
};
var COMMON_TLDS = { com:1,net:1,org:1,io:1,gov:1,edu:1,mil:1,co:1,info:1,biz:1,dev:1,app:1,ai:1,xyz:1,online:1,site:1,tech:1,cloud:1,me:1,tv:1,cc:1,us:1,uk:1,ca:1,au:1,de:1,fr:1,nl:1,ru:1,cn:1,jp:1,in:1,br:1,it:1,es:1,se:1,no:1,fi:1,pl:1,ch:1,eu:1,ml:1,tk:1,ga:1,cf:1,gq:1,pw:1,top:1,live:1,shop:1,store:1,pro:1,vip:1,link:1,click:1,arpa:1 };
function isValidTld(tld) { return COMMON_TLDS[tld] === 1 || /^[a-z]{2}$/.test(tld); } // known gTLD or any 2-letter ccTLD

function extractIocs(ev) {
  var out = { ips: {}, urls: {}, hashes: {}, emails: {}, domains: {} };
  var add = function (bag, v) { if (v) bag[v] = 1; };
  // trust structured fields first
  if (ev.ip && ev.ip !== "-") add(out.ips, ev.ip);
  (ev.urls || []).forEach(function (u) { add(out.urls, u); });
  (ev.hashes || []).forEach(function (h) { add(out.hashes, h); });
  (ev.emails || []).forEach(function (e) { add(out.emails, e); });
  var FILE_EXTx = /\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|html?|php|jsp|aspx?|cgi|pl|py|rb|json|xml|txt|csv|pdf|zip|gz|tar|mp[34]|webp|min|dll|exe|sh|bat|ps1)$/i;
  (ev.domains || []).forEach(function (d) { var t=(String(d).split(".").pop()||"").toLowerCase(); if (isValidTld(t) && !FILE_EXTx.test(String(d))) add(out.domains, d); });
  // then scan the serialized raw + action for anything missed
  var text = (ev.action || "") + " " + safeStr(ev.raw);
  (text.match(RE.ip) || []).forEach(function (v) { add(out.ips, v); });
  (text.match(RE.ip6) || []).forEach(function (v) {
    if (!v || v.indexOf(":") < 0 || classifyIp(v) === "invalid") return;
    // reject one-group shorthands like "a::" that come from "sekurlsa::", "std::", "Class::Method";
    // a real IPv6 in a log has >= 2 hex groups (fe80::1, 2001:db8::1) or is exactly ::1
    var groups = v.split(":").filter(function(g){ return g.length > 0; }).length;
    if (groups < 2 && v !== "::1") return;
    add(out.ips, v);
  });  // IPv6 IOC extraction
  (text.match(RE.url) || []).forEach(function (v) { add(out.urls, v); });
  (text.match(RE.hash) || []).forEach(function (v) { if (hashType(v)) add(out.hashes, v); });
  (text.match(RE.email) || []).forEach(function (v) { add(out.emails, v.toLowerCase()); });
  (text.match(RE.domain) || []).forEach(function (v) {
    if (/\d+\.\d+\.\d+\.\d+/.test(v)) return;                 // not an IP
    if (FILE_EXTx.test(v)) return;                            // "app.js", "style.css" -> not a domain
    var tld = (v.split(".").pop() || "").toLowerCase();
    if (!isValidTld(tld)) return;                                  // "john.doe" -> "doe" rejected
    add(out.domains, v.toLowerCase());
  });
  return {
    ips: Object.keys(out.ips), urls: Object.keys(out.urls), hashes: Object.keys(out.hashes),
    emails: Object.keys(out.emails), domains: Object.keys(out.domains)
  };
}
function safeStr(o) { try { return typeof o === "string" ? o : JSON.stringify(o); } catch (e) { return ""; } }

/* ---------- safe-to-enrich gate: never leak internal indicators ---------- */
function safeToEnrich(type, value) {
  if (type === "ip") { var c = classifyIp(value);
    if (c === "public") return { ok: true };
    return { ok: false, reason: c === "invalid" ? "not a valid IP" : "internal/" + c + " address — must not be sent to third parties" }; }
  if (type === "hash") { return hashType(value) ? { ok: true, note: "lookup only; looking up an internal-only file reveals its existence" } : { ok: false, reason: "not a recognized hash" }; }
  if (type === "domain") { return isInternalHost(value) ? { ok: false, reason: "internal/private hostname — do not disclose" } : { ok: true }; }
  if (type === "url") { var host = ""; try { host = new URL(value).hostname; } catch (e) { host = (value.split("/")[2] || ""); }
    if (isInternalHost(host)) return { ok: false, reason: "internal URL — urlscan makes scans PUBLIC and will visit the URL; never submit internal links" };
    return { ok: true, note: "urlscan submission is public + active; use search first" }; }
  if (type === "email") return { ok: false, reason: "emails are PII — not auto-enriched" };
  return { ok: false, reason: "unknown indicator type" };
}

/* ---------- enrichment link builders (no key, open web UI in a tab) ---------- */
function enrichmentLinks(type, v) {
  var e = encodeURIComponent(v);
  var dom = (type === "domain") ? v.replace(/^www\./i, "") : v;
  if (type === "ip") return {
    VirusTotal: "https://www.virustotal.com/gui/ip-address/" + e,
    AbuseIPDB: "https://www.abuseipdb.com/check/" + e,
    OTX: "https://otx.alienvault.com/indicator/ip/" + e,
    GreyNoise: "https://viz.greynoise.io/ip/" + e,
    Shodan: "https://www.shodan.io/host/" + e,
    Censys: "https://search.censys.io/hosts/" + e,
    Pulsedive: "https://pulsedive.com/indicator/?ioc=" + e,
    ThreatCrowd: "https://threatcrowd.org/ip.php?ip=" + e,
    IPinfo: "https://ipinfo.io/" + e,
    Whois: "https://rdap.org/ip/" + e,
    urlscan: "https://urlscan.io/search/#" + e
  };
  if (type === "domain") return {
    VirusTotal: "https://www.virustotal.com/gui/domain/" + e,
    OTX: "https://otx.alienvault.com/indicator/domain/" + e,
    urlscan: "https://urlscan.io/search/#" + e,
    SafeBrowsing: "https://transparencyreport.google.com/safe-browsing/search?url=" + e,
    Shodan: "https://www.shodan.io/search?query=hostname:" + e,
    Censys: "https://search.censys.io/search?resource=hosts&q=" + e,
    Pulsedive: "https://pulsedive.com/indicator/?ioc=" + e,
    ThreatCrowd: "https://threatcrowd.org/domain.php?domain=" + e,
    URLhaus: "https://urlhaus.abuse.ch/browse.php?search=" + e,
    "crt.sh": "https://crt.sh/?q=" + encodeURIComponent(dom),
    Whois: "https://rdap.org/domain/" + encodeURIComponent(dom)
  };
  if (type === "url") return {
    VirusTotal: "https://www.virustotal.com/gui/search/" + e,
    urlscan: "https://urlscan.io/search/#" + e,
    SafeBrowsing: "https://transparencyreport.google.com/safe-browsing/search?url=" + e,
    URLhaus: "https://urlhaus.abuse.ch/browse.php?search=" + e,
    Pulsedive: "https://pulsedive.com/indicator/?ioc=" + e
  };
  if (type === "hash") return {
    VirusTotal: "https://www.virustotal.com/gui/file/" + e,
    OTX: "https://otx.alienvault.com/indicator/file/" + e,
    MalwareBazaar: "https://bazaar.abuse.ch/browse.php?search=" + e,
    ThreatFox: "https://threatfox.abuse.ch/browse.php?search=ioc%3A" + e,
    HybridAnalysis: "https://www.hybrid-analysis.com/search?query=" + e,
    Pulsedive: "https://pulsedive.com/indicator/?ioc=" + e
  };
  return {};
}

/* ---------- automatic attack-chain correlation ----------
   Link two events if they share a STRONG indicator (public IP, actor, hash,
   domain) within `windowMs`. Connected components => incident chains.        */





