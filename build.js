#!/usr/bin/env node
/* CloudLog build — assemble the modular source in src/ into the single-file index.html.
 *
 * The files in src/ are the human-editable source, split by concern. index.html is the
 * deployable bundle: one file, zero dependencies, runs from file:// or GitHub Pages.
 * After editing anything in src/, run `node build.js` to regenerate index.html.
 *
 *   node build.js           rebuild index.html from src/
 *   node build.js --check   CI check: assert index.html already matches src/
 */
const fs = require("fs"), path = require("path");
const ROOT = __dirname;
const order = JSON.parse(fs.readFileSync(path.join(ROOT, "build", "modules.json"), "utf8"));
const template = fs.readFileSync(path.join(ROOT, "build", "index.template.html"), "utf8");

// A short, human-readable title for each section, kept in the assembled file so index.html reads
// as an intentionally organised source file rather than one undivided block.
const TITLES = {
  "01-core-utils.js":               "Core utilities  —  time, field maps, object flattening, indicators",
  "02-severity-stages.js":          "Severity & kill-chain stages",
  "03-source-normalizers.js":       "Source normalizers  —  GuardDuty, Apache, timestamps",
  "04-detection-rules.js":          "Detection rules  —  ATT&CK signatures, fidelity, frameworks",
  "05-state-and-prefs.js":          "Analyst state, persistence, custom-rule engine, runDetections",
  "06-render.js":                   "Tab rendering  —  metrics, detections, chain, graph, summary",
  "07-investigation.js":            "Investigation  —  pivoting and the inspector drawers",
  "08-hunt.js":                     "Hunt workbench  —  filters, presets, breakdowns, export",
  "09-tabs-and-fileio.js":          "Tabs, file upload, filtering, downloads",
  "10-analyst-and-ai.js":           "Analyst briefing and optional bring-your-own-key AI",
  "11-iocs-and-enrichment.js":      "IOC extraction, IP/CIDR/TLD classification, enrichment links",
  "12-correlation-and-parsers.js":  "Incident correlation and the text-format parsers",
  "13-decisions-and-cases.js":      "Scenarios, decision cards, sequence engine, case management",
  "14-auth-and-crypto.js":          "Access control, AES-256 case encryption, boot"
};

const stripHeader = t => t.replace(/^\/\* =+[\s\S]*?=+ \*\/\n/, "");
function banner(name){
  const title = TITLES[name] || name;
  const bar = "=".repeat(78);
  return "// " + bar + "\n// " + title + "\n// " + bar + "\n";
}

const assembled = order
  .map(name => banner(name) + stripHeader(fs.readFileSync(path.join(ROOT, "src", name), "utf8")).replace(/\n$/, ""))
  .join("\n\n");

const outHtml = template.replace("\n/*__CLOUDLOG_MODULES__*/\n", assembled);
const target = path.join(ROOT, "index.html");
if (process.argv.includes("--check")) {
  const cur = fs.readFileSync(target, "utf8");
  if (cur === outHtml) { console.log("index.html matches src/ \u2713"); process.exit(0); }
  console.error("MISMATCH: index.html differs from assembled src/ \u2014 run `node build.js`"); process.exit(1);
}
fs.writeFileSync(target, outHtml);
console.log("Built index.html from " + order.length + " sections (" + (outHtml.length/1024|0) + "KB).");
