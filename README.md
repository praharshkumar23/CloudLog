# CloudLog

[![CI](https://github.com/praharshkumar23/CloudLog/actions/workflows/ci.yml/badge.svg)](https://github.com/praharshkumar23/CloudLog/actions/workflows/ci.yml)  

**A single-file, offline security log triage tool.** Drop in raw logs from almost any
system and CloudLog flags likely attacks, groups related events into incidents, ranks
them by priority, and helps you investigate — entirely in your browser, with nothing
sent anywhere.

> ⚡ Zero install · 📄 One HTML file · 🔒 100% client-side · 🧭 MITRE ATT&CK–mapped

**Live demo:** `https://praharshkumar23.github.io/CloudLog/` *(enable GitHub Pages — see [Deploy](#deploy-github-pages))*

---

## Screenshots

> Add your own images to `docs/screenshots/` with the names below and they'll render here.

| Summary — plain-English verdict | Investigate — ranked incidents |
|---|---|
| ![Summary](docs/screenshots/summary.png) | ![Investigate](docs/screenshots/investigate.png) |

| Hunt — filter by Event ID / type / IP | Evidence graph — how events connect |
|---|---|
| ![Hunt](docs/screenshots/hunt.png) | ![Evidence graph](docs/screenshots/graph.png) |

## What it is

Security teams drown in log noise. CloudLog is an `index.html` file that runs completely
in the browser — no server, no dependencies, no data leaving the machine. You give it a
log file and it does the first pass of triage for you: what looks malicious, what's
suspicious, what's normal, why, and what to look at first.

It is a **triage assistant**, not a SIEM replacement. It catches common, known attack
patterns and stays quiet on benign data. See [Honest limitations](#honest-limitations) —
that section is the point, not the fine print.

## Features

- **Reads almost any log format** — JSON, NDJSON, CSV/TSV, syslog, CEF, Apache/CLF,
  logfmt, and native handling for AWS GuardDuty, Zeek, Windows/Sysmon, and
  Splunk/Wazuh/Sentinel exports. It auto-detects the format.
- **Explainable detection** — each event is scored malicious / suspicious / info by
  deterministic, readable rules mapped to **MITRE ATT&CK**. No black-box ML; every
  verdict traces to a rule you can read and change.
- **Incident correlation** — links related events by IP, user, hash, domain, and
  process/session/logon IDs, then ranks incidents **P1–P3** (P1 reserved for confirmed
  compromise, so the queue stays meaningful).
- **Plain-English summary** — "we looked at N events, X look like real attacks, here's
  what to do," plus a data-completeness note and an early-kill-chain warning so low/medium
  recon and credential activity doesn't get bulk-dismissed.
- **Investigate & pivot** — click any IP, user, or incident to drill in; a slide-in
  drawer shows full event/incident detail with linked entities and recommended steps.
- **Hunt workbench** — filter by Event ID, event type, IP, user, keyword, severity,
  source, or time window; live breakdowns; export results to CSV/JSON.
- **Evidence graph & attack chain** — see how events connect.
- **Optional AI Analyst** — bring your own API key for natural-language explanations
  (explanations only; it never makes the security decisions).
- **Access control & encryption** — set an admin code, issue login codes to teammates,
  export a locked shareable copy, and save cases encrypted with **AES-256-GCM**.

## Quick start

**Option A — just open it.** Download `index.html` and double-click it. It opens in your
browser (works from `file://`, fully offline).

**Option B — use the hosted link.** Visit the GitHub Pages URL above, click a sample, or
upload your own log.

Then: load a log → read the **Summary** → open **Investigate** → click **🔎 Investigate**
on an incident → click an IP to see all its events. That's the whole loop.

## How it works

A two-layer engine:

1. **Parse** — whatever format you provide is normalized into a common event shape
   (`time, actor, action, ip, source, urls, cmds, hashes, domains, raw`).
2. **Detect & correlate** — deterministic heuristic rules (mapped to MITRE ATT&CK) score
   each event; related events are unioned into incidents and prioritized with confidence,
   risk, and counter-evidence.

For large files the engine runs off the main thread in an inline **Web Worker** (with an
automatic synchronous fallback), so the UI stays responsive.

## Supported inputs (tested)

Real AWS GuardDuty findings, Apache access & error logs, Zeek HTTP, OpenSSH/Linux syslog,
a mobile app log, and multi-format SIEM datasets (Splunk/Wazuh/Sentinel/CSV) with MITRE
labels. See [`docs/PROJECT-RECORD.md`](docs/PROJECT-RECORD.md) for the full validation log.

## Testing

CloudLog ships with an automated test suite (run with Node):

- ~380 unit / format / coverage / OWASP checks + a **960-case attack corpus**
- Per-rule regression (positive/negative per rule family)
- Adversarial parser **fuzzing** (hundreds of malformed inputs, ReDoS baits)
- **Web Worker parity** test (worker output must match the synchronous path)

```bash
node tests/rule_regression.js index.html   # per-rule regression
node tests/worker_test.js index.html       # Web Worker parity
```

The broader battery (960-case corpus, fuzzing, format/OWASP suites) is described in
[`docs/PROJECT-RECORD.md`](docs/PROJECT-RECORD.md).

> Tests validate parsing/detection/worker logic in Node. The tool itself is browser-run;
> behavior is verified for **consistency** — confirm UI interactions in a real browser.

## Security model (read this)

CloudLog is a client-side file, so **the code is visible to anyone who has it** — this is
true of every browser-based tool.

- **The login / lock screen is deterrence, not tamper-proof security.** It stops casual
  and shared-machine access; a skilled person with the file can bypass a client-side lock.
- **The case encryption is the real guarantee.** Saved `.clenc` cases use AES-256-GCM with
  your access code; codes are stored only as SHA-256 hashes. Encrypted cases can't be read
  without the code.
- **For enforced access**, host CloudLog behind a real login rather than sharing the file.

See [SECURITY.md](SECURITY.md) for the full threat model, controls, and crypto details.

In short: **lock = deterrence · encryption = real protection · host behind a login = enforced access.**

## Optional: threat-intel proxy

A tiny zero-dependency Node proxy (`threat-proxy.js`) can add IP/domain reputation lookups
without exposing API keys to the browser. Setup: [`THREAT-INTEL-SETUP.md`](THREAT-INTEL-SETUP.md).
Without it, CloudLog runs fully offline on heuristics alone.

## Deploy (GitHub Pages)

1. Push this repo to GitHub (public).
2. **Settings → Pages →** Source: *Deploy from a branch*, Branch: `main`, folder: `/ (root)`.
3. Wait ~1 minute → your link: `https://<username>.github.io/CloudLog/`.

To make the public link open **locked**, export a locked copy from the tool (Access control
panel) and upload it as `index.html`.

## Honest limitations

I'd rather you trust this because it's honest than oversell it:

- It's a **heuristic** assistant. It catches common, known patterns and **will** have false
  positives and false negatives on real-world data — like any heuristic tool.
- The high test scores measure **consistency and coverage against known cases**, not
  certified real-world accuracy (some tests use self-authored attack samples).
- Correlation is heuristic; it's strongest when logs carry stable IDs (real Sysmon/EDR).
- Without the optional proxy there is **no live threat intel** — verdicts are pattern-based.
- The client-side lock is deterrence; only the encryption is a hard guarantee.

It complements a SIEM/EDR — it does not replace one.

## Project structure

The code is organised as modular source that builds into the single deployable file:

```
src/                       modular source, split by concern (edit here)
  01-core-utils.js         time/format helpers, field-key maps, object flattening
  02-severity-stages.js    severity rating + MITRE kill-chain stage classification
  03-source-normalizers.js GuardDuty / Apache normalizers + timestamp coercion
  04-detection-rules.js    the MITRE-mapped detection rule set + payload signatures
  05-state-and-prefs.js    analyst state, persistence, custom-rule engine, runDetections
  06-render.js             tab rendering (metrics, detections, chain, graph, summary)
  07-investigation.js      pivoting + event/incident inspector drawers
  08-hunt.js               the Hunt workbench (filters, presets, breakdowns, export)
  09-tabs-and-fileio.js    tab switching, file upload, filtering, downloads
  10-analyst-and-ai.js     written briefing + optional bring-your-own-key AI
  11-iocs-and-enrichment.js IP/CIDR/TLD classification, IOC extraction, enrichment links
  12-correlation-and-parsers.js incident correlation + text parsers (syslog/CEF/kv/pcap)
  13-decisions-and-cases.js scenario recognition, decision cards, case management
  14-auth-and-crypto.js    access control, AES-256 case encryption, lock screen
build.js                   assembles src/ -> index.html
index.html                 the deployable single-file bundle (what GitHub Pages serves)
```

Edit files under `src/`, then run `node build.js` to regenerate `index.html`. `node build.js --check`
verifies the bundle is in sync (useful in CI). The bundle is intentionally a single file so it runs
from `file://` and GitHub Pages with zero dependencies and no runtime build step.

## Framework mappings

Every detection carries its exact **MITRE ATT&CK** technique ID, and is additionally mapped to the
relevant **NIST CSF 2.0** subcategory (e.g. `DE.CM-01`, `PR.AA-05`) and **MITRE D3FEND** defensive
countermeasure (e.g. `D3-NTA`, `D3-PMAD`). ATT&CK IDs are exact per rule; CSF and D3FEND are curated
at the technique-family level using real, verifiable framework identifiers. These appear as tags on
each finding in the Detections tab, so an analyst can pivot from *what happened* (ATT&CK) to *where it
fits in our program* (CSF) to *how to defend against it* (D3FEND).

## Verification & CI

CloudLog ships with a test suite and a GitHub Actions pipeline that runs on every push:

- **`build.js --check`** — the deployable `index.html` matches the modular `src/` byte-for-byte.
- **`tests/rule_regression.js`** — every detection rule fires on a positive case and stays silent on a negative one.
- **`tests/worker_test.js`** — the engine returns identical results on the main thread and in the Web Worker.
- **`tests/detection_smoke.js`** — signatures + stateful sequences fire; benign input yields zero malicious verdicts.
- **`tests/accuracy_eval.js`** — optional blind precision/recall measurement (needs a labeled dataset; skips cleanly without one).

See **[docs/DETECTION.md](docs/DETECTION.md)** for the detection architecture, framework mappings, and the measured
**100% precision / 97.1% recall** blind-evaluation results with honest limitations.

## How this was built

CloudLog was designed, directed, and tested by me (**Praharsh**). I used **AI assistance
(Anthropic's Claude)** as a pair-programmer — writing and refining code, reviewing logic,
stress-testing detections, and drafting documentation. The requirements, the security
decisions, the testing against real logs, and every honesty call were mine, and I verified
behavior against real datasets and the automated test suite rather than trusting generated
output blindly. I note this openly because transparency about tooling is part of doing
security work honestly.

## License

MIT — see [LICENSE](LICENSE).
