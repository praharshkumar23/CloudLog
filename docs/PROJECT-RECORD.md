# CloudLog — Complete Project Record

*A full account of what was built, what was tested, what was found broken, and what was fixed.*
*Author/owner: Praharsh · Compiled: 2026-07-20*

---

## 0. READ THIS FIRST — what "100%" does and does NOT mean

**CloudLog is not 100% accurate. No detection tool is.** Several numbers in this document say
"100%" or "0% false positives." Those must be read carefully:

- **Almost every 100% is on a test set written by the same person who wrote the detection rules.**
  That is close to circular: if I choose the attack examples *and* write the signatures, of course
  the signatures match my examples. It mainly proves *internal consistency* (regression coverage),
  **not real-world accuracy**.
- **"0% false positives" only means "none on the specific benign samples tested."** Real production
  traffic is far more varied and **will** produce false positives.
- **The tool will also miss real attacks (false negatives)** — especially novel payloads and
  business-logic / access-control attacks that have no signature at all.
- **The one semi-independent test (real logs from GitHub) still found two serious bugs.** That is
  the clearest evidence that true real-world accuracy is *unknown and lower* than the corpus numbers.

**So treat every "100%" here as "100% on this specific self-authored corpus" — a regression/coverage
figure, a lower bar than production.** Real accuracy has not been measured on independent, labeled,
production-scale data and cannot be claimed. What the numbers *do* honestly show: the tool behaves
consistently, its known bugs were fixed, and it did not flood the benign logs it was tested against.

Honest one-line description: **a heuristic triage assistant that catches common, known attack
patterns and stays quiet on the benign logs it was tested against — verified for consistency, not
certified for accuracy.**

---

## 1. What CloudLog is

**CloudLog is a local-first security-log triage and investigation tool.** It is a single
self-contained `index.html` file (~260 KB) that runs entirely in the browser from `file://` —
no server, no install, no accounts, no data leaving the machine.

**The problem it addresses:** a SOC analyst investigating an incident normally jumps between
many log formats and tools (Windows Event Logs, Sysmon, firewall, VPN, proxy, DNS, EDR,
CloudTrail, Sentinel, Splunk, Wazuh, PCAP…), writing queries and manually correlating events.
That takes hours.

**What CloudLog does:** you drop in a log, and it auto-detects the format, normalizes it,
classifies each event, detects known attack techniques, correlates related events into a small
number of incidents, explains each one with evidence and suggested next steps, and visualizes
the attack. The goal is **hours → minutes**, and to make any log understandable to any analyst.

**Positioning (important):** CloudLog is an **investigation assistant, not a replacement** for a
SIEM, EDR, or analyst. It does deterministic **heuristic** triage — the analyst always makes the
final decision. This honesty is baked into the product's own wording.

---

## 2. Architecture & design principles

**Two-layer parsing engine:**
1. **Format layer** — parses JSON, NDJSON, CSV/TSV, syslog (BSD + RFC5424), CEF, CLF (Apache/Nginx),
   and logfmt/key-value. Auto-detects which one.
2. **Source normalization** — maps any vendor's fields into one canonical event:
   `{ time, actor, action, ip, source, urls, cmds, emails, hashes, domains, raw }`.
   A flatten-and-lookup helper (`flattenObj` + `lookupKeys`) makes field extraction
   case- and separator-insensitive and nesting-aware, so Wazuh's `data.*`/`rule.*` nesting and
   Sentinel's PascalCase both map correctly.

**Detection is deterministic, explainable heuristics — not machine learning.** The same input
always produces the same output. Every verdict can be traced to a specific rule or signal.

**AI is optional and additive.** Detection happens locally with zero network calls. If the user
supplies their own API key, an AI layer can *explain* findings in prose — but it never decides
severity, and nothing is transmitted unless the user opts in.

---

## 3. Feature inventory (everything built)

**Ingestion & normalization**
- Multi-format ingestion with automatic format + source detection.
- Canonical event model; robust field extraction across vendors.
- Binary ingestion for `.pcap`/`.cap` (classic libpcap parser).

**Classification & detection**
- `severityOf` classifier → Malicious / Suspicious / Info, honoring source severity ratings.
- MITRE ATT&CK–mapped rules covering the most common 2025–2026 techniques: brute force &
  password spray (T1110), phishing (T1566), credential dumping (T1003), Kerberoasting (T1558.003),
  process injection (T1055), encoded PowerShell & LOLBins (T1059.001/T1218), lateral movement
  (T1021/T1047), C2 & beaconing (T1071), DNS tunneling (T1071.004), impossible travel / valid
  accounts (T1078), privilege escalation (T1548/T1068), ransomware (T1486), droppers (T1105),
  IDS/IPS signatures, cloud IAM changes (T1098).
- **OWASP raw-payload detection** — inspects raw URLs/bodies/headers for attack payloads (see §5).
- **Evasion normalization** — WAF-style canonicalization before matching (see §5).

**Correlation & investigation**
- `correlateChains` — union-find correlation by shared IP / actor / hash / domain, with a
  time window and a **hub guard** so unrelated attackers aren't merged (see §6).
- Decision Cards — per incident: Priority (P1/P2/P3/Ignore), confidence-weighted Risk,
  Confidence breakdown, counter-evidence, scenario recognition, MITRE tactic, and next steps.
- Entity Risk engine — scores each user/IP by fused signals.
- Incident consolidation funnel — events → alerts → dedup → investigations, with % noise reduced.

**Visualization & reporting**
- Timeline (stage-ordered).
- Attack Chain reconstruction.
- Evidence Graph — typed relationships between entities, color-coded by type (see §7).
- AI Analyst report (grouped/deduped narrative).
- Downloadable HTML incident report + evidence-package export.
- Case management (state machine: New → Investigating → Escalated → Contained → Closed), merge/split.

**Bring-your-own intelligence**
- YARA subset, IOC block-list, allow-list, custom rules — all re-evaluate the data live.

**Threat-intel proxy (optional)** — a zero-dependency Node proxy (`threat-proxy.js`) for
enrichment; the tool falls back to one-click deep links if it isn't running.

---

## 4. How the detection engine evaluates (the basis)

`severityOf` runs these checks **in order**, first match wins:
1. Allow-list membership → **Info**.
2. Block-list membership → **Malicious**.
3. Already-blocked/denied threat rated low → **Suspicious** (mitigated, lower priority).
4. Explicit clean verdict (status = safe/clean/benign) → **Info**.
5. Hard indicators (mimikatz, ransomware, C2 framework names, etc.) → **Malicious**.
6. Source severity rating: Critical → Malicious; High/Medium → Suspicious; Low/Info → Info.
7. OWASP payload signatures (high-severity) → **Malicious**; (any) → **Suspicious**.
8. Risk/severity numeric thresholds, scanner/attack tags → graded.
9. Otherwise → **Info**.

Detection rules come in two kinds:
- **Per-event signatures** — regex/keyword match on one event.
- **Aggregate rules** — a pattern across many events (e.g. brute force = ≥3 failed logins from one
  source IP), rendered as one aggregated row.

---

## 5. The validation journey (accuracy testing arc)

This is the heart of the project. Accuracy was measured against increasingly hostile test sets.
Each move from "friendly" data to "independent" data lowered the true score and exposed real bugs —
that is the testing working, not failing.

### 5.1 Against ground-truth labeled data
The `praharsh_siem` lab dataset (~1,980 events in 4 SIEM formats: Wazuh, Sentinel, snake-JSON, CSV)
carries ground-truth labels (`mitre_technique`, `severity`, `lab_attack`). Measured:

| Metric | Before fixes | After fixes |
|---|---|---|
| Threat catch rate (recall) | 92.2% | **100%** |
| False-positive rate | 7.6% | **0%** |
| Severity agreement | 84.5% | **87.3%** |
| MITRE family mapping (clean formats) | — | **~81%** |
| URL-scan verdicts (SAFE/MALICIOUS) | — | **100% (7/7 & 7/7)** |

> **Caveat:** 100%/0% is the *ceiling* on clean, well-labeled data — not production reality.

### 5.2 Against raw OWASP payloads (unlabeled)
Built a corpus of raw attack payloads (the strings a WAF/proxy actually logs, with no labels).

- **Initial catch rate: 15.3%.** The tool had been reading *labels*, not detecting *attacks*.
- Built a **payload-signature engine** (`PAYLOAD_SIGS`) — ~30 signature families covering SQLi, XSS,
  command injection, path traversal/LFI, SSRF (incl. cloud IMDS), XXE, SSTI, LDAP/NoSQL injection,
  deserialization, Log4Shell/ProxyShell-class RCE, web shells, CRLF/open-redirect, scanners,
  cloud-credential access, JWT attacks, GraphQL abuse, request smuggling, prototype pollution,
  broken access control, IDOR/enumeration, CSV/formula injection, XPath, C2 frameworks, exfil/tunnel.
- **After: 99.2%**, with **0 false positives** on benign traffic.

### 5.3 Under attacker evasion
Tested classic WAF bypasses: URL-encoding, double/triple encoding, SQL comment insertion
(`UNI/**/ON`), MySQL versioned comments (`/*!UNION*/`), case-mixing, Log4Shell obfuscation
(`${${lower:j}ndi:}`), HTML entities, `String.fromCharCode`, null bytes, `||` concat.

- **Initial: 71%** — encoders walked straight through.
- Added `normalizeForDetection` — WAF-style canonicalization (recursive URL-decode, entity-decode,
  strip/keep comments correctly, resolve Log4Shell lookups, collapse whitespace) *before* matching,
  probing both `+`-as-space and `+`-preserved forms.
- **After: 100%** on both evasion sets, **0 false positives**.

### 5.4 The mega corpus (960 cases)
Crossed 23 attack categories (including new forms: JWT, GraphQL, CSV injection, XPath, C2
frameworks, request smuggling, more CVEs) × 6 evasion transforms = **960 test cases**.

- Iteration 1: **78.4%** → Iter 2: 94.4% → Iter 3–4: 99.6% → Iter 5: **100%**.
- Fixes along the way included a double-escaped regex bug (`\\w` instead of `\w`) that silently
  broke command-injection matching, and a `+`-as-space decode that destroyed formula payloads.

### 5.5 Real-world logs (independent test)
Downloaded real public logs from GitHub (loghub + a real Apache access log):

| Real log | Events | Info% | Flagged | Brute-force IPs found |
|---|---|---|---|---|
| Apache error (benign) | 2,000 | 100% | 0 | — |
| HealthApp (benign) | 2,000 | 100% | 4 | — |
| Linux syslog + SSH | 2,000 | 98% | 47 | 25 |
| OpenSSH auth | 2,000 | 69% | 612 | 22 |
| Apache access 10k | 10,000 | 96% | 440 | 2 |

Key result: **benign operational logs stayed ~100% Info (no false-alarm storm), while logs with
real attacks surfaced the attacks and attacking IPs.** This independent test found two serious bugs
(see §6.4, §6.5).

---

### 5.6 Cross-validation against a real GuardDuty log + Splunk project

Validated CloudLog against an independent 2,000-finding AWS GuardDuty log (from the
`AWS-GuardDuty-Log-Analysis-using-Splunk` GitHub repo), using GuardDuty's own `type` and numeric
`severity` as ground truth, and cross-checking the repo's Splunk (SPL) analysis:

- **Attacker-IP extraction:** CloudLog pulled the exact same source IP as the Splunk field
  `service.action.remoteIpDetails.ipAddressV4` for **2,000/2,000 findings (100%)** — the nested
  GuardDuty structure is parsed correctly.
- **Severity:** GuardDuty High=596 → CloudLog malicious=**596 (exact)**; Medium+Low → suspicious;
  **0 findings missed** (nothing dropped to info — correct, since GuardDuty only emits findings).
- **Category coverage vs the Splunk project's 5 investigations:** all five (Brute Force, Recon,
  IAM abuse, Crypto/Malware/C2, S3) were flagged 100%. Initially only Brute Force (T1110) and DNS
  exfil (T1048) mapped to *specific* MITRE techniques; the rest were caught by severity only.
  **Gap closed:** added a GuardDuty-taxonomy → MITRE mapping (Recon→T1595, Crypto→T1496,
  Backdoor/C2→T1071, S3→T1530, IAM abuse→T1078), gated on the GuardDuty `type` field so it has no
  effect on other log sources. Now **all five map to specific techniques at 100%**, with 6 regression
  tests added (review battery v11, now 28 checks).

**Verdict:** correct on the fundamentals (parsing, exact attacker IPs, severity) and now agrees with
the Splunk analysis across all five investigated categories. This is still a *self-consistent*
validation (GuardDuty labels are the source of truth the tool partly keys on), not an independent
accuracy measurement (see §0).

### 5.7 Full-model re-validation across 13 logs (regression hunt)

Re-ran the entire current build against every available log (8 uploaded + 5 real GitHub logs) to
hunt for regressions from the worker / caching / lineage changes. Result: **0 crashes, 0 thrown
exceptions** across all 13 files (parse + severity + detect + correlate + aggregate), and the worker
produces **identical** detections to the sync path on a real 1,980-event file.

**Issue found and fixed — unparsed real-world timestamps.** The sweep surfaced that two real formats
left `time` empty on *every* event, silently breaking the timeline, span, and time-window
correlation for those logs:
- Apache **error**-log ctime `Sun Dec 04 04:47:44 2005` → now parsed (2000/2000).
- **HealthApp** compact `20171223-22:15:29:606` → now parsed (1620/2000; the rest are continuation
  lines with no timestamp).
Root cause: the text-line path (`decorate`) set `time=""` without ever calling the `deepFindDate`
fallback. Fix: route the line through `deepFindDate`, and teach `deepFindDate` the ctime and compact
formats. Two regression tests added (review battery now 31).

**Detection-cache correctness.** The worker returns detections that `render()` reuses via a cache;
the cache key was hardened from array-identity to **content identity** (length + first/last element),
because `applyFilter` always allocates a fresh array — otherwise the cache would never hit. Verified
worker=sync on real data.

**Honest observations (not fixed, by design):** GuardDuty still shows ~one incident per event
(unique IPs, nothing to correlate — data property, §5.6); benign logs still form a few low-risk
correlation clusters; and messy multi-line real logs (Linux/OpenSSH syslog) reach ~75–100% timestamp
coverage, with yearless BSD-syslog dates assuming the current year (inherent to the format). All
Node-verified, not browser-tested.

## 6. Complete bug log (found & fixed)

### 6.1 Parsing / field-mapping
- **CSV parsing was entirely missing** → added a delimited parser + detector.
- **Wazuh/Sentinel field mapping broken** (case/nesting) → `flattenObj`/`lookupKeys`.
- **Email subject wrongly used as actor** → cleaned `ACTOR_KEYS`.
- **`0.0.0.0` junk actor** filtered out.
- **Syslog source-IP extraction weak** → now prefers `from <IP>` / `rhost=` / `src=` markers;
  IP extraction on real SSH logs jumped to 1,734/2,000.

### 6.2 Classification
- **T1547.001 firing 120 false positives** on GuardDuty "Persistence:" finding names → made
  Windows-specific.
- **Medium-severity events dropped to Info** → severity rating now honors Medium (raised catch rate).
- **Already-blocked threats flagged Malicious** → blocked/denied + non-critical → Suspicious.
- **`&type=summary` benign FP** (matched a Windows command pattern) → tightened to require a file path.
- **SAFE-verdict URLs overridden by payload sigs** → explicit clean-verdict guard returns Info early.

### 6.3 Detection signatures
- Raw OWASP payloads not detected → `PAYLOAD_SIGS` engine (§5.2).
- Encoding evasion → `normalizeForDetection` (§5.3).
- Double-escaped regex (`\\w`) silently breaking command injection → rewrote 6 signatures.
- SQLi missed no-space `union`/`||` concat/`1'='1` → hardened.
- 4 whole categories uncovered (CSV injection, exfil/tunnel, C2 frameworks, XPath) → added.

### 6.4 CSV/formula-injection false positive (found on real logs)
- The formula-injection regex included bare arithmetic (`\d+[+\-*]\d`), which matches **dates like
  `2025-04-25`** → flagged **2,861 benign `GET /index.html`** events as CSV injection.
- Fixed to require an actual spreadsheet function/command. http_logs went from 0% Info back to 74%.

### 6.5 Brute-force under-detection (found on real logs)
- Real SSH log had **1,257 brute-force attempts but only 17 correlated** — the rule grouped by
  **username**, while attackers spray many usernames from **one IP**, fragmenting the attack; and
  the source IP wasn't extracted from raw syslog.
- Fixed both → now correlates **1,190 attempts across 32 IPs**, naming the top attacker.

### 6.6 Report / tab output quality (found from user-generated reports)
- **Over-correlation** — one incident = 615 events across **180 distinct IPs**. Added a
  distinct-source **hub guard** (a destination shared by many sources is infrastructure, not one
  incident) → became **250 single-source incidents** (16 events / 1 IP).
- **Detection list spam** — "T1110-WEB" listed **49 times** → `aggregateDetections` merges by rule
  → one row: "120 events (49 sources)".
- **Wrong technique** — 206 web referrers tagged **T1566 "Phishing email"** → constrained T1566 to
  email context; now correctly **T1071-WEB "malicious referrer"** (0 mislabels).
- **Contradiction** — a DNS log flagged "credential-access activity" with **0 detections** →
  tightened credential detection to real theft indicators (lsass/mimikatz/secretsdump), not bare
  "password".
- **`app.js` listed as a domain** (`.js` is technically a ccTLD) → excluded file extensions.

### 6.7 Correlation edge cases (earlier)
- 767 suspicious events → 0 investigations → allowed internal (private-IP) actors to correlate.
- Risk/confidence incoherence (risk 100 / conf 22) → confidence-weighted risk cap.
- 50 identical events → 50 investigations → strong-pivot cap exemption.

### 6.8 External code-review — verified claim-by-claim (not accepted on faith)

Two external reviews were run against the code. Rather than accept them, each claim was
**verified in the actual code and tested empirically** before any change (the discipline: confirm
the bug exists, write a failing test, fix, keep the test). Findings:

| Claim | Verdict | Evidence |
|---|---|---|
| `deepFindDate` epoch → dates land in 1973 | **PARTIAL (real, mechanism misdiagnosed)** | The *string* path is safe: `new Date("123456789012")` → *Invalid Date* (the reviewers' stated mechanism is false). But a re-review caught a **`typeof obj === "number"` branch** returning IDs in `1e9..2e12` raw — so a JSON **number** `123456789012` → `new Date(number)` → **1973**, and epoch-*seconds* numbers → **1970** (read as ms). The 1973 break is real for JSON numbers. *(This was missed in the first pass and caught on re-review — see note below.)* |
| IPv6 blindness | **CONFIRMED** | `RE.ip` was IPv4-only; IPv6 never extracted. |
| AI gauge double-counts a multi-rule event | **PARTIAL / minor** | `highs/meds` count detections, so 1 event × 2 rules adds twice — but bounded (risk capped 100) and the dominant term is per-event. Left the tuned formula intact to avoid destabilizing scoring; documented. |
| Search not debounced | **CONFIRMED** | `oninput = applyFilter` fired every keystroke. |
| `flattenObj` recomputed 3–4×/event | **CONFIRMED** | Never cached. |
| Hub guard allocates objects | **CONFIRMED** | Plain object per indicator. |
| Action taxonomy misses reject/sinkhole/blackhole | **CONFIRMED** | Regex lacked them. |
| Linux LOLBins missing | **PARTIAL** | Some patterns caught via CMDI/REVSHELL; no dedicated execution rule. |
| `%00` null byte not stripped | **CONFIRMED (proved)** | `<scr%00ipt>` and `UN%00ION SELECT` evaded — tested. |

**Fixes applied (each with a permanent regression test in `checkloop.js` battery v11, 14 checks):**
- **Null-byte / control-char strip** in `normalizeForDetection` — closes the `%00` truncation bypass.
- **Epoch handling** — `coerceTime` + hardened `deepFindDate` (both the string **and** the number
  branch) now parse 10-/13-digit epochs bounded to ~2000–2035 and *reject* 11-/12-digit IDs, so
  neither a JSON string nor a JSON number can land in 1973/1970.
- **IPv6 extraction** — added a validated IPv6 regex to **both** `extractIocs` **and** `fromSyslog`
  (raw-syslog source IPs), so IPv6 attackers in unstructured logs are no longer invisible.

> **Honesty note on the verification itself:** the first-pass verdict on the epoch claim ("false as
> described") was *itself incomplete* — it checked the string path and stopped before reading the
> `typeof obj === "number"` branch a few lines down, which held the real 1973 bug. A follow-up
> re-review caught it. The lesson cuts both ways: verify the *whole* function, not just the path the
> claim happens to name. Same for IPv6 — the first fix covered `extractIocs` but missed the parallel
> `fromSyslog` path. Both are now fixed and covered by regression tests.
- **Action taxonomy** — added reject / sinkhole / blackhole / terminated / isolated / contained /
  mitigated / neutralized to the mitigated-action downgrade.
- **Linux LOLBins (T1059.004)** — new rule for `curl|sh`, `wget|python`, `base64 -d|bash`, reverse
  shells; verified it does *not* fire on benign `curl …/health`, `systemctl`, `python3 manage.py`.
- **Performance** — debounced search (250 ms), `Set` for the hub-guard counter, and a cached
  `flatOf(ev)` so the raw object is flattened once per event instead of 3–4×.

**Reviewer-2's "bigger" points — verified round 2 (each tested, not assumed):**
- **Confidence math** — *CONFIRMED additive, but not the described pathology.* Each evidence
  category contributes at most once (booleans, not per-detection), strong signals carry the largest
  weights, and risk is already confidence-capped — so "10 weak > 1 strong" can't actually happen.
  A noisy-OR would need calibrated probabilities we don't have (false precision). **Left as-is,**
  documented.
- **Time-sync** — ISO offsets and CLF/syslog offsets were already handled; **Windows FILETIME
  (18-digit) was a real gap — fixed** in `coerceTime` (converts 100-ns-since-1601 ticks to a bounded
  ISO date). Regression-tested (`filetime-2022`).
- **Aggregate double-count** — real but **minor and debatable** (risk capped at 100, dominant term
  is per-event `maxXdr`, and counting two distinct techniques on one event is arguably correct).
  **Deliberately left** rather than destabilize tuned scoring for a marginal, contestable gain — the
  professional call, and reviewer-2's own lowest-rated item (7/10).
- **Per-rule regression harness** — *did not exist; now built* (`rule_regression.js`): 14 rule
  families each with a POSITIVE (must fire) and NEGATIVE (must stay quiet) sample, plus severity
  checks — **31/31 pass.** Extensible to every rule.
- **Parser fuzzing** — *ran it.* 653 adversarial inputs (binary, truncated, 5,000-deep nesting,
  500 KB strings, ReDoS bait) + 16 detection-path ReDoS baits (up to 140 KB): **0 crashes, 0 hangs,
  0 ReDoS** (slowest legit parse 254 ms). A compact fuzz battery (v12) now guards this permanently.

All fixes verified in Node; **not browser-tested.**

---

### 6.9 Architectural review ("guessing → proving") — verified & actioned

A third review proposed three pillars. Each was checked against the code and benchmarked:

- **Pillar 3 — parser bulletproofing: ALREADY DONE.** Epoch (string + number + FILETIME), IPv6
  (extractIocs + fromSyslog), null-byte, and fuzzing (653 adversarial inputs, 0 crashes) were all
  completed earlier this cycle. The review framed it as future work; it was already in place.

- **Pillar 2 — performance: CONFIRMED, and it was the biggest real issue.** Benchmarked: 10k events
  took 5.5 s and **50k took 24.5 s**, dominated by `runDetections` (19 s at 50k). Root cause: each of
  ~30 payload-signature rules re-ran the expensive `normalizeForDetection` twice per event (~60
  normalize calls/event), and ~25 rules re-ran `JSON.stringify(e.raw)` per event. **Fix:** cache the
  detection probe (`sigProbe`) and raw stringification (`rawStr`) once per event. Result:
  **50k detection 19 s → 8 s, total 24.5 s → ~13 s (~2× faster)**, no accuracy change (383 + 960
  still pass). The remaining path to smooth 100k is a **Web Worker + virtualized table** — the
  review's own recommendation, and the correct next step — but that's a browser-threading/DOM change
  that can't be verified in Node, so it is noted, not faked.

- **Pillar 1 — lineage correlation: flaw CONFIRMED, achievable part shipped.** Verified the flaw:
  three distinct attackers behind one egress IP merged into a single incident (source-IP keys bypass
  the destination hub guard). **Fix shipped:** `buildLinkKeys` now emits deterministic lineage keys —
  `ProcessGuid`, `ParentProcessGuid` (parent↔child link), `LogonId`, `SessionId` — treated as strong
  pivots. Verified: a parent→child→child process tree with **no shared IP** correlates purely by
  GUID/LogonId (regression-tested). *Honest limits:* these keys only help when the log carries those
  IDs (real Sysmon/Windows/EDR); the synthetic SIEM/GuardDuty data mostly lacks them, and the
  underlying NAT/shared-source-IP over-merge still exists when lineage IDs are absent — full
  IP-deprioritisation is not yet done. Documented, not overclaimed.

### 6.10 Inline Web Worker (off-main-thread engine) — built

Completed the architectural next step from §6.9 pillar 2: the heavy engine now runs off the
browser's main thread, so large files no longer freeze the UI — while the file stays a single
zero-install `index.html` (no external `worker.js`).

- **One source of truth, no divergence.** The worker runs the *same* script text (read from the
  main `<script id="cloudlog-main">` via its own `textContent`, turned into a Blob URL). A
  `__IS_WORKER` check plus a permissive Proxy DOM-stub let all the engine functions load in the
  worker while every main-thread UI-wiring statement safely no-ops. No hand-maintained copy of the
  engine, no fragile function/regex serialization.
- **Handoff.** On a large upload (>300 KB) the main thread posts the raw text + a snapshot of
  analyst-tunable state (allow/block lists, custom rules, verdicts, asset criticality, YARA) to the
  worker. The worker parses + detects, then posts back a **structured-clone-safe** bundle
  (detections stripped of their `match` functions; event references replaced with indices). The main
  thread rehydrates and caches it so the first `render()` does no heavy work on the UI thread.
- **Fails safe.** No `Worker`/`Blob`/`URL` support, a worker error, or a 20 s timeout all fall back
  to the existing synchronous path — worst case is exactly today's behaviour, so this can't regress.
- **Verification.** A worker-parity test (`worker_test.js`, 7 checks) runs the script in a simulated
  worker scope (`self===global`, `importScripts` present, no `document`) and confirms the worker's
  parse + detection output **exactly matches the synchronous path**, and that the posted bundle
  carries no functions. Combined with the earlier `sigProbe`/`rawStr` caching, this addresses pillar
  2 end-to-end. *Honest limit:* the browser's actual `Worker`/`Blob`/`postMessage` plumbing can't be
  exercised in Node — the automatic sync fallback is what makes shipping it safe. A **virtualized
  results table** (for rendering, not computing, 100k rows) is the remaining piece.

### 6.11 SOC-practitioner gaps — researched, then addressed

Researched (2025–2026 sources: Prophet Security, Strike48, Corelight, ReliaQuest, CyberDefenders,
Ponemon/Verizon DBIR) what real SOC analysts most often get burned by, then closed the two biggest
gaps CloudLog didn't already cover:

- **Triage on incomplete data ("what you can't see").** Sources repeatedly note that ~30–40% of log
  data is never collected and *every triage decision happens with missing context*, yet analysts
  aren't told. **Added:** a data-completeness line on the Summary — "Coverage: 75% time · 66% user ·
  87% IP · 75% host" with a warning when a key field is sparse ("only 66% name a user — identity
  correlation is limited; don't read absence of a link as absence of activity"). So the analyst knows
  the limits of the picture before trusting it.

- **Bulk-dismissing early kill-chain alerts.** The most-cited miss: recon, scanning, and
  credential-testing surface as low/medium severity and get bulk-closed, leaving the SOC "blind to
  the early phases of the kill chain." **Added:** an explicit "⚠ Early-stage activity — don't dismiss
  these" block on the Summary listing low/medium recon/scan/cred detections, and a matching banner in
  the incident investigation drawer when a chain contains recon/initial-access/credential stages.

Already-covered gaps (confirmed against the research, no change needed): repeatable priority scoring
(Decision Cards P1–P3), confidence + counter-evidence, asset-criticality context, entity risk,
per-incident recommended steps, analyst feedback loop (allow/block/👎), and an audit trail (case
timeline with verdict/owner/status/comments). Honest limits remain: no live threat-intel enrichment
without the optional proxy, and correlation is still heuristic (§10). Node-verified, not browser-tested.

### 6.12 Capability audit — priority inflation (alert fatigue) fixed

Ran all logs through and audited output *quality* (not just crash-freeness). Found a real capability
weakness: **priority inflation**. On the Apache attack log **99 of 250 incidents were P1**, and the
Zeek log produced **P1 incidents at risk 15** — priority decoupled from risk, so "most urgent" became
meaningless (the alert-fatigue trap that research names the #1 SOC failure). The rich SIEM dataset was
already healthy (10 P1), which confirmed the issue was specific to high-volume single-source web noise.

Root cause: `P1 if (sev.malicious && chain.size >= 2)` plus `baseRisk = sev.malicious*20 + …` — so a
scanner firing 50 SQLi probes scored as 50× risk and jumped to P1. **Fix:** (1) reserve P1 for
*confirmed* compromise — malware/C2, or malicious activity **with** credential/privilege/multi-stage
progression — and drop mere attempts to P2/P3; (2) cap the volume contribution to risk
(`min(malicious,3)*20`) so probe count can't max it out. Result: Apache **99 → 12 P1**, Zeek **36 → 0
P1** (all coherent, risk-aligned), SIEM ransomware chain **still P1**. Zero incoherent P1s across every
log; full suite unchanged (383 + 960 + 31 + 2 + per-rule + worker), all-logs loop 14/14 clean. The
priority queue now means what it says, so an analyst can trust "P1 first."

### 6.13 Signature noise reduction + behavioral layer

**Noise audit.** Measured per-rule fire-rates across every log. The signature *content* rules were
fine; the noise came from two **verdict-echo** rules — `TI-SUS` ("flagged suspicious") and `TI-MAL`
("flagged malicious"), plus the GuardDuty `GD-HIGH/GD-MED` mirrors — which simply restate the
severity already shown on each event. On GuardDuty `TI-SUS` "fired" on 70% of events and on the SIEM
set 64%, burying the real findings. **Fix:** tagged those four rules `meta:true`; the Detections tab
now shows real signal first and collapses the verdict echoes into a single expandable
"Source-verdict echoes" footer, and the Detections *tile* counts only signal rules (not echoes). No
detection logic changed — only how it's presented and counted.

**Behavioral layer (new).** Added three deterministic, explainable, **low-severity** behavioral
detections to catch what signatures miss — framed as *hints, not verdicts*, each with strict guards
so they stay silent on benign/uniform logs:
- `BEH-VOL` Volume Outlier — an entity with ≥10× the median activity of its peers (≥30 events, not
  the whole log; needs ≥8 entities to baseline).
- `BEH-OFFHRS` Off-hours Authentication — login/privilege activity in 00:00-06:00 UTC, only in logs
  whose activity is otherwise clearly daytime-shaped (≥70% daytime, ≥300 timestamped events).
- `BEH-RARE` Rare Process/Agent — a process/user-agent seen exactly once in a diverse log
  (≥100 events, ≥8 distinct values), excluding common browsers/bots.

Verified: fires on real attackers (OpenSSH brute-force IPs, the SIEM 429-event attacker, off-hours
Tor-exit logins) and stays **completely silent** on benign logs (HealthApp, Apache-error = 0). It's
low-severity so it does **not** inflate priority (P1 counts unchanged), and the 960-case corpus is
still 100% (no new false positives). Regression tests added (review battery 31 → 34). Honest limit:
behavioral hints will surface benign crawlers/service accounts too — they're explicitly labeled
"allowlist if known," because volume/rarity alone is not malice.

### 6.14 Senior-review pass — stale-cache bug + render performance

Did a deliberate "what would a 7-9-year engineer flag" audit of the delivered tool, profiling before
touching anything. Two real findings, both fixed and verified:

**1. Stale detection cache (correctness bug).** Detections depend on CUSTOM_RULES / IOC_BLOCKLIST /
ALLOWLIST / MEMORY_BAD, and on large files the Web Worker populates a detection cache — but nothing
invalidated that cache when those inputs changed. Symptom: on a big log, *add a rule or block an IP
and the Detections tab silently keeps showing the old results.* Fix: `invalidateDetectionCache()`
called from `savePrefs()` — the single choke point every mutation of those inputs already flows
through — plus on case-load. Verified: cache populates (2.3s → 0ms repeat), savePrefs clears it, and
a newly added rule appears in the next `runDetections` result.

**2. Render performance (profile-first).** Initial render at 10k events was ~25s because every tab
rendered eagerly; per-tab profiling showed Investigate 8.8s (of which `consolidationHtml` 3.3s was a
redundant `runDetections` recompute), Analyst 4.9s, Summary 3.2s. Fixes: (a) lazy tab rendering —
only the visible tab builds; heavy tabs build on first open; (b) `runDetections` now populates its
cache on first full-dataset compute so repeat calls inside one render are free; (c) `correlateChains`
memoized by dataset key. Result (Node timings): 2k logs initial **1.2s**; 10k stress file initial
**5.2s** (was ~25s), Investigate first-open 3.1s, subsequent re-renders ~0.6s/3.1s (2k/10k). Remaining
honest limit: first-open of Investigate on 10k+ files is still ~3s of inherent O(n) work.

Sandbox note: the test environment reset mid-pass (rebuilt a 10k stress input from the real Apache
upload); re-verified with the repo test suite (31 per-rule + 7 worker-parity) plus a fresh 9-log
smoke battery covering parse → full render → every tab first-open, 9/9 clean.

### 6.15 Investigation methodology audit — kill-chain ordering, entry point, attack timeline

Researched professional DFIR/IR methodology (Unified Kill Chain / ATT&CK walkthroughs, SANS-style
timeline reconstruction, Netwitness/PAN/Microsoft ATT&CK-mapping guidance) and audited CloudLog's
investigation pipeline against it. The standard: an investigation reconstructs a **chronological
timeline**, tells the intrusion story in **kill-chain order**, identifies the **entry point** and
walks backward/forward from it, with ATT&CK supplying technique-level mapping. Recon-only activity
is a risk signal, not an incident (CloudLog already conforms — recon-only chains rank P3).

Three real gaps found and fixed:
1. **Scrambled kill chain.** `chain.stages` was built from object-key insertion order — whatever
   order events were scanned — so the incident drawer showed stories like "Initial Access → C2 →
   Impact → … → Reconnaissance → Exfiltration". Fixed with a canonical `KILL_ORDER` (14 stages,
   Recon → Initial Access → Execution → … → Exfiltration → Impact) applied at the source in
   `correlateChains`, so every consumer (cards, drawer, pills) tells a coherent story.
2. **No entry point.** Added "Entry point (first event)" to the incident drawer — the
   chronologically first event with its stage, clickable to full detail, with the DFIR prompt
   "investigate backward from here — how did this first event get in?".
3. **No attack timeline.** Added "Attack timeline: first-seen → last-seen (duration, N events)" —
   the basic reconstruction every professional report leads with.

Verified on the SIEM ransomware chain: stages now render strictly canonically (Recon before Impact),
timeline and duration correct, entry point = chronologically earliest event (7/7 checks). Honest
limits: stage classification is keyword/technique-based per event, so a mis-tagged event can still
place a stage in the chain (stated in the UI); and with sparse timestamps the timeline falls back to
whatever events carry usable times. Full gates re-passed (141 content + 31 rules + 7 worker + 8 presets).

### 6.16 Windows / Sysmon / Linux field mapping — "important fields not visible"

Fixed the exact complaint: on Windows/Sysmon/Linux logs the important fields weren't surfaced. Built
real-shape test inputs (winlogbeat-nested Security events, mixed Sysmon EID 1/3/11 in nested + NXLog
flat shapes, real loghub Linux/OpenSSH/Windows-CBS 2k logs) and audited extraction, then fixed:

- **Human-readable actions per Windows/Sysmon Event ID.** Instead of dumping raw JSON or
  "@timestamp: …", events now read as an analyst expects: `Failed logon (4625): user=j.smith from
  203.0.113.40 LogonType=3`, `Process Create (4688): powershell -enc …`, `PowerShell ScriptBlock
  (4104): IEX(New-Object…)`, `Network connect: update.exe → 203.0.113.99:443` (EID 3), `File created:
  …\svc.exe` (EID 11), `Service installed (7045)`.
- **"Key fields" panel in the event drawer** — surfaces Host, Logon type (decoded: *3 — Network
  (share/SMB)*, *10 — RemoteInteractive (RDP)*, …), Target user, Process, Command line, Parent
  process, Script block, Destination ip:port, Target file, Service, Failure status, Hashes — the
  fields DFIR actually reads, no longer buried in raw JSON.
- **Windows username keys** (`TargetUserName`/`SubjectUserName`/`SamAccountName`) added to actor
  extraction, so Windows events attribute to the user, not an IP.
- **Linux/syslog user extraction** — pulls the user from `session opened for user X`, `user=X`,
  `ruser=X`, `for invalid user X from` (fixed a bug where actor became the literal word "user").
- **CBS/plain `YYYY-MM-DD HH:MM:SS` timestamps** embedded mid-line now parse (Windows CBS log went
  0% → 100% time coverage).
- **`firstMeaningfulValue` no longer picks time/guid keys**, so an action never degrades to
  "@timestamp: …".

Verified: 10/10 mapping checks (Linux users, decoded logon types, per-EID actions, key-fields panel
content) and **zero regressions** across every prior gate — 141 content, 31 rules, 7 worker, 7
investigation, 8 presets. Honest limit: mapping covers the common high-value Event IDs (4624/4625/
4688/4104/7045 and Sysmon 1/3/11); rarer IDs still show their raw fields in the Key-fields panel and
raw JSON, just without a hand-written sentence.

## 7. UI / UX work

**Dark "operator console" cyber theme** — deliberately *not* the matrix-green cliché:
- Deep indigo-black base; **cyan** as the "live/scan" signal; heritage **violet** as brand accent;
  coral / amber / mint for malicious / suspicious / safe. Monospace for data, Inter for prose.
- Live touches (restrained, `prefers-reduced-motion` respected): a pulsing "Engine active" pill
  that shows the event count, count-up metric numbers, hover glows, glowing active-tab underline.

**Performance fix** — the first animated version lagged badly. Cause: full-viewport continuously
animating gradients (rotating conic sweep + grid drift) and a constellation canvas forced whole-page
repaints every frame; the count-up also fought its own updates. Removed all continuous full-screen
animation (background is now static), kept only cheap GPU-composited effects, and fixed the counter.

**Evidence Graph color-coding** — was all red (color was driven by risk; on high-risk data every
node turned red). Now:
- **Colour = type** (user / IP / host / domain / hash).
- **Ring = risk** (red high, amber medium, white low).
- **Size = event count.**
- Also fixed a dark-theme bug where node labels were dark-on-dark (invisible), dimmed edges,
  and a legend that explains the encoding.

**"How this works" panels** — every tab now opens with a collapsible explainer stating the *basis*
of its evaluation (the order of checks, what the rules match, how priority/risk/confidence are
derived, the graph's color key), each ending with a "how to change it" note. This makes the logic
transparent so the analyst can tune it or fix mistakes.

---

## 8. Testing infrastructure (the loop)

A Node harness (`checkloop.js`) runs **10 batteries, ~383 assertions**, on every change:

| Battery | Checks | Covers |
|---|---|---|
| base | 121 | core parsing, classification, detection |
| strict v2 | 172 | NaN/self-loop/coherence/range invariants |
| edge v3 | 8 | empty/malformed input, EDR sample, dedup |
| pcap v4 | 11 | beacon/DGA/exfil/UA detection, benign safe |
| siem v5 | 22 | 4-format parse/mapping/consistency |
| coverage v6 | 15 | 34 event-type → technique mapping |
| owasp v7 | 18 | OWASP corpus catch + benign FP guard |
| evasion v8 | 2 | encoding evasion + benign-decode FP guard |
| behavioral v9 | 13 | logic/CVE/behavioral patterns |
| mega v10 | 1 | 960-case attack × evasion corpus ≥ 95% |
| review v11 | 22 | verified external-review fixes (null-byte, IPv6 ×2, epoch string+number, FILETIME, action taxonomy, Linux LOLBins) |
| fuzz v12 | 2 | 21 adversarial inputs — parser must never throw / must return an array |

A separate **per-rule regression harness** (`rule_regression.js`, 31 checks) runs 14 rule families
with paired positive (must-fire) and negative (must-stay-quiet) samples plus severity checks.

**Current status: all batteries pass, 0 failures; mega corpus 960/960 = 100%; per-rule harness 31/31; parser fuzz clean.**

Every change is verified in Node (syntax + functional) before delivery. **All work is Node-verified,
never live-browser tested** — this constraint is stated honestly throughout.

---

## 9. Current metrics (state today)

**These are coverage/consistency figures on self-authored or clean data — not real-world accuracy
(see §0).**

- Labeled lab data: 100% catch, 0% false positives, ~81% MITRE family mapping —
  *on clean, well-labeled data the tool was partly tuned against; this is a ceiling.*
- OWASP payload corpus: 99.2% — *payloads and signatures written by the same author (circular).*
- Attack × evasion mega corpus: 100% (960/960), 0 FP on benign — *self-authored corpus.*
- Real benign logs (GitHub): ~100% Info — *only 5 datasets, mostly web/auth/ops.*
- Real attack logs (GitHub): brute force and attacker IPs surfaced — *semi-independent; still
  revealed 2 bugs, which were fixed.*
- Test suite: ~383 checks across 10 batteries, 0 failures — *regression coverage, not accuracy.*

**What is genuinely established:** consistent behavior, fixed known bugs, no alert-flood on tested
benign logs. **What is NOT established:** real-world precision/recall on independent, labeled,
production-scale data.

---

## 10. Honest limitations

- **It is not 100% accurate and never will be. In production it will produce both false positives
  (benign flagged) and false negatives (real attacks missed).** The corpus numbers do not predict
  the production numbers (see §0).
- **100% is on self-authored / clean corpora.** Real production data is messier; accuracy there will
  be lower and needs tuning.
- **Signatures catch known patterns.** A genuinely novel payload with no matching rule gets through.
- **The hardest OWASP category — Broken Access Control / IDOR / business-logic abuse — has no payload
  to match.** Real coverage there needs behavioral/stateful detection, not signatures.
- **Normalization itself is attackable** (parser differentials) — a known cat-and-mouse.
- **Raw syslog field extraction is imperfect** (~87% IP extraction on Linux syslog).
- **Only web/auth/ops real logs were tested** — real Windows/EDR/cloud logs were not available, so
  those formats are still only tested on synthetic data.
- **Everything is Node-verified, not browser-verified** — rendering/visual behavior needs a human to
  confirm in an actual browser.

---

## 11. Files delivered

| File | Purpose |
|---|---|
| `index.html` | The tool — single self-contained file, runs from `file://`. |
| `threat-proxy.js` | Optional zero-dependency Node threat-intel proxy. |
| `rule_regression.js` | Per-rule positive/negative regression harness (run in Node). |
| `THREAT-INTEL-SETUP.md` | Setup instructions for the proxy. |
| `README.md` | Hiring-manager-facing overview with honest caveats. |
| `incident-report-apache-FIXED.html` | Example corrected incident report. |
| `CloudLog-Project-Record.md` | This document. |

---

## 12. What's next (roadmap)

1. **Behavioral / stateful detection** — the real frontier: access-control, IDOR, and multi-step
   business-logic attacks that signatures can't see.
2. **Real Windows / EDR / cloud logs** — test and harden field extraction on formats not yet
   exercised with real data.
3. **Browser verification** — confirm every tab renders and behaves correctly in a real browser.
4. **Expand the adversarial corpus** toward more CVEs and encoding variants, and keep the loop green.
5. **Tune on one genuinely messy production log** — the test clean lab data can't provide.

---

*CloudLog performs heuristic triage to help an analyst investigate faster. It does not replace a
SIEM, EDR, or human judgment. Always verify against source systems before acting.*
