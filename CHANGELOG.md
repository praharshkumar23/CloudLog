# Changelog

All notable changes to CloudLog are recorded here.

## [1.0.0]
Initial public release.

### Engine
- Multi-format parsing: JSON, NDJSON, CSV/TSV, syslog, CEF, Apache/CLF, logfmt, and
  native handling for AWS GuardDuty, Zeek, Windows/Sysmon, Splunk/Wazuh/Sentinel.
- Deterministic, explainable detection rules mapped to MITRE ATT&CK.
- Incident correlation via IP / user / hash / domain / process-session-logon lineage IDs.
- Priority scoring (P1–P3) with confidence, risk, and counter-evidence; P1 reserved for
  confirmed compromise to avoid alert-fatigue inflation.
- Off-main-thread inline Web Worker with automatic synchronous fallback.

### Detection & investigation (latest)
- Stateful sequence engine: brute-force→success→execution, discovery→log-clearing, execution→credential-access→lateral,
  privilege-change→security-tooling-disabled, credential-dump→exfiltration; sliding per-step windows; dual-track
  (account + public IP) so a spray that pivots off its source IP is still followed, with actor-isolation guard.
- Host-namespaced logon IDs and well-known-LUID filtering (stops cross-host SYSTEM 0x3e7 incident hairballs).
- Confirmed web-shell / RCE floor (high-fidelity signature + malicious verdict → P1), correlated per attacker.
- Explainable verdicts: every event shows "Why this verdict" (drawer + badge tooltip); behaviour unchanged across 8,995 events.
- Incident drawer investigation aids: attack story, IR checklist answered from evidence, blast radius, ATT&CK techniques
  observed, related incidents, one-click Copy IOCs.
- NIST CSF 2.0 + MITRE D3FEND framework tags and detection fidelity tiers on every finding.
- Fixes: SQLi `UNION(SELECT` bypass, IPv6 false positive from `sekurlsa::`, domain\user extraction, literal
  \u escapes in rule text, unbounded Math.min/max.apply, unescaped enrichment hrefs.

### Security
- Hardened output encoding (`esc()` now escapes quotes/backtick) to prevent stored XSS from
  attacker-controlled log fields in HTML-attribute contexts; verified with an injection test.
- Added SECURITY.md (threat model, controls, crypto, CSP guidance, disclosure).

### Analyst experience
- First-run welcome / onboarding card and a version footer for a finished feel.
- Plain-English summary with data-completeness and early-kill-chain warnings.
- Click-to-pivot interlinking; slide-in event and incident detail drawers.
- Hunt workbench: Event ID / type / IP / user / keyword / severity / source / time filters,
  live breakdowns, CSV/JSON export.
- Persistent "loaded dataset" total that filtering never changes.

### Security
- Access control with admin + analyst login codes (stored as SHA-256 hashes).
- Case encryption with AES-256-GCM (PBKDF2, 210k iterations).
- "Export locked copy" to share the tool with codes baked in.
- Honest in-app security notice (deterrence vs. real protection).

### Testing
- ~380 unit/format/coverage/OWASP checks, 960-case attack corpus, per-rule regression,
  adversarial parser fuzzing, and Web Worker parity tests.
