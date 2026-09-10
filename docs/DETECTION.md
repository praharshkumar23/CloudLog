# Detection capabilities & accuracy

This document is for a reviewer who wants to understand *what CloudLog detects, how, and how well* —
without reading 6,000 lines of source. Every number here is produced by a script in `tests/` so it is
reproducible, not asserted.

## How detection works — three layers

CloudLog does not rely on a single technique. Findings come from three complementary layers, and an
event is surfaced if **any** layer flags it:

1. **Atomic signatures** — ~80 MITRE ATT&CK–mapped rules matching a single event (credential-dumping
   tools, LOLBin abuse, web-app attack payloads, C2 indicators, brute-force, etc.). Web-request
   payloads are canonicalized (URL/Base64/hex decoding) before matching so encoded attacks don't slip
   through.
2. **Correlation** — a union-find engine groups related events into incidents by shared entity (actor,
   public IP, file hash) and by **deterministic lineage** (process GUID, logon ID, session ID). Lineage
   links bypass the time window entirely: the same session is one incident even after a long idle gap,
   which defeats "low and slow" severance.
3. **Stateful sequences** — a sliding-window state machine matches *ordered behaviour over time* per
   entity, catching attacks that are invisible line by line:
   - `Failed logins → success → execution` within a tight window = **Account Takeover**
   - `Discovery → event-log clearing` = **anti-forensics** (log wiping after recon)
   - `Execution → credential access → lateral movement` = **hands-on-keyboard** progression
   - `Privilege change → security tooling disabled` = attacker switching off the alarms after getting the keys
   - `Credential dump → large outbound transfer` = **exfiltration** of the harvest
   Sequences track by **both** the account and the public source IP (binding the account once a
   successful logon reveals it), so a spray that pivots off its source IP onto an internal host is
   still followed — without letting a different user's activity contaminate someone else's tracker.
   The window is *sliding* (each step resets the clock), so a slow attacker who keeps progressing stays
   tracked, while a stale tracker expires.

## Two dimensions on every finding: severity **and** fidelity

Professional triage separates *how bad if true* from *how likely it's true*:

- **Severity** — impact if the detection is real (high / medium / low).
- **Fidelity** — true-positive likelihood. `high-fidelity` (mimikatz, `wmic process call create`,
  completed sequences) is almost never benign → act now. `heuristic` (off-hours login, volume outlier)
  often has an innocent explanation → verify first.

## Framework mapping

Every detection carries its exact **MITRE ATT&CK** technique, plus a curated mapping to the relevant
**NIST CSF 2.0** subcategory (e.g. `DE.CM-01`, `PR.AA-05`) and **MITRE D3FEND** countermeasure (e.g.
`D3-NTA`, `D3-PMAD`). This lets an analyst pivot from *what happened* → *where it fits in our program*
→ *how to defend*. ATT&CK IDs are exact per rule; CSF/D3FEND are curated at the technique-family level.

## How to check a prediction on YOUR logs (no labels needed)

The accuracy figures above come from a labeled corpus; your own logs won't have labels. So every
verdict CloudLog gives is **explainable**, which is how you verify it:

1. **Open any event** (click a row) — the drawer shows **"Why this verdict"**: the exact evidence that
   produced it (e.g. *hard indicator 'mimikatz'*, *high-severity payload signature: SQL Injection*,
   *the source rated it Critical*, *matches your known-bad IOC list*, or *no indicators matched*).
   Hovering any severity badge shows the same reason.
2. **Check that reason against the raw event** shown underneath. If the evidence is real, the verdict
   is right. If it isn't (a benign scanner, a false keyword hit), mark the incident **False Positive** in
   Investigate or add an **allow-list** entry — the tool learns and re-evaluates.
3. **Spot-check the boundaries**: a handful of *malicious*, a handful of *info*. In practice this is how
   an analyst calibrates any detection tool on a new log source in minutes.
4. If you *do* have labeled data (even a small hand-labeled sample), `tests/accuracy_eval.js` will
   give you real precision/recall on it.

The classifier uses a **fixed, deterministic order of checks**, so the same event always gets the same
verdict and the same reason — there is no hidden model to second-guess.

## Investigating an incident — what the drawer gives you

Open 🔎 on any incident and the drawer is laid out in the order an investigator works:

1. **Verdict block** — priority, risk, confidence, likely scenario, kill chain, attack timeline, entry point.
2. **Attack story** — the incident as numbered steps in time order, with consecutive repeats collapsed
   ("5× Failed Login → Logon Success → powershell -enc"), each step tagged with its stage and verdict.
3. **Investigation checklist** — the standard IR questions answered from the evidence, with the snippet
   that answers them: *did they authenticate? credential access? lateral movement? persistence? data
   moved? defenses tampered? how many hosts?* A **Yes** is highlighted in red so nothing is missed.
4. **Blast radius** — hosts, accounts, external IPs, domains and hashes touched.
5. **ATT&CK techniques observed** — the detection rules that fired on this incident's events.
6. **Related incidents** — other incidents sharing this attacker's account / IP / file, one click away.
7. **Copy IOCs** — every external IP, domain and hash in one click, ready for a blocklist.
8. **Events** — every underlying event, each clickable for full detail and its own "why this verdict".

## Measured accuracy (blind evaluation)

`tests/accuracy_eval.js` runs a **blind** test: it strips the ground-truth labels (`severity`,
`mitre_technique`, `lab_attack`) from a labeled dataset before feeding events to CloudLog, so the tool
cannot cheat, then scores its verdicts against the held-out labels.

On the reference SOC-lab corpus (1,980 events, 23 ATT&CK techniques):

| Metric | Value |
| --- | --- |
| Precision | **100%** |
| Recall | **97.1%** |
| F1 | **98.5%** |
| False-positive rate (on benign events) | **0%** |

**How to reproduce:** provide a labeled dataset at `./dataset/labeled.json` (fields `severity`,
`mitre_technique`, `lab_attack`) and run `node tests/accuracy_eval.js index.html`. Without a dataset
the script skips cleanly.

### Honest limitations

- This is measured on a **self-labeled lab corpus** — it demonstrates method and internal consistency,
  and a real recall improvement, not certified real-world accuracy.
- The remaining ~3% of misses are mostly **C2 over port 443** (indistinguishable from normal HTTPS
  without threat intel or beaconing analysis) and a few **contextual events** (plain RDP login,
  Kerberoasting) that are deliberately *not* flagged by type alone — doing so would trade away the 100%
  precision for false positives. That restraint is intentional.
- CloudLog is a **heuristic triage assistant**, not a SIEM: no real-time streaming, no bundled threat
  feed, single-file and stateless by design.

## What the CI proves on every push

The `CI` workflow runs on every push and pull request:

- `build.js --check` — the shipped `index.html` matches the modular `src/` byte-for-byte (no drift).
- `rule_regression.js` — every rule fires on a positive case and stays silent on a negative one (31 checks).
- `worker_test.js` — the engine returns identical results on the main thread and in the Web Worker (7 checks).
- `detection_smoke.js` — signatures and stateful sequences fire; benign input produces zero malicious verdicts.

A green badge means all of the above passed on the current commit.
