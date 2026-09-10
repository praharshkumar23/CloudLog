# Security

CloudLog is a security tool, so it's held to a security tool's standard. This documents its
threat model, the controls in the code, known limitations, and how to report an issue.

## Threat model

The **input is untrusted by definition** — CloudLog parses raw security logs, which routinely
contain attacker-controlled strings (usernames, User-Agents, URLs, hostnames, payloads). The
primary risk is therefore that malicious log content could inject code into the analyst's browser
when rendered (stored/DOM XSS). CloudLog is designed around this assumption.

## Controls in the code

- **Output encoding everywhere untrusted data is rendered.** A single `esc()` helper HTML-escapes
  `& < > " ' \`` and is applied to all log-derived values before they enter the DOM — in both text
  and **HTML-attribute** contexts (e.g. `data-pivot="…"`, `title="…"`). Escaping quotes is the key
  detail: without it, a crafted field could break out of an attribute. The exported evidence/incident
  reports use the same encoder.
- **No dynamic code execution on input.** No `eval`, no `new Function`, no `document.write`, no
  `innerHTML +=` accumulation on untrusted data. The only `new Function` usage is in the offline
  test harness, never in the shipped tool.
- **ReDoS-resistant matching.** User-supplied regex rules run through a guarded matcher, and the
  built-in patterns are fuzz-tested against catastrophic-backtracking inputs.
- **Off-main-thread parsing.** Large/hostile files are parsed in a Web Worker with a sync fallback,
  so a pathological file degrades gracefully instead of hanging the UI.
- **External links** use `rel="noopener"` to prevent reverse-tabnabbing.
- **Secrets are not persisted.** An optional AI API key lives only in the input field for the
  request the user initiates; it is never written to local storage, saved cases, or logs. Access
  codes are stored only as SHA-256 hashes.

## Cryptography

Saved cases can be encrypted with **AES-256-GCM**; the key is derived from the passcode with
**PBKDF2 (SHA-256, 210,000 iterations)** and a random 16-byte salt + 12-byte IV per file, using the
platform **Web Crypto** API. No custom crypto is implemented.

## Honest limitations

- **The browser login is deterrence, not tamper-proof security.** CloudLog is a client-side file;
  anyone with the file can read its code and bypass a JavaScript lock. The strong guarantee is the
  case **encryption**, not the lock. For enforced access, host it behind a real login.
- **Content-Security-Policy is deployment-dependent.** Because the tool is a single inline-script
  file that must also run from `file://`, a strict CSP isn't shipped in the page (it can break the
  offline use case). When hosting on a server you control, add a CSP header — a good starting point:
  `default-src 'self'; script-src 'self' 'unsafe-inline' blob:; worker-src blob:;
  style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`.
  Note `'unsafe-inline'` is required by the single-file design, so output encoding (above) remains
  the primary XSS control.
- Detection is heuristic; see the README's "Honest limitations".

## Reporting a vulnerability

Open a GitHub issue describing the problem and reproduction steps. If you believe it's sensitive,
mark it clearly and avoid posting a working exploit against real data.
