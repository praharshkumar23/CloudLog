# GitHub repo setup — About, topics, and polish

Paste these into GitHub to make the repo look complete and discoverable.

## "About" description (repo sidebar → ⚙ Edit)
Pick one:

- **Short:** `Single-file, offline security log triage tool — flags attacks, correlates incidents, MITRE-mapped. Runs 100% in the browser.`
- **Alt:** `Client-side SOC log triage & investigation in one HTML file. Heuristic detection (MITRE ATT&CK), incident correlation, hunt workbench. No server, no data leaves your machine.`

## Website (repo sidebar → ⚙ Edit → Website)
Your GitHub Pages link, e.g. `https://praharshkumar23.github.io/CloudLog/`

## Topics / tags (repo sidebar → ⚙ Edit → Topics)
```
security  soc  siem  log-analysis  threat-detection  incident-response
mitre-attack  blue-team  dfir  cybersecurity  javascript  client-side
zero-dependency  threat-hunting  log-parser
```

## Recommended repo settings
- ✅ Enable **Issues** (shows you welcome feedback).
- ✅ Under **Settings → Pages**, deploy `main` / root, then confirm the link opens.
- ✅ Add the demo link to the **About** box so visitors can try it in one click.
- ✅ Pin the repo on your GitHub profile.

## First release (optional but professional)
Create a release so it looks maintained:
- Go to **Releases → Draft a new release**
- Tag: `v1.0.0`, Title: `CloudLog v1.0.0`
- Description: copy the top of `CHANGELOG.md`
- Attach `index.html` as a downloadable asset (so people can grab the tool directly).

## Good first commit message
```
CloudLog v1.0.0 — single-file client-side security log triage tool
```
