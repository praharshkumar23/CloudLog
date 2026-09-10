# CloudLog — OSINT & Threat Intel Enrichment

Two modes, picked automatically. Open the **Investigate** tab after loading logs.

## Mode 1 — OSINT deep links (default, zero setup, tool sends nothing)
Every external indicator gets a one-click pivot menu. You click through; the tool
transmits nothing itself. Private IPs / internal hosts are 🔒 not-sent (no buttons).

Sources by indicator type:
- **IP:** VirusTotal, AbuseIPDB, OTX, GreyNoise, Shodan, Censys, Pulsedive, ThreatCrowd, IPinfo, RDAP/whois, urlscan
- **Domain:** VirusTotal, OTX, urlscan, Safe Browsing, Shodan, Censys, Pulsedive, ThreatCrowd, URLhaus, crt.sh, RDAP/whois
- **URL:** VirusTotal, urlscan, Safe Browsing, URLhaus, Pulsedive
- **Hash:** VirusTotal, OTX, MalwareBazaar, ThreatFox, Hybrid Analysis, Pulsedive

## Mode 2 — Live enrichment via the local proxy (real API verdicts + batch)
Browsers can't call these APIs directly (CORS) and keys must not live in the HTML.
`threat-proxy.js` runs on your machine, holds keys in env vars, blocks private IPs
server-side, caches, and adds CORS so the tool can call it.

```bash
# set only the keys you have — the rest are skipped. Geo/ASN needs NO key.
export VT_KEY=...           # VirusTotal v3
export ABUSEIPDB_KEY=...    # AbuseIPDB v2
export OTX_KEY=...          # AlienVault OTX
export URLSCAN_KEY=...      # urlscan.io (passive search)
export GSB_KEY=...          # Google Safe Browsing v4
export GREYNOISE_KEY=...    # GreyNoise Community (scanner/benign-noise)
export SHODAN_KEY=...       # Shodan (exposed services)
export ABUSECH_KEY=...      # abuse.ch ThreatFox + MalwareBazaar (Auth-Key)
# GEO=0 to disable the free keyless ip-api geo/ASN lookup

node threat-proxy.js        # Node 18+, zero npm dependencies, http://localhost:8787
```

Reload the tool. Investigate shows **● connected** and each **Enrich** button returns
live verdicts. **Enrich all safe** batch-runs every public indicator (throttled), and
the **filter** (All / Flagged only / Enrichable / Not-sent) collapses the table to what
matters. Geo/ASN (country, ISP, ASN, hosting/proxy flags) works with no key at all.

### Rate limits are real
VirusTotal free ≈ 4 req/min; GreyNoise/Shodan/abuse.ch have their own caps. The batch
throttle helps but the ceiling is the provider's. Enrich the flagged/suspicious first.

## What is / isn't sent
- **Never:** raw log bodies, private/reserved IPs, internal hostnames/URLs, emails.
- **Only on click / batch, public indicators only:** the single value to the sources
  you enabled. Hash *lookups* are standard, but querying an internal-only hash reveals
  its existence — the tool flags that.

## AI Analyst providers
Ask AI supports **Anthropic (Claude), OpenAI (ChatGPT), and Google (Gemini)** — pick one,
use your own key, edit the model name if needed. It sends only the redacted aggregate
summary you can preview, regardless of provider.
