# Phishing Triage Automation

A SOAR-style phishing triage tool for SOC analysts. Give it a suspicious URL or
file hash (SHA-256) and it queries **VirusTotal** and **urlscan.io**, computes a
**transparent composite risk score**, and emits a triage report (Markdown +
JSON) with a verdict, extracted IOCs, a recommended SOC action, and an
SLA-style priority.

## The problem

Tier-1 analysts drown in phishing alerts. Each one triggers the same manual
routine: paste the URL into VirusTotal, wait for urlscan.io, eyeball vendor
counts, decide block vs. close. It's slow, inconsistent between analysts, and
it burns the SLA clock on alerts that turn out to be benign.

This tool automates the evidence-gathering and the first-pass decision, so the
analyst starts from a scored verdict with IOCs and a recommended action --
not a blank browser tab.

## How it works

```
                 +------------------+
                 |  URL or SHA-256  |
                 +--------+---------+
                          |
            +-------------+-------------+
            |                           |
   +----------------+          +------------------+
   |  VirusTotal    |          |  urlscan.io      |
   |  v3 API        |          |  submit + poll   |
   |  reputation,   |          |  verdict, score, |
   |  detections,   |          |  brand signals   |
   |  categories    |          |                  |
   +-------+--------+          +--------+---------+
           |                            |
           +-------------+--------------+
                         |
                +--------+--------+
                |  Scoring model  |  transparent, points-based (see below)
                +--------+--------+
                         |
           +-------------+-------------+
           |             |             |
     Markdown report  JSON report    IOCs + action + priority
```

For URLs: VirusTotal reputation lookup (with automatic submission if the URL
is unknown) **and** a live urlscan.io dynamic scan with polling.
For file hashes: VirusTotal file report (urlscan.io scans URLs only, so it is
skipped and the model compensates -- see the "overwhelming consensus" signal).

## Scoring model

Every fired signal adds its points to a 0-100 risk score. No black boxes --
each report lists exactly which signals fired and why.

| Signal | Points |
| --- | ---: |
| VT: >= 5 engines flag malicious | +35 |
| VT: >= 20 engines flag malicious (overwhelming consensus) | +30 |
| VT: 1-4 engines flag malicious | +15 |
| VT: >= 3 engines flag suspicious | +10 |
| urlscan.io: overall verdict is malicious | +30 |
| urlscan.io: risk score >= 50 (without a malicious flag) | +15 |
| urlscan.io: brand impersonation detected | +15 |
| VT: category contains phishing / malware / malicious | +10 |
| VT: clean consensus (0 malicious, >= 40 harmless) | -20 (floor 0) |

**Verdict thresholds**

| Score | Verdict | Priority | SLA |
| --- | --- | --- | --- |
| >= 65 | MALICIOUS | P1 | 1 hour |
| 30 - 64 | SUSPICIOUS | P2 | 4 hours |
| 0 - 29 (with data) | CLEAN | P4 | 24 hours |
| no usable source data | UNKNOWN | P2 | 4 hours (escalate to L2) |

## Setup

Python 3.8+ and `requests` only:

```bash
pip install -r requirements.txt
```

Both APIs have free tiers -- no credit card required:

1. **VirusTotal**: create an account at <https://www.virustotal.com/gui/join-us>,
   then copy your API key from your profile page.
2. **urlscan.io**: create an account at <https://urlscan.io/links/>, then copy
   your API key from your profile settings.

Export the keys (never hardcode them):

```bash
export VT_API_KEY="your_virustorm_key"
export URLSCAN_API_KEY="your_urlscan_key"
# tip: copy .env.example to .env if you use a dotenv workflow
```

## Usage

```bash
# Triage a suspicious URL (live APIs)
python3 triage.py "http://suspicious-login.example.net/verify"

# Triage a file hash (SHA-256)
python3 triage.py 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

# Custom output paths
python3 triage.py "http://suspicious.example.net/" --md case-1234.md --json case-1234.json

# Demo mode -- full pipeline against canned API responses, no keys needed
python3 triage.py --demo --demo-case malicious "http://m365-account-verify.example.net/login"
python3 triage.py --demo --demo-case clean "https://www.microsoft.com/"
```

Each run prints the Markdown report to stdout and writes both
`triage-report.md` and `triage-report.json` (or your `--md` / `--json` paths).

## Demo walkthrough

No API keys? The `demo_data/` directory contains realistic canned VirusTotal
and urlscan.io responses for two cases. Run the full pipeline end to end:

```bash
# Case 1: credential-phishing URL impersonating Microsoft 365
python3 triage.py --demo --demo-case malicious "http://m365-account-verify.example.net/login"

# Case 2: known-benign URL
python3 triage.py --demo --demo-case clean "https://www.microsoft.com/"

# Case 3: malicious file hash (VirusTotal only -- urlscan.io is URL-only)
python3 triage.py --demo 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

Expected results: **MALICIOUS (100/100, P1)** for the phishing URL,
**CLEAN (0/100, P4)** for the benign URL, **MALICIOUS (65/100, P1)** for the
file hash. Pre-generated outputs live in `sample_report_malicious.md` and
`sample_report_clean.md`.

## Sample verdict (malicious case, abridged)

```markdown
**Verdict:** MALICIOUS | **Risk score:** 100/100 | **Priority:** P1 (SLA: 1 hour)

| Signal | Points | Detail |
| --- | ---: | --- |
| VT: >= 5 engines flag malicious | +35 | 12 vendors flagged malicious |
| VT: >= 3 engines flag suspicious | +10 | 3 vendors flagged suspicious |
| VT: threat category present | +10 | categories: malicious, phishing |
| urlscan.io: overall verdict malicious | +30 | urlscan score 100/100 |
| urlscan.io: brand impersonation detected | +15 | impersonated: microsoft |

## Recommended SOC action
**P1** -- respond within **1 hour**.
Block all IOCs at the web proxy/firewall and email gateway; add the
URLs/domains to the blocklist. If any user interacted with the URL or ran the
file, isolate the host and force a credential reset. Open an incident ticket
and notify the user.
```

Full examples: [`sample_report_malicious.md`](sample_report_malicious.md),
[`sample_report_clean.md`](sample_report_clean.md).

## Recommended SOC workflow integration

1. **Alert ingestion** -- a SIEM/SOAR playbook (Sentinel, Splunk SOAR) extracts
   the URL or hash from a phishing alert and invokes `triage.py`.
2. **Auto-triage** -- the JSON report feeds the ticket: verdict, score,
   priority, and IOCs populate the incident fields automatically.
3. **Auto-containment (MALICIOUS)** -- the IOC lists (`iocs.urls`,
   `iocs.domains`, `iocs.ips`, `iocs.hashes`) are pushed to the proxy,
   firewall, and EDR blocklists via API.
4. **Analyst review** -- SUSPICIOUS and UNKNOWN verdicts route to the L2
   queue with the full signal breakdown attached, so the analyst reviews
   evidence instead of gathering it.
5. **Close-out** -- CLEAN verdicts auto-close with the report attached as
   documentation.

## Limitations

- **API rate limits**: free VirusTotal keys allow ~4 requests/minute;
  urlscan.io free accounts have a daily scan quota. The tool degrades
  gracefully (a rate-limited source is marked `unavailable` and scoring
  continues with the remaining source), but heavy automation needs paid tiers.
- **Unknown URLs**: a URL never seen by VirusTotal is submitted for analysis
  and the report notes it -- re-run after a few minutes for reputation data.
- **Evasion**: sophisticated phishing kits cloak content from scanners
  (including urlscan.io). A CLEAN verdict means "no evidence of malice", not
  "provably safe" -- treat high-risk contexts (targeted spear-phishing
  reports) accordingly.
- **urlscan.io visibility**: scans are submitted as public. Do not submit
  URLs containing sensitive tokens or internal hostnames unless your
  organization approves.
- **Demo data is fictional**: canned responses use RFC 2606 reserved domains
  (`example.net`) and fabricated verdicts for illustration only.

## Roadmap

- [ ] **abuseIPDB** enrichment -- IP reputation and abuse-confidence scoring
      for extracted infrastructure IPs.
- [ ] **PhishTank** lookup -- community-verified phishing URL corroboration.
- [ ] **Microsoft 365 submission API** -- one-command submission of confirmed
      phish to Defender for Office 365 (admin submission) straight from a
      MALICIOUS verdict.
- [ ] SOAR playbook templates (Sentinel Logic Apps, Splunk SOAR) wrapping
      the CLI.
- [ ] Weighted model tuning -- ROC-style threshold analysis against a labeled
      URL corpus.

## Project structure

```
phishing-triage-automation/
├── triage.py                  # CLI: lookup, scoring, report generation
├── demo_data/                 # canned VT + urlscan.io responses for --demo
│   ├── vt_url_malicious.json
│   ├── urlscan_malicious.json
│   ├── vt_url_clean.json
│   ├── urlscan_clean.json
│   └── vt_file_malicious.json
├── sample_report_malicious.md # example output: phishing URL case
├── sample_report_clean.md     # example output: benign URL case
├── requirements.txt           # requests only
├── .env.example               # API key template (never commit real keys)
└── .gitignore
```

## Disclaimer

Built as a portfolio project demonstrating SOC automation, API integration,
and detection-triage thinking. Scan only URLs and files you are authorized
to analyze, and respect each API provider's terms of service.
