#!/usr/bin/env python3
"""
phishing-triage-automation
==========================
SOAR-style phishing triage for SOC analysts.

Given a suspicious URL or file hash (SHA-256), this tool:

  1. Queries VirusTotal v3 for reputation (vendor detections, categories,
     last-analysis stats).
  2. Submits URLs to urlscan.io, polls for completion, and reads the verdict
     (malicious flag, risk score, brand-impersonation signals).
  3. Computes a composite risk score (0-100) from a transparent signal model.
  4. Emits a triage report (Markdown + JSON) with a verdict, extracted IOCs,
     a recommended SOC action, and an SLA-style priority.

API keys are read from the environment only -- never hardcoded, never logged:

    VT_API_KEY       VirusTotal v3 key (free: https://www.virustotal.com/gui/join-us)
    URLSCAN_API_KEY  urlscan.io key    (free account: https://urlscan.io/links/)

Run with --demo to execute the full pipeline against canned responses in
demo_data/ (no API keys required).
"""

from __future__ import annotations

import argparse
import base64
import datetime as _dt
import json
import os
import re
import sys
import time
import urllib.parse
from pathlib import Path

import requests

TOOL_NAME = "phishing-triage-automation"
BASE_DIR = Path(__file__).resolve().parent
DEMO_DIR = BASE_DIR / "demo_data"

VT_BASE = "https://www.virustotal.com/api/v3"
URLSCAN_SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
URLSCAN_RESULT_URL = "https://urlscan.io/api/v1/result/{uuid}/"

REQUEST_TIMEOUT = 30
URLSCAN_POLL_TIMEOUT = 180   # seconds to wait for a urlscan.io result
URLSCAN_POLL_INTERVAL = 10   # seconds between polls

HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# Canonical inputs used by --demo (canned cases ignore the user's target so
# the generated sample reports are fully coherent).
DEMO_URL_MALICIOUS = "http://m365-account-verify.example.net/login"
DEMO_URL_CLEAN = "https://www.microsoft.com/"
DEMO_HASH = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"


class TriageError(Exception):
    """User-facing failure (bad input, missing key, API problem)."""


# ---------------------------------------------------------------------------
# Scoring model.
# ---------------------------------------------------------------------------
# The model is intentionally simple and transparent: every fired signal adds
# its points to a 0-100 risk score, and the score maps to a verdict. Keep this
# in sync with the table in README.md.
#
#   Signal                                              Points
#   --------------------------------------------------  ------
#   VT: >= 5 engines flag malicious                       +35
#   VT: >= 20 engines flag malicious (overwhelming)       +30
#   VT: 1-4 engines flag malicious                        +15
#   VT: >= 3 engines flag suspicious                      +10
#   urlscan.io: overall verdict is malicious              +30
#   urlscan.io: risk score >= 50 (without malicious flag) +15
#   urlscan.io: brand impersonation detected              +15
#   VT: category contains phishing/malware/malicious      +10
#   VT: clean consensus (0 malicious, >= 40 harmless)     -20 (floor 0)
#
#   Verdict thresholds:
#     score >= 65            -> MALICIOUS
#     30 <= score < 65       -> SUSPICIOUS
#     0  <= score < 30       -> CLEAN        (when we have data)
#     no usable source data  -> UNKNOWN
# ---------------------------------------------------------------------------

VERDICT_MALICIOUS = "MALICIOUS"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_CLEAN = "CLEAN"
VERDICT_UNKNOWN = "UNKNOWN"

THREAT_CATEGORIES = {"phishing", "malware", "malicious"}

RECOMMENDED_ACTIONS = {
    VERDICT_MALICIOUS: (
        "P1",
        "1 hour",
        "Block all IOCs at the web proxy/firewall and email gateway; add the "
        "URLs/domains to the blocklist. If any user interacted with the URL or "
        "ran the file, isolate the host and force a credential reset. Open an "
        "incident ticket and notify the user.",
    ),
    VERDICT_SUSPICIOUS: (
        "P2",
        "4 hours",
        "Quarantine the message in the mail gateway and warn the recipient not "
        "to interact with it. Monitor for 24 hours; escalate to L2 if further "
        "evidence appears.",
    ),
    VERDICT_CLEAN: (
        "P4",
        "24 hours",
        "No action required. Close the alert with triage notes attached.",
    ),
    VERDICT_UNKNOWN: (
        "P2",
        "4 hours",
        "Insufficient automated evidence -- escalate to an L2 analyst for "
        "manual review.",
    ),
}


def utcnow_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def classify_target(target: str) -> tuple[str, str]:
    """Return (kind, normalized_value) where kind is 'sha256' or 'url'."""
    target = target.strip()
    if not target or any(c.isspace() for c in target):
        raise TriageError(f"Invalid target (must be a URL or SHA-256 hash): {target!r}")
    if HASH_RE.match(target):
        return "sha256", target.lower()
    if "://" not in target:
        target = "http://" + target
    parsed = urllib.parse.urlparse(target)
    if not parsed.netloc:
        raise TriageError(f"Could not parse target as a URL or SHA-256 hash: {target!r}")
    return "url", target


def require_env(name: str, purpose: str, signup_url: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise TriageError(
            f"{name} is not set.\n"
            f"  Needed for: {purpose}\n"
            f"  Get a free key: {signup_url}\n"
            f'  Then run: export {name}="your_key_here"  (or add it to a .env file)'
        )
    return value


# ---------------------------------------------------------------------------
# VirusTotal v3
# ---------------------------------------------------------------------------

def vt_url_id(url: str) -> str:
    """VT identifies a URL by its base64url encoding without padding."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _vt_error_message(status: int, source: str) -> str:
    if status == 401:
        return f"{source}: HTTP 401 -- the API key is missing or invalid."
    if status == 403:
        return f"{source}: HTTP 403 -- the key is not authorized for this endpoint."
    if status == 429:
        return f"{source}: HTTP 429 -- rate limited. Wait and retry, or continue with partial data."
    return f"{source}: HTTP {status}."


def vt_lookup(kind: str, value: str, api_key: str) -> dict:
    """Query VirusTotal. Returns a dict with status ok|submitted|error|unavailable.

    On HTTP 429/5xx the source is marked 'unavailable' so triage can continue
    with the remaining source instead of failing outright.
    """
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    try:
        if kind == "url":
            resp = requests.get(
                f"{VT_BASE}/urls/{vt_url_id(value)}", headers=headers, timeout=REQUEST_TIMEOUT
            )
        else:
            resp = requests.get(
                f"{VT_BASE}/files/{value}", headers=headers, timeout=REQUEST_TIMEOUT
            )
    except requests.RequestException as exc:
        return {"status": "unavailable", "error": f"VirusTotal request failed: {exc}"}

    if resp.status_code == 200:
        return {"status": "ok", "attributes": resp.json()["data"]["attributes"]}
    if resp.status_code == 404 and kind == "url":
        # Unknown URL: submit it for analysis so a re-run picks up results.
        try:
            sub = requests.post(
                f"{VT_BASE}/urls", headers=headers, data={"url": value}, timeout=REQUEST_TIMEOUT
            )
        except requests.RequestException as exc:
            return {"status": "unavailable", "error": f"VirusTotal submission failed: {exc}"}
        if sub.status_code == 200:
            return {
                "status": "submitted",
                "note": "URL was unknown to VirusTotal and has been submitted for analysis. "
                        "Re-run in a few minutes for reputation data.",
            }
        return {"status": "error", "error": _vt_error_message(sub.status_code, "VirusTotal")}
    if resp.status_code in (429, 500, 502, 503, 504):
        return {"status": "unavailable", "error": _vt_error_message(resp.status_code, "VirusTotal")}
    return {"status": "error", "error": _vt_error_message(resp.status_code, "VirusTotal")}


def summarize_vt(attributes: dict | None) -> dict | None:
    """Reduce a VT attributes object to the fields the scorer needs."""
    if not attributes:
        return None
    stats = attributes.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)

    results = attributes.get("last_analysis_results") or {}
    malicious_vendors = sorted(
        name for name, r in results.items()
        if isinstance(r, dict) and r.get("category") == "malicious"
    )
    categories = attributes.get("categories") or {}
    threat_categories = sorted(
        {str(v).lower() for v in categories.values()}
        & THREAT_CATEGORIES
    ) or sorted(
        # fall back to vendor result strings mentioning phishing/malware
        {str(r.get("result", "")).lower() for r in results.values()
         if isinstance(r, dict) and r.get("category") == "malicious"
         and any(k in str(r.get("result", "")).lower() for k in THREAT_CATEGORIES)}
    )

    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total_engines": malicious + suspicious + harmless + undetected,
        "malicious_vendors": malicious_vendors[:12],
        "threat_categories": threat_categories,
        "reputation": attributes.get("reputation"),
        "names": attributes.get("names") or ([attributes.get("meaningful_name")] if attributes.get("meaningful_name") else []),
        "type_description": attributes.get("type_description"),
        "hashes": {k: attributes.get(k) for k in ("md5", "sha1", "sha256") if attributes.get(k)},
    }


# ---------------------------------------------------------------------------
# urlscan.io
# ---------------------------------------------------------------------------

def urlscan_submit_and_poll(url: str, api_key: str) -> dict:
    """Submit a URL scan and poll until the result is ready.

    Returns a dict with status ok|unavailable|error.
    """
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    try:
        resp = requests.post(
            URLSCAN_SUBMIT_URL,
            headers=headers,
            json={"url": url, "visibility": "public"},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        return {"status": "unavailable", "error": f"urlscan.io submission failed: {exc}"}

    if resp.status_code == 429:
        return {"status": "unavailable",
                "error": _vt_error_message(429, "urlscan.io") + " (daily scan quota may be exhausted)"}
    if resp.status_code not in (200, 201):
        return {"status": "error", "error": _vt_error_message(resp.status_code, "urlscan.io")}

    try:
        uuid = resp.json()["uuid"]
    except (KeyError, ValueError):
        return {"status": "error", "error": "urlscan.io: unexpected submission response."}

    result_url = URLSCAN_RESULT_URL.format(uuid=uuid)
    deadline = time.time() + URLSCAN_POLL_TIMEOUT
    while time.time() < deadline:
        try:
            poll = requests.get(result_url, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            return {"status": "unavailable", "error": f"urlscan.io poll failed: {exc}"}
        if poll.status_code == 200:
            return {"status": "ok", "result": poll.json(), "uuid": uuid}
        if poll.status_code != 404:  # 404 == still scanning
            return {"status": "error", "error": _vt_error_message(poll.status_code, "urlscan.io")}
        time.sleep(URLSCAN_POLL_INTERVAL)
    return {"status": "unavailable",
            "error": f"urlscan.io: result not ready after {URLSCAN_POLL_TIMEOUT}s (uuid {uuid})."}


def summarize_urlscan(result: dict | None) -> dict | None:
    """Reduce a urlscan.io result object to the fields the scorer needs."""
    if not result:
        return None
    verdicts = result.get("verdicts") or {}
    overall = verdicts.get("overall") or {}
    page = result.get("page") or {}
    lists = result.get("lists") or {}
    brands = overall.get("brands") or {}
    impersonated = sorted(
        brand for brand, info in brands.items()
        if isinstance(info, dict) and (info.get("detected") or info.get("impersonated"))
    )
    return {
        "malicious": bool(overall.get("malicious")),
        "score": int(overall.get("score", 0) or 0),
        "categories": overall.get("categories") or [],
        "impersonated_brands": impersonated,
        "page": {
            "url": page.get("url"),
            "domain": page.get("domain"),
            "ip": page.get("ip"),
            "country": page.get("country"),
            "title": page.get("title"),
        },
        "lists": {
            "ips": (lists.get("ips") or [])[:25],
            "domains": (lists.get("domains") or [])[:25],
            "urls": (lists.get("urls") or [])[:25],
            "hashes": (lists.get("hashes") or [])[:10],
        },
    }


# ---------------------------------------------------------------------------
# Scoring, verdict, IOCs
# ---------------------------------------------------------------------------

def compute_score(vt: dict | None, us: dict | None) -> tuple[int, list[dict]]:
    """Apply the transparent signal model. Returns (score 0-100, fired signals)."""
    signals: list[dict] = []
    score = 0

    def add(name: str, points: int, detail: str) -> None:
        nonlocal score
        score += points
        signals.append({"signal": name, "points": points, "detail": detail})

    if vt:
        m = vt["malicious"]
        if m >= 5:
            add("VT: >= 5 engines flag malicious", 35, f"{m} vendors flagged malicious")
            if m >= 20:
                # Overwhelming consensus: compensates for URL-only signals
                # (urlscan brand/score) that never fire on file-hash input.
                add("VT: overwhelming consensus (>= 20 engines)", 30,
                    f"{m} vendors flagged malicious")
        elif m >= 1:
            add("VT: 1-4 engines flag malicious", 15, f"{m} vendor(s) flagged malicious")
        if vt["suspicious"] >= 3:
            add("VT: >= 3 engines flag suspicious", 10,
                f"{vt['suspicious']} vendors flagged suspicious")
        if vt["threat_categories"]:
            add("VT: threat category present", 10,
                f"categories: {', '.join(vt['threat_categories'])}")
        if m == 0 and vt["harmless"] >= 40:
            add("VT: clean consensus", -20,
                f"0 malicious, {vt['harmless']} harmless verdicts")

    if us:
        if us["malicious"]:
            add("urlscan.io: overall verdict malicious", 30,
                f"urlscan score {us['score']}/100")
        elif us["score"] >= 50:
            add("urlscan.io: elevated risk score", 15,
                f"urlscan score {us['score']}/100 without a malicious flag")
        if us["impersonated_brands"]:
            add("urlscan.io: brand impersonation detected", 15,
                f"impersonated: {', '.join(us['impersonated_brands'])}")

    score = max(0, min(100, score))
    return score, signals


def decide_verdict(score: int, has_data: bool) -> str:
    if not has_data:
        return VERDICT_UNKNOWN
    if score >= 65:
        return VERDICT_MALICIOUS
    if score >= 30:
        return VERDICT_SUSPICIOUS
    return VERDICT_CLEAN


def extract_iocs(kind: str, value: str, vt_attributes: dict | None,
                 us_result: dict | None) -> dict:
    """Collect IOCs (urls, domains, ips, hashes) from both sources."""
    iocs: dict[str, list[str]] = {"urls": [], "domains": [], "ips": [], "hashes": []}

    def add(bucket: str, item) -> None:
        if item and item not in iocs[bucket]:
            iocs[bucket].append(item)

    if kind == "url":
        add("urls", value)
        final = (vt_attributes or {}).get("last_final_url")
        if final and final != value:
            add("urls", final)
    else:
        for label in ("sha256", "sha1", "md5"):
            h = (vt_attributes or {}).get(label)
            if h:
                add("hashes", f"{label}:{h}")
        if not iocs["hashes"]:
            add("hashes", f"sha256:{value}")

    if us_result:
        page = us_result.get("page") or {}
        add("urls", page.get("url"))
        add("domains", page.get("domain"))
        add("ips", page.get("ip"))
        lists = us_result.get("lists") or {}
        for ip in (lists.get("ips") or [])[:25]:
            add("ips", ip)
        for domain in (lists.get("domains") or [])[:25]:
            add("domains", domain)
        for h in (lists.get("hashes") or [])[:10]:
            add("hashes", h)
        # page resources beyond the landing URL can reveal payload/CDN hosts
        for u in (lists.get("urls") or [])[:25]:
            if u and u != value:
                host = urllib.parse.urlparse(u).netloc
                if host and host != page.get("domain"):
                    add("urls", u)
    return iocs


# ---------------------------------------------------------------------------
# Demo mode (canned API responses -- no keys required)
# ---------------------------------------------------------------------------

def load_demo(case: str, kind: str) -> tuple[str, dict | None, dict | None]:
    """Return (canonical_input, vt_attributes, urlscan_result) for a demo case."""
    def read(name: str) -> dict:
        path = DEMO_DIR / name
        if not path.exists():
            raise TriageError(f"Demo data file missing: {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    if case not in ("malicious", "clean"):
        raise TriageError("--demo-case must be 'malicious' or 'clean'.")

    if kind == "sha256":
        vt = read("vt_file_malicious.json")["data"]["attributes"]
        return DEMO_HASH, vt, None

    vt = read(f"vt_url_{case}.json")["data"]["attributes"]
    us = read(f"urlscan_{case}.json")
    canonical = DEMO_URL_MALICIOUS if case == "malicious" else DEMO_URL_CLEAN
    return canonical, vt, us


# ---------------------------------------------------------------------------
# Report building + rendering
# ---------------------------------------------------------------------------

def build_report(kind: str, value: str, mode: str, vt_lookup_result: dict,
                 us_lookup_result: dict | None) -> dict:
    vt_attributes = vt_lookup_result.get("attributes") if vt_lookup_result.get("status") == "ok" else None
    us_result = (us_lookup_result or {}).get("result") if (us_lookup_result or {}).get("status") == "ok" else None

    vt = summarize_vt(vt_attributes)
    us = summarize_urlscan(us_result)
    has_data = vt is not None or us is not None

    score, signals = compute_score(vt, us)
    verdict = decide_verdict(score, has_data)
    priority, sla, action = RECOMMENDED_ACTIONS[verdict]

    sources = {"virustotal": vt_lookup_result.get("status", "skipped")}
    if vt_lookup_result.get("status") in ("error", "unavailable"):
        sources["virustotal_detail"] = vt_lookup_result.get("error", "")
    if vt_lookup_result.get("status") == "submitted":
        sources["virustotal_detail"] = vt_lookup_result.get("note", "")
    if us_lookup_result is None:
        sources["urlscan"] = "skipped (hash input -- urlscan.io scans URLs only)"
    else:
        sources["urlscan"] = us_lookup_result.get("status", "skipped")
        if us_lookup_result.get("status") in ("error", "unavailable"):
            sources["urlscan_detail"] = us_lookup_result.get("error", "")

    return {
        "tool": TOOL_NAME,
        "generated_at": utcnow_iso(),
        "mode": mode,
        "input": {"type": kind, "value": value},
        "sources": sources,
        "virustotal": vt,
        "urlscan": us,
        "score": score,
        "signals": signals,
        "verdict": verdict,
        "priority": priority,
        "sla": sla,
        "recommended_action": action,
        "iocs": extract_iocs(kind, value, vt_attributes, us_result),
    }


def _fmt_list(items: list, empty: str = "none") -> str:
    return ", ".join(str(i) for i in items) if items else empty


def render_markdown(report: dict) -> str:
    v = report["verdict"]
    lines = [
        "# Phishing Triage Report",
        "",
        f"**Verdict:** {v} &nbsp;|&nbsp; **Risk score:** {report['score']}/100 "
        f"&nbsp;|&nbsp; **Priority:** {report['priority']} (SLA: {report['sla']})",
        "",
        f"_Generated {report['generated_at']} by `{report['tool']}` "
        f"| mode: {report['mode']} | input ({report['input']['type']}): `{report['input']['value']}`_",
        "",
        "## Signal breakdown",
        "",
        "| Signal | Points | Detail |",
        "| --- | ---: | --- |",
    ]
    if report["signals"]:
        for s in report["signals"]:
            lines.append(f"| {s['signal']} | {s['points']:+d} | {s['detail']} |")
    else:
        lines.append("| _no signals fired_ | 0 | insufficient source data |")
    lines += ["", f"**Total: {report['score']}/100 -> {v}**", ""]

    vt = report["virustotal"]
    lines += ["## VirusTotal", ""]
    if vt:
        lines += [
            f"- Detections: **{vt['malicious']} malicious** / {vt['suspicious']} suspicious / "
            f"{vt['harmless']} harmless / {vt['undetected']} undetected "
            f"({vt['total_engines']} engines)",
            f"- Threat categories: {_fmt_list(vt['threat_categories'])}",
            f"- Flagging vendors: {_fmt_list(vt['malicious_vendors'])}",
        ]
        if vt.get("reputation") is not None:
            lines.append(f"- Community reputation score: {vt['reputation']}")
        if vt.get("names"):
            lines.append(f"- Known names: {_fmt_list(vt['names'])}")
        if vt.get("type_description"):
            lines.append(f"- File type: {vt['type_description']}")
    else:
        lines.append(f"- {_fmt_list([], report['sources'].get('virustotal_detail', 'no data'))}")
    lines += [""]

    us = report["urlscan"]
    lines += ["## urlscan.io", ""]
    if us:
        page = us["page"]
        lines += [
            f"- Overall verdict: **{'malicious' if us['malicious'] else 'not malicious'}** "
            f"(score {us['score']}/100)",
            f"- Categories: {_fmt_list(us['categories'])}",
            f"- Brand impersonation: {_fmt_list(us['impersonated_brands'])}",
            f"- Page: `{page.get('url')}` -- {page.get('title') or 'no title'} "
            f"({page.get('domain')}, {page.get('ip')}, {page.get('country')})",
        ]
    else:
        detail = report["sources"].get("urlscan_detail") or report["sources"].get("urlscan", "no data")
        lines.append(f"- {detail}")
    lines += [""]

    lines += ["## IOCs", ""]
    iocs = report["iocs"]
    for bucket in ("urls", "domains", "ips", "hashes"):
        lines.append(f"- **{bucket}:**")
        if iocs[bucket]:
            lines += [f"  - `{i}`" for i in iocs[bucket]]
        else:
            lines.append("  - none")
    lines += [""]

    lines += [
        "## Recommended SOC action",
        "",
        f"**{report['priority']}** -- respond within **{report['sla']}**.",
        "",
        report["recommended_action"],
        "",
        "---",
        f"_Report generated by {report['tool']}._"
        + (" _Demo mode: results are based on canned API responses._" if report["mode"] == "demo" else ""),
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="triage.py",
        description="SOAR-style phishing triage: URL/file-hash reputation via "
                    "VirusTotal + urlscan.io, composite risk score, Markdown/JSON report.",
    )
    p.add_argument("target", help="Suspicious URL or file hash (SHA-256).")
    p.add_argument("--demo", action="store_true",
                   help="Run against canned API responses in demo_data/ (no API keys needed). "
                        "The target value is replaced by the canned case input.")
    p.add_argument("--demo-case", choices=["malicious", "clean"], default="malicious",
                   help="Which canned case to use with --demo (default: malicious).")
    p.add_argument("--json", dest="json_path", default="triage-report.json",
                   help="Where to write the JSON report (default: triage-report.json).")
    p.add_argument("--md", dest="md_path", default="triage-report.md",
                   help="Where to write the Markdown report (default: triage-report.md).")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])

    try:
        kind, value = classify_target(args.target)

        if args.demo:
            mode = "demo"
            value, vt_attributes, us_result = load_demo(args.demo_case, kind)
            vt_lookup_result = {"status": "ok", "attributes": vt_attributes}
            us_lookup_result = (
                {"status": "ok", "result": us_result}
                if us_result is not None
                else None
            )
            print(f"[*] demo mode: canned '{args.demo_case}' case "
                  f"({'URL' if kind == 'url' else 'file hash'}), no API calls made.", file=sys.stderr)
        else:
            mode = "live"
            vt_key = require_env(
                "VT_API_KEY", "VirusTotal reputation lookups",
                "https://www.virustotal.com/gui/join-us",
            )
            print("[*] querying VirusTotal...", file=sys.stderr)
            vt_lookup_result = vt_lookup(kind, value, vt_key)
            if vt_lookup_result["status"] == "error":
                raise TriageError(vt_lookup_result["error"])
            if vt_lookup_result["status"] == "submitted":
                print(f"[*] {vt_lookup_result['note']}", file=sys.stderr)

            us_lookup_result = None
            if kind == "url":
                us_key = require_env(
                    "URLSCAN_API_KEY", "urlscan.io dynamic URL scans",
                    "https://urlscan.io/links/",
                )
                print("[*] submitting to urlscan.io (this can take a minute)...", file=sys.stderr)
                us_lookup_result = urlscan_submit_and_poll(value, us_key)
                if us_lookup_result["status"] == "error":
                    raise TriageError(us_lookup_result["error"])

        report = build_report(kind, value, mode, vt_lookup_result, us_lookup_result)
        markdown = render_markdown(report)

        Path(args.json_path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        Path(args.md_path).write_text(markdown, encoding="utf-8")

        print(markdown)
        print(f"[*] reports written: {args.md_path}, {args.json_path}", file=sys.stderr)
        return 0

    except TriageError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[!] interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
