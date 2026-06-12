"""Bio-link safety triage.

Fake accounts usually exist to funnel the real person's followers to a scam.
This module assesses 'link in bio' URLs *without executing anything dangerous*:
no JS execution, no form submission, no downloading payloads here. It pulls
reputation signals and static heuristics, and flags anything that warrants a
real sandbox detonation by a security analyst.

If you want true dynamic detonation, hand the URL to a dedicated, isolated
service (urlscan.io, VirusTotal, a Cuckoo/CAPEv2 instance on an air-gapped VLAN).
Do NOT detonate untrusted URLs on the same host that runs this pipeline.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests


SUSPICIOUS_TLDS = {".top", ".xyz", ".gq", ".tk", ".ml", ".cf", ".click", ".live"}
SCAM_KEYWORDS = re.compile(
    r"\b(airdrop|free\s?crypto|double\s?your|giveaway|claim\s?now|wallet\s?connect|"
    r"seed\s?phrase|verify\s?wallet|elon|metamask\s?support)\b", re.I)
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly", "rebrand.ly"}


@dataclass
class LinkVerdict:
    url: str
    final_url: str = ""
    risk: str = "unknown"        # low | medium | high | unknown
    reasons: list[str] = field(default_factory=list)
    redirect_chain: list[str] = field(default_factory=list)


def triage(url: str, *, timeout: int = 8, vt_api_key: str | None = None) -> LinkVerdict:
    v = LinkVerdict(url=url)
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = (parsed.hostname or "").lower()

    if host in SHORTENERS:
        v.reasons.append(f"URL shortener ({host}) hides the real destination")
    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        v.reasons.append(f"low-reputation TLD on {host}")

    # Resolve redirects with a HEAD/GET but never execute page scripts.
    try:
        resp = requests.get(
            parsed.geturl(), timeout=timeout, allow_redirects=True,
            headers={"User-Agent": "ImposterShield-Triage/1.0 (+safety scan)"},
            stream=True,  # don't pull the body into memory blindly
        )
        v.redirect_chain = [r.url for r in resp.history] + [resp.url]
        v.final_url = resp.url
        snippet = resp.raw.read(4096, decode_content=True).decode("utf-8", "ignore")
        resp.close()
        if SCAM_KEYWORDS.search(snippet):
            v.reasons.append("crypto/giveaway scam keywords in landing page")
        if len(v.redirect_chain) > 3:
            v.reasons.append(f"long redirect chain ({len(v.redirect_chain)} hops)")
    except requests.RequestException as exc:
        v.reasons.append(f"could not fetch ({exc.__class__.__name__})")

    if vt_api_key and v.final_url:
        _augment_with_virustotal(v, vt_api_key)

    # Severity from accumulated reasons.
    if any("scam keyword" in r or "malicious" in r for r in v.reasons):
        v.risk = "high"
    elif len(v.reasons) >= 2:
        v.risk = "medium"
    elif v.reasons:
        v.risk = "low"
    else:
        v.risk = "low"
    return v


def _augment_with_virustotal(v: LinkVerdict, api_key: str) -> None:
    """Pull existing VT reputation (a lookup, not a detonation)."""
    import base64
    try:
        url_id = base64.urlsafe_b64encode(v.final_url.encode()).decode().strip("=")
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key}, timeout=10)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            mal = stats.get("malicious", 0)
            if mal:
                v.reasons.append(f"VirusTotal: {mal} engines flag this URL as malicious")
    except Exception as exc:  # noqa: BLE001
        v.reasons.append(f"VT lookup failed ({exc.__class__.__name__})")
