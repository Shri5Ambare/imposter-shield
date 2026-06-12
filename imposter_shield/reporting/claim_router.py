"""Claim router: pick the right remediation channel(s) for a case.

Different harms need different tracks. Sending a DMCA for defamation gets
rejected; sending a polite impersonation report for an active scam under-prices
the urgency. This module reads the case signals + harm evidence and returns an
ordered list of recommended channels, each with a rationale and the draft to use.

Every recommendation is `requires_human=True`. The router decides *what to
prepare*, never *whether to send*.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Recommendation:
    channel: str                  # dmca | fraud_report | defamation_notice | impersonation_report
    priority: str                 # critical | high | medium
    rationale: str
    draft_kind: str               # which template the UI should generate
    requires_human: bool = True


_PRIORITY_RANK = {"critical": 0, "high": 1, "medium": 2}


@dataclass
class CaseSignals:
    confidence: float
    watermark_or_phash_hit: bool = False     # stolen photo -> copyright track
    harm_kinds: set[str] = field(default_factory=set)  # from HarmEvidence.kind
    has_phishing_or_malware_link: bool = False


def route(signals: CaseSignals) -> list[Recommendation]:
    recs: list[Recommendation] = []

    # 1. Active financial harm to third parties — highest urgency.
    if "financial_scam" in signals.harm_kinds:
        recs.append(Recommendation(
            channel="fraud_report", priority="critical", draft_kind="fraud_report",
            rationale="Account is soliciting money from the victim's audience; ongoing "
                      "financial harm to third parties escalates this to fraud.",
        ))

    # 2. Malware/phishing distribution — platforms treat this as critical.
    if signals.has_phishing_or_malware_link or "phishing" in signals.harm_kinds \
            or "malware" in signals.harm_kinds:
        recs.append(Recommendation(
            channel="fraud_report", priority="critical", draft_kind="fraud_report",
            rationale="Account distributes phishing/malware links; flag as critical "
                      "security threat, not routine impersonation.",
        ))

    # 3. Defamation — separate legal track, jurisdiction-sensitive.
    if "defamation" in signals.harm_kinds:
        recs.append(Recommendation(
            channel="defamation_notice", priority="high", draft_kind="defamation_notice",
            rationale="False statements of fact published under the victim's name; "
                      "defamation track, requires legal review (not DMCA).",
        ))

    # 4. Stolen photos — copyright track (highest takedown success when clean).
    if signals.watermark_or_phash_hit:
        recs.append(Recommendation(
            channel="dmca", priority="high", draft_kind="dmca",
            rationale="Verified theft of the victim's photographs; DMCA to the "
                      "platform's registered copyright agent.",
        ))

    # 5. Always offer the baseline impersonation report.
    recs.append(Recommendation(
        channel="impersonation_report", priority="medium", draft_kind="impersonation_report",
        rationale="Baseline identity-impersonation report via the platform's official form.",
    ))

    # De-duplicate channels, keep the highest priority instance, then sort.
    best: dict[str, Recommendation] = {}
    for r in recs:
        cur = best.get(r.channel)
        if cur is None or _PRIORITY_RANK[r.priority] < _PRIORITY_RANK[cur.priority]:
            best[r.channel] = r
    return sorted(best.values(), key=lambda r: _PRIORITY_RANK[r.priority])
