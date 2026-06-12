"""Harm classifier for captured text (scam DMs, defamatory posts, bio).

Deterministic, explainable pattern matching — no black-box model in the hot path,
so every label can be defended in a report ("flagged because it contains 'send
crypto to this wallet'"). The embedding hook is left for a future upgrade where
you want fuzzy coverage of novel scam phrasing.

Returns labels in [0,1] plus the exact phrases that triggered them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Money-solicitation / advance-fee / investment-scam language.
_FINANCIAL = [
    r"\bsend (?:me )?(?:money|cash|crypto|bitcoin|btc|eth|usdt|gift\s?cards?)\b",
    r"\b(?:wire|transfer|zelle|venmo|cashapp|paypal)\s+(?:me|to)\b",
    r"\b(?:investment|trading) opportunity\b",
    r"\bdouble your (?:money|crypto|investment)\b",
    r"\bguaranteed (?:returns?|profit)\b",
    r"\bseed\s?phrase|wallet\s?address|connect (?:your )?wallet\b",
    r"\bi'?m (?:stuck|stranded|in trouble).{0,40}\b(?:money|funds|help)\b",
    r"\bclaim (?:your )?(?:prize|reward|airdrop|giveaway)\b",
]

# Impersonation-defamation patterns: false statements likely to damage reputation.
_DEFAMATION = [
    r"\b(?:i am|i'?m) a (?:scammer|fraud|criminal|pedophile|thief)\b",
    r"\bdon'?t trust (?:me|this person)\b",
    r"\b(?:i )?(?:stole|scammed|cheated|defrauded)\b",
    r"\bconfess(?:ing)?\b.{0,30}\b(?:crime|fraud|affair)\b",
]

_URGENCY = [r"\b(?:urgent|act now|within \d+ (?:hours?|minutes?)|limited time|don'?t tell anyone)\b"]


@dataclass
class Classification:
    financial_solicitation: float = 0.0
    defamation: float = 0.0
    urgency: float = 0.0
    matched: dict = field(default_factory=dict)  # label -> [matched phrases]

    @property
    def primary_harm(self) -> str | None:
        ranked = sorted(
            (("financial_scam", self.financial_solicitation), ("defamation", self.defamation)),
            key=lambda kv: kv[1], reverse=True,
        )
        top, score = ranked[0]
        return top if score > 0 else None


def _scan(text: str, patterns: list[str]) -> list[str]:
    hits: list[str] = []
    for pat in patterns:
        for m in re.finditer(pat, text, flags=re.IGNORECASE):
            hits.append(m.group(0))
    return hits


def classify(text: str) -> Classification:
    if not text or not text.strip():
        return Classification()

    fin = _scan(text, _FINANCIAL)
    def_ = _scan(text, _DEFAMATION)
    urg = _scan(text, _URGENCY)

    def score(hits: list[str]) -> float:
        # Saturating: 1 hit -> 0.6, 2 -> 0.85, 3+ -> ~1.0.
        return min(1.0, 0.6 + 0.25 * (len(set(hits)) - 1)) if hits else 0.0

    return Classification(
        financial_solicitation=score(fin),
        defamation=score(def_),
        urgency=score(urg),
        matched={k: sorted(set(v)) for k, v in
                 (("financial_scam", fin), ("defamation", def_), ("urgency", urg)) if v},
    )
