"""Confidence-score fusion.

Combines independent signals into one number a human can act on. Weights are
explicit and tunable; the breakdown is preserved so a reviewer (or an appeal)
can see *why* a suspect scored where it did.

The score is advisory. It decides whether a case enters the human review queue —
it never decides to submit anything.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict


@dataclass
class SignalInputs:
    face: float = 0.0            # 0..1 from verification.face_match
    text: float = 0.0           # 0..1 from verification.text_similarity
    watermark_hit: bool = False  # invisible watermark found on a non-official copy
    account_age_days: int | None = None
    followers: int | None = None
    following: int | None = None
    network_overlap: float | None = None  # 0..1 shared-follower fraction


# A watermark hit is near-dispositive: it means *your* pixels (with your secret
# mark) are on an account that isn't yours. It gets a large additive boost rather
# than a weight, because it's evidence of theft, not a soft similarity.
WEIGHTS = {"face": 0.45, "text": 0.20, "heuristics": 0.35}
WATERMARK_BOOST = 0.40


@dataclass
class Decision:
    score: float
    enters_review: bool
    breakdown: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def _heuristic_score(s: SignalInputs) -> tuple[float, list[str]]:
    """Behavioural red flags common to impersonation accounts. Each is a weak
    signal on its own; together they nudge the score. Returns 0..1 + reasons."""
    points, notes, max_points = 0.0, [], 0.0

    if s.account_age_days is not None:
        max_points += 1
        if s.account_age_days < 30:
            points += 1
            notes.append(f"account is {s.account_age_days}d old (very new)")
        elif s.account_age_days < 180:
            points += 0.5
            notes.append(f"account is {s.account_age_days}d old (recent)")

    if s.followers is not None and s.following is not None and s.following > 0:
        max_points += 1
        ratio = s.followers / s.following
        if ratio < 0.1:
            points += 1
            notes.append(f"follows {s.following} but only {s.followers} followers (ratio {ratio:.2f})")
        elif ratio < 0.5:
            points += 0.5
            notes.append(f"low follower/following ratio ({ratio:.2f})")

    if s.network_overlap is not None:
        max_points += 1
        if s.network_overlap > 0.3:
            points += 1
            notes.append(f"{s.network_overlap:.0%} of your followers also followed by suspect (targeting your network)")
        elif s.network_overlap > 0.1:
            points += 0.5
            notes.append(f"{s.network_overlap:.0%} network overlap")

    return (points / max_points if max_points else 0.0), notes


def fuse(s: SignalInputs, review_threshold: float = 0.90) -> Decision:
    heur, heur_notes = _heuristic_score(s)
    base = (
        WEIGHTS["face"] * s.face
        + WEIGHTS["text"] * s.text
        + WEIGHTS["heuristics"] * heur
    )
    score = base + (WATERMARK_BOOST if s.watermark_hit else 0.0)
    score = max(0.0, min(1.0, score))

    notes = list(heur_notes)
    if s.watermark_hit:
        notes.insert(0, "invisible watermark found on a non-official copy — strong theft evidence")

    return Decision(
        score=round(score, 4),
        enters_review=score >= review_threshold,
        breakdown={
            "face": s.face, "text": s.text, "heuristics": round(heur, 4),
            "watermark_hit": s.watermark_hit, "weights": WEIGHTS,
            "inputs": asdict(s),
        },
        notes=notes,
    )
