"""End-to-end orchestration for one suspect candidate.

This is the function a Celery worker calls per discovered candidate. It runs the
automated half (verify → score → assemble evidence) and then *stops at the human
review queue*. Nothing past assembly happens without a person.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .ingestion.discovery import SourceOfTruth, SuspectCandidate
from .core import verification, scoring, watermark
from .core.dossier import DossierData, build_dossier


@dataclass
class CaseResult:
    suspect_url: str
    decision: scoring.Decision
    dossier_path: str | None = None
    queued_for_review: bool = False
    notes: list[str] = field(default_factory=list)


def process_candidate(
    truth: SourceOfTruth,
    candidate: SuspectCandidate,
    *,
    suspect_image_path: str | None = None,
    review_threshold: float = 0.90,
    out_dir: str = "./out",
) -> CaseResult:
    """Verify and score one candidate, building a dossier if it warrants review."""
    notes: list[str] = []

    # 1. Computer vision
    face = verification.FaceSignal(0.0, False, 1.0, 0.0, "n/a")
    if suspect_image_path and truth.image_paths:
        face = verification.face_match(truth.image_paths, suspect_image_path)
        notes.append(f"face: {face.score:.2f} ({face.detail})")

    # 2. NLP
    text = verification.text_similarity([truth.canonical_bio], [candidate.bio])
    notes.append(f"bio similarity: {text.score:.2f}")

    # 3. Watermark / provenance
    wm_hit = False
    if suspect_image_path:
        if watermark.extract_watermark(suspect_image_path):
            wm_hit = True
            notes.append("invisible watermark present on suspect image")
        elif truth.image_phashes:
            for th in truth.image_phashes:
                if watermark.compare_phash(th, suspect_image_path).is_match:
                    wm_hit = True
                    notes.append("perceptual-hash match: suspect reused an official photo")
                    break

    # 4. Fuse into a confidence score
    decision = scoring.fuse(
        scoring.SignalInputs(
            face=face.score,
            text=text.score,
            watermark_hit=wm_hit,
            account_age_days=candidate.metadata.get("account_age_days"),
            followers=candidate.metadata.get("followers"),
            following=candidate.metadata.get("following"),
            network_overlap=candidate.metadata.get("network_overlap"),
        ),
        review_threshold=review_threshold,
    )

    result = CaseResult(suspect_url=candidate.url, decision=decision, notes=notes)
    if not decision.enters_review:
        return result

    # 5. Assemble evidence (still automated) — then hand to humans.
    import os
    os.makedirs(out_dir, exist_ok=True)
    case_id = f"{candidate.platform}-{candidate.handle}"
    dossier_path = os.path.join(out_dir, f"dossier-{case_id}.pdf")
    build_dossier(
        DossierData(
            case_id=case_id,
            protected_name=truth.name,
            protected_handle=truth.handles.get(candidate.platform, ""),
            suspect_url=candidate.url,
            suspect_handle=candidate.handle,
            confidence=decision.score,
            score_breakdown=decision.breakdown,
            notes=decision.notes + notes,
            truth_image_path=truth.image_paths[0] if truth.image_paths else None,
            suspect_image_path=suspect_image_path,
            reviewer="UNASSIGNED",   # set when a human picks up the case
        ),
        dossier_path,
    )
    result.dossier_path = dossier_path
    result.queued_for_review = True
    return result
