"""Celery tasks: async face-match + full verification pipeline per suspect.

Flow triggered when a suspect is created via POST /api/suspects:
  1. verify_suspect(suspect_id, truth_image_paths)
     - downloads/fetches suspect profile images
     - runs face match (DeepFace ArcFace) + perceptual hash + watermark check
     - runs NLP bio similarity (SentenceTransformers, Jaccard fallback)
     - fuses all signals into a ConfidenceScore
     - persists ScoreRecord + updates suspect status
     - if score >= review_threshold → emits notify_reviewer task

  2. notify_reviewer(suspect_id)
     - placeholder: extend to send email/Slack/webhook to assigned reviewer
"""
from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path

import requests
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy.orm import Session

from ..config import settings
from ..core import classifier, scoring, verification
from ..core.watermark import compare_phash, extract_watermark
from ..db.models import ActionLog, CaseStatus, HarmEvidence, HarmKind, ScoreRecord, Suspect
from ..db.session import SessionLocal
from ..security.net import UnsafeURLError, validate_public_url
from .celery_app import celery_app

log = logging.getLogger(__name__)

_ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/jpg", "image/png", "image/webp"}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _db() -> Session:
    return SessionLocal()


def _log(db: Session, suspect_id: int, action: str, detail: dict) -> None:
    db.add(ActionLog(suspect_id=suspect_id, action=action,
                     actor="worker", detail=detail))


def _fetch_image(url: str, dest_dir: str) -> str | None:
    """Safely download an image URL into dest_dir; return local path or None.

    Defends against SSRF (validate_public_url blocks private/loopback targets and
    non-http schemes), oversized responses (Content-Length + streamed byte cap),
    wrong content types, and non-image payloads (PIL.verify on the result).
    """
    try:
        validate_public_url(url)
    except UnsafeURLError as exc:
        log.warning("Refusing to fetch unsafe URL %s: %s", url, exc)
        return None

    try:
        resp = requests.get(url, timeout=settings.image_download_timeout, stream=True)
        resp.raise_for_status()

        ct = resp.headers.get("content-type", "").split(";")[0].strip().lower()
        if ct and ct not in _ALLOWED_IMAGE_TYPES:
            log.warning("Skipping %s: disallowed content-type %s", url, ct)
            return None

        declared = resp.headers.get("content-length")
        if declared and int(declared) > settings.image_max_bytes:
            log.warning("Skipping %s: declared size %s exceeds cap", url, declared)
            return None

        ext = ".png" if ct == "image/png" else (".webp" if ct == "image/webp" else ".jpg")
        dest = os.path.join(dest_dir, Path(url).stem[:40] + ext)

        written = 0
        with open(dest, "wb") as fh:
            for chunk in resp.iter_content(8192):
                written += len(chunk)
                if written > settings.image_max_bytes:    # enforce even if Content-Length lied
                    log.warning("Aborting %s: exceeded byte cap mid-stream", url)
                    fh.close()
                    os.unlink(dest)
                    return None
                fh.write(chunk)

        # Confirm it's actually a decodable image, not an HTML error page, etc.
        try:
            from PIL import Image
            with Image.open(dest) as im:
                im.verify()
        except Exception:  # noqa: BLE001
            log.warning("Skipping %s: not a valid image", url)
            os.unlink(dest)
            return None
        return dest
    except Exception as exc:  # noqa: BLE001
        log.warning("Could not fetch image %s: %s", url, exc)
        return None


# --------------------------------------------------------------------------- #
# main verification task
# --------------------------------------------------------------------------- #

@celery_app.task(
    bind=True,
    max_retries=2,
    retry_backoff=True,         # exponential: 30s, 60s, ... up to the cap
    retry_backoff_max=300,
    retry_jitter=True,          # spread retries to avoid thundering herd
    default_retry_delay=30,
    name="imposter_shield.verify_suspect",
)
def verify_suspect(
    self,
    suspect_id: int,
    truth_image_paths: list[str],   # local paths to Source-of-Truth images
    truth_image_urls: list[str] | None = None,   # if SoT images need to be fetched too
    suspect_image_urls: list[str] | None = None, # suspect profile photo URLs
    truth_phashes: list[str] | None = None,      # pre-computed pHash hex strings
    truth_watermark_secret: bytes | None = None, # watermark secret to check for
) -> dict:
    """Run the full async verification pipeline for one suspect."""
    db = _db()
    try:
        suspect = db.get(Suspect, suspect_id)
        if suspect is None:
            log.error("verify_suspect called for missing suspect %d", suspect_id)
            return {"error": "suspect not found"}

        md = dict(suspect.metadata_json or {})
        _log(db, suspect_id, "worker_started", {"task_id": self.request.id})
        db.commit()

        with tempfile.TemporaryDirectory() as tmp:
            # ---- 1. fetch suspect images ---------------------------------- #
            sus_paths: list[str] = []
            for url in (suspect_image_urls or []):
                p = _fetch_image(url, tmp)
                if p:
                    sus_paths.append(p)

            # ---- 2. fetch truth images if given as URLs ------------------- #
            t_paths = list(truth_image_paths)
            for url in (truth_image_urls or []):
                p = _fetch_image(url, tmp)
                if p:
                    t_paths.append(p)

            # ---- 3. face match -------------------------------------------- #
            face_score = 0.0
            face_detail: dict = {}
            if t_paths and sus_paths:
                try:
                    sig = verification.face_match(t_paths, sus_paths[0])
                    face_score = sig.score
                    face_detail = {
                        "matched": sig.matched, "distance": sig.distance,
                        "threshold": sig.threshold, "model": sig.model,
                        "detail": sig.detail,
                    }
                    # Run against remaining suspect images; keep best.
                    for sp in sus_paths[1:]:
                        try:
                            s2 = verification.face_match(t_paths, sp)
                            if s2.score > face_score:
                                face_score = s2.score
                                face_detail = {
                                    "matched": s2.matched, "distance": s2.distance,
                                    "threshold": s2.threshold, "model": s2.model,
                                    "detail": s2.detail,
                                }
                        except Exception:  # noqa: BLE001
                            pass
                except Exception as exc:  # noqa: BLE001
                    log.warning("Face match failed for suspect %d: %s", suspect_id, exc)

            # ---- 4. perceptual hash + watermark --------------------------- #
            watermark_hit = False
            phash_hit = False
            for sp in sus_paths:
                # Watermark check (honeypot)
                if truth_watermark_secret:
                    try:
                        found = extract_watermark(sp)
                        if found == (truth_watermark_secret if isinstance(truth_watermark_secret, bytes)
                                     else truth_watermark_secret.encode()):
                            watermark_hit = True
                    except Exception:  # noqa: BLE001
                        pass

                # pHash comparison against pre-computed truth hashes
                for hex_hash in (truth_phashes or []):
                    try:
                        import imagehash
                        th = imagehash.hex_to_hash(hex_hash)
                        result = compare_phash(th, sp)
                        if result.is_match:
                            phash_hit = True
                    except Exception:  # noqa: BLE001
                        pass

            stolen_photo = watermark_hit or phash_hit

            # ---- 5. NLP bio similarity ------------------------------------ #
            ident = suspect.identity
            text_sig = verification.text_similarity(
                [ident.canonical_bio], [suspect.bio]
            )

            # ---- 6. harvest harm classifiers on bio ----------------------- #
            bio_labels = classifier.classify(suspect.bio)
            if bio_labels.primary_harm:
                # Auto-add a harm evidence record for detected bio solicitation.
                existing_kinds = {h.kind.value for h in suspect.harm}
                if bio_labels.primary_harm not in existing_kinds:
                    harm_kind = HarmKind(bio_labels.primary_harm)
                    db.add(HarmEvidence(
                        suspect_id=suspect_id, kind=harm_kind,
                        description=f"Auto-detected in bio by classifier",
                        captured_text=suspect.bio,
                        submitted_by="worker",
                        classifier_labels={
                            "financial_solicitation": bio_labels.financial_solicitation,
                            "defamation": bio_labels.defamation,
                            "urgency": bio_labels.urgency,
                            "matched": bio_labels.matched,
                        },
                    ))

            # ---- 7. fuse -------------------------------------------------- #
            md.update({
                "face_score": round(face_score, 4),
                "face_detail": face_detail,
                "watermark_hit": watermark_hit,
                "phash_hit": phash_hit,
                "stolen_photo": stolen_photo,
            })
            suspect.metadata_json = md

            db.flush()  # ensure any worker-added harm row is visible via the relationship
            harm_kinds = {h.kind.value for h in suspect.harm}
            if bio_labels.primary_harm:
                harm_kinds.add(bio_labels.primary_harm)

            decision = scoring.fuse(
                scoring.SignalInputs(
                    face=face_score,
                    text=text_sig.score,
                    watermark_hit=stolen_photo,
                    account_age_days=md.get("account_age_days"),
                    followers=md.get("followers"),
                    following=md.get("following"),
                    network_overlap=md.get("network_overlap"),
                ),
                review_threshold=settings.review_threshold,
            )
            if harm_kinds & {"financial_scam", "phishing", "malware", "defamation"}:
                decision.enters_review = True

            rec = ScoreRecord(
                suspect_id=suspect_id,
                confidence=decision.score,
                enters_review=decision.enters_review,
                breakdown=decision.breakdown,
                threshold=settings.review_threshold,
                model_versions={"text": text_sig.model, "face": "ArcFace"},
            )
            db.add(rec)

            if decision.enters_review and suspect.status == CaseStatus.new:
                suspect.status = CaseStatus.in_review

            _log(db, suspect_id, "worker_scored", {
                "confidence": decision.score,
                "enters_review": decision.enters_review,
                "face_score": face_score,
                "text_score": text_sig.score,
                "stolen_photo": stolen_photo,
            })
            db.commit()

        if decision.enters_review:
            notify_reviewer.delay(suspect_id)

        return {
            "suspect_id": suspect_id,
            "confidence": decision.score,
            "enters_review": decision.enters_review,
        }

    except SoftTimeLimitExceeded:
        _log(db, suspect_id, "worker_timeout", {})
        db.commit()
        raise
    except Exception as exc:  # noqa: BLE001
        _log(db, suspect_id, "worker_error", {"error": str(exc)})
        db.commit()
        raise self.retry(exc=exc)
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# notification stub
# --------------------------------------------------------------------------- #

@celery_app.task(name="imposter_shield.notify_reviewer")
def notify_reviewer(suspect_id: int) -> None:
    """Notify the assigned reviewer that a case has entered review.

    Extend this to send an email (smtplib/SendGrid), Slack webhook, etc.
    Currently just logs so the audit trail shows the notification was triggered.
    """
    db = _db()
    try:
        suspect = db.get(Suspect, suspect_id)
        if suspect is None:
            return
        reviewer = suspect.assigned_reviewer or "(unassigned)"
        log.info(
            "Case %d (@%s on %s) entered review queue. Reviewer: %s",
            suspect_id, suspect.handle, suspect.platform, reviewer,
        )
        _log(db, suspect_id, "review_notified", {"reviewer": reviewer})
        db.commit()
    finally:
        db.close()
