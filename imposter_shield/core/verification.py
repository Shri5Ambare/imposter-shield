"""Face-match and NLP-similarity verification.

Each function returns a *signal* in [0, 1] plus enough detail to defend the
decision later (model name, raw distance, etc.). Signals are fused in
``scoring.py`` — keep the fusion policy out of here so individual signals stay
independently testable and explainable.
"""
from __future__ import annotations

import functools
from dataclasses import dataclass, field
from typing import Sequence

import numpy as np


# --------------------------------------------------------------------------- #
# Computer vision: does the suspect's photo show the protected person?
# --------------------------------------------------------------------------- #

@dataclass
class FaceSignal:
    score: float                 # 1.0 = almost certainly same person
    matched: bool
    distance: float              # raw model distance (lower = closer)
    threshold: float
    model: str
    detail: str = ""


_FACE_MODEL = "ArcFace"          # strong default in DeepFace
_FACE_METRIC = "cosine"


def face_match(truth_image_paths: Sequence[str], suspect_image_path: str) -> FaceSignal:
    """Compare a suspect image against every Source-of-Truth reference image.

    We take the *best* (closest) match across references — a real impostor only
    needs to have stolen one of the protected person's photos. DeepFace handles
    detection + alignment + embedding internally.
    """
    import logging
    from deepface import DeepFace  # imported lazily; heavy + optional at import time

    log = logging.getLogger(__name__)
    best: FaceSignal | None = None
    for truth_path in truth_image_paths:
        try:
            result = DeepFace.verify(
                img1_path=truth_path,
                img2_path=suspect_image_path,
                model_name=_FACE_MODEL,
                distance_metric=_FACE_METRIC,
                enforce_detection=False,   # suspect crops are often messy
            )
        except Exception:  # noqa: BLE001 - a bad image must not kill the job
            # Log full detail server-side; keep the caller-visible note generic so
            # file paths / model internals don't leak into stored breakdowns.
            log.warning("Face verify failed for a reference image", exc_info=True)
            best = best or FaceSignal(0.0, False, 1.0, 0.0, _FACE_MODEL, "face match unavailable")
            continue

        distance = float(result["distance"])
        threshold = float(result["threshold"])
        # Map distance→score relative to the model's own threshold so the number
        # is comparable across images. distance==0 → 1.0, distance==threshold → ~0.5.
        score = float(np.clip(1.0 - (distance / (2.0 * threshold)), 0.0, 1.0))
        candidate = FaceSignal(
            score=score,
            matched=bool(result["verified"]),
            distance=distance,
            threshold=threshold,
            model=_FACE_MODEL,
            detail=f"matched ref {truth_path}",
        )
        if best is None or candidate.score > best.score:
            best = candidate

    return best or FaceSignal(0.0, False, 1.0, 0.0, _FACE_MODEL, "no usable images")


# --------------------------------------------------------------------------- #
# NLP: is the suspect's bio/posts a paraphrase of the real account's text?
# --------------------------------------------------------------------------- #

@dataclass
class TextSignal:
    score: float                 # max cosine similarity found
    best_pair: tuple[str, str] = ("", "")
    model: str = "all-MiniLM-L6-v2"
    per_truth_max: list[float] = field(default_factory=list)


@functools.lru_cache(maxsize=1)
def _embedder():
    from sentence_transformers import SentenceTransformer
    return SentenceTransformer("all-MiniLM-L6-v2")


def _jaccard(a: str, b: str) -> float:
    """Cheap lexical fallback when the embedding model isn't installed.
    Not as good as embeddings (misses paraphrase), but keeps the app runnable."""
    ta, tb = set(a.lower().split()), set(b.lower().split())
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def text_similarity(truth_texts: Sequence[str], suspect_texts: Sequence[str]) -> TextSignal:
    """Max semantic similarity between any truth snippet and any suspect snippet.

    Paraphrased bios score high here even when wording differs, because the
    embeddings capture meaning rather than surface tokens. If sentence-transformers
    (and its torch backend) isn't installed, falls back to lexical Jaccard so the
    rest of the system still functions.
    """
    truth = [t for t in truth_texts if t and t.strip()]
    suspect = [s for s in suspect_texts if s and s.strip()]
    if not truth or not suspect:
        return TextSignal(score=0.0)

    try:
        model = _embedder()
    except Exception:  # noqa: BLE001 - missing optional ML stack
        best = max(((_jaccard(t, s), t, s) for t in truth for s in suspect),
                   key=lambda x: x[0])
        return TextSignal(score=float(best[0]), best_pair=(best[1], best[2]),
                          model="jaccard-fallback")

    t_emb = model.encode(truth, normalize_embeddings=True)
    s_emb = model.encode(suspect, normalize_embeddings=True)
    sims = t_emb @ s_emb.T                      # cosine, both normalized

    flat_idx = int(np.argmax(sims))
    i, j = divmod(flat_idx, sims.shape[1])
    return TextSignal(
        score=float(sims[i, j]),
        best_pair=(truth[i], suspect[j]),
        per_truth_max=[float(x) for x in sims.max(axis=1)],
    )
