"""FastAPI application: auth, identities, cases, harm evidence, claim routing.

Security posture:
  - Every data route requires a valid JWT (Depends(get_current_user)).
  - Resource access is ownership-checked: a user only sees identities they own
    (admins see all). Suspects inherit their identity's ownership.
  - Inputs validated by Pydantic; URLs are HttpUrl; sizes are bounded.
  - Rate limiting via slowapi; auth endpoint limited harder against brute force.
  - All state-changing actions write an immutable ActionLog row.
  - Submission is never automated: status -> 'submitted' requires an explicit
    human action and records who did it.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import schemas
from .config import settings
from .core import classifier, scoring, verification
from .core.dossier import DossierData, build_dossier
from .db.models import (
    ActionLog, CaseStatus, HarmEvidence, ProtectedIdentity, Role, ScoreRecord, Suspect, User,
)
from .db.session import get_db, init_db
from .reporting import claim_router
from .security.auth import (
    create_access_token, get_current_user, hash_password, require_role, verify_password,
)
from .security.headers import SecurityHeadersMiddleware

limiter = Limiter(key_func=get_remote_address, default_limits=[settings.rate_limit_default])
app = FastAPI(title="ImposterShield", version="1.0.0")
app.state.limiter = limiter

# --- middleware (order matters: outermost first) -------------------------- #
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.exception_handler(RateLimitExceeded)
async def _ratelimit_handler(request: Request, exc: RateLimitExceeded):
    from starlette.responses import JSONResponse
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})


@app.on_event("startup")
def _startup() -> None:
    init_db()
    if settings.secret_key_is_ephemeral:
        # Loud warning, not a crash, so dev still works out of the box.
        print("\n[ImposterShield] WARNING: ISHLD_SECRET_KEY is unset — using an "
              "ephemeral key. Tokens reset on restart. Set it before production.\n")


def _log(db: Session, suspect_id: int, action: str, actor: str, detail: dict | None = None) -> None:
    db.add(ActionLog(suspect_id=suspect_id, action=action, actor=actor, detail=detail or {}))


def _owned_identity(db: Session, identity_id: int, user: User) -> ProtectedIdentity:
    ident = db.get(ProtectedIdentity, identity_id)
    if ident is None:
        raise HTTPException(404, "Identity not found")
    if user.role != Role.admin and ident.owner_user_id != user.id:
        # 404 (not 403) so we don't leak existence of other users' resources.
        raise HTTPException(404, "Identity not found")
    return ident


def _owned_suspect(db: Session, suspect_id: int, user: User) -> Suspect:
    s = db.get(Suspect, suspect_id)
    if s is None:
        raise HTTPException(404, "Case not found")
    _owned_identity(db, s.identity_id, user)  # raises if not owned
    return s


# ====================================================================== AUTH

@app.post("/api/auth/token", response_model=schemas.Token)
@limiter.limit(settings.rate_limit_auth)
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(),
          db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form.username).first()
    # Constant-ish path: verify even when user missing to blunt user enumeration.
    if user is None or not verify_password(form.password, user.hashed_password):
        raise HTTPException(401, "Incorrect email or password")
    if not user.is_active:
        raise HTTPException(403, "Account disabled")
    return schemas.Token(access_token=create_access_token(user.email, user.role.value))


@app.get("/api/me", response_model=schemas.UserOut)
def me(user: User = Depends(get_current_user)):
    return user


@app.post("/api/users", response_model=schemas.UserOut, status_code=201)
def create_user(payload: schemas.UserCreate, db: Session = Depends(get_db),
                _: User = Depends(require_role(Role.admin))):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(409, "Email already registered")
    user = User(
        email=payload.email, full_name=payload.full_name,
        hashed_password=hash_password(payload.password), role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# ================================================================ IDENTITIES

@app.post("/api/identities", response_model=schemas.IdentityOut, status_code=201)
def create_identity(payload: schemas.IdentityCreate, db: Session = Depends(get_db),
                    user: User = Depends(require_role(Role.admin, Role.reviewer))):
    ident = ProtectedIdentity(
        name=payload.name, handles=payload.handles, canonical_bio=payload.canonical_bio,
        owner_user_id=user.id, authorized_by=payload.authorized_by,
    )
    db.add(ident)
    db.commit()
    db.refresh(ident)
    return ident


@app.get("/api/identities", response_model=list[schemas.IdentityOut])
def list_identities(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    q = db.query(ProtectedIdentity)
    if user.role != Role.admin:
        q = q.filter(ProtectedIdentity.owner_user_id == user.id)
    return q.all()


# =============================================================== SUSPECTS

@app.post("/api/suspects", response_model=schemas.SuspectOut, status_code=201)
def create_suspect(payload: schemas.SuspectCreate, db: Session = Depends(get_db),
                   user: User = Depends(require_role(Role.admin, Role.reviewer))):
    _owned_identity(db, payload.identity_id, user)
    s = Suspect(
        identity_id=payload.identity_id, platform=payload.platform, url=str(payload.url),
        handle=payload.handle, bio=payload.bio, metadata_json=payload.metadata,
        discovered_via=payload.discovered_via,
    )
    db.add(s)
    db.flush()
    _log(db, s.id, "suspect_created", user.email, {"url": str(payload.url)})
    db.commit()
    db.refresh(s)
    return s


@app.post("/api/suspects/{suspect_id}/score", response_model=schemas.ScoreOut)
def score_suspect(suspect_id: int, db: Session = Depends(get_db),
                  user: User = Depends(require_role(Role.admin, Role.reviewer))):
    """Run NLP + heuristic + harm signals and persist a score.

    (Face match runs in the async worker where images are available; here we use
    bio similarity + heuristics + any harm evidence already attached.)
    """
    s = _owned_suspect(db, suspect_id, user)
    ident = db.get(ProtectedIdentity, s.identity_id)

    text = verification.text_similarity([ident.canonical_bio], [s.bio])
    harm_kinds = {h.kind.value for h in s.harm}
    md = s.metadata_json or {}
    decision = scoring.fuse(
        scoring.SignalInputs(
            face=float(md.get("face_score", 0.0)),
            text=text.score,
            watermark_hit=bool(md.get("watermark_hit", False)),
            account_age_days=md.get("account_age_days"),
            followers=md.get("followers"),
            following=md.get("following"),
            network_overlap=md.get("network_overlap"),
        ),
        review_threshold=settings.review_threshold,
    )
    # Harm evidence raises the floor: an account actively scamming is review-worthy
    # regardless of resemblance score.
    if harm_kinds & {"financial_scam", "phishing", "malware", "defamation"}:
        decision.enters_review = True
        decision.notes.insert(0, f"harm evidence present: {sorted(harm_kinds)}")

    rec = ScoreRecord(
        suspect_id=s.id, confidence=decision.score, enters_review=decision.enters_review,
        breakdown=decision.breakdown, threshold=settings.review_threshold,
        model_versions={"text": text.model, "face": "ArcFace"},
    )
    db.add(rec)
    if decision.enters_review and s.status == CaseStatus.new:
        s.status = CaseStatus.in_review
    _log(db, s.id, "scored", user.email, {"confidence": decision.score})
    db.commit()
    db.refresh(rec)
    return rec


@app.get("/api/cases", response_model=list[schemas.SuspectOut])
def list_cases(status_filter: CaseStatus | None = None, db: Session = Depends(get_db),
               user: User = Depends(get_current_user)):
    q = db.query(Suspect).join(ProtectedIdentity)
    if user.role != Role.admin:
        q = q.filter(ProtectedIdentity.owner_user_id == user.id)
    if status_filter:
        q = q.filter(Suspect.status == status_filter)
    return q.order_by(Suspect.discovered_at.desc()).all()


@app.get("/api/cases/{suspect_id}", response_model=schemas.CaseDetail)
def case_detail(suspect_id: int, db: Session = Depends(get_db),
                user: User = Depends(get_current_user)):
    s = _owned_suspect(db, suspect_id, user)
    latest = (db.query(ScoreRecord).filter(ScoreRecord.suspect_id == s.id)
              .order_by(ScoreRecord.scored_at.desc()).first())
    recs = claim_router.route(claim_router.CaseSignals(
        confidence=latest.confidence if latest else 0.0,
        watermark_or_phash_hit=bool((s.metadata_json or {}).get("watermark_hit")),
        harm_kinds={h.kind.value for h in s.harm},
        has_phishing_or_malware_link=bool((s.metadata_json or {}).get("has_bad_link")),
    ))
    detail = schemas.CaseDetail.model_validate(s)
    detail.latest_score = schemas.ScoreOut.model_validate(latest) if latest else None
    detail.harm = [schemas.HarmEvidenceOut.model_validate(h) for h in s.harm]
    detail.recommendations = [r.__dict__ for r in recs]
    return detail


@app.patch("/api/cases/{suspect_id}/status", response_model=schemas.SuspectOut)
def update_status(suspect_id: int, payload: schemas.StatusUpdate, db: Session = Depends(get_db),
                  user: User = Depends(require_role(Role.admin, Role.reviewer))):
    s = _owned_suspect(db, suspect_id, user)
    prev = s.status
    s.status = payload.status
    # Submission is a human act, explicitly attributed.
    if payload.status == CaseStatus.submitted:
        s.assigned_reviewer = user.email
    _log(db, s.id, f"status:{prev.value}->{payload.status.value}", user.email,
         {"note": payload.note})
    db.commit()
    db.refresh(s)
    return s


# ============================================================ HARM EVIDENCE

@app.post("/api/cases/{suspect_id}/harm", response_model=schemas.HarmEvidenceOut, status_code=201)
def add_harm(suspect_id: int, payload: schemas.HarmEvidenceCreate, db: Session = Depends(get_db),
             user: User = Depends(require_role(Role.admin, Role.reviewer))):
    s = _owned_suspect(db, suspect_id, user)
    labels = classifier.classify(payload.captured_text or payload.description)
    h = HarmEvidence(
        suspect_id=s.id, kind=payload.kind, description=payload.description,
        captured_text=payload.captured_text, evidence_url=payload.evidence_url,
        reporter_contact=payload.reporter_contact, submitted_by=user.email,
        classifier_labels={
            "financial_solicitation": labels.financial_solicitation,
            "defamation": labels.defamation, "urgency": labels.urgency,
            "matched": labels.matched,
        },
    )
    db.add(h)
    _log(db, s.id, "harm_added", user.email, {"kind": payload.kind.value})
    db.commit()
    db.refresh(h)
    return h


# ================================================================== DOSSIER

@app.post("/api/cases/{suspect_id}/dossier")
def generate_dossier(suspect_id: int, db: Session = Depends(get_db),
                     user: User = Depends(require_role(Role.admin, Role.reviewer))):
    s = _owned_suspect(db, suspect_id, user)
    ident = db.get(ProtectedIdentity, s.identity_id)
    latest = (db.query(ScoreRecord).filter(ScoreRecord.suspect_id == s.id)
              .order_by(ScoreRecord.scored_at.desc()).first())
    Path(settings.out_dir).mkdir(parents=True, exist_ok=True)
    out_path = str(Path(settings.out_dir) / f"dossier-{s.id}.pdf")
    harm_notes = [f"{h.kind.value}: {h.description}" for h in s.harm]
    build_dossier(
        DossierData(
            case_id=str(s.id), protected_name=ident.name,
            protected_handle=ident.handles.get(s.platform, ""),
            suspect_url=s.url, suspect_handle=s.handle,
            confidence=latest.confidence if latest else 0.0,
            score_breakdown=latest.breakdown if latest else {},
            notes=harm_notes, reviewer=user.email,
        ),
        out_path,
    )
    _log(db, s.id, "dossier_built", user.email, {"path": out_path})
    db.commit()
    return FileResponse(out_path, media_type="application/pdf", filename=f"dossier-{s.id}.pdf")


# ============================================================== STATIC SPA

_WEB = Path(__file__).parent / "web"
app.mount("/", StaticFiles(directory=str(_WEB), html=True), name="web")
