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

Celery integration:
  - verify_suspect task is dispatched after every create_suspect call.
  - If no broker is configured the task call is silently skipped (CELERY_AVAILABLE
    flag); the API still works, scoring just happens synchronously via /score.

NOTE: this module deliberately does NOT use `from __future__ import annotations`.
Stringized annotations break FastAPI's signature resolution for endpoints wrapped
by slowapi's @limiter.limit (forward refs like OAuth2PasswordRequestForm can't be
resolved through the wrapper). Keep annotations concrete here.
"""
from dataclasses import asdict
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from sqlalchemy.orm import Session
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import schemas
from .config import settings
from .core import classifier, scoring, verification
from .core.dossier import DossierData, build_dossier
from .db.models import (
    ActionLog, AuditEvent, CaseStatus, HarmEvidence, ProtectedIdentity, Role,
    ScoreRecord, Suspect, User,
)
from .db.session import get_db, init_db
from .reporting import claim_router
from .security.auth import (
    create_access_token, get_current_user, hash_password, require_role, verify_password,
)
from .security.headers import SecurityHeadersMiddleware

# Pre-computed dummy hash keeps login response time constant when the email
# doesn't exist — prevents username enumeration via timing side-channel.
_DUMMY_HASH = hash_password("__timing_guard__")

# Try to import Celery tasks; skip gracefully if broker isn't installed/running.
try:
    from .worker.tasks import verify_suspect as _celery_verify
    CELERY_AVAILABLE = True
except Exception:  # noqa: BLE001
    _celery_verify = None
    CELERY_AVAILABLE = False


def _dispatch_verify(suspect: Suspect, identity: ProtectedIdentity) -> str | None:
    """Enqueue the async face-match task. Returns task_id or None if skipped.

    Image URLs are read from suspect/identity metadata; the worker validates each
    one against the SSRF guard before fetching.
    """
    if not CELERY_AVAILABLE or _celery_verify is None:
        return None
    md = suspect.metadata_json or {}
    ident_md = identity.handles or {}
    try:
        result = _celery_verify.delay(
            suspect_id=suspect.id,
            truth_image_paths=[],
            truth_image_urls=list(ident_md.get("_truth_image_urls", []))
                if isinstance(ident_md, dict) else [],
            suspect_image_urls=list(md.get("image_urls", [])),
        )
        return result.id
    except Exception:  # noqa: BLE001 — broker unavailable; degrade silently
        return None

def _real_ip(request: Request) -> str:
    """Client IP for rate limiting and audit logging.

    With trusted_proxy_depth=0 (default/direct) uses request.client.host.
    With trusted_proxy_depth=1 (one reverse proxy in front, e.g. nginx that
    sets X-Forwarded-For: $remote_addr) reads the leftmost XFF entry.
    Only raise this above 0 when you have a controlled reverse proxy.
    """
    depth = settings.trusted_proxy_depth
    if depth > 0:
        xff = request.headers.get("X-Forwarded-For", "")
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            return parts[0]  # leftmost = original client when proxy uses $remote_addr
    return request.client.host if request.client else "unknown"


limiter = Limiter(key_func=_real_ip, default_limits=[settings.rate_limit_default])
app = FastAPI(title="ImposterShield", version="1.0.0")
app.state.limiter = limiter

# --- middleware (order matters: outermost first) -------------------------- #
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts_list)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
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


def _client_ip(request: Request) -> str:
    return _real_ip(request)


def _audit(db: Session, request: Request, category: str, action: str, *,
           actor: str = "", target: str = "", detail: dict | None = None) -> None:
    """Record a non-case event (auth / admin) to the AuditEvent table.

    Fields are truncated to their column limits so a hostile, oversized login
    username can't raise a DB error and disrupt the request.
    """
    db.add(AuditEvent(
        category=category[:40], action=action[:60],
        actor=(actor or "")[:200], target=(target or "")[:200],
        source_ip=_client_ip(request)[:64], detail=detail or {},
    ))


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
    # Always call verify_password (even when user is None) to keep response time
    # constant and prevent username enumeration via timing side-channel.
    password_ok = verify_password(form.password, user.hashed_password if user else _DUMMY_HASH)
    if not user or not password_ok:
        _audit(db, request, "auth", "login_failed", actor=form.username,
               detail={"reason": "bad_credentials"})
        db.commit()
        raise HTTPException(401, "Incorrect email or password")
    if not user.is_active:
        _audit(db, request, "auth", "login_denied", actor=user.email,
               detail={"reason": "account_disabled"})
        db.commit()
        raise HTTPException(403, "Account disabled")
    _audit(db, request, "auth", "login_ok", actor=user.email)
    db.commit()
    return schemas.Token(access_token=create_access_token(user))


@app.post("/api/auth/logout", status_code=204)
def logout(request: Request, db: Session = Depends(get_db),
           user: User = Depends(get_current_user)):
    """Revoke all of the caller's outstanding tokens by bumping token_version."""
    user.token_version += 1
    _audit(db, request, "auth", "logout", actor=user.email)
    db.commit()


@app.get("/api/me", response_model=schemas.UserOut)
def me(user: User = Depends(get_current_user)):
    return user


@app.post("/api/users", response_model=schemas.UserOut, status_code=201)
def create_user(request: Request, payload: schemas.UserCreate, db: Session = Depends(get_db),
                actor: User = Depends(require_role(Role.admin))):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(409, "Email already registered")
    user = User(
        email=payload.email, full_name=payload.full_name,
        hashed_password=hash_password(payload.password), role=payload.role,
    )
    db.add(user)
    _audit(db, request, "admin", "user_created", actor=actor.email,
           target=payload.email, detail={"role": payload.role.value})
    db.commit()
    db.refresh(user)
    return user


@app.get("/api/users", response_model=list[schemas.UserOut])
def list_users(db: Session = Depends(get_db),
               _: User = Depends(require_role(Role.admin)),
               limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    return (db.query(User).order_by(User.created_at.desc())
            .offset(offset).limit(limit).all())


@app.patch("/api/users/{user_id}", response_model=schemas.UserOut)
def update_user(request: Request, user_id: int, payload: schemas.UserUpdate,
                db: Session = Depends(get_db),
                actor: User = Depends(require_role(Role.admin))):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "User not found")
    if target.id == actor.id and payload.role is not None and payload.role != Role.admin:
        raise HTTPException(400, "Cannot demote your own admin account")
    if target.id == actor.id and payload.is_active is False:
        raise HTTPException(400, "Cannot disable your own account")

    changed = []
    if payload.role is not None and payload.role != target.role:
        target.role = payload.role
        changed.append("role")
    if payload.is_active is not None and payload.is_active != target.is_active:
        target.is_active = payload.is_active
        changed.append("is_active")
    if payload.full_name is not None:
        target.full_name = payload.full_name
        changed.append("full_name")
    if payload.password is not None:
        target.hashed_password = hash_password(payload.password)
        changed.append("password")
    # Any security-relevant change revokes the target's existing tokens.
    if {"role", "is_active", "password"} & set(changed):
        target.token_version += 1
    _audit(db, request, "admin", "user_updated", actor=actor.email,
           target=target.email, detail={"changed": changed})
    db.commit()
    db.refresh(target)
    return target


@app.delete("/api/users/{user_id}", status_code=204)
def delete_user(request: Request, user_id: int, db: Session = Depends(get_db),
                actor: User = Depends(require_role(Role.admin))):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "User not found")
    if target.id == actor.id:
        raise HTTPException(400, "Cannot delete your own account")
    email = target.email
    db.delete(target)
    _audit(db, request, "admin", "user_deleted", actor=actor.email, target=email)
    db.commit()


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
@limiter.limit(settings.rate_limit_write)
def create_suspect(request: Request, payload: schemas.SuspectCreate,
                   db: Session = Depends(get_db),
                   user: User = Depends(require_role(Role.admin, Role.reviewer))):
    ident = _owned_identity(db, payload.identity_id, user)
    s = Suspect(
        identity_id=payload.identity_id, platform=payload.platform.value, url=str(payload.url),
        handle=payload.handle, bio=payload.bio, metadata_json=payload.metadata,
        discovered_via=payload.discovered_via,
    )
    db.add(s)
    db.flush()
    task_id = _dispatch_verify(s, ident)
    _log(db, s.id, "suspect_created", user.email,
         {"url": str(payload.url), "async_task_id": task_id,
          "async_available": CELERY_AVAILABLE})
    db.commit()
    db.refresh(s)
    return s


@app.post("/api/suspects/{suspect_id}/score", response_model=schemas.ScoreOut)
@limiter.limit(settings.rate_limit_write)
def score_suspect(request: Request, suspect_id: int, db: Session = Depends(get_db),
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
               user: User = Depends(get_current_user),
               limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    q = db.query(Suspect).join(ProtectedIdentity)
    if user.role != Role.admin:
        q = q.filter(ProtectedIdentity.owner_user_id == user.id)
    if status_filter:
        q = q.filter(Suspect.status == status_filter)
    return q.order_by(Suspect.discovered_at.desc()).offset(offset).limit(limit).all()


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
    detail.recommendations = [asdict(r) for r in recs]
    return detail


@app.get("/api/cases/{suspect_id}/audit", response_model=list[schemas.ActionLogOut])
def case_audit(suspect_id: int, db: Session = Depends(get_db),
               user: User = Depends(get_current_user),
               limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    s = _owned_suspect(db, suspect_id, user)
    return (db.query(ActionLog).filter(ActionLog.suspect_id == s.id)
            .order_by(ActionLog.at.desc()).offset(offset).limit(limit).all())


@app.patch("/api/cases/{suspect_id}/status", response_model=schemas.SuspectOut)
@limiter.limit(settings.rate_limit_write)
def update_status(request: Request, suspect_id: int, payload: schemas.StatusUpdate,
                  db: Session = Depends(get_db),
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
@limiter.limit(settings.rate_limit_write)
def add_harm(request: Request, suspect_id: int, payload: schemas.HarmEvidenceCreate,
             db: Session = Depends(get_db),
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

def _prune_old_dossiers() -> None:
    """Delete generated PDFs older than the retention window."""
    import time
    out = Path(settings.out_dir)
    if not out.exists():
        return
    cutoff = time.time() - settings.dossier_retention_days * 86400
    for pdf in out.glob("dossier-*.pdf"):
        try:
            if pdf.stat().st_mtime < cutoff:
                pdf.unlink()
        except OSError:
            pass


@app.post("/api/cases/{suspect_id}/dossier")
@limiter.limit(settings.rate_limit_write)
def generate_dossier(request: Request, suspect_id: int, db: Session = Depends(get_db),
                     user: User = Depends(require_role(Role.admin, Role.reviewer))):
    s = _owned_suspect(db, suspect_id, user)
    ident = db.get(ProtectedIdentity, s.identity_id)
    latest = (db.query(ScoreRecord).filter(ScoreRecord.suspect_id == s.id)
              .order_by(ScoreRecord.scored_at.desc()).first())
    Path(settings.out_dir).mkdir(parents=True, exist_ok=True)
    _prune_old_dossiers()
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


# ================================================================== HEALTH

@app.get("/api/healthz")
def healthz():
    """Unauthenticated liveness probe for load balancers / container healthchecks."""
    return {"status": "ok", "service": "imposter-shield"}


# ============================================================= WORKER STATUS

@app.get("/api/worker/health")
def worker_health(_: User = Depends(get_current_user)):
    """Quick check: is the Celery broker reachable?"""
    if not CELERY_AVAILABLE:
        return {"status": "unavailable", "reason": "celery/redis not installed"}
    try:
        from .worker.celery_app import celery_app as _ca
        _ca.control.ping(timeout=2)
        return {"status": "ok"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "unreachable", "reason": str(exc)}


@app.get("/api/worker/task/{task_id}")
def task_status(task_id: str, _: User = Depends(get_current_user)):
    """Poll the result of a Celery task by ID."""
    if not CELERY_AVAILABLE:
        raise HTTPException(503, "Celery not available")
    from celery.result import AsyncResult
    from .worker.celery_app import celery_app as _ca
    r = AsyncResult(task_id, app=_ca)
    safe_result = None
    if r.ready() and not r.failed():
        raw = r.result
        if isinstance(raw, dict):
            # Whitelist only safe fields — never expose internal paths or model details.
            safe_result = {k: raw[k] for k in ("suspect_id", "confidence", "enters_review")
                           if k in raw}
    return {
        "task_id": task_id,
        "state": r.state,
        "result": safe_result,
        "error": "Task failed" if r.failed() else None,
    }


# ============================================================== STATIC SPA

_WEB = Path(__file__).parent / "web"
app.mount("/", StaticFiles(directory=str(_WEB), html=True), name="web")
