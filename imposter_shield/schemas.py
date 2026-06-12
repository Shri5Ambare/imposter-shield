"""API request/response models. Pydantic validates and bounds every input."""
from __future__ import annotations

import enum
import json
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, HttpUrl, field_validator

from .db.models import CaseStatus, HarmKind, Role
from .security.net import UnsafeURLError, validate_public_url


class Platform(str, enum.Enum):
    instagram = "instagram"
    x = "x"
    facebook = "facebook"
    linkedin = "linkedin"
    tiktok = "tiktok"
    youtube = "youtube"
    other = "other"


_MAX_METADATA_BYTES = 16 * 1024     # ~16 KB serialized


def _ensure_public_url(value: str) -> str:
    try:
        return validate_public_url(value)
    except UnsafeURLError as exc:
        raise ValueError(str(exc)) from exc


# --- auth ---------------------------------------------------------------- #

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    # Plain str on output (input is validated by UserCreate.email). This avoids
    # 500s when serializing legacy/seed accounts like "admin@local" whose domain
    # has no dot — output validation should never reject already-stored data.
    id: int
    email: str
    full_name: str
    role: Role
    is_active: bool

    model_config = {"from_attributes": True}


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field("", max_length=200)
    password: str = Field(min_length=12, max_length=128)
    role: Role = Role.reviewer


class UserUpdate(BaseModel):
    full_name: str | None = Field(None, max_length=200)
    password: str | None = Field(None, min_length=12, max_length=128)
    role: Role | None = None
    is_active: bool | None = None


# --- identities ----------------------------------------------------------- #

class IdentityCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    handles: dict[str, str] = Field(default_factory=dict)
    canonical_bio: str = Field("", max_length=5000)
    authorized_by: str = Field(min_length=1, max_length=200)


class IdentityOut(BaseModel):
    id: int
    name: str
    handles: dict
    canonical_bio: str
    authorized_by: str

    model_config = {"from_attributes": True}


# --- suspects / cases ----------------------------------------------------- #

class SuspectCreate(BaseModel):
    identity_id: int
    platform: Platform
    url: HttpUrl
    handle: str = Field(min_length=1, max_length=200)
    bio: str = Field("", max_length=5000)
    metadata: dict = Field(default_factory=dict)
    discovered_via: str = Field("manual", max_length=200)

    @field_validator("url")
    @classmethod
    def _url_must_be_public(cls, v: HttpUrl) -> HttpUrl:
        _ensure_public_url(str(v))
        return v

    @field_validator("metadata")
    @classmethod
    def _metadata_bounded(cls, v: dict) -> dict:
        if len(json.dumps(v, default=str)) > _MAX_METADATA_BYTES:
            raise ValueError(f"metadata exceeds {_MAX_METADATA_BYTES} bytes serialized")
        return v


class ScoreOut(BaseModel):
    confidence: float
    enters_review: bool
    breakdown: dict
    threshold: float
    scored_at: datetime

    model_config = {"from_attributes": True}


class HarmEvidenceCreate(BaseModel):
    kind: HarmKind
    description: str = Field(min_length=1, max_length=2000)
    captured_text: str = Field("", max_length=10000)
    evidence_url: str = Field("", max_length=500)
    reporter_contact: str = Field("", max_length=255)

    @field_validator("evidence_url")
    @classmethod
    def _evidence_url_public(cls, v: str) -> str:
        if v.strip():
            _ensure_public_url(v)
        return v

    @field_validator("reporter_contact")
    @classmethod
    def _contact_is_email(cls, v: str) -> str:
        v = v.strip()
        if v and ("@" not in v or "." not in v.split("@")[-1]):
            raise ValueError("reporter_contact must be a valid email or empty")
        return v


class HarmEvidenceOut(BaseModel):
    id: int
    kind: HarmKind
    description: str
    captured_text: str
    evidence_url: str
    reporter_contact: str
    classifier_labels: dict
    created_at: datetime

    model_config = {"from_attributes": True}


class SuspectOut(BaseModel):
    id: int
    identity_id: int
    platform: str
    url: str
    handle: str
    bio: str
    status: CaseStatus
    assigned_reviewer: str
    discovered_at: datetime

    model_config = {"from_attributes": True}


class CaseDetail(SuspectOut):
    latest_score: ScoreOut | None = None
    harm: list[HarmEvidenceOut] = []
    recommendations: list[dict] = []


class StatusUpdate(BaseModel):
    status: CaseStatus
    note: str = Field("", max_length=1000)


class ActionLogOut(BaseModel):
    id: int
    action: str
    actor: str
    detail: dict
    at: datetime

    model_config = {"from_attributes": True}
