"""API request/response models. Pydantic validates and bounds every input."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, HttpUrl

from .db.models import CaseStatus, HarmKind, Role


# --- auth ---------------------------------------------------------------- #

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: int
    email: EmailStr
    full_name: str
    role: Role

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
    platform: str = Field(min_length=1, max_length=40)
    url: HttpUrl
    handle: str = Field(min_length=1, max_length=200)
    bio: str = Field("", max_length=5000)
    metadata: dict = Field(default_factory=dict)
    discovered_via: str = Field("manual", max_length=200)


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
