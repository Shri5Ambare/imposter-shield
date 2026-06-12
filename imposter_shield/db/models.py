"""Persistence + audit log.

The audit log is not optional decoration: every score, threshold, model version,
and human action is recorded so a takedown can be defended and a false positive
can be appealed. Submission is always attributed to a named reviewer.
"""
from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    String, Float, Boolean, DateTime, ForeignKey, JSON, Text, Enum as SAEnum,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# --------------------------------------------------------------------------- #
# Identity & access
# --------------------------------------------------------------------------- #

class Role(str, enum.Enum):
    admin = "admin"
    reviewer = "reviewer"
    viewer = "viewer"


class User(Base):
    __tablename__ = "user"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(200), default="")
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(SAEnum(Role), default=Role.reviewer)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class ProtectedIdentity(Base):
    __tablename__ = "protected_identity"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    handles: Mapped[dict] = mapped_column(JSON, default=dict)   # {platform: handle}
    canonical_bio: Mapped[str] = mapped_column(Text, default="")
    # Who may act on this identity, and who authorized the monitoring. The tool
    # is only for identities you own or are authorized in writing to protect.
    owner_user_id: Mapped[int] = mapped_column(ForeignKey("user.id"))
    authorized_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    suspects: Mapped[list["Suspect"]] = relationship(back_populates="identity")


# --------------------------------------------------------------------------- #
# Suspects, scores, harm, actions
# --------------------------------------------------------------------------- #

class CaseStatus(str, enum.Enum):
    new = "new"
    in_review = "in_review"
    submitted = "submitted"
    dismissed = "dismissed"


class Suspect(Base):
    __tablename__ = "suspect"
    id: Mapped[int] = mapped_column(primary_key=True)
    identity_id: Mapped[int] = mapped_column(ForeignKey("protected_identity.id"), index=True)
    platform: Mapped[str] = mapped_column(String(40))
    url: Mapped[str] = mapped_column(String(500))
    handle: Mapped[str] = mapped_column(String(200))
    bio: Mapped[str] = mapped_column(Text, default="")
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    discovered_via: Mapped[str] = mapped_column(String(200), default="")
    status: Mapped[CaseStatus] = mapped_column(SAEnum(CaseStatus), default=CaseStatus.new)
    assigned_reviewer: Mapped[str] = mapped_column(String(200), default="")
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    identity: Mapped["ProtectedIdentity"] = relationship(back_populates="suspects")
    scores: Mapped[list["ScoreRecord"]] = relationship(back_populates="suspect", cascade="all, delete-orphan")
    harm: Mapped[list["HarmEvidence"]] = relationship(back_populates="suspect", cascade="all, delete-orphan")
    actions: Mapped[list["ActionLog"]] = relationship(back_populates="suspect", cascade="all, delete-orphan")


class ScoreRecord(Base):
    __tablename__ = "score_record"
    id: Mapped[int] = mapped_column(primary_key=True)
    suspect_id: Mapped[int] = mapped_column(ForeignKey("suspect.id"), index=True)
    confidence: Mapped[float] = mapped_column(Float)
    enters_review: Mapped[bool] = mapped_column(Boolean)
    breakdown: Mapped[dict] = mapped_column(JSON, default=dict)
    model_versions: Mapped[dict] = mapped_column(JSON, default=dict)
    threshold: Mapped[float] = mapped_column(Float, default=0.90)
    scored_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    suspect: Mapped["Suspect"] = relationship(back_populates="scores")


class HarmKind(str, enum.Enum):
    financial_scam = "financial_scam"     # asking followers for money/crypto/gift cards
    phishing = "phishing"                 # malicious link in bio/DM
    defamation = "defamation"             # damaging false statements under your name
    malware = "malware"
    other = "other"


class HarmEvidence(Base):
    """What the fake account actually *did* — the thing victims get hurt by.

    This is distinct from identity-resemblance signals. A scam DM screenshot or a
    defamatory post is what escalates a report from auto-ignored to actioned.
    """
    __tablename__ = "harm_evidence"
    id: Mapped[int] = mapped_column(primary_key=True)
    suspect_id: Mapped[int] = mapped_column(ForeignKey("suspect.id"), index=True)
    kind: Mapped[HarmKind] = mapped_column(SAEnum(HarmKind))
    description: Mapped[str] = mapped_column(Text)
    captured_text: Mapped[str] = mapped_column(Text, default="")     # e.g. the scam DM
    evidence_url: Mapped[str] = mapped_column(String(500), default="")  # post/screenshot URL
    reporter_contact: Mapped[str] = mapped_column(String(255), default="")  # victim who forwarded it
    classifier_labels: Mapped[dict] = mapped_column(JSON, default=dict)
    submitted_by: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    suspect: Mapped["Suspect"] = relationship(back_populates="harm")


class ActionLog(Base):
    """Append-only record of every human/system action on a case."""
    __tablename__ = "action_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    suspect_id: Mapped[int] = mapped_column(ForeignKey("suspect.id"), index=True)
    action: Mapped[str] = mapped_column(String(60))
    actor: Mapped[str] = mapped_column(String(200))          # reviewer email or "system"
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    suspect: Mapped["Suspect"] = relationship(back_populates="actions")
