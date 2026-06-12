"""Initialize the DB and create a starter admin + demo data.

Run once:  python seed.py
Prints the admin credentials. Change the password immediately in any real use.
"""
from __future__ import annotations

import os
import secrets

from imposter_shield.db.session import SessionLocal, init_db
from imposter_shield.db.models import (
    HarmEvidence, HarmKind, ProtectedIdentity, Role, ScoreRecord, Suspect, User,
)
from imposter_shield.security.auth import hash_password


def main() -> None:
    init_db()
    db = SessionLocal()
    try:
        if db.query(User).filter(User.email == "admin@local").first():
            print("Admin already exists; skipping seed.")
            return

        admin_pw = os.environ.get("ISHLD_ADMIN_PASSWORD") or secrets.token_urlsafe(12)
        admin = User(
            email="admin@local", full_name="Administrator",
            hashed_password=hash_password(admin_pw), role=Role.admin,
        )
        db.add(admin)
        db.flush()

        ident = ProtectedIdentity(
            name="Jane Doe", handles={"instagram": "real_jane", "x": "real_jane"},
            canonical_bio="Photographer & educator. DMs open for collabs. Never ask for money.",
            owner_user_id=admin.id, authorized_by="self (account owner)",
        )
        db.add(ident)
        db.flush()

        suspect = Suspect(
            identity_id=ident.id, platform="instagram",
            url="https://instagram.com/real_jane_official1", handle="real_jane_official1",
            bio="Photographer & educator. Message me about a guaranteed crypto investment opportunity!",
            metadata_json={"account_age_days": 9, "followers": 22, "following": 1400,
                           "network_overlap": 0.38, "face_score": 0.93, "watermark_hit": True},
            discovered_via="seed",
        )
        db.add(suspect)
        db.flush()

        db.add(HarmEvidence(
            suspect_id=suspect.id, kind=HarmKind.financial_scam,
            description="DMed a follower asking to wire money for a fake investment.",
            captured_text="Hey! Send me crypto to this wallet and I'll double your money, guaranteed returns. Act now, don't tell anyone.",
            reporter_contact="victim@example.com", submitted_by="admin@local",
            classifier_labels={},
        ))
        db.commit()
        print("=" * 56)
        print("Seed complete.")
        print(f"  Admin login : admin@local")
        print(f"  Password    : {admin_pw}")
        print("  Open        : http://localhost:8000/")
        print("=" * 56)
    finally:
        db.close()


if __name__ == "__main__":
    main()
