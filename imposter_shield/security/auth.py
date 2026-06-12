"""Authentication & authorization.

- Passwords hashed with bcrypt (passlib), never stored or logged in plaintext.
- Stateless JWT bearer tokens, short-lived, carrying a `ver` claim that must
  match the user's current `token_version`. Bumping that column (on logout,
  disable, delete, password/role change) invalidates every outstanding token
  for that user without a per-request blacklist.
- Role checks via FastAPI dependencies; resource-ownership checks live next to
  the resources they guard (see api.py `_owned_identity`).

Note on CSRF: tokens are sent in the `Authorization` header, which browsers do
not attach automatically on cross-site requests, so classic cookie-CSRF does not
apply. (Cookies are never used for auth here.)
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from ..config import settings
from ..db.models import Role, User
from ..db.session import get_db

_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")

_CREDENTIALS_EXC = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


def hash_password(plain: str) -> str:
    return _pwd.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd.verify(plain, hashed)


def create_access_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.email,
        "role": user.role.value,
        "ver": user.token_version,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    try:
        payload = jwt.decode(
            token, settings.secret_key, algorithms=[settings.algorithm],
            options={"require": ["exp", "sub"]},
        )
        email = payload.get("sub")
        if not email:
            raise _CREDENTIALS_EXC
        token_ver = payload.get("ver")
    except jwt.PyJWTError:
        raise _CREDENTIALS_EXC

    user = db.query(User).filter(User.email == email).first()
    if user is None or not user.is_active:
        raise _CREDENTIALS_EXC
    # Reject tokens issued before a revocation event (logout, role/password
    # change, disable). `ver` is required: tokens minted before this field
    # existed (None) are no longer accepted.
    if token_ver != user.token_version:
        raise _CREDENTIALS_EXC
    return user


def require_role(*roles: Role):
    """Dependency factory: 403 unless the caller holds one of ``roles``."""
    allowed = set(roles)

    def _dep(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions for this action",
            )
        return user

    return _dep
