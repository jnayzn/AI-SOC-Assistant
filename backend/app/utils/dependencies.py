"""Shared FastAPI dependencies (auth, current user)."""
from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.exceptions import UnauthorizedError
from app.core.security import decode_access_token
from app.database.session import get_db
from app.models.user import User
from app.repositories.user_repository import UserRepository

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


def get_current_user(
    token: str | None = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User | None:
    """Returns the authenticated user, or None for anonymous/guest usage.

    The Analyzer endpoint supports anonymous usage (no login wall for the
    internship demo), but authenticated requests get their history tied to
    their account.
    """
    if not token:
        return None
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        return None
    return UserRepository(db).get_by_id(payload["sub"])


def require_current_user(
    token: str | None = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    if not token:
        raise UnauthorizedError("Authentication required.")
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise UnauthorizedError("Invalid or expired token.")
    user = UserRepository(db).get_by_id(payload["sub"])
    if not user:
        raise UnauthorizedError("User not found.")
    return user
