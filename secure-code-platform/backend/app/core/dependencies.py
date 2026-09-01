"""
FastAPI dependency-injection wiring.

This is the only place that knows how an HTTP request becomes an
authenticated `User` object. Route handlers depend on `get_current_user` /
`require_admin` and never touch JWTs or sessions directly.
"""
from typing import Annotated

from fastapi import Depends, Header
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.exceptions import EmailNotVerifiedError, ForbiddenError, UnauthorizedError
from app.core.security import TokenError, TokenType, decode_token
from app.models.user import User, UserRole
from app.repositories.user_repository import UserRepository

# tokenUrl is only used by FastAPI's interactive /docs "Authorize" button;
# the actual frontend calls POST /api/v1/auth/login directly.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login", auto_error=False)

DbSession = Annotated[Session, Depends(get_db)]


def get_current_user(
    db: DbSession,
    token: Annotated[str | None, Depends(oauth2_scheme)] = None,
) -> User:
    if not token:
        raise UnauthorizedError("Missing authentication token")

    try:
        payload = decode_token(token, TokenType.ACCESS)
    except TokenError as exc:
        raise UnauthorizedError(str(exc)) from exc

    user = UserRepository(db).get_by_id(payload["sub"])
    if user is None:
        raise UnauthorizedError("User no longer exists")
    if not user.is_active:
        raise ForbiddenError("This account has been disabled")

    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def get_current_verified_user(current_user: CurrentUser) -> User:
    if not current_user.is_email_verified:
        raise EmailNotVerifiedError()
    return current_user


VerifiedUser = Annotated[User, Depends(get_current_verified_user)]


def require_admin(current_user: CurrentUser) -> User:
    if current_user.role != UserRole.ADMIN:
        raise ForbiddenError("Admin privileges are required for this action")
    return current_user


AdminUser = Annotated[User, Depends(require_admin)]


def get_optional_user(
    db: DbSession,
    token: Annotated[str | None, Depends(oauth2_scheme)] = None,
) -> User | None:
    """Used by endpoints that behave differently for logged-in vs anonymous callers, if any."""
    if not token:
        return None
    try:
        payload = decode_token(token, TokenType.ACCESS)
    except TokenError:
        return None
    return UserRepository(db).get_by_id(payload["sub"])
