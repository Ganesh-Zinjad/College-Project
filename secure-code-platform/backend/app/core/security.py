"""
Security primitives: password hashing and JWT issuance/verification.

Kept separate from `dependencies.py` (which wires these primitives into
FastAPI's dependency-injection graph) so the cryptographic logic itself is
framework-agnostic and easy to unit test in isolation.
"""
import secrets
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class TokenType(str, Enum):
    ACCESS = "access"
    REFRESH = "refresh"
    EMAIL_VERIFY = "email_verify"
    PASSWORD_RESET = "password_reset"


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# ---------------------------------------------------------------------------
# JWT issuance
# ---------------------------------------------------------------------------

def _create_token(subject: str, token_type: TokenType, expires_delta: timedelta, extra_claims: Optional[dict] = None) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "type": token_type.value,
        "iat": now,
        "exp": now + expires_delta,
        "jti": secrets.token_hex(16),  # unique id — lets us support token revocation later
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_access_token(user_id: str, role: str) -> str:
    return _create_token(
        subject=user_id,
        token_type=TokenType.ACCESS,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        extra_claims={"role": role},
    )


def create_refresh_token(user_id: str) -> str:
    return _create_token(
        subject=user_id,
        token_type=TokenType.REFRESH,
        expires_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )


def create_email_verification_token(user_id: str) -> str:
    return _create_token(
        subject=user_id,
        token_type=TokenType.EMAIL_VERIFY,
        expires_delta=timedelta(hours=settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS),
    )


def create_password_reset_token(user_id: str) -> str:
    return _create_token(
        subject=user_id,
        token_type=TokenType.PASSWORD_RESET,
        expires_delta=timedelta(minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES),
    )


def generate_api_key() -> str:
    """Returns a high-entropy key formatted like `scp_live_<random>` for easy recognition in logs/UI."""
    return f"scp_live_{secrets.token_urlsafe(32)}"


# ---------------------------------------------------------------------------
# JWT verification
# ---------------------------------------------------------------------------

class TokenError(Exception):
    """Raised for any invalid/expired/wrong-type token. Caught at the API layer."""


def decode_token(token: str, expected_type: TokenType) -> dict:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError as exc:
        raise TokenError("Token is invalid or expired") from exc

    if payload.get("type") != expected_type.value:
        raise TokenError(f"Expected a {expected_type.value} token")

    return payload
