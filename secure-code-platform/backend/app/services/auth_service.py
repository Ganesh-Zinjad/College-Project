"""
Authentication service.

Holds all business logic for the auth flows (register, login, email
verification, password reset, token refresh). Route handlers in
`api/v1/auth.py` stay thin — they parse the request, call one method here,
and serialize the response.
"""
from app.core.exceptions import (
    AlreadyExistsError,
    InvalidCredentialsError,
    InvalidTokenError,
    NotFoundError,
)
from app.core.security import (
    TokenError,
    TokenType,
    create_access_token,
    create_email_verification_token,
    create_password_reset_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.models.user import User, UserRole
from app.repositories.user_repository import UserRepository
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse
from app.services.email_service import EmailService
from datetime import datetime, timezone


class AuthService:
    def __init__(self, user_repo: UserRepository, email_service: EmailService):
        self.user_repo = user_repo
        self.email_service = email_service

    def register(self, payload: RegisterRequest) -> User:
        if self.user_repo.get_by_email(payload.email):
            raise AlreadyExistsError("An account with this email already exists")

        # First registered user becomes admin automatically — convenient for a
        # fresh dev/demo database that otherwise has no way to bootstrap an admin.
        role = UserRole.ADMIN if self.user_repo.count_total() == 0 else UserRole.USER

        user = self.user_repo.create(
            full_name=payload.full_name,
            email=payload.email,
            hashed_password=hash_password(payload.password),
            role=role,
        )

        verify_token = create_email_verification_token(user.id)
        self.email_service.send_verification_email(user.email, user.full_name, verify_token)
        return user

    def login(self, payload: LoginRequest) -> tuple[User, TokenResponse]:
        user = self.user_repo.get_by_email(payload.email)
        if user is None or not verify_password(payload.password, user.hashed_password):
            raise InvalidCredentialsError()
        if not user.is_active:
            raise InvalidCredentialsError("This account has been disabled. Contact an administrator.")

        user.last_login_at = datetime.now(timezone.utc)
        self.user_repo.save(user)

        tokens = self._issue_tokens(user)
        return user, tokens

    def refresh(self, refresh_token: str) -> TokenResponse:
        try:
            payload = decode_token(refresh_token, TokenType.REFRESH)
        except TokenError as exc:
            raise InvalidTokenError(str(exc)) from exc

        user = self.user_repo.get_by_id(payload["sub"])
        if user is None or not user.is_active:
            raise InvalidTokenError("User no longer exists or is disabled")

        return self._issue_tokens(user)

    def verify_email(self, token: str) -> User:
        try:
            payload = decode_token(token, TokenType.EMAIL_VERIFY)
        except TokenError as exc:
            raise InvalidTokenError("Verification link is invalid or has expired") from exc

        user = self.user_repo.get_by_id(payload["sub"])
        if user is None:
            raise NotFoundError("User not found")

        user.is_email_verified = True
        return self.user_repo.save(user)

    def resend_verification(self, email: str) -> None:
        user = self.user_repo.get_by_email(email)
        if user is None or user.is_email_verified:
            # Deliberately silent — do not reveal whether an account exists.
            return
        token = create_email_verification_token(user.id)
        self.email_service.send_verification_email(user.email, user.full_name, token)

    def forgot_password(self, email: str) -> None:
        user = self.user_repo.get_by_email(email)
        if user is None:
            # Same response either way, so this endpoint can't be used to enumerate accounts.
            return
        token = create_password_reset_token(user.id)
        self.email_service.send_password_reset_email(user.email, user.full_name, token)

    def reset_password(self, token: str, new_password: str) -> User:
        try:
            payload = decode_token(token, TokenType.PASSWORD_RESET)
        except TokenError as exc:
            raise InvalidTokenError("Reset link is invalid or has expired") from exc

        user = self.user_repo.get_by_id(payload["sub"])
        if user is None:
            raise NotFoundError("User not found")

        user.hashed_password = hash_password(new_password)
        return self.user_repo.save(user)

    @staticmethod
    def _issue_tokens(user: User) -> TokenResponse:
        from app.core.config import settings

        return TokenResponse(
            access_token=create_access_token(user.id, user.role.value),
            refresh_token=create_refresh_token(user.id),
            expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        )
