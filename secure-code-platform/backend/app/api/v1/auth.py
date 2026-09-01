"""Authentication endpoints."""
from fastapi import APIRouter, status

from app.core.dependencies import CurrentUser, DbSession
from app.repositories.user_repository import UserRepository
from app.schemas.auth import (
    ForgotPasswordRequest,
    LoginRequest,
    MessageResponse,
    RefreshTokenRequest,
    RegisterRequest,
    ResendVerificationRequest,
    ResetPasswordRequest,
    TokenResponse,
    VerifyEmailRequest,
)
from app.schemas.user import UserOut
from app.services.auth_service import AuthService
from app.services.email_service import EmailService

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _service(db: DbSession) -> AuthService:
    return AuthService(UserRepository(db), EmailService())


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, db: DbSession):
    user = _service(db).register(payload)
    return user


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: DbSession):
    _, tokens = _service(db).login(payload)
    return tokens


@router.post("/refresh", response_model=TokenResponse)
def refresh(payload: RefreshTokenRequest, db: DbSession):
    return _service(db).refresh(payload.refresh_token)


@router.post("/logout", response_model=MessageResponse)
def logout(current_user: CurrentUser):
    # JWTs are stateless — "logout" is enforced client-side by discarding the
    # tokens. This endpoint exists for a consistent API surface and as the
    # natural place to add server-side token revocation (e.g. a denylist
    # keyed by the `jti` claim) if that's needed later.
    return MessageResponse(message="Logged out successfully")


@router.post("/forgot-password", response_model=MessageResponse)
def forgot_password(payload: ForgotPasswordRequest, db: DbSession):
    _service(db).forgot_password(payload.email)
    return MessageResponse(message="If an account exists for that email, a reset link has been sent")


@router.post("/reset-password", response_model=MessageResponse)
def reset_password(payload: ResetPasswordRequest, db: DbSession):
    _service(db).reset_password(payload.token, payload.new_password)
    return MessageResponse(message="Password has been reset successfully")


@router.post("/verify-email", response_model=MessageResponse)
def verify_email(payload: VerifyEmailRequest, db: DbSession):
    _service(db).verify_email(payload.token)
    return MessageResponse(message="Email verified successfully")


@router.post("/resend-verification", response_model=MessageResponse)
def resend_verification(payload: ResendVerificationRequest, db: DbSession):
    _service(db).resend_verification(payload.email)
    return MessageResponse(message="If an account exists for that email, a verification link has been sent")


@router.get("/me", response_model=UserOut)
def get_me(current_user: CurrentUser):
    return current_user
