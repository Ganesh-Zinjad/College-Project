"""Profile endpoints: personal details, password, API keys, notification prefs."""
from fastapi import APIRouter, status
from sqlalchemy import select

from app.core.dependencies import CurrentUser, DbSession
from app.core.exceptions import ForbiddenError, InvalidCredentialsError, NotFoundError
from app.core.security import generate_api_key, hash_password, verify_password
from app.models.api_key import ApiKey
from app.repositories.user_repository import UserRepository
from app.schemas.auth import MessageResponse
from app.schemas.user import (
    ApiKeyCreatedResponse,
    ApiKeyCreateRequest,
    ApiKeyOut,
    ChangePasswordRequest,
    NotificationSettingsRequest,
    UpdateProfileRequest,
    UserOut,
)

router = APIRouter(prefix="/profile", tags=["Profile"])


@router.get("", response_model=UserOut)
def get_profile(current_user: CurrentUser):
    return current_user


@router.put("", response_model=UserOut)
def update_profile(payload: UpdateProfileRequest, current_user: CurrentUser, db: DbSession):
    current_user.full_name = payload.full_name
    return UserRepository(db).save(current_user)


@router.post("/change-password", response_model=MessageResponse)
def change_password(payload: ChangePasswordRequest, current_user: CurrentUser, db: DbSession):
    if not verify_password(payload.current_password, current_user.hashed_password):
        raise InvalidCredentialsError("Current password is incorrect")
    current_user.hashed_password = hash_password(payload.new_password)
    UserRepository(db).save(current_user)
    return MessageResponse(message="Password updated successfully")


@router.put("/notifications", response_model=UserOut)
def update_notifications(payload: NotificationSettingsRequest, current_user: CurrentUser, db: DbSession):
    current_user.notify_email_on_scan_complete = payload.notify_email_on_scan_complete
    current_user.notify_email_on_critical_vuln = payload.notify_email_on_critical_vuln
    current_user.notify_weekly_digest = payload.notify_weekly_digest
    return UserRepository(db).save(current_user)


# --- API Keys ---

@router.get("/api-keys", response_model=list[ApiKeyOut])
def list_api_keys(current_user: CurrentUser, db: DbSession):
    stmt = select(ApiKey).where(ApiKey.owner_id == current_user.id).order_by(ApiKey.created_at.desc())
    return db.execute(stmt).scalars().all()


@router.post("/api-keys", response_model=ApiKeyCreatedResponse, status_code=status.HTTP_201_CREATED)
def create_api_key(payload: ApiKeyCreateRequest, current_user: CurrentUser, db: DbSession):
    raw_key = generate_api_key()
    key_record = ApiKey(
        owner_id=current_user.id,
        label=payload.label,
        hashed_key=hash_password(raw_key),
        key_prefix=raw_key[:16] + "…",
    )
    db.add(key_record)
    db.commit()
    db.refresh(key_record)
    return ApiKeyCreatedResponse(api_key=ApiKeyOut.model_validate(key_record), raw_key=raw_key)


@router.delete("/api-keys/{key_id}", response_model=MessageResponse)
def revoke_api_key(key_id: str, current_user: CurrentUser, db: DbSession):
    key_record = db.get(ApiKey, key_id)
    if key_record is None:
        raise NotFoundError("API key not found")
    if key_record.owner_id != current_user.id:
        raise ForbiddenError("This API key does not belong to you")
    db.delete(key_record)
    db.commit()
    return MessageResponse(message="API key revoked")
