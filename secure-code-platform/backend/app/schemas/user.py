"""Request/response schemas for user profile and (admin) user management."""
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.schemas.auth import _validate_password_strength


class UserOut(BaseModel):
    id: str
    full_name: str
    email: str
    role: str
    is_active: bool
    is_email_verified: bool
    avatar_color: str
    created_at: datetime
    last_login_at: datetime | None = None

    model_config = {"from_attributes": True}


class UpdateProfileRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return _validate_password_strength(v)

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v: str, info) -> str:
        if "new_password" in info.data and v != info.data["new_password"]:
            raise ValueError("Passwords do not match")
        return v


class NotificationSettingsRequest(BaseModel):
    notify_email_on_scan_complete: bool
    notify_email_on_critical_vuln: bool
    notify_weekly_digest: bool


class ApiKeyOut(BaseModel):
    id: str
    label: str
    key_prefix: str
    is_active: bool
    created_at: datetime
    last_used_at: datetime | None = None

    model_config = {"from_attributes": True}


class ApiKeyCreateRequest(BaseModel):
    label: str = Field(min_length=2, max_length=120)


class ApiKeyCreatedResponse(BaseModel):
    """Returned exactly once, at creation time — the raw key is never retrievable again."""
    api_key: ApiKeyOut
    raw_key: str


# --- Admin: user management ---

class AdminUpdateUserRequest(BaseModel):
    is_active: bool | None = None
    role: str | None = None  # "user" | "admin"


class AdminUserListItem(UserOut):
    total_scans: int = 0
