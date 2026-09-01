"""
User repository.

Encapsulates all direct ORM/session access for the User model. Services call
into this layer instead of touching `db.query(...)` themselves — that keeps
SQLAlchemy specifics out of business logic and makes the service layer easy
to test with a fake repository.
"""
from typing import Optional, Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.scan import Scan
from app.models.user import User, UserRole


class UserRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, user_id: str) -> Optional[User]:
        return self.db.get(User, user_id)

    def get_by_email(self, email: str) -> Optional[User]:
        stmt = select(User).where(func.lower(User.email) == email.lower())
        return self.db.execute(stmt).scalar_one_or_none()

    def create(self, *, full_name: str, email: str, hashed_password: str, role: UserRole = UserRole.USER) -> User:
        user = User(full_name=full_name, email=email.lower(), hashed_password=hashed_password, role=role)
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def save(self, user: User) -> User:
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def delete(self, user: User) -> None:
        self.db.delete(user)
        self.db.commit()

    def list_all(self, *, search: str = "", page: int = 1, page_size: int = 20) -> tuple[Sequence[User], int]:
        stmt = select(User)
        if search:
            like = f"%{search.lower()}%"
            stmt = stmt.where(func.lower(User.full_name).like(like) | func.lower(User.email).like(like))

        total = self.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
        stmt = stmt.order_by(User.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
        items = self.db.execute(stmt).scalars().all()
        return items, total

    def count_total(self) -> int:
        return self.db.execute(select(func.count()).select_from(User)).scalar_one()

    def scan_count_for_user(self, user_id: str) -> int:
        stmt = select(func.count()).select_from(Scan).where(Scan.owner_id == user_id)
        return self.db.execute(stmt).scalar_one()
