from __future__ import annotations

from datetime import UTC, datetime
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.model.base import Base


class UserRole(Base):
    """Справочник ролей пользователей."""

    __tablename__ = "role"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)

    users: Mapped[list[User]] = relationship("User", back_populates="role")


class User(Base):
    """Пользователь системы онлайн-кинотеатра (CinemaApp).

    В схеме используется UUID как идентификатор пользователя, что удобно для микросервисной архитектуры.

    Поля, специфичные для других доменных областей, убраны — остаются только данные для auth/profile.
    """

    __tablename__ = "user"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    role_id: Mapped[int] = mapped_column(Integer, ForeignKey("role.id"), nullable=False)
    role_name: Mapped[str] = mapped_column(String(50), nullable=False)

    username: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    registration_date: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    role: Mapped[UserRole] = relationship("UserRole", back_populates="users")
