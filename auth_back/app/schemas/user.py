from enum import Enum
import uuid
import re
from typing import Self

from pydantic import BaseModel, ConfigDict, EmailStr, field_validator, model_validator


class UserRoleEnum(str, Enum):
    """
    Роли пользователей в системе.

    :cvar str ADMIN: Администратор с полными правами.
    :cvar str USER: Обычный пользователь с базовыми правами.
    :cvar str MODERATOR: Модератор с правами на модерацию контента.
    """

    ADMIN = "admin"
    USER = "user"
    MODERATOR = "moderator"


class UserBase(BaseModel):
    """
    Базовая модель пользователя.

    :cvar EmailStr email: Электронная почта пользователя, уникальный идентификатор.
    :cvar UserRole | None role_name: Роль пользователя (по умолчанию USER).
    :cvar str username: Имя пользователя.
    """

    email: EmailStr
    role_name: UserRoleEnum = UserRoleEnum.USER
    username: str

    @field_validator("role_name", mode="before")
    @classmethod
    def normalize_role(cls, value: str) -> str:
        """
        Нормализует поле 'role_name' перед валидацией.

        Функция гарантирует, что значения "  ADMIN  ", "admin" и "Admin" будут обработаны одинаково.

        :param value: Входящее значение поля 'role_name'.
        :type value: str
        :return: Нормализованная строка (в нижнем регистре, без пробелов).
        :rtype: str
        """
        return value.strip().lower()


class CreateUser(UserBase):
    """
     Новый пользователь.

    :cvar EmailStr email: Электронная почта пользователя, уникальный идентификатор.
    :cvar UserRole | None role_name: Роль пользователя (по умолчанию USER).
    :cvar str username: Имя пользователя.

    :cvar str password: Пароль пользователя для локальной регистрации.
    """

    password: str


class UserResponse(UserBase):
    """
    Модель ответа для данных пользователя.

    :cvar EmailStr email: Электронная почта пользователя.
    :cvar UserRole | None role_name: Роль пользователя (по умолчанию USER).
    :cvar str username: Имя пользователя.

    :cvar int id: Уникальный идентификатор пользователя.
    :cvar bool is_verified: Статус верификации email пользователя.
    """

    id: uuid.UUID
    is_verified: bool = False

    model_config = ConfigDict(from_attributes=True, extra="forbid")


class ResendVerifyEmailRequest(BaseModel):
    """
    Запрос для отправки письма со ссылкой на верификацию ещё раз.

    :cvar EmailStr email: Электронная почта пользователя.
    """

    email: EmailStr


class ForgotPasswordRequest(BaseModel):
    """
    Запрос для сброса пароля.

    :cvar EmailStr email: Электронная почта пользователя.
    """

    email: EmailStr


class ResetPasswordRequest(BaseModel):
    """
    Запрос для установки нового пароля.

    :cvar str password: Новый пароль.
    :cvar str confirm_password: Подтверждение нового пароля.

    Валидация:
    - `password` и `confirm_password` должны совпадать.
    """

    password: str
    confirm_password: str

    @model_validator(mode="after")
    def validate_password_strength(self) -> Self:
        """Валидация сложности пароля."""
        password = self.password
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not re.search(r"[a-zA-Z]", password):
            raise ValueError("Password must contain at least one letter")
        if not re.search(r"[0-9!@#$%^&*()]", password):
            raise ValueError("Password must contain at least one digit or special character (!@#$%^&*())")
        forbidden_passwords = {"password", "qwerty", "11111111", "12345678", "admin", "123456", "letmein", "welcome"}
        password_lower = password.lower()
        if any(forbidden in password_lower for forbidden in forbidden_passwords):
            raise ValueError("Password contains a forbidden pattern and is too common or simple")
        if " " in password:
            raise ValueError("Password cannot contain spaces")
        return self

    @model_validator(mode="after")
    def check_passwords_match(self) -> Self:
        """Валидация пароля."""
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match")
        return self


class UpdatePasswordRequest(ResetPasswordRequest):
    """
    Запрос для обновления пароля.

    :cvar str password: Новый пароль.
    :cvar str confirm_password: Подтверждение нового пароля.

    :cvar str old_password: Текущий пароль пользователя.
    """

    old_password: str


class CreateUserPasswordRequest(UserBase, ResetPasswordRequest):
    """
    Схема запроса для создания нового пользователя.

    :cvar EmailStr email: Электронная почта пользователя, уникальный идентификатор.
    :cvar UserRole | None role_name: Роль пользователя (по умолчанию USER).
    :cvar str username: Имя пользователя.
    :cvar str password: Пароль пользователя.
    :cvar str confirm_password: Подтверждение пароля.

    Валидация:
    - `password` и `confirm_password` должны совпадать.
    """


class UpdateUsernameRequest(BaseModel):
    """
    Схема запроса для обновления имени пользователя.

    :cvar str username: Новое имя пользователя.
    """

    username: str


class LoginUser(BaseModel):
    """
    Схема запроса для входа.

    :cvar EmailStr email: Электронная почта пользователя, уникальный идентификатор.
    :cvar str password: Пароль пользователя.
    """

    email: EmailStr
    password: str

    model_config = ConfigDict(populate_by_name=True)
