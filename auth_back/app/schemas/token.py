import uuid

from pydantic import BaseModel

from app.schemas.user import ResetPasswordRequest


class AccessToken(BaseModel):
    """
    Формируемый access token.

    :cvar str access_token: Access-токен.
    :cvar str token_type: Тип токена (по умолчанию "bearer").
    """

    access_token: str
    token_type: str = "bearer"  # noqa: S105


class TokenPair(AccessToken):
    """
    Пара access и refresh токенов.

    :cvar str access_token: Access-токен.
    :cvar str refresh_token: Refresh token.

    :cvar str token_type: Тип токена (по умолчанию "bearer").
    """

    refresh_token: str


class TokenData(BaseModel):
    """
    Информацией о пользователе и токена.

    Содержит данные для проверки входа в аккаунт и последующего использования
    базовой информации о пользователе в бизнес-логике приложения.

    :cvar int id: ID пользователя в БД.
    :cvar str role: Роль пользователя.
    """

    id: uuid.UUID
    role: str


class RefreshTokenRequest(BaseModel):
    """
    Запрос на обновление access токена по refresh.

    :cvar str refresh_token: Refresh token.
    """

    refresh_token: str

class ForgotTokenRequest(ResetPasswordRequest):
    token: str


class VerifyTokenRequest(BaseModel):
    token:str
