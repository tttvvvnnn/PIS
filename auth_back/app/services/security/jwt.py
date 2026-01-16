from datetime import UTC, datetime, timedelta
from typing import Any
import uuid

import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.crud.black_list import get_black_token_by_jti
from app.exceptions.auth import ExpiredTokenException, InvalidTokenException, MissingRoleException
from app.exceptions.user import UserNotFoundException
import uuid

from app.schemas.token import TokenData, TokenPair

SUB = "sub"
ROLE = "role"
EXP = "exp"
IAT = "iat"
JTI = "jti"


def _create_jwt_token_with_expire(payload: dict[str, Any], expires_delta: timedelta | None = None) -> str:
    """
    Генерация JWT-токена с указанным сроком действия.

    :param payload: Claim JWT.
    :param expires_delta: Срок действия.
    :return: Токен.
    :rtype: Str
    """
    to_encode = payload.copy()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(minutes=15)
    to_encode.update({EXP: expire})
    encoded_jwt = jwt.encode(payload=to_encode, key=settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def _form_token(user_id: int | str | uuid.UUID, role: str | None = None, expires_delta: timedelta | None = None) -> str:
    """
    Формирование JWT-токена с указанными данными.

    :param user_id: ID пользователя в БД.
    :param role: Роль пользователя (опционально).
    :param expires_delta: Срок действия токена (опционально).
    :return: JWT-токен.
    :rtype: Str
    """
    payload: dict[str, Any] = {SUB: str(user_id), JTI: str(uuid.uuid4()), IAT: datetime.now(UTC)}
    if role:
        payload.update({ROLE: role})
    return _create_jwt_token_with_expire(payload=payload, expires_delta=expires_delta)


def form_access_token(user_id: int | str | uuid.UUID, role: str) -> str:
    """
    Генерация access-токена.

    :param user_id: ID пользователя в БД.
    :param role: Роль пользователя.
    :return: Access-токен.
    :rtype: Str
    """
    access_token_expires = timedelta(days=settings.ACCESS_TOKEN_EXPIRE_DAYS)
    return _form_token(user_id=user_id, role=role, expires_delta=access_token_expires)


def form_refresh_token(user_id: int | str | uuid.UUID, role: str) -> str:
    """
    Генерация refresh-токена.

    :param user_id: ID пользователя в БД.
    :param role: Роль пользователя.
    :return: Refresh-токен.
    :rtype: Str
    """
    refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    return _form_token(user_id=user_id, role=role, expires_delta=refresh_token_expires)


def form_short_token(user_id: int | str | uuid.UUID) -> str:
    """
    Генерация краткосрочного JWT-токена для верификации email или сброса пароля.

    :param user_id: ID пользователя в БД.
    :return: JWT токен для верификации.
    :rtype: Str
    """
    short_token_expires = timedelta(days=settings.VERIFICATION_TOKEN_EXPIRE_DAYS)
    return _form_token(user_id=user_id, expires_delta=short_token_expires)


def form_token_pair(user_id: int | str | uuid.UUID, role: str) -> TokenPair:
    """
    Формирование пары access и refresh токенов.

    :param user_id: ID пользователя в БД.
    :param role: Роль пользователя.
    :return: Пара токенов (access и refresh).
    :rtype: TokenPair
    """
    access_token = form_access_token(user_id=user_id, role=role)
    refresh_token = form_refresh_token(user_id=user_id, role=role)
    return TokenPair(access_token=access_token, refresh_token=refresh_token)


def get_payload(token: str) -> dict[str, Any]:
    """
    Декодирование JWT-токена.

    :param token: JWT-токен.
    :return: Данные payload токена.
    :rtype: Dict
    :raises InvalidTokenException: Если токен невалиден.
    :raises ExpiredTokenException: Если токен просрочен.
    """
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except ExpiredSignatureError as e:
        raise ExpiredTokenException from e
    except InvalidTokenError as e:
        raise InvalidTokenException from e


async def _decode_token(token: str, db: AsyncSession) -> dict[str, Any]:
    """
    Декодирование JWT-токена с проверкой на отсутствие в black list.

    :param token: JWT-токен.
    :param db: Асинхронная сессия базы данных.
    :return: Данные payload токена.
    :rtype: Dict
    :raises InvalidTokenException: Если токен невалиден или в черном списке.
    :raises ExpiredTokenException: Если токен просрочен.
    """
    payload = get_payload(token=token)
    black_list_token = await get_black_token_by_jti(db=db, jti=payload[JTI])
    if black_list_token:
        raise InvalidTokenException(detail="Token is blacklisted")
    return payload


def validate_token(token: str) -> uuid.UUID:
    """
    Валидация JWT-токена.

    :param token: JWT-токен.
    :return: ID пользователя в БД.
    :rtype: int
    :raises UserNotFoundException: Если в токене отсутствует user_id.
    :raises ExpiredTokenException: Если токен просрочен.
    :raises InvalidTokenException: Если токен невалиден.
    """
    payload = get_payload(token=token)
    user_id = payload.get("sub")  # subject - идентификатор пользователя (user_id/email)
    if user_id is None:
        raise UserNotFoundException

    return uuid.UUID(str(user_id))


async def validate_token_with_black(token: str, db: AsyncSession) -> TokenData:
    """
    Валидация JWT-токена с проверкой на отсутствие в black list.

    :param token: JWT-токен.
    :param db: Асинхронная сессия базы данных.
    :return: Данные пользователя (id и role).
    :rtype: TokenData
    :raises UserNotFoundException: Если в токене отсутствует id.
    :raises MissingRoleException: Если в токене отсутствует роль.
    :raises ExpiredTokenException: Если токен просрочен.
    :raises InvalidTokenException: Если токен невалиден или в черном списке.
    """
    payload = await _decode_token(token=token, db=db)
    user_id = payload.get("sub")  # subject - идентификатор пользователя (user_id/email)
    role = payload.get("role")
    if user_id is None:
        raise UserNotFoundException
    if role is None:
        raise MissingRoleException
    return TokenData(id=uuid.UUID(str(user_id)), role=str(role))
