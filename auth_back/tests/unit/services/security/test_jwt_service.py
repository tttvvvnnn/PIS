from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import uuid
from freezegun import freeze_time
import jwt
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.model import BlackListToken
from app.exceptions.auth import ExpiredTokenException, InvalidTokenException, MissingRoleException
from app.exceptions.user import UserNotFoundException
from app.services.security.jwt import (
    EXP,
    JTI,
    ROLE,
    SUB,
    TokenData,
    TokenPair,
    _create_jwt_token_with_expire,
    _decode_token,
    _form_token,
    form_access_token,
    form_refresh_token,
    form_short_token,
    form_token_pair,
    get_payload,
    validate_token,
    validate_token_with_black,
)


# Фикстура для мока UUID
@pytest.fixture
def mock_uuid() -> Iterator[MagicMock]:
    """Мокает uuid для предсказуемой генерации идентификаторов."""
    with patch("app.services.security.jwt.uuid") as mock_uuid:
        mock_uuid.uuid4.return_value = "test-uuid"
        yield mock_uuid


# Фикстура для мока текущего времени
@pytest.fixture
def mock_time() -> datetime:
    """Мокает текущее время, возвращая фиксированную дату в UTC."""
    return datetime(2023, 1, 1, 12, 0, 0, tzinfo=UTC)


# Фикстура для мока AsyncSession
@pytest.fixture
def mock_db() -> AsyncSession:
    """Мокает асинхронную сессию базы данных."""
    return AsyncMock(spec=AsyncSession)


######################### ТЕСТЫ _create_jwt_token_with_expire ########################


@pytest.mark.asyncio
async def test_create_jwt_token_with_expire(mock_time: datetime, mock_uuid: MagicMock) -> None:
    """Тестирует создание JWT-токена с указанным сроком действия."""
    with freeze_time(mock_time):
        user_id = uuid.uuid4()
        payload: dict[str, str] = {"sub": str(user_id)}
        expires_delta: timedelta = timedelta(minutes=30)
        token = _create_jwt_token_with_expire(payload, expires_delta)

        decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

        assert decoded["sub"] == str(user_id)
        assert isinstance(decoded["exp"], int)
        assert decoded["exp"] == int((mock_time + expires_delta).timestamp())
