from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.db.crud.black_list import add_token_to_black, get_black_token_by_id
from app.db.model.black_list import BlackListToken


@pytest.fixture
def black_list_token() -> BlackListToken:
    """Фикстура для создания тестового токена в черном списке."""
    return BlackListToken(
        expire=datetime.now(UTC) + timedelta(days=1),  # Токен истекает через день
    )


@pytest.mark.asyncio
async def test_get_black_token_by_id_found(
    db_provider: tuple[AsyncSession, AsyncEngine], black_list_token: BlackListToken
) -> None:
    """Проверяет, что функция возвращает объект BlackListToken, если токен найден."""
    async_session, engine = db_provider

    # Подготовка
    async_session.add(black_list_token)
    await async_session.flush()

    # Вызов функции

    result = await get_black_token_by_id(str(black_list_token.id), async_session)

    # Проверки
    assert isinstance(result, BlackListToken)
    assert result.id == black_list_token.id
    assert result.expire == black_list_token.expire


@pytest.mark.asyncio
async def test_get_black_token_by_id_not_found(db_provider: tuple[AsyncSession, AsyncEngine]) -> None:
    """Проверяет, что функция возвращает None, если токен не найден."""
    async_session, engine = db_provider

    # Вызов функции
    result = await get_black_token_by_id(str(uuid4()), async_session)

    # Проверки
    assert result is None


@pytest.mark.asyncio
async def test_add_token_to_black(db_provider: tuple[AsyncSession, AsyncEngine]) -> None:
    """Проверяет, что функция добавляет токен в черный список."""
    async_session, engine = db_provider

    # Подготовка
    jti = uuid4()
    expire = datetime.now(UTC) + timedelta(days=1)

    # Вызов функции
    await add_token_to_black(jti, expire, async_session)
    await async_session.flush()

    # Проверка, что токен сохранен в базе
    result = await get_black_token_by_id(str(jti), async_session)

    # Проверки
    assert result is not None
    assert result.id == jti
    assert result.expire == expire
