from typing import Any

import uuid
import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.db.crud.user import create_new_user, get_role_id, get_user_by_email, get_user_by_id, get_username_by_id
from app.db.model import User, UserRole
from app.services.security.hash import get_password_hash


@pytest.fixture
def db_user() -> User:
    """Данные юзера в БД."""
    return User(
        email="test@example.com",
        username="testuser",
        password_hash=get_password_hash("password123"),
        role_name="user",
        role_id=1,
    )


@pytest.mark.asyncio
async def test_get_user_by_email(db_provider: tuple[AsyncSession, AsyncEngine], db_user: User) -> None:
    """Проверяет test_get_user_by_email."""
    # Подготовка
    async_session, engine = db_provider

    user_role = UserRole(name="user")
    async_session.add(user_role)
    await async_session.flush()

    db_user.role_id = user_role.id
    async_session.add(db_user)
    await async_session.flush()

    # Вызов функции
    result = await get_user_by_email(async_session, "test@example.com")

    # Проверки
    assert isinstance(result, User)
    assert result == db_user


@pytest.mark.asyncio
async def test_get_user_by_email_not_found(db_provider: tuple[AsyncSession, AsyncEngine]) -> None:
    """Проверяет, что функция возвращает None, если пользователь не найден."""
    # Подготовка
    async_session, engine = db_provider

    # Вызов функции
    result = await get_user_by_email(async_session, "nonexistent@example.com")

    # Проверки
    assert result is None



@pytest.mark.asyncio
async def test_get_user_by_id_found(db_provider: tuple[AsyncSession, AsyncEngine], db_user: User) -> None:
    """Проверяет, что функция возвращает объект User, если пользователь найден по ID."""
    async_session, engine = db_provider

    # Подготовка
    user_role = UserRole(name="user")
    async_session.add(user_role)
    await async_session.flush()

    db_user.role_id = user_role.id
    async_session.add(db_user)
    await async_session.flush()

    # Вызов функции
    result = await get_user_by_id(async_session, db_user.id)

    # Проверки
    assert isinstance(result, User)
    assert result == db_user


@pytest.mark.asyncio
async def test_get_user_by_id_not_found(db_provider: tuple[AsyncSession, AsyncEngine]) -> None:
    """Проверяет, что функция возвращает None, если пользователь не найден по ID."""
    async_session, engine = db_provider

    # Вызов функции
    result = await get_user_by_id(async_session, uuid.uuid4())

    # Проверки
    assert result is None


@pytest.mark.asyncio
async def test_create_new_db_user(db_provider: tuple[AsyncSession, AsyncEngine], db_user: User) -> None:
    """Проверяет, что функция создает объект User с переданными параметрами и добавляет его в сессию через db.add."""
    # Подготовка
    async_session, engine = db_provider

    user_role = UserRole(name="user")
    async_session.add(user_role)
    await async_session.flush()

    user_data: dict[str, Any] = {
        "email": db_user.email,
        "username": db_user.username,
        "password_hash": db_user.password_hash,
        "role_id": user_role.id,
        "role_name": db_user.role_name,
    }

    # Вызов функции
    result = await create_new_user(
            user_data=user_data,
            db=async_session,
        )

    # Проверки
    assert isinstance(result, User)
    assert result.email == db_user.email
    assert result.username == db_user.username
    assert result.password_hash == db_user.password_hash
    assert result.role_id == user_role.id
    assert result.role_name == db_user.role_name
    assert result.is_verified is False

    saved_user = await get_user_by_email(async_session, db_user.email)
    assert saved_user is not None
    assert saved_user.email == db_user.email


@pytest.mark.asyncio
async def test_get_role_id_found(db_provider: tuple[AsyncSession, AsyncEngine]) -> None:
    """Проверяет, что функция возвращает ID роли, если роль найдена."""
    # Подготовка
    async_session, engine = db_provider

    user_role = UserRole(name="admin")
    async_session.add(user_role)
    await async_session.flush()
    role_id = user_role.id

    # Вызов функции
    result = await get_role_id("admin", async_session)

    # Проверки
    assert result == role_id


@pytest.mark.asyncio
async def test_get_role_id_not_found(db_provider: tuple[AsyncSession, AsyncEngine]) -> None:
    """Проверяет, что функция возвращает None, если роль не найдена."""
    # Подготовка
    async_session, engine = db_provider

    # Вызов функции
    result = await get_role_id("NonExistentRole", async_session)

    # Проверки
    assert result is None


######################### ТЕСТЫ get_username_by_id ########################


@pytest.mark.asyncio
async def test_get_username_by_id_success(async_session: AsyncSession) -> None:
    """Проверяет успешное получение имени пользователя по ID."""
    user_role = UserRole(name="user")
    async_session.add(user_role)
    await async_session.flush()

    user = User(
        username="testuser",
        email="test@example.com",
        password_hash=get_password_hash("password123"),
        role_name="user",
        role_id=user_role.id,
    )
    async_session.add(user)
    await async_session.flush()

    result = await get_username_by_id(user_id=user.id, db=async_session)

    assert result == "testuser"


@pytest.mark.asyncio
async def test_get_username_by_id_not_found(async_session: AsyncSession) -> None:
    """Проверяет возврат None, если пользователь не найден."""
    result = await get_username_by_id(user_id=uuid.uuid4(), db=async_session)

    assert result is None
