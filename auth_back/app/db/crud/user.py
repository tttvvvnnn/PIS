from typing import Any
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.model import User, UserRole


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    """
    Получает пользователя из базы данных по электронной почте.

    :param db: Асинхронная сессия базы данных.
    :param email: Электронная почта пользователя.
    :return: Объект пользователя или None, если пользователь не найден.
    :rtype: User | None
    """
    query = select(User).where(User.email == email)
    result = (await db.execute(query)).scalar_one_or_none()

    return result


async def get_user_by_id(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    """
    Получает пользователя из базы данных по ID.

    :param db: Асинхронная сессия базы данных.
    :param user_id: ID пользователя в БД.
    :return: Объект пользователя или None, если пользователь не найден.
    :rtype: User | None
    """
    query = select(User).where(User.id == user_id)
    result = (await db.execute(query)).scalar_one_or_none()

    return result


async def create_new_user(user_data: dict[str, Any], db: AsyncSession) -> User:
    """
    Создает нового пользователя в базе данных.

    :param user_data: Данные о пользователе (email, username, password_hash, role_id, role_name)
    :param db: Асинхронная сессия базы данных.
    :return: Объект пользователя.
    :rtype: User
    """
    user: User = User(**user_data)
    db.add(user)
    await db.flush()

    return user


async def get_role_id(role_name: str, db: AsyncSession) -> int | None:
    """
    Получает ID роли по ее имени.

    :param role_name: Название роли.
    :param db: Асинхронная сессия базы данных.
    :return: ID роли или None, если роль не найдена.
    :rtype: Int | None
    """
    query = select(UserRole.id).where(UserRole.name == role_name)
    result = (await db.execute(query)).scalar_one_or_none()

    return result


async def update_user_password(user: User, password: str, db: AsyncSession) -> User:
    """
    Изменение захешированного пароля пользователя.

    :param user: Пользователь из БД.
    :param password: Новый захешированный пароль пользователя.
    :param db: Асинхронная сессия базы данных.
    :return: Объект пользователя.
    :rtype: User
    """
    user.password_hash = password
    await db.flush()

    return user


async def update_user_is_verified(user: User, is_verified: bool, db: AsyncSession) -> User:
    """
    Изменение верификации пользователя.

    :param user: Пользователь из БД.
    :param is_verified: Верифицирован ли пользователь.
    :param db: Асинхронная сессия базы данных.
    :return: Объект пользователя.
    :rtype: User
    """
    user.is_verified = is_verified
    await db.flush()

    return user


async def update_user_username(user: User, username: str, db: AsyncSession) -> User:
    """
    Изменение имени пользователя.

    :param user: Пользователь из БД.
    :param username: Новое имя пользователя.
    :param db: Асинхронная сессия базы данных.
    :return: Объект пользователя.
    :rtype: User
    """
    user.username = username

    await db.flush()

    return user


async def get_username_by_id(user_id: uuid.UUID, db: AsyncSession) -> str | None:
    """
    Получение имени пользователя по id.

    :param user_id: Идентификатор пользователя.
    :param db: Асинхронная сессия базы данных.
    """
    query = select(User.username).where(User.id == user_id)
    result = (await db.execute(query)).scalar_one_or_none()

    return result
