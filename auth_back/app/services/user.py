import uuid

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession


from app.db.crud.user import get_user_by_id, update_user_password, update_user_username
from app.exceptions.auth import WrongPasswordException
from app.exceptions.user import SamePasswordException, UserNotFoundException, UserUpdateException
from app.schemas.success_msg import SuccessResponse
from app.schemas.user import UpdatePasswordRequest, UserResponse
from app.services.security.hash import get_password_hash, verify_password


async def get_user_data_service(user_id: uuid.UUID, db: AsyncSession) -> UserResponse:
    """
    Функция для получения данных о пользователе.

    :param user_id: ID пользователя в БД.
    :param db: Асинхронная сессия базы данных.
    :return: Основные данные пользователя.
    :rtype: UserResponse
    :raises UserNotFoundException: Если пользователь не найден.
    """
    user_db = await get_user_by_id(user_id=user_id, db=db)
    if user_db is None:
        raise UserNotFoundException
    return UserResponse.model_validate(user_db)


async def update_password_service(user_id: uuid.UUID, passwords: UpdatePasswordRequest, db: AsyncSession) -> SuccessResponse:
    """
    Обновление пароля пользователя в БД.

    :param user_id: ID пользователя в БД.
    :param passwords: Пароли пользователя (старый и новый).
    :param db: Асинхронная сессия базы данных.
    :return: Сообщение об успешном обновлении пароля.
    :rtype: SuccessResponse
    :raises UserNotFoundException: Если пользователь не найден.
    :raises WrongPasswordException: Если старый пароль неверный.
    """
    user = await get_user_by_id(user_id=user_id, db=db)
    if user is None:
        raise UserNotFoundException

    if user.password_hash is None:
        raise WrongPasswordException(detail="Password not set")

    if not verify_password(passwords.old_password, user.password_hash):
        raise WrongPasswordException(detail="Wrong old password")

    if verify_password(passwords.password, user.password_hash):
        raise SamePasswordException

    try:
        await update_user_password(user=user, password=get_password_hash(password=passwords.password), db=db)
    except IntegrityError as e:
        raise UserUpdateException from e

    return SuccessResponse(msg="Password successfully updated")


async def update_username_service(user_id: uuid.UUID, username: str, db: AsyncSession) -> SuccessResponse:
    """
    Сервис обновления имени пользователя в БД.

    :param user_id: ID пользователя в БД.
    :param username: Новое имя пользователя.
    :param db: Асинхронная сессия базы данных.
    :return: Сообщение об успешном обновлении username.
    :rtype: SuccessResponse
    :raises UserNotFoundException: Если пользователь не найден.
    """
    user = await get_user_by_id(user_id=user_id, db=db)
    if user is None:
        raise UserNotFoundException

    try:
        await update_user_username(user=user, username=username, db=db)
        # тут должно быть обновление имени пользователя в рейтинге
    except IntegrityError as e:
        raise UserUpdateException from e

    return SuccessResponse(msg="Username updated successfully")
