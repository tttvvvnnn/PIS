from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status

from app.api.openapi import generate_responses
from app.db.session import get_session
from app.exceptions.auth import WrongPasswordException
from app.exceptions.user import UserNotFoundException
from app.schemas.success_msg import SuccessResponse
from app.schemas.user import UpdatePasswordRequest, UpdateUsernameRequest, UserResponse
from app.services.auth import get_current_user_ann
from app.services.user import get_user_data_service, update_password_service, update_username_service

router = APIRouter(prefix="/user")

get_session_ann = Annotated[AsyncSession, Depends(get_session)]


@router.get(
    "/me",
    status_code=status.HTTP_200_OK,
    response_model=UserResponse,
    summary="Get info about current user",
    responses=generate_responses(UserNotFoundException),
)
async def read_user_me(current_user: get_current_user_ann, db: get_session_ann) -> UserResponse:
    """
    Возвращает основную информацию о пользователе.

    :param current_user: Текущий пользователь.
    :param db: Асинхронная сессия базы данных.
    :return: Данные текущего пользователя.
    :rtype: UserResponse
    """
    return await get_user_data_service(user_id=current_user.id, db=db)


@router.patch(
    "/update-username",
    status_code=status.HTTP_200_OK,
    response_model=SuccessResponse,
    summary="Update username",
    responses=generate_responses(UserNotFoundException),
)
async def update_user_name(
    current_user: get_current_user_ann,
    new_username: UpdateUsernameRequest,
    db: get_session_ann,
) -> SuccessResponse:
    """
    Изменение username пользователя.

    :param current_user: Текущий пользователь.
    :param new_username: Новый username.
    :param db: Асинхронная сессия базы данных.
    :return: Сообщение об успешном обновлении username.
    :rtype: SuccessResponse
    """
    return await update_username_service(user_id=current_user.id, username=new_username.username, db=db)


@router.patch(
    "/update-password",
    status_code=status.HTTP_200_OK,
    response_model=SuccessResponse,
    summary="Update user password",
    responses=generate_responses(
        UserNotFoundException,
        WrongPasswordException,
    ),
)
async def password_update(
    current_user: get_current_user_ann,
    passwords: UpdatePasswordRequest,
    db: get_session_ann,
) -> SuccessResponse:
    """
    Обновление пароля текущего пользователя.

    :param current_user: Текущий пользователь.
    :param passwords: Пароли: старый и новый.
    :param db: Асинхронная сессия базы данных.
    :return: Сообщение об успешном обновлении пароля.
    :rtype: SuccessResponse
    """
    return await update_password_service(user_id=current_user.id, passwords=passwords, db=db)
