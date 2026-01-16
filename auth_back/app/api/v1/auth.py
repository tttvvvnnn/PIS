from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, Query
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status

from app.api.openapi import generate_responses
from app.db.session import get_session
from app.exceptions.auth import (
    ExpiredTokenException,
    InvalidTokenException,
    MissingRoleException,
    WrongPasswordException,
    WrongRoleException,
)
from app.exceptions.email import FailedSendingEmailException
from app.exceptions.user import (
    UserAlreadyExistsException,
    UserCreationException,
    UserNotFoundException,
    UserNotVerifiedException,
    UserVerifiedException,
)
from app.schemas.success_msg import SuccessResponse
from app.schemas.token import AccessToken, RefreshTokenRequest, TokenPair, ForgotTokenRequest, VerifyTokenRequest
from app.schemas.user import (
    CreateUserPasswordRequest,
    ForgotPasswordRequest,
    ResendVerifyEmailRequest,
    ResetPasswordRequest,
)
from app.services.auth import (
    forgot_password_service,
    login_user_service,
    logout_user_service,
    oauth2_scheme,
    refresh_token_service,
    resend_verify_service,
    reset_password_service,
    signup_user_service,
    verify_email_service,
)

router = APIRouter(prefix="/auth")

get_session_ann = Annotated[AsyncSession, Depends(get_session)]

oauth2_annotated = Annotated[str, Depends(oauth2_scheme)]
oauth_pwd_ann = Annotated[OAuth2PasswordRequestForm, Depends()]


@router.post(
    "/signup",
    status_code=status.HTTP_201_CREATED,
    response_model=SuccessResponse,
    summary="Register a new user",
    description="По завершению запроса пользователю приходит сообщение на почту, регистрация ещё не завершена",
    responses=generate_responses(
        FailedSendingEmailException,
        UserAlreadyExistsException,
        WrongRoleException,
        UserCreationException,
    ),
)
async def signup(user: CreateUserPasswordRequest, db: get_session_ann, bg_task: BackgroundTasks) -> SuccessResponse:
    """
    Регистрация нового пользователя с возвращением access-токена.

    :param user: Данные пользователя (email, username, password).
    :param db: Асинхронная сессия базы данных.
    :param bg_task: Объект для фоновых задач.
    :return: Сообщение об успешной отправке на почту письма о верификации.
    :rtype: SuccessResponse
    """
    return await signup_user_service(user=user, db=db, bg_task=bg_task)


@router.post(
    "/resend-verification",
    status_code=status.HTTP_200_OK,
    response_model=SuccessResponse,
    summary="Resend verification email",
    responses=generate_responses(
        UserNotFoundException,
        UserVerifiedException,
        FailedSendingEmailException,
    ),
)
async def resend_verification(
    request: ResendVerifyEmailRequest,
    db: get_session_ann,
    bg_task: BackgroundTasks,
) -> SuccessResponse:
    """
    Повторная отправка письма для верификации email.

    :param request: Данные запроса (email пользователя).
    :param db: Асинхронная сессия базы данных.
    :param bg_task: Объект для фоновых задач (опционально).
    :return: Сообщение об успешной отправке письма с новой ссылкой верификации почты.
    :rtype: SuccessResponse
    """
    return await resend_verify_service(email=request.email, db=db, bg_task=bg_task)

@router.post(
    "/verify",
    status_code=status.HTTP_200_OK,
    response_model=TokenPair,
    summary="Verify email address",
    description="Пользователь получает пару токенов, регистрация завершена",
    responses=generate_responses(
        UserNotFoundException,
        ExpiredTokenException,
        InvalidTokenException,
    ),
)
async def verify_email(db: get_session_ann, data: VerifyTokenRequest) -> TokenPair:
    """
    Верификация почты при переходе по ссылке из письма с входом в аккаунт.

    :param data: Verify token.
    :param db: Асинхронная сессия базы данных.
    :return: Access и refresh токены в теле ответа.
    :rtype: TokenPair
    """
    token_pair = await verify_email_service(verify_token=data.token, db=db)
    return token_pair


@router.post(
    "/login",
    status_code=status.HTTP_200_OK,
    response_model=TokenPair,
    summary="Login user",
    responses=generate_responses(
        UserNotFoundException,
        UserNotVerifiedException,
        WrongPasswordException,
    ),
)
async def login(form_data: oauth_pwd_ann, db: get_session_ann) -> TokenPair:
    """
    Аутентификация пользователя с возвращением access-токена.

    :param form_data: Данные формы (username - формально, на самом деле почта email, password).
    :param db: Асинхронная сессия базы данных.
    :return: Access и refresh токены в теле ответа.
    :rtype: TokenPair
    """
    # TODO не pydantic model - нет верификации названия почты
    tokens: TokenPair = await login_user_service(email=form_data.username, password=form_data.password, db=db)
    return tokens


@router.post(
    "/refresh",
    status_code=status.HTTP_200_OK,
    response_model=AccessToken,
    summary="Get new access token via refresh one",
    responses=generate_responses(
        UserNotFoundException,
        MissingRoleException,
        ExpiredTokenException,
        InvalidTokenException,
    ),
)
async def refresh(request: RefreshTokenRequest, db: get_session_ann) -> AccessToken:
    """
    Обновление access токена по refresh токену.

    :param request: Refresh token.
    :param db: Асинхронная сессия базы данных.
    :return: Access токен в теле ответа.
    :rtype: AccessToken
    """
    return await refresh_token_service(refresh=request.refresh_token, db=db)


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    response_model=SuccessResponse,
    summary="Logout user",
    responses=generate_responses(InvalidTokenException),
)
async def logout_user(
    access_token: oauth2_annotated,
    request: RefreshTokenRequest,
    db: get_session_ann,
) -> SuccessResponse:
    """
    Выход из аккаунта.

    :param access_token: Access-токен, переданный в заголовке Authorization.
    :param request: Refresh-токен, переданный в теле запроса.
    :param db: Асинхронная сессия базы данных.
    :return: Сообщение об успешном выходе из аккаунта.
    :rtype: SuccessResponse
    """
    return await logout_user_service(access=access_token, refresh=request.refresh_token, db=db)


@router.post(
    "/forgot-password",
    status_code=status.HTTP_200_OK,
    response_model=SuccessResponse,
    summary="User forgot password",
    responses=generate_responses(
        UserNotFoundException,
        UserNotVerifiedException,
        FailedSendingEmailException,
    ),
)
async def reset_password_first_step(
    request: ForgotPasswordRequest,
    bg_task: BackgroundTasks,
    db: get_session_ann,
) -> SuccessResponse:
    """
    Первая стадия сброса пароля - отправка письма на почту со ссылкой на запрос по окончательной смены пароля.

    :param request: Email пользователя.
    :param db: Асинхронная сессия базы данных.
    :param bg_task: Объект для фоновых задач.
    :return: Сообщение об успешной отправке письма о сбросе пароля на почту.
    :rtype: SuccessResponse
    """
    return await forgot_password_service(email=request.email, bg_task=bg_task, db=db)

@router.post(
    "/reset-password",
    status_code=status.HTTP_200_OK,
    response_model=SuccessResponse,
    summary="Reset password after email link",
    responses=generate_responses(
        UserNotFoundException,
        ExpiredTokenException,
        InvalidTokenException,
        UserNotVerifiedException,
    ),
)
async def reset_password_second_step(
    reset: ForgotTokenRequest,
    db: get_session_ann,
) -> SuccessResponse:
    """
    Вторая стадия сброса пароля - со сменой в БД.

    :param reset: Новый пароль в двух экземплярах - password и confirm_password.
    :param data: Reset токен полученный из письма.
    :param db: Асинхронная сессия базы данных.
    :return: Сообщение об успешной смене пароля.
    :rtype: SuccessResponse
    """
    return await reset_password_service(password=reset.password, db=db, token=reset.token)
