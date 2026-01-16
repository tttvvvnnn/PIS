from datetime import UTC, datetime
from typing import Annotated
import uuid

from fastapi import BackgroundTasks, Depends
from fastapi.security import OAuth2PasswordBearer
from jwt import ExpiredSignatureError, InvalidTokenError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.crud.black_list import add_token_to_blacklist
from app.db.crud.user import (
    create_new_user as create_db_user,
    get_role_id,
    get_user_by_email,
    get_user_by_id,
    update_user_is_verified,
    update_user_password,
)
from app.db.session import get_session
from app.exceptions.auth import (
    ExpiredTokenException,
    InvalidTokenException,
    TokenBlackListCreationException,
    WrongPasswordException,
    WrongRoleException,
)
from app.exceptions.user import (
    UserAlreadyExistsException,
    UserCreationException,
    UserNotFoundException,
    UserNotVerifiedException,
    UserVerifiedException,
)
from app.schemas.success_msg import SuccessResponse
from app.schemas.token import AccessToken, TokenData, TokenPair
from app.schemas.user import CreateUser, CreateUserPasswordRequest, UserResponse
from app.services.mail.mail import send_forgot_email, send_verify_email
from app.services.security.hash import get_password_hash, verify_password
from app.services.security.jwt import (
    form_access_token,
    form_short_token,
    form_token_pair,
    get_payload,
    validate_token,
    validate_token_with_black,
)

get_session_ann = Annotated[AsyncSession, Depends(get_session)]


async def create_new_user(user: CreateUser, db: AsyncSession) -> UserResponse:
    """
    Создает нового пользователя в базе данных.

    :param user: Данные пользователя (email, username, role_name, password).
    :param db: Асинхронная сессия базы данных.
    :return: ID созданного пользователя.
    :rtype: Int
    :raises UserAlreadyExistsException: Если email уже существует.
    :raises WrongRoleException: Если роль не найдена в БД.
    :raises UserCreationException: Если произошла ошибка при создании пользователя.
    """
    existing_user = await get_user_by_email(email=user.email, db=db)
    if existing_user:
        raise UserAlreadyExistsException

    role_id = await get_role_id(role_name=user.role_name, db=db)
    if role_id is None:
        raise WrongRoleException(role=user.role_name)

    hashed_password = get_password_hash(user.password)

    user_data: dict = user.model_dump(exclude={"confirm_password", "password"})
    user_data["role_id"] = role_id
    user_data["password_hash"] = hashed_password
    try:
        new_user = await create_db_user(
            user_data=user_data,
            db=db,
        )
    except IntegrityError as e:
        raise UserCreationException from e

    return UserResponse.model_validate(new_user)


async def signup_user_service(
    user: CreateUserPasswordRequest,
    db: AsyncSession,
    bg_task: BackgroundTasks,
) -> SuccessResponse:
    """
    Регистрирует нового не верифицированного пользователя в БД.

    :param user: Данные пользователя.
    :param db: Асинхронная сессия базы данных.
    :param bg_task: Объект для фоновых задач.
    :return: Сообщение об успешной отправке на почту письма о верификации.
    :rtype: SuccessResponse
    :raises UserAlreadyExistsException: Если email уже существует.
    :raises WrongRoleException: Если роль не найдена в БД.
    :raises UserCreationException: Если произошла ошибка при создании пользователя.
    :raises FailedSendingEmail: Если не удалось отправить письмо.
    """
    new_user = await create_new_user(CreateUser.model_validate(user.model_dump()), db)

    # Режим "без почты": считаем почту подтвержденной сразу
    db_user = await get_user_by_id(user_id=new_user.id, db=db)
    if db_user is not None:
        await update_user_is_verified(user=db_user, is_verified=True, db=db)

    return SuccessResponse(msg="Account Created!")


async def resend_verify_service(email: str, db: AsyncSession, bg_task: BackgroundTasks) -> SuccessResponse:
    """
    Отправка нового письма со ссылкой верификации почты.

    :param email: Электронная почта пользователя.
    :param db: Асинхронная сессия базы данных.
    :param bg_task: Объект для фоновых задач.
    :return: Сообщение об успешной отправке письма с новой ссылкой верификации почты.
    :rtype: SuccessResponse
    :raises UserNotFoundException: Если пользователь не найден.
    :raises UserVerifiedException: Если пользователь уже верифицирован.
    :raises FailedSendingEmail: Если не удалось отправить письмо.
    """
    user = await get_user_by_email(email=email, db=db)
    if user is None:
        raise UserNotFoundException
    if user.is_verified:
        raise UserVerifiedException

    verify_token: str = form_short_token(user_id=user.id)
    send_verify_email(recipients=[email], token=verify_token, bg_task=bg_task)

    return SuccessResponse(msg="Email is sent again")


async def verify_email_service(verify_token: str, db: AsyncSession) -> TokenPair:
    """
    Сервис по верификации почты пользователя с выдачей access токена и refresh токена.

    :param verify_token: Токен верификации
    :param db: Асинхронная сессия базы данных.
    :return: Access токен и refresh токен.
    :rtype: TokenPair
    :raises ExpiredTokenException: Если токен верификации просрочен.
    :raises InvalidTokenException: Если токен верификации невалиден.
    :raises UserNotFoundException: Если пользователь не найден.
    """
    user_id = validate_token(token=verify_token)
    user = await get_user_by_id(user_id=user_id, db=db)
    if user is None:
        raise UserNotFoundException
    await update_user_is_verified(user=user, is_verified=True, db=db)

    return form_token_pair(user_id=user_id, role=user.role_name)


async def authenticate_user(email: str, password: str, db: AsyncSession) -> UserResponse:
    """
    Аутентифицирует пользователя по email и паролю.

    :param email: Электронная почта пользователя.
    :param password: Пароль пользователя.
    :param db: Асинхронная сессия базы данных.
    :return: Данные о пользователе в БД.
    :rtype: UserResponse
    :raises UserNotFoundException: Если пользователь не найден.
    :raises UserNotVerifiedException: Если пользователь не верифицирован.
    :raises WrongPasswordException: Если пароль неверный.
    """
    user = await get_user_by_email(email=email, db=db)

    if user is None:
        raise UserNotFoundException
    #if not user.is_verified:
        #raise UserNotVerifiedException
    if user.password_hash is None:
        raise WrongPasswordException(detail="Password not set")
    if not verify_password(password, user.password_hash):
        raise WrongPasswordException

    return UserResponse.model_validate(user)


async def login_user_service(email: str, password: str, db: AsyncSession) -> TokenPair:
    """
    Аутентификация пользователя с возвращением access-токена.

    :param email: Электронная почта пользователя.
    :param password: Пароль пользователя.
    :param db: Асинхронная сессия базы данных.
    :return: Access, refresh токены для аутентификации.
    :rtype: TokenPair
    :raises UserNotFoundException: Если пользователь не найден.
    :raises UserNotVerifiedException: Если пользователь не верифицирован.
    :raises WrongPasswordException: Если пароль неверный.
    """
    authenticated_user: UserResponse = await authenticate_user(email=email, password=password, db=db)
    return form_token_pair(user_id=authenticated_user.id, role=authenticated_user.role_name)


async def refresh_token_service(refresh: str, db: AsyncSession) -> AccessToken:
    """
    Обновление access-токена по refresh.

    :param refresh: Refresh токен.
    :param db: Асинхронная сессия базы данных.
    :return: Новый access токен для аутентификации.
    :rtype: AccessToken
    :raises UserNotFoundException: Если в токене отсутствует ID.
    :raises MissingRoleException: Если в токене отсутствует роль.
    :raises ExpiredTokenException: Если токен просрочен.
    :raises InvalidTokenException: Если токен невалиден или в черном списке.
    """
    token_data = await validate_token_with_black(token=refresh, db=db)
    return AccessToken(access_token=form_access_token(user_id=token_data.id, role=token_data.role))


async def logout_user_service(access: str, refresh: str, db: AsyncSession) -> SuccessResponse:
    """
    Сервис по выходу из аккаунта.

    :param access: Access токен, полученный в Bearer токене.
    :param refresh: Refresh токен, полученный в теле запроса.
    :param db: Асинхронная сессия базы данных.
    :return: Сообщение об успешном выходе из аккаунта.
    :rtype: SuccessResponse
    :raises InvalidTokenException: Если токен невалиден.
    :raises TokenBlackListCreationException: Если не удалось занести токен в БД.
    """
    try:
        access_payload = get_payload(token=access)
        # jwt.decode возвращает поле exp в payload[EXP] числом (UNIX timestamp), а не datetime
        await add_token_to_blacklist(
            db=db,
            jti=str(access_payload["jti"]),
            expires_at=datetime.fromtimestamp(access_payload["exp"], tz=UTC),
        )
    except ExpiredSignatureError:
        pass
    except InvalidTokenError as e:
        raise InvalidTokenException from e
    except IntegrityError as e:
        raise TokenBlackListCreationException from e

    try:
        refresh_payload = get_payload(token=refresh)
        # jwt.decode возвращает поле exp в payload[EXP] числом (UNIX timestamp), а не datetime
        await add_token_to_blacklist(
            db=db,
            jti=str(refresh_payload["jti"]),
            expires_at=datetime.fromtimestamp(refresh_payload["exp"], tz=UTC),
        )
    except ExpiredSignatureError:
        pass
    except InvalidTokenError as e:
        raise InvalidTokenException from e
    except IntegrityError as e:
        raise TokenBlackListCreationException from e

    return SuccessResponse(msg="Logged out successfully")


async def forgot_password_service(email: str, db: AsyncSession, bg_task: BackgroundTasks) -> SuccessResponse:
    """
    Сервис по отправке на почту письма о сбросе пароля.

    :param email: Электронная почта пользователя.
    :param db: Асинхронная сессия базы данных.
    :param bg_task: Объект для фоновых задач.
    :return: Сообщение об успешной отправке письма о сбросе пароля на почту.
    :rtype: SuccessResponse
    :raises UserNotFoundException: Если пользователь не найден.
    :raises UserNotVerifiedException: Если пользователь не верифицирован.
    :raises FailedSendingEmail: Если не удалось отправить письмо.
    """
    user = await get_user_by_email(email=email, db=db)
    if user is None:
        raise UserNotFoundException
    if not user.is_verified:
        raise UserNotVerifiedException

    reset_token: str = form_short_token(user_id=user.id)
    send_forgot_email(recipients=[email], token=reset_token, bg_task=bg_task)

    return SuccessResponse(msg="Check your email to reset password")


async def reset_password_service(password: str, token: str, db: AsyncSession) -> SuccessResponse:
    """
    Смена пароля по токену из ссылки в письме.

    :param password: Новый пароль.
    :param token: Reset токен полученный из письма.
    :param db: Асинхронная сессия базы данных.
    :return: Сообщение об успешной смене пароля.
    :rtype: SuccessResponse
    :raises ExpiredTokenException: Если токен сброса пароля просрочен.
    :raises InvalidTokenException: Если токен сброса пароля невалиден.
    :raises UserNotFoundException: Если пользователь не найден.
    :raises UserNotVerifiedException: Если пользователь не верифицирован.
    """
    user_id = validate_token(token=token)

    user = await get_user_by_id(user_id=user_id, db=db)
    if user is None:
        raise UserNotFoundException
    if not user.is_verified:
        raise UserNotVerifiedException

    password_hash = get_password_hash(password)
    await update_user_password(user=user, password=password_hash, db=db)

    return SuccessResponse(msg="Password successfully updated")


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", refreshUrl="/api/v1/auth/refresh")
oauth2_ann = Annotated[str, Depends(oauth2_scheme)]

oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)
oauth2_optional_ann = Annotated[str | None, Depends(oauth2_scheme_optional)]


async def get_current_user(access_token: oauth2_ann, db: get_session_ann) -> TokenData:
    """
    DI для получения пользователя.

    :param access_token: Access-token полученный в bearer.
    :param db: Асинхронная сессия базы данных.
    :return: ID, role пользователя.
    :rtype: TokenData
    :raises UserNotFoundException: Если в токене отсутствует sub - почта / пользователь с такой почтой не найден в БД.
    :raises MissingRoleException: Если в токене отсутствует роль.
    :raises ExpiredTokenException: Если токен просрочен.
    :raises InvalidTokenException: Если токен невалиден.
    """
    token_data = await validate_token_with_black(token=access_token, db=db)
    # Пользователь мог быть удален из базы данных после выдачи токена (например, админом или через /delete-user)
    return token_data


async def get_current_user_optional(access_token: oauth2_optional_ann, db: get_session_ann) -> TokenData | None:
    """
    DI для получения текущего пользователя (опциональная аутентификация).

    :param access_token: Access-токен, полученный в Bearer (может быть None).
    :param db: Асинхронная сессия базы данных.
    :return: Данные токена (ID, роль) или None, если токен отсутствует или невалиден.
    :rtype: TokenData | None
    """
    if not access_token:
        return None

    try:
        token_data = await validate_token_with_black(token=access_token, db=db)
        return token_data
    except (InvalidTokenException, ExpiredTokenException):
        return None


get_current_user_ann = Annotated[TokenData, Depends(get_current_user)]
get_current_user_optional_ann = Annotated[TokenData | None, Depends(get_current_user_optional)]
