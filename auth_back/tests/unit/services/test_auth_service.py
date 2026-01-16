from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
import pytest_asyncio
from pytest_mock import MockerFixture
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.status import HTTP_422_UNPROCESSABLE_CONTENT

from app.db.model import User
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
from app.schemas.token import AccessToken, TokenData, TokenPair
from app.schemas.user import CreateUser, CreateUserPasswordRequest, UserResponse, UserRoleEnum
from app.services.auth import (
    authenticate_user,
    create_new_user,
    forgot_password_service,
    get_current_user,
    get_current_user_optional,
    login_user_service,
    logout_user_service,
    refresh_token_service,
    resend_verify_service,
    reset_password_service,
    signup_user_service,
    verify_email_service,
)
from app.services.security.hash import get_password_hash


@pytest_asyncio.fixture
async def mock_db() -> AsyncSession:
    """Мокаем AsyncSession."""
    return AsyncMock(spec=AsyncSession)


@pytest.fixture
def user_request() -> CreateUserPasswordRequest:
    """Фикстура для тестовых данных пользователя."""
    return CreateUserPasswordRequest(
        email="test@example.com",
        username="testuser",
        role_name=UserRoleEnum.USER,
        password="Test123!",
        confirm_password="Test123!",
    )


@pytest.fixture
def user_data() -> CreateUser:
    """Фикстура для тестовых данных пользователя."""
    return CreateUser(
        email="test@example.com",
        username="testuser",
        role_name=UserRoleEnum.USER,
        password="Test123!",
    )


@pytest.fixture
def db_user() -> User:
    """Фикстура для тестового пользователя в базе."""
    return User(
        id=uuid4(),
        email="test@example.com",
        username="testuser",
        role_id=uuid4(),
        role_name=UserRoleEnum.USER,
        password_hash=get_password_hash("Test123!"),
        is_verified=False,
    )


@pytest.fixture
def user_response() -> UserResponse:
    """Фикстура для тестового пользователя в базе."""
    return UserResponse(
        id=uuid4(),
        email="test@example.com",
        username="testuser",
        role_name=UserRoleEnum.USER,
    )


######################### ТЕСТЫ create_new_user ########################


@pytest.mark.asyncio
async def test_create_new_user_success(
    mock_db: AsyncSession, mocker: MockerFixture, user_data: CreateUser, db_user: User
) -> None:
    """Успешное создание пользователя при регистрации."""
    hashed = get_password_hash("Test123!")
    mocker.patch("app.services.auth.get_user_by_email", return_value=None)
    mocker.patch("app.services.auth.get_role_id", return_value=1)
    mocker.patch("app.services.auth.get_password_hash", return_value=hashed)
    mocker.patch("app.services.auth.create_db_user", return_value=db_user)

    result = await create_new_user(user_data, mock_db)

    assert isinstance(result, UserResponse)
    assert result.email == user_data.email
    assert result.username == user_data.username
    assert result.role_name == user_data.role_name
    assert result.is_verified is False


@pytest.mark.asyncio
async def test_create_new_user_already_exists(
    mock_db: AsyncSession, mocker: MockerFixture, user_data: CreateUser, db_user: User
) -> None:
    """Ошибка создания пользователя: с таким email пользователь уже существует."""
    mocker.patch("app.services.auth.get_user_by_email", return_value=db_user)

    with pytest.raises(UserAlreadyExistsException) as exc:
        await create_new_user(user_data, mock_db)

    assert exc.value.status_code == 409
    assert exc.value.detail == "A user with this email already exists"


@pytest.mark.asyncio
async def test_create_new_user_role_not_found(
    mock_db: AsyncSession, mocker: MockerFixture, user_data: CreateUser
) -> None:
    """Невалидная роль."""
    mocker.patch("app.services.auth.get_user_by_email", return_value=None)
    mocker.patch("app.services.auth.get_role_id", return_value=None)

    with pytest.raises(WrongRoleException) as exc:
        await create_new_user(user_data, mock_db)

    assert exc.value.status_code == HTTP_422_UNPROCESSABLE_CONTENT
    assert "is not valid" in exc.value.detail


@pytest.mark.asyncio
async def test_create_new_user_integrity_error(
    mock_db: AsyncSession, mocker: MockerFixture, user_data: CreateUser
) -> None:
    """Ошибка при создании пользователя в БД."""
    mocker.patch("app.services.auth.get_user_by_email", return_value=None)
    mocker.patch("app.services.auth.get_role_id", return_value=1)
    mocker.patch(
        "app.services.auth.create_db_user",
        side_effect=IntegrityError(
            "statement",
            {},
            Exception("mock error"),
        ),
    )

    with pytest.raises(UserCreationException) as exc:
        await create_new_user(user_data, mock_db)

    assert exc.value.status_code == 500
    assert exc.value.detail == "Failed to create user"


######################### ТЕСТЫ signup_user_service ########################


@pytest.mark.asyncio
async def test_signup_user_service_success(
    mock_db: AsyncSession, mocker: MockerFixture, user_request: CreateUserPasswordRequest, user_response: UserResponse
) -> None:
    """Успешная регистрация пользователя."""
    mocker.patch("app.services.auth.create_new_user", new=AsyncMock(return_value=user_response))
    mocker.patch("app.services.auth.get_user_by_id", new=AsyncMock(return_value=User(id=user_response.id, email=user_response.email, username=user_response.username, role_id=1, role_name=user_response.role_name, password_hash=get_password_hash("Test123!"), is_verified=False)))
    mocker.patch("app.services.auth.update_user_is_verified", new=AsyncMock())
    mocker.patch("app.services.auth.form_short_token", return_value="verify_token")
    mocker.patch("app.services.auth.send_verify_email")
    bg_task = mocker.MagicMock()

    result = await signup_user_service(user_request, mock_db, bg_task=bg_task)

    assert result.msg == "Account Created!"


######################### ТЕСТЫ resend_verify_service ########################


@pytest.mark.asyncio
async def test_resend_verify_service_success(mock_db: AsyncSession, mocker: MockerFixture, db_user: User) -> None:
    """Успешная повторная отправка письма верификации."""
    bg_task = mocker.MagicMock()
    mocker.patch("app.services.auth.get_user_by_email", return_value=db_user)
    mocker.patch("app.services.auth.form_short_token", return_value="verify_token")
    mocker.patch("app.services.auth.send_verify_email")

    result = await resend_verify_service(db_user.email, mock_db, bg_task)

    assert result.msg == "Email is sent again"


@pytest.mark.asyncio
async def test_resend_verify_service_user_not_found(mock_db: AsyncSession, mocker: MockerFixture) -> None:
    """Ошибка: пользователь не найден."""
    bg_task = mocker.MagicMock()
    mocker.patch("app.services.auth.get_user_by_email", return_value=None)

    with pytest.raises(UserNotFoundException) as exc:
        await resend_verify_service("nonexistent@example.com", mock_db, bg_task)

    assert exc.value.status_code == 404
    assert exc.value.detail == "User is not found"


@pytest.mark.asyncio
async def test_resend_verify_service_user_verified(mock_db: AsyncSession, mocker: MockerFixture, db_user: User) -> None:
    """Ошибка: пользователь уже верифицирован."""
    bg_task = mocker.MagicMock()
    db_user.is_verified = True
    mocker.patch("app.services.auth.get_user_by_email", return_value=db_user)

    with pytest.raises(UserVerifiedException) as exc:
        await resend_verify_service(db_user.email, mock_db, bg_task)

    assert exc.value.status_code == 409
    assert exc.value.detail == "User is already verified"


######################### ТЕСТЫ verify_email_service ########################


@pytest.mark.asyncio
async def test_verify_email_service_success(mock_db: AsyncSession, mocker: MockerFixture, db_user: User) -> None:
    """Успешная верификация email."""
    mocker.patch("app.services.auth.validate_token", return_value=db_user.id)
    mocker.patch("app.services.auth.get_user_by_id", return_value=db_user)
    mocker.patch(
        "app.services.auth.form_token_pair",
        return_value=TokenPair(access_token="access_token", refresh_token="refresh_token"),
    )

    result = await verify_email_service("verify_token", mock_db)

    assert isinstance(result, TokenPair)
    assert result.access_token == "access_token"
    assert result.refresh_token == "refresh_token"
    assert db_user.is_verified is True


@pytest.mark.asyncio
async def test_verify_email_service_user_not_found(mock_db: AsyncSession, mocker: MockerFixture) -> None:
    """Ошибка: пользователь не найден."""
    mocker.patch("app.services.auth.validate_token", return_value=1)
    mocker.patch("app.services.auth.get_user_by_id", return_value=None)

    with pytest.raises(UserNotFoundException) as exc:
        await verify_email_service("verify_token", mock_db)

    assert exc.value.status_code == 404
    assert exc.value.detail == "User is not found"


######################### ТЕСТЫ authenticate_user ########################


@pytest.mark.asyncio
async def test_authenticate_user_success(mock_db: AsyncSession, mocker: MockerFixture, db_user: User) -> None:
    """Успешная аутентификация пользователя по паролю."""
    db_user.is_verified = True
    mocker.patch("app.services.auth.get_user_by_email", return_value=db_user)
    mocker.patch("app.services.auth.verify_password", return_value=True)

    user_response = await authenticate_user(db_user.email, "Test123!", mock_db)

    assert user_response.email == "test@example.com"
    assert user_response.username == "testuser"
    assert user_response.role_name == UserRoleEnum.USER


@pytest.mark.asyncio
async def test_authenticate_user_no_password_set(
    mock_db: AsyncSession,
    mocker: MockerFixture,
    db_user: User,
) -> None:
    """Тестирует ошибку, если у пользователя не установлен пароль (password_hash is None)."""
    db_user.is_verified = True
    db_user.password_hash = None
    mocker.patch("app.services.auth.get_user_by_email", return_value=db_user)

    with pytest.raises(WrongPasswordException) as exc:
        await authenticate_user(db_user.email, "any_password", mock_db)

    assert exc.value.status_code == 401
    assert exc.value.detail == "Password not set"


@pytest.mark.asyncio
async def test_authenticate_user_not_found(mock_db: AsyncSession, mocker: MockerFixture) -> None:
    """Регистрация пользователя с неверным email."""
    mocker.patch("app.services.auth.get_user_by_email", return_value=None)

    with pytest.raises(UserNotFoundException) as exc:
        await authenticate_user("test@example.com", "Test123!", mock_db)

    assert exc.value.status_code == 404
    assert "not found" in exc.value.detail


@pytest.mark.asyncio
async def test_authenticate_user_not_verified(mock_db: AsyncSession, mocker: MockerFixture, db_user: User) -> None:
    """В текущей конфигурации проверка is_verified отключена, поэтому аутентификация проходит."""
    db_user.is_verified = False
    mocker.patch("app.services.auth.get_user_by_email", return_value=db_user)

    result = await authenticate_user(db_user.email, "Test123!", mock_db)

    assert isinstance(result, UserResponse)
    assert result.email == db_user.email


@pytest.mark.asyncio
async def test_authenticate_user_wrong_password(mock_db: AsyncSession, mocker: MockerFixture, db_user: User) -> None:
    """Регистрация пользователя с неверным паролем."""
    db_user.is_verified = True
    mocker.patch("app.services.auth.get_user_by_email", return_value=db_user)
    mocker.patch("app.services.auth.verify_password", return_value=False)

    with pytest.raises(WrongPasswordException) as exc:
        await authenticate_user("test@example.com", "wrongpassword", mock_db)

    assert exc.value.status_code == 401
    assert exc.value.detail == "Wrong password"


######################### ТЕСТЫ login_user_service ########################


@pytest.mark.asyncio
async def test_login_user_service_success(
    mock_db: AsyncSession, mocker: MockerFixture, user_response: UserResponse
) -> None:
    """Успешный вход."""
    mocker.patch("app.services.auth.authenticate_user", return_value=user_response)
    mocker.patch(
        "app.services.auth.form_token_pair",
        return_value=TokenPair(access_token="access_token", refresh_token="refresh_token"),
    )

    result = await login_user_service(user_response.email, "Test123!", mock_db)

    assert isinstance(result, TokenPair)
    assert result.access_token == "access_token"
    assert result.refresh_token == "refresh_token"


######################### ТЕСТЫ refresh_token_service ########################


@pytest.mark.asyncio
async def test_refresh_token_service_success(mock_db: AsyncSession, mocker: MockerFixture) -> None:
    """Успешное обновление access-токена."""
    mocker.patch("app.services.auth.validate_token_with_black", return_value=TokenData(id=uuid4(), role="user"))
    mocker.patch("app.services.auth.form_access_token", return_value="new_access_token")

    result = await refresh_token_service("refresh_token", mock_db)

    assert isinstance(result, AccessToken)
    assert result.access_token == "new_access_token"


######################### ТЕСТЫ logout_user_service ########################


@pytest.mark.asyncio
async def test_logout_user_service_success(mock_db: AsyncSession, mocker: MockerFixture) -> None:
    """Успешный выход из аккаунта."""
    mocker.patch(
        "app.services.auth.get_payload",
        side_effect=[
            {"jti": str(uuid4()), "exp": datetime.now(UTC).timestamp()},
            {"jti": str(uuid4()), "exp": datetime.now(UTC).timestamp()},
        ],
    )
    mocker.patch("app.services.auth.add_token_to_blacklist", new=AsyncMock())

    result = await logout_user_service("access_token", "refresh_token", mock_db)

    assert result.msg == "Logged out successfully"


@pytest.mark.asyncio
async def test_logout_user_service_invalid_token(mock_db: AsyncSession, mocker: MockerFixture) -> None:
    """Ошибка: невалидный токен."""
    from jwt.exceptions import InvalidTokenError

    mocker.patch("app.services.auth.get_payload", side_effect=InvalidTokenError)

    with pytest.raises(InvalidTokenException) as exc:
        await logout_user_service("invalid_access_token", "refresh_token", mock_db)

    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid token"
    assert exc.value.headers == {"WWW-Authenticate": "Bearer"}


@pytest.mark.asyncio
async def test_logout_user_service_invalid_refresh_token(mock_db: AsyncSession, mocker: MockerFixture) -> None:
    """Ошибка: невалидный refresh токен."""
    from jwt.exceptions import InvalidTokenError

    # Mock get_payload to return valid payload for access token and raise InvalidTokenError for refresh token
    valid_access_payload: dict[str, str | int] = {
        "jti": "123e4567-e89b-12d3-a456-426614174000",
        "exp": int(datetime(2025, 8, 21, tzinfo=UTC).timestamp()),
    }
    mocker.patch(
        "app.services.auth.get_payload",
        side_effect=[valid_access_payload, InvalidTokenError],  # First call (access) succeeds, second (refresh) fails
    )

    # Mock add_token_to_blacklistlist to simulate successful blacklisting of access token
    mocker.patch("app.services.auth.add_token_to_blacklist", new=AsyncMock(return_value=None))

    with pytest.raises(InvalidTokenException) as exc:
        await logout_user_service("valid_access_token", "invalid_refresh_token", mock_db)

    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid token"
    assert exc.value.headers == {"WWW-Authenticate": "Bearer"}


@pytest.mark.asyncio
async def test_logout_user_service_expired_token(mock_db: AsyncSession, mocker: MockerFixture) -> None:
    """Ошибка: истек срок токена, но выход производится."""
    from jwt.exceptions import ExpiredSignatureError

    mocker.patch("app.services.auth.get_payload", side_effect=ExpiredSignatureError)

    result = await logout_user_service("expired_access_token", "refresh_token", mock_db)

    assert result.msg == "Logged out successfully"


@pytest.mark.asyncio
async def test_logout_user_service_access_integrity_error(
    mock_db: AsyncSession,
    mocker: MockerFixture,
) -> None:
    """Тестирует ошибку IntegrityError при добавлении access-токена в черный список."""
    # Мокаем get_payload для access_token
    access_payload: dict[str, Any] = {"jti": str(uuid4()), "exp": datetime.now(UTC).timestamp() + 3600}
    mocker.patch("app.services.auth.get_payload", return_value=access_payload)

    # Мокаем add_token_to_blacklistlist, чтобы он вызвал IntegrityError
    mocker.patch(
        "app.services.auth.add_token_to_blacklist",
        side_effect=IntegrityError(
            "statement",
            {},
            Exception("mock error"),
        ),
    )

    # Проверяем, что сервис корректно пробрасывает исключение
    with pytest.raises(TokenBlackListCreationException):
        await logout_user_service("access_token", "refresh_token", mock_db)


@pytest.mark.asyncio
async def test_logout_user_service_refresh_integrity_error(
    mock_db: AsyncSession,
    mocker: MockerFixture,
) -> None:
    """Тестирует ошибку IntegrityError при добавлении refresh-токена в черный список."""
    # Мокаем get_payload для access_token и refresh_token
    access_payload: dict[str, Any] = {"jti": str(uuid4()), "exp": datetime.now(UTC).timestamp() + 3600}
    refresh_payload: dict[str, Any] = {"jti": str(uuid4()), "exp": datetime.now(UTC).timestamp() + 86400}
    mocker.patch("app.services.auth.get_payload", side_effect=[access_payload, refresh_payload])

    # Мокаем add_token_to_blacklistlist: первая запись (access) успешна, вторая (refresh) падает с ошибкой
    mocker.patch(
        "app.services.auth.add_token_to_blacklist",
        side_effect=[
            None,  # Успешное добавление access_token
            IntegrityError(
                "statement",
                {},
                Exception("mock error"),
            ),  # Ошибка при добавлении refresh_token
        ],
    )

    # Проверяем, что сервис корректно пробрасывает исключение
    with pytest.raises(TokenBlackListCreationException):
        await logout_user_service("access_token", "refresh_token", mock_db)


######################### ТЕСТЫ forgot_password_service ########################


@pytest.mark.asyncio
async def test_forgot_password_service_success(mock_db: AsyncSession, mocker: MockerFixture, db_user: User) -> None:
    """Успешная отправка письма для сброса пароля."""
    bg_task = mocker.MagicMock()
    db_user.is_verified = True
    mocker.patch("app.services.auth.get_user_by_email", return_value=db_user)
    mocker.patch("app.services.auth.form_short_token", return_value="reset_token")
    mocker.patch("app.services.auth.send_forgot_email")

    result = await forgot_password_service(db_user.email, mock_db, bg_task)

    assert result.msg == "Check your email to reset password"


@pytest.mark.asyncio
async def test_forgot_password_service_not_found(mock_db: AsyncSession, mocker: MockerFixture) -> None:
    """Ошибка: пользователь не найден."""
    bg_task = mocker.MagicMock()
    mocker.patch("app.services.auth.get_user_by_email", return_value=None)

    with pytest.raises(UserNotFoundException) as exc:
        await forgot_password_service("nonexistent@example.com", mock_db, bg_task)

    assert exc.value.status_code == 404
    assert "not found" in exc.value.detail


@pytest.mark.asyncio
async def test_forgot_password_service_not_verified(
    mock_db: AsyncSession, mocker: MockerFixture, db_user: User
) -> None:
    """Ошибка: пользователь не верифицирован."""
    bg_task = mocker.MagicMock()
    mocker.patch("app.services.auth.get_user_by_email", return_value=db_user)

    with pytest.raises(UserNotVerifiedException) as exc:
        await forgot_password_service(db_user.email, mock_db, bg_task)

    assert exc.value.status_code == 403
    assert "Verify your email" in exc.value.detail


######################### ТЕСТЫ reset_password_service ########################


@pytest.mark.asyncio
async def test_reset_password_service_success(mock_db: AsyncSession, mocker: MockerFixture, db_user: User) -> None:
    """Успешный сброс пароля."""
    db_user.is_verified = True
    new_hash = get_password_hash("NewPass123!")
    mocker.patch("app.services.auth.validate_token", return_value=db_user.id)
    mocker.patch("app.services.auth.get_user_by_id", return_value=db_user)
    mocker.patch("app.services.auth.get_password_hash", return_value=new_hash)

    result = await reset_password_service("NewPass123!", "reset_token", mock_db)

    assert result.msg == "Password successfully updated"
    assert db_user.password_hash == new_hash


@pytest.mark.asyncio
async def test_reset_password_service_not_found(mock_db: AsyncSession, mocker: MockerFixture) -> None:
    """Ошибка: пользователь не найден."""
    mocker.patch("app.services.auth.validate_token", return_value=uuid4())
    mocker.patch("app.services.auth.get_user_by_id", return_value=None)

    with pytest.raises(UserNotFoundException) as exc:
        await reset_password_service("NewPass123!", "reset_token", mock_db)

    assert exc.value.status_code == 404
    assert "not found" in exc.value.detail


@pytest.mark.asyncio
async def test_reset_password_service_not_verified(mock_db: AsyncSession, mocker: MockerFixture, db_user: User) -> None:
    """Ошибка: пользователь не верифицирован."""
    mocker.patch("app.services.auth.validate_token", return_value=db_user.id)
    mocker.patch("app.services.auth.get_user_by_id", return_value=db_user)

    with pytest.raises(UserNotVerifiedException) as exc:
        await reset_password_service("NewPass123!", "reset_token", mock_db)

    assert exc.value.status_code == 403
    assert "Verify your email" in exc.value.detail


######################### ТЕСТЫ get_current_user ########################


@pytest.mark.asyncio
async def test_get_current_user_success(mock_db: AsyncSession, mocker: MockerFixture) -> None:
    """Успешное получение текущего пользователя."""
    token_data = TokenData(id=uuid4(), role="user")
    mocker.patch("app.services.auth.validate_token_with_black", AsyncMock(return_value=token_data))

    result = await get_current_user("access_token", mock_db)

    assert isinstance(result, TokenData)
    assert result.id == token_data.id
    assert result.role == "user"


######################### ТЕСТЫ get_current_user_optional ########################


@pytest.mark.asyncio
async def test_get_current_user_optional_success(mock_db: AsyncSession, mocker: MockerFixture) -> None:
    """Успешное получение текущего пользователя с валидным токеном."""
    token_data = TokenData(id=uuid4(), role="user")
    mocker.patch("app.services.auth.validate_token_with_black", AsyncMock(return_value=token_data))

    result = await get_current_user_optional(access_token="valid_access_token", db=mock_db)

    assert isinstance(result, TokenData)
    assert result.id == token_data.id
    assert result.role == token_data.role


@pytest.mark.asyncio
async def test_get_current_user_optional_no_token(mock_db: AsyncSession) -> None:
    """Возврат None, если токен не предоставлен."""
    result = await get_current_user_optional(access_token=None, db=mock_db)

    assert result is None


@pytest.mark.asyncio
async def test_get_current_user_optional_invalid_token(mock_db: AsyncSession, mocker: MockerFixture) -> None:
    """Возврат None при невалидном токене."""
    mocker.patch("app.services.auth.validate_token_with_black", AsyncMock(side_effect=InvalidTokenException))

    result = await get_current_user_optional(access_token="invalid_access_token", db=mock_db)

    assert result is None


@pytest.mark.asyncio
async def test_get_current_user_optional_expired_token(mock_db: AsyncSession, mocker: MockerFixture) -> None:
    """Возврат None при просроченном токене."""
    mocker.patch("app.services.auth.validate_token_with_black", AsyncMock(side_effect=ExpiredTokenException))

    result = await get_current_user_optional(access_token="expired_access_token", db=mock_db)

    assert result is None
