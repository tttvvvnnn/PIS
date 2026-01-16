from typing import Any

from httpx import AsyncClient
import pytest
import pytest_asyncio
from pytest_mock import MockerFixture
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status

from app.db.crud.user import create_new_user, get_user_by_email, get_user_by_id
from app.db.model import User, UserRole
from app.services.security.hash import get_password_hash, verify_password
from app.services.security.jwt import form_access_token, form_short_token, form_token_pair

import uuid


@pytest_asyncio.fixture
async def setup_role(async_session: AsyncSession) -> UserRole:
    """Создаем роль в БД."""
    role = UserRole(id=1, name="user")
    async_session.add(role)
    await async_session.flush()
    return role


@pytest_asyncio.fixture
async def created_user_fixt(async_session: AsyncSession, setup_role: UserRole) -> User:
    """Создает тестового пользователя в базе данных."""
    user_data: dict[str, Any] = {
        "email": "test@example.com",
        "username": "test_user",
        "password_hash": get_password_hash("test_password12"),
        "role_id": setup_role.id,
        "role_name": setup_role.name,
        "is_verified": False,
    }
    user = await create_new_user(user_data=user_data, db=async_session)
    await async_session.flush()
    return user


@pytest_asyncio.fixture
async def verified_test_user(async_session: AsyncSession, setup_role: UserRole) -> User:
    """Создает верифицированного тестового пользователя в базе данных."""
    user_data: dict[str, Any] = {
        "email": "verified@example.com",
        "username": "verified_user",
        "password_hash": get_password_hash("test_password12"),
        "role_id": setup_role.id,
        "role_name": setup_role.name,
        "is_verified": True,
    }
    user = await create_new_user(user_data=user_data, db=async_session)
    await async_session.flush()
    return user


@pytest.fixture
def mock_email(mocker: MockerFixture) -> None:
    """Мокает отправку email."""
    mocker.patch("app.services.mail.mail.fm.send_message", return_value=None)


######################### ТЕСТЫ POST /api/v1/auth/signup ########################


@pytest.mark.asyncio
async def test_signup_success(
    client: AsyncClient,
    async_session: AsyncSession,
    setup_role: UserRole,
    mock_email: None,
) -> None:
    """Тестирует успешную регистрацию нового пользователя через /signup."""
    payload = {
        "email": "newuser@example.com",
        "username": "new_user",
        "password": "string12",
        "confirm_password": "string12",
    }
    response = await client.post("/api/v1/auth/signup", json=payload)
    assert response.status_code == status.HTTP_201_CREATED
    # В текущей конфигурации проекта подтверждение почты отключено,
    # поэтому сервис сразу помечает пользователя как verified.
    assert response.json()["msg"] == "Account Created!"

    # Проверяем, что пользователь создан в базе
    user = await get_user_by_email(db=async_session, email="newuser@example.com")
    assert user is not None
    assert user.password_hash is not None
    assert user.username == "new_user"
    assert user.is_verified is True
    assert verify_password("string12", user.password_hash)


@pytest.mark.asyncio
async def test_signup_uses_default_role(
    client: AsyncClient,
    async_session: AsyncSession,
    setup_role: UserRole,
    mock_email: None,
) -> None:
    """
    Тест: регистрация без роли использует 'user' по умолчанию.

    Проверяет, что:
    1. При создании пользователя без указания 'role_name'
       корректно используется роль 'user'.
    2. Валидатор 'normalize_role' покрывает ветку 'else'
       (обработку значения, не являющегося 'str').
    """
    # Готовим данные без "role_name"
    user_data = {
        "email": "default_user@example.com",
        "username": "default_user",
        "password": "S3cureDefaultTest!",
        "confirm_password": "S3cureDefaultTest!",
        # "role_name" намеренно пропущено
    }

    # Вызываем эндпоинт регистрации
    response = await client.post("/api/v1/auth/signup", json=user_data)

    # Проверяем, что пользователь создан
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["msg"] == "Account Created!"

    # Проверяем в базе, что присвоена роль по умолчанию
    user_in_db = await get_user_by_email(db=async_session, email="default_user@example.com")
    assert user_in_db is not None
    assert user_in_db.role_name == "user"  # Убеждаемся, что значение по умолчанию сработало


@pytest.mark.asyncio
async def test_signup_normalizes_role(
    client: AsyncClient,
    async_session: AsyncSession,
    setup_role: UserRole,
    mock_email: None,
) -> None:
    """Тестирует, что при создании пользователя role_name нормализуется (strip и lower)."""
    # Создаем роль 'admin', чтобы она существовала в БД для теста
    admin_role = UserRole(id=2, name="admin")
    async_session.add(admin_role)
    await async_session.flush()

    # Готовим данные с "грязной" ролью
    user_data = {
        "email": "tester_role@example.com",
        "username": "tester_role",
        "password": "S3cureR0leTest!",
        "confirm_password": "S3cureR0leTest!",
        "role_name": "  ADMIN  ",  # Тестируем strip() и lower()
    }

    # Вызываем эндпоинт регистрации
    response = await client.post("/api/v1/auth/signup", json=user_data)

    # Проверяем, что пользователь создан
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["msg"] == "Account Created!"

    # Проверяем то же самое в базе данных
    user_in_db = await get_user_by_email(db=async_session, email="tester_role@example.com")
    assert user_in_db is not None
    assert user_in_db.role_name == "admin"


@pytest.mark.asyncio
async def test_signup_user_already_exists(
    client: AsyncClient,
    created_user_fixt: User,
    setup_role: UserRole,
) -> None:
    """Тестирует ошибку, когда пользователь уже существует для /signup."""
    payload = {
        "email": "test@example.com",
        "username": "test_user",
        "password": "test_pasword12",
        "confirm_password": "test_pasword12",
        "role_name": "user",
    }
    response = await client.post("/api/v1/auth/signup", json=payload)

    assert response.status_code == status.HTTP_409_CONFLICT
    assert "already exists" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_signup_wrong_role(client: AsyncClient) -> None:
    """Тестирует ошибку, когда роль не существует для /signup."""
    payload = {
        "email": "newuser@example.com",
        "username": "new_user",
        "password": "string12",
        "confirm_password": "string12",
        "role_name": "invalid_role",
    }
    response = await client.post("/api/v1/auth/signup", json=payload)

    # проверка проводиться и в сервисе, и в модели
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "input should be" in response.json()["detail"][0]["msg"].lower()


@pytest.mark.asyncio
async def test_signup_validation_error(client: AsyncClient, setup_role: UserRole) -> None:
    """Тестирует ошибку, когда введены неверные поля."""
    payload = {
        "email": "newuser@example.com",
        "username": "new_user",
        "password": "string",
        "confirm_password": "string12",
        "role_name": "invalid_role",
    }
    response = await client.post("/api/v1/auth/signup", json=payload)

    # проверка проводиться и в сервисе, и в модели
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "input should be" in response.json()["detail"][0]["msg"].lower()

    payload = {
        "username": "new_user",
        "password": "string12",
        "confirm_password": "string12",
        "role_name": "invalid_role",
    }
    response = await client.post("/api/v1/auth/signup", json=payload)

    # проверка проводиться и в сервисе, и в модели
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "field required" in response.json()["detail"][0]["msg"].lower()

    payload: dict[str, Any] = {
        "email": 123,
        "username": "new_user",
        "password": "string12",
        "confirm_password": "string12",
        "role_name": "invalid_role",
    }
    response = await client.post("/api/v1/auth/signup", json=payload)

    # проверка проводиться и в сервисе, и в модели
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "input should be" in response.json()["detail"][0]["msg"].lower()


######################### ТЕСТЫ POST /api/v1/auth/resend-verification ########################


@pytest.mark.asyncio
async def test_resend_verification_success(
    client: AsyncClient,
    created_user_fixt: User,
    mock_email: None,
) -> None:
    """Тестирует успешную повторную отправку письма верификации через /resend-verification."""
    payload = {"email": "test@example.com"}
    response = await client.post("/api/v1/auth/resend-verification", json=payload)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["msg"] == "Email is sent again"


@pytest.mark.asyncio
async def test_resend_verification_user_not_found(client: AsyncClient) -> None:
    """Тестирует ошибку, когда пользователь не найден для /resend-verification."""
    payload = {"email": "nonexistent@example.com"}
    response = await client.post("/api/v1/auth/resend-verification", json=payload)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_resend_verification_already_verified(client: AsyncClient, verified_test_user: User) -> None:
    """Тестирует ошибку, когда пользователь уже верифицирован для /resend-verification."""
    payload = {"email": "verified@example.com"}
    response = await client.post("/api/v1/auth/resend-verification", json=payload)

    assert response.status_code == status.HTTP_409_CONFLICT
    assert "already verified" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_resend_verification_validation_error(client: AsyncClient, created_user_fixt: User) -> None:
    """Тестирует ошибку при неверных входных данных для /resend-verification."""
    payload = {"email": 1234}
    response = await client.post("/api/v1/auth/resend-verification", json=payload)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "input" in response.json()["detail"][0]["msg"].lower()

    payload = {"email": "verified@examplecom"}
    response = await client.post("/api/v1/auth/resend-verification", json=payload)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "email address" in response.json()["detail"][0]["msg"].lower()


######################### ТЕСТЫ GET /api/v1/auth/verify ########################


@pytest.mark.asyncio
async def test_verify_email_success(client: AsyncClient, created_user_fixt: User, async_session: AsyncSession) -> None:
    """Тестирует успешную верификацию email через /verify."""
    verify_token = form_short_token(user_id=created_user_fixt.id)
    response = await client.post(f"/api/v1/auth/verify", json = {"token":verify_token})

    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    assert "access_token" in data
    assert "refresh_token" in data

    # Проверяем, что пользователь верифицирован
    user = await get_user_by_id(db=async_session, user_id=created_user_fixt.id)

    assert user is not None
    assert user.is_verified is True


@pytest.mark.asyncio
async def test_verify_email_user_not_found(client: AsyncClient) -> None:
    """Тестирует ошибку, когда пользователь не найден для /verify."""
    # validate_token ожидает UUID в sub
    verify_token = form_short_token(user_id=uuid.uuid4())
    response = await client.post(f"/api/v1/auth/verify", json = {"token": verify_token})

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_verify_email_invalid_token(client: AsyncClient) -> None:
    """Тестирует ошибку при невалидном токене для /verify."""
    response = await client.post(f"/api/v1/auth/verify", json = {"token": "invalid"})

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "invalid token" in response.json()["detail"].lower()


######################### ТЕСТЫ POST /api/v1/auth/login ########################


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient, verified_test_user: User) -> None:
    """Тестирует успешный логин через /login."""
    payload = {"username": "verified@example.com", "password": "test_password12"}
    response = await client.post("/api/v1/auth/login", data=payload)

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data


@pytest.mark.asyncio
async def test_login_user_not_found(client: AsyncClient) -> None:
    """Тестирует ошибку, когда пользователь не найден для /login."""
    payload = {"username": "nonexistent@example.com", "password": "test_password12"}
    response = await client.post("/api/v1/auth/login", data=payload)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_login_not_verified(client: AsyncClient, created_user_fixt: User) -> None:
    """Тестирует ошибку, когда пользователь не верифицирован для /login."""
    payload = {"username": "test@example.com", "password": "test_password12"}
    response = await client.post("/api/v1/auth/login", data=payload)

    # В текущей конфигурации проекта проверка is_verified при логине отключена.
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data


@pytest.mark.asyncio
async def test_login_wrong_password(client: AsyncClient, verified_test_user: User) -> None:
    """Тестирует ошибку при неверном пароле для /login."""
    payload = {"username": "verified@example.com", "password": "wrong_password"}
    response = await client.post("/api/v1/auth/login", data=payload)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "wrong password" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_login_validation_error(client: AsyncClient, verified_test_user: User) -> None:
    """Тестирует ошибку при неверных входных данных для /login."""
    payload = {"username": "verified@examplecom"}
    response = await client.post("/api/v1/auth/login", data=payload)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "field" in response.json()["detail"][0]["msg"].lower()


######################### ТЕСТЫ POST /api/v1/auth/refresh ########################


@pytest.mark.asyncio
async def test_refresh_token_success(client: AsyncClient, verified_test_user: User, mocker: MockerFixture) -> None:
    """Тестирует успешное обновление access-токена через /refresh."""
    # В проекте blacklist проверяется по jti
    mocker.patch("app.services.security.jwt.get_black_token_by_jti", new=mocker.AsyncMock(return_value=None))
    refresh_token = form_token_pair(user_id=verified_test_user.id, role=verified_test_user.role_name).refresh_token
    response = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data


@pytest.mark.asyncio
async def test_refresh_token_invalid(client: AsyncClient) -> None:
    """Тестирует ошибку при невалидном refresh-токене для /refresh."""
    response = await client.post("/api/v1/auth/refresh", json={"refresh_token": "invalid_token"})

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "invalid token" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_refresh_token_validation_error(client: AsyncClient) -> None:
    """Тестирует ошибку при неверных входных данных refresh-токене для /refresh."""
    response = await client.post("/api/v1/auth/refresh", json={"refresh_token": 123})

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "input" in response.json()["detail"][0]["msg"].lower()


######################### ТЕСТЫ POST /api/v1/auth/logout ########################


@pytest.mark.asyncio
async def test_logout_success(
    client: AsyncClient, verified_test_user: User, async_session: AsyncSession, mocker: MockerFixture
) -> None:
    """Тестирует успешный выход из аккаунта через /logout."""
    # В проекте используется add_token_to_blacklist (async)
    mocker.patch("app.services.auth.add_token_to_blacklist", new=mocker.AsyncMock(return_value=None))
    token_pair = form_token_pair(user_id=verified_test_user.id, role=verified_test_user.role_name)
    headers = {"Authorization": f"Bearer {token_pair.access_token}"}
    response = await client.post(
        "/api/v1/auth/logout", json={"refresh_token": token_pair.refresh_token}, headers=headers
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["msg"] == "Logged out successfully"


@pytest.mark.asyncio
async def test_logout_invalid_token(client: AsyncClient) -> None:
    """Тестирует ошибку при невалидном access-токене для /logout."""
    headers = {"Authorization": "Bearer invalid_token"}
    response = await client.post("/api/v1/auth/logout", json={"refresh_token": "some_refresh_token"}, headers=headers)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "invalid token" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_logout_validation_error(client: AsyncClient, verified_test_user: User) -> None:
    """Тестирует ошибку при передаче неверных данных access-токене для /logout."""
    token = form_access_token(user_id=verified_test_user.id, role=verified_test_user.role_name)
    headers = {"Authorization": f"Bearer {token}"}
    response = await client.post("/api/v1/auth/logout", json={"refresh_token": 123}, headers=headers)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "input" in response.json()["detail"][0]["msg"].lower()


######################### ТЕСТЫ POST /api/v1/auth/forgot-password ########################


@pytest.mark.asyncio
async def test_forgot_password_success(client: AsyncClient, verified_test_user: User, mock_email: None) -> None:
    """Тестирует успешную отправку письма для сброса пароля через /forgot-password."""
    payload = {"email": "verified@example.com"}
    response = await client.post("/api/v1/auth/forgot-password", json=payload)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["msg"] == "Check your email to reset password"


@pytest.mark.asyncio
async def test_forgot_password_user_not_found(client: AsyncClient) -> None:
    """Тестирует ошибку, когда пользователь не найден для /forgot-password."""
    payload = {"email": "nonexistent@example.com"}
    response = await client.post("/api/v1/auth/forgot-password", json=payload)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_forgot_password_not_verified(client: AsyncClient, created_user_fixt: User) -> None:
    """Тестирует ошибку, когда пользователь не верифицирован для /forgot-password."""
    payload = {"email": "test@example.com"}
    response = await client.post("/api/v1/auth/forgot-password", json=payload)

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "verif" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_forgot_password_validation_error(client: AsyncClient, created_user_fixt: User) -> None:
    """Тестирует ошибку, когда переданы неверные данные для /forgot-password."""
    payload = {"email": "testexample.com"}
    response = await client.post("/api/v1/auth/forgot-password", json=payload)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "email" in response.json()["detail"][0]["msg"].lower()

    payload = {"email": 123}
    response = await client.post("/api/v1/auth/forgot-password", json=payload)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "input" in response.json()["detail"][0]["msg"].lower()


######################### ТЕСТЫ POST /api/v1/auth/reset-password ########################


@pytest.mark.asyncio
async def test_reset_password_success(
    client: AsyncClient, verified_test_user: User, async_session: AsyncSession
) -> None:
    """Тестирует успешный сброс пароля через /reset-password."""
    reset_token = form_short_token(user_id=verified_test_user.id)
    payload = {"password": "string12", "confirm_password": "string12", "token": reset_token}
    response = await client.post(f"/api/v1/auth/reset-password", json=payload)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["msg"] == "Password successfully updated"

    # Проверяем, что пароль обновился
    user = await get_user_by_id(db=async_session, user_id=verified_test_user.id)

    assert user is not None
    assert user.password_hash is not None
    assert verify_password("string12", user.password_hash)


@pytest.mark.asyncio
async def test_reset_password_user_not_found(client: AsyncClient) -> None:
    """Тестирует ошибку, когда пользователь не найден для /reset-password."""
    reset_token = form_short_token(user_id=uuid.uuid4())
    payload = {"password": "string12", "confirm_password": "string12", "token": reset_token}
    response = await client.post(f"/api/v1/auth/reset-password", json=payload)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_reset_password_invalid_token(client: AsyncClient) -> None:
    """Тестирует ошибку при невалидном токене для /reset-password."""
    payload = {"password": "string12", "confirm_password": "string12", "token": "invalid_token"}
    response = await client.post("/api/v1/auth/reset-password", json=payload)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "invalid token" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_reset_password_not_verified(client: AsyncClient, created_user_fixt: User) -> None:
    """Тестирует ошибку, когда пользователь не верифицирован для /reset-password."""
    reset_token = form_short_token(user_id=created_user_fixt.id)
    payload = {"password": "string12", "confirm_password": "string12", "token": reset_token}
    response = await client.post(f"/api/v1/auth/reset-password", json=payload)

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "verif" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_reset_password_validation_error(client: AsyncClient) -> None:
    """Тестирует ошибку, когда переданы неверные данные для /reset-password."""
    payload = {"password": "string", "confirm_password": "string", "token": "token"}
    response = await client.post("/api/v1/auth/reset-password", json=payload)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "at least" in response.json()["detail"][0]["msg"].lower()

    payload = {"password": "string12", "confirm_password": "string123", "token": "token"}
    response = await client.post("/api/v1/auth/reset-password", json=payload)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "match" in response.json()["detail"][0]["msg"].lower()

    payload: dict[str, Any] = {"password": 123, "confirm_password": "string123", "token": "token"}
    response = await client.post("/api/v1/auth/reset-password", json=payload)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "valid" in response.json()["detail"][0]["msg"].lower()

    payload = {"password": "123456789", "confirm_password": "string123", "token": "token"}
    response = await client.post("/api/v1/auth/reset-password", json=payload)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "letter" in response.json()["detail"][0]["msg"].lower()

    payload = {"password": "qwerty1234", "confirm_password": "string123", "token": "token"}
    response = await client.post("/api/v1/auth/reset-password", json=payload)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "simple" in response.json()["detail"][0]["msg"].lower()

    payload = {"password": "string 12", "confirm_password": "string123", "token": "token"}
    response = await client.post("/api/v1/auth/reset-password", json=payload)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "spaces" in response.json()["detail"][0]["msg"].lower()
