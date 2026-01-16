from typing import Any

from httpx import AsyncClient
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status

from app.db.crud.user import create_new_user, get_user_by_id
from app.db.model import User, UserRole
from app.schemas.user import UserRoleEnum as UserRoleEnum
from app.services.security.hash import get_password_hash, verify_password
from app.services.security.jwt import form_access_token

import uuid


@pytest_asyncio.fixture
async def create_user_fixt(async_session: AsyncSession) -> User:
    """Создает тестового пользователя в базе данных."""
    role = UserRole(name=UserRoleEnum.USER)
    async_session.add(role)
    await async_session.flush()

    user_data: dict[str, Any] = {
        "email": "test@example.com",
        "username": "test_user",
        "password_hash": get_password_hash("string12"),
        "role_name": "user",
        "role_id": role.id,
        "is_verified": False,
    }
    user = await create_new_user(user_data=user_data, db=async_session)
    await async_session.flush()
    return user


@pytest.fixture
def access_token(create_user_fixt: User) -> str:
    """Генерирует валидный access-токен для тестового пользователя."""
    return form_access_token(user_id=create_user_fixt.id, role=create_user_fixt.role_name)


@pytest.fixture
def setup_create_user_request() -> dict[str, str]:
    """Фикстура для создания запроса создания пользователя."""
    return {"email": "test@example.com", "password": "TestPassword123!", "username": "testuser"}


######################### ТЕСТЫ GET /api/v1/user/me ########################


@pytest.mark.asyncio
async def test_read_user_me_success(
    client: AsyncClient, create_user_fixt: User, access_token: str, async_session: AsyncSession
) -> None:
    """Тестирует успешное получение данных текущего пользователя через /me."""
    headers = {"Authorization": f"Bearer {access_token}"}
    response = await client.get("/api/v1/user/me", headers=headers)

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    # id в JSON всегда строка
    assert data["id"] == str(create_user_fixt.id)
    assert data["username"] == create_user_fixt.username
    assert data["email"] == create_user_fixt.email
    assert data["is_verified"] == create_user_fixt.is_verified
    assert data["role_name"] == create_user_fixt.role_name


@pytest.mark.asyncio
async def test_read_user_me_user_not_found(client: AsyncClient, async_session: AsyncSession) -> None:
    """Тестирует ошибку, когда пользователь не найден для /me."""
    # Создаем токен для несуществующего пользователя
    access_token = form_access_token(user_id=uuid.uuid4(), role="user")
    headers = {"Authorization": f"Bearer {access_token}"}
    response = await client.get("/api/v1/user/me", headers=headers)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_read_user_me_invalid_token(client: AsyncClient) -> None:
    """Тестирует ошибку при использовании невалидного токена для /me."""
    headers = {"Authorization": "Bearer invalid_token"}
    response = await client.get("/api/v1/user/me", headers=headers)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "invalid token" in response.json()["detail"].lower()


######################### ТЕСТЫ PATCH /api/v1/user/update-username ########################


@pytest.mark.asyncio
async def test_update_username_success(
    client: AsyncClient, create_user_fixt: User, access_token: str, async_session: AsyncSession
) -> None:
    """Тестирует успешное обновление имени пользователя через /update-username."""
    headers = {"Authorization": f"Bearer {access_token}"}
    payload = {"username": "new_username"}
    response = await client.patch("/api/v1/user/update-username", json=payload, headers=headers)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["msg"] == "Username updated successfully"

    # Проверяем, что имя пользователя обновилось в базе
    updated_user = await get_user_by_id(db=async_session, user_id=create_user_fixt.id)

    assert updated_user is not None
    assert updated_user.username == "new_username"


@pytest.mark.asyncio
async def test_update_username_role_normalization(
    client: AsyncClient, create_user_fixt: User, access_token: str, async_session: AsyncSession
) -> None:
    """Тестирует нормализацию role_name к нижнему регистру при обновлении имени пользователя."""
    headers = {"Authorization": f"Bearer {access_token}"}

    # Тест с role_name в верхнем регистре
    payload = {"username": "new_username", "role_name": "USER"}
    response = await client.patch("/api/v1/user/update-username", json=payload, headers=headers)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["msg"] == "Username updated successfully"

    # Проверяем, что role_name в базе данных сохранено в нижнем регистре
    updated_user = await get_user_by_id(db=async_session, user_id=create_user_fixt.id)

    assert updated_user is not None
    assert updated_user.role_name == "user"

    # Тест с role_name в смешанном регистре
    payload = {"username": "newer_username", "role_name": "UsEr"}
    response = await client.patch("/api/v1/user/update-username", json=payload, headers=headers)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["msg"] == "Username updated successfully"


@pytest.mark.asyncio
async def test_update_username_user_not_found(client: AsyncClient, async_session: AsyncSession) -> None:
    """Тестирует ошибку, когда пользователь не найден для /update-username."""
    access_token = form_access_token(user_id=uuid.uuid4(), role="user")
    headers = {"Authorization": f"Bearer {access_token}"}
    payload = {"username": "new_username"}
    response = await client.patch("/api/v1/user/update-username", json=payload, headers=headers)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_update_username_validation_error(
    client: AsyncClient,
    access_token: str,
) -> None:
    """Тестирует ошибку, когда поступили неверные данные на endpoint."""
    headers = {"Authorization": f"Bearer {access_token}"}
    payload = {"username": 123}
    response = await client.patch("/api/v1/user/update-username", json=payload, headers=headers)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "Input should be a valid string" in response.json().get("detail", "")[0]["msg"]


######################### ТЕСТЫ PATCH /api/v1/user/update-password ########################


@pytest.mark.asyncio
async def test_update_password_success(
    client: AsyncClient, create_user_fixt: User, access_token: str, async_session: AsyncSession
) -> None:
    """Тестирует успешное обновление пароля через /update-password."""
    headers = {"Authorization": f"Bearer {access_token}"}
    payload = {"old_password": "string12", "password": "new_pasword1", "confirm_password": "new_pasword1"}
    response = await client.patch("/api/v1/user/update-password", json=payload, headers=headers)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["msg"] == "Password successfully updated"

    # Проверяем, что пароль обновился в базе
    updated_user = await get_user_by_id(db=async_session, user_id=create_user_fixt.id)

    assert updated_user is not None
    assert updated_user.password_hash is not None
    assert verify_password(plain_password="new_pasword1", hashed_password=updated_user.password_hash)


@pytest.mark.asyncio
async def test_update_password_wrong_old_password(
    client: AsyncClient, create_user_fixt: User, access_token: str
) -> None:
    """Тестирует ошибку при неверном старом пароле для /update-password."""
    headers = {"Authorization": f"Bearer {access_token}"}
    payload = {"old_password": "wrong_password", "password": "new_pasword1", "confirm_password": "new_pasword1"}
    response = await client.patch("/api/v1/user/update-password", json=payload, headers=headers)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "wrong old password" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_update_password_same_passwords(client: AsyncClient, create_user_fixt: User, access_token: str) -> None:
    """Тестирует ошибку при неверном старом пароле для /update-password."""
    headers = {"Authorization": f"Bearer {access_token}"}
    payload = {"old_password": "string12", "password": "string12", "confirm_password": "string12"}
    response = await client.patch("/api/v1/user/update-password", json=payload, headers=headers)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "new password must be different from the old one" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_update_password_user_not_found(client: AsyncClient, async_session: AsyncSession) -> None:
    """Тестирует ошибку, когда пользователь не найден для /update-password."""
    access_token = form_access_token(user_id=uuid.uuid4(), role="user")
    headers = {"Authorization": f"Bearer {access_token}"}
    payload = {"old_password": "test_password", "password": "new_pasword1", "confirm_password": "new_pasword1"}
    response = await client.patch("/api/v1/user/update-password", json=payload, headers=headers)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_update_password_invalid_token(client: AsyncClient) -> None:
    """Тестирует ошибку при использовании невалидного токена для /update-password."""
    headers = {"Authorization": "Bearer invalid_token"}
    payload = {"old_password": "test_password", "password": "new_pasword1", "confirm_password": "new_pasword1"}
    response = await client.patch("/api/v1/user/update-password", json=payload, headers=headers)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "invalid token" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_update_password_validation_error(
    client: AsyncClient,
    access_token: str,
) -> None:
    """Тестирует ошибку, когда поступили неверные данные на endpoint update_password."""
    headers = {"Authorization": f"Bearer {access_token}"}
    payload = {"old_password": "test_password", "password": "qwerty", "confirm_password": "new_password1"}
    response = await client.patch("/api/v1/user/update-password", json=payload, headers=headers)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "at least" in response.json().get("detail", "")[0]["msg"]

    payload = {"old_password": "test_password", "password": "new_password", "confirm_password": "new_password"}
    response = await client.patch("/api/v1/user/update-password", json=payload, headers=headers)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "Password must contain" in response.json().get("detail", "")[0]["msg"]

    payload: dict[str, Any] = {"old_password": "test_password", "password": 1234, "confirm_password": "new_password"}
    response = await client.patch("/api/v1/user/update-password", json=payload, headers=headers)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "Input should be a valid string" in response.json().get("detail", "")[0]["msg"]
