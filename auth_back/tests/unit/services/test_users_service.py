from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.model import User
from app.exceptions.auth import WrongPasswordException
from app.exceptions.user import UserNotFoundException, UserUpdateException
from app.schemas.user import UpdatePasswordRequest, UserResponse
from app.services.user import get_user_data_service, update_password_service, update_username_service
from app.services.security.hash import get_password_hash


# Фикстура для мока AsyncSession
@pytest.fixture
def mock_db() -> AsyncSession:
    """Мокает асинхронную сессию базы данных."""
    return AsyncMock(spec=AsyncSession)


@pytest.fixture
def db_user() -> User:
    """Мокает объект пользователя из БД."""
    return User(
        id=uuid4(),
        email="test@gmail.com",
        username="test_user",
        role_name="user",
        password_hash=get_password_hash("OldPass123!"),
        is_verified=True,
    )


######################### ТЕСТЫ get_user_data_service ########################


@pytest.mark.asyncio
async def test_get_user_data_service_success(mock_db: AsyncSession, db_user: User, mocker: MagicMock) -> None:
    """Тестирует успешное получение данных пользователя."""
    user_id = db_user.id
    mocker.patch("app.services.user.get_user_by_id", return_value=db_user)

    result: UserResponse = await get_user_data_service(user_id=user_id, db=mock_db)

    assert isinstance(result, UserResponse)
    assert result.username == "test_user"


@pytest.mark.asyncio
async def test_get_user_data_service_user_not_found(mock_db: AsyncSession, mocker: MagicMock) -> None:
    """Тестирует обработку ошибки, когда пользователь не найден."""
    mocker.patch("app.services.user.get_user_by_id", return_value=None)
    with pytest.raises(UserNotFoundException) as exc:
        await get_user_data_service(user_id=uuid4(), db=mock_db)

    assert exc.value.status_code == 404
    assert "not found" in exc.value.detail.lower()


######################### ТЕСТЫ update_password_service ########################


@pytest.mark.asyncio
async def test_update_password_service_user_not_found(mock_db: AsyncSession, mocker: MagicMock) -> None:
    """Тестирует обработку ошибки, когда пользователь не найден при обновлении пароля."""
    user_id: int = 1
    passwords: UpdatePasswordRequest = UpdatePasswordRequest(
        old_password="old_pass", password="new_pass12", confirm_password="new_pass12"
    )

    mocker.patch("app.services.user.get_user_by_id", return_value=None)
    with pytest.raises(UserNotFoundException) as exc:
        await update_password_service(user_id=user_id, passwords=passwords, db=mock_db)

    assert exc.value.status_code == 404
    assert "not found" in exc.value.detail.lower()


@pytest.mark.asyncio
async def test_update_password_service_wrong_password(mock_db: AsyncSession, db_user: User, mocker: MagicMock) -> None:
    """Тестирует обработку ошибки при неверном старом пароле."""
    user_id: int = 1
    passwords: UpdatePasswordRequest = UpdatePasswordRequest(
        old_password="wrong_pass", password="new_pass12", confirm_password="new_pass12"
    )

    mocker.patch("app.services.user.get_user_by_id", return_value=db_user)
    mocker.patch("app.services.user.verify_password", return_value=False)
    with pytest.raises(WrongPasswordException) as exc:
        await update_password_service(user_id=user_id, passwords=passwords, db=mock_db)

    assert exc.value.status_code == 401  # Предполагаемый код для неверного пароля
    assert "wrong old password" in exc.value.detail.lower()


@pytest.mark.asyncio
async def test_update_password_service_no_password_set(mock_db: AsyncSession, db_user: User, mocker: MagicMock) -> None:
    """Тестирует ошибку, если у пользователя не установлен пароль (password_hash is None)."""
    user_id: int = 1
    passwords: UpdatePasswordRequest = UpdatePasswordRequest(
        old_password="old_pass",
        password="new_pass12",
        confirm_password="new_pass12",
    )
    db_user.password_hash = None

    mocker.patch("app.services.user.get_user_by_id", return_value=db_user)

    with pytest.raises(WrongPasswordException) as exc:
        await update_password_service(user_id=user_id, passwords=passwords, db=mock_db)

    assert exc.value.status_code == 401
    assert exc.value.detail == "Password not set"


@pytest.mark.asyncio
async def test_update_password_service_integrity_error(mock_db: AsyncSession, db_user: User, mocker: MagicMock) -> None:
    """Тестирует обработку IntegrityError при обновлении пароля."""
    user_id: int = 1
    passwords: UpdatePasswordRequest = UpdatePasswordRequest(
        old_password="old_pass",
        password="new_pass12",
        confirm_password="new_pass12",
    )

    mocker.patch("app.services.user.get_user_by_id", return_value=db_user)
    # 1-й вызов (старый пароль): True
    # 2-й вызов (проверка на тот же пароль): False
    mocker.patch("app.services.user.verify_password", side_effect=[True, False])
    mocker.patch("app.services.user.get_password_hash", return_value="new_hashed")

    # Мокаем функцию обновления БД, чтобы она вызвала ошибку
    mocker.patch(
        "app.services.user.update_user_password",
        side_effect=IntegrityError(
            "statement",
            {},
            Exception("mock error"),
        ),
    )

    with pytest.raises(UserUpdateException):
        await update_password_service(user_id=user_id, passwords=passwords, db=mock_db)


######################### ТЕСТЫ update_username_service ########################


@pytest.mark.asyncio
async def test_update_username_service_success(mock_db: AsyncSession, db_user: User, mocker: MagicMock) -> None:
    """Тестирует успешное обновление имени пользователя."""
    user_id: int = 1
    new_username: str = "new_user"

    mocker.patch("app.services.user.get_user_by_id", return_value=db_user)
    result = await update_username_service(user_id=user_id, username=new_username, db=mock_db)

    assert result.msg == "Username updated successfully"
    assert db_user.username == new_username


@pytest.mark.asyncio
async def test_update_username_service_user_not_found(mock_db: AsyncSession, mocker: MagicMock) -> None:
    """Тестирует обработку ошибки, когда пользователь не найден при обновлении имени."""
    user_id: int = 1
    new_username: str = "new_user"

    mocker.patch("app.services.user.get_user_by_id", return_value=None)
    with pytest.raises(UserNotFoundException) as exc:
        await update_username_service(user_id=user_id, username=new_username, db=mock_db)

    assert exc.value.status_code == 404
    assert "not found" in exc.value.detail.lower()


@pytest.mark.asyncio
async def test_update_username_service_integrity_error(mock_db: AsyncSession, db_user: User, mocker: MagicMock) -> None:
    """Тестирует обработку IntegrityError при обновлении имени пользователя."""
    user_id: int = 1
    new_username: str = "new_user"

    mocker.patch("app.services.user.get_user_by_id", return_value=db_user)

    # Мокаем первую функцию обновления (user), чтобы она вызвала ошибку
    mocker.patch(
        "app.services.user.update_user_username",
        side_effect=IntegrityError(
            "statement",
            {},
            Exception("mock error"),
        ),
    )

    with pytest.raises(UserUpdateException):
        await update_username_service(user_id=user_id, username=new_username, db=mock_db)
