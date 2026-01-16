from pydantic import ValidationError
from pydantic_settings import SettingsConfigDict
import pytest

from app.core.config import Settings


class MockSettings(Settings):
    """Временная фикстура для создания тестового класса Settings с заданными параметрами."""

    model_config = SettingsConfigDict(
        env_file=None,  # Отключаем загрузку .env для тестов
        case_sensitive=False,
        extra="ignore",
    )


@pytest.mark.anyio
def test_settings_init_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Тестирует успешную инициализацию Settings с корректными параметрами.

    Использует monkeypatch для установки переменных *только* для этого теста.
    Проверяет, что DATABASE_URL устанавливается на основе ENVIRONMENT.
    """
    monkeypatch.setenv("DEV_DATABASE_URL", "postgresqlasyncpg://user:pass@localhost:5432/dev")
    monkeypatch.setenv("TEST_DATABASE_URL", "postgresqlasyncpg://user:pass@localhost:5432/test")
    monkeypatch.setenv("SECRET_KEY", "test_secret")
    monkeypatch.setenv("ALGORITHM", "HS256")

    monkeypatch.setenv("DEV_FRONTEND_URL", "http://dev.local")
    monkeypatch.setenv("VERIFY_URL", "/verify-path")
    monkeypatch.setenv("FORGOT_PASSWORD_URL", "/forgot-path")

    # Тест для ENVIRONMENT=test
    settings = MockSettings(
        ENVIRONMENT="test",
        # Нужно анализатору
        REDIS_URL="redis://localhost:5555/8",
        SECRET_KEY="test_secret",
        ALGORITHM="HS256",
    )
    assert settings.DATABASE_URL == "postgresqlasyncpg://user:pass@localhost:5432/test"
    assert settings.FRONTEND_URL == "http://dev.local"  # Проверяем, что test использует dev URL
    assert settings.VERIFY_URL == "/verify-path"

    # Тест для ENVIRONMENT=dev
    settings = MockSettings(
        ENVIRONMENT="dev",
        SECRET_KEY="test_secret",
        ALGORITHM="HS256",
    )
    assert settings.DATABASE_URL == "postgresqlasyncpg://user:pass@localhost:5432/dev"
    assert settings.FRONTEND_URL == "http://dev.local"
    assert settings.FORGOT_PASSWORD_URL == "/forgot-path"


@pytest.mark.anyio
def test_settings_init_missing_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """Тестирует выброс ValidationError при отсутствии нужного DATABASE_URL."""
    # Удаляем переменные БД, которые могли существовать
    monkeypatch.delenv("DEV_DATABASE_URL", raising=False)
    monkeypatch.delenv("TEST_DATABASE_URL", raising=False)

    monkeypatch.setenv("SECRET_KEY", "test_secret")
    monkeypatch.setenv("ALGORITHM", "HS256")

    _env = "test"
    settings = MockSettings(
        ENVIRONMENT=_env,
        SECRET_KEY="test_secret",
        ALGORITHM="HS256",
    )
    with pytest.raises(ValueError, match=f"No DATABASE_URL for {_env} env"):
        # Принудительно вычисляем свойство, pydantic ленивый и без доступа к переменной не выбрасывает ошибку
        _ = settings.DATABASE_URL

    _env = "dev"
    settings = MockSettings(
        ENVIRONMENT=_env,
        SECRET_KEY="test_secret",
        ALGORITHM="HS256",
    )
    with pytest.raises(ValueError, match=f"No DATABASE_URL for {_env} env"):
        _ = settings.DATABASE_URL


@pytest.mark.anyio
def test_settings_init_missing_required_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    """Тестирует выброс ValidationError, если ОБЯЗАТЕЛЬНЫЕ поля отсутствуют."""
    # Устанавливаем URL БД
    monkeypatch.setenv("DEV_DATABASE_URL", "postgresqlasyncpg://user:pass@localhost:5432/dev")

    # Удаляем обязательные поля
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.delenv("ALGORITHM", raising=False)

    # Ожидаем ошибку валидации Pydantic
    with pytest.raises(ValidationError) as exc_info:
        MockSettings(ENVIRONMENT="dev")  # pyright: ignore[reportCallIssue]

    # Проверяем, что Pydantic жалуется на отсутствие полей
    errors = exc_info.value.errors()
    error_fields = {e["loc"][0] for e in errors}

    assert "SECRET_KEY" in error_fields
    assert "ALGORITHM" in error_fields
