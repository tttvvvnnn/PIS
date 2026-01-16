from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from pydantic_settings import SettingsConfigDict
import pytest

from app.core.email_config import EmailSettings


class MockEmailSettings(EmailSettings):
    """Временная фикстура для создания тестового класса EmailSettings с заданными параметрами."""

    model_config = SettingsConfigDict(
        env_file=None,
        case_sensitive=False,
        extra="ignore",
    )


@pytest.mark.anyio
async def test_email_settings_init_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Тестирует успешную инициализацию EmailSettings с корректными параметрами.

    Проверяет, что MAIL_CONF и FRONTEND_URL устанавливаются на основе ENVIRONMENT.
    """
    # Устанавливаем тестовые переменные окружения через monkeypatch
    monkeypatch.setenv("DEV_MAIL_USERNAME", "dev_user")
    monkeypatch.setenv("DEV_MAIL_PASSWORD", "dev_pass")
    monkeypatch.setenv("DEV_MAIL_FROM", "dev@yourdomain.com")
    monkeypatch.setenv("DEV_MAIL_SERVER", "smtp.dev.com")

    monkeypatch.setenv("TEST_MAIL_USERNAME", "test_user")
    monkeypatch.setenv("TEST_MAIL_PASSWORD", "test_pass")
    monkeypatch.setenv("TEST_MAIL_FROM", "test@yourdomain.com")
    monkeypatch.setenv("TEST_MAIL_SERVER", "smtp.test.com")

    # Тест для ENVIRONMENT=dev
    settings = MockEmailSettings(ENVIRONMENT="dev")
    assert settings.MAIL_CONF.MAIL_USERNAME == "dev_user"
    assert settings.MAIL_CONF.MAIL_PASSWORD._secret_value == "dev_pass"
    assert settings.MAIL_CONF.MAIL_FROM == "dev@yourdomain.com"
    assert settings.MAIL_CONF.MAIL_SERVER == "smtp.dev.com"

    # Тест для ENVIRONMENT=test
    settings = MockEmailSettings(ENVIRONMENT="test")
    assert settings.MAIL_CONF.MAIL_USERNAME == "test_user"
    assert settings.MAIL_CONF.MAIL_PASSWORD._secret_value == "test_pass"
    assert settings.MAIL_CONF.MAIL_FROM == "test@yourdomain.com"
    assert settings.MAIL_CONF.MAIL_SERVER == "smtp.test.com"
    assert settings.MAIL_CONF.SUPPRESS_SEND == 1  # type: ignore[reportUnknownMemberType]


@pytest.mark.anyio
async def test_get_jinja_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Тестирует метод get_jinja_env.

    Проверяет, что возвращается корректный объект Environment с правильным loader и autoescape -
        нужна, чтобы убедиться, что jinja2.Environment правильно настроен для автоматического экранирования
        HTML и XML шаблонов, предотвращая XSS-уязвимости.
    """
    # Установим минимально необходимые переменные, если они нужны для __init__
    monkeypatch.setenv("DEV_FRONTEND_URL", "http://dev.localhost:8000")

    settings = MockEmailSettings(ENVIRONMENT="dev")
    jinja_env = settings.get_jinja_env()

    assert isinstance(jinja_env, Environment)
    assert isinstance(jinja_env.loader, FileSystemLoader)
    assert str(jinja_env.loader.searchpath[0]) == str(Path(settings.TEMPLATES_DIR))
    assert jinja_env.autoescape("template.html") is True  # type: ignore[operator]
    assert jinja_env.autoescape("template.xml") is True  # type: ignore[operator]
    assert jinja_env.autoescape("template.txt") is False  # type: ignore[operator]


@pytest.mark.anyio
async def test_email_settings_template_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Тестирует корректность установки TEMPLATES_DIR.

    Проверяет, что TEMPLATES_DIR соответствует ожидаемому пути.
    """
    # Установим минимально необходимые переменные
    monkeypatch.setenv("DEV_MAIL_USERNAME", "dev_user")
    monkeypatch.setenv("DEV_MAIL_PASSWORD", "dev_pass")
    monkeypatch.setenv("DEV_MAIL_FROM", "dev@yourdomain.com")

    settings = MockEmailSettings(ENVIRONMENT="dev")

    expected_suffix = Path("app/templates")
    assert Path(settings.TEMPLATES_DIR).as_posix().endswith(expected_suffix.as_posix())
    assert str(settings.MAIL_CONF.TEMPLATE_FOLDER) == settings.TEMPLATES_DIR
