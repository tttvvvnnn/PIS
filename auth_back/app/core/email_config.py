from pathlib import Path

from fastapi_mail import ConnectionConfig, FastMail
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import SecretStr, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.config import BASE_DIR, ENV_PATH


class EmailSettings(BaseSettings):
    """
    Настройки для отправки email через fastapi-mail.

    :cvar str ENVIRONMENT: Окружение приложения (dev, test, prod).
    :cvar str DEV_MAIL_USERNAME: Имя пользователя для отправки email в dev.
    :cvar str DEV_MAIL_PASSWORD: Пароль для отправки email в dev.
    :cvar str DEV_MAIL_FROM: Email отправителя в dev.
    :cvar str DEV_MAIL_FROM_NAME: Отображаемое имя отправителя в dev.
    :cvar int DEV_MAIL_PORT: Порт SMTP-сервера в dev.
    :cvar str DEV_MAIL_SERVER: SMTP-сервер в dev.
    :cvar bool DEV_MAIL_STARTTLS: Использовать STARTTLS в dev.
    :cvar bool DEV_MAIL_SSL_TLS: Использовать SSL/TLS в dev.
    :cvar bool DEV_USE_CREDENTIALS: Использовать учетные данные в dev.
    :cvar bool DEV_VALIDATE_CERTS: Валидировать сертификаты в dev.
    :cvar bool DEV_SUPPRESS_SEND: Подавлять отправку email в dev (вывод в консоль).

    :cvar str TEMPLATES_DIR: Путь к папке с шаблонами email.
    :cvar ConnectionConfig MAIL_CONF: Конфигурация для fastapi-mail.
    """

    ENVIRONMENT: str = "dev"

    # Dev настройки
    DEV_MAIL_USERNAME: str = "test"
    DEV_MAIL_PASSWORD: str = "test"  # noqa: S105
    DEV_MAIL_FROM: str = "noreply@yourdomain.com"
    DEV_MAIL_FROM_NAME: str = "CinemaApp"
    DEV_MAIL_PORT: int = 1025
    DEV_MAIL_STARTTLS: bool = False
    DEV_MAIL_SSL_TLS: bool = False
    DEV_USE_CREDENTIALS: bool = False
    DEV_VALIDATE_CERTS: bool = False
    DEV_MAIL_SERVER: str = "mailpit"   # чтобы даже при включении отправки был корректный хост
    DEV_SUPPRESS_SEND: bool = False     # главное: подавляем отправку (не будет пытаться подключаться к SMTP)



    # Тестовые настройки
    TEST_MAIL_USERNAME: str = "test"
    TEST_MAIL_PASSWORD: str = "test"  # noqa: S105
    TEST_MAIL_FROM: str = "noreply@yourdomain.com"
    TEST_MAIL_FROM_NAME: str = "CinemaApp"
    TEST_MAIL_PORT: int = 1025
    TEST_MAIL_SERVER: str = "localhost"
    TEST_MAIL_STARTTLS: bool = False
    TEST_MAIL_SSL_TLS: bool = False
    TEST_USE_CREDENTIALS: bool = False
    TEST_VALIDATE_CERTS: bool = False
    TEST_SUPPRESS_SEND: bool = False  # Suppress sending in tests

    TEMPLATES_DIR: str = str(BASE_DIR / "app/templates")

    model_config = SettingsConfigDict(
        env_file=str(ENV_PATH),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @computed_field
    @property
    def MAIL_CONF(self) -> ConnectionConfig:  # noqa: N802
        """Автоматически создает MAIL_CONF на основе ENVIRONMENT."""
        if self.ENVIRONMENT == "test":
            config = ConnectionConfig(
                MAIL_USERNAME=self.TEST_MAIL_USERNAME,
                MAIL_PASSWORD=SecretStr(self.TEST_MAIL_PASSWORD),
                MAIL_FROM=self.TEST_MAIL_FROM,
                MAIL_FROM_NAME=self.TEST_MAIL_FROM_NAME,
                MAIL_PORT=self.TEST_MAIL_PORT,
                MAIL_SERVER=self.TEST_MAIL_SERVER,
                MAIL_STARTTLS=self.TEST_MAIL_STARTTLS,
                MAIL_SSL_TLS=self.TEST_MAIL_SSL_TLS,
                USE_CREDENTIALS=self.TEST_USE_CREDENTIALS,
                VALIDATE_CERTS=self.TEST_VALIDATE_CERTS,
                SUPPRESS_SEND=self.TEST_SUPPRESS_SEND,
                TEMPLATE_FOLDER=Path(self.TEMPLATES_DIR),
            )

        else:  # dev
            config = ConnectionConfig(
                MAIL_USERNAME=self.DEV_MAIL_USERNAME,
                MAIL_PASSWORD=SecretStr(self.DEV_MAIL_PASSWORD),
                MAIL_FROM=self.DEV_MAIL_FROM,
                MAIL_FROM_NAME=self.DEV_MAIL_FROM_NAME,
                MAIL_PORT=self.DEV_MAIL_PORT,
                MAIL_SERVER=self.DEV_MAIL_SERVER,
                MAIL_STARTTLS=self.DEV_MAIL_STARTTLS,
                MAIL_SSL_TLS=self.DEV_MAIL_SSL_TLS,
                USE_CREDENTIALS=self.DEV_USE_CREDENTIALS,
                VALIDATE_CERTS=self.DEV_VALIDATE_CERTS,
                SUPPRESS_SEND=self.DEV_SUPPRESS_SEND,
                TEMPLATE_FOLDER=Path(self.TEMPLATES_DIR),
            )
        return config

    def get_jinja_env(self) -> Environment:
        """Окружение для jinja."""
        return Environment(
            loader=FileSystemLoader(self.TEMPLATES_DIR),
            autoescape=select_autoescape(["html", "xml"]),
        )


email_settings = EmailSettings()
JINJA_ENV = email_settings.get_jinja_env()
fm = FastMail(email_settings.MAIL_CONF)