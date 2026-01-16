from pathlib import Path
from pydantic import computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent
ENV_PATH = BASE_DIR / ".env"

class Settings(BaseSettings):
    TITLE: str = "CinemaApp Auth Service"
    ENVIRONMENT: str = "dev"
    VERSION: str = "1.0.0"

    # Database
    DEV_DATABASE_URL: str | None = None
    TEST_DATABASE_URL: str | None = None

    # Email
    VERIFY_URL: str = "/verify-email?t="
    FORGOT_PASSWORD_URL: str = "/reset-password?t="
    DEV_FRONTEND_URL: str = "http://localhost:3000" # Порт фронтенда

    # Auth (JWT)
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_DAYS: int = 30
    VERIFICATION_TOKEN_EXPIRE_DAYS: int = 1
    REFRESH_TOKEN_EXPIRE_DAYS: int = 365

    model_config = SettingsConfigDict(
        env_file=str(ENV_PATH),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    @computed_field
    @property
    def DATABASE_URL(self) -> str:
        """Автоматически выбирает DATABASE_URL на основе ENVIRONMENT."""
        if self.ENVIRONMENT == "test":
            db_url = self.TEST_DATABASE_URL
        else:
            db_url = self.DEV_DATABASE_URL

        if not db_url:
            raise ValueError(f"No DATABASE_URL for {self.ENVIRONMENT} env")

        return db_url

    @computed_field
    @property
    def FRONTEND_URL(self) -> str:  # noqa: N802
        """Автоматически выбирает FRONTEND_URL на основе ENVIRONMENT."""
        # Для test и dev используется DEV_FRONTEND_URL
        return self.DEV_FRONTEND_URL
    
settings = Settings()