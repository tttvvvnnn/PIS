from pathlib import Path
import sys

# Добавляем корневую директорию проекта в sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from collections.abc import AsyncGenerator

from httpx import ASGITransport, AsyncClient
import pytest_asyncio
from sqlalchemy import NullPool, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.db.model import Base
from app.db.session import get_session
from app.main import app

@pytest_asyncio.fixture(scope="session")
async def db_engine() -> AsyncGenerator[AsyncEngine, None]:  # noqa: ANN001
    """Создает движок БД и таблицы один раз за всю тестовую сессию."""

    engine = create_async_engine(settings.TEST_DATABASE_URL, poolclass=NullPool, echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    await engine.dispose()


@pytest_asyncio.fixture
async def db_provider(db_engine: AsyncEngine) -> AsyncGenerator[tuple[AsyncSession, AsyncEngine], None]:
    """
    Предоставляет асинхронную сессию и движок базы данных для тестов.

    :return: Кортеж из асинхронной сессии и движка базы данных.
    :rtype: AsyncGenerator[tuple[AsyncSession, AsyncEngine], None]
    """
    async with db_engine.connect() as connection:
        session_factory = async_sessionmaker(
            bind=connection,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )

        async with session_factory() as session:
            await session.begin()

            yield session, db_engine

            await session.rollback()


@pytest_asyncio.fixture
async def async_session(db_provider: tuple[AsyncSession, AsyncEngine]) -> AsyncGenerator[AsyncSession, None]:
    """
    Предоставляет асинхронную сессию базы данных для тестов.

    :param db_provider: Фикстура, предоставляющая сессию и движок.
    :return: Асинхронная сессия базы данных.
    :rtype: AsyncGenerator[AsyncSession, None]
    """
    session: AsyncSession = db_provider[0]
    yield session


@pytest_asyncio.fixture
async def client(async_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """
    Создаёт асинхронный тестовый клиент FastAPI с переопределённой зависимостью сессии.

    :param async_session: Асинхронная сессия SQLAlchemy.
    :returns: Асинхронный клиент FastAPI.
    :rtype: AsyncGenerator[AsyncClient, None]
    """

    async def override_get_session() -> AsyncGenerator[AsyncSession, None]:
        yield async_session

    # Сохраняем исходное состояние
    original_overrides = app.dependency_overrides.copy()

    # Добавляем только свое переопределение
    app.dependency_overrides[get_session] = override_get_session

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=True) as client:
        yield client

    # Восстанавливаем исходное состояние
    app.dependency_overrides = original_overrides
