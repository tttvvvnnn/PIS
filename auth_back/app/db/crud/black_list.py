from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.model import BlackListToken


async def get_black_token_by_jti(db: AsyncSession, jti: str) -> BlackListToken | None:
    query = select(BlackListToken).where(BlackListToken.jti == jti)
    return (await db.execute(query)).scalars().first()


async def add_token_to_blacklist(db: AsyncSession, jti: str, expires_at: datetime) -> None:
    db.add(BlackListToken(jti=jti, expires_at=expires_at))


# ===========================
# Backward-compatible API for tests
# ===========================

async def get_black_token_by_id(token_id: str, db: AsyncSession) -> BlackListToken | None:
    """
    Тесты ожидают поиск по id (UUID в строке).
    """
    try:
        token_uuid = UUID(token_id)
    except ValueError:
        return None

    query = select(BlackListToken).where(BlackListToken.id == token_uuid)
    return (await db.execute(query)).scalars().first()


async def add_token_to_black(jti, expire: datetime, db: AsyncSession) -> None:
    """
    Тесты вызывают add_token_to_black(jti_uuid, expire_dt, session)
    и ожидают, что id == jti_uuid.
    """
    # jti в тестах приходит как UUID
    db.add(BlackListToken(id=jti, jti=str(jti), expires_at=expire))
