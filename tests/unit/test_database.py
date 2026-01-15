from __future__ import annotations

import pytest
from security_checker.checkers.licenses._cache import LicenseCache
from security_checker.database import Database
from sqlmodel import select


@pytest.mark.asyncio
async def test_database_session(db: Database) -> None:
    async with db.session() as session:
        session.add(
            LicenseCache(
                ecosystem="PIP",
                name="requests",
                version="2.32.0",
                license="MIT",
            )
        )
        await session.commit()

    async with db.session() as session:
        rows = await session.exec(
            select(LicenseCache).where(
                LicenseCache.name == "requests",
                LicenseCache.version == "2.32.0",
            )
        )
        cached = rows.first()

    assert cached is not None
    assert cached.license == "MIT"
