from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlmodel import select

from security_checker.checkers.licenses._cache import LicenseCache
from security_checker.checkers.licenses._vendor_trait import LicenseCheckerTrait
from security_checker.database import Database


@dataclass
class QueryCounter:
    count: int = 0


class DummyVendor(LicenseCheckerTrait):
    def __init__(self, counter: QueryCounter) -> None:
        super().__init__()
        self.counter = counter

    @property
    def name(self) -> str:
        return "Dummy"

    @property
    def dependency_manager_name(self) -> str:
        return "dummy"

    @property
    def supported_lockfiles(self) -> set[str]:
        return {"requirements.txt"}

    @property
    def get_ecosystem_name(self) -> str:
        return "PIP"

    def get_lockfile_dependencies(self, file_path: Path):
        raise AssertionError("Not used in cache tests")

    async def query_license(self, package_name: str, version: str) -> str:
        self.counter.count += 1
        return "MIT"


@pytest.fixture
def vendor_db(db: Database) -> Iterator[None]:
    DummyVendor.db = db
    try:
        yield
    finally:
        DummyVendor.db = None


@pytest.mark.asyncio
async def test_cache_hit_uses_cached_value(
    db: Database,
    vendor_db: None,
) -> None:
    counter = QueryCounter()
    vendor = DummyVendor(counter)

    now = datetime.now(timezone.utc)
    async with db.session() as session:
        session.add(
            LicenseCache(
                ecosystem="PIP",
                name="requests",
                version="2.32.0",
                license="BSD",
                updated_at=now,
            )
        )
        await session.commit()

    result = await vendor._query_license("requests", "2.32.0")

    assert result == "BSD"
    assert counter.count == 0


@pytest.mark.asyncio
async def test_cache_miss_inserts_value(
    db: Database,
    vendor_db: None,
) -> None:
    counter = QueryCounter()
    vendor = DummyVendor(counter)

    result = await vendor._query_license("requests", "2.32.0")

    assert result == "MIT"
    assert counter.count == 1

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


@pytest.mark.asyncio
async def test_cache_stale_refreshes(
    db: Database,
    vendor_db: None,
) -> None:
    counter = QueryCounter()
    vendor = DummyVendor(counter)

    stale_time = datetime.now(timezone.utc) - timedelta(days=200)
    async with db.session() as session:
        session.add(
            LicenseCache(
                ecosystem="PIP",
                name="requests",
                version="2.32.0",
                license="BSD",
                updated_at=stale_time,
            )
        )
        await session.commit()

    result = await vendor._query_license("requests", "2.32.0")

    assert result == "MIT"
    assert counter.count == 1

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
    assert cached.updated_at is not None
    cached_time = cached.updated_at
    if cached_time.tzinfo is None:
        cached_time = cached_time.replace(tzinfo=timezone.utc)
    assert cached_time > stale_time
