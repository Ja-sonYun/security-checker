from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from pathlib import Path

import pytest
import pytest_asyncio

from security_checker.database import Database


@pytest.fixture
def copy_lockfile(
    tmp_path: Path,
    lockfile_fixture_path: Path,
) -> Callable[[str], Path]:
    def _copy(name: str) -> Path:
        source = lockfile_fixture_path / name
        target = tmp_path / name
        target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        return target

    return _copy


@pytest_asyncio.fixture
async def db(tmp_path: Path) -> AsyncIterator[Database]:
    database = Database(db_path=tmp_path / "test.db")
    try:
        yield database
    finally:
        await database.close()
