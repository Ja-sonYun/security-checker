from pathlib import Path

import aiosqlite

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class LicenseCacheSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="")

    license_cache_db_path: Path = Field(
        default=Path("license_cache.sqlite"),
        description="Path to the SQLite database for license cache.",
    )


class LicenseCache:
    """Simple SQLite backed cache for package license lookups."""

    def __init__(self, settings: LicenseCacheSettings | None = None) -> None:
        self.settings = settings or LicenseCacheSettings()
        self.db_path = self.settings.license_cache_db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: aiosqlite.Connection | None = None

    async def _create_table(self) -> None:
        assert self._conn is not None
        await self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS licenses (
                package TEXT NOT NULL,
                version TEXT NOT NULL,
                license TEXT NOT NULL,
                PRIMARY KEY (package, version)
            )
            """
        )
        await self._conn.commit()

    async def get(self, package: str, version: str) -> str | None:
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT license FROM licenses WHERE package = ? AND version = ?",
            (package, version),
        ) as cursor:
            row = await cursor.fetchone()
        return row[0] if row else None

    async def set(self, package: str, version: str, license: str) -> None:
        assert self._conn is not None
        await self._conn.execute(
            "INSERT OR REPLACE INTO licenses(package, version, license) VALUES (?, ?, ?)",
            (package, version, license),
        )
        await self._conn.commit()

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    async def __aenter__(self) -> "LicenseCache":
        self._conn = await aiosqlite.connect(self.db_path)
        await self._create_table()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()
