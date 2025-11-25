"""SQLite-based cache for license information."""

import aiosqlite
import asyncio
from pathlib import Path
from typing import Optional
from datetime import datetime


class SqliteCache:
    """SQLite cache for storing package license information."""

    def __init__(self, db_path: Optional[Path] = None):
        """Initialize the SQLite cache.

        Args:
            db_path: Path to the SQLite database file. If None, uses default location.
        """
        if db_path is None:
            cache_dir = Path.home() / ".cache" / "security-checker"
            cache_dir.mkdir(parents=True, exist_ok=True)
            db_path = cache_dir / "licenses.db"

        self.db_path = db_path
        self._init_lock = asyncio.Lock()
        self._initialized = False

    async def _ensure_initialized(self):
        """Ensure the database is initialized."""
        if self._initialized:
            return

        async with self._init_lock:
            if self._initialized:
                return

            async with aiosqlite.connect(str(self.db_path)) as db:
                await db.execute("""
                    CREATE TABLE IF NOT EXISTS license_cache (
                        ecosystem TEXT NOT NULL,
                        package_name TEXT NOT NULL,
                        version TEXT NOT NULL,
                        license TEXT NOT NULL,
                        cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (ecosystem, package_name, version)
                    )
                """)
                await db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_package_lookup
                    ON license_cache (ecosystem, package_name, version)
                """)
                await db.commit()

            self._initialized = True

    async def get_license(
        self,
        ecosystem: str,
        package_name: str,
        version: str
    ) -> Optional[str]:
        """Get cached license for a package.

        Args:
            ecosystem: Package ecosystem (e.g., 'pypi', 'npm')
            package_name: Name of the package
            version: Version of the package

        Returns:
            Cached license string or None if not found
        """
        await self._ensure_initialized()

        async with aiosqlite.connect(str(self.db_path)) as db:
            async with db.execute(
                """
                SELECT license FROM license_cache
                WHERE ecosystem = ? AND package_name = ? AND version = ?
                """,
                (ecosystem, package_name, version)
            ) as cursor:
                row = await cursor.fetchone()
                return row[0] if row else None

    async def set_license(
        self,
        ecosystem: str,
        package_name: str,
        version: str,
        license: str
    ):
        """Cache license for a package.

        Args:
            ecosystem: Package ecosystem (e.g., 'pypi', 'npm')
            package_name: Name of the package
            version: Version of the package
            license: License string to cache
        """
        await self._ensure_initialized()

        async with aiosqlite.connect(str(self.db_path)) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO license_cache
                (ecosystem, package_name, version, license, cached_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (ecosystem, package_name, version, license, datetime.utcnow().isoformat())
            )
            await db.commit()

    async def get_cache_stats(self) -> dict:
        """Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        await self._ensure_initialized()

        async with aiosqlite.connect(str(self.db_path)) as db:
            async with db.execute(
                "SELECT COUNT(*), COUNT(DISTINCT package_name) FROM license_cache"
            ) as cursor:
                row = await cursor.fetchone()
                total_entries, unique_packages = row if row else (0, 0)

            async with db.execute(
                "SELECT ecosystem, COUNT(*) FROM license_cache GROUP BY ecosystem"
            ) as cursor:
                ecosystem_counts = {row[0]: row[1] async for row in cursor}

        return {
            "total_entries": total_entries,
            "unique_packages": unique_packages,
            "by_ecosystem": ecosystem_counts,
            "db_path": str(self.db_path)
        }

    async def clear_cache(self):
        """Clear all cached data."""
        await self._ensure_initialized()

        async with aiosqlite.connect(str(self.db_path)) as db:
            await db.execute("DELETE FROM license_cache")
            await db.commit()
