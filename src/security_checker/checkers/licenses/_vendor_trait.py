import asyncio
from abc import abstractmethod
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from typing import TypeGuard

from security_checker.checkers._base import LockFileBaseTrait
from security_checker.checkers.licenses._cache import LicenseCache
from security_checker.checkers.licenses._models import PackageLicense
from security_checker.console import console
from security_checker.vendors._base import VendorBase
from security_checker.vendors._models import Dependency
from sqlmodel import select


class LicenseCheckerTrait(VendorBase, LockFileBaseTrait):
    CACHE_TTL_DAYS = 100

    @abstractmethod
    async def query_license(self, package_name: str, version: str) -> str: ...

    async def _get_cached_license(
        self, session, package_name: str, version: str
    ) -> LicenseCache | None:
        """Retrieve cached license entry from database."""
        rows = await session.exec(
            select(LicenseCache).where(
                LicenseCache.ecosystem == self.get_ecosystem_name,
                LicenseCache.name == package_name,
                LicenseCache.version == version,
            )
        )
        return rows.first()

    async def _query_license(
        self,
        package_name: str,
        version: str,
    ) -> str:
        if self.db is None:
            console.verbose(
                f"Querying license for {package_name}@{version} directly (no cache)"
            )
            return await self.query_license(package_name, version)

        # Check cache first
        async with self.db.session() as session:
            console.verbose(f"Checking cache for {package_name}@{version}")
            cached = await self._get_cached_license(session, package_name, version)
            now = datetime.now(timezone.utc)
            ttl_cutoff = now - timedelta(days=self.CACHE_TTL_DAYS)

            if cached is not None and cached.updated_at is not None:
                cached_updated = cached.updated_at
                if cached_updated.tzinfo is None:
                    cached_updated = cached_updated.replace(tzinfo=timezone.utc)
                else:
                    cached_updated = cached_updated.astimezone(timezone.utc)
                if cached_updated >= ttl_cutoff:
                    console.verbose(f"Cache hit for {package_name}@{version}")
                    cached.updated_at = now
                    await session.commit()
                    return cached.license

        # Cache miss or stale, query the license
        console.verbose(
            f"Cache miss for {package_name}@{version}, querying registry..."
        )
        license_info = await self.query_license(package_name, version)

        async with self.db.session() as session:
            cached = await self._get_cached_license(session, package_name, version)
            now = datetime.now(timezone.utc)

            if cached is None:
                console.verbose(f"Inserting cache entry for {package_name}@{version}")
                session.add(
                    LicenseCache(
                        ecosystem=self.get_ecosystem_name,
                        name=package_name,
                        version=version,
                        license=license_info,
                        updated_at=now,
                    )
                )
            else:
                console.verbose(f"Updating cache entry for {package_name}@{version}")
                cached.license = license_info
                cached.updated_at = now

            await session.commit()

        return license_info

    async def query_licenses(
        self, packages: Sequence[Dependency]
    ) -> Sequence[PackageLicense]:
        tasks = [
            self._query_license(
                package.name,
                package.version,
            )
            for package in packages
        ]
        licenses = await asyncio.gather(*tasks)

        return [
            PackageLicense(
                name=package.name,
                version=package.version,
                license=license_info,
            )
            for package, license_info in zip(packages, licenses)
        ]


def is_license_checker_trait(
    obj: type[VendorBase] | None,
) -> TypeGuard[type[LicenseCheckerTrait]]:
    if obj is None:
        return False
    return issubclass(obj, LicenseCheckerTrait) and issubclass(obj, LockFileBaseTrait)
