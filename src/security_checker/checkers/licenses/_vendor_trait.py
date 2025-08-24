import asyncio
from abc import abstractmethod
from collections.abc import Sequence
from typing import TypeGuard

from security_checker.checkers._base import LockFileBaseTrait
from security_checker.checkers.licenses._cache import LicenseCache
from security_checker.checkers.licenses._models import PackageLicense
from security_checker.vendors._base import VendorBase
from security_checker.vendors._models import Dependency


class LicenseCheckerTrait(VendorBase, LockFileBaseTrait):
    @abstractmethod
    async def query_license(self, package_name: str, version: str) -> str: ...

    async def query_licenses(
        self, packages: Sequence[Dependency]
    ) -> Sequence[PackageLicense]:
        async with LicenseCache() as cache:
            results: list[PackageLicense | None] = [None] * len(packages)
            to_fetch: list[Dependency] = []
            to_fetch_idx: list[int] = []

            for idx, package in enumerate(packages):
                cached = await cache.get(package.name, package.version)
                if cached is not None:
                    results[idx] = PackageLicense(
                        name=package.name,
                        version=package.version,
                        license=cached,
                    )
                else:
                    to_fetch.append(package)
                    to_fetch_idx.append(idx)

            if to_fetch:
                tasks = [
                    self.query_license(pkg.name, pkg.version) for pkg in to_fetch
                ]
                licenses = await asyncio.gather(*tasks)
                for pkg, license_info, idx in zip(to_fetch, licenses, to_fetch_idx):
                    await cache.set(pkg.name, pkg.version, license_info)
                    results[idx] = PackageLicense(
                        name=pkg.name,
                        version=pkg.version,
                        license=license_info,
                    )

            return [res for res in results if res is not None]


def is_license_checker_trait(obj: type | None) -> TypeGuard[type[LicenseCheckerTrait]]:
    if obj is None:
        return False
    return (
        issubclass(obj, LicenseCheckerTrait)
        and issubclass(obj, VendorBase)
        and issubclass(obj, LockFileBaseTrait)
    )
