import asyncio
from abc import abstractmethod
from collections.abc import Sequence
from typing import TypeGuard

from security_checker.checkers._base import LockFileBaseTrait
from security_checker.checkers.licenses._models import PackageLicense
from security_checker.vendors._base import VendorBase
from security_checker.vendors._models import Dependency


class LicenseCheckerTrait(VendorBase, LockFileBaseTrait):
    @abstractmethod
    async def query_license(self, package_name: str, version: str) -> str: ...

    async def query_licenses(
        self, packages: Sequence[Dependency]
    ) -> Sequence[PackageLicense]:
        tasks = [
            self.query_license(
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


def is_license_checker_trait(obj: type | None) -> TypeGuard[type[LicenseCheckerTrait]]:
    if obj is None:
        return False
    return (
        issubclass(obj, LicenseCheckerTrait)
        and issubclass(obj, VendorBase)
        and issubclass(obj, LockFileBaseTrait)
    )
