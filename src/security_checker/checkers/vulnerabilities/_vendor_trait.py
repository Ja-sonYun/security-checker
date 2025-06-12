import asyncio
from abc import abstractmethod
from collections.abc import Sequence
from typing import TypeGuard

from security_checker.checkers._base import LockFileBaseTrait
from security_checker.checkers.vulnerabilities._models import VulnerablePackage
from security_checker.vendors._base import VendorBase
from security_checker.vendors._models import Dependency


class VulnerabilityCheckerTrait(VendorBase, LockFileBaseTrait):
    @property
    @abstractmethod
    def get_echosystem_name(self) -> str: ...

    @abstractmethod
    async def query_vulnerabilities(
        self,
        package_name: str,
        version: str,
    ) -> VulnerablePackage: ...

    async def scan_dependencies_for_vulnerabilities(
        self, packages: Sequence[Dependency]
    ) -> Sequence[VulnerablePackage]:
        tasks = [
            self.query_vulnerabilities(
                package.name,
                package.version,
            )
            for package in packages
        ]
        vulnerability_results = await asyncio.gather(*tasks)

        return [
            VulnerablePackage(
                name=package.name,
                version=package.version,
                vulnerabilities=vulnerability_info.vulnerabilities,
            )
            for package, vulnerability_info in zip(packages, vulnerability_results)
        ]


def is_vuulnerability_checker_trait(
    obj: type | None,
) -> TypeGuard[type[VulnerabilityCheckerTrait]]:
    if obj is None:
        return False
    return (
        issubclass(obj, VulnerabilityCheckerTrait)
        and issubclass(obj, VendorBase)
        and issubclass(obj, LockFileBaseTrait)
    )
