from collections.abc import Sequence
from pathlib import Path

from security_checker.checkers._base import CheckerBase
from security_checker.checkers.licenses._models import (
    DependencyRoot,
    LicenseCheckResult,
    PackageLicense,
)
from security_checker.checkers.licenses._settings import LicenseCheckerSettings
from security_checker.checkers.licenses._vendor_trait import LicenseCheckerTrait
from security_checker.console import console
from security_checker.utils.git import find_git_root


class LicenseChecker(CheckerBase[LicenseCheckerTrait, LicenseCheckResult]):
    def __init__(self, settings: LicenseCheckerSettings | None = None) -> None:
        super().__init__()
        self.settings = settings or LicenseCheckerSettings()
        console.verbose(
            f"{self.__class__.__name__} settings: "
            f"{self.settings.model_dump_json(indent=2)}"
        )

    @property
    def name(self) -> str:
        return "License Checker"

    async def run(
        self,
        project_path: Path,
        vendors: Sequence[LicenseCheckerTrait],
    ) -> LicenseCheckResult:
        all_paths = self._travel_project(project_path)
        git_root = find_git_root(project_path)

        if not git_root:
            raise ValueError("No git root found for the project.")

        results: dict[DependencyRoot, Sequence[PackageLicense]] = {}
        for vendor in vendors:
            paths = [
                path for path in all_paths if path.name in vendor.supported_lockfiles
            ]
            vendor_results = await self._use_vendor(paths, vendor)
            for root, licenses in vendor_results.dependencies.items():
                if root in results:
                    raise ValueError(
                        f"Duplicate dependency root found: {root}. "
                        "Ensure that different vendors do not return the same root."
                    )
                results[root] = licenses

        return LicenseCheckResult(dependencies=results, settings=self.settings)

    async def _use_vendor(
        self,
        paths: list[Path],
        vendor: LicenseCheckerTrait,
    ) -> LicenseCheckResult:
        console.verbose(
            f"Using vendor: {vendor.dependency_manager_name} for paths: {paths}"
        )
        license_infos: dict[DependencyRoot, Sequence[PackageLicense]] = {}
        for path in paths:
            if not path.is_file():
                continue
            package_root = DependencyRoot(
                root=path.parent,
                package_manager=vendor.dependency_manager_name,
            )
            try:
                license_infos[package_root] = await self._parse_package(path, vendor)
            except ValueError as e:
                console.error(f"Error parsing {path}: {e}")

        return LicenseCheckResult(dependencies=license_infos, settings=self.settings)

    async def _parse_package(
        self,
        lockfile: Path,
        vendor: LicenseCheckerTrait,
    ) -> Sequence[PackageLicense]:
        console.verbose(f"Parsing lockfile: {lockfile} with vendor: {vendor.name}")
        if lockfile.name not in vendor.supported_lockfiles:
            raise ValueError(f"Unsupported lockfile type: {lockfile.suffix}")

        dependencies = vendor.get_lockfile_dependencies(lockfile)
        console.verbose(
            f"Found {len(dependencies.dependencies)} dependencies in {lockfile.name}"
        )
        console.verbose(
            f"Querying licenses for {len(dependencies.dependencies)} dependencies..."
        )
        return await vendor.query_licenses(dependencies.dependencies)
