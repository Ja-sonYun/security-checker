from collections.abc import Sequence
from pathlib import Path

from security_checker.checkers._base import CheckerBase
from security_checker.checkers.vulnerabilities._models import (
    VulnerabilityCheckResult,
    VulnerablePackage,
)
from security_checker.checkers.vulnerabilities._settings import (
    VulnerabilityCheckerSettings,
)
from security_checker.checkers.vulnerabilities._vendor_trait import (
    VulnerabilityCheckerTrait,
)
from security_checker.console import console
from security_checker.utils.git import find_git_root
from security_checker.vendors._models import DependencyRoot


class VulnerabilityChecker(
    CheckerBase[
        VulnerabilityCheckerTrait,
        VulnerabilityCheckResult,
    ]
):
    def __init__(self, settings: VulnerabilityCheckerSettings | None = None) -> None:
        super().__init__()
        self.settings = settings or VulnerabilityCheckerSettings()
        console.verbose(
            f"{self.__class__.__name__} settings: "
            f"{self.settings.model_dump_json(indent=2)}"
        )

    @property
    def name(self) -> str:
        return "Vulnerability Checker"

    async def run(
        self,
        project_path: Path,
        vendors: Sequence[VulnerabilityCheckerTrait],
    ) -> VulnerabilityCheckResult:
        all_paths = self._travel_project(project_path)
        git_root = find_git_root(project_path)

        if not git_root:
            raise ValueError("No git root found for the project.")

        results: dict[DependencyRoot, Sequence[VulnerablePackage]] = {}
        for vendor in vendors:
            paths = [
                path for path in all_paths if path.name in vendor.supported_lockfiles
            ]
            vendor_results = await self._use_vendor(paths, vendor)
            for root, vulnerabilities in vendor_results.dependencies.items():
                if root in results:
                    raise ValueError(
                        f"Duplicate dependency root found: {root}. "
                        "Ensure that different vendors do not return the same root."
                    )
                results[root] = vulnerabilities

        return VulnerabilityCheckResult(
            dependencies=results,
            settings=self.settings,
        )

    async def _use_vendor(
        self,
        paths: list[Path],
        vendor: VulnerabilityCheckerTrait,
    ) -> VulnerabilityCheckResult:
        console.verbose(
            f"Using vendor: {vendor.dependency_manager_name} for paths: {paths}"
        )
        vulnerability_infos: dict[DependencyRoot, Sequence[VulnerablePackage]] = {}
        for path in paths:
            if not path.is_file():
                continue
            package_root = DependencyRoot(
                root=path.parent,
                package_manager=vendor.dependency_manager_name,
            )
            try:
                vulnerability_infos[package_root] = await self._parse_package(
                    path, vendor
                )
            except ValueError as e:
                console.error(f"Error parsing {path}: {e}")

        return VulnerabilityCheckResult(
            dependencies=vulnerability_infos,
            settings=self.settings,
        )

    async def _parse_package(
        self,
        lockfile: Path,
        vendor: VulnerabilityCheckerTrait,
    ) -> Sequence[VulnerablePackage]:
        console.verbose(f"Parsing lockfile: {lockfile} with vendor: {vendor.name}")
        if lockfile.name not in vendor.supported_lockfiles:
            raise ValueError(f"Unsupported lockfile type: {lockfile.suffix}")

        dependencies = vendor.get_lockfile_dependencies(lockfile)
        console.verbose(
            f"Found {len(dependencies.dependencies)} dependencies in {lockfile.name}"
        )
        console.verbose(
            f"Scanning dependencies for {len(dependencies.dependencies)} vulnerabilities..."
        )
        return await vendor.scan_dependencies_for_vulnerabilities(
            dependencies.dependencies
        )
