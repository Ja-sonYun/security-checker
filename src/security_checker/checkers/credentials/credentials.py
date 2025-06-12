from collections.abc import Sequence
from pathlib import Path

from security_checker.checkers._base import CheckerBase
from security_checker.checkers.credentials._models import (
    CredentialAlert,
    CredentialCheckResult,
)
from security_checker.checkers.credentials._vendor_trait import CredentialCheckerTrait
from security_checker.utils.git import find_git_root


class CredentialChecker(CheckerBase[CredentialCheckerTrait, CredentialCheckResult]):
    """
    IMPORTANT: Not tested yet, do not use this.
    """

    @property
    def name(self) -> str:
        return "Credential Checker"

    async def run(
        self,
        project_path: Path,
        vendors: Sequence[CredentialCheckerTrait],
    ) -> CredentialCheckResult:
        all_paths = self._travel_project(project_path)
        git_root = find_git_root(project_path)

        if not git_root:
            raise ValueError("No git root found for the project.")

        all_credentials: list[CredentialAlert] = []
        for vendor in vendors:
            paths = [
                p
                for p in all_paths
                if p.is_file() and p.suffix in vendor.supported_file_extensions
            ]
            vendor_credentials = await self._use_vendor(paths, vendor)
            all_credentials.extend(vendor_credentials.credentials)

        return CredentialCheckResult(credentials=all_credentials)

    async def _use_vendor(
        self,
        paths: list[Path],
        vendor: CredentialCheckerTrait,
    ) -> CredentialCheckResult:
        all_credentials: list[CredentialAlert] = []

        for path in paths:
            if not path.is_file():
                continue
            try:
                file_credentials = vendor.scan_file_for_credentials(path)
                validated_credentials = await vendor.validate_credentials(
                    file_credentials
                )
                all_credentials.extend(validated_credentials)
            except ValueError as e:
                print(f"Error scanning {path}: {e}")

        return CredentialCheckResult(credentials=all_credentials)
