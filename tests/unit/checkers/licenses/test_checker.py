from __future__ import annotations

from pathlib import Path

import pytest
import security_checker.checkers.licenses.licenses as license_checker
from security_checker.checkers.licenses._models import (
    DependencyRoot,
    LicenseCheckResult,
)
from security_checker.checkers.licenses._vendor_trait import LicenseCheckerTrait
from security_checker.vendors._models import Dependencies, Dependency


class DummyVendor(LicenseCheckerTrait):
    def __init__(self, name: str, lockfiles: set[str]) -> None:
        super().__init__()
        self._name = name
        self._lockfiles = lockfiles

    @property
    def name(self) -> str:
        return self._name

    @property
    def dependency_manager_name(self) -> str:
        return self._name

    @property
    def supported_lockfiles(self) -> set[str]:
        return self._lockfiles

    @property
    def get_ecosystem_name(self) -> str:
        return "PIP"

    def get_lockfile_dependencies(self, file_path: Path) -> Dependencies:
        return Dependencies(
            file_path=file_path,
            dependencies=[Dependency(name="requests", version="2.32.0")],
        )

    async def query_license(self, package_name: str, version: str) -> str:
        return "MIT"


@pytest.mark.asyncio
async def test_license_checker_collects_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")

    monkeypatch.setattr(license_checker, "find_git_root", lambda _p: tmp_path)

    checker = license_checker.LicenseChecker()
    vendor = DummyVendor("python", {"requirements.txt"})

    result = await checker.run(tmp_path, [vendor])

    assert isinstance(result, LicenseCheckResult)
    assert len(result.dependencies) == 1
    root = next(iter(result.dependencies))
    assert isinstance(root, DependencyRoot)
    assert result.dependencies[root][0].license == "MIT"


@pytest.mark.asyncio
async def test_license_checker_duplicate_root_raises(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")

    monkeypatch.setattr(license_checker, "find_git_root", lambda _p: tmp_path)

    checker = license_checker.LicenseChecker()
    vendor_a = DummyVendor("same", {"requirements.txt"})
    vendor_b = DummyVendor("same", {"requirements.txt"})

    with pytest.raises(ValueError):
        await checker.run(tmp_path, [vendor_a, vendor_b])
