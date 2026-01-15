from __future__ import annotations

from pathlib import Path

import pytest

import security_checker.checkers.vulnerabilities.vulnerabilities as vuln_checker
from security_checker.checkers.vulnerabilities._models import (
    DependencyRoot,
    VulnerabilityCheckResult,
    VulnerabilityInfo,
    VulnerablePackage,
)
from security_checker.checkers.vulnerabilities._vendor_trait import (
    VulnerabilityCheckerTrait,
)
from security_checker.vendors._models import Dependencies, Dependency


class DummyVendor(VulnerabilityCheckerTrait):
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
        return "NPM"

    def get_lockfile_dependencies(self, file_path: Path) -> Dependencies:
        return Dependencies(
            file_path=file_path,
            dependencies=[Dependency(name="leftpad", version="1.0.0")],
        )

    def is_in_version_range(self, version: str, version_range: str) -> bool:
        return True

    async def query_vulnerabilities(self, package_name: str, version: str):
        return VulnerablePackage(
            name=package_name,
            version=version,
            vulnerabilities=[
                VulnerabilityInfo(
                    vulnerability_id="CVE-1234-5678",
                    severity="LOW",
                    description="Test",
                )
            ],
        )


@pytest.mark.asyncio
async def test_vulnerability_checker_collects_dependencies(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(vuln_checker, "find_git_root", lambda _p: tmp_path)

    checker = vuln_checker.VulnerabilityChecker()
    vendor = DummyVendor("npm", {"package-lock.json"})

    result = await checker.run(tmp_path, [vendor])

    assert isinstance(result, VulnerabilityCheckResult)
    assert len(result.dependencies) == 1
    root = next(iter(result.dependencies))
    assert isinstance(root, DependencyRoot)
    assert result.dependencies[root][0].vulnerabilities[0].severity == "LOW"


@pytest.mark.asyncio
async def test_vulnerability_checker_duplicate_root_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(vuln_checker, "find_git_root", lambda _p: tmp_path)

    checker = vuln_checker.VulnerabilityChecker()
    vendor_a = DummyVendor("same", {"package-lock.json"})
    vendor_b = DummyVendor("same", {"package-lock.json"})

    with pytest.raises(ValueError):
        await checker.run(tmp_path, [vendor_a, vendor_b])
