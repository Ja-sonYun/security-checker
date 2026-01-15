from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import pytest
import security_checker.cli as cli
import security_checker.outputs._base as output_base
from _pytest.monkeypatch import MonkeyPatch
from security_checker.checkers._models import CheckResultInterface
from security_checker.checkers.licenses._vendor_trait import LicenseCheckerTrait
from security_checker.checkers.vulnerabilities._models import (
    VulnerabilityInfo,
    VulnerablePackage,
)
from security_checker.checkers.vulnerabilities._vendor_trait import (
    VulnerabilityCheckerTrait,
)
from security_checker.outputs.stdout import StdoutOutput
from security_checker.vendors._base import VendorBase
from security_checker.vendors._models import Dependencies, Dependency

PY_LOCKFILES: set[str] = {
    "requirements.txt",
    "requirements.lock",
    "requirements-dev.lock",
    "poetry.lock",
    "uv.lock",
}
NODE_LOCKFILES: set[str] = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
}


@dataclass
class DummyArgs:
    path: Path
    vendor: list[str]
    verbose: bool
    db: Path | None
    ignore_packages: list[str]


@dataclass
class DummyTopArgs:
    license: DummyArgs | None
    vuln: DummyArgs | None


class CliCommonSetup(Protocol):
    def __call__(
        self,
        args: Any,
        lockfile_names: Sequence[str] | None = None,
        nested: bool = False,
    ) -> dict[str, Any]: ...


class CliContextFactory(Protocol):
    def __call__(
        self,
        *,
        args: DummyTopArgs,
        vendors: dict[str, type[VendorBase]],
        checker_module: Any,
        lockfile_names: Sequence[str] | None = None,
        nested: bool = False,
    ) -> dict[str, Any]: ...


def build_cli_args(
    path: Path,
    *,
    license_vendors: Sequence[str] | None = None,
    vuln_vendors: Sequence[str] | None = None,
) -> DummyTopArgs:
    license_args = None
    if license_vendors is not None:
        license_args = DummyArgs(
            path=path,
            vendor=list(license_vendors),
            verbose=False,
            db=None,
            ignore_packages=[],
        )

    vuln_args = None
    if vuln_vendors is not None:
        vuln_args = DummyArgs(
            path=path,
            vendor=list(vuln_vendors),
            verbose=False,
            db=None,
            ignore_packages=[],
        )

    return DummyTopArgs(license=license_args, vuln=vuln_args)


def _write_lockfile_fixtures(
    lockfile_fixture_path: Path,
    tmp_path: Path,
    lockfile_names: Sequence[str],
    nested: bool,
) -> list[Path]:
    created: list[Path] = []
    if nested:
        base_dir = tmp_path / "apps"
        for idx, name in enumerate(lockfile_names):
            dest_dir = base_dir / f"app_{idx}" / "nested"
            dest_dir.mkdir(parents=True, exist_ok=True)
            source = lockfile_fixture_path / name
            dest = dest_dir / name
            dest.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
            created.append(dest)
        return created

    dest_dir = tmp_path
    dest_dir.mkdir(parents=True, exist_ok=True)
    for name in lockfile_names:
        source = lockfile_fixture_path / name
        dest = dest_dir / name
        dest.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        created.append(dest)
    return created


@pytest.fixture
def cli_common_setup(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
    lockfile_fixture_path: Path,
) -> CliCommonSetup:
    def _setup(
        args: Any,
        lockfile_names: Sequence[str] | None = None,
        nested: bool = False,
    ) -> dict[str, Any]:
        monkeypatch.setattr(
            cli.CliApp,
            "run",
            lambda *_args, **_kwargs: args,
        )

        monkeypatch.setattr(
            output_base,
            "get_git_info",
            lambda _path: {
                "branch": "main",
                "commit": "deadbeef",
                "remote": "git@github.com:dummy/dummy.git",
                "user": "dummy",
                "repo": "dummy",
            },
        )

        captured: dict[str, Any] = {}

        async def _fake_write_output(
            self: StdoutOutput,
            result: CheckResultInterface,
        ) -> bool:
            captured["summary"] = result.get_summary()
            captured["details"] = result.get_details()
            return True

        monkeypatch.setattr(cli.StdoutOutput, "write_output", _fake_write_output)

        names = lockfile_names or ("requirements.txt",)
        _write_lockfile_fixtures(lockfile_fixture_path, tmp_path, names, nested)

        return captured

    return _setup


@pytest.fixture
def cli_context_factory(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
    cli_common_setup: CliCommonSetup,
) -> CliContextFactory:
    def _factory(
        *,
        args: DummyTopArgs,
        vendors: dict[str, type[VendorBase]],
        checker_module: Any,
        lockfile_names: Sequence[str] | None = None,
        nested: bool = False,
    ) -> dict[str, Any]:
        monkeypatch.setattr(
            cli,
            "supported_vendors",
            vendors,
        )
        monkeypatch.setattr(
            checker_module,
            "find_git_root",
            lambda _path: tmp_path,
        )
        return cli_common_setup(
            args,
            lockfile_names=lockfile_names,
            nested=nested,
        )

    return _factory


@pytest.fixture
def all_lockfile_names(lockfile_fixture_path: Path) -> tuple[str, ...]:
    return tuple(f.name for f in lockfile_fixture_path.iterdir() if f.is_file())


class DummyLicenseVendorBase(LicenseCheckerTrait):
    manager_name = "dummy"
    lockfiles: set[str] = set()
    ecosystem_name = "PIP"

    @property
    def name(self) -> str:
        return f"Dummy {self.manager_name} Vendor"

    @property
    def dependency_manager_name(self) -> str:
        return self.manager_name

    @property
    def supported_lockfiles(self) -> set[str]:
        return self.lockfiles

    @property
    def get_ecosystem_name(self) -> str:
        return self.ecosystem_name

    def get_lockfile_dependencies(self, file_path: Path) -> Dependencies:
        return Dependencies(
            file_path=file_path,
            dependencies=[Dependency(name="requests", version="2.32.0")],
        )

    async def query_license(self, package_name: str, version: str) -> str:
        return "MIT"


class DummyVulnVendorBase(VulnerabilityCheckerTrait):
    manager_name = "dummy"
    lockfiles: set[str] = set()
    ecosystem_name = "PIP"

    @property
    def name(self) -> str:
        return f"Dummy {self.manager_name} Vendor"

    @property
    def dependency_manager_name(self) -> str:
        return self.manager_name

    @property
    def supported_lockfiles(self) -> set[str]:
        return self.lockfiles

    @property
    def get_ecosystem_name(self) -> str:
        return self.ecosystem_name

    def get_lockfile_dependencies(self, file_path: Path) -> Dependencies:
        return Dependencies(
            file_path=file_path,
            dependencies=[Dependency(name="requests", version="2.32.0")],
        )

    def is_in_version_range(self, version: str, version_range: str) -> bool:
        return True

    async def query_vulnerabilities(
        self, package_name: str, version: str
    ) -> VulnerablePackage:
        return VulnerablePackage(
            name=package_name,
            version=version,
            vulnerabilities=[
                VulnerabilityInfo(
                    vulnerability_id="CVE-0000-0000",
                    severity="LOW",
                    description="Test",
                )
            ],
        )
