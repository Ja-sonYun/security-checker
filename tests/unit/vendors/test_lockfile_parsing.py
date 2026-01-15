"""Unified lockfile parsing tests for all vendor implementations."""

from collections.abc import Callable
from pathlib import Path

import pytest

from security_checker.vendors.npm import NpmVendor
from security_checker.vendors.pnpm import PnpmVendor
from security_checker.vendors.poetry import PoetryVendor
from security_checker.vendors.requirements_txt import RequirementsTxtVendor
from security_checker.vendors.rye import RyeVendor
from security_checker.vendors.uv import UvVendor
from security_checker.vendors.yarn import YarnVendor


@pytest.mark.parametrize(
    "vendor_cls,lockfile,expected_deps",
    [
        (
            NpmVendor,
            "package-lock.json",
            [("lodash", "4.17.21"), ("@types/node", "20.12.0")],
        ),
        (YarnVendor, "yarn.lock", [("lodash", "4.17.21"), ("@types/node", "20.12.0")]),
        (
            PnpmVendor,
            "pnpm-lock.yaml",
            [("lodash", "4.17.21"), ("@types/node", "20.12.0")],
        ),
        (
            PoetryVendor,
            "poetry.lock",
            [("requests", "2.32.0"), ("certifi", "2024.7.4")],
        ),
        (UvVendor, "uv.lock", [("requests", "2.32.0"), ("certifi", "2024.7.4")]),
    ],
    ids=["npm", "yarn", "pnpm", "poetry", "uv"],
)
def test_lockfile_parsing(
    copy_lockfile: Callable[[str], Path],
    vendor_cls: type,
    lockfile: str,
    expected_deps: list[tuple[str, str]],
) -> None:
    target = copy_lockfile(lockfile)
    vendor = vendor_cls()
    deps = vendor.get_lockfile_dependencies(target).dependencies
    found = {(dep.name, dep.version) for dep in deps}

    for expected in expected_deps:
        assert expected in found


def test_rye_requirements_lock_parsing(
    copy_lockfile: Callable[[str], Path],
) -> None:
    target = copy_lockfile("requirements.lock")
    vendor = RyeVendor()
    deps = vendor.get_lockfile_dependencies(target).dependencies

    found = {(dep.name, dep.version) for dep in deps}
    assert ("requests", "2.32.0") in found
    assert ("ruff", "0.5.5") in found


def test_rye_requirements_dev_lock_parsing(
    copy_lockfile: Callable[[str], Path],
) -> None:
    target = copy_lockfile("requirements-dev.lock")
    vendor = RyeVendor()
    deps = vendor.get_lockfile_dependencies(target).dependencies

    found = {(dep.name, dep.version) for dep in deps}
    assert ("pytest", "8.2.0") in found
    assert ("pytest-asyncio", "0.23.7") in found


def test_requirements_txt_parsing(
    copy_lockfile: Callable[[str], Path],
) -> None:
    target = copy_lockfile("requirements.txt")
    vendor = RequirementsTxtVendor()
    deps = vendor.get_lockfile_dependencies(target).dependencies

    found = {dep.name: dep.version for dep in deps}
    assert found.get("requests") == "2.32.0"
    assert found.get("urllib3") == "2.2.0"
    assert found.get("idna") == "3.7"
    assert found.get("charset-normalizer") == "3.3.2"
    assert found.get("pyyaml") == ""
