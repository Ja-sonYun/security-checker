from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import security_checker.checkers.licenses.licenses as license_checker
import security_checker.cli as cli
from tests.integration.conftest import (
    NODE_LOCKFILES,
    PY_LOCKFILES,
    CliContextFactory,
    DummyLicenseVendorBase,
    build_cli_args,
)


class DummyPythonVendor(DummyLicenseVendorBase):
    manager_name = "python"
    lockfiles = PY_LOCKFILES
    ecosystem_name = "PIP"


class DummyNodeVendor(DummyLicenseVendorBase):
    manager_name = "node"
    lockfiles = NODE_LOCKFILES
    ecosystem_name = "NPM"


@pytest.fixture
def cli_license_context(
    tmp_path: Path,
    cli_context_factory: CliContextFactory,
) -> dict[str, Any]:
    args = build_cli_args(
        tmp_path,
        license_vendors=["python", "node"],
    )
    return cli_context_factory(
        args=args,
        vendors={"python": DummyPythonVendor, "node": DummyNodeVendor},
        checker_module=license_checker,
    )


@pytest.fixture
def cli_license_nested_context(
    tmp_path: Path,
    cli_context_factory: CliContextFactory,
    all_lockfile_names: tuple[str, ...],
) -> dict[str, Any]:
    args = build_cli_args(
        tmp_path,
        license_vendors=["python", "node"],
    )
    return cli_context_factory(
        args=args,
        vendors={"python": DummyPythonVendor, "node": DummyNodeVendor},
        checker_module=license_checker,
        lockfile_names=all_lockfile_names,
        nested=True,
    )


@pytest.mark.asyncio
async def test_cli_license_flow(cli_license_context: dict[str, Any]) -> None:
    await cli.cli()

    summary = cli_license_context.get("summary", "")
    details = cli_license_context.get("details", [])
    root_headers = [line for line in details if line.startswith("## `")]
    requests_lines = [line for line in details if "`requests`" in line]

    assert "Found 1" in summary
    assert len(root_headers) == 1
    assert len(requests_lines) == 1
    assert "MIT" in requests_lines[0]


@pytest.mark.asyncio
async def test_cli_license_nested_lockfiles(
    cli_license_nested_context: dict[str, Any],
    all_lockfile_names: tuple[str, ...],
) -> None:
    await cli.cli()

    summary = cli_license_nested_context.get("summary", "")
    details = cli_license_nested_context.get("details", [])

    root_headers = [line for line in details if line.startswith("## `")]
    requests_lines = [
        line for line in details if "`requests`" in line and "MIT" in line
    ]

    assert summary == (
        f"Found {len(all_lockfile_names)} dependencies with license information."
    )
    assert len(root_headers) == len(all_lockfile_names)
    assert all("/apps/app_" in header for header in root_headers)
    assert len(requests_lines) == len(all_lockfile_names)
