from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import security_checker.checkers.vulnerabilities.vulnerabilities as vuln_checker
import security_checker.cli as cli
from tests.integration.conftest import (
    NODE_LOCKFILES,
    PY_LOCKFILES,
    CliContextFactory,
    DummyVulnVendorBase,
    build_cli_args,
)


class DummyPythonVendor(DummyVulnVendorBase):
    manager_name = "python"
    lockfiles = PY_LOCKFILES
    ecosystem_name = "PIP"


class DummyNodeVendor(DummyVulnVendorBase):
    manager_name = "node"
    lockfiles = NODE_LOCKFILES
    ecosystem_name = "NPM"


@pytest.fixture
def cli_vuln_context(
    tmp_path: Path,
    cli_context_factory: CliContextFactory,
) -> dict[str, Any]:
    args = build_cli_args(
        tmp_path,
        vuln_vendors=["python", "node"],
    )
    return cli_context_factory(
        args=args,
        vendors={"python": DummyPythonVendor, "node": DummyNodeVendor},
        checker_module=vuln_checker,
    )


@pytest.fixture
def cli_vuln_nested_context(
    tmp_path: Path,
    cli_context_factory: CliContextFactory,
    all_lockfile_names: tuple[str, ...],
) -> dict[str, Any]:
    args = build_cli_args(
        tmp_path,
        vuln_vendors=["python", "node"],
    )
    return cli_context_factory(
        args=args,
        vendors={"python": DummyPythonVendor, "node": DummyNodeVendor},
        checker_module=vuln_checker,
        lockfile_names=all_lockfile_names,
        nested=True,
    )


@pytest.mark.asyncio
async def test_cli_vuln_flow(cli_vuln_context: dict[str, Any]) -> None:
    await cli.cli()

    summary = cli_vuln_context.get("summary", "")
    details = cli_vuln_context.get("details", [])
    root_headers = [line for line in details if line.startswith("## `")]
    vuln_lines = [line for line in details if "CVE-0000-0000" in line]

    assert "Found 1" in summary
    assert len(root_headers) == 1
    assert len(vuln_lines) == 1
    assert "LOW" in vuln_lines[0]


@pytest.mark.asyncio
async def test_cli_vuln_nested_lockfiles(
    cli_vuln_nested_context: dict[str, Any],
    all_lockfile_names: tuple[str, ...],
) -> None:
    await cli.cli()

    summary = cli_vuln_nested_context.get("summary", "")
    details = cli_vuln_nested_context.get("details", [])

    root_headers = [line for line in details if line.startswith("## `")]
    vuln_lines = [line for line in details if "CVE-0000-0000" in line]

    assert summary == (
        f"Found {len(all_lockfile_names)} vulnerabilities across "
        f"{len(all_lockfile_names)} dependency roots."
    )
    assert len(root_headers) == len(all_lockfile_names)
    assert all("/apps/app_" in header for header in root_headers)
    assert len(vuln_lines) == len(all_lockfile_names)
