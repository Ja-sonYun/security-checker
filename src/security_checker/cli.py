import asyncio
import sys
import traceback
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field, ValidationError
from pydantic_settings import (
    BaseSettings,
    CliApp,
    CliImplicitFlag,
    CliPositionalArg,
    CliSubCommand,
    SettingsError,
)

from security_checker.checkers.licenses._vendor_trait import (
    LicenseCheckerTrait,
    is_license_checker_trait,
)
from security_checker.checkers.licenses.licenses import LicenseChecker
from security_checker.checkers.vulnerabilities._vendor_trait import (
    VulnerabilityCheckerTrait,
    is_vuulnerability_checker_trait,
)
from security_checker.checkers.vulnerabilities.vulnerabilities import (
    VulnerabilityChecker,
)
from security_checker.console import console
from security_checker.outputs.stdout import StdoutOutput
from security_checker.vendors._base import VendorBase
from security_checker.vendors.npm import NpmVendor
from security_checker.vendors.pnpm import PnpmVendor
from security_checker.vendors.poetry import PoetryVendor
from security_checker.vendors.requirements_txt import RequirementsTxtVendor
from security_checker.vendors.rye import RyeVendor
from security_checker.vendors.uv import UvVendor

Vendors = Literal[
    "poetry",
    "pnpm",
    "npm",
    "requirements_txt",
    "rye",
    "uv",
]
supported_vendors: dict[Vendors, type[VendorBase]] = {
    "poetry": PoetryVendor,
    "pnpm": PnpmVendor,
    "npm": NpmVendor,
    "requirements_txt": RequirementsTxtVendor,
    "rye": RyeVendor,
    "uv": UvVendor,
}


class BaseCheckerSetting(BaseSettings):
    path: CliPositionalArg[str] = Field(
        description="Path to the project directory to check.",
    )
    vendor: list[Vendors] = Field(
        default=["poetry", "pnpm", "npm", "requirements_txt", "rye", "uv"],
        description="List of vendors to use for license checking.",
        validation_alias=AliasChoices("v", "vendor"),
    )
    verbose: CliImplicitFlag[bool] = Field(
        description="Enable verbose output.",
        default=False,
    )


class LicenseCheckerSettings(BaseCheckerSetting): ...


class VulnerabilityCheckerSettings(BaseCheckerSetting): ...


class Arguments(BaseSettings, cli_exit_on_error=True):
    license: CliSubCommand[LicenseCheckerSettings]
    vuln: CliSubCommand[VulnerabilityCheckerSettings]


async def _handle_license(args: LicenseCheckerSettings) -> None:
    path = Path(args.path)
    vendors: list[LicenseCheckerTrait] = []
    for vendor_name in args.vendor:
        vendor_class = supported_vendors.get(vendor_name)
        if not is_license_checker_trait(vendor_class):
            raise ValueError(
                f"Vendor {vendor_name} does not implement LicenseCheckerTrait."
            )
        vendors.append(vendor_class())
    console.verbose(f"Using vendors: {args.vendor}")
    output = StdoutOutput(path)

    license_checker = LicenseChecker()

    if not path.exists():
        raise ValueError(f"Path {path} does not exist.")

    console.verbose(f"Running license check on path: {path}")
    result = await license_checker.run(
        project_path=path,
        vendors=vendors,
    )

    console.verbose("Writing output for license results.")
    await output.write_output(result=result)


async def _handle_vulnerability(args: VulnerabilityCheckerSettings) -> None:
    path = Path(args.path)
    vendors: list[VulnerabilityCheckerTrait] = []
    for vendor_name in args.vendor:
        vendor_class = supported_vendors.get(vendor_name)
        if not is_vuulnerability_checker_trait(vendor_class):
            raise ValueError(
                f"Vendor {vendor_name} does not implement VulnerabilityCheckerTrait."
            )
        vendors.append(vendor_class())
    console.verbose(f"Using vendors: {args.vendor}")
    output = StdoutOutput(path)

    vulnerability_checker = VulnerabilityChecker()

    if not path.exists():
        raise ValueError(f"Path {path} does not exist.")

    console.verbose(f"Running vulnerability check on path: {path}")
    result = await vulnerability_checker.run(
        project_path=path,
        vendors=vendors,
    )

    console.verbose("Writing output for vulnerability results.")
    await output.write_output(result=result)


async def cli() -> None:
    try:
        args = CliApp.run(Arguments)
    except (SettingsError, ValidationError) as e:
        console.error(f"Error parsing arguments: {e}")
        return

    try:
        if args.license:
            if args.license.verbose:
                console.enable_verbose()
            await _handle_license(args.license)
        elif args.vuln:
            if args.vuln.verbose:
                console.enable_verbose()
            await _handle_vulnerability(args.vuln)
        else:
            CliApp.run(Arguments, cli_args=["--help"])

    except Exception as e:
        traceback_text = traceback.format_exc()
        console.verbose(f"Traceback: {traceback_text}")
        console.error(f"An error occurred: {e}")
        sys.exit(1)


def main() -> None:
    asyncio.run(cli())
