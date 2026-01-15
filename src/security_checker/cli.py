import asyncio
import sys
import traceback
from pathlib import Path
from typing import Callable, Literal, cast

from pydantic import AliasChoices, Field, ValidationError, field_validator
from pydantic_settings import (
    BaseSettings,
    CliApp,
    CliImplicitFlag,
    CliPositionalArg,
    CliSubCommand,
    SettingsError,
)

from security_checker.checkers.licenses._known_licenses import detect_license_score
from security_checker.checkers.licenses._vendor_trait import (
    LicenseCheckerTrait,
    is_license_checker_trait,
)
from security_checker.checkers.licenses.licenses import LicenseChecker
from security_checker.checkers.licenses._models import LicenseCheckResult
from security_checker.checkers.vulnerabilities._vendor_trait import (
    VulnerabilityCheckerTrait,
    is_vulnerability_checker_trait,
)
from security_checker.checkers.vulnerabilities.vulnerabilities import (
    VulnerabilityChecker,
)
from security_checker.console import console
from security_checker.database import Database
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


def _init_vendors[T: VendorBase](
    vendor_names: list[Vendors],
    trait_type: type[T],
    is_trait_fn: Callable[[type[VendorBase] | None], bool],
) -> list[T]:
    """Initialize vendor instances from vendor names."""
    vendors: list[T] = []
    for vendor_name in vendor_names:
        vendor_class = supported_vendors.get(vendor_name)
        if vendor_class is None:
            raise ValueError(f"Vendor {vendor_name} is not supported.")
        if not is_trait_fn(vendor_class):
            raise ValueError(
                f"Vendor {vendor_name} does not implement {trait_type.__name__}."
            )
        vendors.append(cast(type[T], vendor_class)())
    return vendors


def _validate_path(path: Path) -> None:
    """Validate that the given path exists."""
    if not path.exists():
        raise ValueError(f"Path {path} does not exist.")


def _filter_ignored_packages(
    result: LicenseCheckResult,
    ignore_packages: list[str],
) -> LicenseCheckResult:
    normalized = {name.strip().lower() for name in ignore_packages if name.strip()}
    if not normalized:
        return result

    filtered_dependencies = {}
    for root, packages in result.dependencies.items():
        filtered_packages = [
            package
            for package in packages
            if package.name.strip().lower() not in normalized
        ]
        if filtered_packages:
            filtered_dependencies[root] = filtered_packages

    return result.model_copy(update={"dependencies": filtered_dependencies})


def _has_strong_copyleft(result: LicenseCheckResult) -> bool:
    for packages in result.dependencies.values():
        for package in packages:
            if detect_license_score(package.license) == 3:
                return True
    return False


class BaseCheckerSetting(BaseSettings):
    path: CliPositionalArg[Path] = Field(
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
    db: Path | None = Field(
        default=None,
        description="Path to the caching database file.",
    )


class LicenseCheckerSettings(BaseCheckerSetting):
    ignore_packages: list[str] = Field(
        default_factory=list,
        description="Comma-separated package names to ignore.",
        validation_alias=AliasChoices("ignore-packages", "ignore_packages"),
    )

    @field_validator("ignore_packages", mode="before")
    @classmethod
    def _split_ignore_packages(cls, value: object) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        if isinstance(value, list):
            items: list[str] = []
            for item in value:
                if isinstance(item, str):
                    items.extend(
                        [part.strip() for part in item.split(",") if part.strip()]
                    )
                else:
                    items.append(str(item))
            return items
        return [str(value)]


class VulnerabilityCheckerSettings(BaseCheckerSetting): ...


class Arguments(BaseSettings, cli_exit_on_error=True):
    license: CliSubCommand[LicenseCheckerSettings]
    vuln: CliSubCommand[VulnerabilityCheckerSettings]


async def _handle_license(args: LicenseCheckerSettings) -> None:
    vendors = _init_vendors(args.vendor, LicenseCheckerTrait, is_license_checker_trait)
    console.verbose(f"Using vendors: {args.vendor}")
    output = StdoutOutput(args.path)
    license_checker = LicenseChecker()
    _validate_path(args.path)

    console.verbose(f"Running license check on path: {args.path}")
    result = await license_checker.run(
        project_path=args.path,
        vendors=vendors,
    )

    if args.ignore_packages:
        console.verbose(f"Ignoring packages: {', '.join(args.ignore_packages)}")
        result = _filter_ignored_packages(result, args.ignore_packages)

    console.verbose("Writing output for license results.")
    await output.write_output(result=result)

    if _has_strong_copyleft(result):
        console.error("Strong copyleft license detected.")
        sys.exit(1)


async def _handle_vulnerability(args: VulnerabilityCheckerSettings) -> None:
    vendors = _init_vendors(
        args.vendor, VulnerabilityCheckerTrait, is_vulnerability_checker_trait
    )
    console.verbose(f"Using vendors: {args.vendor}")
    output = StdoutOutput(args.path)
    vulnerability_checker = VulnerabilityChecker()
    _validate_path(args.path)

    console.verbose(f"Running vulnerability check on path: {args.path}")
    result = await vulnerability_checker.run(
        project_path=args.path,
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
            if args.license.db:
                VendorBase.db = Database(
                    db_path=args.license.db,
                    echo=args.license.verbose,
                )
            if args.license.verbose:
                console.enable_verbose()
            await _handle_license(args.license)
        elif args.vuln:
            if args.vuln.db:
                raise NotImplementedError(
                    "Database caching for vulnerability checking is not implemented yet."
                )
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

    finally:
        if VendorBase.db:
            try:
                await VendorBase.db.close()
            except Exception:
                console.verbose("Failed to close the database connection.")
        VendorBase.db = None


def main() -> None:
    asyncio.run(cli())
