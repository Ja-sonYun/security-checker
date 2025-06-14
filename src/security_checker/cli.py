import asyncio
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field
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
from security_checker.notifiers._base import NotifierBase
from security_checker.notifiers.slack import SlackNotifier
from security_checker.notifiers.stdout import StdoutNotifier
from security_checker.vendors._base import VendorBase
from security_checker.vendors.npm import NpmVendor
from security_checker.vendors.pnpm import PnpmVendor
from security_checker.vendors.poetry import PoetryVendor
from security_checker.vendors.requirements_txt import RequirementsTxtVendor
from security_checker.vendors.rye import RyeVendor

Vendors = Literal[
    "poetry",
    "pnpm",
    "npm",
    "requirements_txt",
    "rye",
]
supported_vendors: dict[Vendors, type[VendorBase]] = {
    "poetry": PoetryVendor,
    "pnpm": PnpmVendor,
    "npm": NpmVendor,
    "requirements_txt": RequirementsTxtVendor,
    "rye": RyeVendor,
}

Notifiers = Literal[
    "stdout",
    "slack",
]
supported_notifiers: dict[Notifiers, type[NotifierBase]] = {
    "stdout": StdoutNotifier,
    "slack": SlackNotifier,
}


class BaseCheckerSetting(BaseSettings):
    path: CliPositionalArg[str] = Field(
        description="Path to the project directory to check.",
    )
    vendor: list[Vendors] = Field(
        default=["poetry", "pnpm", "npm", "requirements_txt", "rye"],
        description="List of vendors to use for license checking.",
        validation_alias=AliasChoices("v", "vendor"),
    )
    notify: list[Notifiers] = Field(
        default=["stdout"],
        description="List of notifiers to use for reporting results.",
        validation_alias=AliasChoices("n", "notify"),
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
    vendors: list[LicenseCheckerTrait] = []
    for vendor_name in args.vendor:
        vendor_class = supported_vendors.get(vendor_name)
        if not is_license_checker_trait(vendor_class):
            raise ValueError(
                f"Vendor {vendor_name} does not implement LicenseCheckerTrait."
            )
        vendors.append(vendor_class())
    console.verbose(f"Using vendors: {args.vendor}")
    notifiers: list[NotifierBase] = []
    for notifier_name in args.notify:
        notifier_class = supported_notifiers.get(notifier_name)
        if not notifier_class:
            raise ValueError(f"Notifier {notifier_name} is not supported.")
        notifiers.append(notifier_class())
    console.verbose(f"Using vendors: {args.vendor}")

    license_checker = LicenseChecker()

    path = Path(args.path)
    if not path.exists():
        raise ValueError(f"Path {path} does not exist.")

    console.verbose(f"Running license check on path: {path}")
    result = await license_checker.run(
        project_path=path,
        vendors=vendors,
    )

    console.verbose("Sending notifications for license results.")
    await asyncio.gather(
        *[notifier.send_notification(result=result) for notifier in notifiers]
    )


async def _handle_vulnerability(args: VulnerabilityCheckerSettings) -> None:
    vendors: list[VulnerabilityCheckerTrait] = []
    for vendor_name in args.vendor:
        vendor_class = supported_vendors.get(vendor_name)
        if not is_vuulnerability_checker_trait(vendor_class):
            raise ValueError(
                f"Vendor {vendor_name} does not implement VulnerabilityCheckerTrait."
            )
        vendors.append(vendor_class())
    console.verbose(f"Using vendors: {args.vendor}")
    notifiers: list[NotifierBase] = []
    for notifier_name in args.notify:
        notifier_class = supported_notifiers.get(notifier_name)
        if not notifier_class:
            raise ValueError(f"Notifier {notifier_name} is not supported.")
        notifiers.append(notifier_class())
    console.verbose(f"Using notifiers: {args.notify}")

    vulnerability_checker = VulnerabilityChecker()

    path = Path(args.path)
    if not path.exists():
        raise ValueError(f"Path {path} does not exist.")

    console.verbose(f"Running vulnerability check on path: {path}")
    result = await vulnerability_checker.run(
        project_path=path,
        vendors=vendors,
    )

    console.verbose("Sending notifications for vulnerability results.")
    await asyncio.gather(
        *[notifier.send_notification(result=result) for notifier in notifiers]
    )


async def cli():
    try:
        args = CliApp.run(Arguments)
    except SettingsError as e:
        console.print(f"[red]Error parsing arguments:[/red] {e}")
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
        console.verbose(f"[red]An error occurred:[/red] {e}")
        return


def main():
    asyncio.run(cli())
