from collections.abc import Mapping, Sequence

from security_checker.checkers._models import CheckResultBase
from security_checker.checkers.licenses._known_licenses import detect_license_score
from security_checker.checkers.licenses._settings import LicenseCheckerSettings
from security_checker.vendors._models import Dependency, DependencyRoot


class PackageLicense(Dependency):
    license: str


class LicenseCheckResult(CheckResultBase):
    settings: LicenseCheckerSettings

    dependencies: Mapping[DependencyRoot, Sequence[PackageLicense]]

    @property
    def checker_name(self) -> str:
        return "License Checker"

    def get_summary(self) -> str:
        return f"Found {len(self.dependencies)} dependencies with license information."

    def get_details(self) -> Sequence[str]:
        details: list[str] = []
        for package_root, license_info in self.dependencies.items():
            details.append(f"## `{package_root.root.as_posix()}`")

            strong_copyleft_licenses = [
                package
                for package in license_info
                if detect_license_score(package.license) == 3
            ]
            weak_copyleft_licenses = [
                package
                for package in license_info
                if detect_license_score(package.license) == 2
            ]
            permissive_licenses = [
                package
                for package in license_info
                if detect_license_score(package.license) == 1
            ]
            unknown_licenses = [
                package
                for package in license_info
                if detect_license_score(package.license) == 0
            ]

            def _render_license_section(
                title: str,
                packages: Sequence[PackageLicense],
            ) -> None:
                details.append(f"### {title}\n")
                for package in packages:
                    details.append(
                        f" - `{package.name}` (`{package.version}`)\n"
                        f"   - License: {package.license}\n"
                    )
                else:
                    if not packages:
                        details.append(" - None")

            _render_license_section(
                "Strong Copyleft Licenses",
                strong_copyleft_licenses,
            )
            _render_license_section(
                "Weak Copyleft Licenses",
                weak_copyleft_licenses,
            )
            _render_license_section(
                "Permissive Licenses",
                permissive_licenses,
            )
            _render_license_section(
                "Unknown Licenses",
                unknown_licenses,
            )

        return details

    async def get_non_commercial_licenses_summary(self) -> str:
        client = self.settings.get_client()

        response = await client.chat.completions.create(
            model=self.settings.llm_summarize_model,
            messages=[
                {
                    "role": "system",
                    "content": self.settings.llm_non_commercial_license_summary_prompt,
                },
                {
                    "role": "user",
                    "content": (
                        "Please provide a summary of the non-commercial licenses "
                        "found in the following dependencies:\n"
                        + "\n".join(
                            f"{package.name} ({package.version}): {package.license}"
                            for _, packages in self.dependencies.items()
                            for package in packages
                        )
                    ),
                },
            ],
        )

        summary = response.choices[0].message.content or ""

        return summary.strip()

    async def llm_summary(self) -> str:
        return await self.get_non_commercial_licenses_summary()
