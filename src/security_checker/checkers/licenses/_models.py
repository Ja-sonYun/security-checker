from collections.abc import Mapping, Sequence

from security_checker.checkers.licenses._settings import LicenseCheckerSettings
from security_checker.checkers._models import CheckResultBase
from security_checker.vendors._models import Dependency, DependencyRoot


class PackageLicense(Dependency):
    license: str


class LicenseCheckResult(CheckResultBase):
    settings: LicenseCheckerSettings

    dependencies: Mapping[DependencyRoot, Sequence[PackageLicense]]

    def get_summary(self) -> str:
        return f"Found {len(self.dependencies)} dependencies with license information."

    def get_details(self) -> Sequence[str]:
        details: list[str] = []
        for package_root, license_info in self.dependencies.items():
            for package in license_info:
                details.append(
                    f"{package_root}: {package.name} ({package.version}) "
                    f"- License: {package.license}"
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
