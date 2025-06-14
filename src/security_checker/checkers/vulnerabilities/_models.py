from collections.abc import Mapping, Sequence
from datetime import datetime

from pydantic import BaseModel

from security_checker.checkers._models import CheckResultBase
from security_checker.checkers.vulnerabilities._settings import (
    VulnerabilityCheckerSettings,
)
from security_checker.vendors._models import Dependency, DependencyRoot


class VulnerabilityInfo(BaseModel):
    vulnerability_id: str
    severity: str
    description: str
    published_date: datetime | None = None
    fix_version: str | None = None
    reference_url: str | None = None


class VulnerablePackage(Dependency):
    vulnerabilities: Sequence[VulnerabilityInfo]


class VulnerabilityCheckResult(CheckResultBase):
    settings: VulnerabilityCheckerSettings

    dependencies: Mapping[DependencyRoot, Sequence[VulnerablePackage]]

    @property
    def checker_name(self) -> str:
        return "Vulnerability Checker"

    def get_summary(self) -> str:
        total_vulns = sum(
            len(pkg.vulnerabilities)
            for pkgs in self.dependencies.values()
            for pkg in pkgs
        )
        return (
            f"Found {total_vulns} vulnerabilities across "
            f"{len(self.dependencies)} dependency roots."
        )

    def get_details(self) -> Sequence[str]:
        details: list[str] = []

        severity_levels = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MODERATE": 2,
            "MEDIUM": 2,
            "LOW": 1,
            "UNKNOWN": 0,
        }

        for root, pkgs in self.dependencies.items():
            details.append(f"## `{root.root.as_posix()}`")
            all_vulnerabilities = [
                (pkg, vuln) for pkg in pkgs for vuln in pkg.vulnerabilities
            ]
            criticla_severity_vulns = [
                (pkg, vuln)
                for pkg, vuln in all_vulnerabilities
                if severity_levels.get(vuln.severity.upper(), 0) == 4
            ]
            high_severity_vulns = [
                (pkg, vuln)
                for pkg, vuln in all_vulnerabilities
                if severity_levels.get(vuln.severity.upper(), 0) == 3
            ]
            moderate_severity_vulns = [
                (pkg, vuln)
                for pkg, vuln in all_vulnerabilities
                if severity_levels.get(vuln.severity.upper(), 0) == 2
            ]
            low_severity_vulns = [
                (pkg, vuln)
                for pkg, vuln in all_vulnerabilities
                if severity_levels.get(vuln.severity.upper(), 0) == 1
            ]
            unknown_severity_vulns = [
                (pkg, vuln)
                for pkg, vuln in all_vulnerabilities
                if severity_levels.get(vuln.severity.upper(), 0) == 0
            ]

            def _render_vulnerabilities(
                header: str,
                vulns: Sequence[tuple[VulnerablePackage, VulnerabilityInfo]],
            ) -> None:
                details.append(f"### {header}")
                for pkg, vuln in vulns:
                    details.append(f" - `{pkg.name}` (`{pkg.version}`)")
                    details.append(
                        f"   - Vulnerability ID: {vuln.vulnerability_id}\n"
                        f"   - Severity: {vuln.severity}\n"
                        f"   - Description: {vuln.description}\n"
                        f"   - Published Date: {vuln.published_date or 'N/A'}\n"
                        f"   - Fix Version: {vuln.fix_version or 'N/A'}\n"
                        f"   - Reference URL: {vuln.reference_url or 'N/A'}"
                    )
                else:
                    if not vulns:
                        details.append(" - No vulnerabilities found.")

            _render_vulnerabilities(
                "Critical Vulnerabilities (Immediate Action Required)",
                criticla_severity_vulns,
            )
            _render_vulnerabilities(
                "High Vulnerabilities (Action Recommended)",
                high_severity_vulns,
            )
            _render_vulnerabilities(
                "Moderate Vulnerabilities (Review Recommended)",
                moderate_severity_vulns,
            )
            _render_vulnerabilities(
                "Low Vulnerabilities (Monitor)",
                low_severity_vulns,
            )
            _render_vulnerabilities(
                "Unknown Severity Vulnerabilities (Further Investigation Needed)",
                unknown_severity_vulns,
            )

        return details

    async def get_critical_vulnerabilities_summary(self) -> str:
        vulnerabilities = ""
        for root, pkgs in self.dependencies.items():
            vuln_lines = [
                f"{pkg.name} ({pkg.version}): {v.vulnerability_id} "
                f"({v.severity}) - {v.description}"
                for pkg in pkgs
                for v in pkg.vulnerabilities
                if v.severity.upper() in {"CRITICAL", "HIGH"}
            ]
            if vuln_lines:
                vuln_lines.sort()
                vulnerabilities += f"{root}:\n" + "\n".join(vuln_lines) + "\n\n"

        client = self.settings.get_client()
        response = await client.chat.completions.create(
            model=self.settings.llm_summarize_model,
            messages=[
                {
                    "role": "system",
                    "content": self.settings.llm_vulnerability_summarize_prompt,
                },
                {
                    "role": "user",
                    "content": (
                        "Please analyze the following vulnerabilities:\n"
                        f"{vulnerabilities or 'No critical vulnerabilities found.'}"
                    ),
                },
            ],
        )

        return response.choices[0].message.content or "No summary available."

    async def llm_summary(self) -> str:
        return await self.get_critical_vulnerabilities_summary()
