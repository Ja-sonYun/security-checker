import asyncio
from collections.abc import Coroutine, Mapping, Sequence
from datetime import datetime
from typing import Any

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

        for root, pkgs in self.dependencies.items():
            for pkg in pkgs:
                for vuln in pkg.vulnerabilities:
                    fix_info = (
                        f" (Fix: {vuln.fix_version})"
                        if vuln.fix_version
                        else " (No fix available)"
                    )
                    details.append(
                        f"{root}: {pkg.name} ({pkg.version}) - "
                        f"{vuln.vulnerability_id} ({vuln.severity}){fix_info}: "
                        f"{vuln.description[:100]}..."
                    )

        return details

    async def get_critical_vulnerabilities_summary(self) -> str:
        client = self.settings.get_client()
        openai_semaphore = asyncio.Semaphore(5)

        async def _summarize_root(root: DependencyRoot, vuln_lines: list[str]) -> str:
            if not vuln_lines:
                return ""

            async with openai_semaphore:
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
                                + "\n".join(vuln_lines)
                            ),
                        },
                    ],
                )

            summary_text = (response.choices[0].message.content or "").strip()
            return f"## {root}\n\n{summary_text}"

        tasks: list[Coroutine[Any, Any, str]] = []
        for root, pkgs in self.dependencies.items():
            vuln_lines = [
                f"{pkg.name} ({pkg.version}): {v.vulnerability_id} "
                f"({v.severity}) - {v.description}"
                for pkg in pkgs
                for v in pkg.vulnerabilities
                if v.severity.upper() in {"CRITICAL", "HIGH"}
            ]
            tasks.append(_summarize_root(root, vuln_lines))

        summaries = [s for s in await asyncio.gather(*tasks) if s]

        if not summaries:
            return "No critical vulnerabilities detected."

        return "\n\n".join(summaries)

    async def llm_summary(self) -> str:
        return await self.get_critical_vulnerabilities_summary()
