import asyncio
import os
from datetime import datetime
from typing import Any, Sequence

import httpx
from tenacity import retry, stop_after_attempt, wait_fixed

from security_checker.checkers.vulnerabilities._models import (
    Dependency,
    VulnerabilityInfo,
    VulnerablePackage,
)
from security_checker.checkers.vulnerabilities._vendor_trait import (
    VulnerabilityCheckerTrait,
)

_github_semaphore = asyncio.Semaphore(10)
BULK_CHUNK_SIZE = 50


class GithubSecurityAdvisoryRegistry(VulnerabilityCheckerTrait):
    def __init__(
        self,
        github_graphql_url: httpx.URL = httpx.URL("https://api.github.com/graphql"),
        parallel_requests: int = 10,
        github_token: str | None = os.getenv("GITHUB_TOKEN"),
    ) -> None:
        super().__init__()
        self._github_graphql_url = github_graphql_url
        self._parallel_requests = parallel_requests
        self._github_token = github_token
        self._github_api_client = httpx.AsyncClient(
            base_url=str(self._github_graphql_url),
            headers={
                "Authorization": f"Bearer {self._github_token}",
                "Content-Type": "application/json",
            },
        )

    def _make_query(self) -> str:
        return """
        query($package: String!, $ecosystem: SecurityAdvisoryEcosystem!) {
          securityVulnerabilities(first: 10, ecosystem: $ecosystem, package: $package) {
            nodes {
              package { name }
              vulnerableVersionRange
              advisory {
                summary
                severity
                publishedAt
                identifiers { type value }
                references { url }
              }
            }
          }
        }
        """

    def _build_bulk_query(
        self, deps: Sequence[Dependency]
    ) -> tuple[str, dict[str, Any], list[str]]:
        alias_parts: list[str] = []
        variables: dict[str, Any] = {
            "ecosystem": self.get_echosystem_name.upper(),
        }

        for idx, dep in enumerate(deps):
            var_name = f"pkg{idx}"
            alias = f"a{idx}"  # Alias can't start with a number
            variables[var_name] = dep.name
            alias_parts.append(
                f"""
                {alias}: securityVulnerabilities(
                  first: 10,
                  ecosystem: $ecosystem,
                  package: ${var_name}
                ) {{
                  nodes {{
                    package {{ name }}
                    vulnerableVersionRange
                    advisory {{
                      summary
                      severity
                      publishedAt
                      identifiers {{ type value }}
                      references {{ url }}
                    }}
                  }}
                }}
                """
            )

        query = (
            "query("
            + ", ".join([f"${k}: String!" for k in variables if k != "ecosystem"])
            + ", $ecosystem: SecurityAdvisoryEcosystem!) {\n"
            + "\n".join(alias_parts)
            + "\n}"
        )

        return query, variables, [f"a{idx}" for idx in range(len(deps))]

    def _extract_vulnerabilities(
        self,
        version: str,
        raw_nodes: list[dict[str, Any]],
    ) -> list[VulnerabilityInfo]:
        extracted: list[VulnerabilityInfo] = []
        for node in raw_nodes:
            vulnerable_version_range = node.get("vulnerableVersionRange", "UNKNOWN")
            try:
                if not self.is_in_version_range(version, vulnerable_version_range):
                    continue
            except ValueError:
                ...
            advisory = node.get("advisory", {})
            identifiers = advisory.get("identifiers", [])
            vuln_id = next(
                (i["value"] for i in identifiers if i["type"] == "CVE"),
                next((i["value"] for i in identifiers if i["type"] == "GHSA"), None),
            )
            extracted.append(
                VulnerabilityInfo(
                    vulnerability_id=vuln_id or "UNKNOWN",
                    severity=advisory.get("severity", "UNKNOWN"),
                    description=advisory.get("summary", ""),
                    published_date=datetime.fromisoformat(
                        advisory.get("publishedAt", "1970-01-01T00:00:00Z").replace(
                            "Z", "+00:00"
                        )
                    ),
                    reference_url=next(
                        (
                            ref["url"]
                            for ref in advisory.get("references", [])
                            if ref["url"]
                        ),
                        "UNKNOWN",
                    ),
                    version_range=vulnerable_version_range,
                )
            )
        return extracted

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_fixed(2),
    )
    async def query_vulnerabilities(
        self, package_name: str, version: str
    ) -> VulnerablePackage:
        async with _github_semaphore:
            query = self._make_query()
            variables = {
                "package": package_name,
                "ecosystem": self.get_echosystem_name.upper(),
            }
            resp = await self._github_api_client.post(
                str(self._github_graphql_url),
                json={"query": query, "variables": variables},
            )
            resp.raise_for_status()
            raw_nodes = (
                resp.json()
                .get("data", {})
                .get("securityVulnerabilities", {})
                .get("nodes", [])
            )
            vulns = self._extract_vulnerabilities(version, raw_nodes)
            return VulnerablePackage(
                name=package_name,
                version=version,
                vulnerabilities=vulns,
            )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_fixed(2),
    )
    async def scan_dependencies_for_vulnerabilities(
        self, packages: Sequence[Dependency]
    ) -> Sequence[VulnerablePackage]:
        """
        Overrides the base method to handle bulk queries
        """
        results: list[VulnerablePackage] = []

        async def _process_chunk(chunk: Sequence[Dependency]) -> None:
            query, variables, aliases = self._build_bulk_query(chunk)
            async with _github_semaphore:
                resp = await self._github_api_client.post(
                    str(self._github_graphql_url),
                    json={"query": query, "variables": variables},
                )
                resp.raise_for_status()
                data = resp.json().get("data", {})
                for dep, alias in zip(chunk, aliases):
                    raw_nodes = data.get(alias, {}).get("nodes", [])
                    vulns = self._extract_vulnerabilities(dep.version, raw_nodes)
                    results.append(
                        VulnerablePackage(
                            name=dep.name,
                            version=dep.version,
                            vulnerabilities=vulns,
                        )
                    )

        chunks = [
            packages[i : i + BULK_CHUNK_SIZE]
            for i in range(0, len(packages), BULK_CHUNK_SIZE)
        ]

        sem = asyncio.Semaphore(self._parallel_requests)

        async def _run_with_sem(c):
            async with sem:
                await _process_chunk(c)

        await asyncio.gather(*[_run_with_sem(chunk) for chunk in chunks])
        return results
