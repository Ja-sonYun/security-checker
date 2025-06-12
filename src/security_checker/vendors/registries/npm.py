import asyncio
import os

import httpx

from security_checker.checkers.licenses._vendor_trait import LicenseCheckerTrait
from security_checker.vendors.registries.github_security_advisory import (
    GithubSecurityAdvisoryRegistry,
)

_npm_semaphore = asyncio.Semaphore(10)


class NpmJSRegistry(LicenseCheckerTrait, GithubSecurityAdvisoryRegistry):
    def __init__(
        self,
        npm_url: httpx.URL = httpx.URL("https://registry.npmjs.org"),
        github_graphql_url: httpx.URL = httpx.URL("https://api.github.com/graphql"),
        parallel_requests: int = 10,
        github_token: str | None = os.getenv("GITHUB_TOKEN"),
    ) -> None:
        GithubSecurityAdvisoryRegistry.__init__(
            self,
            github_graphql_url=github_graphql_url,
            parallel_requests=parallel_requests,
            github_token=github_token,
        )
        self._npm_url = npm_url
        self._npm_client = httpx.AsyncClient(base_url=str(self._npm_url))

    @property
    def get_echosystem_name(self) -> str:
        return "NPM"

    async def query_license(self, package_name: str, version: str) -> str:
        async with _npm_semaphore:
            try:
                response = await self._npm_client.get(f"/{package_name}/{version}")
            except httpx.TimeoutException:
                return "TIMEOUT"

            if response.status_code == 404:
                return "UNKNOWN"
            if response.status_code != 200:
                response.raise_for_status()

            data = response.json()
            license_info: str | None = None

            # Check the license field (can be string or object)
            if "license" in data:
                license_field = data["license"]
                if isinstance(license_field, str):
                    license_info = license_field
                elif isinstance(license_field, dict) and "type" in license_field:
                    license_info = license_field["type"]

            # Check licenses array (deprecated but still used)
            if not license_info and "licenses" in data:
                licenses = data["licenses"]
                if isinstance(licenses, list) and licenses:
                    if isinstance(licenses[0], dict) and "type" in licenses[0]:
                        license_info = licenses[0]["type"]
                    elif isinstance(licenses[0], str):
                        license_info = licenses[0]

            return license_info if license_info else "UNKNOWN"
