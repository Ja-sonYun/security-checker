import asyncio
import os

import httpx
from packaging.specifiers import SpecifierSet
from packaging.version import Version
from tenacity import retry, stop_after_attempt, wait_fixed

from security_checker.cache import SqliteCache
from security_checker.checkers.licenses._vendor_trait import LicenseCheckerTrait
from security_checker.vendors.registries.github_security_advisory import (
    GithubSecurityAdvisoryRegistry,
)

_pypi_semaphore = asyncio.Semaphore(10)
_cache = SqliteCache()


class PyPiRegistry(LicenseCheckerTrait, GithubSecurityAdvisoryRegistry):
    def __init__(
        self,
        pypi_url: httpx.URL = httpx.URL("https://pypi.org/pypi"),
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
        self._pypi_url = pypi_url
        self._pypi_client = httpx.AsyncClient(base_url=str(self._pypi_url))

    @property
    def get_echosystem_name(self) -> str:
        return "PIP"

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_fixed(2),
    )
    async def query_license(self, package_name: str, version: str) -> str:
        # Check cache first
        cached_license = await _cache.get_license("pypi", package_name, version)
        if cached_license is not None:
            return cached_license

        async with _pypi_semaphore:
            try:
                response = await self._pypi_client.get(
                    f"{self._pypi_url}/{package_name}/{version}/json"
                )
            except httpx.TimeoutException:
                license_result = "TIMEOUT"
                await _cache.set_license("pypi", package_name, version, license_result)
                return license_result

            if response.status_code == 404:
                license_result = "UNKNOWN"
                await _cache.set_license("pypi", package_name, version, license_result)
                return license_result
            if response.status_code != 200:
                response.raise_for_status()

            data = response.json()

            # Check if the response contains the necessary information
            if "info" not in data or "license" not in data["info"]:
                license_result = "UNKNOWN"
                await _cache.set_license("pypi", package_name, version, license_result)
                return license_result

            package_info = data["info"]
            license_info: str | None = None

            # Extract license information from classifiers
            classifiers = package_info.get("classifiers", [])
            for classifier in classifiers:
                if classifier.startswith("License"):
                    license_info = (
                        classifier.split("::", 1)[-1]
                        .strip()
                        .replace("OSI Approved ", "")
                        .replace("::", "")
                        .strip()
                    )
                    break

            # Check if the license field is present and not too long
            if (
                len((_license := package_info.get("license", None)) or "") < 100
                and _license
            ):
                license_info = _license

            if license_info is None:
                license_info = package_info.get("license_expression", None)

            license_result = license_info if license_info else "UNKNOWN"
            await _cache.set_license("pypi", package_name, version, license_result)
            return license_result

    def is_in_version_range(self, version: str, version_range: str) -> bool:
        spec = SpecifierSet(version_range.replace(" ", ""))
        return Version(version) in spec
