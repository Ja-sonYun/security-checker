from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx
import pytest
import pytest_asyncio
from tenacity import wait_none

from security_checker.vendors._models import Dependencies
from security_checker.vendors.registries.npm import NpmJSRegistry
from security_checker.vendors.registries.pypi import PyPiRegistry


@pytest.fixture(autouse=True)
def disable_retry_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    """Disable retry wait time for faster tests."""
    monkeypatch.setattr(
        "security_checker.vendors.registries.npm.NpmJSRegistry.query_license.retry.wait",
        wait_none(),
    )


@dataclass
class DummyResponse:
    status_code: int
    payload: dict[str, Any]
    raise_for_status_error: Exception | None = None
    raise_for_status_ok: bool = False

    def json(self) -> dict[str, Any]:
        return self.payload

    def raise_for_status(self) -> None:
        if self.raise_for_status_ok:
            return
        if self.raise_for_status_error is None:
            raise AssertionError("Unexpected status")
        raise self.raise_for_status_error


class DummyAsyncClient:
    def __init__(self, response: DummyResponse | Exception) -> None:
        self._response = response

    async def get(self, _path: str) -> DummyResponse:
        if isinstance(self._response, Exception):
            raise self._response
        return self._response

    async def post(self, _url: str, json: dict | None = None) -> DummyResponse:
        return await self.get(_url)


def http_status_error(status_code: int) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://registry.example.com/test/1.0.0")
    response = httpx.Response(status_code, request=request)
    return httpx.HTTPStatusError("error", request=request, response=response)


async def close_registry_clients(*clients: Any) -> None:
    for client in clients:
        if hasattr(client, "aclose"):
            await client.aclose()


class DummyNpmRegistry(NpmJSRegistry):
    def __init__(self, response: DummyResponse | Exception) -> None:
        self._npm_url = httpx.URL("https://registry.npmjs.org")
        self._npm_client = DummyAsyncClient(response)
        self._github_graphql_url = httpx.URL("https://api.github.com/graphql")
        self._parallel_requests = 10
        self._github_api_client = DummyAsyncClient(DummyResponse(200, {}))

    @property
    def name(self) -> str:
        return "Dummy NPM Registry"

    @property
    def dependency_manager_name(self) -> str:
        return "npm"

    @property
    def supported_lockfiles(self) -> set[str]:
        return {"package-lock.json"}

    def get_lockfile_dependencies(self, file_path: Path) -> Dependencies:
        return Dependencies(file_path=file_path, dependencies=[])


class DummyPyPiRegistry(PyPiRegistry):
    def __init__(self, response: DummyResponse | Exception) -> None:
        self._pypi_url = httpx.URL("https://pypi.org/pypi")
        self._pypi_client = DummyAsyncClient(response)
        self._github_graphql_url = httpx.URL("https://api.github.com/graphql")
        self._parallel_requests = 10
        self._github_api_client = DummyAsyncClient(DummyResponse(200, {}))

    @property
    def name(self) -> str:
        return "Dummy PyPI"

    @property
    def dependency_manager_name(self) -> str:
        return "dummy"

    @property
    def supported_lockfiles(self) -> set[str]:
        return {"requirements.txt"}

    def get_lockfile_dependencies(self, file_path: Path) -> Dependencies:
        raise AssertionError("Not used in registry unit tests")


async def _close_registry(registry: Any) -> None:
    clients: list[Any] = []
    for attr in ("_npm_client", "_pypi_client", "_github_api_client"):
        client = getattr(registry, attr, None)
        if client is not None:
            clients.append(client)
    if clients:
        await close_registry_clients(*clients)


class NpmRegistryFactory(Protocol):
    def __call__(
        self, response: DummyResponse | Exception | None = None
    ) -> DummyNpmRegistry: ...


class PyPiRegistryFactory(Protocol):
    def __call__(
        self, response: DummyResponse | Exception | None = None
    ) -> DummyPyPiRegistry: ...


@pytest_asyncio.fixture
async def npm_registry_factory() -> AsyncIterator[NpmRegistryFactory]:
    registries: list[Any] = []

    def _make_npm(
        response: DummyResponse | Exception | None = None,
    ) -> DummyNpmRegistry:
        registry = DummyNpmRegistry(response or DummyResponse(200, {}))
        registries.append(registry)
        return registry

    yield _make_npm

    for registry in registries:
        await _close_registry(registry)


@pytest_asyncio.fixture
async def pypi_registry_factory() -> AsyncIterator[PyPiRegistryFactory]:
    registries: list[Any] = []

    def _make_pypi(
        response: DummyResponse | Exception | None = None,
    ) -> DummyPyPiRegistry:
        registry = DummyPyPiRegistry(response or DummyResponse(200, {}))
        registries.append(registry)
        return registry

    yield _make_pypi

    for registry in registries:
        await _close_registry(registry)
