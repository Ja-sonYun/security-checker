from __future__ import annotations

import httpx
import pytest
from tenacity import RetryError

from tests.unit.vendors.registries.conftest import (
    DummyResponse,
    NpmRegistryFactory,
    http_status_error,
)


@pytest.mark.asyncio
async def test_query_license_timeout(
    npm_registry_factory: NpmRegistryFactory,
) -> None:
    registry = npm_registry_factory(httpx.TimeoutException("timeout"))

    result = await registry.query_license("test", "1.0.0")

    assert result == "TIMEOUT"


@pytest.mark.asyncio
async def test_query_license_not_found(
    npm_registry_factory: NpmRegistryFactory,
) -> None:
    registry = npm_registry_factory(DummyResponse(404, {}))

    result = await registry.query_license("test", "1.0.0")

    assert result == "UNKNOWN"


@pytest.mark.asyncio
async def test_query_license_http_error(
    npm_registry_factory: NpmRegistryFactory,
) -> None:
    registry = npm_registry_factory(
        DummyResponse(
            500,
            {},
            raise_for_status_error=http_status_error(500),
        )
    )

    with pytest.raises(RetryError) as exc:
        await registry.query_license("test", "1.0.0")

    assert isinstance(exc.value.last_attempt.exception(), httpx.HTTPStatusError)


@pytest.mark.asyncio
async def test_query_license_uses_license_string(
    npm_registry_factory: NpmRegistryFactory,
) -> None:
    registry = npm_registry_factory(DummyResponse(200, {"license": "MIT"}))

    result = await registry.query_license("test", "1.0.0")

    assert result == "MIT"


@pytest.mark.asyncio
async def test_query_license_uses_license_object(
    npm_registry_factory: NpmRegistryFactory,
) -> None:
    registry = npm_registry_factory(
        DummyResponse(200, {"license": {"type": "Apache-2.0"}})
    )

    result = await registry.query_license("test", "1.0.0")

    assert result == "Apache-2.0"


@pytest.mark.asyncio
async def test_query_license_uses_licenses_dict_list(
    npm_registry_factory: NpmRegistryFactory,
) -> None:
    registry = npm_registry_factory(
        DummyResponse(200, {"licenses": [{"type": "BSD-3-Clause"}]})
    )

    result = await registry.query_license("test", "1.0.0")

    assert result == "BSD-3-Clause"


@pytest.mark.asyncio
async def test_query_license_uses_licenses_string_list(
    npm_registry_factory: NpmRegistryFactory,
) -> None:
    registry = npm_registry_factory(DummyResponse(200, {"licenses": ["ISC"]}))

    result = await registry.query_license("test", "1.0.0")

    assert result == "ISC"


@pytest.mark.asyncio
async def test_query_license_unknown(
    npm_registry_factory: NpmRegistryFactory,
) -> None:
    registry = npm_registry_factory(DummyResponse(200, {}))

    result = await registry.query_license("test", "1.0.0")

    assert result == "UNKNOWN"
