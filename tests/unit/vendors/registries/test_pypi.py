from __future__ import annotations

import pytest

from tests.unit.vendors.registries.conftest import DummyResponse, PyPiRegistryFactory


@pytest.mark.asyncio
async def test_pypi_license_from_license_field(
    pypi_registry_factory: PyPiRegistryFactory,
) -> None:
    registry = pypi_registry_factory(
        DummyResponse(
            200,
            {
                "info": {
                    "license": "MIT",
                    "classifiers": [],
                }
            },
        )
    )

    license_text = await registry.query_license("requests", "2.32.0")

    assert license_text == "MIT"


@pytest.mark.asyncio
async def test_pypi_license_from_classifier(
    pypi_registry_factory: PyPiRegistryFactory,
) -> None:
    registry = pypi_registry_factory(
        DummyResponse(
            200,
            {
                "info": {
                    "license": "",
                    "classifiers": [
                        "License :: OSI Approved :: Apache Software License"
                    ],
                }
            },
        )
    )

    license_text = await registry.query_license("requests", "2.32.0")

    assert "Apache" in license_text


@pytest.mark.asyncio
async def test_version_range_check(
    pypi_registry_factory: PyPiRegistryFactory,
) -> None:
    registry = pypi_registry_factory(DummyResponse(200, {}))
    assert registry.is_in_version_range("1.2.3", ">=1.0,<2.0")
    assert not registry.is_in_version_range("2.1.0", ">=1.0,<2.0")
