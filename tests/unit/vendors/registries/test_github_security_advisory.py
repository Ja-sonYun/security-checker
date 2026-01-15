from __future__ import annotations

from datetime import datetime, timezone

import pytest

from security_checker.checkers.vulnerabilities._models import Dependency
from tests.unit.vendors.registries.conftest import DummyResponse, PyPiRegistryFactory


def test_build_bulk_query(pypi_registry_factory: PyPiRegistryFactory) -> None:
    registry = pypi_registry_factory()
    deps = [
        Dependency(name="requests", version="2.32.0"),
        Dependency(name="urllib3", version="2.2.0"),
    ]
    query, variables, aliases = registry._build_bulk_query(deps)

    assert "securityVulnerabilities" in query
    assert variables["pkg0"] == "requests"
    assert variables["pkg1"] == "urllib3"
    assert aliases == ["a0", "a1"]


def test_extract_vulnerabilities(
    pypi_registry_factory: PyPiRegistryFactory,
) -> None:
    registry = pypi_registry_factory()
    raw_nodes = [
        {
            "vulnerableVersionRange": ">=1.0.0",
            "advisory": {
                "summary": "Test",
                "severity": "HIGH",
                "publishedAt": "2024-01-01T00:00:00Z",
                "identifiers": [{"type": "CVE", "value": "CVE-0000-0000"}],
                "references": [{"url": "https://example.com"}],
            },
        }
    ]

    vulns = registry._extract_vulnerabilities("1.2.3", raw_nodes)

    assert len(vulns) == 1
    assert vulns[0].vulnerability_id == "CVE-0000-0000"
    assert vulns[0].severity == "HIGH"
    assert vulns[0].published_date == datetime(2024, 1, 1, tzinfo=timezone.utc)


@pytest.mark.asyncio
async def test_query_vulnerabilities_uses_github_response(
    monkeypatch: pytest.MonkeyPatch,
    pypi_registry_factory: PyPiRegistryFactory,
) -> None:
    registry = pypi_registry_factory()

    async def _fake_post(_url: str, json: dict) -> DummyResponse:
        payload = {
            "data": {
                "securityVulnerabilities": {
                    "nodes": [
                        {
                            "vulnerableVersionRange": ">=1.0,<2.0",
                            "advisory": {
                                "summary": "Test",
                                "severity": "CRITICAL",
                                "publishedAt": "2024-01-01T00:00:00Z",
                                "identifiers": [
                                    {"type": "CVE", "value": "CVE-9999-0001"}
                                ],
                                "references": [{"url": "https://example.com"}],
                            },
                        }
                    ]
                }
            }
        }
        return DummyResponse(200, payload, raise_for_status_ok=True)

    monkeypatch.setattr(registry._github_api_client, "post", _fake_post)

    result = await registry.query_vulnerabilities("requests", "1.5.0")

    assert result.name == "requests"
    assert result.version == "1.5.0"
    assert len(result.vulnerabilities) == 1
    assert result.vulnerabilities[0].vulnerability_id == "CVE-9999-0001"


@pytest.mark.asyncio
async def test_scan_dependencies_uses_bulk_response(
    monkeypatch: pytest.MonkeyPatch,
    pypi_registry_factory: PyPiRegistryFactory,
) -> None:
    registry = pypi_registry_factory()
    deps = [
        Dependency(name="requests", version="1.5.0"),
        Dependency(name="urllib3", version="1.2.0"),
    ]

    async def _fake_post(_url: str, json: dict) -> DummyResponse:
        payload = {
            "data": {
                "a0": {
                    "nodes": [
                        {
                            "vulnerableVersionRange": ">=1.0,<2.0",
                            "advisory": {
                                "summary": "Test",
                                "severity": "HIGH",
                                "publishedAt": "2024-01-01T00:00:00Z",
                                "identifiers": [
                                    {"type": "CVE", "value": "CVE-1111-0001"}
                                ],
                                "references": [{"url": "https://example.com"}],
                            },
                        }
                    ]
                },
                "a1": {
                    "nodes": [
                        {
                            "vulnerableVersionRange": ">=1.0,<2.0",
                            "advisory": {
                                "summary": "Test",
                                "severity": "LOW",
                                "publishedAt": "2024-01-01T00:00:00Z",
                                "identifiers": [
                                    {"type": "CVE", "value": "CVE-2222-0001"}
                                ],
                                "references": [{"url": "https://example.com"}],
                            },
                        }
                    ]
                },
            }
        }
        return DummyResponse(200, payload, raise_for_status_ok=True)

    monkeypatch.setattr(registry._github_api_client, "post", _fake_post)

    results = await registry.scan_dependencies_for_vulnerabilities(deps)

    assert len(results) == 2
    assert results[0].name == "requests"
    assert results[0].vulnerabilities[0].vulnerability_id == "CVE-1111-0001"
    assert results[1].name == "urllib3"
    assert results[1].vulnerabilities[0].vulnerability_id == "CVE-2222-0001"
