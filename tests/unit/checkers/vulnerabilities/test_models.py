from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from security_checker.checkers.vulnerabilities._models import (
    DependencyRoot,
    VulnerabilityCheckResult,
    VulnerabilityInfo,
    VulnerablePackage,
)


def test_vulnerability_check_result_summary_and_details() -> None:
    root = DependencyRoot(root=Path("/repo"), package_manager="npm")
    vuln = VulnerabilityInfo(
        vulnerability_id="CVE-1234-5678",
        severity="HIGH",
        description="Test",
        published_date=datetime.now(timezone.utc),
        version_range=">=1.0.0",
        reference_url="https://example.com",
    )
    package = VulnerablePackage(name="leftpad", version="1.0.0", vulnerabilities=[vuln])
    result = VulnerabilityCheckResult(dependencies={root: [package]})

    summary = result.get_summary()
    details = "\n".join(result.get_details())

    assert "Found 1 vulnerabilities" in summary
    assert "High Vulnerabilities" in details
    assert "leftpad" in details
    assert "CVE-1234-5678" in details
