from pathlib import Path

from security_checker.checkers.licenses._models import (
    DependencyRoot,
    LicenseCheckResult,
    PackageLicense,
)


def test_license_check_result_summary_and_details() -> None:
    root = DependencyRoot(root=Path("/repo"), package_manager="poetry")
    packages = [
        PackageLicense(name="pkg-gpl", version="1.0.0", license="GPL v3"),
        PackageLicense(name="pkg-mpl", version="2.0.0", license="MPL 2.0"),
        PackageLicense(name="pkg-mit", version="3.0.0", license="MIT"),
        PackageLicense(name="pkg-unk", version="0.1.0", license="UNKNOWN"),
    ]
    result = LicenseCheckResult(dependencies={root: packages})

    summary = result.get_summary()
    details = "\n".join(result.get_details())

    assert summary == "Found 1 dependencies with license information."
    assert "## `/repo`" in details
    assert "Strong Copyleft Licenses" in details
    assert "Weak Copyleft Licenses" in details
    assert "Permissive Licenses" in details
    assert "Unknown Licenses" in details
    assert "pkg-gpl" in details
    assert "pkg-mit" in details
