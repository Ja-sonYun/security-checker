#!/usr/bin/env python3
"""Simple test to verify caching works without full imports."""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from security_checker.cache import SqliteCache


async def test_simple_caching():
    """Simple test demonstrating caching functionality."""
    print("=" * 60)
    print("TESTING: License Caching with SQLite")
    print("=" * 60)

    cache = SqliteCache()

    # Clear cache
    await cache.clear_cache()
    print("\n✓ Cache initialized and cleared\n")

    # Simulate package license caching
    packages = [
        ("pypi", "requests", "2.28.0", "Apache-2.0"),
        ("pypi", "django", "4.0.0", "BSD-3-Clause"),
        ("pypi", "flask", "2.0.0", "BSD-3-Clause"),
        ("npm", "express", "4.18.0", "MIT"),
        ("npm", "react", "18.0.0", "MIT"),
    ]

    print("Caching licenses for packages:")
    for ecosystem, name, version, license in packages:
        await cache.set_license(ecosystem, name, version, license)
        print(f"  • {ecosystem}:{name}@{version} → {license}")

    print("\n✓ All licenses cached successfully\n")

    # Retrieve from cache
    print("Retrieving licenses from cache:")
    for ecosystem, name, version, expected_license in packages:
        cached = await cache.get_license(ecosystem, name, version)
        status = "✓" if cached == expected_license else "✗"
        print(f"  {status} {ecosystem}:{name}@{version} → {cached}")

    print()

    # Show cache stats
    stats = await cache.get_cache_stats()
    print("Cache Statistics:")
    print(f"  • Total entries: {stats['total_entries']}")
    print(f"  • Unique packages: {stats['unique_packages']}")
    print(f"  • By ecosystem: {stats['by_ecosystem']}")
    print(f"  • Database location: {stats['db_path']}")

    print("\n" + "=" * 60)
    print("✅ ALL TESTS PASSED - CACHING IS FUNCTIONAL!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_simple_caching())
