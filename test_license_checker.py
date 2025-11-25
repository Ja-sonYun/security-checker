#!/usr/bin/env python3
"""Test script to verify license checker with caching."""

import asyncio
import sys
import time
from pathlib import Path

# Add src to path so we can import the module
sys.path.insert(0, str(Path(__file__).parent / "src"))

from security_checker.vendors.registries.pypi import PyPiRegistry
from security_checker.cache import SqliteCache


async def test_license_checker_with_cache():
    """Test the license checker with caching."""
    print("Testing License Checker with SQLite cache...\n")

    # Clear cache for fresh test
    cache = SqliteCache()
    await cache.clear_cache()
    print("✓ Cache cleared for fresh test\n")

    # Create PyPI registry
    registry = PyPiRegistry()

    # Test packages
    test_packages = [
        ("requests", "2.28.0"),
        ("django", "4.0.0"),
        ("flask", "2.0.0"),
    ]

    # Test 1: Query licenses (should hit API)
    print("1. First run - querying licenses (should hit PyPI API)...")
    start_time = time.time()
    results_first = []
    for name, version in test_packages:
        license = await registry.query_license(name, version)
        results_first.append((name, version, license))
        print(f"   {name} {version}: {license}")
    first_run_time = time.time() - start_time
    print(f"   Time: {first_run_time:.2f}s\n")

    # Test 2: Query same licenses again (should hit cache)
    print("2. Second run - querying same licenses (should hit cache)...")
    start_time = time.time()
    results_second = []
    for name, version in test_packages:
        license = await registry.query_license(name, version)
        results_second.append((name, version, license))
        print(f"   {name} {version}: {license}")
    second_run_time = time.time() - start_time
    print(f"   Time: {second_run_time:.2f}s\n")

    # Verify results are the same
    assert results_first == results_second, "Results mismatch!"
    print("✓ Results match between first and second run\n")

    # Verify cache is significantly faster
    if second_run_time < first_run_time * 0.5:
        speedup = first_run_time / second_run_time if second_run_time > 0 else float('inf')
        print(f"✓ Cache is {speedup:.1f}x faster than API calls\n")
    else:
        print(f"⚠ Warning: Cache speedup not as significant as expected\n")
        print(f"   First run: {first_run_time:.2f}s, Second run: {second_run_time:.2f}s\n")

    # Check cache stats
    stats = await cache.get_cache_stats()
    print("3. Cache statistics:")
    print(f"   Total entries: {stats['total_entries']}")
    print(f"   Unique packages: {stats['unique_packages']}")
    print(f"   By ecosystem: {stats['by_ecosystem']}")
    print(f"   Database path: {stats['db_path']}\n")

    assert stats['total_entries'] == len(test_packages), \
        f"Expected {len(test_packages)} cached entries, got {stats['total_entries']}"

    print("✅ All license checker cache tests passed!")


if __name__ == "__main__":
    asyncio.run(test_license_checker_with_cache())
