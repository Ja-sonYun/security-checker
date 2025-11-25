#!/usr/bin/env python3
"""Test script to verify license caching functionality."""

import asyncio
import sys
from pathlib import Path

# Add src to path so we can import the module
sys.path.insert(0, str(Path(__file__).parent / "src"))

from security_checker.cache import SqliteCache


async def test_cache():
    """Test the cache functionality."""
    print("Testing SQLite cache...")

    # Initialize cache
    cache = SqliteCache()

    # Test 1: Set and get a license
    print("\n1. Testing cache set/get...")
    await cache.set_license("pypi", "requests", "2.28.0", "Apache-2.0")
    result = await cache.get_license("pypi", "requests", "2.28.0")
    assert result == "Apache-2.0", f"Expected 'Apache-2.0', got '{result}'"
    print("   ✓ Cache set/get working")

    # Test 2: Get non-existent entry
    print("\n2. Testing cache miss...")
    result = await cache.get_license("pypi", "nonexistent", "1.0.0")
    assert result is None, f"Expected None, got '{result}'"
    print("   ✓ Cache miss returns None")

    # Test 3: Multiple ecosystems
    print("\n3. Testing multiple ecosystems...")
    await cache.set_license("npm", "express", "4.18.0", "MIT")
    await cache.set_license("pypi", "django", "4.0.0", "BSD-3-Clause")

    npm_result = await cache.get_license("npm", "express", "4.18.0")
    pypi_result = await cache.get_license("pypi", "django", "4.0.0")

    assert npm_result == "MIT", f"Expected 'MIT', got '{npm_result}'"
    assert pypi_result == "BSD-3-Clause", f"Expected 'BSD-3-Clause', got '{pypi_result}'"
    print("   ✓ Multiple ecosystems working")

    # Test 4: Get cache stats
    print("\n4. Testing cache statistics...")
    stats = await cache.get_cache_stats()
    print(f"   Total entries: {stats['total_entries']}")
    print(f"   Unique packages: {stats['unique_packages']}")
    print(f"   By ecosystem: {stats['by_ecosystem']}")
    print(f"   Database path: {stats['db_path']}")

    assert stats['total_entries'] >= 3, f"Expected at least 3 entries, got {stats['total_entries']}"
    print("   ✓ Cache statistics working")

    # Test 5: Clear cache
    print("\n5. Testing cache clear...")
    await cache.clear_cache()
    stats_after = await cache.get_cache_stats()
    assert stats_after['total_entries'] == 0, f"Expected 0 entries after clear, got {stats_after['total_entries']}"
    print("   ✓ Cache clear working")

    print("\n✅ All cache tests passed!")


if __name__ == "__main__":
    asyncio.run(test_cache())
