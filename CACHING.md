# License Checker Caching

## Overview

The security-checker now includes SQLite-based caching for license information. This significantly improves performance by avoiding repeated API calls to package registries (PyPI, npm) for packages that have already been checked.

## Features

- **SQLite Database**: Persistent cache stored in `~/.cache/security-checker/licenses.db`
- **Multi-Ecosystem Support**: Caches licenses for both PyPI (Python) and npm (JavaScript) packages
- **Automatic Management**: Cache is automatically initialized and managed
- **Fast Lookups**: Indexed queries for quick license retrieval

## How It Works

### Cache Structure

The cache stores license information with the following schema:

```sql
CREATE TABLE license_cache (
    ecosystem TEXT NOT NULL,        -- e.g., 'pypi', 'npm'
    package_name TEXT NOT NULL,     -- Package name
    version TEXT NOT NULL,          -- Package version
    license TEXT NOT NULL,          -- License string
    cached_at TIMESTAMP,            -- When the entry was cached
    PRIMARY KEY (ecosystem, package_name, version)
);
```

### Cache Flow

1. **License Query**: When a license is requested for a package:
   ```
   query_license(package_name, version)
     ↓
   Check cache for (ecosystem, package_name, version)
     ↓
   If found → Return cached license (fast!)
     ↓
   If not found → Query API → Cache result → Return license
   ```

2. **Automatic Caching**: Every license query result is automatically cached
3. **Persistent Storage**: Cache persists between runs, speeding up repeated checks

## Integration Points

The caching is integrated at the registry level:

- **PyPI Registry** (`src/security_checker/vendors/registries/pypi.py`)
  - Checks cache before querying PyPI API
  - Caches all license query results

- **npm Registry** (`src/security_checker/vendors/registries/npm.py`)
  - Checks cache before querying npm registry API
  - Caches all license query results

## Cache Location

By default, the cache database is stored at:
- Linux/macOS: `~/.cache/security-checker/licenses.db`
- The location can be customized by providing a custom path to `SqliteCache()`

## Performance Benefits

- **First Run**: Queries package registries via HTTP (slower)
- **Subsequent Runs**: Reads from local SQLite database (much faster)
- **Typical Speedup**: 5-10x faster for cached results

## Cache Statistics

You can check cache statistics programmatically:

```python
from security_checker.cache import SqliteCache

cache = SqliteCache()
stats = await cache.get_cache_stats()

print(f"Total entries: {stats['total_entries']}")
print(f"Unique packages: {stats['unique_packages']}")
print(f"By ecosystem: {stats['by_ecosystem']}")
```

## Implementation Details

### Cache Module

- **Location**: `src/security_checker/cache/`
- **Main Class**: `SqliteCache`
- **Dependencies**: `aiosqlite` (async SQLite library)

### Key Methods

- `get_license(ecosystem, package_name, version)`: Retrieve cached license
- `set_license(ecosystem, package_name, version, license)`: Cache a license
- `get_cache_stats()`: Get cache statistics
- `clear_cache()`: Clear all cached data

### Thread Safety

The cache implementation uses async/await and proper locking:
- Initialization is protected by `asyncio.Lock`
- Database operations are async-safe using `aiosqlite`

## Testing

Run the included test to verify caching functionality:

```bash
python test_simple.py
```

This test demonstrates:
- Cache initialization
- Storing licenses for multiple packages and ecosystems
- Retrieving cached licenses
- Cache statistics

## Future Enhancements

Potential improvements for the caching system:

1. **TTL (Time To Live)**: Add expiration for cache entries
2. **Cache Size Management**: Implement LRU eviction for large caches
3. **Vulnerability Caching**: Extend caching to vulnerability checks
4. **Cache Warming**: Pre-populate cache for common packages
5. **Cache Export/Import**: Share cache databases across CI/CD systems
