# Security Checker

A simple CLI to check dependency licenses and vulnerabilities.

## Install

```bash
pip install security-checker
```

## Usage

```bash
# License check
security-checker license /path/to/your/project

# License check (ignore packages)
security-checker license /path/to/your/project --ignore-packages package-a,package-b

# Vulnerability check
security-checker vuln /path/to/your/project
```

License check exits with non-zero status when strong copyleft licenses are found.

## DB Cache (License Only)

```bash
security-checker license /path/to/your/project --db /path/to/cache.sqlite
```

## GitHub Actions (Composite Action)

This action uses a SQLite cache database for license checks.

```yaml
name: License Check

on:
  pull_request:

jobs:
  license:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Ja-sonYun/security-checker@v1
        id: license
        with:
          check: license
          path: .
          ignore-packages: package-a,package-b

      - name: Show output
        run: |
          echo "${{ steps.license.outputs.stdout }}"

      - name: Write summary
        run: |
          {
            echo "## Security Checker"
            echo ""
            echo "### License Summary"
            echo "${{ steps.license.outputs.stdout }}"
          } >> "$GITHUB_STEP_SUMMARY"
```
