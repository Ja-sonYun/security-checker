# Security Checker

A comprehensive command-line tool to check security-related issues in your projects, including vulnerability scanning and license compliance checking.

## Features

- **Vulnerability Scanning**: Check for known security vulnerabilities in your project dependencies
- **License Compliance**: Verify and analyze license compatibility of your dependencies
- **Multi-Package Manager Support**: Works with Poetry, npm, pnpm, pip (requirements.txt), and uv
- **Output to Stdout**: Print summaries and details directly to stdout
- **Extensible Architecture**: Easy to add new package managers

## Installation

### From PyPI

```bash
pip install security-checker
```

## Usage

Security Checker provides two main commands: `license` for license checking and `vuln` for vulnerability scanning.

### License Checking

Check license compliance of your project dependencies:

```bash
# With default settings (all supported package managers)
security-checker license /path/to/your/project
```

### Vulnerability Scanning

Scan for security vulnerabilities in your dependencies:

```bash
# With default settings (all supported package managers)
security-checker vuln /path/to/your/project
```

## Development

### Requirements

- Python >= 3.10
- [uv](https://docs.astral.sh/uv/) 0.4 or newer

### Setup Development Environment

```bash
git clone https://github.com/Ja-sonYun/security-checker.git
cd security-checker

uv sync --group dev
source .venv/bin/activate
```

### Code Quality

This project uses:

- **Ruff**: For linting and code formatting
- **Type hints**: Full type annotation coverage

Run code quality checks:

```bash
uv run ruff check .
uv run ruff format .
```

### Project Structure

```
src/security_checker/
├── checkers/            # Core checking logic
│   ├── credentials/     # Credential scanning (TODO)
│   ├── licenses/        # License compliance checking
│   └── vulnerabilities/ # Vulnerability scanning
├── outputs/             # Stdout output handlers
├── vendors/             # Package manager integrations
├── utils/               # Utility functions
└── cli.py               # Command-line interface
```

### Adding New Package Managers

1. Create a new vendor class in `src/security_checker/vendors/`
2. Implement the required traits for license and/or vulnerability checking
3. Add the vendor to the supported vendors list in `cli.py`

## To-Do

- [ ] Implement credential scanning
- [ ] Support result caching to avoid redundant checks
- [ ] Add unit tests for all components
