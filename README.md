# Security Checker

A comprehensive command-line tool to check security-related issues in your projects, including vulnerability scanning and license compliance checking.

## Features

- **Vulnerability Scanning**: Check for known security vulnerabilities in your project dependencies
- **License Compliance**: Verify and analyze license compatibility of your dependencies
- **Multi-Package Manager Support**: Works with Poetry, npm, pnpm, pip (requirements.txt), and Rye
- **Multiple Output Formats**: Support for stdout, Slack notifications, and Markdown reports
- **Extensible Architecture**: Easy to add new package managers and notification methods

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

## Configuration

### Slack Notifications

To use Slack notifications, set the following environment variables:

```bash
export SLACK_BOT_TOKEN="xoxb-your-bot-token"
export SLACK_CHANNEL="#your-channel"
```

### LLM Summary generation requires an OpenAI API key:

```bash
export LLM_API_KEY="your-openai-api-key"
export LLM_SUMMARIZE_MODEL="o4-mini"
export LLM_ENDPOINT="https://api.openai.com/v1"
```

## Development

### Requirements

- Python >= 3.10
- Rye

### Setup Development Environment

```bash
git clone https://github.com/Ja-sonYun/security-checker.git
cd security-checker

rye sync
```

### Code Quality

This project uses:

- **Ruff**: For linting and code formatting
- **Type hints**: Full type annotation coverage

Run code quality checks:

```bash
ruff check .
ruff format .
```

### Project Structure

```
src/security_checker/
├── checkers/            # Core checking logic
│   ├── credentials/     # Credential scanning (TODO)
│   ├── licenses/        # License compliance checking
│   └── vulnerabilities/ # Vulnerability scanning
├── notifiers/           # Output and notification handlers
├── vendors/             # Package manager integrations
├── utils/               # Utility functions
└── cli.py               # Command-line interface
```

### Adding New Package Managers

1. Create a new vendor class in `src/security_checker/vendors/`
2. Implement the required traits for license and/or vulnerability checking
3. Add the vendor to the supported vendors list in `cli.py`

### Adding New Notification Methods

1. Create a new notifier class in `src/security_checker/notifiers/`
2. Extend the `NotifierBase` class
3. Add the notifier to the supported notifiers list in `cli.py`
