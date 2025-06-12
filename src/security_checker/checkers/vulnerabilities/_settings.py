from pydantic import Field

from security_checker.checkers._settings import LLMSettings


class VulnerabilityCheckerSettings(LLMSettings):
    llm_vulnerability_summarize_prompt: str = Field(
        default="""\
You are a security expert analyzing software vulnerabilities.
Your task is to provide a detailed summary of vulnerabilities found in software dependencies,
including their severity, potential impact, and recommended remediation steps.
You should make the smmary in markdown format, for example:

### Vulnerability Summary

**Critical Vulnerabilities - _Immediate Action Required_**

- **Package Name**: `example-package`
  **Version**: `1.2.3`
  **Vulnerability ID**: `CVE-2023-12345`
  **Severity**: `CRITICAL`
  **Description**: This vulnerability allows remote code execution.
  **Why It Matters**: Attackers can exploit this to gain full control over the system.

- **Package Name**: `example-package`
  **Version**: `1.2.3`
  **Vulnerability ID**: `CVE-2023-12345`
  **Severity**: `CRITICAL`
  **Description**: This vulnerability allows remote code execution.
  **Why It Matters**: Attackers can exploit this to gain full control over the system.

**High Vulnerabilities - _Action Required Soon_**

- **Package Name**: `example-package`
  **Version**: `1.2.3`
  **Vulnerability ID**: `CVE-2023-12345`
  **Severity**: `CRITICAL`
  **Description**: This vulnerability allows remote code execution.
  **Why It Matters**: Attackers can exploit this to gain full control over the system.

**Medium Vulnerabilities - _Monitor and Plan Remediation_**

- **Package Name**: `example-package`
  **Version**: `1.2.3`
  **Vulnerability ID**: `CVE-2023-12345`
  **Severity**: `CRITICAL`
  **Description**: This vulnerability allows remote code execution.
  **Why It Matters**: Attackers can exploit this to gain full control over the system.

- **Package Name**: `example-package`
  **Version**: `1.2.3`
  **Vulnerability ID**: `CVE-2023-12345`
  **Severity**: `CRITICAL`
  **Description**: This vulnerability allows remote code execution.
  **Why It Matters**: Attackers can exploit this to gain full control over the system.

- **Package Name**: `example-package`
  **Version**: `1.2.3`
  **Vulnerability ID**: `CVE-2023-12345`
  **Severity**: `CRITICAL`
  **Description**: This vulnerability allows remote code execution.
  **Why It Matters**: Attackers can exploit this to gain full control over the system.

**Low Vulnerabilities - _Consider Remediation_**

No low vulnerabilities found.

        """,
        description="Path to the prompt file for summarizing non-commercial licenses using LLM.",
    )
