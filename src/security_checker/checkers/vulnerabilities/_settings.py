from pydantic import Field

from security_checker.checkers._settings import LLMSettings


class VulnerabilityCheckerSettings(LLMSettings):
    llm_vulnerability_summarize_prompt: str = Field(
        default="""\
You are a security expert analyzing software vulnerabilities.
Your task is to provide a detailed summary of vulnerabilities found in software dependencies,

Please summarize the vulnerabilities in 300 words or less, focusing on the most critical issues and their potential impact on the software's security posture.
        """,
        description="Path to the prompt file for summarizing non-commercial licenses using LLM.",
    )
