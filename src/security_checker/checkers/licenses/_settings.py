from pydantic import Field

from security_checker.checkers._settings import LLMSettings


class LicenseCheckerSettings(LLMSettings):
    llm_non_commercial_license_summary_prompt: str = Field(
        default=(
            "You are a helpful assistant that provides information "
            "with markdown about software licenses. "
            "If there is a license that may affect to development the commercial software, "
            "like GPL, AGPL, or similar, please summarize it in a way that "
            "is easy to understand for a developer. "
            "If nothing may affect to development the commercial software, "
            "just return 'No non-commercial licenses found.'"
        ),
        description="Path to the prompt file for summarizing non-commercial licenses using LLM.",
    )
