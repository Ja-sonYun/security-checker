import os

from openai import AsyncClient
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class LLMSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="")

    llm_endpoint: str | None = Field(
        default=None,
        description="The endpoint for the LLM service.",
    )
    llm_api_key: SecretStr | None = Field(
        default_factory=lambda: (
            SecretStr(openai_api_key)
            if (openai_api_key := os.getenv("OPENAI_API_KEY"))
            else None
        ),
        description="The API key for the LLM service.",
    )
    llm_summarize_model: str = Field(
        default="o4-mini",
        description="The model to use for summarizing licenses with LLM.",
    )

    def get_client(self) -> AsyncClient:
        if self.llm_endpoint and self.llm_api_key:
            return AsyncClient(
                base_url=self.llm_endpoint,
                api_key=self.llm_api_key.get_secret_value(),
            )

        return AsyncClient()
