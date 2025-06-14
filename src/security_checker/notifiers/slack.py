from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from slack_sdk.web.async_client import AsyncWebClient

from security_checker.checkers._models import CheckResultInterface
from security_checker.console import console
from security_checker.notifiers._base import NotifierBase


class SlackSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="")

    slack_token: SecretStr | None = Field(
        default=None,
        description="The Slack API token for sending notifications.",
    )
    slack_channel_id: str | None = Field(
        default=None,
        description="The Slack channel ID to send notifications to.",
    )


class SlackNotifier(NotifierBase):
    def __init__(
        self,
        path: Path,
        settings: SlackSettings | None = None,
    ) -> None:
        super().__init__(path)

        self.settings = settings or SlackSettings()

        if not self.settings.slack_token or not self.settings.slack_channel_id:
            raise ValueError(
                "Slack token and channel ID must be provided in the settings."
            )

        self.client = AsyncWebClient(token=self.settings.slack_token.get_secret_value())
        self.channel_id = self.settings.slack_channel_id

    async def send_notification(self, result: CheckResultInterface) -> bool:
        console.verbose("Generating summary for result with llm...")
        llm_summary = await result.llm_summary()
        console.print(llm_summary)

        try:
            console.verbose("Sending notification to Slack...")
            await self.client.chat_postMessage(
                channel=self.channel_id,
                text=f"## {result.checker_name} Results for {self.remote} on branch {self.branch}:\n{llm_summary}",
                blocks=[
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"Security Check Results for {self.remote} on branch {self.branch}",
                            "emoji": True,
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": llm_summary,
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "For more details, visit the repository security page.",
                        },
                        "accessory": {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "Open",
                                "emoji": True,
                            },
                            "url": f"{self.repository_url}/security/dependabot",
                        },
                    },
                ],
            )

            return True
        except Exception as e:
            console.error(f"Error sending notification to Slack: {e}")
            return False
