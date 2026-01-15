from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel

from security_checker.checkers._models import CheckResultBase


class CredentialAlert(BaseModel):
    file_path: Path
    line_number: int
    content: str
    credential_type: str
    severity: str


class CredentialCheckResult(CheckResultBase):
    credentials: Sequence[CredentialAlert]

    @property
    def checker_name(self) -> str:
        return "Credential Checker"

    def get_summary(self) -> str:
        return f"Found {len(self.credentials)} potential credential leaks."

    def get_details(self) -> Sequence[str]:
        details = []
        for credential in self.credentials:
            details.append(
                f"{credential.file_path}:{credential.line_number} "
                f"- {credential.credential_type} ({credential.severity})..."
            )
        return details
