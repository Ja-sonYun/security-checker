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


class DependencyRoot(BaseModel):
    root: Path
    package_manager: str

    def __hash__(self):
        return hash((self.root, self.package_manager))

    def __str__(self):
        return f"{self.package_manager}://{self.root}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DependencyRoot):
            return NotImplemented
        return self.root == other.root and self.package_manager == other.package_manager

    def __ne__(self, other: object) -> bool:
        if not isinstance(other, DependencyRoot):
            return NotImplemented
        return not self.__eq__(other)


class CredentialCheckResult(CheckResultBase):
    credentials: Sequence[CredentialAlert]

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
