import asyncio
from abc import abstractmethod
from collections.abc import Sequence
from pathlib import Path

from security_checker.checkers.credentials._models import CredentialAlert
from security_checker.vendors._base import VendorBase


class CredentialCheckerTrait(VendorBase):
    @property
    @abstractmethod
    def supported_file_extensions(self) -> set[str]: ...

    @property
    @abstractmethod
    def credential_patterns(self) -> dict[str, str]: ...

    @abstractmethod
    def scan_file_for_credentials(
        self, file_path: Path
    ) -> Sequence[CredentialAlert]: ...

    @abstractmethod
    async def validate_credential(self, credential: CredentialAlert) -> bool: ...

    async def validate_credentials(
        self, credentials: Sequence[CredentialAlert]
    ) -> Sequence[CredentialAlert]:
        tasks = [self.validate_credential(credential) for credential in credentials]
        validations = await asyncio.gather(*tasks)

        return [
            credential
            for credential, is_valid in zip(credentials, validations)
            if is_valid
        ]
