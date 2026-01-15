import asyncio
from abc import ABC, abstractmethod
from typing import ClassVar

from security_checker.database import Database

# Shared semaphore for rate limiting all external API calls
api_semaphore = asyncio.Semaphore(10)


class VendorBase(ABC):
    db: ClassVar[Database | None] = None

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def get_ecosystem_name(self) -> str: ...
