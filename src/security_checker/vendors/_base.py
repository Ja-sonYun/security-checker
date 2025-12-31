from abc import ABC, abstractproperty
from pathlib import Path
from typing import ClassVar

from security_checker.database import Database


class VendorBase(ABC):
    db_path: ClassVar[Path | None] = None

    @abstractproperty
    def name(self) -> str: ...

    @abstractproperty
    def get_ecosystem_name(self) -> str: ...

    def get_db(self) -> Database | None:
        if self.db_path is None:
            return None
        return Database(db_path=self.db_path)
