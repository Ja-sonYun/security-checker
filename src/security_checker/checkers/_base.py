from abc import ABC, abstractmethod
from collections.abc import Sequence
from pathlib import Path
from typing import Generic, TypeVar

from security_checker.checkers._models import CheckResultBase
from security_checker.vendors._base import VendorBase
from security_checker.vendors._models import Dependencies

_ResultType = TypeVar("_ResultType", bound=CheckResultBase)
_VendorTraitType = TypeVar("_VendorTraitType", bound=VendorBase)


class CheckerBase(ABC, Generic[_VendorTraitType, _ResultType]):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    async def run(
        self,
        project_path: Path,
        vendors: Sequence[_VendorTraitType],
    ) -> _ResultType: ...

    @staticmethod
    def _travel_project(project_path: Path) -> list[Path]:
        if not project_path.is_dir():
            raise ValueError(f"{project_path} is not a valid directory.")

        files: list[Path] = []
        for path in project_path.rglob("*"):
            if path.is_file():
                files.append(path)

        return files


class LockFileBaseTrait(ABC):
    @property
    @abstractmethod
    def supported_lockfiles(self) -> set[str]: ...

    @property
    @abstractmethod
    def dependency_manager_name(self) -> str: ...

    @abstractmethod
    def get_lockfile_dependencies(self, file_path: Path) -> Dependencies: ...
