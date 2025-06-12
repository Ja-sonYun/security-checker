from pathlib import Path

from pydantic import BaseModel


class Dependency(BaseModel):
    name: str
    version: str


class Dependencies(BaseModel):
    file_path: Path
    dependencies: list[Dependency]


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
