from pathlib import Path

from security_checker.vendors._models import Dependencies, Dependency
from security_checker.vendors.registries.pypi import PyPiRegistry


class PoetryVendor(PyPiRegistry):
    @property
    def name(self) -> str:
        return "Python Poetry"

    @property
    def dependency_manager_name(self) -> str:
        return "poetry"

    @property
    def supported_lockfiles(self) -> set[str]:
        return {"poetry.lock"}

    def get_lockfile_dependencies(self, file_path: Path) -> Dependencies:
        packages: list[Dependency] = []
        current_name: str | None = None
        current_version: str | None = None

        # Open the poetry.lock file and read its contents
        with file_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # Check for the start of a package entry
                if line == "[[package]]":
                    current_name = current_version = None
                elif line.startswith("name = "):
                    current_name = line.split("=", 1)[1].strip().strip('"')
                elif line.startswith("version = "):
                    current_version = line.split("=", 1)[1].strip().strip('"')
                    if current_name:
                        # If both name and version are found, create a Dependency object
                        packages.append(
                            Dependency(
                                name=current_name,
                                version=current_version,
                            )
                        )
                        current_name, current_version = None, None

        return Dependencies(file_path=file_path, dependencies=packages)
