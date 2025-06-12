from pathlib import Path

from security_checker.vendors._models import Dependencies, Dependency
from security_checker.vendors.registries.pypi import PyPiRegistry


class RyeVendor(PyPiRegistry):
    @property
    def name(self) -> str:
        return "Rye"

    @property
    def dependency_manager_name(self) -> str:
        return "rye"

    @property
    def supported_lockfiles(self) -> set[str]:
        return {"requirements.lock", "requirements-dev.lock"}

    def get_lockfile_dependencies(self, file_path: Path) -> Dependencies:
        packages: list[Dependency] = []

        with file_path.open("r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()

                if not line or line.startswith("#"):
                    continue

                if line.startswith("-e") or line.startswith("--"):
                    continue

                if "==" not in line:
                    continue

                requirement_part = line.split(";", 1)[0].split("--hash", 1)[0].strip()

                name_part, version_part = requirement_part.split("==", 1)
                name = name_part.split("[", 1)[0].strip()
                version = version_part.strip()

                packages.append(Dependency(name=name, version=version))

        return Dependencies(file_path=file_path, dependencies=packages)
