import re
from pathlib import Path

from security_checker.vendors._models import Dependencies, Dependency
from security_checker.vendors.registries.pypi import PyPiRegistry


class RequirementsTxtVendor(PyPiRegistry):
    @property
    def name(self) -> str:
        return "Python requirements.txt"

    @property
    def dependency_manager_name(self) -> str:
        return "requirements.txt"

    @property
    def supported_lockfiles(self) -> set[str]:
        return {"requirements.txt"}

    def get_lockfile_dependencies(self, file_path: Path) -> Dependencies:
        packages: list[Dependency] = []
        text = file_path.read_text(encoding="utf-8")

        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # Remove comments
            if "#" in line:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue

            # Extract package name and version
            name = ""
            version = ""
            if "==" in line:
                name, version = line.split("==", 1)
            elif ">=" in line:
                name, version = line.split(">=", 1)
            elif "<=" in line:
                name, version = line.split("<=", 1)
            elif "~=" in line:
                name, version = line.split("~=", 1)
            elif ">" in line or "<" in line:
                # Handle cases with multiple comparison operators
                parts = re.split(r"[><]+", line, 1)
                name = parts[0]
                version = parts[1] if len(parts) > 1 else ""
            else:
                # If no version is specified, treat the whole line as the package name
                name = line
                version = ""

            packages.append(
                Dependency(
                    name=name.strip(),
                    version=version.strip().strip('"').strip("'"),
                )
            )

        return Dependencies(file_path=file_path, dependencies=packages)
