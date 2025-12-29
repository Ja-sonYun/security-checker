from __future__ import annotations

from pathlib import Path
from typing import Any

try:  # Python 3.11+
    import tomllib as toml  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover - fallback for Python 3.10
    import tomli as toml  # type: ignore[no-redef]

from security_checker.vendors._models import Dependencies, Dependency
from security_checker.vendors.registries.pypi import PyPiRegistry


class UvVendor(PyPiRegistry):
    @property
    def name(self) -> str:
        return "Python uv"

    @property
    def dependency_manager_name(self) -> str:
        return "uv"

    @property
    def supported_lockfiles(self) -> set[str]:
        return {"uv.lock"}

    def get_lockfile_dependencies(self, file_path: Path) -> Dependencies:
        packages: list[Dependency] = []
        data = self._load_lockfile(file_path)

        for package in data.get("package", []):
            name = package.get("name")
            version = package.get("version")
            source = package.get("source", {})

            if not name or not version:
                continue

            if self._is_editable_source(source):
                continue

            packages.append(Dependency(name=name, version=str(version)))

        return Dependencies(file_path=file_path, dependencies=packages)

    @staticmethod
    def _load_lockfile(file_path: Path) -> dict[str, Any]:
        with file_path.open("rb") as lock_file:
            return toml.load(lock_file)

    @staticmethod
    def _is_editable_source(source: Any) -> bool:
        if not isinstance(source, dict):
            return False
        editable = source.get("editable")
        return isinstance(editable, str)
