from pathlib import Path

import yaml

from security_checker.console import console
from security_checker.vendors._models import Dependencies, Dependency
from security_checker.vendors.registries.npm import NpmJSRegistry


class PnpmVendor(NpmJSRegistry):
    @property
    def name(self) -> str:
        return "Node.js PNPM"

    @property
    def dependency_manager_name(self) -> str:
        return "pnpm"

    @property
    def supported_lockfiles(self) -> set[str]:
        return {"pnpm-lock.yaml"}

    def get_lockfile_dependencies(self, file_path: Path) -> Dependencies:
        packages: list[Dependency] = []

        with file_path.open("r", encoding="utf-8") as f:
            lock_data = yaml.safe_load(f)

        if "packages" in lock_data and isinstance(lock_data["packages"], dict):
            for raw_key in lock_data["packages"].keys():
                key = raw_key.lstrip("/")
                if not key:
                    continue

                # Remove peer dependencies and version suffixes
                base = key.split("(", 1)[0]

                # Split the base into name and version
                try:
                    name, version = base.rsplit("@", 1)
                except ValueError:
                    console.warning(
                        f"Invalid package format in {file_path}: {base}. Skipping."
                    )
                    continue

                packages.append(Dependency(name=name, version=version))

        return Dependencies(file_path=file_path, dependencies=packages)
