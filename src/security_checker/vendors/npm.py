import json
from pathlib import Path

from security_checker.vendors._models import Dependencies, Dependency
from security_checker.vendors.registries.npm import NpmJSRegistry


class NpmVendor(NpmJSRegistry):
    @property
    def name(self) -> str:
        return "Node.js NPM"

    @property
    def dependency_manager_name(self) -> str:
        return "npm"

    @property
    def supported_lockfiles(self) -> set[str]:
        return {"package-lock.json"}

    def get_lockfile_dependencies(self, file_path: Path) -> Dependencies:
        packages: list[Dependency] = []

        with file_path.open("r", encoding="utf-8") as f:
            lock_data = json.load(f)

        # Handle different package-lock.json formats
        if "packages" in lock_data:
            # lockfileVersion 2 or 3
            for package_path, package_info in lock_data["packages"].items():
                if package_path == "":  # Root package
                    continue

                # Extract package name from path
                package_name = package_path.split("node_modules/")[-1]
                version = package_info.get("version")

                if version:
                    packages.append(
                        Dependency(
                            name=package_name,
                            version=version,
                        )
                    )
        elif "dependencies" in lock_data:
            # lockfileVersion 1
            self._extract_dependencies_v1(lock_data["dependencies"], packages)

        return Dependencies(file_path=file_path, dependencies=packages)

    def _extract_dependencies_v1(
        self, dependencies: dict, packages: list[Dependency]
    ) -> None:
        """Extract dependencies from lockfileVersion 1 format"""
        for name, info in dependencies.items():
            version = info.get("version")
            if version:
                packages.append(
                    Dependency(
                        name=name,
                        version=version,
                    )
                )

            # Recursively process nested dependencies
            if "dependencies" in info:
                self._extract_dependencies_v1(info["dependencies"], packages)
