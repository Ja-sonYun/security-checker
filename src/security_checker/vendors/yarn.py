from pathlib import Path

from security_checker.vendors._models import Dependencies, Dependency
from security_checker.vendors.registries.npm import NpmJSRegistry


class YarnVendor(NpmJSRegistry):
    """
    IMPORTANT: This class not yet tested.
    """

    @property
    def name(self) -> str:
        return "Node.js Yarn"

    @property
    def dependency_manager_name(self) -> str:
        return "yarn"

    @property
    def supported_lockfiles(self) -> set[str]:
        return {"yarn.lock"}

    def get_lockfile_dependencies(self, file_path: Path) -> Dependencies:
        text = file_path.read_text(encoding="utf-8")
        entries: dict[tuple[str, str], bool] = {}
        lines = text.splitlines()
        i = 0

        while i < len(lines):
            line = lines[i]
            if not line.startswith('"'):
                i += 1
                continue

            selectors = line.rstrip()[:-1]
            selectors = [s.strip().strip('"') for s in selectors.split(",")]

            version = None
            i += 1
            while i < len(lines) and lines[i].startswith("  "):
                inner = lines[i].strip()
                if inner.startswith("version "):
                    version = inner.split(" ", 1)[1].strip().strip('"')
                    break
                i += 1

            if version:
                for sel in selectors:
                    name = sel.rsplit("@", 1)[0]
                    entries[(name, version)] = True

            while i < len(lines) and lines[i].strip():
                i += 1

        deps = [Dependency(name=n, version=v) for n, v in entries.keys()]
        return Dependencies(file_path=file_path, dependencies=deps)
