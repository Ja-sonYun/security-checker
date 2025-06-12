from pathlib import Path


def find_git_root(path: Path) -> Path | None:
    current_path = path.resolve()
    while current_path != current_path.parent:
        if (current_path / ".git").is_dir():
            return current_path
        current_path = current_path.parent
    return None
