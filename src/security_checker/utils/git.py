from pathlib import Path

from git import GitCommandError, Repo


def find_git_root(path: Path) -> Path | None:
    current_path = path.resolve()
    while current_path != current_path.parent:
        if (current_path / ".git").is_dir():
            return current_path
        current_path = current_path.parent
    return None


def get_git_info(path: Path) -> dict[str, str]:
    git_root = find_git_root(path)
    if not git_root:
        raise ValueError(f"No Git repository found: {path}")

    repo = Repo(git_root)

    try:
        branch = repo.active_branch.name
    except TypeError:
        try:
            branch = repo.git.symbolic_ref("--short", "-q", "HEAD").strip()
            branch = branch or "DETACHED_HEAD"
        except GitCommandError:
            branch = "DETACHED_HEAD"

    return {
        "branch": branch,
        "commit": repo.head.commit.hexsha,
        "remote": repo.remotes[0].url if repo.remotes else "No remote",
    }
