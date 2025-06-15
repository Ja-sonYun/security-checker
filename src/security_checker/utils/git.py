import re
from pathlib import Path
from urllib.parse import urlparse

from git import GitCommandError, Repo


def find_git_root(path: Path) -> Path | None:
    current_path = path.resolve()
    while current_path != current_path.parent:
        if (current_path / ".git").is_dir():
            return current_path
        current_path = current_path.parent
    return None


def parse_github_ref(url: str) -> tuple[str, str]:
    ssh_match = re.match(
        r"git@github\.com:(?P<user>[^/]+)/(?P<repo>.+?)(?:\.git)?$", url
    )
    if ssh_match:
        return ssh_match["user"], ssh_match["repo"]

    parsed = urlparse(url)
    if parsed.scheme in {"http", "https"} and parsed.netloc == "github.com":
        user, repo = Path(parsed.path.lstrip("/")).parts[:2]
        return user, repo.removesuffix(".git")

    raise ValueError(f"Invalid GitHub URL: {url}")


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

    user, repo_name = (
        parse_github_ref(repo.remotes[0].url)
        if repo.remotes
        else ("unknown", "unknown")
    )

    return {
        "branch": branch,
        "commit": repo.head.commit.hexsha,
        "remote": repo.remotes[0].url if repo.remotes else "No remote",
        "user": user,
        "repo": repo_name,
    }
