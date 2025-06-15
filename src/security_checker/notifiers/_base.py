from abc import ABC, abstractmethod
from pathlib import Path

from security_checker.checkers._models import CheckResultInterface
from security_checker.utils.git import get_git_info


class NotifierBase(ABC):
    def __init__(self, path: Path) -> None:
        self.path = path
        git_info = get_git_info(path)
        self.branch = git_info.get("branch", "unknown")
        self.commit = git_info.get("commit", "unknown")
        self.remote = git_info.get("remote", "unknown")
        self.user = git_info.get("user", "unknown")
        self.repo = git_info.get("repo", "unknown")
        self.repository_url = f"https://github.com/{self.user}/{self.repo}"

        print(
            f"Notifier initialized for repository {self.user}/{self.repo} "
            f"on branch {self.branch} with remote {self.remote}."
        )

    @abstractmethod
    async def send_notification(self, result: CheckResultInterface) -> bool: ...
