from __future__ import annotations

from pathlib import Path

import pytest

import security_checker.utils.git as git_utils


class DummyRepo:
    class DummyHead:
        class DummyCommit:
            hexsha = "deadbeef"

        commit = DummyCommit()

    head = DummyHead()

    class DummyRemote:
        url = "git@github.com:dummy/repo.git"

    remotes = [DummyRemote()]

    class DummyGit:
        @staticmethod
        def symbolic_ref(*_args, **_kwargs) -> str:
            return "main"

    git = DummyGit()

    @property
    def active_branch(self):
        raise TypeError("detached")


def test_parse_github_ref_ssh() -> None:
    user, repo = git_utils.parse_github_ref("git@github.com:octo/test.git")
    assert user == "octo"
    assert repo == "test"


def test_parse_github_ref_https() -> None:
    user, repo = git_utils.parse_github_ref("https://github.com/octo/test")
    assert user == "octo"
    assert repo == "test"


def test_parse_github_ref_invalid() -> None:
    with pytest.raises(ValueError):
        git_utils.parse_github_ref("https://example.com/invalid")


def test_find_git_root(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    nested = root / "a" / "b"
    nested.mkdir(parents=True)
    (root / ".git").mkdir()

    assert git_utils.find_git_root(nested) == root


def test_get_git_info(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    monkeypatch.setattr(git_utils, "find_git_root", lambda _p: repo_path)
    monkeypatch.setattr(git_utils, "Repo", lambda _p: DummyRepo())

    info = git_utils.get_git_info(repo_path)

    assert info["branch"] == "main"
    assert info["commit"] == "deadbeef"
    assert info["user"] == "dummy"
    assert info["repo"] == "repo"
