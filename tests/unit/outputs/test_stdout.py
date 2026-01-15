from pathlib import Path

import pytest

from security_checker.outputs.stdout import StdoutOutput
from security_checker.checkers._models import CheckResultInterface


class DummyResult(CheckResultInterface):
    @property
    def checker_name(self) -> str:
        return "Dummy"

    def get_summary(self) -> str:
        return "summary"

    def get_details(self) -> list[str]:
        return ["detail1", "detail2"]


@pytest.mark.asyncio
async def test_stdout_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    printed: list[str] = []

    def _fake_print(*args: object, **kwargs: object) -> None:
        printed.append(" ".join(str(a) for a in args))

    monkeypatch.setattr("security_checker.console.console.print", _fake_print)
    monkeypatch.setattr(
        "security_checker.outputs._base.get_git_info",
        lambda _path: {
            "branch": "main",
            "commit": "deadbeef",
            "remote": "git@github.com:dummy/repo.git",
            "user": "dummy",
            "repo": "repo",
        },
    )

    output = StdoutOutput(tmp_path)
    result = DummyResult()

    ok = await output.write_output(result)

    assert ok is True
    assert "summary" in printed[0]
    assert any("detail1" in line for line in printed)
