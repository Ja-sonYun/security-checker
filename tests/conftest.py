from pathlib import Path

import pytest


@pytest.fixture
def lockfile_fixture_path() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / "lockfiles"
