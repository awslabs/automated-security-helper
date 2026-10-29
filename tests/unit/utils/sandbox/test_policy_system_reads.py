"""The fixed system read paths never grant a sandboxed tool the user's home tree."""

from pathlib import Path

import pytest

from automated_security_helper.utils.sandbox import policy
from automated_security_helper.utils.sandbox.policy import _existing, _under_home

pytestmark = pytest.mark.unit


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A home directory under ``tmp_path`` that ``Path.home()`` reports."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", staticmethod(lambda: fake_home))
    return fake_home


def test_under_home_is_true_for_home_itself_and_its_descendants(home: Path):
    """The home directory and anything below it are under home."""
    nested = home / "share" / "tools"
    nested.mkdir(parents=True)

    assert _under_home(home) is True
    assert _under_home(home / "share") is True
    assert _under_home(nested) is True


def test_under_home_is_false_outside_home(home: Path, tmp_path: Path):
    """A sibling of home, home's parent, and a name that merely starts with home's are outside it."""
    sibling = tmp_path / "opt"
    sibling.mkdir()
    lookalike = tmp_path / "home2"
    lookalike.mkdir()

    assert _under_home(sibling) is False
    assert _under_home(tmp_path) is False
    assert _under_home(lookalike) is False


def test_system_read_paths_under_home_are_dropped_before_existing(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The policy's filter keeps a system read path outside home and drops one under it."""
    outside = tmp_path / "usr"
    outside.mkdir()
    inside = home / ".local"
    inside.mkdir()
    monkeypatch.setattr(
        policy, "SYSTEM_READ_PATHS", (outside.as_posix(), inside.as_posix())
    )

    kept = _existing(
        [p for p in (Path(p) for p in policy.SYSTEM_READ_PATHS) if not _under_home(p)]
    )

    assert kept == [outside.absolute()]
