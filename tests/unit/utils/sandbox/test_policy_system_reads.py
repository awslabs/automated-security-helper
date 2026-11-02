"""The fixed system read paths never grant a sandboxed tool the user's home tree."""

import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.sandbox import policy
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    _homes,
    _under_home,
    build_scanner_policy,
)

pytestmark = pytest.mark.unit


def _fake_home(path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``Path.home()`` reports ``path`` and the passwd entry names no second home."""
    monkeypatch.setattr(Path, "home", staticmethod(lambda: path))
    monkeypatch.setattr(policy, "_passwd_home", lambda: None)


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A home directory under ``tmp_path`` that ``Path.home()`` reports."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    _fake_home(fake_home, monkeypatch)
    return fake_home


def _policy_read_only(tmp_path: Path) -> set:
    """The resolved read-only paths one scanner gets, with no network and no cwd."""
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    built = build_scanner_policy(
        "probe",
        SandboxRequirements(),
        argv0="/bin/true",
        source_dir=source,
        output_dir=output,
        results_dir=output / "results",
        scan_target=None,
        cwd=None,
        offline=True,
        network_scanners=None,
    )
    return {os.path.realpath(p) for p in built.read_only}


def test_under_home_is_true_for_home_itself_and_its_descendants(home: Path):
    """The home directory and anything below it are under home."""
    nested = home / "share" / "tools"
    nested.mkdir(parents=True)

    assert _homes() == [Path(os.path.realpath(home))]
    assert _under_home(home, _homes()) is True
    assert _under_home(home / "share", _homes()) is True
    assert _under_home(nested, _homes()) is True


def test_under_home_is_false_outside_home(home: Path, tmp_path: Path):
    """A sibling of home, home's parent, and a name that merely starts with home's are outside it."""
    sibling = tmp_path / "opt"
    sibling.mkdir()
    lookalike = tmp_path / "home2"
    lookalike.mkdir()

    assert _under_home(sibling, _homes()) is False
    assert _under_home(tmp_path, _homes()) is False
    assert _under_home(lookalike, _homes()) is False


def test_policy_drops_a_system_read_path_under_home(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A system read path under home is absent from read_only; one outside it stays."""
    outside = tmp_path / "usr"
    outside.mkdir()
    inside = home / ".local"
    inside.mkdir()
    monkeypatch.setattr(
        policy, "SYSTEM_READ_PATHS", (outside.as_posix(), inside.as_posix())
    )

    read_only = _policy_read_only(tmp_path)

    assert os.path.realpath(outside) in read_only
    assert os.path.realpath(inside) not in read_only


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="the policy's home set leaves out the POSIX root only",
)
def test_a_root_home_drops_no_system_read_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """With HOME set to the filesystem root, as in some containers, every system path survives."""
    _fake_home(Path("/"), monkeypatch)
    first = tmp_path / "usr"
    first.mkdir()
    second = tmp_path / "etc"
    second.mkdir()
    monkeypatch.setattr(
        policy, "SYSTEM_READ_PATHS", (first.as_posix(), second.as_posix())
    )

    assert _homes() == []
    assert _under_home(first, _homes()) is False

    read_only = _policy_read_only(tmp_path)

    assert os.path.realpath(first) in read_only
    assert os.path.realpath(second) in read_only
