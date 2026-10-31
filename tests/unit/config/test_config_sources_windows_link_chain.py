# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""On Windows a discovered link is refused unresolved only when its chain
reaches a network share, or cannot be read.

Resolving a link on Windows can open a connection to the host a UNC target
names, so a source that is a link is not resolved before it is judged. Refusing
every link went further than that reason: a link to a local file is resolved
with nothing opened but local entries, and is judged by the permit as the file
it names, as on every other platform. ``os.readlink`` opens the link's own
entry and never its target, so the chain is read hop by hop and refused only
when a hop spells a share, a hop cannot be read, or the chain is longer than
the bound ``os.path.realpath`` applies.

The Windows branch is reached by standing in for the platform test
(``_on_windows``), with POSIX symbolic links, and with ``os.readlink`` made to
answer as Windows does for the one link under test.

Red at the base: a link to a local file, or to nothing, was refused unresolved.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.config import config_sources

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        os.name == "nt",
        reason="creating a symlink needs a privilege or Developer Mode there",
    ),
]


@pytest.fixture
def on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_sources, "_on_windows", lambda: True)


def _recording_permit(answer: bool = True):
    asked: List[Path] = []

    def permit(path: Path) -> bool:
        asked.append(path)
        return answer

    return permit, asked


def _readlink_answering(
    monkeypatch: pytest.MonkeyPatch, answers: dict[Path, str]
) -> None:
    """``os.readlink`` as Windows reads a reparse point, for the named links."""
    real = os.readlink

    def readlink(path, *args, **kwargs):
        key = Path(os.fspath(path))
        if key in answers:
            return answers[key]
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os, "readlink", readlink)


def _no_resolving(monkeypatch: pytest.MonkeyPatch) -> List[str]:
    resolved: List[str] = []
    real = os.path.realpath

    def recording(path, *args, **kwargs):
        resolved.append(os.fspath(path))
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os.path, "realpath", recording)
    return resolved


def test_a_link_to_a_local_file_is_judged_by_the_permit_as_that_file(
    tmp_path: Path, on_windows: None
) -> None:
    target = tmp_path / "target.yaml"
    target.write_text("project_name: demo\n", encoding="utf-8")
    link = tmp_path / ".ash.yaml"
    link.symlink_to(target)
    permit, asked = _recording_permit(True)

    assert config_sources._permitted(link, permit) is True

    assert asked == [Path(os.path.realpath(target))]


def test_a_link_to_a_local_file_the_permit_refuses_is_refused(
    tmp_path: Path, on_windows: None
) -> None:
    """The control: admitting a local chain hands the decision to the permit."""
    target = tmp_path / "target.yaml"
    target.write_text("project_name: demo\n", encoding="utf-8")
    link = tmp_path / ".ash.yaml"
    link.symlink_to(target)
    permit, asked = _recording_permit(False)

    assert config_sources._permitted(link, permit) is False

    assert len(asked) == 1


def test_a_link_to_nothing_is_judged_by_the_permit_not_refused_unresolved(
    tmp_path: Path, on_windows: None
) -> None:
    link = tmp_path / ".ash.yaml"
    link.symlink_to(tmp_path / "missing.yaml")
    permit, asked = _recording_permit(True)

    assert config_sources._permitted(link, permit) is True

    assert asked == [Path(os.path.realpath(tmp_path / "missing.yaml"))]


def test_a_relative_link_is_followed_from_its_own_directory(
    tmp_path: Path, on_windows: None
) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "real.yaml").write_text("x: 1\n", encoding="utf-8")
    link = tmp_path / ".ash.yaml"
    link.symlink_to(Path("sub") / "real.yaml")
    permit, asked = _recording_permit(True)

    assert config_sources._permitted(link, permit) is True

    assert asked == [Path(os.path.realpath(tmp_path / "sub" / "real.yaml"))]


@pytest.mark.parametrize(
    "spelling",
    [
        "\\\\server\\share\\config.yaml",
        "//server/share/config.yaml",
        "\\\\?\\UNC\\server\\share\\config.yaml",
        "\\\\.\\UNC\\server\\share\\config.yaml",
        "//?/UNC/server/share/config.yaml",
        "\\\\?\\unc\\server\\share\\config.yaml",
        "\\\\?\\GLOBALROOT\\Device\\LanmanRedirector\\server\\share\\config.yaml",
        "\\\\?\\GLOBALROOT\\??\\UNC\\server\\share\\config.yaml",
        "\\\\?\\GLOBALROOT\\Device\\Mup\\server\\share\\config.yaml",
        "//?/GLOBALROOT/Device/Mup/server/share/config.yaml",
        "/\\?\\GLOBALROOT\\Device\\Mup\\server\\share\\config.yaml",
        "\\\\.\\pipe\\config",
        "\\\\?\\Volume{volume-guid}\\config.yaml",
        "\\??\\UNC\\server\\share\\config.yaml",
        "\\\\server",
        "\\\\?\\C:",
        "\\\\.\\C:",
        "\\\\?\\c:",
        "//./C:",
    ],
)
def test_a_link_to_a_share_or_a_device_is_refused_without_resolving_it(
    tmp_path: Path,
    on_windows: None,
    monkeypatch: pytest.MonkeyPatch,
    spelling: str,
) -> None:
    link = tmp_path / ".ash.yaml"
    link.symlink_to(tmp_path / "anything.yaml")
    _readlink_answering(monkeypatch, {link: spelling})
    resolved = _no_resolving(monkeypatch)
    permit, asked = _recording_permit(True)

    assert config_sources._permitted(link, permit) is False

    assert asked == []
    assert resolved == []


@pytest.mark.parametrize(
    "spelling",
    [
        "\\\\?\\C:\\repo\\config.yaml",
        "\\\\.\\C:\\repo\\config.yaml",
        "\\\\?\\c:\\repo\\config.yaml",
        "\\\\?\\C:\\",
        "//?/C:/repo/config.yaml",
        "\\??\\C:\\repo\\config.yaml",
        "C:\\repo\\a.yaml",
        "\\repo\\a.yaml",
    ],
)
def test_the_extended_form_a_junction_takes_is_a_local_name_not_a_share(
    tmp_path: Path,
    on_windows: None,
    monkeypatch: pytest.MonkeyPatch,
    spelling: str,
) -> None:
    link = tmp_path / ".ash.yaml"
    link.symlink_to(tmp_path / "anything.yaml")
    _readlink_answering(monkeypatch, {link: spelling})
    permit, asked = _recording_permit(True)

    assert config_sources._permitted(link, permit) is True

    assert len(asked) == 1


def test_a_share_named_by_a_later_link_in_the_chain_is_refused(
    tmp_path: Path, on_windows: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    second = tmp_path / "second"
    second.symlink_to(tmp_path / "anything.yaml")
    first = tmp_path / ".ash.yaml"
    first.symlink_to(second)
    _readlink_answering(monkeypatch, {second: "\\\\server\\share\\config.yaml"})
    resolved = _no_resolving(monkeypatch)
    permit, asked = _recording_permit(True)

    assert config_sources._permitted(first, permit) is False

    assert asked == []
    assert resolved == []


def test_a_link_whose_target_cannot_be_read_is_refused_unresolved(
    tmp_path: Path, on_windows: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = tmp_path / ".ash.yaml"
    link.symlink_to(tmp_path / "anything.yaml")

    def unreadable(path, *args, **kwargs):
        raise OSError("not a symbolic link or junction")

    monkeypatch.setattr(os, "readlink", unreadable)
    resolved = _no_resolving(monkeypatch)
    permit, asked = _recording_permit(True)

    assert config_sources._permitted(link, permit) is False

    assert asked == []
    assert resolved == []


def test_a_hop_that_cannot_be_examined_is_refused_unresolved(
    tmp_path: Path, on_windows: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hop under a directory that cannot be searched is not absent: it may be
    a link whose own target was never read and names a share."""
    second = tmp_path / "second"
    second.symlink_to(tmp_path / "anything.yaml")
    first = tmp_path / ".ash.yaml"
    first.symlink_to(second)
    real_lstat = os.lstat

    def lstat(path, *args, **kwargs):
        if Path(os.fspath(path)) == second:
            raise PermissionError(13, "Permission denied")
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)
    resolved = _no_resolving(monkeypatch)
    permit, asked = _recording_permit(True)

    assert config_sources._permitted(first, permit) is False

    assert asked == []
    assert resolved == []


def test_a_hop_that_is_not_there_is_a_local_name(
    tmp_path: Path, on_windows: None
) -> None:
    """The control for the test above: an absent hop ends the walk as local."""
    first = tmp_path / ".ash.yaml"
    first.symlink_to(tmp_path / "gone" / "anything.yaml")
    permit, asked = _recording_permit(True)

    assert config_sources._permitted(first, permit) is True

    assert len(asked) == 1


def test_a_reparse_point_that_is_no_symbolic_link_is_refused_unresolved(
    tmp_path: Path, on_windows: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CPython raises ValueError, not OSError, from ``os.readlink`` for a
    reparse point that is neither a symbolic link nor a junction."""
    link = tmp_path / ".ash.yaml"
    link.symlink_to(tmp_path / "anything.yaml")

    def not_a_symlink(path, *args, **kwargs):
        raise ValueError("not a symbolic link")

    monkeypatch.setattr(os, "readlink", not_a_symlink)
    resolved = _no_resolving(monkeypatch)
    permit, asked = _recording_permit(True)

    assert config_sources._permitted(link, permit) is False

    assert asked == []
    assert resolved == []


def _chain(tmp_path: Path, links: int) -> Path:
    """``links`` symbolic links in a row, the last leading to a real file."""
    target = tmp_path / "target.yaml"
    target.write_text("x: 1\n", encoding="utf-8")
    previous: Path = target
    for index in reversed(range(links)):
        link = tmp_path / f"link{index}"
        link.symlink_to(previous)
        previous = link
    return previous


def test_a_chain_of_forty_links_is_followed(tmp_path: Path, on_windows: None) -> None:
    head = _chain(tmp_path, 40)
    permit, asked = _recording_permit(True)

    assert config_sources._permitted(head, permit) is True

    assert len(asked) == 1


def test_a_chain_of_forty_one_links_is_refused_unresolved(
    tmp_path: Path, on_windows: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    head = _chain(tmp_path, 41)
    resolved = _no_resolving(monkeypatch)
    permit, asked = _recording_permit(True)

    assert config_sources._permitted(head, permit) is False

    assert asked == []
    assert resolved == []


def test_a_path_that_is_no_link_is_judged_by_the_permit(
    tmp_path: Path, on_windows: None
) -> None:
    plain = tmp_path / ".ash.yaml"
    plain.write_text("x: 1\n", encoding="utf-8")
    permit, asked = _recording_permit(True)

    assert config_sources._permitted(plain, permit) is True

    assert asked == [Path(os.path.realpath(plain))]


def test_off_windows_a_link_is_never_read_for_a_share(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the platform test: nothing of this runs elsewhere."""
    monkeypatch.setattr(config_sources, "_on_windows", lambda: False)
    link = tmp_path / ".ash.yaml"
    link.symlink_to(tmp_path / "anything.yaml")
    _readlink_answering(monkeypatch, {link: "\\\\server\\share\\config.yaml"})
    permit, asked = _recording_permit(True)

    assert config_sources._permitted(link, permit) is True

    assert len(asked) == 1
