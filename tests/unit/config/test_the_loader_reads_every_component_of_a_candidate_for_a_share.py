# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""On Windows the config loader reads every component of a candidate, not the last.

Resolving a path on Windows opens what it names, so a candidate whose spelling
leads to a network share must be refused before anything resolves it. The loader
used to read only the candidate's own chain: ``os.lstat`` of the whole spelling
follows a link in any PARENT component (only the last one is left alone), and a
relative link target was collapsed by text and then ``lstat``-ed whole, which
follows a link among the collapsed target's parents. In both cases the share was
opened at the very check meant to prevent it, and the permit then judged the
path that resolving had already reached.

The loader now asks ``utils/link_chain`` (the one reading, shared with the MCP
sandbox gates): every component from the anchor down, each looked up only under a
prefix already examined and found free of links, a relative target walked name by
name from the directory the link is in, and the spellings the loader's own copy
did not know (a ``..`` step behind a device prefix, a drive with no root).

The Windows branch is reached by standing in for the platform test
(``_on_windows``) with POSIX symbolic links, and with ``os.readlink`` made to
answer as Windows does for the one link under test.

Red at the base: each refused case below was admitted, the permit was asked
about the path behind the link, and ``os.lstat`` was asked about an entry under
the link. Every control is green at the base and at the tip.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List

import pytest

from automated_security_helper.config import config_sources
from automated_security_helper.core.exceptions import ASHConfigInputNotPermittedError

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        os.name == "nt",
        reason="creating a symlink needs a privilege or Developer Mode there",
    ),
]

#: Spelled once, as ``os.readlink`` returns it for a link to a network share.
SHARE = "\\\\server\\share\\vendor"


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
    monkeypatch: pytest.MonkeyPatch, answers: Dict[Path, str]
) -> None:
    """``os.readlink`` as Windows reads a reparse point, for the named links."""
    real = os.readlink

    def readlink(path, *args, **kwargs):
        key = Path(os.fspath(path))
        if key in answers:
            return answers[key]
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os, "readlink", readlink)


def _lstat_recording(monkeypatch: pytest.MonkeyPatch) -> List[Path]:
    """Every path ``os.lstat`` is asked about, from here on."""
    seen: List[Path] = []
    real = os.lstat

    def lstat(path, *args, **kwargs):
        seen.append(Path(os.fspath(path)))
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)
    return seen


def _no_resolving(monkeypatch: pytest.MonkeyPatch) -> List[str]:
    resolved: List[str] = []
    real = os.path.realpath

    def recording(path, *args, **kwargs):
        resolved.append(os.fspath(path))
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os.path, "realpath", recording)
    return resolved


def _under(seen: List[Path], link: Path) -> List[Path]:
    return [path for path in seen if link in path.parents]


def _dir_linked_to_a_share(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """``lnk`` is a link, which Windows would read as leading to a share.

    On disk it leads to ``real``, which holds a config file, so that a lookup
    through the link FINDS that file: the loader's old reading went through the
    link and saw a plain file, a local name, and admitted it.
    """
    real = tmp_path / "real"
    real.mkdir()
    (real / ".ash.yaml").write_text("project_name: demo\n", encoding="utf-8")
    link = tmp_path / "lnk"
    link.symlink_to(real, target_is_directory=True)
    _readlink_answering(monkeypatch, {link: SHARE})
    return real, link


def test_a_candidate_under_a_parent_link_to_a_share_is_refused_unresolved(
    tmp_path: Path, on_windows: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _real, link = _dir_linked_to_a_share(tmp_path, monkeypatch)
    seen = _lstat_recording(monkeypatch)
    resolved = _no_resolving(monkeypatch)
    permit, asked = _recording_permit(True)

    assert config_sources._permitted(link / ".ash.yaml", permit) is False

    assert asked == []
    assert resolved == []
    assert _under(seen, link) == []


def test_a_parent_link_to_a_local_directory_is_followed_and_judged_by_the_permit(
    tmp_path: Path, on_windows: None
) -> None:
    """The control: a parent link that stays on local names is not refused."""
    real = tmp_path / "real"
    real.mkdir()
    (real / ".ash.yaml").write_text("project_name: demo\n", encoding="utf-8")
    link = tmp_path / "lnk"
    link.symlink_to(real, target_is_directory=True)
    permit, asked = _recording_permit(True)

    assert config_sources._permitted(link / ".ash.yaml", permit) is True

    assert asked == [Path(os.path.realpath(real / ".ash.yaml"))]


def test_a_plain_candidate_in_a_real_directory_is_judged_by_the_permit(
    tmp_path: Path, on_windows: None
) -> None:
    """The control: the plain real-package path is admitted."""
    plain = tmp_path / "pkg" / ".ash.yaml"
    plain.parent.mkdir()
    plain.write_text("project_name: demo\n", encoding="utf-8")
    permit, asked = _recording_permit(True)

    assert config_sources._permitted(plain, permit) is True

    assert asked == [Path(os.path.realpath(plain))]


def test_a_candidate_that_is_not_there_is_judged_by_the_permit(
    tmp_path: Path, on_windows: None
) -> None:
    """The control: a missing component ends the walk with nothing judged."""
    permit, asked = _recording_permit(True)

    assert config_sources._permitted(tmp_path / "missing" / ".ash.yaml", permit)

    assert len(asked) == 1


def test_off_windows_a_parent_link_is_never_read_for_a_share(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the platform test: nothing of this runs elsewhere."""
    monkeypatch.setattr(config_sources, "_on_windows", lambda: False)
    _real, link = _dir_linked_to_a_share(tmp_path, monkeypatch)
    permit, asked = _recording_permit(True)

    assert config_sources._permitted(link / ".ash.yaml", permit) is True

    assert len(asked) == 1


def _relative_link_through_vendor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str
):
    """``scan/.ash/ash.yaml`` links to ``target``, a relative spelling with ``..``.

    ``scan/vendor`` is a link which Windows would read as leading to a share; on
    disk it leads to ``real_vendor``, which holds the file, so that a lookup of
    the collapsed target as a whole finds a plain file under the link.
    """
    real_vendor = tmp_path / "real_vendor"
    real_vendor.mkdir()
    (real_vendor / "cfg.yaml").write_text("project_name: demo\n", encoding="utf-8")
    scan = tmp_path / "scan"
    (scan / ".ash").mkdir(parents=True)
    vendor = scan / "vendor"
    vendor.symlink_to(real_vendor, target_is_directory=True)
    link = scan / ".ash" / "ash.yaml"
    link.symlink_to(target)
    _readlink_answering(monkeypatch, {vendor: SHARE})
    return link, vendor


def test_a_relative_hop_whose_collapsed_parent_is_a_link_to_a_share_is_refused(
    tmp_path: Path, on_windows: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    link, vendor = _relative_link_through_vendor(
        tmp_path, monkeypatch, "../vendor/cfg.yaml"
    )
    seen = _lstat_recording(monkeypatch)
    resolved = _no_resolving(monkeypatch)
    permit, asked = _recording_permit(True)

    assert config_sources._permitted(link, permit) is False

    assert asked == []
    assert resolved == []
    assert _under(seen, vendor) == []


def test_a_relative_hop_through_a_local_directory_is_followed_and_judged(
    tmp_path: Path, on_windows: None
) -> None:
    """The control: the same shape with a plain directory is admitted."""
    (tmp_path / "scan" / ".ash").mkdir(parents=True)
    (tmp_path / "scan" / "vendor").mkdir()
    cfg = tmp_path / "scan" / "vendor" / "cfg.yaml"
    cfg.write_text("project_name: demo\n", encoding="utf-8")
    link = tmp_path / "scan" / ".ash" / "ash.yaml"
    link.symlink_to("../vendor/cfg.yaml")
    permit, asked = _recording_permit(True)

    assert config_sources._permitted(link, permit) is True

    assert asked == [Path(os.path.realpath(cfg))]


@pytest.mark.parametrize(
    "spelling",
    [
        # A step back behind a device prefix is not a step up a local tree: Win32
        # normalizes it before the object manager sees the name, so a drive
        # letter in front names nothing local.
        "\\\\.\\C:\\..\\UNC\\server\\share\\cfg.yaml",
        "\\\\?\\C:\\..\\UNC\\server\\share\\cfg.yaml",
        "//./C:/../UNC/server/share/cfg.yaml",
        # A drive and no root is read from the drive's current directory, a
        # per-process fact, so what it names cannot be told from the link.
        "C:cfg.yaml",
        "C:..\\cfg.yaml",
    ],
)
def test_a_hop_spelled_in_a_way_the_shared_reading_refuses_is_refused(
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
        "C:\\repo\\a.yaml",
        "\\repo\\a.yaml",
        "sub\\a.yaml",
    ],
)
def test_a_local_spelling_is_still_admitted(
    tmp_path: Path,
    on_windows: None,
    monkeypatch: pytest.MonkeyPatch,
    spelling: str,
) -> None:
    """The control for the test above: a local name is not over-refused."""
    link = tmp_path / ".ash.yaml"
    link.symlink_to(tmp_path / "anything.yaml")
    _readlink_answering(monkeypatch, {link: spelling})
    permit, asked = _recording_permit(True)

    assert config_sources._permitted(link, permit) is True

    assert len(asked) == 1


def test_a_search_directory_that_is_a_link_to_a_share_is_refused_before_any_lookup(
    tmp_path: Path, on_windows: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Looking for a config name under a link looks through it: ``lstat`` of
    ``lnk/.ash`` follows ``lnk``. The directory is judged first, whether or not a
    config name is there, and the refusal names the directory as given."""
    _real, link = _dir_linked_to_a_share(tmp_path, monkeypatch)
    seen = _lstat_recording(monkeypatch)
    resolved = _no_resolving(monkeypatch)
    permit, asked = _recording_permit(True)

    with pytest.raises(ASHConfigInputNotPermittedError) as raised:
        config_sources.check_discovery_candidates(link, permit)

    assert asked == []
    assert resolved == []
    assert _under(seen, link) == []
    assert "server" not in str(raised.value)
    assert "Errno" not in str(raised.value)


def test_discovery_refuses_a_search_directory_that_is_a_link_to_a_share(
    tmp_path: Path, on_windows: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _real, link = _dir_linked_to_a_share(tmp_path, monkeypatch)
    seen = _lstat_recording(monkeypatch)
    permit, asked = _recording_permit(True)

    with pytest.raises(ASHConfigInputNotPermittedError):
        config_sources.discover_config_source(link, permit=permit)

    assert asked == []
    assert _under(seen, link) == []


def test_a_search_directory_that_is_a_local_link_is_still_discovered(
    tmp_path: Path, on_windows: None
) -> None:
    """The control: a search directory reached through a local link is read."""
    real = tmp_path / "real"
    real.mkdir()
    (real / ".ash.yaml").write_text("project_name: demo\n", encoding="utf-8")
    link = tmp_path / "lnk"
    link.symlink_to(real, target_is_directory=True)
    permit, asked = _recording_permit(True)

    discovery = config_sources.discover_config_source(link, permit=permit)

    assert discovery.selected is not None
    assert discovery.selected.path == link / ".ash.yaml"
    assert asked


def test_a_refused_candidate_is_never_opened(
    tmp_path: Path, on_windows: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A name the gate refused is not opened, and checking opens nothing."""
    _real, link = _dir_linked_to_a_share(tmp_path, monkeypatch)
    opened: List[str] = []
    real_open = os.open

    def recording_open(path, *args, **kwargs):
        opened.append(os.fspath(path))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", recording_open)
    permit, _asked = _recording_permit(True)

    with pytest.raises(ASHConfigInputNotPermittedError):
        config_sources.discover_config_source(link, permit=permit)

    assert [name for name in opened if str(link) in name] == []
