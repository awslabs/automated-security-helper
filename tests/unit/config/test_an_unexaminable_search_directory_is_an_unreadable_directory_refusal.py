# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A search directory with a component ASH cannot examine is not a share refusal.

On Windows, under a permit, the directory to look for a config source in is
judged before any name is looked up under it. The reading behind that judgment
(``utils/link_chain``) keeps WHY it answered: a link that leads to a share or
cannot be read, or a component that ``os.lstat`` refused to examine at all.
The second says nothing about where anything leads, so telling the caller that
the directory "leads through a network share, a device path or a link" is
wrong, and the MCP pre-scan check then reported a permission refusal where the
directory is simply unreadable.

The refusal for that case is the unreadable-directory error the name lookup
gives (``ASHConfigSourceError``, "Make the directory readable"), which the MCP
check reports as a failed check, and a directory that leads to a share keeps
its not-permitted refusal.

The Windows branch is reached by standing in for the platform test
(``_on_windows``), with ``os.lstat`` made to refuse one component the way a
directory the process cannot search does.

Red at the base: the unexaminable case raised ``ASHConfigInputNotPermittedError``
and the MCP check returned a refusal of the config chain. The share case and the
readable case are green at the base and at the tip.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.config import config_sources
from automated_security_helper.core.exceptions import (
    ASHConfigInputNotPermittedError,
    ASHConfigSourceError,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        os.name == "nt",
        reason="creating a symlink needs a privilege or Developer Mode there",
    ),
]

SHARE = "\\\\server\\share\\vendor"


@pytest.fixture
def on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_sources, "_on_windows", lambda: True)


def _permit_everything(path: Path) -> bool:
    return True


def _lstat_refusing(monkeypatch: pytest.MonkeyPatch, refused: Path) -> List[Path]:
    """``os.lstat`` refuses `refused` as a directory nobody can search would."""
    asked: List[Path] = []
    real = os.lstat

    def lstat(path, *args, **kwargs):
        key = Path(os.fspath(path))
        if key == refused:
            asked.append(key)
            raise PermissionError(errno.EACCES, "Permission denied")
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)
    return asked


def _scan_under_a_blocked_directory(tmp_path: Path) -> Path:
    blocked = tmp_path / "blocked"
    scan = blocked / "scan"
    scan.mkdir(parents=True)
    (scan / ".ash.yaml").write_text("project_name: demo\n", encoding="utf-8")
    return scan


def test_an_unexaminable_search_directory_is_the_unreadable_directory_refusal(
    tmp_path: Path, on_windows: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = _scan_under_a_blocked_directory(tmp_path)
    asked = _lstat_refusing(monkeypatch, scan.parent)

    with pytest.raises(ASHConfigSourceError) as raised:
        config_sources.check_search_directory(scan, _permit_everything)

    assert asked, "the component was never examined"
    assert not isinstance(raised.value, ASHConfigInputNotPermittedError)
    assert "Make the directory readable" in str(raised.value)
    assert scan.as_posix() in str(raised.value)
    assert "network share" not in str(raised.value)


def test_discovery_reports_an_unexaminable_search_directory_as_unreadable(
    tmp_path: Path, on_windows: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = _scan_under_a_blocked_directory(tmp_path)
    _lstat_refusing(monkeypatch, scan.parent)

    with pytest.raises(ASHConfigSourceError) as raised:
        config_sources.check_discovery_candidates(scan, _permit_everything)

    assert not isinstance(raised.value, ASHConfigInputNotPermittedError)
    assert "Make the directory readable" in str(raised.value)


def test_the_mcp_pre_scan_check_reports_it_as_a_failed_check_not_a_refusal(
    tmp_path: Path, on_windows: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = _scan_under_a_blocked_directory(tmp_path)
    _lstat_refusing(monkeypatch, scan.parent)

    refusal = mcp_tools._discovered_config_refusal(scan, None)

    assert isinstance(refusal, mcp_tools.ConfigCheckFailedError), refusal


def test_a_search_directory_that_leads_to_a_share_keeps_the_not_permitted_refusal(
    tmp_path: Path, on_windows: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: a link that leads to a share is still a permission refusal."""
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "lnk"
    link.symlink_to(real, target_is_directory=True)
    real_readlink = os.readlink

    def readlink(path, *args, **kwargs):
        if Path(os.fspath(path)) == link:
            return SHARE
        return real_readlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "readlink", readlink)

    with pytest.raises(ASHConfigInputNotPermittedError):
        config_sources.check_search_directory(link, _permit_everything)


def test_a_readable_search_directory_is_admitted(
    tmp_path: Path, on_windows: None
) -> None:
    """The control: nothing is refused when every component can be examined."""
    scan = _scan_under_a_blocked_directory(tmp_path)

    config_sources.check_search_directory(scan, _permit_everything)


def test_without_a_permit_an_unexaminable_search_directory_is_not_judged(
    tmp_path: Path, on_windows: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: a local caller with no permit is not gated, by design."""
    scan = _scan_under_a_blocked_directory(tmp_path)
    asked = _lstat_refusing(monkeypatch, scan.parent)

    config_sources.check_search_directory(scan, None)

    assert asked == []
