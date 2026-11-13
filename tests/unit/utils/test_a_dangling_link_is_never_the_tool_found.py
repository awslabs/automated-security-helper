# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""find_executable never answers a link whose target is gone.

``UVToolRunner.install_tool_with_version`` removes the path ``find_executable``
returns when that path does not exist, so the uv tool link it replaces is not left
dangling. That branch can only run if ``find_executable`` can return a path that does
not exist. It cannot, and these cells pin why: a candidate counts only as an
executable file, found by a first search (on PATH and in the directories searched
after it) and again when a remembered path is given a second time. A dangling link
is neither, so the only way the branch runs is a file removed between the lookup and
the check that follows it.

No tool is started here: the files are only looked up.
"""

import os
import stat
from pathlib import Path

import pytest

from automated_security_helper.utils import subprocess_utils

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(os.name == "nt", reason="POSIX links and bits"),
]

TOOL = "ash-dangling-link-probe-tool"


def _file(directory: Path) -> str:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / TOOL
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path.as_posix()


def _dangling(directory: Path) -> str:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / TOOL
    path.symlink_to(directory / "not-there")
    assert path.is_symlink() and not path.exists()
    return path.as_posix()


@pytest.fixture(autouse=True)
def _empty_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess_utils, "_find_executable_cache", {})


@pytest.mark.parametrize("searched_by", ["PATH", "ASH_BIN_PATH"])
def test_a_first_search_passes_a_dangling_link_by(tmp_path, monkeypatch, searched_by):
    """The control comes first in each case: the same name as a real file is found
    in the same directory, so a None below is the link refused and not a directory
    that was never searched."""
    monkeypatch.setenv("PATH", "")
    monkeypatch.delenv("ASH_BIN_PATH", raising=False)
    monkeypatch.setenv(searched_by, str(tmp_path / "d"))
    real = _file(tmp_path / "d")
    assert subprocess_utils.find_executable(TOOL) == real

    Path(real).unlink()
    link = _dangling(tmp_path / "d")
    monkeypatch.setattr(subprocess_utils, "_find_executable_cache", {})
    assert subprocess_utils.find_executable(TOOL) != link
    assert subprocess_utils.find_executable(TOOL) is None


def test_a_remembered_path_that_became_a_dangling_link_is_not_given_again(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("PATH", str(tmp_path / "d"))
    monkeypatch.delenv("ASH_BIN_PATH", raising=False)
    real = _file(tmp_path / "d")
    assert subprocess_utils.find_executable(TOOL) == real

    Path(real).unlink()
    link = _dangling(tmp_path / "d")
    answer = subprocess_utils.find_executable(TOOL)
    assert answer != link
    assert answer is None or os.path.exists(answer), answer
