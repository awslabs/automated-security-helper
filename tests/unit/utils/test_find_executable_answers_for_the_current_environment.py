# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""find_executable's cache answers only for the environment it was filled in.

``find_executable`` remembers each answer for the life of the process. It was keyed
by the command alone, so after PATH or ASH_BIN_PATH changed it still named the file
the old value found, and a hit was never checked again: a tool deleted, or whose
execute bit was removed, after the first lookup was still the answer. The
directories searched after PATH (ASH_BIN_PATH's, then /usr/local/bin) were checked
with ``exists()`` alone, so a file without the execute bit, or a directory, of the
tool's name was returned as the tool, and starting it failed later with a less
useful error.

Now the answer is keyed by the command, PATH and ASH_BIN_PATH, a hit is used only
while it is still an executable file, and the fallback directories count only an
executable file. The cache still saves the search: a second lookup in an unchanged
environment does not search again.
"""

from __future__ import annotations

import os
import shutil
import sys
import uuid
from pathlib import Path

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import (
    clear_find_executable_cache,
    find_executable,
)

POSIX_ONLY = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX execute permission and file names"
)


@pytest.fixture
def tool_name() -> str:
    """A name no directory on the host holds, /usr/local/bin included."""
    return f"ash-lookup-probe-{uuid.uuid4().hex[:12]}"


@pytest.fixture(autouse=True)
def _a_lookup_of_our_own(monkeypatch):
    monkeypatch.delenv("ASH_BIN_PATH", raising=False)
    clear_find_executable_cache()
    yield
    clear_find_executable_cache()


def _executable(directory: Path, name: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _only_on_path(monkeypatch, *directories: Path) -> None:
    monkeypatch.setenv("PATH", os.pathsep.join(str(d) for d in directories))


@POSIX_ONLY
def test_an_unchanged_environment_is_answered_from_the_cache(
    tmp_path, monkeypatch, tool_name
):
    """The control: a fix that dropped the cache would pass every test below."""
    tool = _executable(tmp_path / "a", tool_name)
    _only_on_path(monkeypatch, tool.parent)
    assert find_executable(tool_name) == str(tool)

    searches = []
    real_which = shutil.which

    def counting(*args, **kwargs):
        searches.append(args)
        return real_which(*args, **kwargs)

    monkeypatch.setattr(subprocess_utils.shutil, "which", counting)

    assert find_executable(tool_name) == str(tool)
    assert searches == [], searches


@POSIX_ONLY
def test_a_path_that_changed_is_searched_again(tmp_path, monkeypatch, tool_name):
    first = _executable(tmp_path / "a", tool_name)
    second = _executable(tmp_path / "b", tool_name)
    _only_on_path(monkeypatch, first.parent)
    assert find_executable(tool_name) == str(first)

    _only_on_path(monkeypatch, second.parent)

    assert find_executable(tool_name) == str(second)


@POSIX_ONLY
def test_an_ash_bin_path_that_changed_is_searched_again(
    tmp_path, monkeypatch, tool_name
):
    first = _executable(tmp_path / "bin-a", tool_name)
    second = _executable(tmp_path / "bin-b", tool_name)
    _only_on_path(monkeypatch, tmp_path / "empty")
    monkeypatch.setenv("ASH_BIN_PATH", str(first.parent))
    assert find_executable(tool_name) == first.as_posix()

    monkeypatch.setenv("ASH_BIN_PATH", str(second.parent))

    assert find_executable(tool_name) == second.as_posix()


@POSIX_ONLY
def test_a_tool_deleted_after_its_lookup_is_not_the_answer(
    tmp_path, monkeypatch, tool_name
):
    tool = _executable(tmp_path / "a", tool_name)
    _only_on_path(monkeypatch, tool.parent)
    assert find_executable(tool_name) == str(tool)

    tool.unlink()

    assert find_executable(tool_name) is None


@POSIX_ONLY
def test_a_tool_that_lost_its_execute_bit_is_not_the_answer(
    tmp_path, monkeypatch, tool_name
):
    tool = _executable(tmp_path / "a", tool_name)
    _only_on_path(monkeypatch, tool.parent)
    assert find_executable(tool_name) == str(tool)

    tool.chmod(0o644)

    assert find_executable(tool_name) is None


@POSIX_ONLY
@pytest.mark.parametrize("kind", ["a file without the execute bit", "a directory"])
def test_the_ash_bin_path_fallback_counts_only_an_executable_file(
    tmp_path, monkeypatch, tool_name, kind
):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    if kind == "a directory":
        (bin_dir / tool_name).mkdir()
    else:
        (bin_dir / tool_name).write_text("not a program\n", encoding="utf-8")
        (bin_dir / tool_name).chmod(0o644)
    _only_on_path(monkeypatch, tmp_path / "empty")
    monkeypatch.setenv("ASH_BIN_PATH", str(bin_dir))

    assert find_executable(tool_name) is None
