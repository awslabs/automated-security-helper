# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A remembered answer that is no longer usable is searched for under the scan.

When a cached path is gone, the lookup searches again with the same rules as the
first time, so a copy inside the scanned tree is still refused rather than becoming
the answer. ``find_executable_for_scan`` goes through the same lookup, so it follows
a PATH change and a deleted tool too.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

from automated_security_helper.utils.subprocess_utils import (
    ALLOW_IN_TREE_TOOLS_ENV,
    clear_find_executable_cache,
    find_executable_for_scan,
    lookup_for_scan,
)

POSIX_ONLY = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX execute permission and file names"
)


@pytest.fixture
def tool_name() -> str:
    """A name no directory on the host holds, /usr/local/bin included."""
    return f"ash-recheck-probe-{uuid.uuid4().hex[:12]}"


@pytest.fixture(autouse=True)
def _a_lookup_of_our_own(monkeypatch):
    monkeypatch.delenv("ASH_BIN_PATH", raising=False)
    monkeypatch.delenv(ALLOW_IN_TREE_TOOLS_ENV, raising=False)
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
def test_the_scanned_trees_copy_is_still_refused_after_the_answer_is_deleted(
    tmp_path, monkeypatch, tool_name
):
    repo = tmp_path / "repo"
    inside = _executable(repo / "bin", tool_name)
    outside = _executable(tmp_path / "outside", tool_name)
    _only_on_path(monkeypatch, inside.parent, outside.parent)
    assert lookup_for_scan(tool_name, repo) == (str(outside), None)

    outside.unlink()

    found, reason = lookup_for_scan(tool_name, repo)
    assert found is None
    assert reason is not None and str(inside) in reason, reason


@POSIX_ONLY
def test_find_executable_for_scan_answers_for_the_current_environment(
    tmp_path, monkeypatch, tool_name
):
    repo = tmp_path / "repo"
    repo.mkdir()
    first = _executable(tmp_path / "a", tool_name)
    second = _executable(tmp_path / "b", tool_name)
    _only_on_path(monkeypatch, first.parent)
    assert find_executable_for_scan(tool_name, repo) == str(first)

    _only_on_path(monkeypatch, second.parent)
    assert find_executable_for_scan(tool_name, repo) == str(second)

    second.unlink()
    assert find_executable_for_scan(tool_name, repo) is None
