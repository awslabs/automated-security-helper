# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A per-call profile's file name follows the registered file, not the name alone.

Two stdio servers share the default session's ``config/`` directory, and each
may register the same profile name for a different file. ``call_profile_filename``
used to digest the name alone, so the two wrote one file for two profiles and a
plan recorded by one server was scanned under the other's. The digest now covers
the file the name is registered for, through the entry's digest of its absolute
path: the same name for the same file gives one name whatever each server's
spelling of the path (it used to digest the spelling, so one file under two
spellings got two names, and two files that shared a relative spelling from two
working directories got one), and an unregistered name keeps the shape.

The profiles are registered the way a server registers them, through
``register_profiles`` from real files, so the entry's digest is the one a
running server computes and not one the test builds.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import profile_registry
from automated_security_helper.cli.mcp.profile_registry import (
    call_profile_filename,
    is_call_profile_filename,
    register_profiles,
    set_profile_registry,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fresh_registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    profile_registry.clear_profile_registry()
    yield
    profile_registry.clear_profile_registry()


def _a_profile_file(directory: Path, name: str = "strict.yaml") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("project_name: strict\n", encoding="utf-8")
    return path


def _registered(name: str, spelling: object) -> None:
    """Register ``name`` for the file ``spelling`` names, as a server does."""
    set_profile_registry(register_profiles([f"{name}={spelling}"]))


def test_the_same_name_for_two_files_gives_two_names(tmp_path: Path) -> None:
    one = _a_profile_file(tmp_path / "one")
    two = _a_profile_file(tmp_path / "two")

    _registered("strict", one)
    first = call_profile_filename("strict")
    _registered("strict", two)
    second = call_profile_filename("strict")

    assert first != second
    assert is_call_profile_filename(first)
    assert is_call_profile_filename(second)


def test_one_file_under_two_spellings_gives_one_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red at the base: the digest covered the path as spelled, so the same file
    registered as an absolute path by one server and relative to its working
    directory by another got two names, and two servers' plans for one profile
    were scanned under different files."""
    (tmp_path / "one").mkdir()
    _a_profile_file(tmp_path)
    monkeypatch.chdir(tmp_path)

    _registered("strict", tmp_path / "strict.yaml")
    by_absolute_path = call_profile_filename("strict")
    _registered("strict", Path("one") / ".." / "strict.yaml")
    by_relative_spelling = call_profile_filename("strict")

    assert by_absolute_path == by_relative_spelling
    assert is_call_profile_filename(by_absolute_path)


def test_two_files_with_one_relative_spelling_from_two_directories_give_two_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other half of the digest: two servers started in different working
    directories, each with a ``strict.yaml`` beside it, register the same
    relative spelling for two different files. They must not share a name."""
    first_directory = tmp_path / "server-a"
    second_directory = tmp_path / "server-b"
    _a_profile_file(first_directory)
    _a_profile_file(second_directory)

    monkeypatch.chdir(first_directory)
    _registered("strict", "strict.yaml")
    from_the_first = call_profile_filename("strict")
    monkeypatch.chdir(second_directory)
    _registered("strict", "strict.yaml")
    from_the_second = call_profile_filename("strict")

    assert from_the_first != from_the_second
    assert is_call_profile_filename(from_the_first)
    assert is_call_profile_filename(from_the_second)


def test_the_same_name_for_one_file_gives_one_name(tmp_path: Path) -> None:
    _registered("strict", _a_profile_file(tmp_path))

    assert call_profile_filename("strict") == call_profile_filename("strict")


def test_an_unregistered_name_keeps_the_shape() -> None:
    assert is_call_profile_filename(call_profile_filename("nobody"))
