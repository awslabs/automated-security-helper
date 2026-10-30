# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A per-call profile's file name follows the registered file, not the name alone.

Two stdio servers share the default session's ``config/`` directory, and each
may register the same profile name for a different file. ``call_profile_filename``
used to digest the name alone, so the two wrote one file for two profiles and a
plan recorded by one server was scanned under the other's. The digest now covers
the path the name is registered under; the same name for the same file still
gives one name, and an unregistered name keeps the shape.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import profile_registry
from automated_security_helper.cli.mcp.profile_registry import (
    ProfileEntry,
    call_profile_filename,
    is_call_profile_filename,
    set_profile_registry,
)
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fresh_registry():
    profile_registry.clear_profile_registry()
    yield
    profile_registry.clear_profile_registry()


def _registered(name: str, path: Path) -> None:
    set_profile_registry(
        {
            name: ProfileEntry(
                name=name, path=path, config=AshConfig(), path_sha256="0" * 64
            )
        }
    )


def test_the_same_name_for_two_files_gives_two_names(tmp_path: Path) -> None:
    _registered("strict", tmp_path / "one" / "strict.yaml")
    first = call_profile_filename("strict")
    _registered("strict", tmp_path / "two" / "strict.yaml")
    second = call_profile_filename("strict")

    assert first != second
    assert is_call_profile_filename(first)
    assert is_call_profile_filename(second)


def test_the_same_name_for_one_file_gives_one_name(tmp_path: Path) -> None:
    _registered("strict", tmp_path / "strict.yaml")

    assert call_profile_filename("strict") == call_profile_filename("strict")


def test_an_unregistered_name_keeps_the_shape() -> None:
    assert is_call_profile_filename(call_profile_filename("nobody"))
