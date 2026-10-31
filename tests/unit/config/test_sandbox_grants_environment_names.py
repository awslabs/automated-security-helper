# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``described`` shows ``<value>`` only for a config name the environment chose.

A file an ``extends`` entry named with a value read from the environment is
shown as ``<value>``, because its path holds the value. A name with nothing
behind it -- the ``config_overrides`` stand-in an MCP client's overrides are
listed under, a file that is gone -- is not such a file and is shown as it is
written. A name that cannot resolve because of a link loop may still name a
file the environment chose, so it stays hidden.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.environment_record import (
    ENVIRONMENT_VALUE_SHOWN,
)
from automated_security_helper.config.sandbox_grants import described

pytestmark = pytest.mark.unit


def _symlink_or_skip(link: Path, target: str) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symlinks are not available here: {error}")


def _environment_file(tmp_path: Path) -> Path:
    chosen = tmp_path / "chosen.yaml"
    chosen.write_text("project_name: x\n", encoding="utf-8")
    return chosen


def test_the_config_overrides_stand_in_is_shown_as_written(tmp_path, monkeypatch):
    chosen = _environment_file(tmp_path)
    monkeypatch.chdir(tmp_path)

    shown = described([Path("config_overrides")], environment_paths=[chosen])

    assert shown == "config_overrides"


def test_a_file_that_is_gone_is_shown_as_written(tmp_path):
    chosen = _environment_file(tmp_path)
    gone = tmp_path / "gone.yaml"

    shown = described([gone], environment_paths=[chosen])

    assert shown == gone.as_posix()


def test_the_file_the_environment_chose_is_still_hidden(tmp_path):
    chosen = _environment_file(tmp_path)

    shown = described([chosen], environment_paths=[chosen])

    assert shown == ENVIRONMENT_VALUE_SHOWN


def test_a_link_to_the_file_the_environment_chose_is_still_hidden(tmp_path):
    chosen = _environment_file(tmp_path)
    link = tmp_path / "ref.yaml"
    _symlink_or_skip(link, chosen.name)

    shown = described([link], environment_paths=[chosen])

    assert shown == ENVIRONMENT_VALUE_SHOWN


def test_a_dangling_link_to_a_chosen_file_that_is_gone_is_still_hidden(tmp_path):
    chosen = tmp_path / "chosen-gone.yaml"
    link = tmp_path / "ref.yaml"
    _symlink_or_skip(link, chosen.name)

    shown = described([link], environment_paths=[chosen])

    assert shown == ENVIRONMENT_VALUE_SHOWN


def test_a_link_loop_is_still_hidden(tmp_path):
    chosen = _environment_file(tmp_path)
    first = tmp_path / "first.yaml"
    second = tmp_path / "second.yaml"
    _symlink_or_skip(first, second.name)
    _symlink_or_skip(second, first.name)

    shown = described([first], environment_paths=[chosen])

    assert shown == ENVIRONMENT_VALUE_SHOWN
