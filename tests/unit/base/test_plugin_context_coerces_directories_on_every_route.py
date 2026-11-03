# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A PluginContext holds its directories as paths whichever way they arrive.

Assignment coerced a str to a Path, but ``model_construct`` and
``model_copy(update=...)`` skip validation and ``__setattr__`` both, so a str
given to a directory field through either was stored as a str. A later
assignment of the same directory as a Path then hit the "no change" return and
kept the str, which is the crash the assignment coercion exists to prevent
(every later plugin that called a Path method on it). One helper now serves all
three routes.

``work_dir`` assignment also asked whether the assignment moves the directory
twice, and each answer costs two filesystem resolutions; it asks once.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base import plugin_context as plugin_context_module
from automated_security_helper.base.plugin_context import PluginContext

pytestmark = pytest.mark.unit

DIRECTORY_FIELDS = ("source_dir", "output_dir", "work_dir", "workspace_output_dir")


def _spelled_as_str(tmp_path) -> dict[str, str]:
    values = {}
    for name in DIRECTORY_FIELDS:
        directory = tmp_path / f"{name}-dir"
        directory.mkdir()
        values[name] = str(directory)
    return values


def test_model_construct_stores_str_directories_as_paths(plugin_context, tmp_path):
    built = PluginContext.model_construct(
        config=plugin_context.config, **_spelled_as_str(tmp_path)
    )

    for name in DIRECTORY_FIELDS:
        assert isinstance(getattr(built, name), Path), (name, getattr(built, name))


def test_model_copy_update_stores_str_directories_as_paths(plugin_context, tmp_path):
    copied = plugin_context.model_copy(update=_spelled_as_str(tmp_path))

    for name in DIRECTORY_FIELDS:
        assert isinstance(getattr(copied, name), Path), (name, getattr(copied, name))
    # The original is untouched.
    assert plugin_context.work_dir != copied.work_dir


def test_an_update_that_names_no_directory_changes_nothing_else(plugin_context):
    copied = plugin_context.model_copy(update={"run_id": "r1"})

    assert copied.run_id == "r1"
    assert copied.work_dir == plugin_context.work_dir


def test_a_path_written_back_over_a_constructed_str_is_a_path(plugin_context, tmp_path):
    """The crash the assignment coercion is for: the str survived a later write
    of the same directory because that write counted as no change."""
    values = _spelled_as_str(tmp_path)
    built = PluginContext.model_construct(config=plugin_context.config, **values)

    built.work_dir = Path(values["work_dir"])

    assert isinstance(built.work_dir, Path), type(built.work_dir)


def test_a_move_of_work_dir_asks_whether_it_moved_once(plugin_context, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    with (
        patch.object(
            plugin_context_module,
            "_repoints",
            wraps=plugin_context_module._repoints,
        ) as asked,
        pytest.warns(DeprecationWarning),
    ):
        plugin_context.work_dir = elsewhere

    assert asked.call_count == 1, asked.call_args_list
    assert plugin_context.work_dir == elsewhere


def test_the_same_directory_under_another_spelling_is_still_no_change(
    plugin_context,
):
    before = plugin_context.work_dir

    plugin_context.work_dir = str(before)

    assert plugin_context.work_dir is before
