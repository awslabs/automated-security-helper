# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Assigning ``work_dir`` another spelling of the directory it already holds changes nothing.

Such an assignment is not a repoint, so it does not warn. It used to be stored all
the same: a relative spelling then depended on the current directory from that
moment on, and a spelling through a symlink replaced the plain path. It is kept
as it was.
"""

from __future__ import annotations

import os
import warnings
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit


@pytest.fixture
def context(tmp_path) -> PluginContext:
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    built = PluginContext(
        source_dir=source,
        output_dir=output,
        config=AshConfig(project_name="plugin-context-low4"),
    )
    built.work_dir.mkdir(parents=True, exist_ok=True)
    return built


def test_a_relative_spelling_leaves_the_stored_directory_as_it_was(
    context, tmp_path, monkeypatch
):
    before = context.work_dir
    monkeypatch.chdir(tmp_path)

    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        context.work_dir = os.path.relpath(before)

    assert context.work_dir == before
    assert context.work_dir.is_absolute()


def test_a_relative_spelling_does_not_follow_a_later_change_of_directory(
    context, tmp_path, monkeypatch
):
    before = context.work_dir
    monkeypatch.chdir(tmp_path)
    context.work_dir = Path(os.path.relpath(before))

    monkeypatch.chdir(tmp_path / "src")

    assert context.work_dir == before
    assert context.work_dir.is_dir()


def test_a_spelling_through_a_symlink_leaves_the_plain_path(context, tmp_path):
    before = context.work_dir
    link = tmp_path / "work-link"
    try:
        link.symlink_to(before, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this platform cannot make a symlink here")

    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        context.work_dir = link

    assert context.work_dir == before


def test_the_same_directory_as_a_string_stays_a_path(context):
    before = context.work_dir

    context.work_dir = str(before)

    assert context.work_dir == before
    assert isinstance(context.work_dir, Path)


def test_another_directory_is_still_stored_and_warned_about(context, tmp_path):
    target = tmp_path / "somewhere-else"

    with pytest.warns(DeprecationWarning, match="replaces"):
        context.work_dir = target

    assert context.work_dir == target
