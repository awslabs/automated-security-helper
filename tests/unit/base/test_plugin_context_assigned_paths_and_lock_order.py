# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A PluginContext keeps its directories as paths, and resolves its forward
references without holding its lock through an import.

Two corrections. The model does not validate assignments, so a str assigned to
``work_dir`` (or any directory field) was stored as a str and every later
plugin that called a Path method on it crashed; the assignment now coerces to
Path. And ``_resolve_forward_refs`` imported ``config.ash_config`` inside its
lock while that module's import calls the resolver back, so a thread
importing the module and a thread first building a context could each hold
the lock the other waited for; the import now runs before the lock. The lock
order is read from the source, since a race that reproduces the deadlock would
hang the run that measures it.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from automated_security_helper.base import plugin_context as plugin_context_module
from automated_security_helper.base.forward_refs import OnceOnlyResolver
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME

pytestmark = pytest.mark.unit


@pytest.fixture
def context(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir()
    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )


def test_a_str_assigned_to_work_dir_is_stored_as_a_path(context, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    with pytest.warns(DeprecationWarning):
        context.work_dir = str(elsewhere)

    assert isinstance(context.work_dir, Path), type(context.work_dir)
    assert context.work_dir == elsewhere
    # The Path method a later plugin calls.
    assert context.work_dir.joinpath("scanners").name == "scanners"


def test_a_str_assigned_to_output_dir_is_stored_as_a_path(context, tmp_path):
    elsewhere = tmp_path / "out2"
    elsewhere.mkdir()

    context.output_dir = str(elsewhere)

    assert isinstance(context.output_dir, Path), type(context.output_dir)


def test_the_import_precedes_the_lock():
    """The context resolves through the shared once-only resolver, whose
    import step runs before its lock."""
    assert isinstance(plugin_context_module._forward_refs, OnceOnlyResolver)
    source = inspect.getsource(OnceOnlyResolver.resolve)
    import_at = source.index("target = import_target()")
    lock_at = source.index("with self._lock:")

    assert import_at < lock_at, source
    plugin_context_module._resolve_forward_refs()
    assert plugin_context_module._forward_refs.resolved is True
