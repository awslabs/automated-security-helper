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
order is measured by a probe thread that tries the lock without blocking, since a
race that reproduces the deadlock would hang the run that measures it.
"""

from __future__ import annotations

import threading
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


def test_the_context_imports_its_forward_reference_outside_the_resolver_lock(
    monkeypatch,
):
    """The context's own resolve function, run against a fresh resolver with a
    stub import, imports before the lock is taken. The reentrant lock can only be
    read from another thread, so the stub starts one with a non-blocking acquire
    and a join timeout; it cannot hang."""
    resolver: OnceOnlyResolver[type] = OnceOnlyResolver()
    took_the_lock: list[bool] = []

    def _stub_import() -> type:
        def _probe() -> None:
            got = resolver._lock.acquire(blocking=False)
            took_the_lock.append(got)
            if got:
                resolver._lock.release()

        thread = threading.Thread(target=_probe, daemon=True)
        thread.start()
        thread.join(timeout=10)
        assert not thread.is_alive(), "the probe thread did not finish"
        return object

    monkeypatch.setattr(plugin_context_module, "_forward_refs", resolver)
    monkeypatch.setattr(plugin_context_module, "_import_ash_config", _stub_import)
    # The bind would rebuild the real model on the stub; the import is the subject.
    monkeypatch.setattr(plugin_context_module, "_bind_ash_config", lambda target: None)

    plugin_context_module._resolve_forward_refs()

    assert took_the_lock == [True], "the import ran while the lock was held"
    assert resolver.resolved is True
