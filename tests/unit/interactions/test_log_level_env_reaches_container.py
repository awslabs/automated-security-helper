# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ASH_DEBUG and ASH_VERBOSE on the host reach the scan inside the container.

The CLI reads ASH_DEBUG/ASH_VERBOSE as the log level when no flag is given
(#628). In container mode the host process is not the one that scans: the
in-container CLI is, and it sees only what ``_assemble_run_command`` puts on the
``docker run`` line. ``_apply_log_level_env`` records an env-requested level on
the options as ``debug``/``verbose``, and the container command is built from
those. This file follows that path end to end, from the host environment to the
argv, so that an env var which changed the host's console but not the
container's would fail here.

Nothing is built or run. ``run_ash_container`` is replaced by a recorder at the
point ``_run_container_mode`` calls it, and the recorded flags are handed to the
real ``_assemble_run_command``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.core.enums import ExecutionStrategy
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.interactions.run_ash_container import (
    _assemble_run_command,
)


class _Stop(Exception):
    """Raised by the recorder: nothing past the call is under test."""


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ("ASH_DEBUG", "ASH_VERBOSE", "CI", "ASH_IN_CONTAINER"):
        monkeypatch.delenv(name, raising=False)


def _container_kwargs(monkeypatch, tmp_path: Path) -> Dict[str, Any]:
    recorded: List[Dict[str, Any]] = []

    def recorder(**kwargs):
        recorded.append(kwargs)
        raise _Stop

    monkeypatch.setattr(ras, "run_ash_container", recorder)
    opts = ras.ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")
    ras._apply_log_level_env(opts)
    with pytest.raises(_Stop):
        ras._run_container_mode(opts, ras.ASH_LOGGER)
    assert len(recorded) == 1
    return recorded[0]


def _argv(tmp_path: Path, debug: bool, verbose: bool) -> List[str]:
    return _assemble_run_command(
        oci_command_prefix=[],
        resolved_oci_runner="docker",
        image_name="ash:latest",
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        offline=False,
        debug=debug,
        color=False,
        quiet=False,
        progress=False,
        verbose=verbose,
        simple=False,
        python_based_plugins_only=False,
        cleanup=False,
        inspect=False,
        fail_on_findings=None,
        fail_on_incomplete_scanners=None,
        phases=[],
        scanners=[],
        exclude_scanners=[],
        output_formats=[],
        config=None,
        config_overrides=[],
        existing_results=None,
        ash_plugin_modules=[],
        strategy=ExecutionStrategy.PARALLEL,
        ctx=None,
    )


def test_host_ash_debug_reaches_the_container(monkeypatch, tmp_path):
    monkeypatch.setenv("ASH_DEBUG", "true")

    kwargs = _container_kwargs(monkeypatch, tmp_path)
    argv = _argv(tmp_path, kwargs["debug"], kwargs["verbose"])

    assert kwargs["debug"] is True
    assert "ASH_DEBUG=YES" in argv
    assert "--debug" in argv


def test_host_ash_verbose_reaches_the_container(monkeypatch, tmp_path):
    monkeypatch.setenv("ASH_VERBOSE", "1")

    kwargs = _container_kwargs(monkeypatch, tmp_path)
    argv = _argv(tmp_path, kwargs["debug"], kwargs["verbose"])

    assert kwargs["verbose"] is True
    assert "--verbose" in argv
    assert "--debug" not in argv


def test_without_either_variable_the_container_runs_at_the_default_level(
    monkeypatch, tmp_path
):
    """The control: the two tests above are not passing on a constant."""
    kwargs = _container_kwargs(monkeypatch, tmp_path)
    argv = _argv(tmp_path, kwargs["debug"], kwargs["verbose"])

    assert "ASH_DEBUG=NO" in argv
    assert "--debug" not in argv
    assert "--verbose" not in argv
