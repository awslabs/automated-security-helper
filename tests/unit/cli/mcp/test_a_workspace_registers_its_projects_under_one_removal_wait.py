# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace's projects are registered under one wait for an output removal.

``register_scan`` waits for the removal of an output tree it meets, up to the
wait it is given (``OUTPUT_REMOVAL_WAIT_SECONDS`` by default). The workspace
registered its N projects with a call each, so N removals in the way could make
it wait N times as long as the one wait the registry means. The projects now
share one deadline and each call is given what is left of it.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.cli.mcp import workspace as workspace_module
from automated_security_helper.core.resource_management.scan_registry import (
    OUTPUT_REMOVAL_WAIT_SECONDS,
)

pytestmark = pytest.mark.unit


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now


class _Registry:
    """Records the removal wait each registration was given; each takes two seconds."""

    def __init__(self, clock: _Clock) -> None:
        self.clock = clock
        self.waits: list = []

    def register_scan(self, **kwargs) -> str:
        self.waits.append(kwargs.get("removal_wait_seconds"))
        self.clock.now += 2.0
        return f"scan-{len(self.waits)}"

    def update_scan_status(self, scan_id, status) -> None:
        return None

    def get_scan(self, scan_id):
        return None


def _project(tmp_path, key: str) -> SimpleNamespace:
    return SimpleNamespace(
        key=key,
        path=(tmp_path / key).as_posix(),
        gate_threshold="MEDIUM",
        config_source=None,
    )


def _register(tmp_path, monkeypatch, count: int):
    clock = _Clock()
    registry = _Registry(clock)
    monkeypatch.setattr(workspace_module, "get_scan_registry", lambda: registry)
    monkeypatch.setattr(workspace_module, "time", clock)
    monkeypatch.setattr(
        workspace_module, "_refuse_outputs_another_scan_writes", lambda *a, **k: None
    )
    projects = [_project(tmp_path, f"p{index}") for index in range(count)]
    plan = SimpleNamespace(active_projects=projects, workspace_root=tmp_path.as_posix())
    outputs = {project.key: Path(project.path) / "out" for project in projects}
    workspace_module._register_projects(
        plan, outputs, "session", output_dir=tmp_path / "out"
    )
    return registry


def test_each_project_is_given_what_is_left_of_one_wait(tmp_path, monkeypatch):
    registry = _register(tmp_path, monkeypatch, 4)

    # RED at the base: no wait was passed, so each call took the registry's whole
    # default. Two seconds pass per registration, so the calls see 5, 3, 1 and
    # then nothing left.
    assert OUTPUT_REMOVAL_WAIT_SECONDS == 5.0
    assert registry.waits == [5.0, 3.0, 1.0, 0.0]


def test_a_single_project_is_given_the_whole_wait(tmp_path, monkeypatch):
    """One project waits as long as the registry's own default, as before."""
    registry = _register(tmp_path, monkeypatch, 1)

    assert registry.waits == [OUTPUT_REMOVAL_WAIT_SECONDS]
