# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every way into a scan registers what it scans as the scanned tree.

Tool lookups refuse a copy inside a scanned tree only while one is registered
(utils/subprocess_utils.scanning_tree), so each entry point is checked for it: the
``run_ash_scan`` wrapper, ahead of mode dispatch, for every mode; and the
orchestrator's own ``initialize`` and ``execute_scan``, for callers that use it
directly. Each check records the trees in force at the point the real work would
start.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.interactions import run_ash_scan as mod
from automated_security_helper.utils import subprocess_utils


class Stop(Exception):
    pass


@pytest.mark.parametrize("mode", ["local", "container", "nix"])
def test_run_ash_scan_registers_the_source_dir_before_dispatch(
    mode, tmp_path, monkeypatch
):
    seen: list = []

    def record(*args, **kwargs):
        seen.append(subprocess_utils.scanned_trees())
        raise Stop

    target = {
        "local": "_run_local_mode",
        "container": "_run_container_mode",
        "nix": "_run_nix_mode",
    }[mode]
    monkeypatch.setattr(mod, target, record)
    source = tmp_path / "repo"
    source.mkdir()

    with pytest.raises((Stop, SystemExit)):
        mod.run_ash_scan(
            source_dir=str(source),
            output_dir=str(tmp_path / "out"),
            mode=mod.RunMode(mode),
            show_summary=False,
        )

    assert seen and str(source.absolute()) in seen[0]


def test_a_workspace_registers_its_root(tmp_path):
    """The wrapper's workspace branch: the root, not a project or the cwd."""
    seen: list = []
    root = tmp_path / "workspace"
    root.mkdir()

    wrapped = mod._in_scanned_tree_from_arguments(
        lambda **kwargs: seen.append(subprocess_utils.scanned_trees())
    )
    wrapped(workspace_plan=SimpleNamespace(workspace_root=str(root)))

    assert seen == [[str(root.absolute())]]


class TestTheOrchestrator:
    def orchestrator(self, tmp_path):
        from automated_security_helper.core.orchestrator import ASHScanOrchestrator

        source = tmp_path / "repo"
        source.mkdir()
        return ASHScanOrchestrator(source_dir=source, output_dir=tmp_path / "out")

    def test_initialize_runs_with_the_source_dir_registered(
        self, tmp_path, monkeypatch
    ):
        from automated_security_helper.core.orchestrator import ASHScanOrchestrator

        seen: list = []
        monkeypatch.setattr(
            ASHScanOrchestrator,
            "_initialize",
            lambda self: seen.append(subprocess_utils.scanned_trees()),
        )
        orchestrator = self.orchestrator(tmp_path)

        orchestrator.initialize()

        assert seen == [[str(Path(orchestrator.source_dir).absolute())]]

    def test_execute_scan_runs_with_the_source_dir_registered(
        self, tmp_path, monkeypatch
    ):
        from automated_security_helper.core.orchestrator import ASHScanOrchestrator

        seen: list = []
        monkeypatch.setattr(
            ASHScanOrchestrator,
            "_execute_scan",
            lambda self, phases=None: seen.append(subprocess_utils.scanned_trees()),
        )
        orchestrator = self.orchestrator(tmp_path)

        orchestrator.execute_scan()

        assert seen == [[str(Path(orchestrator.source_dir).absolute())]]

    def test_nothing_stays_registered_when_initialize_raises(
        self, tmp_path, monkeypatch
    ):
        from automated_security_helper.core.orchestrator import ASHScanOrchestrator

        def boom(self):
            raise RuntimeError("config could not be resolved")

        monkeypatch.setattr(ASHScanOrchestrator, "_initialize", boom)
        orchestrator = self.orchestrator(tmp_path)

        with pytest.raises(RuntimeError):
            orchestrator.initialize()

        assert subprocess_utils.scanned_trees() == []
