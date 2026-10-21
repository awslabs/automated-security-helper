# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Scanner and project threads run with the scan's scanned-tree scope.

The scope (utils/subprocess_utils.scanning_tree) lives in a context variable, and a
pool thread starts with an empty context unless it is handed a copy. Without one, a
scanner's own spawns would run with no tree to refuse tools from.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import scanning_tree


def test_scanner_threads_see_the_scans_trees(tmp_path):
    seen: list = []
    executor = ScannerExecutor(
        plugin_context=MagicMock(),
        progress_display=MagicMock(),
        scanner_tasks=[("one", MagicMock(), []), ("two", MagicMock(), [])],
        max_workers=2,
        process_results_fn=lambda result, aggregated: aggregated,
    )

    def record(scanner_name, scanner_plugin, scan_targets):
        seen.append(subprocess_utils.scanned_trees())
        return [], True

    executor._safe_execute_scanner = record  # type: ignore[method-assign]

    with scanning_tree(tmp_path):
        executor.run_parallel(AshAggregatedResults())

    assert seen == [[str(tmp_path)], [str(tmp_path)]]


def test_the_sandbox_backend_cache_is_per_scope(tmp_path, monkeypatch):
    """Which bwrap a probe found depends on the trees; one scan's is not another's."""
    from automated_security_helper.utils.sandbox import scope

    probes: list = []
    monkeypatch.setattr(
        scope, "_probe_backend", lambda name: probes.append(name) or MagicMock()
    )
    scope.clear_backend_cache()
    try:
        with scanning_tree(tmp_path / "a"):
            scope.resolve_backend("bwrap")
            scope.resolve_backend("bwrap")
        with scanning_tree(tmp_path / "b"):
            scope.resolve_backend("bwrap")
    finally:
        scope.clear_backend_cache()

    assert probes == ["bwrap", "bwrap"]


@pytest.mark.skipif(sys.platform == "win32", reason="a POSIX stand-in for uv")
def test_the_uv_runner_lookup_cache_is_per_scope(tmp_path, monkeypatch):
    from automated_security_helper.utils import uv_tool_runner

    tree = tmp_path / "repo"
    bin_dir = tree / ".venv" / "bin"
    bin_dir.mkdir(parents=True)
    uv = bin_dir / "uv"
    uv.write_text("#!/bin/sh\nexit 0\n")
    uv.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.delenv("ASH_ALLOW_IN_TREE_TOOLS", raising=False)
    monkeypatch.setattr(
        subprocess_utils, "path_independent_dirs", lambda: [tmp_path / "ash-bin"]
    )
    uv_tool_runner._reset_uv_tool_runner_caches()
    subprocess_utils.clear_find_executable_cache()
    try:
        with scanning_tree(tree):
            assert uv_tool_runner.find_uv_or_none() is None
        assert uv_tool_runner.find_uv_or_none() == str(uv)
    finally:
        uv_tool_runner._reset_uv_tool_runner_caches()
        subprocess_utils.clear_find_executable_cache()
