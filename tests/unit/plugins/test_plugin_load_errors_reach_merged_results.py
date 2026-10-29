# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plugin module that failed to import in any shard or project fails the merged run.

Each scan records the plugin modules it could not import in
``metadata.plugin_load_errors``, and ``.github/scripts/assert_scanners_completed.py``
fails a results file that records any: the scanners that did load still write
healthy rows, so nothing else says a group of plugins is missing.

Two outputs combine several runs. ``ash merge`` builds its metadata from the
lowest-indexed shard, and the workspace results file writes metadata of its own.
Neither carried the other runs' load errors, so a failure in shard 1, or in the
second project of a workspace, left a merged file the gate passed. Each now
records every run's: a module listed once when the runs agree on its error, and
with each distinct error when they do not.

The controls are the same outputs with no load error anywhere, which the gate
passes, so a gate or merge that failed every file would fail them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

from automated_security_helper.cli.merge import merge_shard_results
from automated_security_helper.workspace.execution import execute_workspace
from tests.unit.cli.test_merge import as_loaded, build_shards
from tests.unit.test_scanners_completed_gate import _run as run_gate
from tests.unit.workspace.test_execution import _make_workspace, _sarif, _settings

pytestmark = pytest.mark.unit

MODULE = "automated_security_helper.plugin_modules.ash_builtin.reporters"
ERROR = "ImportError: No module named 'zz_missing_dependency'"
OTHER_ERROR = "ImportError: cannot import name 'zz_gone' from 'zz_missing_dependency'"


def _write_merged(tmp_path: Path, shards) -> Dict[str, Any]:
    """Merge *shards*, write the merged results as ``ash merge`` does, return them."""
    merged = merge_shard_results(as_loaded(shards))
    path = tmp_path / "ash_aggregated_results.json"
    path.write_text(merged.model_dump_json(indent=2), encoding="utf-8")
    return {"model": merged, "path": path}


class TestAshMergeKeepsEveryShardsLoadErrors:
    def test_a_load_error_in_a_later_shard_is_recorded(self, tmp_path):
        shards = build_shards(3)
        shards[1].metadata.plugin_load_errors = {MODULE: ERROR}

        merged = _write_merged(tmp_path, shards)

        assert merged["model"].metadata.plugin_load_errors == {MODULE: ERROR}

    def test_the_completeness_gate_fails_the_merged_file(self, tmp_path, capsys):
        shards = build_shards(3)
        shards[2].metadata.plugin_load_errors = {MODULE: ERROR}

        merged = _write_merged(tmp_path, shards)

        assert run_gate(merged["path"]) == 1
        assert MODULE in capsys.readouterr().out

    def test_an_error_two_shards_agree_on_is_listed_once(self, tmp_path):
        shards = build_shards(3)
        shards[0].metadata.plugin_load_errors = {MODULE: ERROR}
        shards[2].metadata.plugin_load_errors = {MODULE: ERROR}

        merged = _write_merged(tmp_path, shards)

        assert merged["model"].metadata.plugin_load_errors == {MODULE: ERROR}

    def test_each_distinct_error_is_kept_in_shard_order(self, tmp_path):
        shards = build_shards(3)
        shards[2].metadata.plugin_load_errors = {MODULE: OTHER_ERROR}
        shards[1].metadata.plugin_load_errors = {MODULE: ERROR}

        # Passed in reverse, so the order kept is the shard index, not the
        # argument order.
        merged = merge_shard_results(list(reversed(as_loaded(shards))))

        assert merged.metadata.plugin_load_errors == {MODULE: f"{ERROR}; {OTHER_ERROR}"}

    def test_control_no_load_error_anywhere(self, tmp_path):
        merged = _write_merged(tmp_path, build_shards(3))

        assert merged["model"].metadata.plugin_load_errors == {}
        assert run_gate(merged["path"]) == 0


class _Orchestrator:
    """A project scan that ran bandit; a project in ``load_errors`` lost a plugin group."""

    load_errors: Dict[str, Dict[str, str]] = {}

    def __init__(self, **kwargs: Any) -> None:
        self.key = Path(kwargs["source_dir"]).name

    @classmethod
    def create(cls, **kwargs: Any) -> "_Orchestrator":
        return cls(**kwargs)

    def execute_scan(self, phases=None):
        from automated_security_helper.models.asharp_model import (
            AshAggregatedResults,
            ScannerTargetStatusInfo,
        )
        from automated_security_helper.schemas.sarif_schema_model import SarifReport

        model = AshAggregatedResults()
        model.sarif = SarifReport.model_validate(_sarif(count=0))
        model.scanner_results["bandit"] = ScannerTargetStatusInfo(
            status="PASSED", excluded=False, dependencies_satisfied=True
        )
        model.metadata.plugin_load_errors = dict(self.load_errors.get(self.key, {}))
        return model


def _workspace(tmp_path: Path, load_errors: Optional[Dict[str, Dict[str, str]]]):
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("web", "MEDIUM"))
    _Orchestrator.load_errors = load_errors or {}
    try:
        return execute_workspace(
            plan, _settings(tmp_path), orchestrator_factory=_Orchestrator.create
        )
    finally:
        _Orchestrator.load_errors = {}


@pytest.fixture
def web_lost_a_group(tmp_path):
    return _workspace(tmp_path, {"web": {MODULE: ERROR}})


class TestTheWorkspaceResultsKeepEveryProjectsLoadErrors:
    def test_the_unified_results_file_records_it(self, web_lost_a_group):
        document = json.loads(web_lost_a_group.results_path.read_text("utf-8"))

        assert document["metadata"].get("plugin_load_errors") == {MODULE: ERROR}

    def test_the_model_reads_it_back(self, web_lost_a_group):
        from automated_security_helper.models.asharp_model import AshAggregatedResults

        model = AshAggregatedResults.model_validate_json(
            web_lost_a_group.results_path.read_text("utf-8")
        )

        assert model.metadata.plugin_load_errors == {MODULE: ERROR}

    def test_the_completeness_gate_fails_the_workspace_file(
        self, web_lost_a_group, capsys
    ):
        assert run_gate(web_lost_a_group.results_path) == 1
        assert MODULE in capsys.readouterr().out

    def test_control_no_load_error_in_any_project(self, tmp_path):
        result = _workspace(tmp_path, None)
        document = json.loads(result.results_path.read_text("utf-8"))

        assert not document["metadata"].get("plugin_load_errors")
        assert run_gate(result.results_path) == 0
