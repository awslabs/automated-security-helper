# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash merge`` is quiet about scanners every shard's ``--scanners`` left out.

Two shards run with the same ``--scanners bandit,detect-secrets`` merge without
"WARNING 8 scanner(s) were assigned to a shard but no shard intended to run them:
cdk-nag (assigned to shard 1), cfn-nag ...", a warning that would name every
scanner outside the list on every such merge. A record of what a shard selected
among only the scanners it owns can't tell ``ash merge`` "no job asked for it"
from "one job asked for it and its owner did not".

Each shard also records ``intended_scanners``, what its selection asks for over
every candidate. These tests run the real ``ScanPhase`` selection for each shard,
stamp what it recorded onto the shard results, and merge them.
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.cli.merge import (
    merge_shard_results,
    stamp_shard_assignment,
)
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scanner_validation import ScannerValidationManager
from tests.unit.cli.test_merge import SCANNERS, as_loaded, build_shard
from tests.unit.core.phases.test_scan_phase_sharding import _make_scanner_class

pytestmark = pytest.mark.unit

# The ``capture`` fixture comes from tests/unit/conftest.py by name, so this file
# and test_merge.py capture warnings the same way.


def _phase(tmp_path, index):
    """A ScanPhase as tests/unit/core/phases/test_scan_phase_sharding.py builds one."""
    source_dir = tmp_path / f"shard-{index}" / "source"
    source_dir.mkdir(parents=True)
    (source_dir / "app.py").write_text("print('hello')")
    context = MagicMock()
    context.source_dir = source_dir
    context.work_dir = source_dir.parent / "work"
    context.output_dir = source_dir.parent / "output"
    context.config.get_plugin_config.return_value = None
    context.config.global_settings.ignore_paths = []
    context.ignore_suppressions = False
    context.cached_source_files = []

    checkpoint = MagicMock()
    checkpoint.get_missing_scanners.return_value = []
    checkpoint.get_unexpected_scanners.return_value = []
    checkpoint.has_issues.return_value = False
    checkpoint.checkpoint_name = "test"
    checkpoint.timestamp = datetime(2024, 1, 1)
    checkpoint.expected_scanners = []
    checkpoint.actual_scanners = []
    checkpoint.discrepancies = []
    checkpoint.errors = []
    checkpoint.metadata = {}
    validation = MagicMock(spec=ScannerValidationManager)
    validation.validate_task_queue.return_value = checkpoint
    validation.validate_execution_completion.return_value = checkpoint
    validation.ensure_complete_results.return_value = checkpoint
    validation.report_execution_discrepancies.return_value = {}
    validation.report_result_completeness.return_value = {}

    with patch(
        "automated_security_helper.core.phases.scan_phase.ScannerValidationManager",
        return_value=validation,
    ):
        phase = ScanPhase(
            plugin_context=context,
            plugins=[],
            progress_display=MagicMock(add_task=MagicMock(return_value=1)),
        )
    phase.validation_manager = validation
    return phase


def _shards(
    tmp_path, selections, disabled=(), python_only=False, non_python=(), older=()
):
    """Run ScanPhase for each shard of a 2-way split with that shard's --scanners.

    *disabled* scanners have ``enabled: false`` in every shard's config, and
    *non_python* scanners are not Python-only. A shard index in *older* drops
    ``intended_scanners``, as results from a release without the field have.
    """
    shards = []
    for index, enabled in enumerate(selections):
        phase = _phase(tmp_path, index)
        phase.plugins = [
            _make_scanner_class(
                name,
                enabled=name not in disabled,
                python_only=name not in non_python,
            )
            for name in SCANNERS
        ]
        phase._execute_phase(
            aggregated_results=AshAggregatedResults(),
            parallel=False,
            shard_index=index,
            shard_count=2,
            enabled_scanners=enabled,
            python_based_plugins_only=python_only,
        )
        assignment = phase._shard_assignment
        if index in older:
            assignment.intended_scanners = None
        model = build_shard(index, 2, assignment.assigned_scanners)
        stamp_shard_assignment(model, assignment)
        shards.append(model)
    return shards


def _warnings(capture):
    return [
        record.getMessage()
        for record in capture.records
        if record.levelname == "WARNING" and "scanner(s)" in record.getMessage()
    ]


def test_the_same_allowlist_on_every_shard_is_quiet(tmp_path, capture):
    allowlist = ["bandit", "detect-secrets"]
    shards = _shards(tmp_path, [allowlist, allowlist])

    merge_shard_results(as_loaded(shards))

    assert _warnings(capture) == []


def test_a_scanner_one_job_asked_for_and_its_owner_dropped_is_named(
    tmp_path,
    capture,
):
    """Sorted, the five scanners deal bandit, detect-secrets and semgrep to shard 0
    and checkov and grype to shard 1. Shard 0's job asked for grype; shard 1's did
    not, so grype ran nowhere. checkov was asked for by neither job."""
    shards = _shards(tmp_path, [["bandit", "grype"], ["bandit"]])

    merge_shard_results(as_loaded(shards))

    warnings = _warnings(capture)
    assert warnings, "the hole was not named"
    assert "grype" in warnings[0]
    assert "checkov" not in warnings[0], warnings[0]


def test_a_scanner_every_shards_config_disables_is_quiet(tmp_path, capture):
    """grype is shard 1's; its config disables it on both jobs."""
    shards = _shards(tmp_path, [[], []], disabled=("grype",))

    merge_shard_results(as_loaded(shards))

    assert _warnings(capture) == []


def test_a_scanner_one_jobs_config_disabled_is_named(tmp_path, capture):
    """The enabled flag is part of what a job asks for: shard 0's job has grype
    enabled, shard 1's, which owns it, does not."""
    first = _shards(tmp_path / "a", [[]])[0]
    second = _shards(tmp_path / "b", [[], []], disabled=("grype",))[1]

    merge_shard_results(as_loaded([first, second]))

    warnings = _warnings(capture)
    assert warnings and "grype" in warnings[0], warnings


def test_one_older_shard_brings_back_the_old_warning(tmp_path, capture):
    """Every shard has to say what it asked for; one that cannot leaves merge
    unable to tell a choice from a hole, so it names every scanner that ran
    nowhere."""
    allowlist = ["bandit", "detect-secrets"]
    shards = _shards(tmp_path, [allowlist, allowlist], older=(1,))

    merge_shard_results(as_loaded(shards))

    warnings = _warnings(capture)
    assert warnings and "no shard intended to run them" in warnings[0], warnings


def test_a_python_only_run_does_not_ask_for_the_other_scanners(tmp_path):
    shards = _shards(
        tmp_path, [[], []], python_only=True, non_python=("grype", "semgrep")
    )

    for shard in shards:
        intended = shard.metadata.shard.intended_scanners
        assert "grype" not in intended and "semgrep" not in intended, intended
        assert "bandit" in intended
