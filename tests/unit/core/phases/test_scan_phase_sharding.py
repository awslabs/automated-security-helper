# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Sharding applied inside the scan phase, where scanner names are authoritative.

Why the partition lives here
----------------------------
A shard has to be expressed in terms of the same names ``--exclude-scanners``
matches on, which is ``plugin_instance.config.name``. That is only knowable after
instantiation: scanner classes carry no class-level ``name``, and constructing one
without a plugin context raises ``PydanticUserError``. So the CLI layer cannot
compute the partition -- it would have to guess names, and a name it guessed wrong
would be assigned to no shard and silently dropped from the whole scan.

The partition is taken over every *registered* scanner, before the
dependency-satisfied and enabled filters run. That way two executors agree on the
split even when a tool is installed on one runner and missing on another; the
missing one is then reported as MISSING by the shard that owns it, rather than
shifting the partition and quietly moving other scanners between shards.

The expected partitions below are written out by hand rather than computed with
``partition_scanners``. Deriving them from the function under test would make
these tests agree with any partition rule, including a broken one.
"""

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scanner_validation import ScannerValidationManager
from automated_security_helper.core.phases.scan_phase import ScanPhase


# sorted(...) is [bandit, checkov, grype, semgrep]; dealt round-robin at count=2
# that is positions 0,2 -> shard 0 and positions 1,3 -> shard 1.
FOUR_SCANNERS = ["semgrep", "bandit", "grype", "checkov"]
EXPECTED_AT_2 = {
    0: {"bandit", "grype"},
    1: {"checkov", "semgrep"},
}
# At count=3: positions 0,3 -> 0; position 1 -> 1; position 2 -> 2.
EXPECTED_AT_3 = {
    0: {"bandit", "semgrep"},
    1: {"checkov"},
    2: {"grype"},
}


@pytest.fixture
def mock_plugin_context(tmp_path):
    ctx = MagicMock()
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "app.py").write_text("print('hello')")
    (tmp_path / "work").mkdir()
    (tmp_path / "output").mkdir()
    ctx.source_dir = source_dir
    ctx.work_dir = tmp_path / "work"
    ctx.output_dir = tmp_path / "output"
    ctx.config = MagicMock()
    ctx.config.get_plugin_config.return_value = None
    ctx.config.global_settings.ignore_paths = []
    ctx.ignore_suppressions = False
    ctx.cached_source_files = []
    return ctx


def _class_name_for(config_name: str) -> str:
    """Mimic the real gap between a scanner's class name and its config name.

    Real scanners differ: ``DetectSecretsScanner`` carries ``config.name ==
    "detect-secrets"``. Doubles that set both to the same string cannot tell
    whether the code read the config name or the class name -- a mutation that
    dropped the config-name preference passed all 1114 tests in this repo.
    """
    return config_name.replace("-", "").replace("_", "").capitalize() + "Scanner"


def _make_scanner_class(name, enabled=True, deps_satisfied=True, python_only=True):
    """Callable scanner-class double that returns a configured instance."""
    class_name = _class_name_for(name)
    plugin_cls = MagicMock()
    plugin_cls.__name__ = class_name

    instance = MagicMock()
    instance.__class__ = plugin_cls
    instance.__class__.__name__ = class_name

    config = MagicMock()
    config.name = name
    config.enabled = enabled
    config.options.severity_threshold = "HIGH"
    instance.config = config

    instance.validate_plugin_dependencies.return_value = deps_satisfied
    instance.dependencies_satisfied = deps_satisfied
    instance.is_python_only.return_value = python_only
    instance.errors = []
    instance.output = []
    instance.exit_code = 0
    instance.start_time = datetime(2024, 1, 1, 10, 0, 0)
    instance.end_time = datetime(2024, 1, 1, 10, 0, 5)
    instance.context = None

    plugin_cls.return_value = instance
    return plugin_cls


@pytest.fixture
def scan_phase(mock_plugin_context):
    """ScanPhase with a specced validation manager.

    ``spec=`` is deliberate and mirrors the sibling suite: a bare MagicMock
    fabricates any attribute touched, so it would agree with a call to a method
    the real facade does not have.
    """
    with patch(
        "automated_security_helper.core.phases.scan_phase.ScannerValidationManager"
    ) as MockValMgr:
        val_mgr = MagicMock(spec=ScannerValidationManager)
        val_mgr.validate_registered_scanners.return_value = None
        val_mgr.validate_scanner_enablement.return_value = None

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

        val_mgr.validate_task_queue.return_value = checkpoint
        val_mgr.validate_execution_completion.return_value = checkpoint
        val_mgr.ensure_complete_results.return_value = checkpoint
        val_mgr.report_execution_discrepancies.return_value = {}
        val_mgr.report_result_completeness.return_value = {}
        MockValMgr.return_value = val_mgr

        phase = ScanPhase(
            plugin_context=mock_plugin_context,
            plugins=[],
            progress_display=MagicMock(add_task=MagicMock(return_value=1)),
        )
        phase.validation_manager = val_mgr
        return phase


def _excluded_names(result: AshAggregatedResults) -> set[str]:
    return {
        name
        for name, status in result.scanner_results.items()
        if getattr(status, "excluded", False)
    }


def _run(scan_phase, scanner_names, **kwargs) -> AshAggregatedResults:
    scan_phase.plugins = [_make_scanner_class(n) for n in scanner_names]
    return scan_phase._execute_phase(
        aggregated_results=AshAggregatedResults(),
        parallel=False,
        **kwargs,
    )


class TestShardPartitioning:
    @pytest.mark.parametrize("index", [0, 1])
    def test_shard_excludes_exactly_the_scanners_it_does_not_own(
        self, scan_phase, index
    ):
        result = _run(scan_phase, FOUR_SCANNERS, shard_index=index, shard_count=2)
        assert _excluded_names(result) == set(FOUR_SCANNERS) - EXPECTED_AT_2[index]

    @pytest.mark.parametrize("index", [0, 1, 2])
    def test_uneven_split_is_still_exact(self, scan_phase, index):
        result = _run(scan_phase, FOUR_SCANNERS, shard_index=index, shard_count=3)
        assert _excluded_names(result) == set(FOUR_SCANNERS) - EXPECTED_AT_3[index]

    def test_partition_does_not_depend_on_plugin_order(self, scan_phase, request):
        # plugin_modules() order follows module load sequence, which differs
        # between executors. If the split moved with it, two shards would run the
        # same scanner and a third would run none.
        forward = _run(scan_phase, FOUR_SCANNERS, shard_index=0, shard_count=2)
        # A second phase instance, because _execute_phase mutates phase state.
        other = request.getfixturevalue("scan_phase")
        reversed_ = _run(
            other, list(reversed(FOUR_SCANNERS)), shard_index=0, shard_count=2
        )
        assert _excluded_names(forward) == _excluded_names(reversed_)

    def test_single_shard_excludes_nothing(self, scan_phase):
        result = _run(scan_phase, FOUR_SCANNERS, shard_index=0, shard_count=1)
        assert _excluded_names(result) == set()

    def test_no_shard_selection_excludes_nothing(self, scan_phase):
        # The regression guard for every existing non-sharded invocation.
        result = _run(scan_phase, FOUR_SCANNERS)
        assert _excluded_names(result) == set()


class TestShardStatusSemantics:
    def test_unassigned_scanner_is_excluded_not_missing(self, scan_phase):
        """SKIPPED/excluded, never MISSING.

        MISSING means the scanner's dependencies were unsatisfied -- a broken
        runner. Reporting an unassigned shard member that way would have every
        shard's report claim most scanners are broken, and would hide a genuinely
        missing tool among the noise.
        """
        result = _run(scan_phase, FOUR_SCANNERS, shard_index=0, shard_count=2)
        for name in set(FOUR_SCANNERS) - EXPECTED_AT_2[0]:
            status = result.scanner_results[name]
            assert status.status == ScannerStatus.SKIPPED, name
            assert status.excluded is True, name
            assert status.dependencies_satisfied is True, name


class TestOperatorExclusionsAndSharding:
    def test_operator_exclusion_is_honoured_inside_a_shard(self, scan_phase):
        # --exclude-scanners bandit on shard 0, which owns bandit. The operator's
        # exclusion must win; dropping it would run a scanner they turned off.
        result = _run(
            scan_phase,
            FOUR_SCANNERS,
            shard_index=0,
            shard_count=2,
            excluded_scanners=["bandit"],
        )
        assert _excluded_names(result) == set(FOUR_SCANNERS) - {"grype"}

    def test_operator_exclusion_of_another_shards_scanner_is_harmless(self, scan_phase):
        result = _run(
            scan_phase,
            FOUR_SCANNERS,
            shard_index=0,
            shard_count=2,
            excluded_scanners=["checkov"],
        )
        assert _excluded_names(result) == set(FOUR_SCANNERS) - EXPECTED_AT_2[0]


class TestScannerDisplayName:
    """The name rule the whole phase keys on, which nothing else covered.

    Both the shard partition and the ``--exclude-scanners`` check are computed
    from ``_scanner_display_name``, and ``scanner_results`` is keyed by it. If the
    config name stopped winning, every result key would change from
    ``detect-secrets`` to ``detectsecretsscanner`` and the operator's own
    ``--exclude-scanners detect-secrets`` would stop matching. Removing the
    preference passed the entire existing suite, so it is pinned here.
    """

    def test_config_name_wins_over_the_class_name(self):
        from automated_security_helper.core.phases.scan_phase import (
            _scanner_display_name,
        )

        instance = _make_scanner_class("detect-secrets").return_value
        assert instance.__class__.__name__ == "DetectsecretsScanner"
        assert _scanner_display_name(instance) == "detect-secrets"

    @pytest.mark.parametrize("absent_value", [None, ""])
    def test_falls_back_to_the_class_name_when_config_name_is_unusable(
        self, absent_value
    ):
        from automated_security_helper.core.phases.scan_phase import (
            _scanner_display_name,
        )

        instance = _make_scanner_class("detect-secrets").return_value
        instance.config.name = absent_value
        # Lower-cased, matching what the phase logged before the helper existed.
        assert _scanner_display_name(instance) == "detectsecretsscanner"

    def test_falls_back_when_there_is_no_config_at_all(self):
        from automated_security_helper.core.phases.scan_phase import (
            _scanner_display_name,
        )

        instance = _make_scanner_class("grype").return_value
        instance.config = None
        assert _scanner_display_name(instance) == "grypescanner"

    def test_the_partition_is_computed_over_config_names(self):
        # The end-to-end consequence: shard membership must be decided by the
        # names an operator writes, not by Python class names.
        from automated_security_helper.core.sharding import partition_scanners

        assert partition_scanners(FOUR_SCANNERS, 0, 2) == sorted(EXPECTED_AT_2[0])


class TestShardSelectionValidation:
    @pytest.mark.parametrize(
        "index,count",
        [(0, None), (None, 2), (2, 2), (-1, 2), (0, 0)],
    )
    def test_an_unusable_selection_is_refused(self, scan_phase, index, count):
        from automated_security_helper.core.exceptions import ShardSelectionError

        with pytest.raises(ShardSelectionError):
            _run(scan_phase, FOUR_SCANNERS, shard_index=index, shard_count=count)
