# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--exclude-scanners semgrep`` leaves opengrep out, and the rows say so.

Why these tests exist
---------------------
``semgrep`` is a retired scanner name that opengrep serves
(``utils/scanner_names.SCANNER_NAME_ALIASES``). The scan phase resolved the names
of ``--scanners`` and ``--exclude-scanners`` to their plugin only after it had
subtracted the exclusions from the allowlist and recorded what the operator
excluded. So an exclusion by the old name:

* escaped the check that refuses an allowlist its exclusions cancel
  (``--scanners opengrep --exclude-scanners semgrep`` ran no scanner at all);
* was missing from the set the not-selected rows are told apart by, so an
  excluded scanner whose constructor raised was recorded ERROR and failed the
  completeness gate of a run that ran everything it selected, and a sharded run's
  row blamed the shard split for what the operator excluded.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.exceptions import ScannerSelectionError
from automated_security_helper.core.constants import SHARD_SPLIT_REASON_PREFIX
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.core.scanner_selection import selection_after_exclusions
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
)

pytestmark = pytest.mark.unit


class TestTheCancelledSelection:
    def test_an_allowlist_its_exclusion_by_the_old_name_empties_is_refused(self):
        # Red at the base: [opengrep] came back, and the phase then excluded it.
        with pytest.raises(ScannerSelectionError):
            selection_after_exclusions(["opengrep"], ["semgrep"])

    def test_the_old_name_in_the_allowlist_is_cancelled_by_the_new_one(self):
        with pytest.raises(ScannerSelectionError):
            selection_after_exclusions(["Semgrep"], ["opengrep"])

    def test_an_exclusion_by_the_old_name_leaves_the_other_scanners_selected(self):
        """The control: only the scanner the alias names is taken out."""
        assert selection_after_exclusions(["bandit", "opengrep"], ["semgrep"]) == [
            "bandit"
        ]

    def test_the_phase_refuses_the_cancelled_selection(self, tmp_path):
        phase, aggregated = _phase(tmp_path, [_plugin("Opengrep", "opengrep")])

        # Red at the base: the phase ran zero scanners and returned.
        with pytest.raises(ScannerSelectionError):
            phase._execute_phase(
                aggregated_results=aggregated,
                enabled_scanners=["opengrep"],
                excluded_scanners=["semgrep"],
            )


def _constructor_raises(self, *args, **kwargs):
    raise RuntimeError("constructor failed")


class TestTheRowsOfAnExcludedScanner:
    @pytest.fixture(autouse=True)
    def _opengrep_constructor_raises(self, monkeypatch):
        monkeypatch.setattr(OpengrepScanner, "__init__", _constructor_raises)

    def test_a_constructor_failure_of_a_scanner_excluded_by_the_old_name_is_skipped(
        self, tmp_path
    ):
        phase, aggregated = _phase(tmp_path, [OpengrepScanner])

        result = _run(phase, aggregated, excluded_scanners=["semgrep"])

        row = result.scanner_results["opengrep"]
        # Red at the base: ERROR, which failed the completeness gate.
        assert row.status == ScannerStatus.SKIPPED, row
        assert row.excluded is True
        assert "excluded from this run" in (row.skipped_reason or ""), row

    def test_a_constructor_failure_that_nothing_excluded_is_still_an_error(
        self, tmp_path
    ):
        """The control: the exclusion is what changes the row."""
        phase, aggregated = _phase(tmp_path, [OpengrepScanner])

        result = _run(phase, aggregated, excluded_scanners=["bandit"])

        assert result.scanner_results["opengrep"].status == ScannerStatus.ERROR

    @pytest.mark.parametrize("shard_index", [0, 1])
    def test_a_shards_row_for_it_names_the_exclusion_not_the_split(
        self, tmp_path, shard_index
    ):
        phase, aggregated = _phase(
            tmp_path,
            [_plugin("Opengrep", "opengrep"), _plugin("Other", "other")],
        )

        result = _run(
            phase,
            aggregated,
            excluded_scanners=["semgrep"],
            shard_index=shard_index,
            shard_count=2,
        )

        reason = result.scanner_results["opengrep"].skipped_reason or ""
        # Red at the base on the shard that was not assigned it: the split's reason.
        assert not reason.startswith(SHARD_SPLIT_REASON_PREFIX), reason
        assert "excluded from this run" in reason, reason


def _plugin(class_name: str, config_name: str):
    cls = MagicMock(name=class_name)
    cls.__name__ = class_name
    instance = MagicMock()
    instance.__class__ = cls
    instance.__class__.__name__ = class_name
    config = MagicMock()
    config.enabled = True
    config.name = config_name
    instance.config = config
    instance.is_python_only.return_value = True
    instance.unsupported_platform_reason.return_value = None
    instance.validate_plugin_dependencies.return_value = True
    instance.dependencies_satisfied = True
    cls.return_value = instance
    return cls


def _phase(tmp_path, plugins):
    for sub in ("src", "out", "work"):
        (tmp_path / sub).mkdir(exist_ok=True)
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=plugins,
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    phase.validation_manager = MagicMock()
    return phase, aggregated


def _run(phase, aggregated, **kwargs):
    with patch(
        "automated_security_helper.core.phases.scan_phase.ScannerExecutor"
    ) as executor:
        double = MagicMock()
        double.completed_scanners = []
        double.run_parallel.return_value = aggregated
        double.run_sequential.return_value = aggregated
        executor.return_value = double
        return phase._execute_phase(aggregated_results=aggregated, **kwargs)


class TestASelectionByTheOldName:
    def test_the_old_name_is_served_and_recorded_as_matched(self, tmp_path):
        phase, aggregated = _phase(
            tmp_path, [_plugin("Opengrep", "opengrep"), _plugin("Other", "other")]
        )

        result = _run(phase, aggregated, enabled_scanners=["semgrep"])

        # Red before the names were resolved: ["semgrep"] was recorded as unmatched.
        assert result.metadata.requested_scanners_not_run is None

    def test_the_control_a_misspelled_name_is_still_recorded_as_unmatched(
        self, tmp_path
    ):
        phase, aggregated = _phase(
            tmp_path, [_plugin("Opengrep", "opengrep"), _plugin("Other", "other")]
        )

        result = _run(phase, aggregated, enabled_scanners=["semgrep", "nope"])

        assert result.metadata.requested_scanners_not_run == ["nope"]
