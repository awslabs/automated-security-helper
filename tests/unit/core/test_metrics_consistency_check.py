"""The metrics consistency check runs where both sides of it are final.

It compares the totals of the ``scanner_results`` rows with ``summary_stats``, so it
runs at the end of ``populate_metrics_from_unified_source``, after both are written.
At the end of the scan phase neither is final: a scanner that ran has no row yet
(rows are rebuilt from the unified metrics after the final suppression pass), and
``save_model`` fills ``summary_stats`` from the SARIF whenever ``scanner_results`` is
empty, so a check there would log a "Metrics consistency check failed" warning per
severity -- ``scanner_results total=0, summary_stats=21`` and so on -- with nothing
inconsistent in the results.

A real mismatch is reported.
"""

from __future__ import annotations

from typing import Literal
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

WARNING = "Metrics consistency check failed"


class _Config(ScannerPluginConfigBase):
    name: Literal["finding-tool"] = "finding-tool"


class _Scanner(ScannerPluginBase):
    def model_post_init(self, context):
        if self.config is None:
            self.config = _Config()
        self.command = "finding-tool"
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError

    def scan(self, target, target_type, global_ignore_paths=None, config=None):
        return SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "finding-tool"}},
                        "results": [
                            {
                                "ruleId": f"R{index}",
                                "level": "error",
                                "message": {"text": "a finding"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app.py"},
                                            "region": {"startLine": index},
                                        }
                                    }
                                ],
                                "properties": {"scanner_name": "finding-tool"},
                            }
                            for index in (1, 2, 3)
                        ],
                    }
                ],
            }
        )


@pytest.fixture
def context(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("a = 1\nb = 2\nc = 3\n", encoding="utf-8")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=get_default_config(),
    )


def _warnings(warning_mock) -> list[str]:
    return [
        str(call.args[0])
        for call in warning_mock.call_args_list
        if call.args and WARNING in str(call.args[0])
    ]


def test_a_scan_where_every_scanner_ran_logs_no_consistency_warning(context):
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=[_Scanner],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )

    with patch.object(ASH_LOGGER, "warning", wraps=ASH_LOGGER.warning) as warning:
        results = phase._execute_phase(aggregated_results=aggregated, parallel=False)
        results = populate_metrics_from_unified_source(aggregated_results=results)

    assert results.metadata.summary_stats.critical == 3
    assert _warnings(warning) == [], (
        "nothing in these results is inconsistent; the warnings measured when the "
        f"check ran, not the results: {_warnings(warning)}"
    )


def test_a_real_mismatch_is_reported(context):
    from automated_security_helper.core.unified_metrics import (
        metrics_consistency_discrepancies,
    )

    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=[_Scanner],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    results = phase._execute_phase(aggregated_results=aggregated, parallel=False)
    results = populate_metrics_from_unified_source(aggregated_results=results)
    assert metrics_consistency_discrepancies(results) == []

    results.metadata.summary_stats.critical = 5

    assert metrics_consistency_discrepancies(results) == [
        "critical: scanner_results total=3, summary_stats=5"
    ]


def test_a_unified_metrics_row_is_counted_by_its_own_fields():
    """The third row shape the check reads: a ``ScannerMetrics`` placed in
    ``scanner_results`` as it is. Its severity counts, ``total`` and ``actionable``
    are its own attributes, so the check reads them rather than failing on the row
    and reporting nothing."""
    from automated_security_helper.core.unified_metrics import (
        ScannerMetrics,
        metrics_consistency_discrepancies,
    )

    results = AshAggregatedResults()
    results.scanner_results["finding-tool"] = ScannerMetrics(
        scanner_name="finding-tool", high=2, low=1, actionable=2
    )
    logger = MagicMock()

    discrepancies = metrics_consistency_discrepancies(results, logger=logger)

    logger.error.assert_not_called()
    assert discrepancies == [
        "high: scanner_results total=2, summary_stats=0",
        "low: scanner_results total=1, summary_stats=0",
        "total: scanner_results total=3, summary_stats=0",
        "actionable: scanner_results total=2, summary_stats=0",
    ]


def test_a_row_shaped_like_unified_metrics_but_not_one_is_logged_and_skipped():
    """A row with ScannerMetrics' first names but not its type: an unknown shape,
    logged at debug and left out of the totals, so the check does not raise on the
    first attribute it lacks, and it returns its result."""
    from types import SimpleNamespace

    from automated_security_helper.core.unified_metrics import (
        metrics_consistency_discrepancies,
    )

    results = AshAggregatedResults()
    results.scanner_results["look-alike"] = SimpleNamespace(
        critical=1, scanner_name="look-alike"
    )
    logger = MagicMock()

    discrepancies = metrics_consistency_discrepancies(results, logger=logger)

    logger.error.assert_not_called()
    assert discrepancies == []
    (message,) = [str(call.args[0]) for call in logger.debug.call_args_list]
    assert message.startswith("Unknown scanner_info structure for look-alike"), message


def test_a_real_mismatch_is_logged_by_the_rebuild(context):
    """Through the path every scan takes: the rebuild logs what the check finds."""
    from automated_security_helper.core import unified_metrics

    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=[_Scanner],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    results = phase._execute_phase(aggregated_results=aggregated, parallel=False)
    real = unified_metrics._populate_summary_stats_from_unified_metrics

    def miscount(aggregated_results, metrics):
        """A summary that disagrees with the rows by two criticals."""
        written = real(aggregated_results, metrics)
        written.metadata.summary_stats.critical += 2
        return written

    with (
        patch.object(
            unified_metrics, "_populate_summary_stats_from_unified_metrics", miscount
        ),
        patch.object(ASH_LOGGER, "warning", wraps=ASH_LOGGER.warning) as warning,
    ):
        populate_metrics_from_unified_source(aggregated_results=results)

    assert _warnings(warning) == [
        f"{WARNING} for critical: scanner_results total=3, summary_stats=5"
    ], _warnings(warning)
