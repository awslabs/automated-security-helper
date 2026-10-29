"""A scanner's recorded status is read only from a report this version writes.

``ScanResultProcessor`` records, for each scanner and target, the serialized results
container: a mapping that names its scanner. ``get_scanner_status_info`` read the
``"None"`` and ``"source"`` entries by subscript. A results file from another ASH
version, or one put together by hand, can hold something else there: the sample
results under tests/test_data/outputs carry ``"source"`` mappings without
``scanner_name``. Merged as the one shard of a 1-way scan, that file raised
``KeyError: 'scanner_name'`` out of ``ash merge``.

Such an entry is no report. The scanner then has no recorded status, which the
calculator has always reported as an error, and the merge reaches a verdict.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

SAMPLE_RESULTS = (
    Path(__file__).resolve().parents[2]
    / "test_data"
    / "outputs"
    / "ash_aggregated_results.json"
)


def _status(reports) -> tuple:
    model = AshAggregatedResults()
    model.additional_reports = {"bandit": reports}
    return ScannerStatisticsCalculator.get_scanner_status_info(model, "bandit")


@pytest.mark.parametrize(
    "reports",
    [
        pytest.param({"source": {"status": "PASSED"}}, id="source-without-a-name"),
        pytest.param(
            {"None": {"status": "PASSED", "excluded": True}}, id="None-without-a-name"
        ),
        pytest.param({"source": "PASSED"}, id="source-not-a-mapping"),
        pytest.param({"None": ["PASSED"]}, id="None-not-a-mapping"),
        pytest.param("source None", id="the-scanner's-entry-not-a-mapping"),
        pytest.param(
            {"source": {"scanner_name": "grype", "status": "PASSED"}},
            id="source-naming-another-scanner-passed",
        ),
        pytest.param(
            {"source": {"scanner_name": "grype", "status": "MISSING"}},
            id="source-naming-another-scanner-missing",
        ),
        pytest.param(
            {"None": {"scanner_name": "grype", "status": "SKIPPED", "excluded": True}},
            id="None-naming-another-scanner",
        ),
    ],
)
def test_an_entry_that_is_no_report_records_no_status(reports):
    """An entry that is no report, or that names another scanner, records no
    status, so the scanner reads as errored, as a scanner with nothing recorded
    always has. Only a
    results file given to ``ash merge`` can hold such a report: a scan writes each
    one under the name it carries."""
    assert _status(reports) == (False, False, True)


@pytest.mark.parametrize(
    "reports,expected",
    [
        pytest.param(
            {"source": {"scanner_name": "bandit", "status": "PASSED"}},
            (False, False, False),
            id="source-passed",
        ),
        pytest.param(
            {"source": {"scanner_name": "bandit", "status": "MISSING"}},
            (False, True, False),
            id="source-missing",
        ),
        pytest.param(
            {"None": {"scanner_name": "bandit", "status": "SKIPPED", "excluded": True}},
            (True, False, False),
            id="None-excluded",
        ),
    ],
)
def test_a_report_this_version_writes_is_read(reports, expected):
    """The control: a report that names its scanner gives its status."""
    assert _status(reports) == expected


def _merge_the_sample_results_as_one_shard(tmp_path, *flags):
    from automated_security_helper.cli.main import app
    from automated_security_helper.cli.merge import (
        RESULTS_FILE_NAME,
        stamp_shard_assignment,
    )
    from automated_security_helper.core.sharding import ShardAssignment
    from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
        CsvReporter,
    )
    from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
        SarifReporter,
    )

    model = AshAggregatedResults.model_validate_json(
        SAMPLE_RESULTS.read_text(encoding="utf-8")
    )
    scanners = sorted(model.additional_reports)
    stamp_shard_assignment(
        model,
        ShardAssignment(
            shard_index=0,
            shard_count=1,
            assigned_scanners=scanners,
            candidate_scanners=scanners,
        ),
    )
    shard = tmp_path / "shard-0"
    shard.mkdir()
    (shard / RESULTS_FILE_NAME).write_text(
        model.model_dump_json(indent=2), encoding="utf-8"
    )
    manager = MagicMock()
    manager.plugin_modules.return_value = [SarifReporter, CsvReporter]
    with (
        patch("automated_security_helper.cli.merge.ash_plugin_manager", manager),
        patch("automated_security_helper.cli.merge.load_plugins"),
    ):
        return CliRunner().invoke(
            app,
            [
                "merge",
                "--results",
                str(shard),
                "--output-dir",
                str(tmp_path / "out"),
                *flags,
            ],
        )


def test_the_sample_results_merge_as_one_shard_to_a_verdict(tmp_path):
    """Its scanners recorded no report this version reads, so each one is
    incomplete; told to merge anyway, the merge counts the findings and exits 2
    for them, with no traceback."""
    result = _merge_the_sample_results_as_one_shard(
        tmp_path, "--no-fail-on-incomplete-scanners"
    )

    assert isinstance(result.exception, SystemExit), result.exception
    assert result.exit_code == 2, result.output
    assert "Exiting due to 32 actionable findings" in result.output
    assert (tmp_path / "out" / "ash_aggregated_results.json").is_file()


def test_without_the_override_the_sample_results_are_refused(tmp_path):
    """The other control: by default, a shard whose scanners all recorded nothing
    is refused before any statistics are read, as it was."""
    result = _merge_the_sample_results_as_one_shard(tmp_path)

    assert isinstance(result.exception, SystemExit), result.exception
    assert result.exit_code == 1, result.output
    assert "completed none of the scanners they owned" in result.output
