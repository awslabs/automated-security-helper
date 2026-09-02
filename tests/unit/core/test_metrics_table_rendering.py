"""Behavior tests for the ASH metrics table renderer.

Scope. These tests exercise ``metrics_table`` only. The upstream metrics
calculation (``get_unified_scanner_metrics``) is substituted with real
``ScannerMetrics`` instances so each rendering branch -- narrow versus wide
terminal, each scanner status, the actionable-count styling -- can be driven
directly. ``ScannerMetrics`` is the production pydantic model, not a stand-in,
so a renamed or retyped field fails these tests rather than being fabricated.

``Console`` and ``ASH_LOGGER`` doubles are built with ``create_autospec`` against
the real objects: a bare ``Mock`` would answer to any attribute and could not
catch a call to a method that does not exist.
"""

from pathlib import Path
from unittest.mock import create_autospec, patch

import pytest
from rich.console import Console
from rich.table import Table
from rich.text import Text

from automated_security_helper.core import metrics_table as metrics_table_module
from automated_security_helper.core.metrics_table import (
    display_metrics_table,
    generate_metrics_table_from_unified_data,
)
from automated_security_helper.core.unified_metrics import ScannerMetrics
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.log import ASH_LOGGER

NARROW_WIDTH = 80
WIDE_WIDTH = 140


def _metrics(**overrides) -> ScannerMetrics:
    base = {
        "scanner_name": "bandit",
        "status": "PASSED",
        "threshold": "MEDIUM",
        "threshold_source": "global",
        "actionable": 0,
        "duration": 1.5,
    }
    base.update(overrides)
    return ScannerMetrics(**base)


def _console(width: int) -> Console:
    """A Console that renders into a string rather than the captured stdout."""
    return Console(width=width, file=None, record=True, force_terminal=False)


@pytest.fixture
def wide_console():
    return Console(width=WIDE_WIDTH, force_terminal=False)


@pytest.fixture
def narrow_console():
    return Console(width=NARROW_WIDTH, force_terminal=False)


def _build(metrics, console, source_dir=None, output_dir=None) -> Table:
    with patch.object(
        metrics_table_module, "get_unified_scanner_metrics", return_value=metrics
    ):
        return generate_metrics_table_from_unified_data(
            asharp_model=AshAggregatedResults(),
            source_dir=source_dir,
            output_dir=output_dir,
            console=console,
        )


def _cells(table: Table, header_options: tuple) -> list:
    """Return the cells of the first column whose header matches."""
    for column in table.columns:
        if column.header in header_options:
            return list(column._cells)
    raise AssertionError(
        f"no column headed {header_options}; have {[c.header for c in table.columns]}"
    )


# ---------------------------------------------------------------------------
# Responsive headers
# ---------------------------------------------------------------------------


def test_wide_console_uses_full_column_headers(wide_console):
    table = _build([_metrics()], wide_console)

    headers = [c.header for c in table.columns]
    assert headers == [
        "Scanner",
        "Suppressed",
        "Critical",
        "High",
        "Medium",
        "Low",
        "Info",
        "Duration",
        "Actionable",
        "Result",
        "Threshold",
    ]


def test_narrow_console_uses_abbreviated_column_headers(narrow_console):
    table = _build([_metrics()], narrow_console)

    headers = [c.header for c in table.columns]
    # "Scanner" and "Result" carry the same header in both modes; only the nine
    # others abbreviate.
    assert headers == [
        "Scanner",
        "S",
        "C",
        "H",
        "M",
        "L",
        "I",
        "Time",
        "Action",
        "Result",
        "Thresh",
    ]


def test_a_console_of_exactly_one_hundred_columns_is_treated_as_wide(wide_console):
    """The cutoff is ``width < 100``, so 100 itself keeps the full headers."""
    table = _build([_metrics()], Console(width=100, force_terminal=False))

    assert "Suppressed" in [c.header for c in table.columns]

    narrow = _build([_metrics()], Console(width=99, force_terminal=False))
    assert "S" in [c.header for c in narrow.columns]


def test_no_console_defaults_to_full_headers():
    table = _build([_metrics()], None)

    assert "Suppressed" in [c.header for c in table.columns]


# ---------------------------------------------------------------------------
# Threshold rendering
# ---------------------------------------------------------------------------


def test_wide_threshold_cell_shows_level_and_full_source(wide_console):
    table = _build(
        [_metrics(threshold="CRITICAL", threshold_source="scanner")], wide_console
    )

    cell = _cells(table, ("Threshold",))[0]
    assert isinstance(cell, Text)
    assert cell.plain == "CRITICAL (scanner)"


def test_narrow_threshold_cell_abbreviates_medium_to_med(narrow_console):
    table = _build(
        [_metrics(threshold="MEDIUM", threshold_source="global")], narrow_console
    )

    assert _cells(table, ("Thresh",))[0].plain == "MED (g)"


def test_narrow_threshold_cell_truncates_other_levels_to_four_characters(
    narrow_console,
):
    table = _build(
        [
            _metrics(threshold="CRITICAL", threshold_source="config"),
            _metrics(threshold="LOW", threshold_source="scanner"),
        ],
        narrow_console,
    )

    cells = [c.plain for c in _cells(table, ("Thresh",))]
    assert cells == ["CRIT (c)", "LOW (s)"]


# ---------------------------------------------------------------------------
# Status rendering
# ---------------------------------------------------------------------------

ALL_STATUSES = ["PASSED", "FAILED", "ERROR", "SKIPPED", "MISSING", "PENDING"]


def test_wide_status_cells_use_rich_markup_strings(wide_console):
    table = _build([_metrics(status=s) for s in ALL_STATUSES], wide_console)

    assert [c for c in _cells(table, ("Result",))] == [
        "[bold green]PASSED[/bold green]",
        "[bold red]FAILED[/bold red]",
        "[bold red]ERROR[/bold red]",
        "[bold blue]SKIPPED[/bold blue]",
        "[bold yellow]MISSING[/bold yellow]",
        "[bold white]PENDING[/bold white]",
    ]


def test_narrow_status_cells_use_styled_text_objects(narrow_console):
    table = _build([_metrics(status=s) for s in ALL_STATUSES], narrow_console)

    cells = _cells(table, ("Result",))
    assert all(isinstance(c, Text) for c in cells)
    assert [c.plain for c in cells] == ALL_STATUSES
    assert [c.style for c in cells] == [
        "green bold",
        "red bold",
        "red bold",
        "blue bold",
        "yellow bold",
        "white bold",
    ]


def test_an_unrecognized_status_falls_through_to_the_white_default(narrow_console):
    table = _build([_metrics(status="THROTTLED")], narrow_console)

    cell = _cells(table, ("Result",))[0]
    assert cell.plain == "THROTTLED"
    assert cell.style == "white bold"


# ---------------------------------------------------------------------------
# Actionable count styling
# ---------------------------------------------------------------------------


def test_a_nonzero_actionable_count_is_styled_red(wide_console):
    table = _build([_metrics(actionable=3)], wide_console)

    cell = _cells(table, ("Actionable",))[0]
    assert cell.plain == "3"
    assert cell.style == "red bold"


def test_a_zero_actionable_count_is_styled_green(wide_console):
    table = _build([_metrics(actionable=0)], wide_console)

    cell = _cells(table, ("Actionable",))[0]
    assert cell.plain == "0"
    assert cell.style == "green bold"


# ---------------------------------------------------------------------------
# Rows, durations and caption
# ---------------------------------------------------------------------------


def test_one_row_is_added_per_scanner_with_severity_counts_stringified(wide_console):
    table = _build(
        [
            _metrics(
                scanner_name="semgrep",
                suppressed=1,
                critical=2,
                high=3,
                medium=4,
                low=5,
                info=6,
            )
        ],
        wide_console,
    )

    assert len(table.rows) == 1
    assert _cells(table, ("Scanner",)) == ["semgrep"]
    assert _cells(table, ("Suppressed",)) == ["1"]
    assert _cells(table, ("Critical",)) == ["2"]
    assert _cells(table, ("High",)) == ["3"]
    assert _cells(table, ("Medium",)) == ["4"]
    assert _cells(table, ("Low",)) == ["5"]
    assert _cells(table, ("Info",)) == ["6"]


def test_duration_is_rendered_through_format_duration(wide_console):
    table = _build(
        [
            _metrics(scanner_name="a", duration=90),
            _metrics(scanner_name="b", duration=0.5),
            _metrics(scanner_name="c", duration=None),
        ],
        wide_console,
    )

    assert _cells(table, ("Duration",)) == ["1m 30s", "500ms", "N/A"]


def test_an_empty_metrics_list_yields_a_table_with_no_rows(wide_console):
    table = _build([], wide_console)

    assert table.rows == []
    assert len(table.columns) == 11


def test_caption_names_both_directories_when_both_are_supplied(wide_console, tmp_path):
    source_dir = tmp_path / "src"
    output_dir = tmp_path / "out"

    table = _build([_metrics()], wide_console, source_dir, output_dir)

    assert table.caption is not None
    assert "source-dir:" in table.caption
    assert "output-dir:" in table.caption
    # Assert on the leaf names: whether the paths render absolute or relative to
    # cwd depends on where pytest put tmp_path, and both forms end in these.
    assert Path(source_dir).name in table.caption
    assert Path(output_dir).name in table.caption


def test_caption_is_omitted_when_a_directory_is_missing(wide_console, tmp_path):
    table = _build([_metrics()], wide_console, tmp_path / "src", None)

    assert table.caption is None


# ---------------------------------------------------------------------------
# display_metrics_table
# ---------------------------------------------------------------------------


@pytest.fixture
def console_class():
    """An autospec'd Console class patched into the module under test."""
    cls = create_autospec(Console)
    with patch.object(metrics_table_module, "Console", cls):
        yield cls


@pytest.fixture
def logger():
    """An autospec'd ASH_LOGGER so branch-specific log calls can be asserted."""
    double = create_autospec(ASH_LOGGER)
    with patch.object(metrics_table_module, "ASH_LOGGER", double):
        yield double


@pytest.fixture
def stub_table():
    """Return a real Table from the generator so display_ can be driven alone."""
    with patch.object(
        metrics_table_module,
        "generate_metrics_table_from_unified_data",
        return_value=Table(title="stub"),
    ) as generator:
        yield generator


def test_display_uses_the_auto_color_system_on_non_windows(
    console_class, stub_table, logger
):
    with patch.object(metrics_table_module.platform, "system", return_value="Linux"):
        display_metrics_table(AshAggregatedResults(), use_color=True)

    kwargs = console_class.call_args.kwargs
    assert kwargs["color_system"] == "auto"
    assert kwargs["legacy_windows"] is False
    assert kwargs["safe_box"] is False
    assert kwargs["force_terminal"] is True


def test_display_uses_the_windows_color_system_on_windows(
    console_class, stub_table, logger
):
    with patch.object(metrics_table_module.platform, "system", return_value="Windows"):
        display_metrics_table(AshAggregatedResults(), use_color=True)

    kwargs = console_class.call_args.kwargs
    assert kwargs["color_system"] == "windows"
    assert kwargs["legacy_windows"] is True
    assert kwargs["safe_box"] is True


def test_display_disables_the_color_system_when_color_is_off(
    console_class, stub_table, logger
):
    display_metrics_table(AshAggregatedResults(), use_color=False)

    kwargs = console_class.call_args.kwargs
    assert kwargs["color_system"] is None
    assert kwargs["force_terminal"] is False


def test_display_uses_an_ascii_help_title_on_windows(console_class, stub_table, logger):
    with patch.object(metrics_table_module.platform, "system", return_value="Windows"):
        display_metrics_table(AshAggregatedResults())

    titles = [
        call.args[0].title
        for call in console_class.return_value.print.call_args_list
        if call.args and hasattr(call.args[0], "title")
    ]
    assert "[STATS] ASH Scan Results Help" in titles


def test_display_uses_an_emoji_help_title_off_windows(
    console_class, stub_table, logger
):
    with patch.object(metrics_table_module.platform, "system", return_value="Linux"):
        display_metrics_table(AshAggregatedResults())

    titles = [
        call.args[0].title
        for call in console_class.return_value.print.call_args_list
        if call.args and hasattr(call.args[0], "title")
    ]
    assert "📊 ASH Scan Results Help" in titles


def test_display_forwards_the_directories_to_the_table_generator(
    console_class, stub_table, logger, tmp_path
):
    model = AshAggregatedResults()

    display_metrics_table(model, source_dir=tmp_path / "s", output_dir=tmp_path / "o")

    kwargs = stub_table.call_args.kwargs
    assert kwargs["asharp_model"] is model
    assert kwargs["source_dir"] == tmp_path / "s"
    assert kwargs["output_dir"] == tmp_path / "o"
    assert kwargs["console"] is console_class.return_value


@pytest.mark.parametrize("io_error", [ValueError, OSError, BrokenPipeError])
def test_display_survives_a_closed_stream_and_logs_instead(
    console_class, stub_table, logger, io_error
):
    """A closed stdout must not fail the scan; it degrades to a log line."""
    console_class.return_value.print.side_effect = io_error("stream is closed")

    display_metrics_table(AshAggregatedResults())

    assert logger.warning.call_count == 1
    assert (
        "Could not write metrics table to console" in logger.warning.call_args.args[0]
    )
    logger.info.assert_called_once()
    assert logger.error.call_count == 0


def test_display_falls_back_to_plain_text_when_table_generation_fails(
    console_class, logger, capsys
):
    with patch.object(
        metrics_table_module,
        "generate_metrics_table_from_unified_data",
        side_effect=RuntimeError("model is malformed"),
    ):
        display_metrics_table(AshAggregatedResults())

    out = capsys.readouterr().out
    assert "ASH Scan Results Summary" in out
    assert "model is malformed" in out
    assert "Please check the output files for detailed results." in out
    assert logger.error.call_count == 1
    assert "Error displaying metrics table" in logger.error.call_args.args[0]


def test_display_logs_when_even_the_plain_text_fallback_cannot_write(
    console_class, logger
):
    """Both the table and the fallback print fail: the scan still returns."""
    with (
        patch.object(
            metrics_table_module,
            "generate_metrics_table_from_unified_data",
            side_effect=RuntimeError("model is malformed"),
        ),
        patch("builtins.print", side_effect=OSError("stdout closed")),
    ):
        display_metrics_table(AshAggregatedResults())

    assert logger.error.call_count == 1
    assert logger.warning.call_count == 1
    assert "Could not write to stdout/stderr" in logger.warning.call_args.args[0]
    logger.info.assert_called_once()


def test_display_returns_none_on_the_happy_path(console_class, stub_table, logger):
    assert display_metrics_table(AshAggregatedResults()) is None
    assert logger.warning.call_count == 0
    assert logger.error.call_count == 0
