# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An env-read severity threshold is shown as its reference, graded by value.

An external scanner section's ``options.severity_threshold`` can be written as
``${VARIABLE}``. The resolver keeps the reference in the stored config, and the
grading read deliberately takes the resolved text so the gate works -- but the
report surfaces (the emitter's scanner rows, and the markdown, text and html
reports built from them) printed that same resolved text, so a value read from
the environment appeared in every rendered report. The rows now show the
written reference, and the resolved value is used for grading only.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.utils.redacted_model import EnvResolvedScalar

pytestmark = pytest.mark.unit

THRESHOLD_CANARY = "zz-thr-canary-krw"
VARIABLE = "ASH_SHOWN_THR_CANARY"
REFERENCE = "${" + VARIABLE + "}"
SCANNER = "extthr"


@pytest.fixture
def ext_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(VARIABLE, THRESHOLD_CANARY)
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "ext.yaml"
    path.write_text(
        "project_name: zz-thr\n"
        f"scanners:\n  {SCANNER}:\n    enabled: true\n    options:\n"
        f"      severity_threshold: {REFERENCE}\n",
        encoding="utf-8",
    )
    return resolve_config(config_path=str(path), fallback_to_default=False)


def _report_model(config, scanner: str = SCANNER):
    from automated_security_helper.models.asharp_model import (
        AshAggregatedResults,
        ScannerTargetStatusInfo,
    )

    model = AshAggregatedResults()
    model.ash_config = config
    model.scanner_results[scanner] = ScannerTargetStatusInfo(duration=1.0)
    return model


def test_the_raw_section_holds_the_marker_premise(ext_config):
    entry = ext_config.get_plugin_config(plugin_type="scanner", plugin_name=SCANNER)
    assert isinstance(entry["options"]["severity_threshold"], EnvResolvedScalar), entry


def test_the_grading_read_stays_the_resolved_value(ext_config):
    """The must-not-change control: the gate judges by what the variable held."""
    threshold, source = ScannerStatisticsCalculator.get_scanner_threshold_info(
        SimpleNamespace(ash_config=ext_config, additional_reports={}), SCANNER
    )
    assert type(threshold) is str and threshold == THRESHOLD_CANARY, (
        type(threshold),
        threshold,
    )
    assert source == "config", source


def test_the_results_record_keeps_the_reference_control(ext_config):
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    dumped = json.dumps(
        AshAggregatedResults(ash_config=ext_config).model_dump(mode="json")[
            "ash_config"
        ]
    )
    assert THRESHOLD_CANARY not in dumped, "the results record holds the value"
    assert REFERENCE in dumped, "the results record lost the reference"


def test_the_emitter_row_shows_the_reference_not_the_value(ext_config):
    from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
        ReportContentEmitter,
    )

    rows = {
        r["scanner_name"]: r
        for r in ReportContentEmitter(_report_model(ext_config)).get_scanner_results()
    }
    assert SCANNER in rows, sorted(rows)
    assert rows[SCANNER]["threshold"] == REFERENCE, rows[SCANNER]
    assert THRESHOLD_CANARY not in repr(rows[SCANNER]), rows[SCANNER]


def _report_text(reporter: str, config, tmp_path: Path) -> str:
    """What the named scan-time reporter prints for the one-scanner model."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
        HtmlReporter,
    )
    from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
        MarkdownReporter,
    )
    from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
        TextReporter,
    )

    cls = {"markdown": MarkdownReporter, "text": TextReporter, "html": HtmlReporter}[
        reporter
    ]
    context = PluginContext(
        source_dir=tmp_path, output_dir=tmp_path / "out", config=config
    )
    return cls(context=context).report(_report_model(config))


@pytest.mark.parametrize("reporter", ["markdown", "text", "html"])
def test_the_scan_time_report_shows_the_reference_not_the_value(
    ext_config, tmp_path, reporter
):
    text = _report_text(reporter, ext_config, tmp_path)
    assert SCANNER in text, text[:2000]
    assert THRESHOLD_CANARY not in text, [
        line for line in text.splitlines() if THRESHOLD_CANARY in line
    ]
    # The markdown reporter escapes {, _ and } in table cells; dropping the
    # backslashes reads the reference back through that venue's escaping.
    assert REFERENCE in text.replace("\\", ""), "the report lost the reference"


@pytest.mark.parametrize(
    "surface", ["emitter", "metrics-table", "markdown", "text", "html"]
)
def test_every_report_surface_prints_the_threshold_the_stats_row_carries(
    ext_config, tmp_path, surface
):
    """The shown form travels in the stats row, and every surface that prints a
    scanner's threshold prints that row's threshold with its source -- none
    rebuilds it from the config."""
    from rich.console import Console

    from automated_security_helper.core.metrics_table import (
        generate_metrics_table_from_unified_data,
    )
    from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
        ReportContentEmitter,
    )

    model = _report_model(ext_config)
    row = ScannerStatisticsCalculator.extract_scanner_statistics(model)[SCANNER]
    assert row["threshold"] == REFERENCE, row  # the premise: a reference to carry
    cell = f"{row['threshold']} ({row['threshold_source']})"

    if surface == "emitter":
        printed = {
            r["scanner_name"]: r
            for r in ReportContentEmitter(model).get_scanner_results()
        }[SCANNER]
        assert (printed["threshold"], printed["threshold_source"]) == (
            row["threshold"],
            row["threshold_source"],
        )
    elif surface == "metrics-table":
        table = generate_metrics_table_from_unified_data(
            asharp_model=model, console=Console(width=140, force_terminal=False)
        )
        column = next(c for c in table.columns if c.header == "Threshold")
        assert [c.plain for c in column._cells] == [cell]
    else:
        # The markdown reporter escapes {, _ and } in table cells; dropping the
        # backslashes reads the cell back through that venue's escaping.
        assert cell in _report_text(surface, ext_config, tmp_path).replace("\\", "")


def test_a_glued_reference_is_shown_whole(tmp_path, monkeypatch):
    """A reference with trailing text (``${VAR}tail``) is shown as written.

    The resolver glues the tail onto the variable's value, so the grading
    value is the glued text -- and the shown form is the whole written
    reference, tail included. Rebuilt from the variable's name alone it would
    read ``${VAR}``, which is not what the file says the threshold is.
    """
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
        ReportContentEmitter,
    )

    glued_variable = "ASH_SHOWN_THR_GLUE"
    glued_tail = "-thr-tail-krw"
    glued_reference = "${" + glued_variable + "}" + glued_tail
    glued_value = "zz-glue-head-krw"

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(glued_variable, glued_value)
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "ext.yaml"
    path.write_text(
        "project_name: zz-thr\n"
        f"scanners:\n  {SCANNER}:\n    enabled: true\n    options:\n"
        f"      severity_threshold: {glued_reference}\n",
        encoding="utf-8",
    )
    config = resolve_config(config_path=str(path), fallback_to_default=False)

    # The grading control: the gate judges by the glued resolved text.
    threshold, _source = ScannerStatisticsCalculator.get_scanner_threshold_info(
        SimpleNamespace(ash_config=config, additional_reports={}), SCANNER
    )
    assert threshold == glued_value + glued_tail, threshold

    rows = {
        r["scanner_name"]: r
        for r in ReportContentEmitter(_report_model(config)).get_scanner_results()
    }
    assert rows[SCANNER]["threshold"] == glued_reference, rows[SCANNER]
    assert glued_value not in repr(rows[SCANNER]), rows[SCANNER]


def test_a_directly_written_threshold_still_shows_itself(tmp_path, monkeypatch):
    """The must-not-flag control: a threshold typed into the file is shown as typed."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
        ReportContentEmitter,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "ext.yaml"
    path.write_text(
        "project_name: zz-thr\n"
        f"scanners:\n  {SCANNER}:\n    enabled: true\n    options:\n"
        "      severity_threshold: HIGH\n",
        encoding="utf-8",
    )
    config = resolve_config(config_path=str(path), fallback_to_default=False)

    rows = {
        r["scanner_name"]: r
        for r in ReportContentEmitter(_report_model(config)).get_scanner_results()
    }
    assert rows[SCANNER]["threshold"] == "HIGH", rows[SCANNER]


def _config_writing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, written: str):
    """The config a file writes *written* as the external scanner's threshold."""
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(VARIABLE, THRESHOLD_CANARY)
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "ext.yaml"
    path.write_text(
        "project_name: zz-thr\n"
        f"scanners:\n  {SCANNER}:\n    enabled: true\n    options:\n"
        f"      severity_threshold: {written}\n",
        encoding="utf-8",
    )
    return resolve_config(config_path=str(path), fallback_to_default=False)


def _metrics_row(config):
    return _metrics_row_of(_report_model(config))


def _metrics_row_of(model, scanner: str = SCANNER):
    from automated_security_helper.core.unified_metrics import (
        get_unified_scanner_metrics,
    )

    rows = {m.scanner_name: m for m in get_unified_scanner_metrics(model)}
    return rows[scanner]


def _narrow_threshold_cell(config) -> str:
    return _narrow_threshold_cell_of(_report_model(config))


def _narrow_threshold_cell_of(model) -> str:
    from rich.console import Console

    from automated_security_helper.core.metrics_table import (
        generate_metrics_table_from_unified_data,
    )

    table = generate_metrics_table_from_unified_data(
        asharp_model=model,
        console=Console(width=80, force_terminal=False),
    )
    column = next(c for c in table.columns if c.header == "Thresh")
    return column._cells[0].plain


def _rendered_table_text(model, width: int) -> str:
    """The metrics table as a *width*-column console renders it: the bytes a
    reader sees, never a row object or a matcher's return value."""
    from rich.console import Console

    from automated_security_helper.core.metrics_table import (
        generate_metrics_table_from_unified_data,
    )

    table = generate_metrics_table_from_unified_data(
        asharp_model=model,
        console=Console(width=width, force_terminal=False),
    )
    sink = Console(width=width, force_terminal=False, record=True)
    sink.print(table)
    return sink.export_text()


def _dumped_and_reloaded(config, tmp_path: Path):
    """The results record a later invocation reads, written and loaded the way
    production does it: dumped with the results writer's exact kwargs
    (``model_dump_json(indent=2, by_alias=True)``, models/asharp_model.py), so
    a drift in either side reddens this file; loaded back with
    ``model_validate_json`` under ``warning_of_dropped_keys``; then
    ``take_own_values`` over the reloaded config with the report path's
    kwargs. Both reload paths run that call -- ``ash report``, and a scan over
    existing results, which is the one that renders the metrics table -- and
    its pending set is the fields the record cannot hold, so the external
    section's reloaded reference text survives it. Returns the reloaded model
    and the file's text."""
    from automated_security_helper.config.recorded_config import take_own_values
    from automated_security_helper.models.asharp_model import (
        AshAggregatedResults,
        warning_of_dropped_keys,
    )

    results_file = tmp_path / "ash_aggregated_results.json"
    results_file.write_text(
        _report_model(config).model_dump_json(indent=2, by_alias=True),
        encoding="utf-8",
    )
    text = results_file.read_text(encoding="utf-8")
    with open(results_file, "r", encoding="utf-8") as f:
        with warning_of_dropped_keys(results_file) as context:
            record = AshAggregatedResults.model_validate_json(f.read(), context=context)
    take_own_values(
        record.ash_config,
        config,
        override_keys=[],
        refuse_unless_supplied=(
            "Pass it with --config-overrides '{field}=<value>', or a --config "
            "file that sets it."
        ),
    )
    return record, text


def test_an_env_read_threshold_row_says_it_was_read_and_the_narrow_cell_says_env(
    ext_config,
):
    row = _metrics_row(ext_config)
    assert row.threshold == REFERENCE, row
    assert row.threshold_from_env is True, row
    assert _narrow_threshold_cell(ext_config) == "ENV (c)"


def test_a_marker_copied_from_older_state_still_masks_the_rendered_bytes(ext_config):
    """A marker that survived from older state carries only ``variable``: str's
    copy protocol carries the slots the source instance has, and an instance
    written before ``shown`` and ``from_environment`` existed has neither. The
    summary read treats the missing slot as read-from-the-environment
    (``getattr(raw_threshold, "from_environment", True)``) and rebuilds the
    shown form from the name, so the rendered table bytes carry the reference
    and never the value the variable held."""
    entry = ext_config.scanners.__pydantic_extra__[SCANNER]
    marker = entry["options"]["severity_threshold"]
    assert isinstance(marker, EnvResolvedScalar), marker
    degraded = EnvResolvedScalar(str(marker))
    degraded.variable = marker.variable
    assert not hasattr(degraded, "shown"), "not the older-state shape"
    assert not hasattr(degraded, "from_environment"), "not the older-state shape"
    entry["options"]["severity_threshold"] = degraded

    # The premise: the read the summary makes sees the degraded shape.
    placed = ext_config.get_plugin_config(plugin_type="scanner", plugin_name=SCANNER)[
        "options"
    ]["severity_threshold"]
    assert isinstance(placed, EnvResolvedScalar), placed
    assert not hasattr(placed, "from_environment"), placed

    model = _report_model(ext_config)
    wide = _rendered_table_text(model, width=200)
    assert THRESHOLD_CANARY not in wide, [
        line for line in wide.splitlines() if THRESHOLD_CANARY in line
    ]
    assert REFERENCE in wide, wide
    narrow = _rendered_table_text(model, width=80)
    assert THRESHOLD_CANARY not in narrow, narrow
    assert "ENV (c)" in narrow, narrow


@pytest.mark.parametrize(
    "resolved,expected",
    [
        (("MEDIUM", "global"), ("MEDIUM", "MEDIUM", "global", False)),
        (("HIGH", "config"), ("HIGH", REFERENCE, "config", True)),
    ],
    ids=["global-fallback", "normalized-value"],
)
def test_the_reference_is_kept_while_the_source_is_the_scanners_own_config(
    ext_config, monkeypatch, resolved, expected
):
    """The kept reference describes where the scanner's own threshold came
    from. When the resolver answers the global level for it, the source is no
    longer the scanner's config and the row shows what is graded with that
    source. When the source stays config but the resolver normalized the text
    (strip, upper-case), the graded value was still read from the environment,
    so the row keeps the reference: the normalized text is derived from the
    variable's value, and showing it would print that value in every report."""
    from automated_security_helper.core import scanner_statistics_calculator

    monkeypatch.setattr(
        scanner_statistics_calculator,
        "resolve_scanner_threshold",
        lambda scanner_threshold, ash_config, scanner_name=None: resolved,
    )

    assert (
        ScannerStatisticsCalculator._threshold_resolution(
            SimpleNamespace(ash_config=ext_config, additional_reports={}), SCANNER
        )
        == expected
    )


@pytest.mark.parametrize(
    "written",
    ["high", "${" + "ASH_SHOWN_THR_DEFAULTED" + ":high}"],
    ids=["typed-level", "unset-variable-used-default"],
)
def test_a_literal_threshold_the_resolver_normalized_shows_what_is_graded(
    tmp_path, monkeypatch, written
):
    """The must-not-hide control for the kept reference: a level typed into the
    file is no secret and no reference, so a normalized answer is shown as the
    graded value. A reference whose variable is unset used its default, which
    is the file's own typed level, so it shows the graded value the same way
    and not the default's raw text."""
    from automated_security_helper.core import scanner_statistics_calculator

    monkeypatch.delenv("ASH_SHOWN_THR_DEFAULTED", raising=False)
    config = _config_writing(tmp_path, monkeypatch, written)
    monkeypatch.setattr(
        scanner_statistics_calculator,
        "resolve_scanner_threshold",
        lambda scanner_threshold, ash_config, scanner_name=None: ("HIGH", "config"),
    )

    assert ScannerStatisticsCalculator._threshold_resolution(
        SimpleNamespace(ash_config=config, additional_reports={}), SCANNER
    ) == ("HIGH", "HIGH", "config", False)


def test_a_quoted_reference_shows_the_reference_token_in_the_narrow_cell(
    tmp_path, monkeypatch
):
    """A quoted reference in a live config is plain text the resolver never
    read: the same shape as a reloaded record's threshold (a plain str with no
    resolver marker), but with no results file involved. The narrow cell must
    not cut that text mid-reference. The round trip itself is the next test."""
    config = _config_writing(tmp_path, monkeypatch, "'" + REFERENCE + "'")
    entry = config.get_plugin_config(plugin_type="scanner", plugin_name=SCANNER)
    assert type(entry["options"]["severity_threshold"]) is str, entry

    row = _metrics_row(config)
    assert (row.threshold, row.threshold_from_env) == (REFERENCE, False), row
    assert _narrow_threshold_cell(config) == "REF (c)"


@pytest.mark.parametrize(
    "written",
    [REFERENCE, "!ENV " + REFERENCE],
    ids=["bare-reference", "tagged-reference"],
)
def test_a_results_record_reloaded_by_a_scan_over_existing_results_shows_ref(
    tmp_path, monkeypatch, written
):
    """The path the code comment and the help line describe: a scan read the
    variable and wrote its results record, and a later scan over those
    existing results loads the file back, runs ``take_own_values`` over the
    reloaded config, and hands the model to the execution engine, which
    renders the metrics table (``ash report`` runs the same reload and the
    same ``take_own_values`` but never renders this table). The record holds
    the reference as the file wrote it (the ``!ENV `` tag included), the
    reloaded row has no provenance flag, the narrow cell reads ``REF (c)``,
    and the variable's value appears nowhere -- not in the file, not in the
    reloaded dump, and not in the rendered table bytes."""
    config = _config_writing(tmp_path, monkeypatch, written)
    scan_row = _metrics_row(config)
    assert scan_row.threshold_from_env is True, scan_row  # the premise: a real read
    assert _narrow_threshold_cell(config) == "ENV (c)"

    record, text = _dumped_and_reloaded(config, tmp_path)

    assert THRESHOLD_CANARY not in text, "the results file holds the value"
    assert REFERENCE in text, "the results file lost the reference"
    entry = record.ash_config.get_plugin_config(
        plugin_type="scanner", plugin_name=SCANNER
    )
    reloaded = entry["options"]["severity_threshold"]
    assert type(reloaded) is str and REFERENCE in reloaded, reloaded

    row = _metrics_row_of(record)
    assert row.threshold_from_env is False, row
    assert _narrow_threshold_cell_of(record) == "REF (c)"
    narrow = _rendered_table_text(record, width=80)
    assert "REF (c)" in narrow, narrow
    assert THRESHOLD_CANARY not in narrow, narrow
    assert THRESHOLD_CANARY not in record.model_dump_json(), "the reload resolved it"
    assert THRESHOLD_CANARY not in repr(row), row


BUILTIN_SCANNER = "bandit"
BUILTIN_VARIABLE = "ASH_SHOWN_THR_BUILTIN"
GLOBAL_VARIABLE = "ASH_SHOWN_THR_GLOBAL"


def test_a_builtin_scanners_env_read_threshold_says_env_in_the_narrow_cell(
    tmp_path, monkeypatch
):
    """A builtin (typed) section validates the env-read text to the plain
    level, so no resolver marker survives the load; the load's record is what
    knows the variable was read, and the row says so: the written reference
    with ``ENV (c)``, never ``REF``, which the help line reserves for a
    reference ASH did not read in this run."""
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(BUILTIN_VARIABLE, "MEDIUM")
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "builtin.yaml"
    path.write_text(
        "project_name: zz-thr\n"
        f"scanners:\n  {BUILTIN_SCANNER}:\n    enabled: true\n    options:\n"
        "      severity_threshold: ${" + BUILTIN_VARIABLE + "}\n",
        encoding="utf-8",
    )
    config = resolve_config(config_path=str(path), fallback_to_default=False)

    # The premise: validation typed the value to the plain level.
    entry = config.get_plugin_config(plugin_type="scanner", plugin_name=BUILTIN_SCANNER)
    assert entry["options"]["severity_threshold"] == "MEDIUM", entry
    assert type(entry["options"]["severity_threshold"]) is str, entry

    model = _report_model(config, scanner=BUILTIN_SCANNER)
    row = _metrics_row_of(model, scanner=BUILTIN_SCANNER)
    assert row.threshold == "${" + BUILTIN_VARIABLE + "}", row
    assert (row.threshold_source, row.threshold_from_env) == ("config", True), row
    assert _narrow_threshold_cell_of(model) == "ENV (c)"


def test_a_global_env_read_threshold_says_env_g_in_the_narrow_cell(
    tmp_path, monkeypatch
):
    """``global_settings.severity_threshold`` is a typed field too: the load
    validates the env-read text to the plain level and records the read. A
    scanner with no threshold of its own grades at that global level, and its
    row names the read: the written reference with ``ENV (g)``."""
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(GLOBAL_VARIABLE, "LOW")
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "glob.yaml"
    path.write_text(
        "project_name: zz-thr\n"
        "global_settings:\n"
        "  severity_threshold: ${" + GLOBAL_VARIABLE + "}\n"
        f"scanners:\n  {SCANNER}:\n    enabled: true\n",
        encoding="utf-8",
    )
    config = resolve_config(config_path=str(path), fallback_to_default=False)

    # The premise: validation typed the value to the plain level.
    assert config.global_settings.severity_threshold == "LOW"

    row = _metrics_row(config)
    assert row.threshold == "${" + GLOBAL_VARIABLE + "}", row
    assert (row.threshold_source, row.threshold_from_env) == ("global", True), row
    assert _narrow_threshold_cell(config) == "ENV (g)"


DEFAULTED = "ASH_SHOWN_THR_DEFAULTED"


def test_a_defaulted_reference_whose_variable_is_set_shows_without_its_default(
    tmp_path, monkeypatch
):
    """``${VAR:MEDIUM}`` with VAR=CRITICAL grades at CRITICAL. Printing the
    default would show a level the gate is not using, so the row shows the
    reference without it (the value it stands for stays out of the report)."""
    from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
        ReportContentEmitter,
    )

    monkeypatch.setenv(DEFAULTED, "CRITICAL")
    config = _config_writing(tmp_path, monkeypatch, "${" + DEFAULTED + ":MEDIUM}")

    threshold, source = ScannerStatisticsCalculator.get_scanner_threshold_info(
        SimpleNamespace(ash_config=config, additional_reports={}), SCANNER
    )
    assert (threshold, source) == ("CRITICAL", "config")
    rows = {
        r["scanner_name"]: r
        for r in ReportContentEmitter(_report_model(config)).get_scanner_results()
    }
    assert rows[SCANNER]["threshold"] == "${" + DEFAULTED + "}", rows[SCANNER]
    assert "MEDIUM" not in repr(rows[SCANNER]), rows[SCANNER]
    assert _metrics_row(config).threshold_from_env is True


def test_a_glued_defaulted_reference_keeps_its_tail_and_drops_its_default(
    tmp_path, monkeypatch
):
    monkeypatch.setenv(DEFAULTED, "zz-glue-head-krw")
    config = _config_writing(tmp_path, monkeypatch, "${" + DEFAULTED + ":MEDIUM}-tail")

    assert _metrics_row(config).threshold == "${" + DEFAULTED + "}-tail"


def test_a_defaulted_reference_that_used_its_default_shows_the_default_value(
    tmp_path, monkeypatch
):
    """The variable is unset, so the file's own default is what is graded: the
    row shows that level, and it is no env read for the narrow table to name."""
    monkeypatch.delenv(DEFAULTED, raising=False)
    config = _config_writing(tmp_path, monkeypatch, "${" + DEFAULTED + ":HIGH}")

    threshold, source = ScannerStatisticsCalculator.get_scanner_threshold_info(
        SimpleNamespace(ash_config=config, additional_reports={}), SCANNER
    )
    assert (threshold, source) == ("HIGH", "config")
    row = _metrics_row(config)
    assert row.threshold == "HIGH", row
    assert row.threshold_from_env is False, row
    assert _narrow_threshold_cell(config) == "HIGH (c)"


def test_the_resolver_marker_records_which_branch_it_took(monkeypatch):
    from automated_security_helper.config.ash_config import resolve_env_references

    monkeypatch.setenv(DEFAULTED, "CRITICAL")
    read = resolve_env_references("${" + DEFAULTED + ":MEDIUM}")
    assert (read, read.shown, read.from_environment) == (
        "CRITICAL",
        "${" + DEFAULTED + "}",
        True,
    )

    monkeypatch.delenv(DEFAULTED)
    defaulted = resolve_env_references("${" + DEFAULTED + ":MEDIUM}")
    assert (defaulted, defaulted.shown, defaulted.from_environment) == (
        "MEDIUM",
        "MEDIUM",
        False,
    )


@pytest.mark.parametrize(
    "written",
    ["${HOME}", "'" + REFERENCE + "'"],
    ids=["refused-name", "quoted-reference"],
)
def test_a_reference_text_the_resolver_never_read_is_not_claimed_as_env(
    tmp_path, monkeypatch, written
):
    """The must-not-flag control for provenance: ``${HOME}`` is a name the
    resolver refuses to read, and a quoted reference never reaches it. Both stay
    literal text that merely looks like a reference."""
    config = _config_writing(tmp_path, monkeypatch, written)

    row = _metrics_row(config)
    assert row.threshold_from_env is False, row
    assert "ENV" not in _narrow_threshold_cell(config)
