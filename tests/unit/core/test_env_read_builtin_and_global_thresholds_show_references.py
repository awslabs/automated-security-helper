# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A builtin or global env-read severity threshold is shown as its reference.

The external-section fix keyed the shown form on the env resolver's marker
(``EnvResolvedScalar``), which only a non-validating dict section keeps: a
builtin scanner's typed section and the global settings validate the value to
a plain vocabulary word, so their report rows printed the resolved word. The
load already records every environment read with its written reference
(``AshConfig._environment_references``), so the shown form now consults that
record at the threshold's own path; grading still reads the resolved value.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)

BUILTIN_VAR = "ASH_SHOWN_BI_CANARY"
GLOBAL_VAR = "ASH_SHOWN_GL_CANARY"


def _resolve(tmp_path, monkeypatch, body: str, **env: str):
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "shown.yaml"
    path.write_text(body, encoding="utf-8")
    return resolve_config(config_path=str(path), fallback_to_default=False)


def _rows(config, *scanners: str):
    from automated_security_helper.models.asharp_model import (
        AshAggregatedResults,
        ScannerTargetStatusInfo,
    )
    from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
        ReportContentEmitter,
    )

    model = AshAggregatedResults()
    model.ash_config = config
    for scanner in scanners:
        model.scanner_results[scanner] = ScannerTargetStatusInfo(duration=1.0)
    return {
        r["scanner_name"]: r for r in ReportContentEmitter(model).get_scanner_results()
    }


def _builtin_config(tmp_path, monkeypatch):
    return _resolve(
        tmp_path,
        monkeypatch,
        "project_name: zz-shown\nscanners:\n  bandit:\n    enabled: true\n"
        "    options:\n      severity_threshold: ${" + BUILTIN_VAR + "}\n",
        **{BUILTIN_VAR: "MEDIUM"},
    )


def _global_config(tmp_path, monkeypatch):
    return _resolve(
        tmp_path,
        monkeypatch,
        "project_name: zz-shown\nglobal_settings:\n  severity_threshold: ${"
        + GLOBAL_VAR
        + "}\nscanners:\n  glthr:\n    enabled: true\n",
        **{GLOBAL_VAR: "CRITICAL"},
    )


def test_the_builtin_premise_validation_drops_the_marker(tmp_path, monkeypatch):
    """Premise: a typed section's env-read threshold validates to the plain
    resolved word, so the marker the external fix keys on cannot carry the
    shown form here."""
    config = _builtin_config(tmp_path, monkeypatch)
    value = config.scanners.bandit.options.severity_threshold
    assert type(value) is str and value == "MEDIUM", (type(value), value)


def test_a_builtin_env_read_threshold_row_shows_the_reference(tmp_path, monkeypatch):
    config = _builtin_config(tmp_path, monkeypatch)
    rows = _rows(config, "bandit")
    assert rows["bandit"]["threshold"] == "${" + BUILTIN_VAR + "}", rows["bandit"]
    assert rows["bandit"]["threshold_source"] == "config", rows["bandit"]


def test_the_builtin_grading_read_stays_the_resolved_value(tmp_path, monkeypatch):
    """The must-not-change control: the gate judges by what the variable held."""
    config = _builtin_config(tmp_path, monkeypatch)
    graded, source = ScannerStatisticsCalculator.get_scanner_threshold_info(
        SimpleNamespace(ash_config=config), "bandit"
    )
    assert (graded, source) == ("MEDIUM", "config"), (graded, source)


def test_a_global_env_read_threshold_row_shows_the_reference(tmp_path, monkeypatch):
    config = _global_config(tmp_path, monkeypatch)
    rows = _rows(config, "glthr")
    assert rows["glthr"]["threshold"] == "${" + GLOBAL_VAR + "}", rows["glthr"]
    assert rows["glthr"]["threshold_source"] == "global", rows["glthr"]


def test_the_global_grading_read_stays_the_resolved_value(tmp_path, monkeypatch):
    config = _global_config(tmp_path, monkeypatch)
    graded, source = ScannerStatisticsCalculator.get_scanner_threshold_info(
        SimpleNamespace(ash_config=config), "glthr"
    )
    assert (graded, source) == ("CRITICAL", "global"), (graded, source)


@pytest.mark.parametrize("reporter", ["markdown", "text"])
def test_the_scan_time_report_shows_the_reference_not_the_word(
    tmp_path, monkeypatch, reporter
):
    """The rendered reports built from the rows carry the reference. The
    resolved word is a vocabulary member, so the leak is set membership, not
    arbitrary text -- still, the row must say where the value came from."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.models.asharp_model import (
        AshAggregatedResults,
        ScannerTargetStatusInfo,
    )
    from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
        MarkdownReporter,
    )
    from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
        TextReporter,
    )

    config = _builtin_config(tmp_path, monkeypatch)
    model = AshAggregatedResults()
    model.ash_config = config
    model.scanner_results["bandit"] = ScannerTargetStatusInfo(duration=1.0)
    cls = {"markdown": MarkdownReporter, "text": TextReporter}[reporter]
    context = PluginContext(
        source_dir=tmp_path, output_dir=tmp_path / "out", config=config
    )
    text = cls(context=context).report(model)
    # The markdown reporter escapes {, _ and } in table cells; dropping the
    # backslashes reads the reference back through that venue's escaping.
    assert "${" + BUILTIN_VAR + "}" in text.replace("\\", ""), (
        "the report lost the reference"
    )


BUILTIN_DEFAULTED = "ASH_SHOWN_BI_DEFAULTED"
GLOBAL_DEFAULTED = "ASH_SHOWN_GL_DEFAULTED"


def _metrics_row(config, scanner: str):
    from automated_security_helper.core.unified_metrics import (
        get_unified_scanner_metrics,
    )
    from automated_security_helper.models.asharp_model import (
        AshAggregatedResults,
        ScannerTargetStatusInfo,
    )

    model = AshAggregatedResults()
    model.ash_config = config
    model.scanner_results[scanner] = ScannerTargetStatusInfo(duration=1.0)
    return {m.scanner_name: m for m in get_unified_scanner_metrics(model)}[scanner]


def _narrow_threshold_cell(config, scanner: str) -> str:
    from rich.console import Console

    from automated_security_helper.core.metrics_table import (
        generate_metrics_table_from_unified_data,
    )
    from automated_security_helper.models.asharp_model import (
        AshAggregatedResults,
        ScannerTargetStatusInfo,
    )

    model = AshAggregatedResults()
    model.ash_config = config
    model.scanner_results[scanner] = ScannerTargetStatusInfo(duration=1.0)
    table = generate_metrics_table_from_unified_data(
        asharp_model=model, console=Console(width=80, force_terminal=False)
    )
    column = next(c for c in table.columns if c.header == "Thresh")
    return column._cells[0].plain


def test_a_builtin_env_read_threshold_says_it_was_read(tmp_path, monkeypatch):
    """The row carries the reference and says the environment supplied it, so
    the narrow table names the env read and not a reference read back from a
    results file."""
    config = _builtin_config(tmp_path, monkeypatch)

    row = _metrics_row(config, "bandit")

    assert row.threshold == "${" + BUILTIN_VAR + "}", row
    assert row.threshold_from_env is True, row
    assert _narrow_threshold_cell(config, "bandit") == "ENV (c)"


def test_a_global_env_read_threshold_says_it_was_read(tmp_path, monkeypatch):
    config = _global_config(tmp_path, monkeypatch)

    row = _metrics_row(config, "glthr")

    assert row.threshold == "${" + GLOBAL_VAR + "}", row
    assert row.threshold_from_env is True, row
    assert _narrow_threshold_cell(config, "glthr") == "ENV (g)"


def test_a_builtin_threshold_that_used_its_default_shows_the_graded_level(
    tmp_path, monkeypatch
):
    """The variable is unset, so the file's own default is graded: the row shows
    that level and is no env read for the narrow table to name."""
    monkeypatch.delenv(BUILTIN_DEFAULTED, raising=False)
    config = _resolve(
        tmp_path,
        monkeypatch,
        "project_name: zz-shown\nscanners:\n  bandit:\n    enabled: true\n"
        "    options:\n      severity_threshold: ${" + BUILTIN_DEFAULTED + ":LOW}\n",
    )

    row = _metrics_row(config, "bandit")

    assert (row.threshold, row.threshold_from_env) == ("LOW", False), row
    assert _narrow_threshold_cell(config, "bandit") == "LOW (c)"


def test_a_global_threshold_that_used_its_default_shows_the_graded_level(
    tmp_path, monkeypatch
):
    monkeypatch.delenv(GLOBAL_DEFAULTED, raising=False)
    config = _resolve(
        tmp_path,
        monkeypatch,
        "project_name: zz-shown\nglobal_settings:\n  severity_threshold: ${"
        + GLOBAL_DEFAULTED
        + ":HIGH}\nscanners:\n  glthr:\n    enabled: true\n",
    )

    row = _metrics_row(config, "glthr")

    assert (row.threshold, row.threshold_from_env) == ("HIGH", False), row
    assert _narrow_threshold_cell(config, "glthr") == "HIGH (g)"


def test_a_directly_written_builtin_threshold_is_no_env_read(tmp_path, monkeypatch):
    """The must-not-flag control for provenance: a level typed into the file
    is shown as typed and claims no environment read."""
    config = _resolve(
        tmp_path,
        monkeypatch,
        "project_name: zz-shown\nscanners:\n  bandit:\n    enabled: true\n"
        "    options:\n      severity_threshold: LOW\n",
    )

    row = _metrics_row(config, "bandit")

    assert (row.threshold, row.threshold_from_env) == ("LOW", False), row
    assert _narrow_threshold_cell(config, "bandit") == "LOW (c)"


def test_a_directly_written_builtin_threshold_still_shows_itself(tmp_path, monkeypatch):
    """The must-not-flag control: a threshold typed into the file is shown as
    typed, for the builtin section exactly as for an external one."""
    config = _resolve(
        tmp_path,
        monkeypatch,
        "project_name: zz-shown\nscanners:\n  bandit:\n    enabled: true\n"
        "    options:\n      severity_threshold: LOW\n",
    )
    rows = _rows(config, "bandit")
    assert rows["bandit"]["threshold"] == "LOW", rows["bandit"]
    assert rows["bandit"]["threshold_source"] == "config", rows["bandit"]
