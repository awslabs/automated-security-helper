# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The CSV and flat-JSON reports name duplicate clusters when asked, and only then.

A real model with two scanners' SARIF runs reporting one CVE in one package (and
one finding only grype reports) is flattened and reported both ways. The cells
pin the contract the design makes: default off leaves the header and every row
byte-identical; on adds three columns after every other column; rows, ids,
severities, suppressions and per-scanner counts are the same either way.
"""

import csv
import json
from io import StringIO

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
    CsvReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
    FlatJSONReporter,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    Message1,
    PropertyBag,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.finding_clusters import ANNOTATION_COLUMNS
from automated_security_helper.core.unified_metrics import get_unified_scanner_metrics

pytestmark = pytest.mark.unit

CVE = "CVE-2024-0001"


def _run(scanner, rule_id, level, **package):
    props = PropertyBag(tags=[f"tool_name::{scanner}"])
    props.__pydantic_extra__ = {"scanner_name": scanner, **package}
    return Run(
        tool=Tool(driver=ToolComponent(name=scanner)),
        results=[
            Result(
                ruleId=rule_id,
                level=level,
                message=Message(root=Message1(text=f"{scanner} says {rule_id}")),
                properties=props,
            )
        ],
    )


def _model(*, annotate=False) -> AshAggregatedResults:
    left_pad = {
        "package_name": "left-pad",
        "package_path": "node_modules/left-pad",
    }
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    model.ash_config.global_settings.deduplication.annotate = annotate
    model.sarif = SarifReport(
        runs=[
            _run("grype", CVE, "error", package_version="1.0.0", **left_pad),
            _run("trivy", CVE, "warning", package_version="1.0.1", **left_pad),
            _run(
                "grype",
                "CVE-2024-0002",
                "note",
                package_name="other",
                package_path="node_modules/other",
            ),
        ]
    )
    return model


def _csv(test_plugin_context, model):
    text = CsvReporter(context=test_plugin_context).report(model)
    rows = list(csv.DictReader(StringIO(text)))
    return text, list(csv.reader(StringIO(text)))[0], rows


def _by_scanner(rows, cve=CVE):
    return {row["scanner"]: row for row in rows if row["rule_id"] == cve}


def test_the_default_csv_has_none_of_the_columns(test_plugin_context):
    _, header, rows = _csv(test_plugin_context, _model())
    assert not set(ANNOTATION_COLUMNS) & set(header)
    assert len(rows) == 3


def test_annotation_adds_three_columns_after_every_other_column(test_plugin_context):
    _, off_header, _ = _csv(test_plugin_context, _model())
    _, on_header, _ = _csv(test_plugin_context, _model(annotate=True))
    assert on_header == [*off_header, *ANNOTATION_COLUMNS]


def test_every_pre_existing_cell_is_unchanged_when_annotating(test_plugin_context):
    _, off_header, off_rows = _csv(test_plugin_context, _model())
    _, _, on_rows = _csv(test_plugin_context, _model(annotate=True))
    assert len(on_rows) == len(off_rows)
    for before, after in zip(off_rows, on_rows, strict=True):
        assert {key: after[key] for key in off_header} == before


def test_the_csv_names_the_primary_and_the_duplicate(test_plugin_context):
    _, _, rows = _csv(test_plugin_context, _model(annotate=True))
    by_scanner = _by_scanner(rows)
    grype, trivy = by_scanner["grype"], by_scanner["trivy"]

    assert grype["cluster_id"] == trivy["cluster_id"] != ""
    assert grype["cluster_id"].startswith("dup-")
    # The more severe finding stands for the cluster.
    assert grype["duplicate_of"] == ""
    assert json.loads(grype["duplicate_sources"]) == [
        {
            "id": trivy["id"],
            "rule_id": CVE,
            "scanner": "trivy",
            "severity": trivy["severity"],
        }
    ]
    assert trivy["duplicate_of"] == grype["id"]
    assert trivy["duplicate_sources"] == ""


def test_a_finding_in_no_cluster_has_blank_cells(test_plugin_context):
    _, _, rows = _csv(test_plugin_context, _model(annotate=True))
    lone = _by_scanner(rows, "CVE-2024-0002")["grype"]
    assert [lone[column] for column in ANNOTATION_COLUMNS] == ["", "", ""]


def test_ids_stay_the_scanner_inclusive_identity(test_plugin_context):
    _, _, off_rows = _csv(test_plugin_context, _model())
    _, _, on_rows = _csv(test_plugin_context, _model(annotate=True))
    ids = [row["id"] for row in on_rows]
    assert ids == [row["id"] for row in off_rows]
    assert len(set(ids)) == len(ids), "two scanners' reports are still two findings"


def test_the_header_only_form_follows(test_plugin_context):
    empty = AshAggregatedResults()
    empty.ash_config = get_default_config()
    off = CsvReporter(context=test_plugin_context).report(empty)
    empty.ash_config.global_settings.deduplication.annotate = True
    on = CsvReporter(context=test_plugin_context).report(empty)
    assert on.splitlines() == [off.splitlines()[0] + "," + ",".join(ANNOTATION_COLUMNS)]


def test_the_default_flat_json_carries_no_annotation_key(test_plugin_context):
    data = json.loads(FlatJSONReporter(context=test_plugin_context).report(_model()))
    assert all(not set(ANNOTATION_COLUMNS) & set(f) for f in data["findings"])


def test_flat_json_annotates_only_clustered_findings(test_plugin_context):
    off = json.loads(FlatJSONReporter(context=test_plugin_context).report(_model()))
    on = json.loads(
        FlatJSONReporter(context=test_plugin_context).report(_model(annotate=True))
    )
    assert [f["id"] for f in on["findings"]] == [f["id"] for f in off["findings"]]
    by_scanner = {f["scanner"]: f for f in on["findings"] if f["rule_id"] == CVE}
    grype, trivy = by_scanner["grype"], by_scanner["trivy"]
    assert grype["cluster_id"] == trivy["cluster_id"]
    assert "duplicate_of" not in grype
    assert [s["scanner"] for s in grype["duplicate_sources"]] == ["trivy"]
    assert trivy["duplicate_of"] == grype["id"]
    assert "duplicate_sources" not in trivy
    (lone,) = [f for f in on["findings"] if f["rule_id"] == "CVE-2024-0002"]
    assert not set(ANNOTATION_COLUMNS) & set(lone)
    # Everything but the annotation is what the default report carries.
    for before, after in zip(off["findings"], on["findings"], strict=True):
        assert {k: v for k, v in after.items() if k not in ANNOTATION_COLUMNS} == before
    for key in ("scanner_metrics", "top_hotspots"):
        assert on[key] == off[key]


def test_per_scanner_metrics_are_blind_to_the_annotation():
    off, on = _model(), _model(annotate=True)
    assert get_unified_scanner_metrics(on) == get_unified_scanner_metrics(off)


def _write(output_dir, model):
    (output_dir / "ash_aggregated_results.json").write_text(
        model.model_dump_json(by_alias=True), encoding="utf-8"
    )


def _cli_csv(output_dir, *extra):
    result = CliRunner().invoke(
        app,
        [
            "report",
            "--format",
            "csv",
            "--output-dir",
            str(output_dir),
            "--log-level",
            "ERROR",
            *extra,
        ],
    )
    assert result.exit_code == 0, result.output
    lines = result.stdout.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("id,"))
    return list(csv.reader(StringIO("\n".join(lines[start:]))))[0]


def test_ash_report_flag_turns_the_columns_on(tmp_path):
    _write(tmp_path, _model())
    assert not set(ANNOTATION_COLUMNS) & set(_cli_csv(tmp_path))
    header = _cli_csv(tmp_path, "--annotate-duplicates")
    assert tuple(header[-3:]) == ANNOTATION_COLUMNS


def test_ash_report_honors_the_recorded_setting_and_the_override(tmp_path):
    _write(tmp_path, _model(annotate=True))
    assert tuple(_cli_csv(tmp_path)[-3:]) == ANNOTATION_COLUMNS
    _write(tmp_path, _model())
    header = _cli_csv(
        tmp_path, "--config-overrides", "global_settings.deduplication.annotate=true"
    )
    assert tuple(header[-3:]) == ANNOTATION_COLUMNS


def test_an_explicit_false_override_turns_the_recorded_setting_off(tmp_path):
    _write(tmp_path, _model(annotate=True))
    header = _cli_csv(
        tmp_path, "--config-overrides", "global_settings.deduplication.annotate=false"
    )
    assert not set(ANNOTATION_COLUMNS) & set(header)
    # Left unnamed by the operator's configuration, the recorded setting stands.
    assert tuple(_cli_csv(tmp_path)[-3:]) == ANNOTATION_COLUMNS


def test_a_request_the_results_cannot_record_is_said_not_swallowed(tmp_path, caplog):
    import logging

    # A workspace's merged results record no ash_config, so the request has
    # nowhere to land; the reporters then render without it, which must be
    # said, never a silent no-op.
    _write(tmp_path, AshAggregatedResults())
    with caplog.at_level(logging.WARNING, logger="ash"):
        result = CliRunner().invoke(
            app,
            [
                "report",
                "--format",
                "csv",
                "--output-dir",
                str(tmp_path),
                "--log-level",
                "INFO",
                "--annotate-duplicates",
                "--fold-duplicates",
            ],
        )
    assert result.exit_code == 0, result.output
    message = next(
        (r.message for r in caplog.records if "changed nothing" in r.message), None
    )
    assert message is not None
    assert "--annotate-duplicates" in message and "--fold-duplicates" in message
    assert "record no" in message


def test_scan_and_report_declare_the_flag_off_by_default():
    import inspect

    from automated_security_helper.cli.report import report_command
    from automated_security_helper.cli.scan import run_ash_scan_cli_command

    for command in (run_ash_scan_cli_command, report_command):
        parameter = inspect.signature(command).parameters["annotate_duplicates"]
        assert parameter.default is False
        # typer reads a leading string as the option's name.
        assert parameter.annotation.__metadata__[0].default == "--annotate-duplicates"
