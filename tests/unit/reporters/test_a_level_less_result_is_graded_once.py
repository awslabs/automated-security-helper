# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A SARIF result with no ``level`` gets one grade, wherever it is read.

Why this exists
---------------
A result that names no ``level`` and no ``properties.issue_severity`` gets one grade
in a scan, though four readers reach it different ways: the results model and,
through it, every report, the summary counts and Bedrock; the exit-code gate, which
reads ``ash.sarif`` (dumped with ``exclude_unset``, so a defaulted level would be
absent from the file); ``result_severity`` on the JSON form, which the MCP result
filter uses; and Bedrock's ``exclude_defaults`` dump, where a result at the default
level would otherwise show as ``none``. A split would let the CSV say CRITICAL and
the summary count an actionable finding while the scan exits 0 at the MEDIUM
threshold.

There is one default, ``utils.severity_ladder.MISSING_SARIF_LEVEL``: SARIF
2.1.0's own, ``"warning"`` (3.27.10: when the rule gives no level, "SET level to
"warning""), graded MEDIUM. The results model defaults to it, every grader reads a
missing level as it, ingestion applies SARIF's procedure first (a non-``fail``
``kind`` is ``none``; otherwise the rule's ``defaultConfiguration.level``), and
``ash.sarif`` writes ``level`` on every result, so the file and memory agree.
"""

import csv
import io
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_result_processor import (
    ScanResultProcessor,
)
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scan_results_container import ScanResultsContainer
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sarif_utils import attach_scanner_details

pytestmark = pytest.mark.unit


def _scanner_report(results, rules=None) -> SarifReport:
    report = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "bandit",
                            "rules": rules or [{"id": "R-PLAIN"}],
                        }
                    },
                    "results": results,
                }
            ],
        }
    )
    return attach_scanner_details(
        report, scanner_name="bandit", scanner_version="1.8.6"
    )


def _result(rule_id="R-PLAIN", uri="src/a.py", **extra) -> dict:
    return {
        "ruleId": rule_id,
        "message": {"text": f"finding {rule_id}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 1},
                }
            }
        ],
        **extra,
    }


def _process(tmp_path, report) -> AshAggregatedResults:
    context = MagicMock()
    context.source_dir = tmp_path / "source"
    context.output_dir = tmp_path / "output"
    context.ignore_suppressions = True
    context.source_dir.mkdir(exist_ok=True)
    model = AshAggregatedResults()
    model.ash_config = AshConfig(project_name="levels")
    model = ScanResultProcessor(
        plugin_context=context, validation_manager=MagicMock()
    ).process_container(
        ScanResultsContainer(
            scanner_name="bandit",
            report_type="sarif",
            target=context.source_dir,
            target_type="source",
            raw_results=report,
            status=ScannerStatus.PASSED,
        ),
        model,
    )
    return populate_metrics_from_unified_source(aggregated_results=model)


def _direct(tmp_path) -> AshAggregatedResults:
    """Built without ScanResultProcessor, so ``level`` is never set at all."""
    model = AshAggregatedResults()
    model.ash_config = AshConfig(project_name="levels")
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "AWS Labs - Automated Security Helper"},
                        "extensions": [
                            {
                                "name": "bandit",
                                "version": "1.8.6",
                                "rules": [{"id": "R-PLAIN"}],
                            }
                        ],
                    },
                    "results": [
                        _result(
                            properties={"scanner_name": "bandit", "tags": ["bandit"]}
                        )
                    ],
                }
            ],
        }
    )
    assert "level" not in model.sarif.runs[0].results[0].model_fields_set
    return populate_metrics_from_unified_source(aggregated_results=model)


@pytest.fixture(params=["through the processor", "built directly"])
def model(request, tmp_path):
    if request.param == "built directly":
        return _direct(tmp_path)
    return _process(tmp_path, _scanner_report([_result()]))


@pytest.fixture
def context(tmp_path) -> PluginContext:
    return PluginContext(
        source_dir=tmp_path / "source",
        output_dir=tmp_path / "out",
        config=AshConfig(project_name="levels"),
    )


def _render(module: str, cls: str, context, model) -> str:
    import importlib

    reporter_module = importlib.import_module(
        f"automated_security_helper.plugin_modules.ash_builtin.reporters.{module}"
    )
    return getattr(reporter_module, cls)(context=context).report(model)


def test_the_summary_grades_it_medium_and_counts_it(model):
    stats = model.metadata.summary_stats
    counts = stats.severity_counts

    assert (counts.critical, counts.high, counts.medium, counts.low, counts.info) == (
        0,
        0,
        1,
        0,
        0,
    )
    assert stats.actionable == 1


def test_the_gate_fails_on_it_at_medium(model, context, tmp_path):
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _compute_exit_code,
    )

    reports = Path(context.output_dir) / "reports"
    reports.mkdir(parents=True)
    (reports / "ash.sarif").write_text(
        _render("sarif_reporter", "SarifReporter", context, model), encoding="utf-8"
    )
    opts = ScanOptions(
        source_dir=context.source_dir,
        output_dir=context.output_dir,
        fail_on_incomplete_scanners=False,
    )

    assert _compute_exit_code(model, opts, True) == 2


def test_ash_sarif_writes_the_level(model, context):
    document = json.loads(_render("sarif_reporter", "SarifReporter", context, model))

    assert [r["level"] for r in document["runs"][0]["results"]] == ["warning"]


def test_writing_ash_sarif_leaves_the_model_as_it_was(model, context):
    """The level and rule reference are set for the dump and then taken back.

    Including whether they were set: a field left in model_fields_set would
    turn up in every later exclude_unset dump, ash_aggregated_results.json
    among them, as if the scanner had stated it.
    """
    before = [
        (set(r.model_fields_set), r.level, r.rule) for r in model.sarif.runs[0].results
    ]

    _render("sarif_reporter", "SarifReporter", context, model)

    after = [
        (set(r.model_fields_set), r.level, r.rule) for r in model.sarif.runs[0].results
    ]
    assert after == before


def test_every_report_grades_it_medium(model, context):
    rows = list(
        csv.DictReader(
            io.StringIO(_render("csv_reporter", "CsvReporter", context, model))
        )
    )
    assert [row["severity"] for row in rows] == ["MEDIUM"]

    flat = json.loads(_render("flatjson_reporter", "FlatJSONReporter", context, model))
    assert [f["severity"] for f in flat["findings"]] == ["MEDIUM"]

    gitlab = json.loads(
        _render("gitlab_sast_reporter", "GitLabSASTReporter", context, model)
    )
    assert [v["severity"] for v in gitlab["vulnerabilities"]] == ["Medium"]

    ocsf = json.loads(_render("ocsf_reporter", "OcsfReporter", context, model))
    assert {
        record["severity_id"] for record in ocsf if record.get("vulnerabilities")
    } == {3}

    page = _render("html_reporter", "HtmlReporter", context, model)
    # The redesigned report shows a finding's grade as a severity pill.
    assert 'class="pill severity-medium">MEDIUM</span>' in page
    assert 'severity-critical">CRITICAL' not in page

    ghas = json.loads(_render("github_ghas_reporter", "GHASReporter", context, model))
    score = float(
        ghas["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"]
    )
    assert 4.0 <= score <= 6.9

    junit = _render("junitxml_reporter", "JunitXmlReporter", context, model)
    # Actionable at MEDIUM: an <error> element, not <skipped> below the threshold.
    assert 'errors="1"' in junit and 'skipped="0"' in junit

    from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
        ReportContentEmitter,
    )

    assert [v.severity for v in ReportContentEmitter(model).flat_vulns] == ["MEDIUM"]


def test_mcp_and_inspect_grade_it_medium(model, context):
    from automated_security_helper.cli.inspect.inspect_findings_app import (
        extract_findings,
    )
    from automated_security_helper.core.resource_management.result_filters import (
        _get_finding_severity,
    )

    on_disk = json.loads(_render("sarif_reporter", "SarifReporter", context, model))
    saved = json.loads(model.sarif.model_dump_json(by_alias=True, exclude_unset=True))

    assert _get_finding_severity(on_disk["runs"][0]["results"][0]) == "MEDIUM"
    assert _get_finding_severity(saved["runs"][0]["results"][0]) == "MEDIUM"
    assert [f["severity"] for f in extract_findings(model)] == ["medium"]


def test_the_workspace_gate_counts_it_at_medium(model, context):
    from automated_security_helper.workspace.aggregation import (
        count_actionable_results,
        has_finding_at_min_severity,
    )

    results = json.loads(
        model.sarif.model_dump_json(by_alias=True, exclude_unset=True)
    )["runs"][0]["results"]

    assert count_actionable_results(results, "MEDIUM") == 1
    assert has_finding_at_min_severity(results, "medium") is True
    assert has_finding_at_min_severity(results, "high") is False


def test_bedrock_sends_it_and_names_its_level(model, context, monkeypatch, tmp_path):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")  # pragma: allowlist secret
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "no-aws-creds"))

    def refuse(*args, **kwargs):
        raise AssertionError("a botocore request was attempted")

    monkeypatch.setattr("botocore.endpoint.Endpoint._send", refuse)
    from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
        BedrockSummaryReporter,
        BedrockSummaryReporterConfig,
        BedrockSummaryReporterConfigOptions,
    )

    BedrockSummaryReporterConfig.model_rebuild()
    BedrockSummaryReporter.model_rebuild()
    reporter = BedrockSummaryReporter(
        context=context,
        config=BedrockSummaryReporterConfig(
            options=BedrockSummaryReporterConfigOptions(
                aws_region="us-east-1", model_id="test-vendor.test-model-v1:0"
            )
        ),
    )

    findings, _, indexed = reporter._extract_findings(model)

    assert [f.get("level") for f in findings] == ["warning"]
    assert [f["level"] for f in indexed] == ["warning"]


def test_a_rules_default_level_and_a_non_fail_kind_are_honored(tmp_path):
    """SARIF 3.27.10 asks the rule before falling back to "warning"."""
    report = _scanner_report(
        [
            _result("R-DEFAULT-ERROR", "src/b.py"),
            _result("R-PLAIN", "src/c.py", kind="pass"),
            _result("R-PLAIN", "src/d.py", level="note"),
        ],
        rules=[
            {"id": "R-PLAIN"},
            {"id": "R-DEFAULT-ERROR", "defaultConfiguration": {"level": "error"}},
        ],
    )
    model = _process(tmp_path, report)
    by_uri = {
        r.locations[0].physicalLocation.root.artifactLocation.uri: str(
            getattr(r.level, "value", r.level)
        )
        for r in model.sarif.runs[0].results
    }

    assert by_uri == {"src/b.py": "error", "src/c.py": "none", "src/d.py": "note"}
    counts = model.metadata.summary_stats.severity_counts
    assert (counts.critical, counts.low, counts.info) == (1, 1, 1)
