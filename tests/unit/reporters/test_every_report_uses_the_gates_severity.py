# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every report, and ``ash inspect``, grades a finding the way the gate does.

Why this exists
---------------
A SARIF ``error`` with no ``properties.issue_severity`` is CRITICAL in the summary
counts and the exit-code gate (``sarif_utils._resolve_result_severity``), and so it
is in flat-json, CSV, the HTML, Markdown and text finding lists, ``ash inspect``,
the GitLab SAST report, OCSF (severity_id) and the GHAS report (GitHub's band).
``inspect`` and GitLab SAST read ``issue_severity`` too, and the HTML and OCSF
reports print a severity, not the SARIF level ("ERROR"). One finding has one
severity in a run, so a reader can tell from any report which findings failed the
scan.

Every consumer asks ``utils.severity_ladder.result_severity``, the gate's
rule: ``issue_severity`` when it names one of the five severities, else the level
(error CRITICAL, warning MEDIUM, note LOW, none INFO).

The fixture's five findings cover both halves of the rule: an ``error`` with no
declared severity (the case that diverged), an ``error`` declared HIGH, a
``warning``, a ``note`` declared CRITICAL (which inspect and GitLab SAST graded
from the level), and a ``none``.
"""

import csv
import io
import json

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

#: (rule id, level, declared issue_severity or None, the gate's severity)
FINDINGS = [
    ("R-ERROR", "error", None, "CRITICAL"),
    ("R-ERROR-HIGH", "error", "HIGH", "HIGH"),
    ("R-WARNING", "warning", None, "MEDIUM"),
    ("R-NOTE-CRITICAL", "note", "CRITICAL", "CRITICAL"),
    ("R-NONE", "none", None, "INFO"),
]
EXPECTED = {rule: severity for rule, _, _, severity in FINDINGS}


def _sarif() -> dict:
    results = []
    for index, (rule, level, declared, _) in enumerate(FINDINGS):
        properties = {"scanner_name": "bandit", "tags": []}
        if declared:
            properties["issue_severity"] = declared
        results.append(
            {
                "ruleId": rule,
                "level": level,
                "message": {"text": f"finding {rule}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"src/f{index}.py"},
                            "region": {"startLine": index + 1},
                        }
                    }
                ],
                "properties": properties,
            }
        )
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "bandit",
                        "rules": [{"id": rule} for rule, _, _, _ in FINDINGS],
                    }
                },
                "results": results,
            }
        ],
    }


@pytest.fixture
def model() -> AshAggregatedResults:
    results = AshAggregatedResults()
    results.ash_config = AshConfig(project_name="severity")
    results.sarif = SarifReport.model_validate(_sarif())
    return populate_metrics_from_unified_source(aggregated_results=results)


@pytest.fixture
def context(tmp_path) -> PluginContext:
    return PluginContext(
        source_dir=tmp_path, output_dir=tmp_path / "out", config=AshConfig()
    )


def _render(reporter_module: str, reporter_class: str, context, model) -> str:
    import importlib

    module = importlib.import_module(
        f"automated_security_helper.plugin_modules.ash_builtin.reporters.{reporter_module}"
    )
    return getattr(module, reporter_class)(context=context).report(model)


def test_the_resolver_is_the_gates_rule(model):
    from automated_security_helper.utils.severity_ladder import result_severity

    for result in model.sarif.runs[0].results:
        assert result_severity(result) == EXPECTED[result.ruleId], result.ruleId
        as_dict = json.loads(result.model_dump_json(by_alias=True, exclude_none=True))
        assert result_severity(as_dict) == EXPECTED[result.ruleId], result.ruleId


def test_the_summary_counts_agree(model):
    counts = model.metadata.summary_stats.severity_counts

    assert (counts.critical, counts.high, counts.medium, counts.low, counts.info) == (
        2,
        1,
        1,
        0,
        1,
    )


def test_flat_json(model, context):
    report = json.loads(
        _render("flatjson_reporter", "FlatJSONReporter", context, model)
    )

    assert {f["rule_id"]: f["severity"] for f in report["findings"]} == EXPECTED


def test_csv(model, context):
    rows = list(
        csv.DictReader(
            io.StringIO(_render("csv_reporter", "CsvReporter", context, model))
        )
    )

    assert {row["rule_id"]: row["severity"] for row in rows} == EXPECTED


def test_gitlab_sast(model, context):
    report = json.loads(
        _render("gitlab_sast_reporter", "GitLabSASTReporter", context, model)
    )

    by_rule = {
        vuln["identifiers"][0]["value"]: vuln["severity"]
        for vuln in report["vulnerabilities"]
    }
    assert by_rule == {rule: severity.title() for rule, severity in EXPECTED.items()}


def test_ocsf(model, context):
    report = json.loads(_render("ocsf_reporter", "OcsfReporter", context, model))
    ids = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

    by_rule = {}
    for record in report:
        for vulnerability in record.get("vulnerabilities") or []:
            title = vulnerability.get("title")
            if title in EXPECTED:
                by_rule[title] = (record["severity_id"], vulnerability["severity"])
    assert by_rule == {
        rule: (ids[severity], severity) for rule, severity in EXPECTED.items()
    }


def test_html_lists_the_gates_severities(model, context):
    page = _render("html_reporter", "HtmlReporter", context, model)

    # The redesigned report shows each finding's grade as a severity pill.
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "INFO"):
        assert f'class="pill severity-{severity.lower()}">{severity}</span>' in page, (
            severity
        )
    # No SARIF level name appears as a severity grade.
    for level in ("error", "warning", "note", "none"):
        assert f'class="severity-{level}"' not in page, level
        assert f'class="pill severity-{level}"' not in page, level


def test_ghas_security_severity_lands_in_the_gates_band(model, context):
    report = json.loads(_render("github_ghas_reporter", "GHASReporter", context, model))
    rules = {
        rule["id"]: float(rule["properties"]["security-severity"])
        for rule in report["runs"][0]["tool"]["driver"]["rules"]
    }
    # GitHub's buckets: 9.0-10.0 Critical, 7.0-8.9 High, 4.0-6.9 Medium,
    # 0.1-3.9 Low.
    bands = {
        "CRITICAL": (9.0, 10.0),
        "HIGH": (7.0, 8.9),
        "MEDIUM": (4.0, 6.9),
        "LOW": (0.1, 3.9),
        "INFO": (0.0, 3.9),
    }
    for rule, severity in EXPECTED.items():
        low, high = bands[severity]
        assert low <= rules[rule] <= high, (rule, severity, rules[rule])


def test_inspect(model):
    from automated_security_helper.cli.inspect.inspect_findings_app import (
        extract_findings,
    )

    by_rule = {f["rule_id"]: f["severity"] for f in extract_findings(model)}

    assert by_rule == {rule: severity.lower() for rule, severity in EXPECTED.items()}


def test_the_mcp_result_filter(model):
    from automated_security_helper.core.resource_management.result_filters import (
        _get_finding_severity,
    )

    for result in json.loads(model.sarif.model_dump_json(by_alias=True))["runs"][0][
        "results"
    ]:
        assert _get_finding_severity(result) == EXPECTED[result["ruleId"]]


def test_markdown_text_and_html_detail_sections(model):
    from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
        ReportContentEmitter,
    )

    emitter = ReportContentEmitter(model)
    by_rule = {
        vuln.rule_id: vuln.severity
        for vuln in emitter.flat_vulns
        if vuln.rule_id in EXPECTED
    }

    assert by_rule == EXPECTED
