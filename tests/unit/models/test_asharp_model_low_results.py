# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The aggregated results write, flatten and report what they hold.

- ``used_suppressions`` is written in order, so identical scans write one file.
- ``to_flat_vulnerabilities`` flattens again when its sarif was replaced or
  added to, and a copy made with another sarif is not served the first one's
  findings.
- The suppressed count lands on a scanner row whatever the case of the row's
  name.
- ``metadata_only`` and ``to_simple_dict`` send the configuration's record of the
  metadata, with a ``validation_summary`` the scan filled in place.
- A failed final-metrics pass logs no value the stored configuration read from
  the environment.
"""

import json
import logging

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    PropertyBag,
    Result,
    Run,
    SarifReport,
    Suppression,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

PROJECT_VAR = "ASH_LOW_RESULTS_PROJECT_NAME"
CANARY = "/nonexistent/ENVCANARY-low-results/settings.yaml"


def _result(rule: str, suppressed: bool = False) -> Result:
    extra = (
        {"suppressions": [Suppression(kind="external", justification="reviewed")]}
        if suppressed
        else {}
    )
    return Result(
        ruleId=rule, level="error", message=Message(text=f"{rule} found"), **extra
    )


def _report(*rules: str, tool: str = "bandit", suppressed: bool = False) -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name=tool, version="1.0.0")),
                results=[_result(rule, suppressed) for rule in rules],
                properties=PropertyBag(),
            )
        ],
    )


def _rules(model: AshAggregatedResults) -> list:
    return sorted(vuln.rule_id for vuln in model.to_flat_vulnerabilities())


def test_used_suppressions_are_written_in_order():
    ids = {
        f"app/file_{index:02d}.py|RULE-{index}|{index}|{index}" for index in range(30)
    }
    model = AshAggregatedResults(used_suppressions=ids)

    assert json.loads(model.model_dump_json())["used_suppressions"] == sorted(ids)
    assert model.model_dump(mode="json")["used_suppressions"] == sorted(ids)
    # A dump to Python keeps the set the model holds.
    assert model.model_dump()["used_suppressions"] == ids


def test_unchanged_findings_are_flattened_once():
    model = AshAggregatedResults(sarif=_report("B101"))

    first = model.to_flat_vulnerabilities()

    assert model.to_flat_vulnerabilities() is first


def test_a_replaced_sarif_is_flattened_again():
    model = AshAggregatedResults(sarif=_report("B101"))
    assert _rules(model) == ["B101"]

    model.sarif = _report("B102", "B103")

    assert _rules(model) == ["B102", "B103"]


def test_a_result_added_in_place_is_flattened():
    model = AshAggregatedResults(sarif=_report("B101"))
    assert _rules(model) == ["B101"]

    model.sarif.runs[0].results.append(_result("B104"))

    assert _rules(model) == ["B101", "B104"]


def test_a_copy_with_another_sarif_is_not_served_the_first_findings():
    model = AshAggregatedResults(sarif=_report("B101"))
    assert _rules(model) == ["B101"]

    other = model.model_copy(update={"sarif": _report("B102")})

    assert _rules(other) == ["B102"]


def test_a_report_entry_added_in_place_is_flattened():
    model = AshAggregatedResults(
        additional_reports={"custom": [{"title": "first", "rule_id": "C1"}]}
    )
    assert _rules(model) == ["C1"]

    model.additional_reports["custom"].append({"title": "second", "rule_id": "C2"})

    assert _rules(model) == ["C1", "C2"]


def test_a_mixed_case_scanner_row_gets_its_suppressed_count():
    model = AshAggregatedResults(
        sarif=_report("B102", tool="Mixed-Scan", suppressed=True)
    )
    model.scanner_results["Mixed-Scan"] = ScannerTargetStatusInfo(
        status=ScannerStatus.PASSED
    )

    model.to_flat_vulnerabilities()

    row = model.scanner_results["Mixed-Scan"]
    assert row.suppressed_finding_count == 1, row
    assert row.severity_counts.suppressed == 1, row
    assert list(model.scanner_results) == ["Mixed-Scan"]


def _env_named_project(tmp_path, monkeypatch) -> AshAggregatedResults:
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(PROJECT_VAR, "zz-low-results-project")
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "recorded.yaml"
    path.write_text("project_name: ${" + PROJECT_VAR + "}\n", encoding="utf-8")
    config = resolve_config(config_path=str(path), fallback_to_default=False)
    model = AshAggregatedResults(ash_config=config)
    model.metadata.project_name = "zz-low-results-project"
    return model


def test_to_simple_dict_sends_the_project_name_as_its_reference(tmp_path, monkeypatch):
    model = _env_named_project(tmp_path, monkeypatch)

    sent = model.to_simple_dict()

    assert sent["metadata"]["project_name"] == "${" + PROJECT_VAR + "}"


def test_metadata_only_sends_the_project_name_as_its_reference(tmp_path, monkeypatch):
    model = _env_named_project(tmp_path, monkeypatch)

    metadata = model.metadata_only()

    assert metadata["project_name"] == "${" + PROJECT_VAR + "}"
    assert "zz-low-results-project" not in json.dumps(metadata)


def test_a_validation_summary_filled_in_place_is_sent():
    model = AshAggregatedResults()
    summary = {"expected_count": 3, "actual_count": 3, "has_issues": False}
    model.metadata.validation_summary["scanner_tasks_validation"] = dict(summary)

    expected = {"scanner_tasks_validation": summary}
    assert model.to_simple_dict()["metadata"]["validation_summary"] == expected
    assert model.metadata_only()["validation_summary"] == expected


def test_an_empty_validation_summary_is_not_sent():
    model = AshAggregatedResults()

    assert "validation_summary" not in model.to_simple_dict()["metadata"]
    assert "validation_summary" not in model.metadata_only()


@pytest.fixture
def logged():
    lines = []

    class _Collect(logging.Handler):
        def emit(self, record):
            lines.append(logging.Formatter("%(message)s").format(record))

    handler = _Collect(level=logging.DEBUG)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.DEBUG)
    ASH_LOGGER.addHandler(handler)
    try:
        yield lines
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)


def test_a_failed_final_metrics_pass_logs_no_environment_value(monkeypatch, logged):
    config = AshConfig(project_name="demo")
    config._environment_values = [CANARY]
    model = AshAggregatedResults(ash_config=config)

    def refuse(_results):
        raise RuntimeError(f"could not read {CANARY}")

    monkeypatch.setattr(
        "automated_security_helper.core.unified_metrics.get_unified_scanner_metrics",
        refuse,
    )

    model._populate_final_metrics()

    assert any("Error populating final metrics" in line for line in logged), logged
    assert any("Stack trace:" in line for line in logged), logged
    for line in logged:
        assert "ENVCANARY-low-results" not in line, line
