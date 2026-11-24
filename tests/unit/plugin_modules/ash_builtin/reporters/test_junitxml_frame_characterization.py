# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The JUnit report, differentially, against the per-result loop it replaced.

``_oracle_report`` is ``JunitXmlReporter.report`` as it stood before the per-result
projection moved onto a frame (comments dropped, logic verbatim). The reporter's
output over a corpus that crosses every input of the grading cascade must be the
oracle's, byte for byte: result kind, level, issue severity, suppression state,
the ``below_threshold`` and ``severity_threshold`` properties, the scanner and the
workspace project, text a XML 1.0 document cannot hold, and every threshold source.
"""

from __future__ import annotations

import itertools

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters import (
    junitxml_reporter as jx,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
    JUnitXMLReporterConfig,
    JUnitXMLReporterConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_section import (
    workspace_policy_gates,
    workspace_project_scanner_thresholds,
    workspace_project_thresholds,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_skipped_rows import (
    skipped_project_detail,
    skipped_projects,
)
from automated_security_helper.models.flat_vulnerability import (
    extract_workspace_project,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.policy_origin import is_policy_origin
from automated_security_helper.utils.sarif_utils import (
    FINDING_KINDS,
    result_message_text,
    result_rule_id,
    suppressions_in_effect,
)
from automated_security_helper.utils.severity_ladder import (
    SEVERITIES,
    sarif_level_fails_threshold,
    severity_fails_threshold,
)

from tests.unit.plugin_modules.ash_builtin.reporters.test_junitxml_reporter import (
    _get_reporter,
)

pytestmark = pytest.mark.unit


def _oracle_report(reporter, model) -> str:
    from junitparser import Error, JUnitXml, Skipped, TestCase, TestSuite

    report = JUnitXml(name="ASH Scan Report")
    test_suite_dict = {}
    configured_threshold = jx._configured_severity_threshold(model)
    scanner_thresholds: dict = {}
    project_thresholds = workspace_project_thresholds(model)
    project_scanner_thresholds = workspace_project_scanner_thresholds(model)
    policy_gates = workspace_policy_gates(model)

    if model.sarif is not None:
        for result in model.sarif.get_all_results():
            message_text = jx._xml_text(result_message_text(result, default=""))
            named_rule = result_rule_id(result)
            rule_id = jx._xml_text(named_rule) if named_rule else None
            test_name = (
                f"{message_text} [{rule_id}]"
                if rule_id and message_text
                else message_text or rule_id or ""
            )
            test_case = TestCase(name=test_name, classname=rule_id)
            props = result.properties
            actual_scanner = "ash"
            extra = getattr(props, "__pydantic_extra__", None) or {}
            if "scanner_name" in extra:
                actual_scanner = extra["scanner_name"]
            elif props is not None and getattr(props, "tags", None):
                for tag in props.tags:
                    if tag.startswith("tool_name::"):
                        actual_scanner = tag.split("::")[1]
                        break
            if (
                actual_scanner == "ash"
                and props is not None
                and hasattr(props, "scanner_details")
                and hasattr(props.scanner_details, "tool_name")
            ):
                actual_scanner = props.scanner_details.tool_name
            if not isinstance(actual_scanner, str) or not actual_scanner:
                actual_scanner = "ash"
            project = extract_workspace_project(result)
            in_effect = suppressions_in_effect(result.suppressions)
            if in_effect:
                test_case.result = [
                    Skipped(
                        message=jx._xml_text(
                            "; ".join(
                                s.justification for s in in_effect if s.justification
                            )
                        ),
                        type_="suppression",
                    )
                ]
            elif result.kind == "notApplicable":
                test_case.result = [
                    Skipped(
                        message="Rule was not evaluated for this target",
                        type_="not-evaluated",
                    )
                ]
            elif (
                project
                and is_policy_origin(props)
                and policy_gates.get(project) is False
            ):
                test_case.result = [
                    Skipped(
                        message=(
                            "Finding is from a workspace-policy scanner that "
                            "does not gate this project"
                        ),
                        type_=jx.POLICY_NOT_GATING_SKIP_TYPE,
                    )
                ]
            else:
                is_actionable = True
                if reporter.config.options.respect_severity_threshold and props:
                    below_threshold = jx._as_flag(
                        getattr(props, "below_threshold", None)
                    )
                    if below_threshold is not None:
                        is_actionable = not below_threshold
                if is_actionable and reporter.config.options.respect_severity_threshold:
                    threshold = (
                        jx._normalized_threshold(
                            getattr(props, "severity_threshold", None)
                        )
                        or (
                            project_scanner_thresholds.get(project, {}).get(
                                actual_scanner
                            )
                            if project is not None
                            else None
                        )
                        or (
                            project_thresholds.get(project)
                            if project is not None
                            else None
                        )
                        or jx._scanner_threshold(
                            model, actual_scanner, scanner_thresholds
                        )
                        or configured_threshold
                    )
                    issue_severity = (
                        str(getattr(props, "issue_severity", "") or "").strip().upper()
                    )
                    if issue_severity in SEVERITIES:
                        is_actionable = severity_fails_threshold(
                            issue_severity, threshold
                        )
                    else:
                        is_actionable = sarif_level_fails_threshold(
                            result.level, threshold
                        )
                if is_actionable:
                    level_type = jx._ERROR_TYPE_BY_LEVEL.get(str(result.level))
                    if result.kind in FINDING_KINDS:
                        error_type = level_type or (
                            "error" if result.kind == "fail" else "note"
                        )
                    elif result.level in ("error", "warning"):
                        error_type = level_type
                    else:
                        error_type = None
                    if error_type is not None:
                        test_case.result = [
                            Error(message=message_text, type_=error_type)
                        ]
                else:
                    test_case.result = [
                        Skipped(
                            message="Finding is below configured severity threshold",
                            type_="threshold",
                        )
                    ]
            metadata = []
            if props is not None:
                for key, value in props.model_dump(by_alias=True).items():
                    metadata.append(f"{key}: {value}")
            if metadata:
                test_case.system_out = jx._xml_text("\n".join(metadata))
            suite_name = jx._xml_text(
                f"{project}/{actual_scanner}" if project else actual_scanner
            )
            if suite_name not in test_suite_dict:
                test_suite_dict[suite_name] = TestSuite(name=suite_name)
            test_suite_dict[suite_name].add_testcase(test_case)

    for suite_name, test_suite in test_suite_dict.items():
        del suite_name
        report.add_testsuite(test_suite)
    for entry in skipped_projects(model):
        suite = TestSuite(name=jx._xml_text(entry.project))
        case = TestCase(
            name=f"project skipped ({entry.reason.value})",
            classname=jx.SKIPPED_PROJECT_CLASSNAME,
        )
        case.result = [
            Skipped(
                message=jx._xml_text(skipped_project_detail(entry)),
                type_=jx.SKIPPED_PROJECT_SKIP_TYPE,
            )
        ]
        suite.add_testcase(case)
        report.add_testsuite(suite)
    return report.tostring().decode("utf-8")


_KINDS = [None, "fail", "open", "review", "pass", "informational", "notApplicable"]
_LEVELS = ["error", "warning", "note", "none"]
_SEVERITIES = [None, "HIGH", " low ", "INFO", "bogus"]
_SUPPRESSIONS = [
    None,
    [{"kind": "external", "state": "accepted", "justification": "j1"}],
    [{"kind": "external", "state": "accepted", "justification": ""}],
    [
        {"kind": "external", "state": "accepted", "justification": "j1"},
        {"kind": "inSource", "state": "accepted", "justification": "j2\x01"},
    ],
    [{"kind": "external", "state": "rejected", "justification": "no"}],
]
# Each of these cycles against the product above, so the pairings are many
# without crossing every axis with every other.
_SCANNERS = ["bandit", "semgrep", "ev\ud800il", "", None, "bandit", "checkov"]
_PROJECTS = [None, "watch", "strict", "tuned", "plain", "legacy", "unlisted"]
_BELOW = [None, True, "false", "true", "maybe"]
_PROP_THRESHOLDS = [None, None, "HIGH", "bogus", "low"]
_MESSAGES = ["finding", "", "  ", "ctl\x00\x1f￾", "sur\ud800x", "back\\x01slash"]
_RULES = ["R1", None, "ru\x02le", "R1"]


def _corpus() -> list[dict]:
    results = []
    cycle = itertools.cycle(
        itertools.product(
            _SCANNERS, _PROJECTS, _BELOW, _PROP_THRESHOLDS, _MESSAGES, _RULES
        )
    )
    for n, (kind, level, severity, supp) in enumerate(
        itertools.product(_KINDS, _LEVELS, _SEVERITIES, _SUPPRESSIONS)
    ):
        scanner, project, below, prop_threshold, message, rule = next(cycle)
        for _ in range(n % 5):
            next(cycle)
        props: dict = {}
        if scanner is not None:
            props["scanner_name"] = scanner
        else:
            props["tags"] = ["tool_name::tagged"]
        if project:
            props["workspace_project"] = project
        if severity is not None:
            props["issue_severity"] = severity
        if below is not None:
            props["below_threshold"] = below
        if prop_threshold is not None:
            props["severity_threshold"] = prop_threshold
        if project in ("watch", "strict", "legacy") and n % 2:
            props["origin"] = "workspace-policy"
        entry: dict = {
            "level": level,
            "message": {"text": message},
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": f"src/f{n}.py"}}}
            ],
            "properties": props,
        }
        if rule is not None:
            entry["ruleId"] = rule
        if kind is not None:
            entry["kind"] = kind
        if supp is not None:
            entry["suppressions"] = supp
        results.append(entry)
    return results


def _sarif(results: list[dict]) -> SarifReport:
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "ASH"}},
                    "results": results,
                    "invocations": [],
                }
            ],
        }
    )


def _project(key: str, **fields) -> WorkspaceProjectResult:
    return WorkspaceProjectResult(
        project=key,
        relative_path=key,
        display_label=key,
        status=ProjectRunStatus.COMPLETED,
        severity_threshold="MEDIUM",
        output_path=f"projects/{key}",
        **fields,
    )


def _workspace_model(tmp_path) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.ash_config = None
    model.sarif = _sarif(_corpus())
    model.workspace = WorkspaceResults(
        workspace_file=(tmp_path / "fixture.code-workspace").as_posix(),
        workspace_root=tmp_path.as_posix(),
        exit_code=2,
        projects=[
            _project("watch", policy_scanners_gate=False),
            _project("strict", policy_scanners_gate=True),
            _project("tuned", scanner_thresholds={"bandit": "CRITICAL"}),
            _project("plain", severity_threshold="HIGH"),
            _project("legacy"),
        ],
    )
    return model


def _single_model(threshold: str) -> AshAggregatedResults:
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.default_config import get_default_config

    AshConfig.model_rebuild()
    AshAggregatedResults.model_rebuild()
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    model.ash_config.global_settings.severity_threshold = threshold
    model.sarif = _sarif(_corpus())
    return model


def _reporter(tmp_path, respect: bool):
    return _get_reporter(
        tmp_path,
        JUnitXMLReporterConfig(
            options=JUnitXMLReporterConfigOptions(respect_severity_threshold=respect)
        ),
    )


def test_the_corpus_reaches_every_arm_of_the_cascade(tmp_path):
    """A planted control: the oracle's output holds every result type, so the
    comparisons below are not equal on an empty or one-armed report."""
    xml = _oracle_report(_reporter(tmp_path, True), _single_model("MEDIUM"))
    for needle in (
        'type="suppression"',
        'type="not-evaluated"',
        'type="threshold"',
        'type="error"',
        'type="warning"',
        'type="note"',
    ):
        assert needle in xml, needle
    assert "<system-out>" in xml
    assert xml.count("<testsuite ") > 3
    assert len(_corpus()) == len(_KINDS) * len(_LEVELS) * len(_SEVERITIES) * len(
        _SUPPRESSIONS
    )


@pytest.mark.parametrize("respect", [True, False])
@pytest.mark.parametrize("threshold", ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
def test_a_single_scan_reports_as_the_loop_did(tmp_path, threshold, respect):
    reporter = _reporter(tmp_path, respect)
    model = _single_model(threshold)
    assert reporter.report(model) == _oracle_report(reporter, model)


@pytest.mark.parametrize("respect", [True, False])
def test_a_workspace_reports_as_the_loop_did(tmp_path, respect):
    reporter = _reporter(tmp_path, respect)
    model = _workspace_model(tmp_path)
    assert reporter.report(model) == _oracle_report(reporter, model)


def test_a_report_with_no_sarif_reports_as_the_loop_did(tmp_path):
    reporter = _reporter(tmp_path, True)
    model = AshAggregatedResults()
    model.ash_config = None
    assert reporter.report(model) == _oracle_report(reporter, model)
