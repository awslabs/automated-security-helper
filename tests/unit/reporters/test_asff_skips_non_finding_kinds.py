# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The ASFF export carries a result that states a finding and no other.

A SARIF result of kind ``pass``, ``notApplicable`` or ``informational`` whose level
is ``none`` (or not stated) and whose declared severity is at most INFO says that a
rule passed, did not apply, or reported information only. Exported as a Security Hub
finding it is a record in a SIEM that nobody can act on, such as an INFORMATIONAL
finding for a cdk-nag rule that was not evaluated. The OCSF, GitLab SAST and GitHub
reporters already leave such a result out.

A result of such a kind that reports a problem anyway, by a level above ``none`` or
by a declared severity above INFO, contradicts its kind and is a finding: it is
exported, graded as any other result. A suppressed result that states no finding is
still sent, as ARCHIVED, so that an earlier import of it is archived.

The formatter pairs each result with its flattened finding by position, and the
flattening holds every result of the run, so every result is still prepared and
paired and only the findings it returns are filtered. The last test pins that.

Every test with a non-finding kind has a control that changes the kind and nothing
else. A failing result (the default kind, stated or absent), and the two kinds that
assert a finding a reader still has to judge, ``open`` and ``review``, are exported
as before.
"""

from __future__ import annotations

from typing import Any

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.asff_formatter import (
    AsffFormatter,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Kind,
    Kind1,
    Level,
    Location,
    Message,
    PhysicalLocation,
    PhysicalLocation2,
    PropertyBag,
    Region,
    Result,
    Run,
    SarifReport,
    Suppression,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.sarif_utils import (
    NON_FINDING_KINDS,
    shared_correlation_ids,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

ACCOUNT = "123456789012"
REGION = "us-east-1"
CORRELATION_FIELD = "ash/correlationId"

# Sorted, so every pytest-xdist worker collects the same ids in the same order.
NON_FINDING = sorted(NON_FINDING_KINDS)
# The kinds that assert a finding.
FINDING = ["fail", "open", "review"]
# The same, and a result that states no kind at all, which is a fail result.
ANY_FINDING = [None, *FINDING]


def _result(
    rule: str,
    *,
    kind: str | None = "fail",
    level: str = "error",
    scanner: str = "cdk-nag",
    uri: str = "stack.template.json",
    start: int = 3,
    tags: list[str] | None = None,
    issue_severity: str | None = None,
    suppressed: bool = False,
) -> Result:
    """A located result of *scanner* with *kind* and *level*.

    A *kind* of None leaves the kind unstated; *suppressed* adds a suppression in
    effect.
    """
    properties: dict[str, Any] = {"scanner_name": scanner}
    if tags:
        properties["tags"] = tags
    if issue_severity:
        properties["issue_severity"] = issue_severity
    stated: dict[str, Any] = {}
    if kind is not None:
        stated["kind"] = Kind(kind)
    if suppressed:
        stated["suppressions"] = [
            Suppression(kind=Kind1.inSource, justification="reviewed")
        ]
    return Result(
        ruleId=rule,
        level=Level(level),
        message=Message(text=f"{rule} reported here"),
        properties=PropertyBag(**properties),
        **stated,
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    root=PhysicalLocation2(
                        artifactLocation=ArtifactLocation(uri=uri),
                        region=Region(startLine=start),
                    )
                )
            )
        ],
    )


def _model(*results: Result, target: str = "tgt") -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    model.metadata.generated_at = "2026-01-15T12:00:00.000Z"
    # The correlation id is scoped to the run's target, which the metadata records.
    model.metadata.project_name = target
    model.sarif = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="ASH")),
                results=list(results),
                properties=PropertyBag(),
            )
        ],
    )
    return model


def _export(model: AshAggregatedResults, target: str = "tgt") -> list[dict[str, Any]]:
    formatter = AsffFormatter(target, "source=/s;converted=no", None, offline=True)
    return formatter.build_asff_findings(model, account_id=ACCOUNT, region=REGION)


def _rules(findings: list[dict[str, Any]]) -> list[str]:
    """The rule id each exported finding carries, in export order."""
    return [finding["ProductFields"]["ash/ruleId"] for finding in findings]


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_result_that_states_no_finding_is_not_exported(kind):
    model = _model(
        _result("AwsSolutions-S1", kind=kind, level="none", start=3),
        _result("AwsSolutions-IAM4", start=9),
    )

    assert _rules(_export(model)) == ["AwsSolutions-IAM4"]


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_run_of_only_results_that_state_no_finding_exports_nothing(kind):
    model = _model(
        _result("AwsSolutions-S1", kind=kind, level="none", start=3),
        _result("AwsSolutions-S2", kind=kind, level="none", start=4),
    )

    assert _export(model) == []


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_suppressed_result_that_states_no_finding_is_sent_archived(kind):
    """The rule is read before the suppression: the note is no finding, so it is
    not an active record, but it is still sent once as ARCHIVED so that an earlier
    import of it is archived."""
    model = _model(
        _result("AwsSolutions-S1", kind=kind, level="none", start=3, suppressed=True),
        _result("AwsSolutions-IAM4", start=9),
    )

    exported = _export(model)

    assert _rules(exported) == ["AwsSolutions-S1", "AwsSolutions-IAM4"]
    assert [finding["RecordState"] for finding in exported] == ["ARCHIVED", "ACTIVE"]


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_result_whose_level_reports_a_problem_is_exported(kind):
    """A result that contradicts its kind is a finding, graded by its level."""
    model = _model(_result("AwsSolutions-S1", kind=kind, level="warning"))

    exported = _export(model)

    assert _rules(exported) == ["AwsSolutions-S1"]
    assert exported[0]["Severity"]["Label"] == "MEDIUM"
    assert exported[0]["RecordState"] == "ACTIVE"


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_result_with_a_high_issue_severity_is_exported(kind):
    """A declared severity above INFO reports a problem whatever the level says."""
    model = _model(
        _result("AwsSolutions-S1", kind=kind, level="none", issue_severity="HIGH")
    )

    exported = _export(model)

    assert _rules(exported) == ["AwsSolutions-S1"]
    assert exported[0]["Severity"]["Label"] == "HIGH"


@pytest.mark.parametrize("kind", ANY_FINDING)
def test_the_same_result_that_asserts_a_finding_is_exported(kind):
    model = _model(
        _result("AwsSolutions-S1", kind=kind, level="none", start=3),
        _result("AwsSolutions-IAM4", start=9),
    )

    assert _rules(_export(model)) == ["AwsSolutions-S1", "AwsSolutions-IAM4"]


@pytest.mark.parametrize("kind", NON_FINDING)
def test_the_exported_finding_keeps_the_correlation_id_of_its_own_result(kind):
    """The id of each result is read by position from the flattened findings of the
    whole run, so a result that is left out of the export cannot be left out of that
    pairing. The two results here name one rule, one file and one line, which is all a
    match that ignored position would look at, and only the second is a secret
    detection: paired with the wrong row, its finding carries no correlation id."""
    model = _model(
        _result(
            "R7",
            kind=kind,
            level="none",
            scanner="cdk-nag",
            uri="config/settings.py",
            start=12,
        ),
        _result(
            "R7",
            scanner="not-a-shipped-scanner",
            uri="config/settings.py",
            start=12,
            tags=["secret"],
        ),
    )
    expected = shared_correlation_ids(model, list(model.sarif.get_all_results()))[1]
    assert expected is not None and expected.startswith("secret/")

    exported = [
        finding
        for finding in _export(model)
        if finding["ProductFields"]["ash/scanner"] == "not-a-shipped-scanner"
    ]
    found = [finding["ProductFields"].get(CORRELATION_FIELD) for finding in exported]

    assert found == [expected]
