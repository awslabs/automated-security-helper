# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A result of any kind that asserts a finding takes its rule's severity.

Normalization skipped every kind except ``fail``, but the schema's finding kinds
are ``fail``, ``open`` and ``review``: the last two assert a finding a reader
still has to judge. A ``review`` result whose rule scored 9.8 lost its CRITICAL
grade to the level fallback (a ``warning`` is MEDIUM), so a scan that failed a
``high`` threshold passed. A kind that states no finding is still left alone.
"""

import pytest

from automated_security_helper.schemas.sarif_schema_model import (
    Kind,
    Message,
    PropertyBag,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.sarif_utils import (
    _resolve_result_severity,
    normalize_sarif_result_severities,
)

pytestmark = pytest.mark.unit


def _report(kind: Kind | None) -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(
                    driver=ToolComponent(
                        name="grype",
                        rules=[
                            ReportingDescriptor(
                                id="CVE-TEST",
                                properties=PropertyBag(**{"security-severity": 9.8}),
                            )
                        ],
                    )
                ),
                results=[
                    Result(
                        ruleId="CVE-TEST",
                        level="warning",
                        kind=kind,
                        message=Message(text="test finding"),
                    )
                ],
            )
        ],
    )


@pytest.mark.parametrize("kind", [None, Kind.fail, Kind.open, Kind.review])
def test_a_kind_that_asserts_a_finding_takes_the_rules_severity(kind):
    report = normalize_sarif_result_severities(_report(kind))
    result = report.runs[0].results[0]

    assert result.properties.issue_severity == "CRITICAL"
    # Not the MEDIUM its warning level alone would give.
    assert _resolve_result_severity(result) == "critical"


@pytest.mark.parametrize("kind", [Kind.pass_, Kind.notApplicable, Kind.informational])
def test_a_kind_that_states_no_finding_is_left_as_it_is(kind):
    report = normalize_sarif_result_severities(_report(kind))

    assert report.runs[0].results[0].properties is None
