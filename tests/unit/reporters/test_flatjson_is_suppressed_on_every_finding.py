# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every finding of the flat JSON report says whether it is suppressed.

The findings are dumped with ``exclude_unset``, so a finding whose constructor
never set ``is_suppressed`` (the ones built from a scanner's additional report)
omitted the key, while the findings built from SARIF results carried it. A
consumer filtering on the key read the former as neither suppressed nor open.
"""

import json

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
    FlatJSONReporter,
)

pytestmark = pytest.mark.unit


def test_a_finding_built_without_the_flag_carries_it(test_plugin_context, monkeypatch):
    finding = FlatVulnerability(
        id="f-1",
        title="t",
        description="d",
        severity="HIGH",
        scanner="npm-audit",
        scanner_type="SCA",
    )
    # The premise: nothing set the flag, so the unset-excluding dump omits it.
    assert "is_suppressed" not in finding.model_dump(exclude_unset=True)
    monkeypatch.setattr(
        AshAggregatedResults, "to_flat_vulnerabilities", lambda self: [finding]
    )

    data = json.loads(
        FlatJSONReporter(context=test_plugin_context).report(AshAggregatedResults())
    )

    (emitted,) = data["findings"]
    assert emitted["is_suppressed"] is False


def test_a_finding_that_set_the_flag_keeps_its_value(test_plugin_context, monkeypatch):
    finding = FlatVulnerability(
        id="f-2",
        title="t",
        description="d",
        severity="LOW",
        scanner="bandit",
        scanner_type="SAST",
        is_suppressed=True,
    )
    monkeypatch.setattr(
        AshAggregatedResults, "to_flat_vulnerabilities", lambda self: [finding]
    )

    data = json.loads(
        FlatJSONReporter(context=test_plugin_context).report(AshAggregatedResults())
    )

    assert data["findings"][0]["is_suppressed"] is True
