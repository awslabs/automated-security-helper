# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The findings array of the flat JSON report, pinned against the original loop.

The oracle below is the per-finding dump the reporter ran before the suppressed
flag was read off the flat frame, copied verbatim, with the one key every finding
has gained since: ``result_kind``, written for a finding whose constructor never
set it, as ``is_suppressed`` is. The report's ``findings`` must equal what it
gives, finding for finding, for findings that differ in which fields they set, in
whether they are suppressed, and in what their text and line numbers hold (a lone
surrogate in a path, a line wider than 64 bits).
"""

import json
from typing import Any, Dict, List

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
    FlatJSONReporter,
)

pytestmark = pytest.mark.unit


def _oracle(vuln: Any) -> Dict[str, Any]:
    data = vuln.model_dump(exclude_none=True, exclude_unset=True, mode="json")
    data.setdefault("is_suppressed", bool(getattr(vuln, "is_suppressed", False)))
    data.setdefault("result_kind", vuln.result_kind)
    return data


def _findings() -> List[FlatVulnerability]:
    return [
        FlatVulnerability(
            id="f-unset",
            title="t",
            description="d",
            severity="HIGH",
            scanner="npm-audit",
            scanner_type="SCA",
        ),
        FlatVulnerability(
            id="f-suppressed",
            title="t",
            description="d",
            severity="LOW",
            scanner="Bandit",
            scanner_type="SAST",
            is_suppressed=True,
            file_path="src/a.py",
            line_start=3,
            line_end=4,
            rule_id="B101",
        ),
        FlatVulnerability(
            id="f-open",
            title="t",
            description="d",
            severity="MEDIUM",
            scanner="bandit",
            scanner_type="SAST",
            is_suppressed=False,
            file_path="src/b.py",
        ),
        FlatVulnerability(
            id="f-surrogate",
            title="t",
            description="d",
            severity="LOW",
            scanner="semgrep",
            scanner_type="SAST",
            file_path="src/bad\udc80name.py",
            is_suppressed=True,
        ),
        FlatVulnerability(
            id="f-wide-line",
            title="t",
            description="d",
            severity="LOW",
            scanner="semgrep",
            scanner_type="SAST",
            file_path="src/c.py",
            line_start=2**70,
            line_end=2**70 + 1,
        ),
    ]


def _report(test_plugin_context, monkeypatch, findings):
    monkeypatch.setattr(
        AshAggregatedResults, "to_flat_vulnerabilities", lambda self: findings
    )
    return json.loads(
        FlatJSONReporter(context=test_plugin_context).report(AshAggregatedResults())
    )


def test_every_finding_is_the_original_dump(test_plugin_context, monkeypatch):
    findings = _findings()
    data = _report(test_plugin_context, monkeypatch, findings)
    assert data["findings"] == json.loads(
        json.dumps([_oracle(f) for f in findings], default=str)
    )


def test_the_flag_is_each_findings_own_in_order(test_plugin_context, monkeypatch):
    findings = _findings()
    data = _report(test_plugin_context, monkeypatch, findings)
    assert [f["id"] for f in data["findings"]] == [f.id for f in findings]
    assert [f["is_suppressed"] for f in data["findings"]] == [
        False,
        True,
        False,
        True,
        False,
    ]


def test_a_run_with_no_findings_has_an_empty_array(test_plugin_context, monkeypatch):
    data = _report(test_plugin_context, monkeypatch, [])
    assert data["findings"] == []
