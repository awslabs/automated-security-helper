# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The GitLab SAST report's per-finding projection, pinned to its recorded output.

The document ``report()`` writes for a fixed set of results is compared with the
one the reporter wrote before its projection (the id each finding ends with, the
severity it is graded at) moved onto a frame. The corpus holds what that
projection reads: findings that fall back to the legacy id and collide on it, a
finding that holds a shared id beside them, a suppressed finding among the
collisions, a result that cannot be transformed between two collisions, a path
with a lone surrogate, and a rule-less result.

``ASH_WRITE_GOLDEN=1`` rewrites the recorded file from the current reporter; the
file was recorded from the reporter as it stood before the move and is not edited
by hand.
"""

import json
import os
from pathlib import Path

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters import (
    gitlab_sast_reporter as module,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_sast_reporter import (
    GitLabSASTReporter,
    GitLabSASTReporterConfig,
    GitLabSASTReporterConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    PropertyBag,
    Region,
    Result,
    Suppression,
)

pytestmark = pytest.mark.unit

GOLDEN = Path(__file__).parent / "golden" / "gitlab_sast_projection.json"


def _result(rule, uri, line, *, level="warning", scanner="bandit", severity=None):
    properties = {"scanner_name": scanner} if scanner else {}
    if severity:
        properties["issue_severity"] = severity
    return Result(
        ruleId=rule,
        level=level,
        message=Message(text=f"{rule} at {line}"),
        properties=PropertyBag(**properties) if properties else None,
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri=uri),
                    region=Region(startLine=line),
                )
            )
        ]
        if uri
        else None,
    )


def _suppressed(rule, uri, line, reason):
    result = _result(rule, uri, line)
    result.suppressions = [Suppression(kind="inSource", justification=reason)]
    return result


def _corpus():
    return [
        _result("B101", "app/a.py", 3),
        _result("B101", "app/a.py", 3),
        _suppressed("B101", "app/a.py", 3, "assert is fine here"),
        _result("BOOM", "app/a.py", 3),
        _result("B101", "app/a.py", 3, severity="high"),
        _result("B102", "app/b.py", 9, level="error"),
        _result("B102", "app/b.py", 9, level="error"),
        _result("B103", "app/\udcffbad.py", 5, level="note"),
        _result("B103", "app/\udcffbad.py", 5, level="note"),
        _result(None, None, None, level="none", scanner=None),
        _result(None, None, None, level="none", scanner=None),
        _result("B104", "app/c.py", 1, scanner="grype"),
    ]


def _shared(shared_at):
    def read(model, all_results):
        return [
            f"shared-{index}" if index in shared_at else None
            for index in range(len(all_results))
        ]

    return read


def _run(monkeypatch, context, shared_at, exclude_suppressed):
    real = module.result_severity

    def severity(result):
        if getattr(result, "ruleId", None) is not None and (
            getattr(result.ruleId, "root", result.ruleId) == "BOOM"
        ):
            raise ValueError("cannot grade")
        return real(result)

    monkeypatch.setattr(module, "result_severity", severity)
    monkeypatch.setattr(module, "shared_finding_ids", _shared(shared_at))
    model = AshAggregatedResults()
    model.sarif.runs[0].results = _corpus()
    # Each vulnerability's details carry the time the model was generated.
    model.metadata.generated_at = "2026-01-02T03:04:05+00:00"
    config = GitLabSASTReporterConfig(
        options=GitLabSASTReporterConfigOptions(exclude_suppressed=exclude_suppressed)
    )
    reporter = GitLabSASTReporter(context=context, config=config)
    document = json.loads(reporter.report(model))
    return {
        "vulnerabilities": document["vulnerabilities"],
        "status": document["scan"]["status"],
        "messages": document["scan"].get("messages"),
    }


CASES = {
    "all_legacy": (set(), False),
    "mixed_shared": ({0, 5, 9}, False),
    "all_shared": (set(range(12)), False),
    "all_legacy_excluding_suppressed": (set(), True),
}


def test_projection_matches_the_recorded_report(monkeypatch, test_plugin_context):
    recorded = {
        name: _run(monkeypatch, test_plugin_context, shared_at, exclude)
        for name, (shared_at, exclude) in CASES.items()
    }
    if os.environ.get("ASH_WRITE_GOLDEN") == "1":
        GOLDEN.parent.mkdir(exist_ok=True)
        GOLDEN.write_text(json.dumps(recorded, indent=1, sort_keys=False) + "\n")
    expected = json.loads(GOLDEN.read_text())
    assert recorded == expected
    # Same bytes in the same order, not only the same values.
    assert json.dumps(recorded) == json.dumps(expected)
