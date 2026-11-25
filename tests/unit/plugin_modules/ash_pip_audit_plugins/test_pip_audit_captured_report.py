# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pip-audit converter over a REAL capture.

``tests/test_data/scanners/pip-audit/captured/pip-audit-2.10.1.json`` is the
unedited output of ``pip-audit==2.10.1 --format=json --vulnerability-service=pypi
--desc=on --aliases=on --no-deps --disable-pip --requirement=requirements.txt``
over the committed ``requirements.txt`` (see ``captured/README.md``).
``positive.sarif`` is what ``convert_pip_audit_json`` wrote from it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_pip_audit_plugins.pip_audit_scanner import (
    ADVISORY_LEVEL,
    ADVISORY_SEVERITY,
    convert_pip_audit_json,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "pip-audit"
    / "captured"
)


@pytest.fixture(scope="module")
def document():
    return json.loads((CAPTURED / "pip-audit-2.10.1.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def converted(document):
    return convert_pip_audit_json(
        document,
        uri="requirements.txt",
        requirements_text=(CAPTURED / "requirements.txt").read_text(encoding="utf-8"),
    )


def test_the_capture_repeats_an_advisory_the_service_returned_twice(document):
    """Control: the raw capture holds duplicate ids, so the dedup test below
    is not vacuous."""
    for dep in document["dependencies"]:
        ids = [v["id"] for v in dep["vulns"]]
        assert len(ids) > len(set(ids)), dep["name"]


def test_one_result_per_package_and_advisory(converted):
    results, _rules, skipped = converted
    assert skipped == []
    rows = [(r.ruleId, r.properties.model_dump()["package_name"]) for r in results]
    assert sorted(rows) == [
        ("PYSEC-2020-96", "pyyaml"),
        ("PYSEC-2021-142", "pyyaml"),
        ("PYSEC-2026-215", "idna"),
    ]


def test_fingerprints_are_unique(converted):
    results, _rules, _skipped = converted
    prints = [r.partialFingerprints["pip-audit/v1"] for r in results]
    assert len(prints) == len(set(prints))


def test_severity_and_level_agree_over_every_captured_result(converted):
    results, _rules, _skipped = converted
    assert results
    for result in results:
        level = result.level.value if hasattr(result.level, "value") else result.level
        assert level == ADVISORY_LEVEL
        assert result.properties.model_dump()["issue_severity"] == ADVISORY_SEVERITY


def test_results_sit_on_the_requirements_line_naming_the_package(converted):
    results, _rules, _skipped = converted
    lines = {
        r.properties.model_dump()["package_name"]: (
            r.locations[0].physicalLocation.root.region.startLine
        )
        for r in results
    }
    assert lines == {"pyyaml": 1, "idna": 2}


def test_the_committed_sarif_is_what_the_converter_writes(converted):
    """The fixture the facets corpus gate reads does not drift from the code."""
    results, _rules, _skipped = converted
    committed = SarifReport.model_validate(
        json.loads((CAPTURED / "positive.sarif").read_text(encoding="utf-8"))
    )
    committed_results = committed.runs[0].results
    assert [r.ruleId for r in committed_results] == [r.ruleId for r in results]
    assert [r.partialFingerprints for r in committed_results] == [
        r.partialFingerprints for r in results
    ]
