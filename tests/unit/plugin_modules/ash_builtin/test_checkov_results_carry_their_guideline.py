# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""checkov results carry the policy page of their check as a reference.

checkov's SARIF has no related locations; its JSON report names the policy page of
each check (``guideline``). ``attach_checkov_guidelines`` copies it, on the key and
under the count rule that ``attach_checkov_resources`` uses, as a related location,
which is what the flat model's ``references`` column reads. The URL must survive
``rewrite_checkov_paths``, which rebuilds every location URI as a path.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    attach_checkov_guidelines,
    attach_checkov_resources,
    checkov_guidelines,
    checkov_resources,
    rewrite_checkov_paths,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.scanner_names import SCANNER_TOOL_TYPES

pytestmark = pytest.mark.unit

URL = "https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws/s3-21"


def _record(check_id, path, lines, guideline, resource="aws_s3_bucket.b"):
    return {
        "check_id": check_id,
        "repo_file_path": path,
        "file_line_range": list(lines),
        "resource": resource,
        "guideline": guideline,
    }


def _report(check_type, *records):
    return {
        "check_type": check_type,
        "results": {"failed_checks": list(records), "skipped_checks": []},
    }


def _result(rule_id, uri, start, end):
    return {
        "ruleId": rule_id,
        "message": {"text": "m"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": start, "endLine": end},
                }
            }
        ],
    }


def _sarif(*results):
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Checkov"}}, "results": list(results)}],
    }


def _related(result):
    return [
        r["physicalLocation"]["artifactLocation"]["uri"]
        for r in result.get("relatedLocations") or []
    ]


def test_a_result_takes_the_guideline_of_its_record() -> None:
    sarif = _sarif(_result("CKV_AWS_21", "tf/main.tf", 1, 3))
    reports = [_report("terraform", _record("CKV_AWS_21", "/tf/main.tf", (1, 3), URL))]
    assert attach_checkov_guidelines(sarif, checkov_guidelines(reports)) == 1
    assert _related(sarif["runs"][0]["results"][0]) == [URL]


def test_the_guideline_is_read_for_every_framework() -> None:
    """A guideline names the policy, so the resource allow-list does not apply."""
    reports = [
        _report("dockerfile", _record("CKV_DOCKER_2", "/Dockerfile", (1, 2), URL))
    ]
    assert list(checkov_guidelines(reports).values()) == [[URL]]
    assert list(checkov_resources(reports).values()) == [[None]]


@pytest.mark.parametrize("guideline", [URL, "http://docs.example/policy"])
def test_an_http_or_https_url_is_copied(guideline) -> None:
    """The positive control for the refusals below, on the same builders."""
    sarif = _sarif(_result("CKV_X_1", "a.tf", 1, 2))
    reports = [_report("terraform", _record("CKV_X_1", "/a.tf", (1, 2), guideline))]
    assert attach_checkov_guidelines(sarif, checkov_guidelines(reports)) == 1
    assert _related(sarif["runs"][0]["results"][0]) == [guideline]


@pytest.mark.parametrize(
    "guideline",
    [
        None,
        "",
        "javascript:alert(1)",
        "/etc/passwd",
        "ftp://x/y",
        5,
        " https://x/y",
        "HTTPS://X/Y",
    ],
)
def test_only_an_http_url_is_copied(guideline) -> None:
    sarif = _sarif(_result("CKV_X_1", "a.tf", 1, 2))
    reports = [_report("terraform", _record("CKV_X_1", "/a.tf", (1, 2), guideline))]
    assert attach_checkov_guidelines(sarif, checkov_guidelines(reports)) == 0
    assert "relatedLocations" not in sarif["runs"][0]["results"][0]


def test_a_count_mismatch_copies_nothing() -> None:
    sarif = _sarif(_result("CKV_X_1", "a.tf", 1, 2), _result("CKV_X_1", "a.tf", 1, 2))
    reports = [_report("terraform", _record("CKV_X_1", "/a.tf", (1, 2), URL))]
    assert attach_checkov_guidelines(sarif, checkov_guidelines(reports)) == 0


def test_the_url_survives_the_path_rewrite_and_reaches_the_flat_row(tmp_path) -> None:
    source = tmp_path / "src"
    (source / "tf").mkdir(parents=True)
    (source / "tf" / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
    reports = [_report("terraform", _record("CKV_AWS_21", "/tf/main.tf", (1, 3), URL))]
    sarif = _sarif(_result("CKV_AWS_21", "tf/main.tf", 1, 3))
    attach_checkov_resources(sarif, checkov_resources(reports))
    attach_checkov_guidelines(sarif, checkov_guidelines(reports))
    rewrite_checkov_paths(
        sarif,
        ran_in=source.as_posix(),
        source_dir=source.as_posix(),
        scanned_dirs=[source.as_posix()],
    )
    assert _related(sarif["runs"][0]["results"][0]) == [URL]
    report = SarifReport.model_validate(json.loads(json.dumps(sarif)))
    flat = FlatVulnerability.from_sarif_result(
        report.runs[0].results[0],
        "checkov",
        SCANNER_TOOL_TYPES["checkov"],
        report.runs[0],
    )
    assert json.loads(flat.references) == [URL]
    assert flat.resource_id == "aws_s3_bucket.b"
