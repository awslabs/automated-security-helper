# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash/correlationId``: one value for one secret, whichever scanner found it.

ASH does not deduplicate, so a secret that two scanners find is two ASFF
findings with two Ids. These tests pin the value that lets a consumer put them
side by side, and that it changes nothing else: which findings have it, what
makes two values equal, and that every finding is still sent with its own Id.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.asff_formatter import (
    AsffFormatter,
    _secret_correlation_id,
    _unique_by_id,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    PhysicalLocation2,
    PropertyBag,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

ACCOUNT = "123456789012"
REGION = "us-east-1"
FIELD = "ash/correlationId"


def _result(
    rule: str,
    *,
    scanner: str,
    uri: str | None = "config/settings.py",
    start: int | None = 12,
    column: int | None = None,
    tags: list[str] | None = None,
    package: str | None = None,
    project: str | None = None,
) -> Result:
    props: dict[str, Any] = {"scanner_name": scanner}
    if tags:
        props["tags"] = tags
    if package:
        props["package_name"] = package
    if project:
        props["workspace_project"] = project
    kwargs: dict[str, Any] = {
        "ruleId": rule,
        "level": "error",
        "message": Message(text=f"{rule} reported here"),
        "properties": PropertyBag(**props),
    }
    if uri is not None:
        kwargs["locations"] = [
            Location(
                physicalLocation=PhysicalLocation(
                    root=PhysicalLocation2(
                        artifactLocation=ArtifactLocation(uri=uri),
                        region=(
                            Region(startLine=start, startColumn=column)
                            if start is not None
                            else None
                        ),
                    )
                )
            )
        ]
    return Result(**kwargs)


def _findings(
    *results: Result, target: str = "tgt", project: str | None = None
) -> list[dict[str, Any]]:
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    model.metadata.generated_at = "2026-01-15T12:00:00.000Z"
    # The value is read off the model's flattened finding, whose scope is the
    # metadata's project name, so the run's target is recorded there.
    model.metadata.project_name = target
    if project is not None:
        model.metadata.workspace_project = project
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
    formatter = AsffFormatter(target, "source=/s;converted=no", None, offline=True)
    return formatter.build_asff_findings(model, account_id=ACCOUNT, region=REGION)


def _correlation(finding: dict[str, Any]) -> str | None:
    return finding["ProductFields"].get(FIELD)


def test_two_scanners_on_one_secret_share_the_value_and_keep_their_ids():
    first, second = _findings(
        _result("aws-access-token", scanner="gitleaks"),
        _result("AWSKeyDetector", scanner="detect-secrets"),
    )
    assert _correlation(first) is not None
    assert _correlation(first) == _correlation(second)
    assert first["Id"] != second["Id"]
    assert first["GeneratorId"] != second["GeneratorId"]
    # Both are still there to send: the value groups findings, it drops none.
    kept, duplicates = _unique_by_id([first, second])
    assert len(kept) == 2 and duplicates == 0


def test_the_value_is_this_hash_of_the_target_and_the_location_key():
    (finding,) = _findings(_result("aws-access-token", scanner="gitleaks"))
    key = {"file": "config/settings.py", "startLine": 12, "project": None}
    digest = hashlib.sha256(
        json.dumps(["tgt", key], sort_keys=True).encode("utf-8")
    ).hexdigest()
    assert _correlation(finding) == f"secret/{digest}"
    assert len(_correlation(finding)) == len("secret/") + 64


def test_the_field_is_the_last_product_field():
    (finding,) = _findings(_result("aws-access-token", scanner="gitleaks"))
    assert list(finding["ProductFields"])[-1] == FIELD


@pytest.mark.parametrize(
    "other",
    [
        pytest.param({"uri": "config/other.py"}, id="another-file"),
        pytest.param({"start": 13}, id="another-line"),
        pytest.param({"project": "service-b"}, id="another-project"),
    ],
)
def test_a_secret_somewhere_else_has_another_value(other):
    first, second = _findings(
        _result("aws-access-token", scanner="gitleaks"),
        _result("AWSKeyDetector", scanner="detect-secrets", **other),
    )
    assert _correlation(first) and _correlation(second)
    assert _correlation(first) != _correlation(second)


def test_the_same_place_in_another_target_has_another_value():
    (here,) = _findings(_result("aws-access-token", scanner="gitleaks"))
    (there,) = _findings(
        _result("aws-access-token", scanner="gitleaks"), target="other-repo"
    )
    assert _correlation(here) != _correlation(there)


def test_the_column_is_not_in_the_value():
    """Few scanners report a column and those that do place a secret's start
    differently, so two findings that differ only there still correlate."""
    first, second = _findings(
        _result("aws-access-token", scanner="gitleaks", column=5),
        _result("AWSKeyDetector", scanner="detect-secrets"),
    )
    assert _correlation(first) == _correlation(second)


def test_the_run_project_stands_in_for_a_result_that_names_none():
    named, unnamed = _findings(
        _result("aws-access-token", scanner="gitleaks", project="service-a"),
        _result("AWSKeyDetector", scanner="detect-secrets"),
        project="service-a",
    )
    assert _correlation(named) == _correlation(unnamed)


@pytest.mark.parametrize(
    "result",
    [
        pytest.param(_result("B101", scanner="bandit"), id="sast"),
        pytest.param(
            _result("CVE-2024-12345", scanner="grype", package="left-pad", start=1),
            id="dependency",
        ),
        pytest.param(_result("CKV_AWS_18", scanner="checkov"), id="iac"),
        pytest.param(_result("R1", scanner="not-a-shipped-scanner"), id="unknown"),
    ],
)
def test_a_finding_that_is_no_secret_detection_has_no_value(result):
    (finding,) = _findings(result)
    assert FIELD not in finding["ProductFields"]


def test_two_rules_on_one_line_that_detect_no_secret_do_not_correlate():
    """Two checks firing on one line are two problems: the place alone says
    which problem only for a secret."""
    first, second = _findings(
        _result("B101", scanner="bandit"),
        _result("python.lang.security.audit.x", scanner="semgrep"),
    )
    assert FIELD not in first["ProductFields"]
    assert FIELD not in second["ProductFields"]


@pytest.mark.parametrize(
    "where",
    [
        pytest.param({"uri": None}, id="no-file"),
        pytest.param({"start": None}, id="no-line"),
    ],
)
def test_a_secret_with_no_place_to_compare_has_no_value(where):
    (finding,) = _findings(_result("aws-access-token", scanner="gitleaks", **where))
    assert FIELD not in finding["ProductFields"]


def test_a_secret_rule_of_a_scanner_of_another_type_correlates_too():
    """A detection is told by its rule or its tags as well as by its scanner's
    type (``utils/secret_masking.is_secret_detection_of_rule``)."""
    by_scanner, by_tag = _findings(
        _result("aws-access-token", scanner="gitleaks"),
        _result("R7", scanner="not-a-shipped-scanner", tags=["secret"]),
    )
    assert _correlation(by_scanner) == _correlation(by_tag)


def test_no_key_gives_no_value():
    assert _secret_correlation_id("tgt", None) is None
