# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``secret_location_key``: where a secret is, without who reported it."""

from __future__ import annotations

import pytest

from automated_security_helper.models.vocab import TargetType
from automated_security_helper.utils.finding_identity import (
    finding_identity,
    identity_key,
    secret_location_key,
)

pytestmark = pytest.mark.unit


def _identity(scanner="gitleaks", rule="aws-access-token", **overrides):
    fields = {
        "scanner": scanner,
        "rule_id": rule,
        "file_path": "config/settings.py",
        "line_start": 12,
        "line_end": 12,
    }
    fields.update(overrides)
    return finding_identity(**fields)


def test_the_key_is_the_file_the_start_line_and_the_project():
    assert secret_location_key(_identity(workspace_project="service-a")) == {
        "file": "config/settings.py",
        "startLine": 12,
        "project": "service-a",
    }


def test_the_scanner_and_the_rule_are_not_in_it():
    one = _identity()
    other = _identity(scanner="detect-secrets", rule="AWSKeyDetector")
    assert identity_key(one) != identity_key(other)
    assert secret_location_key(one) == secret_location_key(other)


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"line_end": 14}, id="end-line"),
        pytest.param({"column": 9}, id="column"),
        pytest.param({"message": "another wording"}, id="message"),
        pytest.param(
            {"fingerprints": (("fingerprints", (("k/v1", "abc"),)),)},
            id="fingerprint",
        ),
    ],
)
def test_what_scanners_report_differently_about_one_secret_is_not_in_it(overrides):
    assert secret_location_key(_identity(**overrides)) == secret_location_key(
        _identity()
    )


def test_the_run_project_is_folded_in_as_the_identity_key_folds_it():
    assert secret_location_key(_identity(), "service-a") == secret_location_key(
        _identity(workspace_project="service-a")
    )
    assert (
        secret_location_key(_identity(workspace_project="service-b"), "service-a")[
            "project"
        ]
        == "service-b"
    )


def test_a_converted_file_is_told_from_a_source_file_of_the_same_path():
    converted = secret_location_key(_identity(converted=True))
    assert converted["tree"] == "converted"
    assert converted["tree"] == TargetType.CONVERTED.value
    assert "tree" not in secret_location_key(_identity())


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"file_path": None}, id="no-file"),
        pytest.param({"file_path": ""}, id="empty-file"),
        pytest.param({"line_start": None}, id="no-line"),
    ],
)
def test_no_place_to_compare_gives_no_key(overrides):
    assert secret_location_key(_identity(**overrides)) is None
