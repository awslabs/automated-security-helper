# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The named properties behind the baseline gate's identity-match policy and the
baseline provenance marker."""

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.flat_vulnerability import FlatVulnerability

pytestmark = pytest.mark.unit


def _finding() -> FlatVulnerability:
    return FlatVulnerability(
        id="f1",
        title="t",
        description="d",
        severity="MEDIUM",
        scanner="bandit",
        scanner_type="SAST",
        rule_id="B105",
        file_path="a.py",
    )


@pytest.mark.parametrize(
    "key, expected",
    [
        (None, False),
        ({}, False),
        ({"project": "p"}, False),
        ({"fingerprints": {"a": "1"}}, True),
        ({"partialFingerprints": {"a": "1"}}, True),
    ],
)
def test_has_fingerprint_identity_follows_the_assigned_key(key, expected):
    finding = _finding()
    finding._assigned_identity_key = key
    assert finding.has_fingerprint_identity is expected


@pytest.mark.parametrize("secret", [True, False])
def test_requires_exact_identity_match_is_the_secret_detection_flag(secret):
    finding = _finding()
    finding._secret_detection = secret
    assert finding.requires_exact_identity_match is secret


def test_baseline_filtered_reads_the_marker_by_presence():
    results = AshAggregatedResults()
    assert results.baseline_filtered is False
    results.metadata.baseline = {"sha256": "abc"}
    assert results.baseline_filtered is True
    results.metadata.baseline = None
    assert results.baseline_filtered is True
