# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Severity and SeverityThreshold enums: wire spellings, order, ingest, schema."""

from __future__ import annotations

import json

import pytest

from automated_security_helper.models.vocab import (
    SEVERITY_BUCKETS,
    SEVERITY_COUNT_FIELDS,
    SEVERITY_THRESHOLD_VALUES,
    SEVERITY_VALUES,
    Severity,
    SeverityThreshold,
)


pytestmark = pytest.mark.unit


def test_severity_members_are_the_wire_spellings_most_severe_first():
    assert SEVERITY_VALUES == ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    assert [m.name for m in Severity] == list(SEVERITY_VALUES)


def test_threshold_members_are_the_wire_spellings_loosest_first():
    assert SEVERITY_THRESHOLD_VALUES == ("ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert "INFO" not in SEVERITY_THRESHOLD_VALUES
    assert "ALL" not in SEVERITY_VALUES


def test_derived_buckets_are_lowercase_and_keep_the_order():
    assert SEVERITY_BUCKETS == ("critical", "high", "medium", "low", "info")
    assert SEVERITY_COUNT_FIELDS == (
        "suppressed",
        "critical",
        "high",
        "medium",
        "low",
        "info",
    )


def test_members_compare_hash_and_serialize_as_their_values():
    assert Severity.HIGH == "HIGH"
    assert hash(Severity.HIGH) == hash("HIGH")
    assert {"HIGH": 1}[Severity.HIGH] == 1
    assert json.dumps({Severity.HIGH: SeverityThreshold.ALL}) == '{"HIGH": "ALL"}'
    # str methods stay str methods: a member is not shadowed by a property.
    assert Severity.HIGH.lower() == "high"
    assert Severity.HIGH.bucket == "high"


@pytest.mark.parametrize("text", ["high", "HIGH", " High ", "hIgH"])
def test_from_text_case_folds_and_strips(text):
    assert Severity.from_text(text) is Severity.HIGH


@pytest.mark.parametrize("text", ["moderate", "", "   ", None, 3, "ALL", "none"])
def test_an_off_ladder_word_is_none_not_an_error(text):
    assert Severity.from_text(text) is None


def test_the_threshold_ingest_helper_has_its_own_vocabulary():
    assert SeverityThreshold.from_text("all") is SeverityThreshold.ALL
    assert SeverityThreshold.from_text("INFO") is None
    assert SeverityThreshold.from_text(SeverityThreshold.LOW) is SeverityThreshold.LOW
    assert Severity.from_text(Severity.LOW) is Severity.LOW


def test_the_config_threshold_validates_case_sensitively_and_keeps_text():
    from pydantic import ValidationError

    from automated_security_helper.config.ash_config import (
        AshConfigGlobalSettingsSection,
    )

    section = AshConfigGlobalSettingsSection(severity_threshold="HIGH")
    assert type(section.severity_threshold) is str
    assert section.severity_threshold == "HIGH"
    with pytest.raises(ValidationError):
        AshConfigGlobalSettingsSection(severity_threshold="high")
    with pytest.raises(ValidationError):
        AshConfigGlobalSettingsSection(severity_threshold="INFO")


def test_the_config_threshold_validates_under_strict_as_a_file_load_does():
    from automated_security_helper.config.ash_config import (
        AshConfigGlobalSettingsSection,
    )

    section = AshConfigGlobalSettingsSection.model_validate(
        {"severity_threshold": "LOW"}, strict=True
    )
    assert section.severity_threshold == "LOW"


def test_the_container_threshold_is_text_and_dumps_text():
    from automated_security_helper.models.scan_results_container import (
        ScanResultsContainer,
    )

    container = ScanResultsContainer(
        scanner_name="x", scanner_severity_threshold="LOW", target="."
    )
    assert type(container.scanner_severity_threshold) is str
    assert container.model_dump(mode="json")["scanner_severity_threshold"] == "LOW"
