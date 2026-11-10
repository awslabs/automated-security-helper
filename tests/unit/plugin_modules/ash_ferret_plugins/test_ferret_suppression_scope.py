# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ferret-scan's suppression-scope block: validation and matching.

``scope.engines.ferret-scan`` carries ``confidence_level`` (the band ferret-scan
reported, from the result's ``confidenceLevel`` property) and ``validator``
(the result's ``validator`` property). The plugin owns both: ASH's core
dispatches the block here and never reads its keys. Everything fails closed —
a finding without the named property never matches.
"""

import json

import pytest

from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    FerretScanScanner,
    FerretScopeBlock,
)
from automated_security_helper.utils.suppression_scope_registry import (
    engine_hooks_for,
)

pytestmark = pytest.mark.unit


def _finding(
    rule_id="API_KEY_OR_SECRET",
    scanner="ferret-scan",
    confidence_level="high",
    validator="aws_credentials",
    properties=...,
    **kw,
):
    if properties is ...:
        properties = json.dumps(
            {
                "confidence": 95.0,
                "confidenceLevel": confidence_level,
                "validator": validator,
            }
        )
    values = {
        "id": "f1",
        "title": "t",
        "description": "d",
        "severity": "MEDIUM",
        "scanner": scanner,
        "scanner_type": "SECRETS",
        "rule_id": rule_id,
        "file_path": "src/config.py",
        "line_start": 12,
        "properties": properties,
    }
    values.update(kw)
    return FlatVulnerability(**values)


def _entry(block, rule_id="API_KEY_OR_SECRET"):
    return AshSuppression.model_validate(
        {
            "rule_id": rule_id,
            "path": "src/*.py",
            "reason": "test",
            "scope": {"engines": {"ferret-scan": block}},
        }
    )


class TestRegistration:
    def test_ferret_scan_registers_its_hooks(self):
        assert engine_hooks_for("ferret-scan") is FerretScanScanner


class TestValidation:
    def test_a_good_block_validates(self):
        assert (
            FerretScanScanner.validate_suppression_scope(
                {"confidence_level": ["low", "medium"], "validator": "aws_credentials"}
            )
            == []
        )

    def test_an_empty_block_is_refused(self):
        problems = FerretScanScanner.validate_suppression_scope({})
        assert problems and "selects nothing" in problems[0]

    def test_an_unknown_key_is_refused(self):
        problems = FerretScanScanner.validate_suppression_scope(
            {"confidence": "low"}
        )
        assert problems

    def test_an_unknown_band_is_refused_naming_the_valid_set(self):
        problems = FerretScanScanner.validate_suppression_scope(
            {"confidence_level": "extreme"}
        )
        assert problems and "'high', 'low', 'medium'" in problems[0]

    @pytest.mark.parametrize(
        "value", ["", "   ", [], [""], ["  "]], ids=["blank", "spaces", "empty-list", "blank-item", "space-item"]
    )
    def test_an_empty_confidence_value_is_refused(self, value):
        assert FerretScanScanner.validate_suppression_scope(
            {"confidence_level": value}
        )

    def test_an_empty_validator_is_refused(self):
        assert FerretScanScanner.validate_suppression_scope({"validator": "  "})


class TestMatching:
    def test_confidence_level_matches_its_band_case_insensitively(self):
        finding = _finding(confidence_level="Low")
        assert FerretScanScanner.suppression_scope_matches(
            {"confidence_level": ["low", "medium"]}, finding
        )

    def test_confidence_level_does_not_match_another_band(self):
        finding = _finding(confidence_level="high")
        assert not FerretScanScanner.suppression_scope_matches(
            {"confidence_level": ["low", "medium"]}, finding
        )

    def test_validator_matches_exactly_case_insensitively(self):
        finding = _finding(validator="AWS_Credentials")
        assert FerretScanScanner.suppression_scope_matches(
            {"validator": "aws_credentials"}, finding
        )

    def test_validator_is_not_a_glob(self):
        finding = _finding(validator="aws_credentials")
        assert not FerretScanScanner.suppression_scope_matches(
            {"validator": "aws_*"}, finding
        )

    def test_both_keys_must_match(self):
        finding = _finding(confidence_level="low", validator="aws_credentials")
        assert FerretScanScanner.suppression_scope_matches(
            {"confidence_level": "low", "validator": "aws_credentials"}, finding
        )
        assert not FerretScanScanner.suppression_scope_matches(
            {"confidence_level": "low", "validator": "generic_secrets"}, finding
        )

    @pytest.mark.parametrize(
        "properties",
        [None, "not json", json.dumps([1, 2]), json.dumps({})],
        ids=["absent", "unparseable", "not-a-dict", "no-keys"],
    )
    def test_a_finding_without_usable_properties_never_matches(self, properties):
        finding = _finding(properties=properties)
        assert not FerretScanScanner.suppression_scope_matches(
            {"confidence_level": "high"}, finding
        )
        assert not FerretScanScanner.suppression_scope_matches(
            {"validator": "aws_credentials"}, finding
        )

    def test_an_unknown_key_fails_closed_at_match_time(self):
        finding = _finding()
        assert not FerretScanScanner.suppression_scope_matches(
            {"confidence": "high"}, finding
        )

    def test_an_empty_block_fails_closed_at_match_time(self):
        assert not FerretScanScanner.suppression_scope_matches({}, _finding())


class TestThroughAshSuppression:
    """The block as the matcher dispatches it, scanner attribution included."""

    def test_a_scoped_entry_suppresses_the_covered_finding(self):
        entry = _entry({"confidence_level": ["low", "medium"]})
        assert entry.matches(_finding(confidence_level="medium"))

    def test_a_scoped_entry_leaves_other_bands_reported(self):
        entry = _entry({"confidence_level": ["low", "medium"]})
        assert not entry.matches(_finding(confidence_level="high"))

    def test_a_scoped_entry_never_covers_another_scanner(self):
        entry = _entry({"confidence_level": ["low", "medium", "high"]})
        finding = _finding(scanner="bandit", confidence_level="low")
        assert not entry.matches(finding)


class TestBlockModel:
    def test_single_string_and_list_forms_are_both_accepted(self):
        assert FerretScopeBlock.model_validate({"confidence_level": "low"})
        assert FerretScopeBlock.model_validate({"confidence_level": ["low", "HIGH"]})

    def test_split_rule_qualifier_is_the_no_split_default(self):
        assert FerretScanScanner.split_rule_qualifier("API_KEY_OR_SECRET") == (
            "API_KEY_OR_SECRET",
            None,
        )
