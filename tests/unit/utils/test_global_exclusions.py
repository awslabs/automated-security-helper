# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``global_settings.exclusions``: rule+path exclusions that DROP results (#894).

An exclusion names a rule (glob allowed), a path (the suppression matcher's
reading), optionally one scanner, and a required reason. A result every
file-naming location of which is under the path, whose rule matches and whose
scanner matches (when named), is dropped from the SARIF report -- unlike a
suppression, which keeps the result marked ``suppressed``. A delivered
(client-supplied) config's exclusion never drops: it marks, so the results
show what the client chose to hide, as a client-supplied ignore path does.
"""

import pytest
from pydantic import ValidationError

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.core import AshExclusion
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation2,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif

pytestmark = pytest.mark.unit


def _result(rule_id: str, *uris: str) -> Result:
    return Result(
        ruleId=rule_id,
        message=Message(text=f"{rule_id} finding"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation2(
                    artifactLocation=ArtifactLocation(uri=uri),
                    region=Region(startLine=1, endLine=1),
                )
            )
            for uri in uris
        ],
    )


def _report(*results: Result) -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="bandit", version="1.0.0")),
                results=list(results),
            )
        ],
    )


def _context(test_source_dir, test_output_dir, *exclusions) -> PluginContext:
    config = AshConfig(
        project_name="test-project",
        global_settings={"exclusions": list(exclusions)},
    )
    return PluginContext(
        source_dir=test_source_dir,
        output_dir=test_output_dir,
        config=config,
    )


def _kept_rule_uri_pairs(report: SarifReport) -> set:
    return {
        (
            result.ruleId,
            result.locations[0].physicalLocation.root.artifactLocation.uri,
        )
        for result in report.runs[0].results
    }


B101_TESTS = {"rule_id": "B101", "path": "**/tests/**", "reason": "asserts in tests"}


class TestExclusionsDropResults:
    def test_matching_rule_under_path_is_dropped_and_others_kept(
        self, test_source_dir, test_output_dir
    ):
        report = apply_suppressions_to_sarif(
            _report(
                _result("B101", "tests/test_x.py"),
                _result("B101", "src/app.py"),
                _result("B105", "tests/test_x.py"),
            ),
            _context(test_source_dir, test_output_dir, B101_TESTS),
        )
        kept = _kept_rule_uri_pairs(report)
        assert ("B101", "tests/test_x.py") not in kept
        assert ("B101", "src/app.py") in kept
        assert ("B105", "tests/test_x.py") in kept
        # Dropped, not suppressed: the kept results carry no suppression mark.
        for result in report.runs[0].results:
            assert not result.suppressions

    def test_a_bare_directory_path_names_its_subtree(
        self, test_source_dir, test_output_dir
    ):
        exclusion = {"rule_id": "B101", "path": "tests", "reason": "asserts in tests"}
        report = apply_suppressions_to_sarif(
            _report(
                _result("B101", "tests/test_x.py"),
                _result("B101", "pkg/tests/test_x.py"),
            ),
            _context(test_source_dir, test_output_dir, exclusion),
        )
        kept = _kept_rule_uri_pairs(report)
        assert ("B101", "tests/test_x.py") not in kept
        # Anchored: a tests directory elsewhere is not the one named.
        assert ("B101", "pkg/tests/test_x.py") in kept

    def test_a_rule_glob_matches_and_bounds(self, test_source_dir, test_output_dir):
        exclusion = {"rule_id": "B1*", "path": "tests", "reason": "bandit low-value"}
        report = apply_suppressions_to_sarif(
            _report(
                _result("B101", "tests/test_x.py"),
                _result("B607", "tests/test_x.py"),
            ),
            _context(test_source_dir, test_output_dir, exclusion),
        )
        kept = _kept_rule_uri_pairs(report)
        assert ("B101", "tests/test_x.py") not in kept
        assert ("B607", "tests/test_x.py") in kept

    def test_a_multi_location_result_is_kept_when_one_location_is_outside(
        self, test_source_dir, test_output_dir
    ):
        report = apply_suppressions_to_sarif(
            _report(_result("B101", "tests/test_x.py", "src/app.py")),
            _context(test_source_dir, test_output_dir, B101_TESTS),
        )
        assert len(report.runs[0].results) == 1


class TestExclusionScoping:
    def test_a_named_scanner_bounds_the_exclusion(
        self, test_source_dir, test_output_dir
    ):
        exclusion = dict(B101_TESTS, scanner="bandit")
        context = _context(test_source_dir, test_output_dir, exclusion)
        dropped = apply_suppressions_to_sarif(
            _report(_result("B101", "tests/test_x.py")),
            context,
            scanner_name="bandit",
        )
        assert _kept_rule_uri_pairs(dropped) == set()
        kept = apply_suppressions_to_sarif(
            _report(_result("B101", "tests/test_x.py")),
            context,
            scanner_name="semgrep",
        )
        assert ("B101", "tests/test_x.py") in _kept_rule_uri_pairs(kept)

    def test_an_expired_exclusion_does_not_apply(
        self, test_source_dir, test_output_dir
    ):
        exclusion = dict(B101_TESTS, expires="2020-01-01")
        report = apply_suppressions_to_sarif(
            _report(_result("B101", "tests/test_x.py")),
            _context(test_source_dir, test_output_dir, exclusion),
        )
        assert ("B101", "tests/test_x.py") in _kept_rule_uri_pairs(report)

    def test_ignore_suppressions_lifts_exclusions_too(
        self, test_source_dir, test_output_dir
    ):
        config = AshConfig(
            project_name="test-project",
            global_settings={"exclusions": [B101_TESTS]},
        )
        context = PluginContext(
            source_dir=test_source_dir,
            output_dir=test_output_dir,
            config=config,
            ignore_suppressions=True,
        )
        report = apply_suppressions_to_sarif(
            _report(_result("B101", "tests/test_x.py")), context
        )
        assert ("B101", "tests/test_x.py") in _kept_rule_uri_pairs(report)

    def test_a_client_supplied_exclusion_marks_instead_of_dropping(
        self, test_source_dir, test_output_dir
    ):
        exclusion = AshExclusion(
            rule_id="B101",
            path="**/tests/**",
            reason="asserts in tests",
            client_supplied=True,
        )
        report = apply_suppressions_to_sarif(
            _report(_result("B101", "tests/test_x.py")),
            _context(test_source_dir, test_output_dir, exclusion),
        )
        results = report.runs[0].results
        assert len(results) == 1
        assert results[0].suppressions
        assert "client-supplied" in results[0].suppressions[0].justification


class TestAshExclusionModel:
    def test_rule_id_path_and_reason_are_required(self):
        with pytest.raises(ValidationError):
            AshExclusion(path="tests", reason="no rule")
        with pytest.raises(ValidationError):
            AshExclusion(rule_id="B101", reason="no path")
        with pytest.raises(ValidationError):
            AshExclusion(rule_id="B101", path="tests")

    def test_an_unknown_key_is_refused(self):
        with pytest.raises(ValidationError):
            AshExclusion(rule_id="B101", path="tests", reason="x", line_start=5)

    def test_the_config_field_round_trips(self):
        config = AshConfig(
            project_name="test-project",
            global_settings={"exclusions": [dict(B101_TESTS, scanner="bandit")]},
        )
        entry = config.global_settings.exclusions[0]
        assert entry.rule_id == "B101"
        assert entry.scanner == "bandit"
        assert entry.client_supplied is False
