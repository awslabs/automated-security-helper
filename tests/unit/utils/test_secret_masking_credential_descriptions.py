# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Which rules and messages describe a credential in code, and in what time.

A rule or a message that describes a credential in code counts for a finding of
any scanner type. A code scanner's message can hold the value its rule matched
without quoting it, so a rule or message of a code scanner that reads like such
a description is classed as a secret rule or finding, which masks the value and
the file from the finding's line to the end: masking is the side that fails
closed. A dependency scanner is the exception for its findings, which describe
the dependency and not the scanned code: its rule is still listed among the
secret rules, but its finding enters by neither that rule nor its own text.
The pattern that reads such a description joined its two words with ``.*`` and
backtracked over the whole text for every credential word in it; and the pattern
that read the string literals of a matched line restarted at every quote of a
line of escaped quotes.

Every value here is an ordinary word or derived at import time; none is a
credential.
"""

import re
import time

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils import secret_masking
from automated_security_helper.utils.secret_masking import (
    MASKED_LINE,
    _describes_a_credential_in_code,
    _matched_values,
    is_secret_finding,
    mask_secrets_in_results,
    secret_rule_ids,
)

pytestmark = pytest.mark.unit

CVE_TEXT = "The product uses a hard-coded cryptographic key to sign tokens."
PATH_TEXT = "Listing of the hardcoded-secrets directory is enabled"


def _result(rule_id, message, scanner):
    return {
        "ruleId": rule_id,
        "level": "warning",
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "app.py"},
                    "region": {"startLine": 5, "endLine": 5},
                }
            }
        ],
        "properties": {"scanner_name": scanner, "tags": [scanner]},
    }


def _report(*runs):
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate({"version": "2.1.0", "runs": list(runs)})
    return model.sarif


def _run(scanner, rule_id, description, *results):
    return {
        "tool": {
            "driver": {
                "name": scanner,
                "rules": [{"id": rule_id, "fullDescription": {"text": description}}],
            }
        },
        "results": list(results),
    }


class TestWhichRulesDescribeACredential:
    def test_a_dependency_scanners_rule_that_describes_one_is_still_listed(self):
        """The rule is listed; a finding of a dependency scanner does not enter
        by it (``is_secret_finding`` gets the described-only rule ids)."""
        report = _report(
            _run(
                "grype",
                "CVE-2024-0001",
                CVE_TEXT,
                _result("CVE-2024-0001", "vuln", "grype"),
            )
        )

        assert "CVE-2024-0001" in secret_rule_ids(report)

    def test_a_code_scanners_rule_that_describes_one_is_a_secret_rule(self):
        report = _report(
            _run(
                "semgrep",
                "rule.a",
                CVE_TEXT,
                _result("rule.a", "found", "semgrep"),
            )
        )

        assert "rule.a" in secret_rule_ids(report)

    def test_a_rule_that_describes_nothing_of_the_kind_is_not(self):
        """Control."""
        report = _report(
            _run(
                "semgrep",
                "rule.b",
                "Use of a deprecated function",
                _result("rule.b", "found", "semgrep"),
            )
        )

        assert "rule.b" not in secret_rule_ids(report)

    def test_an_infrastructure_scanners_rule_is(self):
        report = _report(
            _run(
                "checkov",
                "CKV_AWS_41",
                CVE_TEXT,
                _result("CKV_AWS_41", "found", "checkov"),
            )
        )

        assert "CKV_AWS_41" in secret_rule_ids(report)

    def test_a_rule_of_a_scanner_of_unknown_type_still_is(self):
        """Control: a scanner ASH does not know keeps the earlier reading."""
        report = _report(
            _run(
                "custom-tool",
                "RULE-1",
                CVE_TEXT,
                _result("RULE-1", "found", "custom-tool"),
            )
        )

        assert "RULE-1" in secret_rule_ids(report)


class TestWhichRulesDescribeACredentialInAMixedReport:
    """A report holds the runs of several scanners; a rule counts by its own
    description, not by which other scanners share the report."""

    def _report_of_three(self, third_scanner="custom-tool"):
        return _report(
            _run(
                "checkov",
                "CKV_AWS_41",
                CVE_TEXT,
                _result("CKV_AWS_41", "found", "checkov"),
            ),
            _run(
                "grype",
                "CVE-2024-0001",
                CVE_TEXT,
                _result("CVE-2024-0001", "vuln", "grype"),
            ),
            _run(
                third_scanner,
                "RULE-1",
                CVE_TEXT,
                _result("RULE-1", "found", third_scanner),
            ),
        )

    def test_every_scanners_describing_rule_is_a_secret_rule(self):
        ids = secret_rule_ids(self._report_of_three())

        assert {"CKV_AWS_41", "CVE-2024-0001", "RULE-1"} <= ids

    def test_a_scanner_of_unknown_type_is_not_dropped_beside_known_ones(self):
        """Control: with a known non-infrastructure scanner in the report, a rule
        of a scanner ASH does not know still counts."""
        ids = secret_rule_ids(self._report_of_three(third_scanner="semgrep"))

        assert "RULE-1" in ids

    def test_a_rule_that_describes_nothing_of_the_kind_stays_out(self):
        """Control."""
        report = _report(
            _run(
                "checkov",
                "CKV_AWS_41",
                CVE_TEXT,
                _result("CKV_AWS_41", "found", "checkov"),
            ),
            _run(
                "semgrep",
                "rule.b",
                "Use of a deprecated function",
                _result("rule.b", "found", "semgrep"),
            ),
        )

        ids = secret_rule_ids(report)

        assert "CKV_AWS_41" in ids
        assert "rule.b" not in ids


class TestWhichMessagesDescribeACredential:
    def test_a_code_scanners_message_that_describes_one_is_a_secret_finding(self):
        report = _report(
            _run("semgrep", "x", "", _result("rule.a", PATH_TEXT, "semgrep"))
        )

        assert is_secret_finding(report.runs[0].results[0])

    def test_a_code_scanners_message_that_describes_nothing_of_the_kind_is_not(self):
        """Control."""
        report = _report(
            _run(
                "semgrep",
                "x",
                "",
                _result("rule.a", "Use of a deprecated function", "semgrep"),
            )
        )

        assert not is_secret_finding(report.runs[0].results[0])

    def test_an_infrastructure_scanners_message_is(self):
        report = _report(
            _run("checkov", "x", "", _result("CKV_AWS_1", PATH_TEXT, "checkov"))
        )

        assert is_secret_finding(report.runs[0].results[0])

    def test_a_quoted_value_marks_a_secret_finding_whatever_the_scanner(self):
        """Control."""
        message = "Possible hardcoded " + "pass" + "word: 'value'"
        report = _report(
            _run("semgrep", "x", "", _result("rule.a", message, "semgrep"))
        )

        assert is_secret_finding(report.runs[0].results[0])


#: A value a code scanner's rule matched; an ordinary-looking token, no credential.
MATCHED = "k7q2m9zx4t"


def _model_with_matched_value(message):
    """One semgrep finding whose region covers a line that holds ``MATCHED`` and
    whose message holds it too, without a quote around it."""
    line = f'secret = "{MATCHED}"'
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep"}},
                    "results": [
                        {
                            "ruleId": "rule.a",
                            "level": "warning",
                            "message": {"text": message},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app.py"},
                                        "region": {
                                            "startLine": 5,
                                            "endLine": 5,
                                            "startColumn": 1,
                                            "endColumn": len(line) + 1,
                                            "snippet": {"text": line + "\n"},
                                        },
                                    }
                                }
                            ],
                            "properties": {
                                "scanner_name": "semgrep",
                                "tags": ["semgrep"],
                            },
                        }
                    ],
                }
            ],
        }
    )
    return model


class TestACodeScannersMatchedValueIsMasked:
    """A code scanner's message that describes a credential holds the value its
    rule matched, and the finding is a secret finding whatever the scanner's type."""

    def test_the_value_in_the_message_and_the_snippet_are_masked(self):
        model = _model_with_matched_value(f"Hard-coded secret found: {MATCHED}")
        result = model.sarif.runs[0].results[0]
        assert is_secret_finding(result)

        mask_secrets_in_results(model)

        region = result.locations[0].physicalLocation.root.region
        assert MATCHED not in result.message.root.text
        assert region.snippet.text == MASKED_LINE + "\n"

    def test_a_message_that_describes_nothing_of_the_kind_is_left_alone(self):
        """Control: the same finding with an ordinary message is no secret finding,
        so its message and snippet are as the scanner wrote them."""
        message = f"Use of a deprecated function, see {MATCHED}"
        model = _model_with_matched_value(message)
        result = model.sarif.runs[0].results[0]
        assert not is_secret_finding(result)

        mask_secrets_in_results(model)

        assert result.message.root.text == message


class TestTheDescriptionReadIsLinear:
    def test_a_long_message_of_credential_words_is_read_quickly(self):
        text = "key " * 5000

        started = time.monotonic()
        described = _describes_a_credential_in_code(text)
        elapsed = time.monotonic() - started

        assert not described
        assert elapsed < 1.0

    @pytest.mark.parametrize(
        "text",
        [
            "Ensure no hard coded AWS access key and secret key exists in provider",
            "SecureString parameter should not have hardcoded default values",
            "DB password must not be a plaintext string",
            "Ensure no sensitive credentials are exposed in VM custom_data",
        ],
    )
    def test_the_descriptions_still_match(self, text):
        assert _describes_a_credential_in_code(text)

    def test_master_username_does_not(self):
        assert not _describes_a_credential_in_code(
            "master username must not be a plaintext string"
        )


#: The pattern the scan replaces, kept here as the reference it has to agree with.
REFERENCE = re.compile(r"""(["'])((?:\\.|(?!\1)[^\\])*)\1""")


class TestTheStringLiteralScan:
    @pytest.mark.parametrize(
        "line",
        [
            'x = "abc"',
            "x = 'abc' + \"def\"",
            '\'abc"def"',
            '"a\\"b" \'c\'',
            'x = "unterminated',
            "\"a\\\\\" + 'b'",
            '""',
            "'it''s'",
            "'a\\'b'",
            "no quotes at all",
            "\\\"escaped start\\\" 'x'",
            'a = f"{x}" and "\\\\\\""',
        ],
    )
    def test_agrees_with_the_pattern(self, line):
        """The scan is read off the module so that the other tests of this file
        still run on a module that does not have it."""
        expected = [found.group(2) for found in REFERENCE.finditer(line)]

        assert secret_masking._string_literals(line) == expected

    def test_a_line_of_escaped_quotes_is_read_quickly(self):
        line = '\\"' * 20000
        result = {
            "ruleId": "generic.secrets.security.detected-generic-secret",
            "message": {"text": "found"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "app.py"},
                        "region": {
                            "startLine": 1,
                            "endLine": 1,
                            "startColumn": 1,
                            "endColumn": len(line) + 1,
                            "snippet": {"text": line},
                        },
                    }
                }
            ],
        }
        report = _report({"tool": {"driver": {"name": "semgrep"}}, "results": [result]})

        started = time.monotonic()
        values = _matched_values(report.runs[0].results[0])
        elapsed = time.monotonic() - started

        assert values == [line]
        assert elapsed < 1.0
