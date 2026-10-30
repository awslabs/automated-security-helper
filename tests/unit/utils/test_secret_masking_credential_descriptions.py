# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Which rules and messages describe a credential in code, and in what time.

A dependency scanner's rule whose CVE text mentioned a hard-coded key, and a code
scanner's message that named a ``hardcoded-secrets`` path, were classed as secret
rules and findings, which masked their files from the finding's line to the end.
The pattern that read such a description joined its two words with ``.*`` and
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
    _describes_a_credential_in_code,
    _matched_values,
    is_secret_finding,
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
    def test_a_dependency_scanners_cve_rule_is_not_a_secret_rule(self):
        report = _report(
            _run(
                "grype",
                "CVE-2024-0001",
                CVE_TEXT,
                _result("CVE-2024-0001", "vuln", "grype"),
            )
        )

        assert "CVE-2024-0001" not in secret_rule_ids(report)

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


class TestWhichMessagesDescribeACredential:
    def test_a_code_scanners_message_naming_a_path_is_not_a_secret_finding(self):
        report = _report(
            _run("semgrep", "x", "", _result("rule.a", PATH_TEXT, "semgrep"))
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
