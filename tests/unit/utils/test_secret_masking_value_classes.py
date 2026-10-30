# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Which values are masked where, and how a quoted value is read.

A word with punctuation around it (``password:``) propagated and rewrote bandit's
own label; a value of asterisks alone was taken for a masked form and propagated
as a shape with no token boundary; a ``$`` followed by letters of both cases and
digits was classed as a template placeholder; the fallback quoted-value pattern
could not span a line break; a one-character value was masked in every field of
every overlapping finding; a shape of an absurd length made the pattern fail to
compile; a value that is the head of a longer shape token was masked first and
left the rest of the token readable; a value a finding's region matched was kept
in that finding's own message; and a masked value quoted with spaces around it
was never read back from the finding's line.

Every value here is derived at import time or an ordinary word; none is a
credential.
"""

import hashlib
import string

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.secret_masking import (
    _mask_bandit_password_secret,
    _mask_secret_value,
    _propagates,
    mask_secret_values_in_tree,
    mask_secrets_in_results,
    secret_value_shape,
    shapes_of_secret_values,
)

pytestmark = pytest.mark.unit

NAME = "pass" + "word"
HARDCODED = "Possible hardcoded " + NAME + ": "


def _derived(label, length):
    alphabet = string.ascii_lowercase + string.digits
    digest = hashlib.sha256(label.encode()).digest()
    return "".join(alphabet[byte % len(alphabet)] for byte in digest)[:length]


def _value(label, length):
    """A derived value that holds a digit, so it is never letters alone."""
    return _derived(label, length - 1) + "9"


def _result(rule_id, line, message, uri="app.py", scanner="bandit", region=None):
    region = dict(region or {})
    region.setdefault("startLine", line)
    region.setdefault("endLine", line)
    return {
        "ruleId": rule_id,
        "level": "warning",
        "message": {"text": message},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}
        ],
        "properties": {"scanner_name": scanner, "tags": [scanner]},
    }


def _results(*results):
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "test"}}, "results": list(results)}],
        }
    )
    return model


def _message(model, position):
    return model.sarif.runs[0].results[position].message.root.text


class TestWordsWithPunctuationAroundThem:
    @pytest.mark.parametrize("value", [NAME + ":", "--access_token", "'" + NAME + "'"])
    def test_are_not_masked_everywhere(self, value):
        assert not _propagates(value)

    def test_a_value_with_punctuation_inside_still_is(self):
        """Control."""
        assert _propagates("p@ssw0rd!" + _derived("inside", 3))

    def test_bandits_label_in_another_finding_is_kept(self):
        other = _value("label-other", 10)
        model = _results(
            _result("B105", 5, HARDCODED + f"'{NAME}:'"),
            _result("B105", 9, HARDCODED + f"'{other}'"),
        )

        mask_secrets_in_results(model)

        assert _message(model, 1) == HARDCODED + f"'{_mask_secret_value(other)}'"


class TestAValueOfAsterisksAlone:
    def test_is_not_a_masked_form_and_propagates_nothing(self):
        assert not _propagates("*" * 8)
        assert shapes_of_secret_values(["*" * 8]) == []

    def test_markdown_emphasis_in_another_finding_is_kept(self):
        """``*config*`` is eight characters from ``*`` to ``*``, the token the
        shape of eight asterisks matched."""
        model = _results(
            _result("B105", 5, HARDCODED + "'********'"),
            _result("B404", 9, "see *config* and *output* first"),
        )

        mask_secrets_in_results(model)

        assert _message(model, 1) == "see *config* and *output* first"
        assert _message(model, 0) == HARDCODED + "'********'"


class TestATemplatePlaceholder:
    def test_a_dollar_value_of_mixed_case_and_digits_is_a_value(self):
        assert _propagates("$uperSecret99")

    @pytest.mark.parametrize("value", ["$DB_PASSWORD", "$db_password", "${NAME_1}"])
    def test_a_variable_reference_is_not(self, value):
        assert not _propagates(value)


class TestAQuotedValueThatHoldsALineBreak:
    def test_is_masked_when_the_message_goes_on_after_it(self):
        value = _derived("two-line", 4) + "\n" + _derived("two-line-2", 4)
        text = HARDCODED + f"'{value}' and more"

        masked = _mask_bandit_password_secret(text)

        assert value not in masked
        assert masked == HARDCODED + f"'{_mask_secret_value(value)}' and more"


class TestAOneCharacterValue:
    def test_is_not_masked_in_an_overlapping_finding(self):
        model = _results(
            _result("B105", 5, HARDCODED + "'-'"),
            _result("B404", 5, "a - b - c"),
        )

        mask_secrets_in_results(model)

        assert _message(model, 1) == "a - b - c"
        assert _message(model, 0) == HARDCODED + "'*'"


class TestAShapeOfAnAbsurdLength:
    def test_is_ignored_instead_of_failing_the_pattern(self):
        tree = {"text": "a token here"}
        shapes = [{"prefix": "ab", "suffix": "c", "length": 2**33}]

        mask_secret_values_in_tree(tree, [], shapes)

        assert tree == {"text": "a token here"}

    def test_a_shape_of_an_ordinary_length_still_masks(self):
        """Control."""
        value = _value("ordinary-length", 12)
        tree = {"text": "token " + value}

        mask_secret_values_in_tree(tree, [], [secret_value_shape(value)])

        assert tree["text"] == "token " + _mask_secret_value(value)


class TestAValueThatHeadsALongerToken:
    def test_the_longer_shape_token_is_masked_whole(self):
        head = "abc!xyz4"
        tail = "efgh5678"
        token = head + "$" + tail
        tree = {"text": token}

        mask_secret_values_in_tree(tree, [head], [secret_value_shape(token)])

        assert tree["text"] == _mask_secret_value(token)
        assert tail not in tree["text"]


class TestAValueAFindingsRegionMatched:
    def test_is_masked_in_the_findings_own_message(self):
        value = "hunter" + "2"
        line = "secret = " + f'"{value}"'
        model = _results(
            _result(
                "generic.secrets.security.detected-generic-secret",
                5,
                f'Hardcoded value "{value}" found in source',
                scanner="semgrep",
                region={
                    "startColumn": 1,
                    "endColumn": len(line) + 1,
                    "snippet": {"text": line + "\n"},
                },
            )
        )

        mask_secrets_in_results(model)

        assert value not in _message(model, 0)
        assert _message(model, 0).startswith("Hardcoded value ")

    def test_an_ordinary_word_the_region_matched_stays_in_the_message(self):
        """Control: the words of a label are what recognizes the finding."""
        line = NAME + ' = "x"'
        model = _results(
            _result(
                "generic.secrets.security.detected-generic-secret",
                5,
                "Hardcoded " + NAME + " found",
                scanner="semgrep",
                region={
                    "startColumn": 1,
                    "endColumn": len(NAME) + 1,
                    "snippet": {"text": line + "\n"},
                },
            )
        )

        mask_secrets_in_results(model)

        assert _message(model, 0) == "Hardcoded " + NAME + " found"


class TestAMaskedValueQuotedWithSpacesAroundIt:
    def test_is_read_back_from_the_findings_own_line(self):
        value = " " + _value("spaced", 10) + " "
        masked = _mask_secret_value(value)
        assert masked.strip() == "*" * len(masked.strip())
        model = _results(
            _result(
                "B105",
                5,
                HARDCODED + f"'{masked}'",
                region={"snippet": {"text": f'token = "{value}"\n'}},
            ),
            _result("B404", 9, "reuse:" + value + "here"),
        )

        mask_secrets_in_results(model)

        assert value.strip() not in _message(model, 1)
