# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Masking treats the fingerprint and GUID fields as text, and reads a rule named
by reference.

A fingerprint or GUID field is not on the skip list: a value a scanner matched
can sit in a hash-shaped field, and masking is the side that fails closed. A
result that names its rule through ``result.rule.id`` instead of ``ruleId`` was
never matched to a secret rule.

Every value here is derived at import time; none is a credential.
"""

import hashlib
import string

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.secret_masking import (
    MASKED_LINE,
    SecretValueShape,
    _mask_secret_value,
    is_secret_finding,
    mask_secret_values_in_tree,
    mask_secrets_in_results,
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


VALUE = _value("identifier-fields", 12)


def _guid(label):
    """A GUID-shaped text derived at import time, in the version-4 form the
    schema's pattern accepts."""
    digits = hashlib.sha256(label.encode()).hexdigest()
    return "-".join(
        [
            digits[:8],
            digits[8:12],
            "4" + digits[13:16],
            "a" + digits[17:20],
            digits[20:32],
        ]
    )


#: A GUID-shaped text.
GUID = _guid("identifier-fields-guid")


def _result(rule_id, line, message, uri="app.py", scanner="bandit", **extra):
    result = {
        "ruleId": rule_id,
        "level": "warning",
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {
                        "startLine": line,
                        "endLine": line,
                        "snippet": {"text": "x = 1\n"},
                    },
                }
            }
        ],
        "properties": {"scanner_name": scanner, "tags": [scanner]},
    }
    result.update(extra)
    return result


def _results(*results, run_extra=None):
    run = {"tool": {"driver": {"name": "test"}}, "results": list(results)}
    run.update(run_extra or {})
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate({"version": "2.1.0", "runs": [run]})
    return model


class TestFingerprintsAndGuidsOfAPlainJsonReport:
    def test_identifier_keys_are_masked_like_any_text(self):
        shape = SecretValueShape(prefix=GUID[:2], suffix=GUID[-1], length=36)
        tree = {
            "runGuid": GUID,
            "baselineGuid": GUID,
            "provenance": {"firstDetectionRunGuid": GUID},
            "fingerprints": {"primaryLocationLineHash": VALUE},
            "partialFingerprints": {"primaryLocationLineHash": VALUE},
            "message": {"text": "uses " + VALUE + " and " + GUID},
        }

        mask_secret_values_in_tree(tree, [VALUE], [shape])

        assert VALUE not in tree["fingerprints"]["primaryLocationLineHash"]
        assert VALUE not in tree["partialFingerprints"]["primaryLocationLineHash"]
        assert tree["runGuid"] != GUID
        assert tree["baselineGuid"] != GUID
        assert tree["provenance"]["firstDetectionRunGuid"] != GUID
        # Control: the same tokens are masked where they are message text.
        assert VALUE not in tree["message"]["text"]
        assert GUID not in tree["message"]["text"]


class TestFingerprintsOfAModel:
    def test_a_fingerprint_holding_a_value_is_masked(self):
        neighbor = _result(
            "B404",
            9,
            "import " + VALUE,
            fingerprints={"primaryLocationLineHash": VALUE},
            partialFingerprints={"primaryLocationLineHash": VALUE},
        )
        model = _results(_result("B105", 5, HARDCODED + f"'{VALUE}'"), neighbor)

        mask_secrets_in_results(model)

        masked = _mask_secret_value(VALUE)
        result = model.sarif.runs[0].results[1]
        assert result.fingerprints == {"primaryLocationLineHash": masked}
        assert result.partialFingerprints == {"primaryLocationLineHash": masked}
        # Control: the value is masked in the neighbor's message the same way.
        assert result.message.root.text == "import " + masked

    def test_a_fingerprint_holding_nothing_secret_is_kept(self):
        """Control: a hash that is no exposed value is not touched."""
        other = _value("identifier-fields-other", 40)
        neighbor = _result(
            "B404",
            9,
            "import",
            fingerprints={"primaryLocationLineHash": other},
        )
        model = _results(_result("B105", 5, HARDCODED + f"'{VALUE}'"), neighbor)

        mask_secrets_in_results(model)

        result = model.sarif.runs[0].results[1]
        assert result.fingerprints == {"primaryLocationLineHash": other}


class TestARuleNamedByReference:
    def _finding(self):
        result = _result(
            None,
            5,
            "Base64 High Entropy String",
            scanner="checkov",
            rule={"id": "CKV_SECRET_6"},
        )
        return result

    def test_the_rule_reference_marks_a_secret_finding(self):
        model = _results(self._finding())

        assert is_secret_finding(model.sarif.runs[0].results[0])

    def test_its_snippet_is_masked_whole(self):
        model = _results(self._finding())

        mask_secrets_in_results(model)

        region = (
            model.sarif.runs[0].results[0].locations[0].physicalLocation.root.region
        )
        assert region.snippet.text == MASKED_LINE + "\n"

    def test_a_rule_reference_that_is_no_secret_rule_is_left_alone(self):
        """Control."""
        model = _results(
            _result(None, 5, "import", scanner="checkov", rule={"id": "CKV_AWS_1"})
        )

        assert not is_secret_finding(model.sarif.runs[0].results[0])
