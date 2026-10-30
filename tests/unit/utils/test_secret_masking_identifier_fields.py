# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Masking leaves a result's identifiers alone, and reads a rule named by reference.

A shape of the right length matched the GUID fields the skip list did not name
(``baselineGuid``, ``runGuid``, ``firstDetectionRunGuid``) and the fingerprints
that are a finding's identity, so a masked token stood where the schema wants a
GUID and the finding's identity changed. A result that names its rule through
``result.rule.id`` instead of ``ruleId`` was never matched to a secret rule.

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


#: A GUID-shaped text, and a value of the same length that shares its visible
#: prefix and suffix, so the value's shape matches the GUID.
GUID = _guid("identifier-fields-guid")
GUID_SHAPED_VALUE = GUID[:2] + _derived("guid-shaped-body", 33) + GUID[-1]


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
    def test_identifier_keys_are_left_alone(self):
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

        assert tree["runGuid"] == GUID
        assert tree["baselineGuid"] == GUID
        assert tree["provenance"]["firstDetectionRunGuid"] == GUID
        assert tree["fingerprints"]["primaryLocationLineHash"] == VALUE
        assert tree["partialFingerprints"]["primaryLocationLineHash"] == VALUE
        # Control: the same tokens are masked where they are text.
        assert VALUE not in tree["message"]["text"]
        assert GUID not in tree["message"]["text"]


class TestFingerprintsAndGuidsOfAModel:
    def test_fingerprints_and_guids_are_left_alone(self):
        neighbor = _result(
            "B404",
            9,
            "import " + VALUE,
            fingerprints={"primaryLocationLineHash": VALUE},
            partialFingerprints={"primaryLocationLineHash": VALUE},
            provenance={"firstDetectionRunGuid": GUID, "lastDetectionRunGuid": GUID},
        )
        model = _results(
            _result("B105", 5, HARDCODED + f"'{VALUE}'"),
            _result("B105", 6, HARDCODED + f"'{GUID_SHAPED_VALUE}'"),
            neighbor,
            run_extra={"baselineGuid": GUID},
        )

        mask_secrets_in_results(model)

        run = model.sarif.runs[0]
        result = run.results[2]
        assert run.baselineGuid == GUID
        assert result.fingerprints == {"primaryLocationLineHash": VALUE}
        assert result.partialFingerprints == {"primaryLocationLineHash": VALUE}
        assert result.provenance.firstDetectionRunGuid == GUID
        assert result.provenance.lastDetectionRunGuid == GUID
        # Control: the value is masked in the neighbor's message.
        assert result.message.root.text == "import " + _mask_secret_value(VALUE)

    def test_the_masked_results_validate_when_loaded_back(self):
        model = _results(
            _result("B105", 6, HARDCODED + f"'{GUID_SHAPED_VALUE}'"),
            _result("B404", 9, "import", provenance={"firstDetectionRunGuid": GUID}),
            run_extra={"baselineGuid": GUID},
        )

        mask_secrets_in_results(model)
        loaded = AshAggregatedResults.model_validate_json(model.model_dump_json())

        assert loaded.sarif.runs[0].baselineGuid == GUID


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
