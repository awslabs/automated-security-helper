# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A masked report still validates: a field that declares a pattern keeps matching it.

The SARIF models declare a pattern on every GUID field (and on a few others) and do
not validate on assignment, so a masked GUID was written without complaint and the
report was then refused when it was read again (``ash merge``, the findings
browser). The mask removes the exposed value; a field that matched its pattern takes
a fixed synthetic value that matches it too.

Every value here is derived at import time; none is a credential.
"""

import hashlib
import inspect
import json
import re
import string

import pytest
from pydantic import BaseModel

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas import sarif_schema_model
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.secret_masking import (
    _GUID_KEYS,
    _GUID_PATTERN,
    _SKIPPED_FIELDS,
    _SYNTHETIC_GUID,
    _keep_the_pattern,
    mask_secret_values_in_tree,
    mask_secrets_in_results,
    secret_value_shape,
)

pytestmark = pytest.mark.unit

NAME = "pass" + "word"
HARDCODED = "Possible hardcoded " + NAME + ": "


def _derived(label, length):
    alphabet = string.ascii_lowercase + string.digits
    digest = hashlib.sha256(label.encode()).digest()
    return "".join(alphabet[byte % len(alphabet)] for byte in digest)[:length]


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


VALUE = _derived("patterned-fields", 11) + "9"
GUID = _guid("patterned-fields-guid")
OTHER_GUID = _guid("patterned-fields-other-guid")
#: A value of the same length as a GUID that shares its visible prefix and suffix,
#: so its shape matches the GUID.
GUID_SHAPED_VALUE = GUID[:2] + _derived("patterned-shaped-body", 33) + GUID[-1]


def _result(rule_id, line, message, **extra):
    result = {
        "ruleId": rule_id,
        "level": "warning",
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "app.py"},
                    "region": {
                        "startLine": line,
                        "endLine": line,
                        "snippet": {"text": "x = 1\n"},
                    },
                }
            }
        ],
        "properties": {"scanner_name": "bandit", "tags": ["bandit"]},
    }
    result.update(extra)
    return result


def _results(*results, run_extra=None):
    run = {"tool": {"driver": {"name": "test"}}, "results": list(results)}
    run.update(run_extra or {})
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate({"version": "2.1.0", "runs": [run]})
    return model


def _declared_patterns():
    """(model, field name, pattern) for every string field the SARIF models give a
    pattern, read off the declarations."""
    found = []
    for _, model in inspect.getmembers(sarif_schema_model, inspect.isclass):
        if not issubclass(model, BaseModel):
            continue
        for name, field in model.model_fields.items():
            for item in field.metadata:
                pattern = getattr(item, "pattern", None)
                if isinstance(pattern, str):
                    found.append((model, name, pattern))
    return found


class TestAMaskedReportValidatesAgain:
    def _masked(self):
        model = _results(
            _result("B105", 5, HARDCODED + f"'{GUID}'"),
            _result("B105", 6, HARDCODED + f"'{GUID_SHAPED_VALUE}'"),
            _result(
                "B404",
                9,
                "import",
                provenance={
                    "firstDetectionRunGuid": GUID,
                    "lastDetectionRunGuid": GUID,
                },
            ),
            run_extra={"baselineGuid": GUID},
        )
        mask_secrets_in_results(model)
        return model

    def test_the_report_passes_model_validate(self):
        model = self._masked()

        dumped = model.sarif.model_dump_json(by_alias=True)

        SarifReport.model_validate(json.loads(dumped))
        AshAggregatedResults.model_validate_json(model.model_dump_json())

    def test_a_guid_holding_the_value_takes_the_synthetic_guid(self):
        model = self._masked()

        run = model.sarif.runs[0]
        provenance = run.results[2].provenance
        assert run.baselineGuid == _SYNTHETIC_GUID
        assert provenance.firstDetectionRunGuid == _SYNTHETIC_GUID
        assert provenance.lastDetectionRunGuid == _SYNTHETIC_GUID
        assert GUID not in model.sarif.model_dump_json(by_alias=True)

    def test_a_guid_that_holds_nothing_exposed_is_kept(self):
        """Control: only a masked field is replaced."""
        model = _results(
            _result("B105", 5, HARDCODED + f"'{VALUE}'"),
            _result(
                "B404", 9, "import", provenance={"firstDetectionRunGuid": OTHER_GUID}
            ),
            run_extra={"baselineGuid": OTHER_GUID},
        )

        mask_secrets_in_results(model)

        run = model.sarif.runs[0]
        assert run.baselineGuid == OTHER_GUID
        assert run.results[1].provenance.firstDetectionRunGuid == OTHER_GUID


class TestAMaskedPlainJsonReport:
    def test_the_guid_keys_take_a_value_the_pattern_accepts(self):
        tree = {
            "runGuid": GUID,
            "baselineGuid": GUID,
            "provenance": {
                "firstDetectionRunGuid": GUID,
                "lastDetectionRunGuid": GUID,
            },
            "deprecatedGuids": [GUID],
            "message": {"text": "uses " + GUID},
        }

        mask_secret_values_in_tree(tree, [GUID], [secret_value_shape(GUID)])

        values = [
            tree["runGuid"],
            tree["baselineGuid"],
            tree["provenance"]["firstDetectionRunGuid"],
            tree["provenance"]["lastDetectionRunGuid"],
            tree["deprecatedGuids"][0],
        ]
        for value in values:
            assert value != GUID
            assert re.search(_GUID_PATTERN, value)
        # Control: the same token is masked, as text, where no pattern binds it.
        assert GUID not in tree["message"]["text"]

    def test_a_guid_key_that_holds_nothing_exposed_is_kept(self):
        """Control."""
        tree = {"runGuid": OTHER_GUID, "deprecatedGuids": [OTHER_GUID]}

        mask_secret_values_in_tree(tree, [GUID], [secret_value_shape(GUID)])

        assert tree == {"runGuid": OTHER_GUID, "deprecatedGuids": [OTHER_GUID]}


class TestThePatternsTheModelsDeclare:
    #: One text that matches each of the four distinct patterns, in the order the
    #: first match is taken.
    EXAMPLES = (GUID, "1.2.3.4", "fr", "text/plain")

    def test_the_guid_pattern_is_the_models(self):
        patterns = {pattern for _, _, pattern in _declared_patterns()}

        assert _GUID_PATTERN in patterns

    def test_there_are_four_distinct_patterns(self):
        """If the models gain a fifth, a synthetic value has to be added for it."""
        patterns = {pattern for _, _, pattern in _declared_patterns()}

        assert len(patterns) == 4

    def test_each_pattern_has_a_synthetic_value_that_hides_the_original(self):
        for pattern in {pattern for _, _, pattern in _declared_patterns()}:
            original = next(
                example for example in self.EXAMPLES if re.search(pattern, example)
            )

            replaced = _keep_the_pattern(pattern, original, "*" * len(original))

            assert re.search(pattern, replaced), pattern
            assert replaced != original, pattern

    def test_a_masked_text_that_still_matches_is_kept(self):
        """Control."""
        assert _keep_the_pattern(r"^x+$", "xxxx", "xx") == "xx"

    def test_a_field_that_never_matched_is_left_as_masked(self):
        """Control: an invalid original is not repaired."""
        assert _keep_the_pattern(_GUID_PATTERN, "not a guid", "******") == "******"


class TestEveryGuidFieldIsCovered:
    def test_the_plain_json_keys_are_the_models_guid_fields_that_are_not_skipped(self):
        names = set()
        for _, name, pattern in _declared_patterns():
            if pattern == _GUID_PATTERN:
                # DeprecatedGuid is a root model; its list is ``deprecatedGuids``.
                names.add("deprecatedGuids" if name == "root" else name)

        assert names - set(_SKIPPED_FIELDS) == set(_GUID_KEYS)
