# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Masking leaves the enum-valued SARIF fields alone.

``Result.level``, ``Result.kind`` and ``Suppression.kind`` hold one of a fixed set
of strings. A secret value equal to one of them (a hard-coded password check
quotes ordinary words), or a value whose masked shape matched one, was masked in
every overlapping result's enum field, so the result's severity read as a masked
token and the results file no longer validated on the next load.

Every value here is an enum string of the SARIF schema or a placeholder derived
at import time; none is a credential.
"""

import hashlib
import string

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import (
    ColumnKind,
    Kind,
    Kind1,
    Level,
    SarifReport,
)
from automated_security_helper.utils.secret_masking import (
    SecretValueShape,
    _mask_secret_value,
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


def _result(rule_id, line, message, level="warning", kind=None, suppressions=None):
    result = {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "app.py"},
                    "region": {"startLine": line, "endLine": line},
                }
            }
        ],
        "properties": {"scanner_name": "bandit", "tags": ["bandit"]},
    }
    if kind is not None:
        result["kind"] = kind
    if suppressions is not None:
        result["suppressions"] = suppressions
    return result


def _results(*results):
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "test"}}, "results": list(results)}],
        }
    )
    return model


class TestEnumFieldsOfOverlappingResults:
    def test_a_value_equal_to_a_level_leaves_the_level_alone(self):
        """The hard-coded value ``warning`` is the level of the result on its line."""
        model = _results(
            _result("B105", 5, HARDCODED + "'warning'", level="error"),
            _result("B404", 5, "import", level="warning", kind="fail"),
        )

        mask_secrets_in_results(model)

        neighbor = model.sarif.runs[0].results[1]
        assert neighbor.level == Level.warning
        assert neighbor.kind == Kind.fail
        assert model.sarif.runs[0].results[0].level == Level.error

    def test_a_value_equal_to_a_suppression_kind_leaves_the_kind_alone(self):
        model = _results(
            _result("B105", 5, HARDCODED + "'inSource'"),
            _result(
                "B404",
                5,
                "import",
                suppressions=[{"kind": "inSource", "justification": "reviewed"}],
            ),
        )

        mask_secrets_in_results(model)

        suppression = model.sarif.runs[0].results[1].suppressions[0]
        assert suppression.kind == Kind1.inSource

    def test_the_masked_results_validate_when_loaded_back(self):
        model = _results(
            _result("B105", 5, HARDCODED + "'warning'"),
            _result("B404", 5, "import", level="warning", kind="fail"),
        )

        mask_secrets_in_results(model)
        loaded = AshAggregatedResults.model_validate_json(model.model_dump_json())

        assert loaded.sarif.runs[0].results[1].level == Level.warning
        assert loaded.sarif.runs[0].results[1].kind == Kind.fail

    def test_the_secret_findings_own_values_are_still_masked(self):
        """Control: only the enum fields are exempt."""
        value = _derived("enum-control-value", 12)
        model = _results(
            _result("B105", 5, HARDCODED + f"'{value}'"),
            _result("B404", 5, f"uses {value}", level="warning"),
        )

        mask_secrets_in_results(model)

        assert value not in model.sarif.runs[0].results[0].message.root.text
        assert value not in model.sarif.runs[0].results[1].message.root.text
        assert model.sarif.runs[0].results[1].level == Level.warning


class TestFreeTextFieldsNamedLikeAnEnum:
    def test_a_logical_locations_kind_is_still_masked(self):
        """``LogicalLocation.kind`` is free text that shares its name with
        ``Result.kind``; only the enum member is left alone."""
        value = _derived("free-text-kind-value", 12)
        neighbor = _result("B404", 5, "import", level="warning", kind="fail")
        neighbor["locations"][0]["logicalLocations"] = [
            {"name": "handler", "kind": f"function {value}"}
        ]
        model = _results(_result("B105", 5, HARDCODED + f"'{value}'"), neighbor)

        mask_secrets_in_results(model)

        result = model.sarif.runs[0].results[1]
        logical = result.locations[0].logicalLocations[0]
        assert logical.kind == "function " + _mask_secret_value(value)
        assert result.kind == Kind.fail


class TestEnumFieldsOfAPlainJsonReport:
    def test_a_shape_leaves_the_enum_keys_of_a_json_result_alone(self):
        """A report reduced to plain data (a workspace's spooled runs) has no enum
        members, so the fields are known by name."""
        shape = SecretValueShape(prefix="i", suffix="e", length=8)
        tree = {
            "results": [
                {
                    "kind": "inSource",
                    "level": "warning",
                    "suppressions": [{"kind": "inSource"}],
                    "message": {
                        "text": "token " + "i" + _derived("json-shape", 6) + "e"
                    },
                }
            ]
        }

        mask_secret_values_in_tree(tree, values=(), shapes=[shape])

        result = tree["results"][0]
        assert result["kind"] == "inSource"
        assert result["level"] == "warning"
        assert result["suppressions"][0]["kind"] == "inSource"
        assert "i" + _derived("json-shape", 6) + "e" not in result["message"]["text"]

    def test_a_value_equal_to_the_column_kind_leaves_it_alone(self):
        """The enum string a value can equal. ``utf16CodeUnits`` holds digits, so
        it is secret-shaped and propagates; the other enum words are letters
        alone, which no value or shape masks, so the by-name exemption is
        observable on this one. Without it the run's ``columnKind`` reads as a
        masked token; the same word in a message is masked."""
        word = ColumnKind.utf16CodeUnits.value
        tree = {
            "runs": [
                {
                    "columnKind": word,
                    "results": [{"message": {"text": "column kind " + word}}],
                }
            ]
        }

        mask_secret_values_in_tree(tree, values=[word])

        run = tree["runs"][0]
        assert run["columnKind"] == word
        assert run["results"][0]["message"]["text"] == (
            "column kind " + _mask_secret_value(word)
        )

    def test_a_thread_flow_locations_state_is_still_masked(self):
        """``state`` is an enum only on a suppression; a thread flow location's
        ``state`` is a free-text map that can carry the value a finding exposed."""
        value = _derived("json-state-secret", 24)
        tree = {
            "results": [
                {
                    "level": "warning",
                    "codeFlows": [
                        {"threadFlows": [{"locations": [{"state": {"token": value}}]}]}
                    ],
                    "suppressions": [{"kind": "inSource", "state": "accepted"}],
                }
            ]
        }

        mask_secret_values_in_tree(tree, values=[value])

        result = tree["results"][0]
        location = result["codeFlows"][0]["threadFlows"][0]["locations"][0]
        assert location["state"]["token"] == _mask_secret_value(value)
        assert result["suppressions"][0]["state"] == "accepted"
        assert result["level"] == "warning"

    def test_a_free_text_kind_is_still_masked(self):
        """``kind`` is an enum on a result and a suppression only; a logical
        location's or an address's ``kind`` is free text that can carry the value
        a finding exposed, and every ``kind`` was skipped whatever its parent."""
        value = _derived("json-kind-secret", 24)
        tree = {
            "results": [
                {
                    "kind": "fail",
                    "suppressions": [{"kind": "inSource"}],
                    "locations": [
                        {
                            "logicalLocations": [{"kind": "function " + value}],
                            "physicalLocation": {
                                "address": {"kind": "section " + value}
                            },
                        }
                    ],
                }
            ]
        }

        mask_secret_values_in_tree(tree, values=[value])

        result = tree["results"][0]
        location = result["locations"][0]
        masked = _mask_secret_value(value)
        assert location["logicalLocations"][0]["kind"] == "function " + masked
        assert location["physicalLocation"]["address"]["kind"] == "section " + masked
        assert result["kind"] == "fail"
        assert result["suppressions"][0]["kind"] == "inSource"
