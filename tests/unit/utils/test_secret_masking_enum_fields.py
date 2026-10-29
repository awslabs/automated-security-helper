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
    Kind,
    Kind1,
    Level,
    SarifReport,
)
from automated_security_helper.utils.secret_masking import (
    SecretValueShape,
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
        assert neighbor.level is Level.warning
        assert neighbor.kind is Kind.fail
        assert model.sarif.runs[0].results[0].level is Level.error

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
        assert suppression.kind is Kind1.inSource

    def test_the_masked_results_validate_when_loaded_back(self):
        model = _results(
            _result("B105", 5, HARDCODED + "'warning'"),
            _result("B404", 5, "import", level="warning", kind="fail"),
        )

        mask_secrets_in_results(model)
        loaded = AshAggregatedResults.model_validate_json(model.model_dump_json())

        assert loaded.sarif.runs[0].results[1].level is Level.warning
        assert loaded.sarif.runs[0].results[1].kind is Kind.fail

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
        assert model.sarif.runs[0].results[1].level is Level.warning


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
