# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A shape masks only tokens that could be the value it stands for.

A value's shape (its visible prefix and suffix and its length) is masked
wherever a token of that shape occurs, so that ``ash merge`` can mask a value
no shard holds any more. Every token of the shape was masked, so an eight
character secret starting with ``p`` and ending with ``d`` masked ``password``
and ``provided`` in every message, bandit's own label among them; and a
hard-coded password check's word-like value, masked in its own message on the
first pass, was read back as a masked form on the next pass and propagated as a
shape the same way.

A shape is of a value that propagates, which is never letters alone, so a token
that is letters alone, a placeholder or too repetitive is not that value and is
kept. The values here are derived at import time; none is a credential.
"""

import hashlib
import string

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.secret_masking import (
    _mask_secret_value,
    mask_secret_values_in_tree,
    mask_secrets_in_results,
    secret_value_shape,
)

pytestmark = pytest.mark.unit


def _derived(label, length):
    alphabet = string.ascii_lowercase + string.digits
    digest = hashlib.sha256(label.encode()).digest()
    return "".join(alphabet[byte % len(alphabet)] for byte in digest)[:length]


NAME = "pass" + "word"
HARDCODED = "Possible hardcoded " + NAME + ": "
#: Eight characters, first ``p``, last ``d``: the shape of ``password`` and
#: ``provided``, and a value that propagates: a literal digit, so it is never
#: letters alone whatever the derived part reads, and seven distinct characters,
#: an entropy well above the floor rather than on it.
SHAPED = "p" + _derived("shape-tokens-values", 5) + "9" + "d"
#: Another token of that shape that could be a value: the same characters.
OTHER_SHAPED = "p" + SHAPED[1:7][::-1] + "d"
NEIGHBOR_MESSAGE = "A default was provided for the call"


def _result(rule_id, line, message):
    return {
        "ruleId": rule_id,
        "level": "warning",
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


class TestWordsOfAShape:
    def test_ordinary_words_of_the_shape_are_kept(self):
        """The secret's own label and a neighbor's prose keep their words."""
        model = _results(
            _result("B105", 2, HARDCODED + "'" + SHAPED + "'"),
            _result("B404", 7, NEIGHBOR_MESSAGE),
        )

        mask_secrets_in_results(model)

        assert _message(model, 0) == HARDCODED + "'" + _mask_secret_value(SHAPED) + "'"
        assert _message(model, 1) == NEIGHBOR_MESSAGE

    def test_a_token_that_could_be_the_value_is_masked_in_a_neighbor(self):
        """The shape fires inside ``mask_secrets_in_results``, not only in the
        tree control below: a token of the shape that could be a value is masked
        in a neighbor's message and the prose around it keeps its words."""
        model = _results(
            _result("B105", 2, HARDCODED + "'" + SHAPED + "'"),
            _result("B404", 7, NEIGHBOR_MESSAGE + " " + OTHER_SHAPED),
        )

        mask_secrets_in_results(model)

        assert _message(model, 1) == (
            NEIGHBOR_MESSAGE + " " + _mask_secret_value(OTHER_SHAPED)
        )

    def test_a_word_like_value_masked_on_the_first_pass_masks_no_words_on_the_next(
        self,
    ):
        """On the second pass the message holds the masked form, which is read
        back as a value of that shape."""
        model = _results(
            _result("B105", 2, HARDCODED + "'" + NAME + "'"),
            _result("B404", 7, NEIGHBOR_MESSAGE),
        )
        mask_secrets_in_results(model)
        assert _message(model, 0) == HARDCODED + "'" + _mask_secret_value(NAME) + "'"

        mask_secrets_in_results(model)

        assert _message(model, 0) == HARDCODED + "'" + _mask_secret_value(NAME) + "'"
        assert _message(model, 1) == NEIGHBOR_MESSAGE

    def test_a_token_that_could_be_the_value_is_still_masked(self):
        """Control: what a recorded shape is for."""
        tree = {"text": f"run({OTHER_SHAPED}) was provided"}

        mask_secret_values_in_tree(tree, values=(), shapes=[secret_value_shape(SHAPED)])

        assert tree["text"] == f"run({_mask_secret_value(OTHER_SHAPED)}) was provided"
