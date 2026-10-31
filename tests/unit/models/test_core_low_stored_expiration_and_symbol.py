# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two edge values of an entry in models/core.py.

* A results file read under ``TOLERATE_STORED_CONFIG`` keeps a malformed
  ``expiration`` string and records it as unreadable, but refused an
  ``expiration`` that was not text (a number, a list), so one such stored entry
  failed the load of the whole file. It is now kept as its text and recorded the
  same way. A config file still refuses it.
* A ``symbol`` written as a YAML block scalar ends in a newline and matches no
  definition, so an entry must refuse it. ``is_valid_symbol`` already reads the
  whole text with ``fullmatch``, so these cases pass without any change in this
  module; they pin that behavior and are not red before it.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from automated_security_helper.models.core import (
    SYMBOL_RULE,
    UNREADABLE_EXPIRATION_NOTE,
    AshSuppression,
    IgnorePathWithReason,
)
from automated_security_helper.utils.unknown_keys import TOLERATE_STORED_CONFIG

pytestmark = pytest.mark.unit

IGNORE_PATH = {"path": "vendor/**", "reason": "r"}
SUPPRESSION = {"path": "app.py", "rule_id": "B101", "reason": "r"}

ENTRIES = [
    pytest.param(IgnorePathWithReason, IGNORE_PATH, id="an ignore path"),
    pytest.param(AshSuppression, SUPPRESSION, id="a suppression"),
]


@pytest.mark.parametrize("model, data", ENTRIES)
@pytest.mark.parametrize(
    "value",
    [209912, True, ["2099-01-31"], {"on": "2099-01-31"}],
    ids=["number", "boolean", "list", "mapping"],
)
def test_a_stored_expiration_that_is_not_text_is_kept_and_noted(model, data, value):
    notes: list[str] = []

    entry = model.model_validate(
        {**data, "expiration": value}, context={TOLERATE_STORED_CONFIG: notes}
    )

    assert notes == [UNREADABLE_EXPIRATION_NOTE]
    assert isinstance(entry.expiration, str)
    assert entry.is_expired is True


@pytest.mark.parametrize("model, data", ENTRIES)
def test_a_config_file_still_refuses_an_expiration_that_is_not_text(model, data):
    with pytest.raises(ValidationError) as excinfo:
        model.model_validate({**data, "expiration": 209912}, strict=True)

    assert "expiration must be a quoted YYYY-MM-DD string" in str(excinfo.value)


@pytest.mark.parametrize("model, data", ENTRIES)
def test_a_stored_text_expiration_is_unchanged_by_the_tolerance(model, data):
    notes: list[str] = []

    entry = model.model_validate(
        {**data, "expiration": "2099-01-31"}, context={TOLERATE_STORED_CONFIG: notes}
    )

    assert notes == []
    assert entry.expiration == "2099-01-31"


@pytest.mark.parametrize("symbol", ["Outer.method\n", "handler\n"])
def test_a_symbol_with_a_trailing_newline_is_refused(symbol):
    with pytest.raises(ValidationError) as excinfo:
        AshSuppression(**SUPPRESSION, symbol=symbol)

    assert SYMBOL_RULE in str(excinfo.value)


@pytest.mark.parametrize("symbol", ["Outer.method", "handler", "#private", "a.$b"])
def test_a_well_formed_symbol_still_loads(symbol):
    assert AshSuppression(**SUPPRESSION, symbol=symbol).symbol == symbol
