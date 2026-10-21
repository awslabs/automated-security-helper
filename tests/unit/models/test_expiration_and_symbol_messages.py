# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One message for a refused expiration or symbol, from the models.

A scan, `ash config validate` and `ash config lint` all print the model's
message, so these are the words an operator reads from each; pydantic's string
check must not refuse an unquoted date before the entry's own validator sees it,
and lint prints no messages of its own for either field.

A date or a number can only be the file's own text, never a value read from
the environment, so a date is shown and a number is named by its type. A string
that is not a date, and a symbol that is not a qualified name, get the rule
alone: a string may have been read from the environment.
"""

from __future__ import annotations

from datetime import date, datetime

import pytest
from pydantic import ValidationError

from automated_security_helper.config.ash_config import (
    AshConfig,
    ContentDbStalenessOverride,
)
from automated_security_helper.config.config_validator import ConfigValidator
from automated_security_helper.models.core import AshSuppression, IgnorePathWithReason

ENTRY = {"path": "vendor/**", "reason": "r"}
SUPPRESSION = {"path": "app.py", "rule_id": "B101", "reason": "r"}


def _message(model, data) -> str:
    with pytest.raises(ValidationError) as excinfo:
        model.model_validate(data, strict=True)
    (error,) = excinfo.value.errors()
    return error["msg"]


def _override(**fields):
    return {"database": "grype-db", "policy": "warn", "reason": "r", **fields}


EXPIRING = [
    pytest.param(IgnorePathWithReason, ENTRY, id="an ignore path"),
    pytest.param(AshSuppression, SUPPRESSION, id="a suppression"),
    pytest.param(ContentDbStalenessOverride, _override(), id="a content db override"),
]


@pytest.mark.parametrize("model, data", EXPIRING)
@pytest.mark.parametrize(
    "value", [date(2099, 1, 31), datetime(2099, 1, 31, 10, 0)], ids=["date", "datetime"]
)
def test_an_unquoted_date(model, data, value):
    message = _message(model, {**data, "expiration": value})
    assert "expiration must be a quoted YYYY-MM-DD string" in message, message
    assert value.isoformat() in message, message
    assert "put it in quotes" in message, message


@pytest.mark.parametrize("model, data", EXPIRING)
@pytest.mark.parametrize(
    "value, named",
    [(20990131, "a number"), (["2099-01-31"], "a list"), (True, "true or false")],
)
def test_a_value_that_is_not_text_is_named_by_its_type(model, data, value, named):
    message = _message(model, {**data, "expiration": value})
    assert message.endswith(
        f"expiration must be a quoted YYYY-MM-DD string, not {named}"
    ), message
    assert "20990131" not in message


@pytest.mark.parametrize("model, data", EXPIRING)
def test_a_string_that_is_not_a_date(model, data):
    message = _message(model, {**data, "expiration": "31/01/2099"})
    assert message == "Value error, Invalid expiration date format. Use YYYY-MM-DD", (
        message
    )


def test_the_printed_message_states_the_rule_without_the_string():
    with pytest.raises(ValidationError) as excinfo:
        AshConfig.model_validate(
            {
                "project_name": "p",
                "global_settings": {
                    "suppressions": [{**SUPPRESSION, "expiration": "31/01/2099"}]
                },
            },
            strict=True,
        )
    (error,) = excinfo.value.errors()
    printed = ConfigValidator.format_model_error(error)
    assert "31/01/2099" not in printed, printed
    assert "Invalid expiration date format. Use YYYY-MM-DD" in printed, printed


@pytest.mark.parametrize("value", ["handler(request)", "my func", 5])
def test_a_symbol_that_is_not_a_qualified_name(value):
    """Text or not, the same rule, and not the value."""
    message = _message(AshSuppression, {**SUPPRESSION, "symbol": value})
    assert message == (
        "Value error, symbol must be a dotted qualified name such as "
        "'MyClass.my_method' (identifiers joined by '.', no spaces, "
        "wildcards or call syntax)"
    ), message


@pytest.mark.parametrize("value", ["2099-01-31", None])
def test_a_quoted_date_and_no_date_load(value):
    assert IgnorePathWithReason(**ENTRY, expiration=value).expiration == value
