# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The AWS reporters' retry options are bounded, whoever sets them.

``max_retries``, ``base_delay`` and ``max_delay`` decide how long a reporter keeps
calling an AWS API that refuses it. Each reporter's options model caps them:
``max_retries`` at 10, ``max_delay`` at 60 seconds, and ``base_delay`` at
``max_delay`` (or 60 seconds for a model without ``max_delay``). A value over a
cap is a validation error naming the field and the cap. The cases are derived
from the reporters' own models, so a reporter that gains one of these options is
covered.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

import pytest
from pydantic import BaseModel, ValidationError

from automated_security_helper.plugin_modules.ash_aws_plugins import ASH_REPORTERS
from automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils import (
    MAX_RETRY_DELAY_SECONDS,
    MAX_RETRIES,
)

RETRY_OPTIONS = ("max_retries", "base_delay", "max_delay")


def _options_models() -> List[Tuple[str, type[BaseModel]]]:
    found = []
    for reporter in ASH_REPORTERS:
        config_model = reporter.model_fields["config"].annotation.__args__[0]
        options_model = config_model.model_fields["options"].annotation
        found.append((reporter.__name__, options_model))
    return found


#: Each option, with the value at its cap and the value one over it.
_CAPS: Dict[str, Tuple[Any, Any]] = {
    "max_retries": (MAX_RETRIES, MAX_RETRIES + 1),
    "max_delay": (MAX_RETRY_DELAY_SECONDS, MAX_RETRY_DELAY_SECONDS + 1),
}

_CASES = [
    (reporter, model, name)
    for name in _CAPS
    for reporter, model in _options_models()
    if name in model.model_fields
]


def test_the_caps_are_the_documented_ones():
    assert (MAX_RETRIES, MAX_RETRY_DELAY_SECONDS) == (10, 60)


def test_every_reporter_with_retries_is_checked():
    """Three of the four reporters retry; a fourth that gains the options is covered."""
    retrying = {
        r for r, m in _options_models() if set(RETRY_OPTIONS) & set(m.model_fields)
    }
    assert {
        "S3Reporter",
        "CloudWatchLogsReporter",
        "BedrockSummaryReporter",
    } <= retrying


@pytest.mark.parametrize(
    "reporter,model,name", _CASES, ids=[f"{r}.{n}" for r, _, n in _CASES]
)
def test_a_value_at_the_cap_is_accepted(reporter, model, name):
    at_cap, _ = _CAPS[name]
    assert getattr(model(**{name: at_cap}), name) == at_cap


@pytest.mark.parametrize(
    "reporter,model,name", _CASES, ids=[f"{r}.{n}" for r, _, n in _CASES]
)
def test_a_value_over_the_cap_is_refused_naming_the_field_and_the_cap(
    reporter, model, name
):
    at_cap, over = _CAPS[name]
    with pytest.raises(ValidationError) as refused:
        model(**{name: over})
    message = str(refused.value)
    assert name in message, message
    assert str(at_cap) in message, message


_DELAY_CASES = [(r, m) for r, m in _options_models() if "base_delay" in m.model_fields]


@pytest.mark.parametrize(
    "reporter,model", _DELAY_CASES, ids=[r for r, _ in _DELAY_CASES]
)
def test_base_delay_may_equal_max_delay_but_not_exceed_it(reporter, model):
    assert model(base_delay=5.0, max_delay=5.0).base_delay == 5.0
    with pytest.raises(ValidationError) as refused:
        model(base_delay=6.0, max_delay=5.0)
    message = str(refused.value)
    assert "base_delay" in message and "max_delay" in message, message


@pytest.mark.parametrize(
    "reporter,model", _DELAY_CASES, ids=[r for r, _ in _DELAY_CASES]
)
def test_base_delay_is_capped_with_the_default_max_delay(reporter, model):
    with pytest.raises(ValidationError) as refused:
        model(base_delay=MAX_RETRY_DELAY_SECONDS + 1)
    assert "base_delay" in str(refused.value)


@pytest.mark.parametrize(
    "reporter,model", _options_models(), ids=[r for r, _ in _options_models()]
)
def test_the_defaults_are_within_the_caps(reporter, model):
    """A reporter built with no options validates."""
    built = model()
    for name in RETRY_OPTIONS:
        if name in model.model_fields:
            value = getattr(built, name)
            # An option left unset may be None: the Bedrock reporter's
            # max_retries, whose default applies where it is read.
            assert value is None or value <= (
                MAX_RETRIES if name == "max_retries" else MAX_RETRY_DELAY_SECONDS
            )
