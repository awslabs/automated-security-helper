# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An Enum that overrides ``_missing_`` keeps env-resolved text only when the
text equals a member value.

Enum lookup calls ``_missing_`` only for text that matches no member value.
Text that equals a member value exactly is found first, so the member prints
as that text and the redaction needle matches it: it takes the downcast, at a
scalar field and inside a container. Any other text reaches the hook, which
may re-spell it (a case-folding lookup turns "high" into HIGH), so it is
refused. A ``_missing_`` that is not a classmethod counts as an override.
"""

from __future__ import annotations

import enum
from typing import List, Optional

import pytest

from automated_security_helper.utils.redacted_model import (
    RedactedSection,
    env_resolved_scalar,
)

VARIABLE = "ASH_MISSING_HOOK_CANARY"


class _FoldingSeverity(enum.Enum):
    HIGH = "HIGH"

    @classmethod
    def _missing_(cls, value):
        return cls(value.upper()) if isinstance(value, str) else None


class _StaticFoldingSeverity(enum.Enum):
    HIGH = "HIGH"

    @staticmethod
    def _missing_(value):
        if isinstance(value, str) and value.upper() == "HIGH":
            return _StaticFoldingSeverity.HIGH
        return None


class _MixedFoldingSeverity(enum.Enum):
    NAME = "NAME"
    LEVEL = 3

    @classmethod
    def _missing_(cls, value):
        return None


def _refusal_text(model_type, payload) -> str:
    with pytest.raises(Exception) as refused:
        model_type.model_validate(payload)
    errors = refused.value.errors()  # type: ignore[attr-defined]
    return " ".join(f"{error['loc']}: {error['msg']}" for error in errors)


def _hook_enums():
    return pytest.mark.parametrize(
        "kind",
        [_FoldingSeverity, _StaticFoldingSeverity],
        ids=["classmethod-hook", "staticmethod-hook"],
    )


@_hook_enums()
def test_the_override_is_the_premise_of_these_cells(kind):
    """Control: the stock lookup is not replaced by the identical function, so
    the override is what these cells exercise, and the hook does re-spell."""
    assert kind("HIGH") is kind.HIGH
    assert kind("high") is kind.HIGH
    assert getattr(kind._missing_, "__func__", None) is not getattr(
        enum.Enum._missing_, "__func__", None
    )


@_hook_enums()
def test_exact_member_text_at_a_scalar_field_takes_the_downcast(kind):
    class Section(RedactedSection):
        severity: Optional[kind] = None  # type: ignore[valid-type]

    section = Section.model_validate(
        {"severity": env_resolved_scalar("HIGH", VARIABLE)}
    )

    assert section.severity is kind.HIGH


@_hook_enums()
def test_exact_member_text_in_a_container_takes_the_downcast(kind):
    class Section(RedactedSection):
        severities: Optional[List[kind]] = None  # type: ignore[valid-type]

    section = Section.model_validate(
        {"severities": [env_resolved_scalar("HIGH", VARIABLE)]}
    )

    assert section.severities == [kind.HIGH]


@_hook_enums()
def test_text_that_reaches_the_hook_is_refused_at_a_scalar_field(kind):
    class Section(RedactedSection):
        severity: Optional[kind] = None  # type: ignore[valid-type]

    text = _refusal_text(Section, {"severity": env_resolved_scalar("high", VARIABLE)})

    assert VARIABLE in text and "severity" in text, text
    assert "high" not in text, text


@_hook_enums()
def test_text_that_reaches_the_hook_is_refused_in_a_container(kind):
    class Section(RedactedSection):
        severities: Optional[List[kind]] = None  # type: ignore[valid-type]

    text = _refusal_text(
        Section, {"severities": [env_resolved_scalar("high", VARIABLE)]}
    )

    assert VARIABLE in text and "severities" in text, text
    assert "high" not in text, text


@pytest.mark.parametrize("text", ["NAME", "3"], ids=["str-member", "int-member"])
def test_an_enum_with_a_non_str_member_is_refused_whatever_the_text(text):
    class Section(RedactedSection):
        level: Optional[_MixedFoldingSeverity] = None

    refused = _refusal_text(Section, {"level": env_resolved_scalar(text, VARIABLE)})

    assert VARIABLE in refused and "level" in refused, refused
