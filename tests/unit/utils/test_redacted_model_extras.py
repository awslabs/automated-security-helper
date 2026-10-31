# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A section's extras are read like its fields where they are typed or opted in.

A section declared with ``extra="allow"`` and ``__pydantic_extra__: Dict[str,
X]`` has pydantic validate each extra as X. The field validator saw declared
fields only, so an X that converts text (an int, a Path) typed an env-read
value silently. The typed walk now reads an extra that holds a reference
against X, for the section itself and for a plain model under one of its
fields.

An extra stays out of the field validator's downcast by default, because the
segment models keep a plugin's raw config in theirs and that config must still
hold its markers when the plugin's own model validates it. A section whose
extras are validated data sets ``_downcast_extras`` and gets them downcast to
plain str, keys included, so no str subclass reaches a config dump.
"""

from typing import Any, ClassVar, Dict, Optional
from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

from automated_security_helper.utils.redacted_model import (
    EnvResolvedScalar,
    RedactedSection,
    env_resolved_scalar,
)

pytestmark = pytest.mark.unit

CANARY = "424242"
VARIABLE = "ASH_EXTRAS_CANARY"


def _refusal_text(model_type, payload) -> str:
    with pytest.raises(ValidationError) as refused:
        model_type.model_validate(payload)
    return " ".join(
        f"{error['loc']}: {error['msg']}" for error in refused.value.errors()
    )


class _NumberExtras(RedactedSection):
    model_config = ConfigDict(extra="allow")
    __pydantic_extra__: Dict[str, int] = {}

    name: str = ""


class _TextExtras(RedactedSection):
    model_config = ConfigDict(extra="allow")
    __pydantic_extra__: Dict[str, str] = {}

    name: str = ""


class _AnyExtras(RedactedSection):
    model_config = ConfigDict(extra="allow")
    __pydantic_extra__: Dict[str, Any] = {}

    name: str = ""


class _PlainNumberExtras(BaseModel):
    model_config = ConfigDict(extra="allow")
    __pydantic_extra__: Dict[str, int] = {}


class _Holder(RedactedSection):
    inner: Optional[_PlainNumberExtras] = None


class _Downcasting(RedactedSection):
    model_config = ConfigDict(extra="allow")
    _downcast_extras: ClassVar[bool] = True

    name: str = ""


class _Keeping(RedactedSection):
    model_config = ConfigDict(extra="allow")

    name: str = ""


def test_a_reference_at_an_extra_typed_as_a_number_is_refused_by_name():
    text = _refusal_text(
        _NumberExtras, {"name": "x", "limit": env_resolved_scalar(CANARY, VARIABLE)}
    )
    assert VARIABLE in text, text
    assert "limit" in text, text
    assert CANARY not in text, text


def test_a_container_at_an_extra_typed_as_a_number_is_refused_by_name():
    text = _refusal_text(
        _NumberExtras, {"limit": [env_resolved_scalar(CANARY, VARIABLE)]}
    )
    assert VARIABLE in text, text
    assert CANARY not in text, text


def test_a_reference_as_the_key_of_an_extra_names_no_key():
    marker_key = env_resolved_scalar("secret-key-text", VARIABLE)
    text = _refusal_text(
        _NumberExtras, {marker_key: [env_resolved_scalar(CANARY, VARIABLE)]}
    )
    assert VARIABLE in text, text
    assert "secret-key-text" not in text, text


def test_a_reference_at_an_extra_typed_as_a_str_keeps_the_text():
    section = _TextExtras.model_validate(
        {"name": "x", "note": env_resolved_scalar("plain", VARIABLE)}
    )
    assert section.__pydantic_extra__ == {"note": "plain"}


def test_a_reference_at_an_extra_typed_as_anything_is_left_alone():
    """The segment models' shape: the raw config stays as the file wrote it."""
    marker = env_resolved_scalar(CANARY, VARIABLE)
    section = _AnyExtras.model_validate({"raw": {"limit": marker}})
    assert section.__pydantic_extra__["raw"]["limit"] is marker


def test_a_section_with_no_declared_extras_type_is_left_alone():
    marker = env_resolved_scalar(CANARY, VARIABLE)
    section = _Keeping.model_validate({"raw": marker})
    assert section.__pydantic_extra__["raw"] is marker


def test_a_reference_at_a_typed_extra_of_a_plain_model_is_refused_by_name():
    text = _refusal_text(
        _Holder, {"inner": {"count": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    assert VARIABLE in text, text
    assert "inner" in text, text
    assert CANARY not in text, text


def test_a_plain_model_with_typed_extras_keeps_a_value_that_holds_no_reference():
    section = _Holder.model_validate({"inner": {"count": 7}})
    assert section.inner is not None
    assert section.inner.__pydantic_extra__ == {"count": 7}


def test_a_section_that_opts_in_downcasts_its_extras_and_their_keys():
    marker = env_resolved_scalar("value-text", VARIABLE)
    key = env_resolved_scalar("key-text", "ASH_EXTRAS_KEY")
    section = _Downcasting.model_validate(
        {"name": "x", "free": marker, "nested": {"inner": [marker]}, key: 1}
    )
    extras = section.__pydantic_extra__
    assert extras["free"] == "value-text"
    assert type(extras["free"]) is str
    assert type(extras["nested"]["inner"][0]) is str
    assert all(type(name) is str for name in extras), list(map(type, extras))
    assert extras["key-text"] == 1


def test_a_section_that_does_not_opt_in_keeps_the_markers_in_its_extras():
    """The control for the default: the raw config still holds its markers."""
    marker = env_resolved_scalar("value-text", VARIABLE)
    section = _Keeping.model_validate({"free": marker})
    assert isinstance(section.__pydantic_extra__["free"], EnvResolvedScalar)


class _Carried(RedactedSection):
    name: str = ""


class _Wrapper(RedactedSection):
    carried: Optional[_Carried] = None
    held: Optional[_Downcasting] = None


def test_a_spec_double_given_for_a_section_field_is_kept_as_given():
    """pydantic hands an instance given for a section field through the field's
    validators unchanged and runs the after validator on it; a MagicMock built
    with spec= passes the instance check with a type that has none of the
    section's class attributes, so the validator leaves it as given."""
    double = MagicMock(spec=_Carried)
    double.name = "x"
    section = _Wrapper(carried=double)
    assert section.carried is double


def test_a_real_section_given_for_a_section_field_is_kept_and_a_nested_one_is_downcast():
    """The control: a real instance is kept as given, and a nested section built
    from a dict still has its opted-in extras downcast by the same validator."""
    carried = _Carried(name="x")
    marker = env_resolved_scalar("value-text", VARIABLE)
    section = _Wrapper.model_validate(
        {"carried": carried, "held": {"name": "y", "free": marker}}
    )
    assert section.carried is carried
    assert section.held is not None
    assert section.held.__pydantic_extra__["free"] == "value-text"
    assert type(section.held.__pydantic_extra__["free"]) is str
