# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An environment reference written as a mapping KEY is detected, refused at a
typed key slot, and downcast everywhere else, exactly as one written as a value.

The detector that starts the section validator's typed walk and downcast
(``first_env_scalar``) read a dict's values only, so a dict whose only
reference was a key passed the gate untouched: a ``Dict[int, str]`` key slot
converted the env-read text to a number that printed in clear, and an untyped
key slot kept the str subclass in the validated model, where PyYAML's
SafeDumper has no representer for it and every config dump failed. The
downcast view (``without_env_scalars``) kept keys as they were for the same
reason, against its own contract.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import pytest
import yaml
from pydantic import ValidationError

from automated_security_helper.utils.redacted_model import (
    EnvResolvedScalar,
    RedactedSection,
    env_resolved_scalar,
    first_env_scalar,
    without_env_scalars,
)

pytestmark = pytest.mark.unit

CANARY = "424242"
VARIABLE = "ASH_KEY_CANARY"


def _refusal_text(model_type, payload) -> str:
    """The refusal as the product's describe layer reads it: loc and msg per
    error, without pydantic's raw ``input_value`` rendering."""
    with pytest.raises(ValidationError) as refused:
        model_type.model_validate(payload)
    return " ".join(
        f"{error['loc']}: {error['msg']}" for error in refused.value.errors()
    )


def _assert_named_not_echoed(text: str, field: str) -> None:
    assert VARIABLE in text, text
    assert field in text, text
    assert CANARY not in text.replace(field, ""), text


def test_a_marker_key_at_a_typed_key_slot_is_refused_by_name():
    """A ``Dict[int, str]`` key slot converts the text: before the fix the key
    was never seen, so pydantic typed the env-read "424242" to 424242 and the
    number printed wherever the section was shown."""

    class Section(RedactedSection):
        counts: Optional[Dict[int, str]] = None

    text = _refusal_text(
        Section, {"counts": {env_resolved_scalar(CANARY, VARIABLE): "x"}}
    )
    _assert_named_not_echoed(text, "counts")


def test_a_marker_key_at_an_untyped_key_slot_is_downcast_to_plain_str():
    """An ``Any`` key slot keeps whatever it is given: the key must reach it
    as a plain str, not as the marker subclass."""

    class Section(RedactedSection):
        names: Optional[Dict[Any, Any]] = None

    section = Section.model_validate(
        {"names": {env_resolved_scalar(CANARY, VARIABLE): 1}}
    )
    (key,) = section.names
    assert key == CANARY
    assert type(key) is str


def test_a_section_with_a_marker_key_still_dumps_through_the_safe_dumper():
    """The contract the key gap broke: no str subclass survives validation, so
    a config dump (SafeDumper, which has no representer for one) succeeds."""

    class Section(RedactedSection):
        names: Optional[Dict[Any, Any]] = None

    section = Section.model_validate(
        {"names": {env_resolved_scalar(CANARY, VARIABLE): 1}}
    )
    dumped = yaml.safe_dump(section.model_dump())
    assert CANARY in dumped


def test_a_container_whose_only_marker_is_a_key_is_refused_at_a_scalar_field():
    """A mapping at an int field is refused by what it holds, naming the
    variable of the first reference in it; a key counts as held."""

    class Section(RedactedSection):
        limit: Optional[int] = None

    text = _refusal_text(Section, {"limit": {env_resolved_scalar(CANARY, VARIABLE): 1}})
    _assert_named_not_echoed(text, "limit")


def test_first_env_scalar_reads_a_dict_key_before_its_value():
    key = env_resolved_scalar("k", VARIABLE + "_K")
    value = env_resolved_scalar("v", VARIABLE + "_V")
    assert first_env_scalar({key: value}) is key
    assert first_env_scalar({"outer": {key: 1}}) is key
    assert first_env_scalar({"outer": [{"inner": {key: 1}}]}) is key


def test_without_env_scalars_downcasts_dict_keys_at_every_depth():
    key = env_resolved_scalar("k", VARIABLE + "_K")
    value = env_resolved_scalar("v", VARIABLE + "_V")
    view = without_env_scalars({key: [value], "outer": {key: value}})

    def no_marker(node) -> bool:
        if isinstance(node, EnvResolvedScalar):
            return False
        if isinstance(node, dict):
            return all(no_marker(k) and no_marker(v) for k, v in node.items())
        if isinstance(node, (list, tuple, set)):
            return all(no_marker(item) for item in node)
        return True

    assert view == {"k": ["v"], "outer": {"k": "v"}}
    assert no_marker(view)
    assert all(type(k) is str for k in view)
    assert all(type(k) is str for k in view["outer"])


def test_a_marker_key_at_a_str_key_slot_still_takes_the_downcast():
    """The must-not-flag control: a str key slot keeps the text, so the
    reference is admitted there and the key lands as a plain str."""

    class Section(RedactedSection):
        counts: Optional[Dict[str, int]] = None

    section = Section.model_validate(
        {"counts": {env_resolved_scalar(CANARY, VARIABLE): 7}}
    )
    assert section.counts == {CANARY: 7}
    assert all(type(key) is str for key in section.counts)
