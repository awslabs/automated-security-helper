# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""In a union, a container-shaped arm speaks for a value's markers only when
pydantic would accept the value at that arm.

The typed walk admitted a union as soon as one arm that could hold the value
kept every marker as text, even when that arm would fail validation for
another reason: a fixed tuple of another length, a model given a key it does
not declare (a marker under it is never read) or missing a field it requires.
pydantic refuses such an arm and its smart-mode union hands the value to a
sibling, so the sibling converted the env-read text and printed it in clear
while the walk had read it as kept.

The arm is validated as pydantic validates it: under the config in force around
the slot and with the load's context. Validated under the default config, a
TypedDict arm whose keys the holder's ``alias_generator`` names was refused for a
key it does read, an arm under the holder's ``extra="forbid"`` vouched for a
value pydantic hands to a converting sibling, and a section arm validated
without the ``strict_file_load`` context accepted a reference the load refuses.
"""

from __future__ import annotations

from typing import ClassVar, Dict, FrozenSet, List, Optional, Tuple, Union

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError, ValidationInfo
from pydantic import model_validator
from typing_extensions import TypedDict

from automated_security_helper.utils.redacted_model import (
    RedactedSection,
    env_resolved_scalar,
)

pytestmark = pytest.mark.unit

CANARY = "424242"
VARIABLE = "ASH_ARM_CANARY"


def _refusal_text(model_type, payload, context=None) -> str:
    with pytest.raises(ValidationError) as refused:
        model_type.model_validate(payload, context=context)
    return " ".join(
        f"{error['loc']}: {error['msg']}" for error in refused.value.errors()
    )


def _assert_named_not_echoed(text: str, field: str) -> None:
    assert VARIABLE in text, text
    assert field in text, text
    assert CANARY not in text.replace(field, ""), text


class _Closed(BaseModel):
    model_config = ConfigDict(extra="forbid")

    count: int = 0


class _Needs(BaseModel):
    count: int


class _Named(BaseModel):
    name: str = ""


class _Open(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str = ""


class _Lenient(BaseModel):
    """Ignores undeclared keys (pydantic's default) and types the one it has."""

    count: int = 0


def test_a_model_arm_given_an_undeclared_key_still_refuses_its_typed_field():
    """The arm is walked before the filter decides whether it may admit: a
    reference at the declared int field is refused by name even though the
    undeclared key beside it means the arm cannot vouch for the value."""

    class Section(RedactedSection):
        value: Optional[_Lenient] = None

    text = _refusal_text(
        Section,
        {
            "value": {
                "count": env_resolved_scalar(CANARY, VARIABLE),
                "other": env_resolved_scalar("7", "ASH_ARM_OTHER"),
            }
        },
    )
    _assert_named_not_echoed(text, "value")


def test_a_refused_arm_wins_over_a_lenient_models_silence():
    """An open model given a reference under a key it does not declare reads
    it as an extra and says nothing; the sibling that declares the key as an
    int refuses it by name, and that finding is the union's answer."""

    class Section(RedactedSection):
        value: Optional[Union[_Open, _Lenient]] = None

    text = _refusal_text(
        Section, {"value": {"count": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    _assert_named_not_echoed(text, "value")


def test_a_model_arm_given_an_undeclared_marker_key_does_not_mask_a_sibling():
    class Section(RedactedSection):
        value: Optional[Union[_Closed, Dict[str, int]]] = None

    text = _refusal_text(
        Section, {"value": {"other": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    _assert_named_not_echoed(text, "value")


def test_a_model_arm_missing_a_required_field_does_not_mask_a_sibling():
    class Section(RedactedSection):
        value: Optional[Union[_Needs, Dict[str, int]]] = None

    text = _refusal_text(
        Section, {"value": {"other": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    _assert_named_not_echoed(text, "value")


def test_a_fixed_tuple_arm_of_another_length_does_not_mask_a_sibling():
    class Section(RedactedSection):
        value: Optional[Union[Tuple[str, str], List[int]]] = None

    text = _refusal_text(Section, {"value": [env_resolved_scalar(CANARY, VARIABLE)]})
    _assert_named_not_echoed(text, "value")


def test_a_model_arm_that_takes_the_value_still_admits_the_text():
    """The control: the marker sits under a declared str field, so the model
    arm holds it as text and the reference is admitted and downcast."""

    class Section(RedactedSection):
        value: Optional[Union[_Named, Dict[str, int]]] = None

    section = Section.model_validate(
        {"value": {"name": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    assert section.value == _Named(name=CANARY)
    assert type(section.value.name) is str


def test_an_undeclared_marker_key_with_no_converting_sibling_is_downcast():
    """No arm speaks for the marker, so the walk refuses nothing and the
    downcast hands pydantic plain text, which the open model keeps as an
    extra."""

    class Section(RedactedSection):
        value: Optional[Union[_Open, List[int]]] = None

    section = Section.model_validate(
        {"value": {"other": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    assert section.value.__pydantic_extra__ == {"other": CANARY}
    assert type(section.value.__pydantic_extra__["other"]) is str


class _Opts(TypedDict):
    """No config of its own: pydantic builds it under the holder's."""

    max_count: int
    label: str


def test_a_typed_dict_arm_under_the_holders_alias_generator_still_admits():
    """The holder's alias_generator names the TypedDict's keys, so pydantic
    accepts the camel-cased value at the TypedDict arm, where the reference
    sits at a str field; the arm vouches, and the Dict[str, int] sibling that
    would type the reference is never asked. Validated under the default
    config, the arm read its key as missing and the sibling refused a config
    pydantic accepts."""

    class Section(RedactedSection):
        model_config = ConfigDict(alias_generator=str.upper)

        value: Optional[Union[_Opts, Dict[str, int]]] = None

    section = Section.model_validate(
        {"VALUE": {"MAX_COUNT": 1, "LABEL": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    assert section.value == {"max_count": 1, "label": CANARY}
    assert type(section.value["label"]) is str


def test_a_typed_dict_arm_under_the_holders_extra_forbid_does_not_vouch():
    """The holder forbids undeclared keys, and pydantic applies that to the
    TypedDict arm too, so the arm refuses the value for its extra key and the
    union hands the value to Dict[str, int], which types the reference: it is
    refused by name. Validated under the default config, the arm ignored the
    extra key, vouched for the value, and the sibling typed the text
    silently."""

    class Section(RedactedSection):
        model_config = ConfigDict(extra="forbid")

        value: Optional[Union[_Opts, Dict[str, int]]] = None

    text = _refusal_text(
        Section,
        {
            "value": {
                "max_count": 1,
                "label": env_resolved_scalar(CANARY, VARIABLE),
                "note": 2,
            }
        },
    )
    _assert_named_not_echoed(text, "value")


class _Opted(RedactedSection):
    """A section that opts a typed field into keeping a reference on the
    plugin route; a config-file load refuses the reference there by name."""

    _env_scalar_typed_fields: ClassVar[FrozenSet[str]] = frozenset({"scan_timeout"})

    scan_timeout: int = 0


def test_a_section_arm_is_validated_with_the_loads_context():
    """Under the config-file context the section arm refuses the reference at
    its opted field, so it cannot vouch for the value, and the Dict[str, int]
    sibling that would type the reference refuses it by name. Validated
    without the context, the arm accepted the reference (the plugin route
    keeps it) and vouched, and the real load, which refuses the arm, handed
    the text to the sibling."""

    class Section(RedactedSection):
        value: Optional[Union[_Opted, Dict[str, int]]] = None

    text = _refusal_text(
        Section,
        {"value": {"scan_timeout": env_resolved_scalar(CANARY, VARIABLE)}},
        context={"strict_file_load": True},
    )
    _assert_named_not_echoed(text, "value")


class _Picky(RedactedSection):
    """A section arm that refuses its value when the load's context carries a
    key of its own, as a plugin option model reads keys beside
    ``strict_file_load``."""

    other: str = ""

    @model_validator(mode="before")
    @classmethod
    def _refuse_when_the_context_says_so(cls, value, info: ValidationInfo):
        if info.context and info.context.get("ash_test_refuse_picky"):
            raise ValueError("refused by the load's context")
        return value


def test_a_section_arm_is_validated_with_every_key_of_the_loads_context():
    """The arm read carried only ``strict_file_load``; under a context with
    another key the arm vouched for a value the real load refuses, and the
    converting sibling typed the reference silently. The load's context is now
    carried whole (a shallow copy), so the arm refuses in the read as it does
    in the load, and the sibling's typing is refused by name."""

    class Section(RedactedSection):
        value: Optional[Union[_Picky, Dict[str, int]]] = None

    text = _refusal_text(
        Section,
        {"value": {"other": env_resolved_scalar(CANARY, VARIABLE)}},
        context={"ash_test_refuse_picky": True},
    )
    _assert_named_not_echoed(text, "value")


def test_an_arm_whose_configured_adapter_cannot_be_built_is_read_under_the_default(
    monkeypatch,
):
    """An arm read under the holder's config whose configured adapter pydantic
    cannot build was taken to vouch for the value unread; it is read under the
    default config instead, and an arm that then refuses the value does not
    vouch. The configured build's failure is stood in for by an adapter
    builder that answers None whenever a config is given, since no config of
    the project's models makes the wrapped build fail."""
    from automated_security_helper.utils import redacted_model as module

    real = module._arm_adapter

    def without_a_configured_build(annotation, config=None):
        return None if config is not None else real(annotation)

    monkeypatch.setattr(module, "_arm_adapter", without_a_configured_build)
    token = module._WALK_CONFIG.set(ConfigDict(extra="forbid"))
    try:
        vouched = module._arm_validates(
            List[int], [env_resolved_scalar("not-a-number", VARIABLE)]
        )
    finally:
        module._WALK_CONFIG.reset(token)
    assert vouched is False
