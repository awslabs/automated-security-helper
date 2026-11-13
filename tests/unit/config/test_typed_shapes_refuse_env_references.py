# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every annotation shape that cannot keep a plain str refuses a reference.

The refusal of ``${ASH_X}`` at typed fields used to recognize only bare and
Optional int, float and bool. Every other typed shape -- a constrained or
Annotated number, a union of numbers, Decimal, date, a container of numbers --
was downcast to plain str and typed silently by a lax model, converting a
value read from the environment into a spelling the redaction needle never
matches. The rule is now what the refusal was always about: a field (or a
container's item slot) that cannot keep the text as a plain str would convert
it, so the reference is refused there, naming the variable and never the
value. A shape that keeps the text (str, Optional[str], Any, a str Literal, a
container of strings) still takes the downcast.
"""

from __future__ import annotations

import collections.abc
import dataclasses
import datetime
import decimal
import enum
import ipaddress
import sys
from pathlib import Path
from typing import (
    Annotated,
    Any,
    ClassVar,
    Deque,
    Dict,
    Generic,
    List,
    Literal,
    NamedTuple,
    NewType,
    Optional,
    Tuple,
    TypeVar,
    Union,
)

import attrs
import pydantic.dataclasses
import pydantic.networks
import pytest
from pydantic import (
    AliasChoices,
    AliasPath,
    AnyUrl,
    BaseModel,
    ConfigDict,
    Field,
    PositiveInt,
    RootModel,
    SecretBytes,
    SecretStr,
    TypeAdapter,
    ValidationError,
    conint,
)
from pydantic.errors import PydanticSchemaGenerationError, PydanticUserError
from pydantic.fields import FieldInfo
from pydantic_core import core_schema
from typing_extensions import TypeAliasType, TypedDict

from automated_security_helper.utils.redacted_model import (
    RedactedSection,
    env_resolved_scalar,
    first_env_scalar,
)

pytestmark = pytest.mark.unit

CANARY = "424242"
VARIABLE = "ASH_SHAPE_CANARY"


def _refusal_text(model_type, payload) -> str:
    """The refusal as the product's describe layer reads it: loc and msg per
    error. pydantic's RAW rendering also appends ``input_value=...``, which
    echoes the input on every refusal route, typed or not; the shown surfaces
    build from the message (test_env_references_load_typed_fields pins the
    file-load text end to end), so that is what these cells measure."""
    with pytest.raises(Exception) as refused:
        model_type.model_validate(payload)
    errors = refused.value.errors()  # type: ignore[attr-defined]
    return " ".join(f"{error['loc']}: {error['msg']}" for error in errors)


def _assert_named_not_echoed(text: str, field: str) -> None:
    assert VARIABLE in text, text
    assert field in text, text
    assert CANARY not in text.replace(field, ""), text


@pytest.mark.parametrize(
    "annotation",
    [
        Optional[PositiveInt],
        Optional[Annotated[int, Field(ge=0)]],
        conint(ge=0),
        Union[int, float],
        decimal.Decimal,
        datetime.date,
    ],
    ids=[
        "optional-positive-int",
        "optional-annotated-int",
        "conint",
        "union-int-float",
        "decimal",
        "date",
    ],
)
def test_a_scalar_shape_that_converts_the_text_is_refused(annotation):
    class Section(RedactedSection):
        limit: Optional[annotation] = None  # type: ignore[valid-type]

    text = _refusal_text(Section, {"limit": env_resolved_scalar(CANARY, VARIABLE)})
    _assert_named_not_echoed(text, "limit")


@pytest.mark.parametrize(
    ("annotation", "payload_shape"),
    [
        (List[int], lambda marker: [marker]),
        (Dict[str, int], lambda marker: {"a": marker}),
        (Tuple[int, ...], lambda marker: [marker]),
    ],
    ids=["list-int", "dict-str-int", "tuple-int"],
)
def test_a_container_item_slot_that_converts_the_text_is_refused(
    annotation, payload_shape
):
    class Section(RedactedSection):
        ids: Optional[annotation] = None  # type: ignore[valid-type]

    marker = env_resolved_scalar(CANARY, VARIABLE)
    text = _refusal_text(Section, {"ids": payload_shape(marker)})
    _assert_named_not_echoed(text, "ids")


def test_a_bare_marker_at_a_container_field_is_refused():
    class Section(RedactedSection):
        ids: Optional[List[int]] = None

    text = _refusal_text(Section, {"ids": env_resolved_scalar(CANARY, VARIABLE)})
    _assert_named_not_echoed(text, "ids")


@pytest.mark.parametrize(
    "annotation",
    [str, Optional[str], Any, Literal["424242", "other"], Union[int, str]],
    ids=["str", "optional-str", "any", "str-literal", "union-with-str"],
)
def test_a_shape_that_keeps_the_text_still_takes_the_downcast(annotation):
    """The must-not-flag controls: a slot a plain str can land in keeps the
    resolved text, downcast so no str subclass reaches a config dump."""

    class Section(RedactedSection):
        value: Optional[annotation] = None  # type: ignore[valid-type]

    section = Section.model_validate({"value": env_resolved_scalar(CANARY, VARIABLE)})
    assert section.value == CANARY
    assert type(section.value) is str


def test_a_container_of_strings_still_takes_the_downcast():
    class Section(RedactedSection):
        names: Optional[List[str]] = None

    section = Section.model_validate({"names": [env_resolved_scalar(CANARY, VARIABLE)]})
    assert section.names == [CANARY]
    assert type(section.names[0]) is str


def test_a_dict_with_typed_values_and_a_marker_key_is_still_downcast():
    """The key slot keeps a plain str, so a marker THERE converts nothing:
    only a marker at the int value slot is refused (the cell above)."""

    class Section(RedactedSection):
        counts: Optional[Dict[str, int]] = None

    section = Section.model_validate(
        {"counts": {env_resolved_scalar(CANARY, VARIABLE): 7}}
    )
    assert section.counts == {CANARY: 7}


def test_a_str_enum_field_still_accepts_the_text():
    """A str-valued Enum converts to a member that still spells the text, so
    the needle matches it wherever it prints; the slot admits the reference
    (output_formats is the production shape)."""
    import enum

    class Choice(str, enum.Enum):
        RED = "zz-red-choice"

    class Section(RedactedSection):
        color: Optional[Choice] = None

    section = Section.model_validate(
        {"color": env_resolved_scalar("zz-red-choice", VARIABLE)}
    )
    assert section.color is Choice.RED


def test_an_opted_field_still_hands_the_text_to_its_own_validation():
    class Section(RedactedSection):
        _env_scalar_typed_fields: ClassVar[frozenset] = frozenset({"limit"})
        limit: Optional[PositiveInt] = None

    section = Section.model_validate(
        {"limit": env_resolved_scalar("67", "ASH_SHAPE_OPTED")}
    )
    assert section.limit == 67


def test_a_secret_str_field_admits_the_text():
    """SecretStr never prints its value (repr and str both mask), so the text
    can land there without the needle having to match a spelling."""

    class Section(RedactedSection):
        token: Optional[SecretStr] = None

    section = Section.model_validate({"token": env_resolved_scalar(CANARY, VARIABLE)})
    assert isinstance(section.token, SecretStr)
    assert section.token.get_secret_value() == CANARY
    assert CANARY not in repr(section.token)


def test_a_secret_bytes_field_admits_the_text():
    class Section(RedactedSection):
        token: Optional[SecretBytes] = None

    section = Section.model_validate({"token": env_resolved_scalar(CANARY, VARIABLE)})
    assert isinstance(section.token, SecretBytes)
    assert section.token.get_secret_value() == CANARY.encode()
    assert CANARY not in repr(section.token)
    assert CANARY not in str(section.token)


def test_a_plain_enum_of_str_members_admits_the_text():
    """The env text equals a constant the code declares, and the member
    prints as that constant (repr shows the value, spelled as the text), which
    the needle matches: the slot selects among the code's own literals, all
    str here. An enum with a non-str member is refused instead (the cells
    further down)."""

    class Mode(enum.Enum):
        FAST = "zz-fast-mode"

    class Section(RedactedSection):
        mode: Optional[Mode] = None

    section = Section.model_validate(
        {"mode": env_resolved_scalar("zz-fast-mode", VARIABLE)}
    )
    assert section.mode is Mode.FAST


def test_a_path_field_is_refused_and_the_message_names_the_union_idiom():
    class Section(RedactedSection):
        target: Optional[Path] = None

    text = _refusal_text(Section, {"target": env_resolved_scalar(CANARY, VARIABLE)})
    _assert_named_not_echoed(text, "target")
    assert "Path | str" in text, text


def test_a_url_field_is_refused_and_the_message_names_the_union_idiom():
    class Section(RedactedSection):
        endpoint: Optional[AnyUrl] = None

    text = _refusal_text(Section, {"endpoint": env_resolved_scalar(CANARY, VARIABLE)})
    _assert_named_not_echoed(text, "endpoint")
    assert "AnyUrl | str" in text, text


def test_the_idiom_text_is_absent_from_a_refusal_that_involves_no_path_or_url():
    class Section(RedactedSection):
        limit: Optional[int] = None

    text = _refusal_text(Section, {"limit": env_resolved_scalar(CANARY, VARIABLE)})
    assert "| str" not in text, text


def test_a_path_or_str_union_takes_the_downcast():
    """The sanctioned idiom: the union's str arm keeps the text."""

    class Section(RedactedSection):
        target: Optional[Union[Path, str]] = None
        endpoint: Optional[Union[AnyUrl, str]] = None

    section = Section.model_validate(
        {
            "target": env_resolved_scalar("./x", VARIABLE),
            "endpoint": env_resolved_scalar("http://A//b", VARIABLE),
        }
    )
    assert section.target == "./x"
    assert type(section.target) is str
    assert section.endpoint == "http://A//b"
    assert type(section.endpoint) is str


@pytest.mark.parametrize(
    ("annotation", "payload_shape"),
    [
        (Union[int, List[int]], lambda marker: [marker]),
        (Union[int, Dict[str, int]], lambda marker: {"k": marker}),
        (Union[str, List[int]], lambda marker: [marker]),
        (Union[Literal["all"], List[int]], lambda marker: [marker]),
        (Union[List[int], Literal["all"]], lambda marker: [marker]),
        (Annotated[Literal["all"], Field()] | List[int], lambda marker: [marker]),
        (Union[Literal["all"], Dict[str, int]], lambda marker: {"k": marker}),
        (Union[int, Deque[int]], lambda marker: [marker]),
        (Deque[int], lambda marker: [marker]),
    ],
    ids=[
        "int-or-list-int",
        "int-or-dict-str-int",
        "str-or-list-int",
        "literal-or-list-int",
        "list-int-or-literal",
        "annotated-literal-or-list-int",
        "literal-or-dict-str-int",
        "int-or-deque-int",
        "deque-int",
    ],
)
def test_a_union_arm_that_cannot_hold_the_value_does_not_admit_it(
    annotation, payload_shape
):
    """An argless arm (int, str) or a Literal describes no container, so it
    must not count as the arm that keeps the markers of a list or dict value,
    and a Literal's values are constants, never item annotations to walk. A
    deque is a container a list converts into, so its item slot is walked."""

    class Section(RedactedSection):
        value: Optional[annotation] = None  # type: ignore[valid-type]

    marker = env_resolved_scalar(CANARY, VARIABLE)
    text = _refusal_text(Section, {"value": payload_shape(marker)})
    _assert_named_not_echoed(text, "value")


def test_a_union_with_a_str_arm_still_admits_a_scalar_reference():
    class Section(RedactedSection):
        value: Optional[Union[str, List[int]]] = None

    section = Section.model_validate({"value": env_resolved_scalar(CANARY, VARIABLE)})
    assert section.value == CANARY
    assert type(section.value) is str


def test_a_union_with_a_str_list_arm_still_admits_a_list_of_references():
    class Section(RedactedSection):
        value: Optional[Union[int, List[str]]] = None

    section = Section.model_validate({"value": [env_resolved_scalar(CANARY, VARIABLE)]})
    assert section.value == [CANARY]
    assert type(section.value[0]) is str


def test_a_fixed_tuple_refuses_a_marker_at_a_later_int_slot_from_a_yaml_list():
    """YAML gives lists, never tuples: the slots still pair positionally."""

    class Section(RedactedSection):
        pair: Optional[Tuple[str, int]] = None

    marker = env_resolved_scalar(CANARY, VARIABLE)
    text = _refusal_text(Section, {"pair": ["a", marker]})
    _assert_named_not_echoed(text, "pair")


def test_a_fixed_tuple_admits_a_marker_at_a_later_str_slot_from_a_yaml_list():
    class Section(RedactedSection):
        pair: Optional[Tuple[int, str]] = None

    section = Section.model_validate(
        {"pair": [1, env_resolved_scalar(CANARY, VARIABLE)]}
    )
    assert section.pair == (1, CANARY)
    assert type(section.pair[1]) is str


def test_a_fixed_tuple_pairs_the_shared_prefix_when_the_lengths_differ():
    """The model's own validation owns the length error; the walk still
    refuses a marker that sits at an int slot inside the shared prefix."""

    class Section(RedactedSection):
        pair: Optional[Tuple[str, int]] = None

    marker = env_resolved_scalar(CANARY, VARIABLE)
    text = _refusal_text(Section, {"pair": ["a", marker, "extra"]})
    _assert_named_not_echoed(text, "pair")


def test_a_marker_under_a_plain_model_annotation_at_a_converting_field_is_refused():
    """A field annotated as a plain BaseModel (not a section) has no args to
    walk, but its own fields convert: ``n: int`` would type the downcast text
    laxly, so the reference is refused at the inner slot."""

    class Inner(BaseModel):
        n: int = 0

    class Section(RedactedSection):
        inner: Inner = Inner()

    text = _refusal_text(
        Section, {"inner": {"n": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    _assert_named_not_echoed(text, "inner")


def test_a_plain_model_annotation_still_validates_literal_values():
    class Inner(BaseModel):
        n: int = 0

    class Section(RedactedSection):
        inner: Inner = Inner()

    section = Section.model_validate({"inner": {"n": 7}})
    assert section.inner.n == 7


def test_a_dataclass_annotation_is_walked_by_field_and_a_str_field_keeps_the_text():
    @dataclasses.dataclass
    class Inner:
        n: int = 0
        label: str = ""

    class Section(RedactedSection):
        inner: Inner = Inner()

    marker = env_resolved_scalar(CANARY, VARIABLE)
    text = _refusal_text(Section, {"inner": {"n": marker}})
    _assert_named_not_echoed(text, "inner")

    section = Section.model_validate({"inner": {"label": marker}})
    assert section.inner.label == CANARY
    assert type(section.inner.label) is str


def test_a_plain_model_annotation_is_walked_by_alias():
    class Inner(BaseModel):
        count: int = Field(0, alias="total")

    class Section(RedactedSection):
        inner: Inner = Inner()

    text = _refusal_text(
        Section, {"inner": {"total": env_resolved_scalar(CANARY, VARIABLE)}}
    )
    _assert_named_not_echoed(text, "inner")


def test_a_marker_at_a_converting_field_of_a_section_under_a_plain_model_is_refused():
    """The annotation reaches a section only through a plain model's field, so
    the outer field's walk is the only one that sees the marker before it is
    downcast: the nested section's own validator gets plain text, and its
    ``n: int`` would type the environment's text silently."""

    class Sub(RedactedSection):
        n: int = 0

    class Inner(BaseModel):
        sub: Sub = Sub()

    class Section(RedactedSection):
        inner: Inner = Inner()

    text = _refusal_text(
        Section, {"inner": {"sub": {"n": env_resolved_scalar(CANARY, VARIABLE)}}}
    )
    _assert_named_not_echoed(text, "inner")


def test_a_marker_at_a_converting_field_of_a_section_in_a_list_of_plain_models():
    class Sub(RedactedSection):
        n: int = 0

    class Inner(BaseModel):
        sub: Sub = Sub()

    class Section(RedactedSection):
        items: List[Inner] = []

    text = _refusal_text(
        Section,
        {"items": [{"sub": {"n": env_resolved_scalar(CANARY, VARIABLE)}}]},
    )
    _assert_named_not_echoed(text, "items")


def test_a_str_field_of_a_section_under_a_plain_model_keeps_the_text():
    class Sub(RedactedSection):
        label: str = ""

    class Inner(BaseModel):
        sub: Sub = Sub()

    class Section(RedactedSection):
        inner: Inner = Inner()

    marker = env_resolved_scalar(CANARY, VARIABLE)
    section = Section.model_validate({"inner": {"sub": {"label": marker}}})
    assert section.inner.sub.label == CANARY
    assert type(section.inner.sub.label) is str


def test_a_marker_at_an_opted_field_of_a_section_under_a_plain_model_is_refused():
    """The walk reaches a section's fields like a plain model's and does not
    honor its ``_env_scalar_typed_fields`` opt-in, on purpose: the plain model
    between hides the marker from the section's own validator, so the opt-in
    (which hands the marker to the field's own validation) could not apply,
    and the text would be typed with no named refusal. The same reference
    written at the section itself is handed on, which is the divergence the
    walk's docstring states."""

    class Sub(RedactedSection):
        _env_scalar_typed_fields: ClassVar[frozenset] = frozenset({"limit"})
        limit: Optional[PositiveInt] = None

    class Inner(BaseModel):
        sub: Sub = Sub()

    class Section(RedactedSection):
        inner: Inner = Inner()

    marker = env_resolved_scalar("67", "ASH_SHAPE_OPTED")
    assert Sub.model_validate({"limit": marker}).limit == 67, (
        "control: written at the section itself, the opt-in hands the text on"
    )
    text = _refusal_text(Section, {"inner": {"sub": {"limit": marker}}})
    assert "ASH_SHAPE_OPTED" in text, text
    assert "inner" in text, text


def _write_yaml(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "typed-shape.ash.yaml"
    path.write_text("project_name: typed-shape\n" + body, encoding="utf-8")
    return path


def test_a_reference_under_a_custom_scanner_model_is_refused_at_load(
    tmp_path, monkeypatch
):
    """``build.custom_scanners`` is a list of the scanner base model, a plain
    BaseModel: its ``dependencies_satisfied`` is a bool, so a reference there
    would be typed from the environment's text.

    The field's before-validator refuses every non-empty list with the one
    "not supported" message, which names the variable and never carries its
    value. A reference at a slot that converts its text (this bool) draws no
    advice to write the value in the file: the field can never be filled, so
    that advice would lead to a second refusal (pinned in
    test_a_custom_scanners_env_entry_draws_the_named_refusal).

    FILE-LOAD-PATH PIN: no value through the file-load path via layers L1
    (the marker's text is the placeholder in a file load), L2
    (``redact_refused_input`` in ``format_model_error``) and L3
    (``describe_validation_error`` given the document's environment values).
    It fails only when L1 is bypassed and L2 and L3 are both gone."""
    from automated_security_helper.config.resolve_config import (
        ConfigFileRefused,
        load_config_file_for_run,
    )

    monkeypatch.setenv(VARIABLE, CANARY)
    path = _write_yaml(
        tmp_path,
        f"build:\n  custom_scanners:\n    - dependencies_satisfied: ${{{VARIABLE}}}\n",
    )

    with pytest.raises(ConfigFileRefused) as refused:
        load_config_file_for_run(path)

    text = str(refused.value)
    assert "custom_scanners is not supported" in text, text
    assert "Write the value in the file" not in text, text
    assert VARIABLE in text, text
    assert CANARY not in text, text


def test_a_reference_at_a_typed_option_of_a_loaded_scanner_is_refused_by_name(
    tmp_path, monkeypatch
):
    """The config model never walks a scanner section it does not declare
    (pydantic validates declared fields only, so the walker never sees the
    extras), so the later loaded-plugin option check is the one that refuses a
    reference at a typed option. For the loaded trivy-repo scanner's bool
    ``ignore_unfixed`` it raises a refusal that names the slot and the option
    and does not echo the value."""
    from automated_security_helper.config.plugin_option_check import (
        refuse_unknown_plugin_options,
    )
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError
    from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
        TrivyRepoScanner,
    )

    monkeypatch.setenv(VARIABLE, CANARY)
    path = _write_yaml(
        tmp_path,
        "scanners:\n"
        "  trivy-repo:\n"
        "    options:\n"
        f"      ignore_unfixed: ${{{VARIABLE}}}\n",
    )
    config = resolve_config(path)

    with pytest.raises(ASHConfigValidationError) as refused:
        refuse_unknown_plugin_options(config, {"scanner": [TrivyRepoScanner]})

    text = str(refused.value)
    assert "scanners.trivy-repo.options" in text, text
    assert "ignore_unfixed" in text, text
    assert CANARY not in text, text


@pytest.mark.parametrize(
    "annotation",
    [
        Union[Literal["all"], List[str]],
        Union[int, Deque[str]],
        Deque[str],
    ],
    ids=["literal-or-list-str", "int-or-deque-str", "deque-str"],
)
def test_a_container_of_strings_behind_a_literal_or_deque_arm_takes_the_downcast(
    annotation,
):
    """The must-not-flag controls for the Literal and Deque rows above: the
    arm that holds the list keeps the text, so the markers are downcast."""

    class Section(RedactedSection):
        value: Optional[annotation] = None  # type: ignore[valid-type]

    section = Section.model_validate({"value": [env_resolved_scalar(CANARY, VARIABLE)]})
    assert [str(item) for item in section.value] == [CANARY]
    assert all(type(item) is str for item in section.value)


class _Level(enum.IntEnum):
    HIGH = 67


class _Bit(enum.IntFlag):
    ON = 67


class _SingleBit(enum.IntFlag):
    ON = 1


class _Number(enum.Enum):
    SIXTY_SEVEN = 67


@pytest.mark.parametrize(
    "enum_type",
    [_Level, _Bit, _SingleBit, _Number],
    ids=[
        "int-enum",
        "int-flag-multi-bit-member",
        "int-flag-single-bit-member",
        "plain-enum-of-ints",
    ],
)
def test_an_enum_with_non_str_members_is_refused(enum_type):
    """A lax model matches "067" to member 67 through int coercion and the
    member prints as 67: a spelling the needle never matches. Only an Enum
    whose members are all str keeps the text (the str-valued cells above)."""

    class Section(RedactedSection):
        level: Optional[enum_type] = None  # type: ignore[valid-type]

    text = _refusal_text(Section, {"level": env_resolved_scalar("067", VARIABLE)})
    assert VARIABLE in text and "level" in text, text
    assert "067" not in text, text


@pytest.mark.parametrize(
    ("annotation", "text"),
    [
        (Union[_Bit, List[_Bit]], "067"),
        (
            Union[ipaddress.IPv4Network, List[ipaddress.IPv4Network]],
            "10.0.0.0/255.0.0.0",
        ),
    ],
    ids=["int-flag-or-list-of-it", "network-or-list-of-networks"],
)
def test_an_argless_iterable_arm_does_not_hold_the_list_for_its_siblings(
    annotation, text
):
    """An IntFlag iterates (Python 3.11 and later) and so does an IPv4Network
    (every version), but neither takes a list: the arm that does is the
    parameterized one, whose item slot converts the text ("067" to 67,
    "10.0.0.0/255.0.0.0" to 10.0.0.0/8, spellings the needle never matches).
    The bare class must not stand in for it and admit the whole value."""

    class Section(RedactedSection):
        value: Optional[annotation] = None  # type: ignore[valid-type]

    marker = env_resolved_scalar(text, VARIABLE)
    refused = _refusal_text(Section, {"value": [marker]})
    assert VARIABLE in refused and "value" in refused, refused
    assert text not in refused, refused


@pytest.mark.parametrize(
    "annotation",
    [
        Union[_Bit, List[str]],
        Union[ipaddress.IPv4Network, List[str]],
    ],
    ids=["int-flag-or-list-str", "network-or-list-str"],
)
def test_a_list_of_strings_beside_an_argless_iterable_arm_takes_the_downcast(
    annotation,
):
    """The must-not-flag control for the cells above: the list arm that keeps
    the text still admits the value."""

    class Section(RedactedSection):
        value: Optional[annotation] = None  # type: ignore[valid-type]

    section = Section.model_validate({"value": [env_resolved_scalar("067", VARIABLE)]})
    assert section.value == ["067"]
    assert type(section.value[0]) is str


class _FoldingSeverity(enum.Enum):
    HIGH = "HIGH"

    @classmethod
    def _missing_(cls, value):
        return cls(value.upper()) if isinstance(value, str) else None


def test_a_str_enum_with_its_own_missing_hook_is_refused():
    """The hook runs on text that equals no member and may map it to one
    spelled differently: "high" lands as HIGH, which the needle never
    matches. Only an enum with the stock lookup keeps the text."""

    class Section(RedactedSection):
        severity: Optional[_FoldingSeverity] = None

    text = _refusal_text(Section, {"severity": env_resolved_scalar("high", VARIABLE)})
    assert VARIABLE in text and "severity" in text, text
    assert "high" not in text, text


class _StaticHookSeverity(enum.Enum):
    HIGH = "HIGH"

    @staticmethod
    def _missing_(value):
        return None


class _PlainFunctionHookSeverity(enum.Enum):
    HIGH = "HIGH"

    def _missing_(value):  # noqa: N805 - the shape under test: no self, no cls
        return None


@pytest.mark.parametrize(
    "severity_type",
    [_StaticHookSeverity, _PlainFunctionHookSeverity],
    ids=["staticmethod", "plain-function"],
)
def test_a_missing_hook_that_is_not_a_classmethod_draws_the_named_refusal(
    severity_type,
):
    """Enum lookup calls a staticmethod or plain-function hook just as it
    calls a classmethod, and such a hook has no underlying function to
    compare with the stock one. It counts as an override, so the field
    refuses by name; it must not escape as an AttributeError, which the
    validator does not turn into a validation error."""

    class Section(RedactedSection):
        severity: Optional[severity_type] = None  # type: ignore[valid-type]

    with pytest.raises(ValidationError) as refused:
        Section.model_validate({"severity": env_resolved_scalar("high", VARIABLE)})
    text = " ".join(
        f"{error['loc']}: {error['msg']}" for error in refused.value.errors()
    )
    assert VARIABLE in text and "severity" in text, text
    assert "high" not in text, text


class _Ids(RootModel[List[int]]):
    pass


class _Names(RootModel[List[str]]):
    pass


@pytest.mark.parametrize(
    "annotation",
    [Optional[_Ids], _Ids, Union[_Ids, int]],
    ids=["optional-root-model", "root-model", "root-model-or-int"],
)
def test_a_root_model_over_a_list_of_numbers_refuses_a_marker_in_the_list(
    annotation,
):
    """A RootModel takes the list its root annotation describes, so the walk
    reads the list against that annotation: "067" would type to 67."""

    class Section(RedactedSection):
        ids: annotation = None  # type: ignore[valid-type]

    text = _refusal_text(Section, {"ids": [env_resolved_scalar("067", VARIABLE)]})
    assert VARIABLE in text and "ids" in text, text
    assert "067" not in text, text


def test_a_root_model_over_a_list_of_strings_takes_the_downcast():
    class Section(RedactedSection):
        names: Optional[_Names] = None

    section = Section.model_validate({"names": [env_resolved_scalar("067", VARIABLE)]})
    assert section.names is not None
    assert section.names.root == ["067"]
    assert type(section.names.root[0]) is str


class _CountedSection(RedactedSection):
    count: int = 0


class _CountedItems(RootModel[List[_CountedSection]]):
    pass


class _NamedSection(RedactedSection):
    name: str = ""


class _NamedItems(RootModel[List[_NamedSection]]):
    pass


class _AliasedSection(RedactedSection):
    """A field whose accepted keys are an AliasChoices, which the model-walk
    cannot enumerate: only the section's own validator sees the key "n"."""

    count: int = Field(0, validation_alias=AliasChoices("count", "n"))


class _AliasedItems(RootModel[List[_AliasedSection]]):
    pass


@pytest.mark.parametrize(
    "annotation",
    [_CountedItems, Optional[_CountedItems], List[_CountedSection]],
    ids=["root-model", "optional-root-model", "plain-list"],
)
def test_sections_under_a_root_model_refuse_a_marker_at_a_typed_field(annotation):
    """A RootModel over a list of sections answers a marker at a section's
    typed field as the plain list of the same sections does: refused by the
    section that holds the field, naming that field (not the outer one), never
    typed ("067" to 67)."""

    class Section(RedactedSection):
        items: annotation = None  # type: ignore[valid-type]

    text = _refusal_text(
        Section, {"items": [{"count": env_resolved_scalar("067", VARIABLE)}]}
    )
    assert VARIABLE in text and "count" in text, text
    assert "067" not in text, text


@pytest.mark.parametrize(
    "annotation",
    [_AliasedItems, Optional[_AliasedItems], List[_AliasedSection]],
    ids=["root-model", "optional-root-model", "plain-list"],
)
def test_a_section_under_a_root_model_sees_the_marker_under_every_accepted_key(
    annotation,
):
    """The section behind a RootModel must receive the marker itself, because
    only its own validator knows every key its field accepts. A gate that stops
    at the RootModel downcasts the marker first, and the field's lax typing
    then turns "067" into 67 without any refusal."""

    class Section(RedactedSection):
        items: annotation = None  # type: ignore[valid-type]

    text = _refusal_text(
        Section, {"items": [{"n": env_resolved_scalar("067", VARIABLE)}]}
    )
    assert VARIABLE in text and "count" in text, text
    assert "067" not in text, text


class _SectionAndCount(RootModel[Tuple[_CountedSection, int]]):
    pass


class _SectionsOrCounts(RootModel[List[Union[_CountedSection, int]]]):
    pass


@pytest.mark.parametrize(
    ("annotation", "build"),
    [
        (_SectionAndCount, lambda m: [{"count": 1}, m]),
        (Optional[_SectionAndCount], lambda m: [{"count": 1}, m]),
        (_SectionsOrCounts, lambda m: [{"count": 1}, m]),
        (Optional[Tuple[_CountedSection, int]], lambda m: [{"count": 1}, m]),
    ],
    ids=[
        "root-model-tuple",
        "optional-root-model-tuple",
        "root-model-list-union",
        "plain-tuple-field",
    ],
)
def test_a_typed_slot_beside_a_section_refuses_a_marker(annotation, build):
    """A field that reaches a section is not handed on whole: the sections
    keep their markers (only their own validators know every accepted key),
    but a slot BESIDE a section -- the tuple's int, the union's int arm --
    still converts text, so a marker there is refused, never typed ("067"
    to 67)."""

    class Section(RedactedSection):
        pair: annotation = None  # type: ignore[valid-type]

    marker = env_resolved_scalar("067", VARIABLE)
    text = _refusal_text(Section, {"pair": build(marker)})
    assert VARIABLE in text and "pair" in text, text
    assert "067" not in text, text


def test_a_section_beside_a_typed_slot_still_takes_its_marker():
    """The must-not-flag control for the cells above: the section in the
    tuple still receives its marker (its own validator downcasts it at a str
    field), and the int slot beside it takes a plain int."""

    class _NameAndCount(RootModel[Tuple[_NamedSection, int]]):
        pass

    class Section(RedactedSection):
        pair: Optional[_NameAndCount] = None

    section = Section.model_validate(
        {"pair": [{"name": env_resolved_scalar("067", VARIABLE)}, 3]}
    )
    assert section.pair is not None
    assert section.pair.root[0].name == "067"
    assert section.pair.root[1] == 3


class _Tree(RootModel[Union[str, int, List["_Tree"], Dict[str, "_Tree"]]]):
    """A RootModel whose root annotation names the class itself, as a plugin
    may declare a recursive option shape."""


_Tree.model_rebuild()


def test_a_self_referencing_root_model_is_refused_not_recursed():
    """Reading whether a shape reaches a section opens a RootModel's root. A
    class whose root names itself must be read once, not opened without
    bound: a RecursionError would crash the config load instead of refusing
    the marker by name."""

    class Section(RedactedSection):
        tree: Optional[_Tree] = None

    marker = env_resolved_scalar("067", VARIABLE)
    text = _refusal_text(Section, {"tree": {"a": marker}})
    assert VARIABLE in text and "tree" in text, text
    assert "067" not in text, text


class _DeepPathSection(RedactedSection):
    count: int = Field(0, validation_alias=AliasPath("deep", "count"))


class _OnePathSection(RedactedSection):
    count: int = Field(0, validation_alias=AliasPath("n"))


class _PlainHoldsAliased(BaseModel):
    sub: _AliasedSection


class _PlainHoldsDeep(BaseModel):
    sub: _DeepPathSection


class _PlainHoldsOnePath(BaseModel):
    sub: _OnePathSection


class _PlainAliasedInt(BaseModel):
    count: int = Field(0, validation_alias=AliasChoices("count", "n"))


class _PlainAliasedStr(BaseModel):
    name: str = Field("", validation_alias=AliasChoices("name", "n"))


_ALIAS_BEHIND_A_PLAIN_MODEL = [
    # (annotation, payload builder): shapes the gate does not pierce, because
    # a plain model or dataclass sits between the field and the section, so the
    # walk alone decides and must read every key a field accepts.
    (Optional[_PlainHoldsAliased], lambda m: {"sub": {"n": m}}),
    (List[_PlainHoldsAliased], lambda m: [{"sub": {"n": m}}]),
    (Dict[str, _PlainHoldsAliased], lambda m: {"k": {"sub": {"n": m}}}),
    (Optional[_PlainHoldsOnePath], lambda m: {"sub": {"n": m}}),
    (Optional[_PlainHoldsDeep], lambda m: {"sub": {"deep": {"count": m}}}),
    (Optional[_PlainAliasedInt], lambda m: {"n": m}),
]


@pytest.mark.parametrize(
    ("annotation", "build"),
    _ALIAS_BEHIND_A_PLAIN_MODEL,
    ids=[
        "plain-holds-aliaschoices",
        "list-of-plain-holds-aliaschoices",
        "dict-of-plain-holds-aliaschoices",
        "plain-holds-single-aliaspath",
        "plain-holds-nested-aliaspath",
        "plain-model-own-aliaschoices",
    ],
)
def test_a_marker_under_a_validation_alias_is_refused_behind_a_plain_model(
    annotation, build
):
    """The reader of a model's fields lists the field name and any str alias.
    A key that only an AliasChoices member or an AliasPath names was skipped,
    the marker was downcast, and the field's lax typing turned "067" into 67
    with no refusal."""

    class Section(RedactedSection):
        items: annotation = None  # type: ignore[valid-type]

    marker = env_resolved_scalar("067", VARIABLE)
    text = _refusal_text(Section, {"items": build(marker)})
    assert VARIABLE in text, text
    assert "067" not in text, text


@pydantic.dataclasses.dataclass
class _DataclassHoldsAliased:
    sub: _AliasedSection


@pydantic.dataclasses.dataclass
class _DataclassAliasedInt:
    count: int = Field(0, validation_alias=AliasChoices("count", "n"))


@pytest.mark.parametrize(
    ("annotation", "build"),
    [
        (Optional[_DataclassHoldsAliased], lambda m: {"sub": {"n": m}}),
        (Optional[_DataclassAliasedInt], lambda m: {"n": m}),
    ],
    ids=["dataclass-holds-aliased-section", "dataclass-own-aliaschoices"],
)
def test_a_marker_under_a_validation_alias_is_refused_behind_a_dataclass(
    annotation, build
):
    """A pydantic dataclass carries validation aliases like a model does, and
    a dataclass is no section, so the walk alone decides here too: it must
    read the keys the dataclass accepts as well as the section behind it."""

    class Section(RedactedSection):
        items: annotation = None  # type: ignore[valid-type]

    marker = env_resolved_scalar("067", VARIABLE)
    text = _refusal_text(Section, {"items": build(marker)})
    assert VARIABLE in text, text
    assert "067" not in text, text


class _AliasPathOwnerFirst(BaseModel):
    """The AliasPath owner is declared BEFORE the field that owns the shared
    first key, so a one-pass field reader writes the alias slot under
    "settings" first and the later field's own-name write replaces it."""

    timeout: int = Field(0, validation_alias=AliasPath("settings", "timeout"))
    settings: Optional[Dict[str, str]] = None


class _ChoiceNamesALaterField(BaseModel):
    """An AliasChoices member names a field declared later ("max"), so a
    one-pass reader's own-name write for that field replaces the member's
    slot under the shared key."""

    limit: int = Field(0, validation_alias=AliasChoices("limit", "max"))
    max: Optional[str] = None


@pytest.mark.parametrize(
    ("annotation", "build"),
    [
        (Optional[_AliasPathOwnerFirst], lambda m: {"settings": {"timeout": m}}),
        (Optional[_ChoiceNamesALaterField], lambda m: {"max": m}),
    ],
    ids=["aliaspath-owner-declared-first", "aliaschoices-member-is-a-later-field"],
)
def test_a_marker_under_an_alias_key_is_refused_whatever_the_declaration_order(
    annotation, build
):
    """A model's field reader registers every field's own name and every
    alias key it accepts. Registered in one pass, an own-name write erases
    the alias slot an earlier field put under the same key, so the refusal
    depended on declaration order: the marker under the shared key was
    downcast and the aliased field's lax typing turned "067" into 67."""

    class Section(RedactedSection):
        items: annotation = None  # type: ignore[valid-type]

    marker = env_resolved_scalar("067", VARIABLE)
    text = _refusal_text(Section, {"items": build(marker)})
    assert VARIABLE in text, text
    assert "067" not in text, text


def test_a_str_field_under_a_validation_alias_keeps_the_text_behind_a_plain_model():
    """The must-not-flag control: the same key shapes at a str field."""

    class Section(RedactedSection):
        items: Optional[_PlainAliasedStr] = None

    section = Section.model_validate(
        {"items": {"n": env_resolved_scalar("067", VARIABLE)}}
    )
    assert section.items is not None
    assert section.items.name == "067"
    assert type(section.items.name) is str


class _TypedDictAliasedInt(TypedDict):
    count: Annotated[int, Field(validation_alias=AliasChoices("count", "n"))]


class _TypedDictAliasedStr(TypedDict):
    name: Annotated[str, Field(validation_alias=AliasChoices("name", "n"))]


class _NamedTupleAliasedInt(NamedTuple):
    count: Annotated[int, Field(validation_alias=AliasChoices("count", "n"))]


class _NamedTupleAliasedStr(NamedTuple):
    name: Annotated[str, Field(validation_alias=AliasChoices("name", "n"))]


@attrs.define
class _AttrsHolder:
    count: int = 0


@pytest.mark.parametrize(
    "payload", [{"n": 67}, {"count": 67}], ids=["alias-key", "field-name"]
)
def test_a_typed_dict_takes_the_keys_its_validation_alias_names(payload):
    """Reachability: pydantic validates a TypedDict as a section's field type
    and reads a validation alias off the field's Annotated metadata, so a
    holder of this shape takes a dict by an alias key like a model does."""

    class Section(RedactedSection):
        items: Optional[_TypedDictAliasedInt] = None

    section = Section.model_validate({"items": payload})
    assert section.items == {"count": 67}


@pytest.mark.parametrize(
    "payload", [{"n": 67}, {"count": 67}, [67]], ids=["alias-key", "field-name", "list"]
)
def test_a_named_tuple_takes_the_keys_its_validation_alias_names(payload):
    """Reachability: pydantic validates a NamedTuple through an arguments
    schema whose parameters carry the validation alias, so a dict reaches a
    field by an alias key and a list reaches it by position."""

    class Section(RedactedSection):
        items: Optional[_NamedTupleAliasedInt] = None

    section = Section.model_validate({"items": payload})
    assert section.items == _NamedTupleAliasedInt(count=67)
    assert isinstance(section.items, _NamedTupleAliasedInt)


def test_an_attrs_class_is_no_field_type_for_a_section():
    """Closure for attrs: pydantic has no schema for an attrs class, so a
    section cannot declare one as a field type, and no validation alias is
    ever read off its fields."""
    with pytest.raises(PydanticSchemaGenerationError):

        class Section(RedactedSection):
            items: Optional[_AttrsHolder] = None


def test_an_attrs_class_under_arbitrary_types_takes_only_an_instance():
    """Closure for attrs, with the escape hatch the error names: the field is
    an isinstance check, so a dict (the only shape that carries a marker out
    of a config file) is refused as the wrong type and nothing is converted."""

    class Section(RedactedSection):
        model_config = ConfigDict(arbitrary_types_allowed=True)

        items: Optional[_AttrsHolder] = None

    marker = env_resolved_scalar("067", VARIABLE)
    with pytest.raises(ValidationError) as refused:
        Section.model_validate({"items": {"count": marker}})
    assert {error["type"] for error in refused.value.errors()} == {"is_instance_of"}
    held = Section.model_validate({"items": _AttrsHolder(count=67)})
    assert held.items == _AttrsHolder(count=67)


@pytest.mark.parametrize(
    ("annotation", "build"),
    [
        (Optional[_TypedDictAliasedInt], lambda m: {"n": m}),
        (Optional[_TypedDictAliasedInt], lambda m: {"count": m}),
        (Optional[_NamedTupleAliasedInt], lambda m: {"n": m}),
        (Optional[_NamedTupleAliasedInt], lambda m: [m]),
    ],
    ids=[
        "typed-dict-alias-key",
        "typed-dict-field-name",
        "named-tuple-alias-key",
        "named-tuple-position",
    ],
)
def test_a_marker_in_a_typed_dict_or_named_tuple_is_refused(annotation, build):
    """A TypedDict and a NamedTuple are no section and no model, so the walk
    alone decides here too. Both are reachable (the cells above), and a field
    of either that types the text would print the value read from the
    environment, so the marker is refused whichever key or position it
    arrives by."""

    class Section(RedactedSection):
        items: annotation = None  # type: ignore[valid-type]

    marker = env_resolved_scalar("067", VARIABLE)
    text = _refusal_text(Section, {"items": build(marker)})
    assert VARIABLE in text, text
    assert "067" not in text, text


@pytest.mark.parametrize(
    ("annotation", "build", "read"),
    [
        (
            Optional[_TypedDictAliasedStr],
            lambda m: {"n": m},
            lambda section: section.items["name"],
        ),
        (
            Optional[_NamedTupleAliasedStr],
            lambda m: {"n": m},
            lambda section: section.items.name,
        ),
        (
            Optional[_NamedTupleAliasedStr],
            lambda m: [m],
            lambda section: section.items.name,
        ),
    ],
    ids=["typed-dict-alias-key", "named-tuple-alias-key", "named-tuple-position"],
)
def test_a_str_field_in_a_typed_dict_or_named_tuple_keeps_the_text(
    annotation, build, read
):
    """The must-not-flag control: the same key shapes at a str field."""

    class Section(RedactedSection):
        items: annotation = None  # type: ignore[valid-type]

    section = Section.model_validate(
        {"items": build(env_resolved_scalar("067", VARIABLE))}
    )
    assert read(section) == "067"
    assert type(read(section)) is str


_T = TypeVar("_T")
_A = TypeVar("_A")
_B = TypeVar("_B")
_NEEDS_GENERIC_NAMED_TUPLE = pytest.mark.skipif(
    sys.version_info < (3, 11), reason="a generic NamedTuple needs Python 3.11"
)

if sys.version_info >= (3, 11):

    class _GenericNamedTuple(NamedTuple, Generic[_T]):
        count: Annotated[_T, Field(validation_alias=AliasChoices("count", "n"))]

    class _GenericTypedDict(TypedDict, Generic[_T]):
        count: Annotated[_T, Field(validation_alias=AliasChoices("count", "n"))]

    class _PairNamedTuple(NamedTuple, Generic[_A, _B]):
        first: _A
        second: _B

    _GENERIC_HOLDERS = {
        "named-tuple": _GenericNamedTuple,
        "typed-dict": _GenericTypedDict,
    }
else:
    _GENERIC_HOLDERS = {}


def _generic_holder(kind, argument):
    return Optional[_GENERIC_HOLDERS[kind][argument]]


@_NEEDS_GENERIC_NAMED_TUPLE
@pytest.mark.parametrize(
    ("kind", "payload"),
    [
        ("typed-dict", {"n": 67}),
        ("typed-dict", {"count": 67}),
        ("named-tuple", {"n": 67}),
        ("named-tuple", {"count": 67}),
        ("named-tuple", [67]),
    ],
    ids=[
        "typed-dict-alias-key",
        "typed-dict-field-name",
        "named-tuple-alias-key",
        "named-tuple-field-name",
        "named-tuple-list",
    ],
)
def test_a_parameterized_holder_takes_the_keys_its_validation_alias_names(
    kind, payload
):
    """Reachability: pydantic resolves NT[int] and TD[int] to the class with
    the type variable bound, and reads the alias like it does for the bare
    class."""
    annotation = _generic_holder(kind, int)

    class Section(RedactedSection):
        items: annotation = None  # type: ignore[valid-type]

    section = Section.model_validate({"items": payload})
    assert section.items is not None
    assert section.items["count" if kind == "typed-dict" else 0] == 67


@_NEEDS_GENERIC_NAMED_TUPLE
@pytest.mark.parametrize(
    ("kind", "build"),
    [
        ("typed-dict", lambda m: {"n": m}),
        ("typed-dict", lambda m: {"count": m}),
        ("named-tuple", lambda m: {"n": m}),
        ("named-tuple", lambda m: {"count": m}),
        ("named-tuple", lambda m: [m]),
    ],
    ids=[
        "typed-dict-alias-key",
        "typed-dict-field-name",
        "named-tuple-alias-key",
        "named-tuple-field-name",
        "named-tuple-position",
    ],
)
def test_a_marker_in_a_parameterized_holder_is_refused(kind, build):
    """A parameterized TypedDict or NamedTuple is the same holder as the bare
    class with its type variable bound, so the walk reads it the same way.

    The named-tuple-position member is a regression pin with no red state: a
    one-parameter binding to int is also refused by the walk reading the alias
    as a sequence of int. The two-parameter cell below defeats that."""
    annotation = _generic_holder(kind, int)

    class Section(RedactedSection):
        items: annotation = None  # type: ignore[valid-type]

    marker = env_resolved_scalar("067", VARIABLE)
    text = _refusal_text(Section, {"items": build(marker)})
    assert VARIABLE in text, text
    assert "067" not in text, text


@_NEEDS_GENERIC_NAMED_TUPLE
@pytest.mark.parametrize("kind", ["typed-dict", "named-tuple"])
def test_a_str_binding_of_a_parameterized_holder_keeps_the_text(kind):
    """The must-not-flag control: the type variable bound to str."""
    annotation = _generic_holder(kind, str)

    class Section(RedactedSection):
        items: annotation = None  # type: ignore[valid-type]

    section = Section.model_validate(
        {"items": {"n": env_resolved_scalar("067", VARIABLE)}}
    )
    assert section.items is not None
    held = section.items["count" if kind == "typed-dict" else 0]
    assert held == "067"
    assert type(held) is str


@_NEEDS_GENERIC_NAMED_TUPLE
def test_a_parameterized_named_tuple_takes_its_items_by_position():
    """Reachability for the two-parameter holder below."""

    class Section(RedactedSection):
        items: Optional[_PairNamedTuple[str, int]] = None

    section = Section.model_validate({"items": ["x", 67]})
    assert section.items == ("x", 67)


@_NEEDS_GENERIC_NAMED_TUPLE
def test_a_marker_at_a_later_position_of_a_parameterized_named_tuple_is_refused():
    """Defeats the accident the one-parameter cell rides on: bound to
    (str, int), a walk that reads the alias as a sequence of its first type
    argument admits the marker at position 1 as text, and only a walk that
    pairs each item with its own field refuses it at the int."""

    class Section(RedactedSection):
        items: Optional[_PairNamedTuple[str, int]] = None

    marker = env_resolved_scalar("067", VARIABLE)
    text = _refusal_text(Section, {"items": ["x", marker]})
    assert VARIABLE in text, text
    assert "067" not in text, text


@pydantic.dataclasses.dataclass
class _GenericDataclass(Generic[_T]):
    count: _T = Field(0, validation_alias=AliasChoices("count", "n"))


class _GenericModel(BaseModel, Generic[_T]):
    count: _T = Field(0, validation_alias=AliasChoices("count", "n"))


@pytest.mark.parametrize(
    "payload", [{"n": 67}, {"count": 67}], ids=["alias-key", "field-name"]
)
@pytest.mark.parametrize(
    "holder", [_GenericDataclass, _GenericModel], ids=["dataclass", "model"]
)
def test_a_parameterized_dataclass_or_model_takes_its_validation_alias_keys(
    holder, payload
):
    """Reachability: pydantic validates both with the type variable bound and
    reads the alias."""
    annotation = Optional[holder[int]]

    class Section(RedactedSection):
        items: annotation = None  # type: ignore[valid-type]

    section = Section.model_validate({"items": payload})
    assert section.items is not None
    assert section.items.count == 67


@pytest.mark.parametrize(
    "build",
    [lambda m: {"n": m}, lambda m: {"count": m}],
    ids=["alias-key", "field-name"],
)
@pytest.mark.parametrize(
    "holder", [_GenericDataclass, _GenericModel], ids=["dataclass", "model"]
)
def test_a_marker_in_a_parameterized_dataclass_or_model_is_refused(holder, build):
    """A parameterized dataclass is a typing alias of the class and the walk
    must resolve it; a parameterized model is a real subclass, which the model
    arm already reads (the closure record for that shape)."""
    annotation = Optional[holder[int]]

    class Section(RedactedSection):
        items: annotation = None  # type: ignore[valid-type]

    marker = env_resolved_scalar("067", VARIABLE)
    text = _refusal_text(Section, {"items": build(marker)})
    assert VARIABLE in text, text
    assert "067" not in text, text


@pytest.mark.parametrize(
    "holder", [_GenericDataclass, _GenericModel], ids=["dataclass", "model"]
)
def test_a_str_binding_of_a_parameterized_dataclass_or_model_keeps_the_text(holder):
    """The must-not-flag control: the type variable bound to str."""
    annotation = Optional[holder[str]]

    class Section(RedactedSection):
        items: annotation = None  # type: ignore[valid-type]

    section = Section.model_validate(
        {"items": {"n": env_resolved_scalar("067", VARIABLE)}}
    )
    assert section.items is not None
    assert section.items.count == "067"
    assert type(section.items.count) is str


def _holder_class(kind):
    return _GENERIC_HOLDERS[kind]


_COMPOSED = {
    "list-named-tuple": (
        lambda: List[_holder_class("named-tuple")[int]],
        lambda v: [{"n": v}],
        lambda section: section.items[0][0],
    ),
    "optional-dataclass": (
        lambda: Optional[_GenericDataclass[int]],
        lambda v: {"n": v},
        lambda section: section.items.count,
    ),
    "dict-typed-dict": (
        lambda: Dict[str, _holder_class("typed-dict")[int]],
        lambda v: {"k": {"n": v}},
        lambda section: section.items["k"]["count"],
    ),
}
_COMPOSED_PARAMS = [
    pytest.param("list-named-tuple", marks=_NEEDS_GENERIC_NAMED_TUPLE),
    "optional-dataclass",
    pytest.param("dict-typed-dict", marks=_NEEDS_GENERIC_NAMED_TUPLE),
]


@pytest.mark.parametrize("kind", _COMPOSED_PARAMS)
def test_a_parameterized_holder_inside_a_container_takes_its_alias_keys(kind):
    """Reachability for the composed shapes below."""
    make_annotation, build, read = _COMPOSED[kind]
    annotation = make_annotation()

    class Section(RedactedSection):
        items: annotation = None  # type: ignore[valid-type]

    section = Section.model_validate({"items": build(67)})
    assert read(section) == 67


@pytest.mark.parametrize("kind", _COMPOSED_PARAMS)
def test_a_marker_in_a_parameterized_holder_inside_a_container_is_refused(kind):
    """The outer arm (list item, Optional arm, dict value) hands the inner
    holder to the walk, which resolves the parameterized alias and reads the
    alias key behind which the marker sits."""
    make_annotation, build, _ = _COMPOSED[kind]
    annotation = make_annotation()

    class Section(RedactedSection):
        items: annotation = None  # type: ignore[valid-type]

    marker = env_resolved_scalar("067", VARIABLE)
    text = _refusal_text(Section, {"items": build(marker)})
    assert VARIABLE in text, text
    assert "067" not in text, text


_Port = NewType("_Port", int)
_Count = TypeAliasType("_Count", int)
_Ports = TypeAliasType("_Ports", List[int])
_Box = TypeAliasType("_Box", List[_T], type_params=(_T,))

_Duo = TypeAliasType("_Duo", Tuple[_A, _B], type_params=(_A, _B))
_IntMap = TypeAliasType("_IntMap", Dict[str, _T], type_params=(_T,))

#: (annotation, valid input, what it validates to, builds the input around a
#: marker). The last two members defeat an accident of the older walk, which
#: read a parameterized alias as a container of its FIRST type argument: that
#: is the item type of _Box[int] (a list of T), so the _Box cell is refused
#: without the alias ever being read and is a regression pin with no red
#: state. _Duo[str, int] pairs both items with str and _IntMap[int] reads int
#: as a dict KEY with an Any value, so a marker is admitted there.
_WRAPPED_INT_SLOTS = {
    "new-type": (Optional[_Port], 67, 67, lambda m: m),
    "new-type-in-list": (Optional[List[_Port]], [67], [67], lambda m: [m]),
    "type-alias": (Optional[_Count], 67, 67, lambda m: m),
    "type-alias-of-list": (Optional[_Ports], [67], [67], lambda m: [m]),
    "parameterized-type-alias": (Optional[_Box[int]], [67], [67], lambda m: [m]),
    "parameterized-tuple-alias": (
        Optional[_Duo[str, int]],
        ["x", 67],
        ("x", 67),
        lambda m: ["x", m],
    ),
    "parameterized-dict-alias": (
        Optional[_IntMap[int]],
        {"k": 67},
        {"k": 67},
        lambda m: {"k": m},
    ),
}


@pytest.mark.parametrize("kind", list(_WRAPPED_INT_SLOTS))
def test_a_wrapped_int_slot_takes_an_int(kind):
    """Reachability: pydantic expands a NewType and a TypeAliasType to the
    type they stand for, so each of these is an int slot."""
    annotation, valid, expected, _ = _WRAPPED_INT_SLOTS[kind]

    class Section(RedactedSection):
        items: annotation = None  # type: ignore[valid-type]

    assert Section.model_validate({"items": valid}).items == expected


@pytest.mark.parametrize("kind", list(_WRAPPED_INT_SLOTS))
def test_a_marker_at_a_wrapped_int_slot_is_refused(kind):
    """A NewType and a TypeAliasType are neither a type, a union nor a generic
    alias with arguments, so a walk that reads only those shapes finds no slot
    in them and hands the text on to the int they stand for.

    The parameterized-type-alias member is a regression pin with no red
    state (see the table above); the tuple and dict members defeat the
    accident it rides on."""
    annotation, _, _, build = _WRAPPED_INT_SLOTS[kind]

    class Section(RedactedSection):
        items: annotation = None  # type: ignore[valid-type]

    marker = env_resolved_scalar("067", VARIABLE)
    text = _refusal_text(Section, {"items": build(marker)})
    assert VARIABLE in text, text
    assert "067" not in text, text


def _prefixed(name: str) -> str:
    return "x_" + name


class _TypedDictOwnGenerator(TypedDict):
    __pydantic_config__ = ConfigDict(alias_generator=_prefixed)  # type: ignore[misc]
    count: int


class _TypedDictPlainInt(TypedDict):
    count: int


class _NamedTuplePlainInt(NamedTuple):
    count: int


class _PrefixedPlain(BaseModel):
    model_config = ConfigDict(alias_generator=_prefixed)
    sub: _TypedDictPlainInt


class _PrefixedSection(RedactedSection):
    model_config = ConfigDict(alias_generator=_prefixed)
    items: Optional[_NamedTuplePlainInt] = None


class _HoldsPrefixed(RedactedSection):
    items: Optional[_PrefixedPlain] = None


class _HoldsOwnGenerator(RedactedSection):
    items: Optional[_TypedDictOwnGenerator] = None


class _TypedDictOuterGenerator(TypedDict):
    """A TypedDict with a generator of its own around one with none: the inner
    one is built under the outer one's config, and the walk has to carry that
    config down, not read the inner holder's fields as the outer's."""

    __pydantic_config__ = ConfigDict(alias_generator=_prefixed)  # type: ignore[misc]
    inner: _TypedDictPlainInt


class _HoldsOuterGenerator(RedactedSection):
    items: Optional[_TypedDictOuterGenerator] = None


_GENERATED = {
    "typed-dict-own-config": (_HoldsOwnGenerator, lambda v: {"items": {"x_count": v}}),
    "named-tuple-section-config": (
        _PrefixedSection,
        lambda v: {"x_items": {"x_count": v}},
    ),
    "typed-dict-in-prefixed-model": (
        _HoldsPrefixed,
        lambda v: {"items": {"x_sub": {"x_count": v}}},
    ),
    "typed-dict-nested-under-generator": (
        _HoldsOuterGenerator,
        lambda v: {"items": {"x_inner": {"x_count": v}}},
    ),
}


@pytest.mark.parametrize("kind", list(_GENERATED))
def test_a_generated_alias_key_reaches_a_typed_dict_or_named_tuple(kind):
    """Reachability: pydantic applies the config in force (the TypedDict's own,
    else the class around it) to the fields of a TypedDict or NamedTuple."""
    section_type, build = _GENERATED[kind]
    section = section_type.model_validate(build(67))
    assert section.items is not None


@pytest.mark.parametrize("kind", list(_GENERATED))
def test_a_marker_behind_a_generated_alias_key_is_refused(kind):
    """A TypedDict and a NamedTuple take the keys an alias_generator makes, but
    their fields carry no alias until pydantic applies the generator while it
    builds the schema, so a walk that reads the field metadata alone lists the
    plain name and misses the generated key."""
    section_type, build = _GENERATED[kind]
    marker = env_resolved_scalar("067", VARIABLE)
    text = _refusal_text(section_type, build(marker))
    assert VARIABLE in text, text
    assert "067" not in text, text


def test_sections_under_a_root_model_keep_a_marker_at_a_str_field_as_text():
    """The must-not-flag control for the cells above: a str field keeps the
    text, downcast to a plain str, behind the RootModel."""

    class Section(RedactedSection):
        items: Optional[_NamedItems] = None

    section = Section.model_validate(
        {"items": [{"name": env_resolved_scalar("067", VARIABLE)}]}
    )
    assert section.items is not None
    assert section.items.root[0].name == "067"
    assert type(section.items.root[0].name) is str


def test_a_plain_enum_of_str_members_in_a_list_takes_the_downcast():
    class Mode(enum.Enum):
        FAST = "zz-fast-mode"

    class Section(RedactedSection):
        modes: Optional[List[Mode]] = None

    section = Section.model_validate(
        {"modes": [env_resolved_scalar("zz-fast-mode", VARIABLE)]}
    )
    assert section.modes == [Mode.FAST]


def _file_load_refusal(model_type, payload) -> str:
    """The refusal under the operator's config-file route."""
    with pytest.raises(Exception) as refused:
        model_type.model_validate(
            payload, strict=True, context={"strict_file_load": True}
        )
    return " ".join(
        f"{error['loc']}: {error['msg']}"
        for error in refused.value.errors()  # type: ignore[attr-defined]
    )


def test_the_operator_file_load_refusal_does_not_ask_for_a_retyped_field():
    """An operator who wrote the reference in a config file cannot retype a
    plugin's Python field, so the file-load refusal carries no idiom advice,
    at a scalar field and at a container's item slot."""

    class Section(RedactedSection):
        target: Optional[Path] = None
        targets: Optional[List[Path]] = None

    marker = env_resolved_scalar(CANARY, VARIABLE)
    scalar = _file_load_refusal(Section, {"target": marker})
    items = _file_load_refusal(Section, {"targets": [marker]})
    for text, field in ((scalar, "target"), (items, "targets")):
        _assert_named_not_echoed(text, field)
        assert "| str" not in text, text
        assert "Plugin authors" not in text, text


def test_the_idiom_hint_is_addressed_to_plugin_authors():
    class Section(RedactedSection):
        target: Optional[Path] = None

    text = _refusal_text(Section, {"target": env_resolved_scalar(CANARY, VARIABLE)})
    assert "Plugin authors" in text, text
    assert "`Path | str`" in text, text


def test_the_idiom_hint_for_a_container_names_the_item_slot():
    """A List[Path] option keeps its list: for a marker in the list the advice
    retypes the ITEM, never the whole option as a scalar."""

    class Section(RedactedSection):
        targets: Optional[List[Path]] = None

    marker = env_resolved_scalar(CANARY, VARIABLE)
    text = _refusal_text(Section, {"targets": [marker]})
    assert "Plugin authors" in text, text
    assert "each item" in text, text
    assert "`Path | str`" in text, text


@pytest.mark.parametrize(
    ("annotation", "noun"),
    [
        (List[Path], "list"),
        (List[Union[Path, str]], "list"),
        (Dict[str, Path], "dictionary"),
        (List[List[Path]], "list"),
        (Dict[str, List[Path]], "dictionary"),
    ],
    ids=["list-path", "list-path-or-str", "dict-str-path", "nested-list", "dict-list"],
)
def test_a_lone_marker_at_a_container_option_is_refused_by_shape_without_advice(
    annotation, noun
):
    """A bare reference at a container option is a shape mismatch that no
    retype of the items fixes (the retyped option refuses it again), so the
    message states the shape through its opening phrase and gives no advice:
    not `Path | str`, and no sentence about what the option takes, which was
    inaccurate for a union with a scalar arm and absent at nested slots."""

    class Section(RedactedSection):
        targets: Optional[annotation] = None  # type: ignore[valid-type]

    text = _refusal_text(Section, {"targets": env_resolved_scalar(CANARY, VARIABLE)})
    _assert_named_not_echoed(text, "targets")
    assert f"Input should be a valid {noun}" in text, text
    for advice in ("Plugin authors", "this option takes", "| str", "each item"):
        assert advice not in text, text


@pytest.mark.parametrize(
    "annotation",
    [Union[List[Path], Path], Union[Path, List[Path]]],
    ids=["list-first", "path-first"],
)
def test_the_hint_for_a_union_does_not_depend_on_its_arm_order(annotation):
    """The arm that refuses a lone reference is the option-level Path, so the
    advice retypes the option, whichever order the arms are written in."""

    class Section(RedactedSection):
        target: Optional[annotation] = None  # type: ignore[valid-type]

    text = _refusal_text(Section, {"target": env_resolved_scalar(CANARY, VARIABLE)})
    assert "declare this option as `Path | str`" in text, text
    assert "each item" not in text, text


_PUBLIC_URL_TYPES = sorted(
    name
    for name in pydantic.networks.__all__
    if name.endswith(("Url", "Dsn"))
    and isinstance(getattr(pydantic.networks, name), type)
)


def test_the_public_url_type_list_includes_the_multi_host_dsns():
    """Control for the list below: a vacuous parametrization would pass."""
    assert {"AnyUrl", "HttpUrl", "PostgresDsn", "MongoDsn", "NatsDsn"} <= set(
        _PUBLIC_URL_TYPES
    )


@pytest.mark.parametrize("name", _PUBLIC_URL_TYPES)
def test_every_public_url_type_is_refused_with_the_idiom_naming_it(name):
    """pydantic's multi-host DSNs (PostgresDsn, MongoDsn, NatsDsn) derive from
    a different private base than AnyUrl; the hint must reach them through the
    public type names."""
    url_type = getattr(pydantic.networks, name)

    class Section(RedactedSection):
        endpoint: Optional[url_type] = None  # type: ignore[valid-type]

    text = _refusal_text(Section, {"endpoint": env_resolved_scalar(CANARY, VARIABLE)})
    _assert_named_not_echoed(text, "endpoint")
    assert f"`{name} | str`" in text, text


def test_a_url_type_in_a_container_names_the_item_slot():
    class Section(RedactedSection):
        endpoints: Optional[List[pydantic.networks.PostgresDsn]] = None

    text = _refusal_text(
        Section, {"endpoints": [env_resolved_scalar(CANARY, VARIABLE)]}
    )
    _assert_named_not_echoed(text, "endpoints")
    assert "`PostgresDsn | str`" in text and "each item" in text, text


def _schema_nodes(schema, kind):
    """Every node of a core schema, at any depth, whose type is *kind*."""
    found = []
    pending = [schema]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            if node.get("type") == kind:
                found.append(node)
            pending.extend(node.values())
        elif isinstance(node, (list, tuple)):
            pending.extend(node)
    return found


def _typed_dict_fields(adapter):
    nodes = _schema_nodes(adapter.core_schema, "typed-dict")
    assert len(nodes) == 1, nodes
    return nodes[0]["fields"]


def _named_tuple_parameters(adapter):
    nodes = _schema_nodes(adapter.core_schema, "arguments")
    assert len(nodes) == 1, nodes
    return {param["name"]: param for param in nodes[0]["arguments_schema"]}


def test_the_public_schema_carries_a_typed_dicts_own_generated_alias():
    """Measurement for reading generated aliases through public surface: a
    TypedDict with an alias_generator in its own config."""
    fields = _typed_dict_fields(TypeAdapter(_TypedDictOwnGenerator))
    assert fields["count"]["validation_alias"] == "x_count"


def test_the_public_schema_carries_the_enclosing_generated_alias_for_a_typed_dict():
    """A TypedDict with no config of its own is built under the one around it.
    TypeAdapter refuses a config for any TypedDict, so the config goes with a
    wrapper type."""
    config = ConfigDict(alias_generator=_prefixed)
    fields = _typed_dict_fields(TypeAdapter(List[_TypedDictPlainInt], config=config))
    assert fields["count"]["validation_alias"] == "x_count"
    with pytest.raises(PydanticUserError):
        TypeAdapter(_TypedDictPlainInt, config=config)


def test_the_public_schema_carries_a_named_tuples_generated_alias():
    config = ConfigDict(alias_generator=_prefixed)
    parameters = _named_tuple_parameters(
        TypeAdapter(List[_NamedTuplePlainInt], config=config)
    )
    assert parameters["count"]["alias"] == "x_count"


@_NEEDS_GENERIC_NAMED_TUPLE
def test_the_public_schema_carries_the_alias_choices_of_a_parameterized_holder():
    """The form the core schema gives an AliasChoices, which an adapter has to
    turn back into the objects the walk's alias helper reads."""
    typed_dict = _typed_dict_fields(TypeAdapter(List[_GenericTypedDict[int]]))
    assert typed_dict["count"]["validation_alias"] == [["count"], ["n"]]
    named_tuple = _named_tuple_parameters(TypeAdapter(List[_GenericNamedTuple[int]]))
    assert named_tuple["count"]["alias"] == [["count"], ["n"]]


@pydantic.dataclasses.dataclass(config=ConfigDict(alias_generator=_prefixed))
class _PrefixedDataclass:
    count: int


def test_a_model_and_a_dataclass_carry_their_generated_aliases_publicly():
    assert _PrefixedPlain.model_fields["sub"].validation_alias == "x_sub"
    assert _PrefixedDataclass.__pydantic_fields__["count"].validation_alias == (
        "x_count"
    )


def test_a_bare_field_info_carries_no_generated_alias():
    """Why a TypedDict's or NamedTuple's hint alone is not enough: the
    generator is applied by the schema builder, not by FieldInfo."""
    info = FieldInfo.from_annotation(int)
    assert info.alias is None
    assert info.validation_alias is None


class _HeaderMap:
    """A legitimate type that consumes a mapping of strings through a core
    schema of its own: the walk cannot read what it does with the text."""

    def __init__(self, items):
        self.items = dict(items)

    @classmethod
    def __get_pydantic_core_schema__(cls, source, handler):
        return core_schema.no_info_after_validator_function(
            cls,
            core_schema.dict_schema(core_schema.str_schema(), core_schema.str_schema()),
        )


class _TagList:
    """The same, over a list of strings."""

    def __init__(self, items):
        self.items = list(items)

    @classmethod
    def __get_pydantic_core_schema__(cls, source, handler):
        return core_schema.no_info_after_validator_function(
            cls, core_schema.list_schema(core_schema.str_schema())
        )


class _StrOnlyModel(BaseModel):
    name: str = ""


@pytest.mark.parametrize(
    ("holder", "build"),
    [
        (_HeaderMap, lambda m: {"Authorization": m}),
        (_TagList, lambda m: [m]),
    ],
    ids=["header-map", "tag-list"],
)
def test_a_marker_inside_a_container_given_to_an_opaque_schema_is_refused(
    holder, build
):
    """Characterization of the break surface of failing closed. Each type is a
    legitimate pattern: it takes strings and keeps them as strings. The walk
    cannot read a custom core schema, so a marker inside the container it is
    given is refused, as a marker at its scalar slot already is. These cells
    flip from red to green with that rule, and the flip is the measurement
    that a plugin author's type of this shape stops accepting a reference."""
    annotation = Optional[holder]

    class Section(RedactedSection):
        items: annotation = None  # type: ignore[valid-type]

    marker = env_resolved_scalar("067", VARIABLE)
    text = _refusal_text(Section, {"items": build(marker)})
    assert VARIABLE in text, text
    assert "067" not in text, text


def test_a_marker_at_the_scalar_slot_of_an_opaque_schema_is_refused():
    """The rule the container cells follow: pinned, green before and after."""

    class Section(RedactedSection):
        items: Optional[_HeaderMap] = None

    text = _refusal_text(Section, {"items": env_resolved_scalar("067", VARIABLE)})
    assert VARIABLE in text, text


def test_a_container_of_str_and_a_plain_model_keep_a_marker_as_text():
    """The must-not-flag control: no opaque schema, nothing refused."""

    class Section(RedactedSection):
        mapping: Optional[Dict[str, str]] = None
        model: Optional[_StrOnlyModel] = None

    marker = env_resolved_scalar("067", VARIABLE)
    section = Section.model_validate(
        {"mapping": {"k": marker}, "model": {"name": marker}}
    )
    assert section.mapping == {"k": "067"}
    assert section.model is not None
    assert section.model.name == "067"


class _BareBag(collections.abc.Collection):
    """A user-defined Collection with no core schema: under arbitrary types
    pydantic checks instances of it, so it takes no list."""

    def __init__(self, items=()):
        self._items = list(items)

    def __len__(self):
        return len(self._items)

    def __iter__(self):
        return iter(self._items)

    def __contains__(self, item):
        return item in self._items


class _BagList(list):
    """A user-defined list subclass: a Collection too, and no more able to take
    a plain list than the class above."""


@pytest.mark.parametrize(
    "annotation",
    [
        Optional[Union[List[Path], _BareBag]],
        Optional[Union[_BareBag, List[Path]]],
        Optional[Union[List[Path], _BagList]],
    ],
    ids=["bare-collection-after", "bare-collection-before", "list-subclass"],
)
def test_a_list_behind_a_custom_collection_arm_is_refused_at_a_path_arm(annotation):
    """An arm that is a user-defined Collection cannot take a list, so it must
    not count as the arm that holds it: the sibling List[Path] arm converts the
    text, and the reference there is refused whichever order the arms are in."""

    class Section(RedactedSection):
        model_config = ConfigDict(arbitrary_types_allowed=True)

        items: annotation = None  # type: ignore[valid-type]

    text = _refusal_text(Section, {"items": [env_resolved_scalar("067", VARIABLE)]})
    assert VARIABLE in text, text
    assert "067" not in text, text


def test_a_stdlib_collection_arm_beside_a_path_arm_is_refused():
    """The must-refuse control: a stdlib collection still holds the list."""

    class Section(RedactedSection):
        items: Optional[Union[List[Path], Deque[Path]]] = None

    text = _refusal_text(Section, {"items": [env_resolved_scalar("067", VARIABLE)]})
    assert VARIABLE in text, text
    assert "067" not in text, text


def test_a_custom_collection_arm_beside_a_str_arm_keeps_the_text():
    """The must-not-flag control: a list of str has nowhere to convert."""

    class Section(RedactedSection):
        model_config = ConfigDict(arbitrary_types_allowed=True)

        items: Optional[Union[List[str], _BareBag]] = None

    section = Section.model_validate({"items": [env_resolved_scalar("067", VARIABLE)]})
    assert section.items == ["067"]


class _CountRoot(RootModel[int]):
    pass


class _Options(BaseModel):
    depth: int = 0


@pytest.mark.parametrize(
    "annotation",
    [
        Optional[Union[Literal["all"], int]],
        Union[int, Literal["all"]],
        Union[Literal["all"], float],
        Union[Literal["all"], bool],
        Union[Literal["all"], decimal.Decimal],
        Union[Literal["all"], datetime.date],
        Union[Literal["all"], Path],
        Union[Literal["all"], _Level],
        Union[Literal["all"], _CountRoot],
        Union[Literal["all"], PositiveInt],
        Annotated[Literal["all"], Field()] | int,
        Union[Literal["all"], int, List[int]],
    ],
    ids=[
        "optional-literal-or-int",
        "int-or-literal",
        "literal-or-float",
        "literal-or-bool",
        "literal-or-decimal",
        "literal-or-date",
        "literal-or-path",
        "literal-or-int-enum",
        "literal-or-root-model-of-int",
        "literal-or-positive-int",
        "annotated-literal-or-int",
        "literal-or-int-or-list",
    ],
)
def test_a_scalar_marker_at_a_literal_beside_a_converting_arm_is_refused(annotation):
    """A smart union keeps a text equal to a Literal constant and hands any
    other text to the next arm that accepts a str, so the int arm of
    ``Literal["all"] | int`` turns the read "424242" into 424242 and the
    spelling is what the redaction needle holds. The Literal arm cannot admit
    the marker while a sibling arm converts it."""

    class Section(RedactedSection):
        value: Optional[annotation] = None  # type: ignore[valid-type]

    text = _refusal_text(Section, {"value": env_resolved_scalar(CANARY, VARIABLE)})
    _assert_named_not_echoed(text, "value")


@pytest.mark.parametrize(
    "annotation",
    [
        Optional[Literal["all", "none"]],
        Union[Literal["all"], List[int]],
        Union[Literal["all"], Dict[str, int]],
        Union[Literal["all"], _Ids],
        Union[Literal["all"], _Options],
    ],
    ids=[
        "optional-literal",
        "literal-or-list-of-int",
        "literal-or-dict",
        "literal-or-root-model-of-list",
        "literal-or-model",
    ],
)
def test_a_scalar_marker_at_a_literal_with_no_converting_arm_takes_the_downcast(
    annotation,
):
    """The must-not-flag controls for the cells above: a container, a model,
    or an arm that keeps the text takes no conversion of a scalar text, so the
    Literal's constant (or the str arm) still keeps it as a plain str."""

    class Section(RedactedSection):
        value: Optional[annotation] = None  # type: ignore[valid-type]

    section = Section.model_validate({"value": env_resolved_scalar("all", VARIABLE)})
    assert section.value == "all"
    assert type(section.value) is str


class _StaticLookupSeverity(enum.Enum):
    HIGH = "HIGH"

    @staticmethod
    def _missing_(value):
        return None


def test_a_str_enum_with_a_static_missing_hook_is_refused():
    """A ``_missing_`` written as a staticmethod has no underlying function to
    compare with the stock lookup's. It is an override like any other: refused,
    naming the variable, where the comparison once raised AttributeError out of
    the validator."""

    class Section(RedactedSection):
        severity: Optional[_StaticLookupSeverity] = None

    text = _refusal_text(Section, {"severity": env_resolved_scalar("high", VARIABLE)})
    assert VARIABLE in text and "severity" in text, text
    assert "high" not in text, text


class _Target(BaseModel):
    target: Path = Path(".")


@pytest.mark.parametrize(
    ("annotation", "payload_shape"),
    [
        (_Target, lambda marker: {"target": marker}),
        (List[_Target], lambda marker: [{"target": marker}]),
        (Dict[str, _Target], lambda marker: {"a": {"target": marker}}),
    ],
    ids=["model", "list-of-models", "dict-of-models"],
)
def test_a_path_field_of_a_model_names_the_option_and_no_item(
    annotation, payload_shape
):
    """The slot that refuses is a model's field, and no list is involved at
    that slot, so the advice is to retype the field, not each item."""

    class Section(RedactedSection):
        inner: Optional[annotation] = None  # type: ignore[valid-type]

    text = _refusal_text(
        Section, {"inner": payload_shape(env_resolved_scalar(CANARY, VARIABLE))}
    )
    _assert_named_not_echoed(text, "inner")
    assert "declare this option as `Path | str`" in text, text
    assert "each item" not in text, text


@pytest.mark.parametrize(
    ("annotation", "payload_shape"),
    [
        (List[Path], lambda marker: [marker]),
        (Dict[str, Path], lambda marker: {"a": marker}),
        (Optional[List[Path]], lambda marker: [marker]),
    ],
    ids=["list-of-paths", "dict-of-paths", "optional-list-of-paths"],
)
def test_a_path_item_of_a_container_still_names_each_item(annotation, payload_shape):
    """The control for the cell above: a container's item slot keeps the
    advice that retypes each item, so the option keeps its list."""

    class Section(RedactedSection):
        targets: Optional[annotation] = None  # type: ignore[valid-type]

    text = _refusal_text(
        Section, {"targets": payload_shape(env_resolved_scalar(CANARY, VARIABLE))}
    )
    _assert_named_not_echoed(text, "targets")
    assert "declare each item of this option as `Path | str`" in text, text


class _PlainHolder:
    """A class of the code's own with no core schema."""


def _join(value):
    return ",".join(value)


class _LegacyHolder:
    """A class that builds its validation through the legacy
    ``__get_validators__`` hook alone, and so accepts a list the reader cannot
    see it taking."""

    def __init__(self, text):
        self.text = text

    @classmethod
    def __get_validators__(cls):
        yield cls._validate

    @classmethod
    def _validate(cls, value, _info):
        return cls(",".join(value))


class _UnknownMetadata:
    """Annotation metadata this module has no knowledge of."""


def _container_shapes(marker):
    return {
        "dict": {"count": marker},
        "list": [marker],
        "tuple": (marker,),
        "set": {marker},
    }


def _legacy_section():
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")

        class Section(RedactedSection):
            value: Optional[_LegacyHolder] = None

    return Section


@pytest.mark.parametrize("shape", ["dict", "list", "tuple", "set"])
@pytest.mark.parametrize(
    "annotation",
    [_PlainHolder, _BareBag, Union[_PlainHolder, _BareBag]],
    ids=["plain-class", "own-collection", "plain-or-own-collection"],
)
def test_a_container_at_a_type_checked_class_is_refused_by_the_type_check(
    annotation, shape
):
    """A class pydantic checks by isinstance, with nothing in its annotation
    that could accept a container, is judged by that check: the container is
    the wrong type, whichever shape it has, and the refusal is pydantic's."""

    class Section(RedactedSection):
        model_config = ConfigDict(arbitrary_types_allowed=True)

        items: Optional[annotation] = None  # type: ignore[valid-type]

    marker = env_resolved_scalar(CANARY, VARIABLE)
    with pytest.raises(ValidationError) as refused:
        Section.model_validate({"items": _container_shapes(marker)[shape]})
    assert {error["type"] for error in refused.value.errors()} == {"is_instance_of"}


def test_an_instance_at_a_type_checked_class_is_held():
    class Section(RedactedSection):
        model_config = ConfigDict(arbitrary_types_allowed=True)

        items: Optional[_PlainHolder] = None

    held = _PlainHolder()
    assert Section.model_validate({"items": held}).items is held


@pytest.mark.parametrize("shape", ["list", "tuple", "set"])
def test_a_container_at_a_field_with_a_before_validator_is_refused_by_name(shape):
    """The field's own validator would turn the container into a str, so the
    reference must not reach it: the named refusal stands."""
    from pydantic import BeforeValidator

    class Section(RedactedSection):
        value: Annotated[str, BeforeValidator(_join)] = ""

    marker = env_resolved_scalar(CANARY, VARIABLE)
    text = _refusal_text(Section, {"value": _container_shapes(marker)[shape]})
    _assert_named_not_echoed(text, "value")
    assert Section.model_validate({"value": ["a", "b"]}).value == "a,b"


@pytest.mark.parametrize("shape", ["list", "tuple", "set"])
def test_a_container_at_a_legacy_validators_class_is_refused_by_name(shape):
    """A class built through ``__get_validators__`` alone takes the container
    through its own validator: the named refusal stands."""
    Section = _legacy_section()
    marker = env_resolved_scalar(CANARY, VARIABLE)
    text = _refusal_text(Section, {"value": _container_shapes(marker)[shape]})
    _assert_named_not_echoed(text, "value")
    assert Section.model_validate({"value": ["a", "b"]}).value.text == "a,b"


def test_a_container_under_unrecognized_annotation_metadata_is_refused_by_name():
    """The no-path branch is an allowlist: metadata this module does not know
    is treated as one that may carry a validator, and the named refusal stays."""

    class Section(RedactedSection):
        model_config = ConfigDict(arbitrary_types_allowed=True)

        items: Optional[Annotated[_PlainHolder, _UnknownMetadata()]] = None

    marker = env_resolved_scalar(CANARY, VARIABLE)
    text = _refusal_text(Section, {"items": [marker]})
    _assert_named_not_echoed(text, "items")


def test_a_container_at_a_builtin_scalar_keeps_the_named_refusal():
    """A builtin scalar is not on the allowlist: pydantic's check for it is not
    an isinstance check of a class the code owns, so the named refusal stays."""

    class Section(RedactedSection):
        flag: Optional[bool] = None

    marker = env_resolved_scalar(CANARY, VARIABLE)
    text = _refusal_text(Section, {"flag": [marker]})
    _assert_named_not_echoed(text, "flag")


def test_first_env_scalar_returns_the_first_reference_in_a_list():
    """``first_env_scalar`` promises document order: the scalar that comes
    back is the first one in the order the config file wrote, so a refusal
    that names one variable names the first. The cell pins the contract, not
    the walk's mechanism: any traversal that reads items in document order
    passes."""
    first = env_resolved_scalar(CANARY, "ASH_SHAPE_FIRST")
    second = env_resolved_scalar(CANARY, "ASH_SHAPE_SECOND")

    found = first_env_scalar([first, second])

    assert found is not None
    assert found.variable == "ASH_SHAPE_FIRST", found.variable


def test_first_env_scalar_returns_the_first_reference_in_a_mapping():
    """Mapping values are read in the mapping's own order, which is the order
    the config file wrote, so the first value's reference comes back."""
    first = env_resolved_scalar(CANARY, "ASH_SHAPE_FIRST")
    second = env_resolved_scalar(CANARY, "ASH_SHAPE_SECOND")

    found = first_env_scalar({"a": first, "b": second})

    assert found is not None
    assert found.variable == "ASH_SHAPE_FIRST", found.variable


def test_first_env_scalar_reads_a_nested_first_before_a_later_sibling():
    """Depth first: a reference inside the first item comes back before the
    next item at the outer level, in a list and in a mapping. A breadth-first
    walk returns the later sibling for both shapes; the previous
    last-in-first-out walk returns it too, so the cell tells both apart from
    the contract."""
    first = env_resolved_scalar(CANARY, "ASH_SHAPE_FIRST")
    second = env_resolved_scalar(CANARY, "ASH_SHAPE_SECOND")

    in_a_mapping = first_env_scalar([{"k": first}, second])
    in_a_list = first_env_scalar([[first], second])

    assert in_a_mapping is not None
    assert in_a_mapping.variable == "ASH_SHAPE_FIRST", in_a_mapping.variable
    assert in_a_list is not None
    assert in_a_list.variable == "ASH_SHAPE_FIRST", in_a_list.variable


class _AscendingSet(set):
    """A set that iterates its members by ascending variable name, whatever
    order the hash table would give: the iteration order a walk that takes
    the set as it comes would turn into its last pick."""

    def __iter__(self):
        return iter(sorted(super().__iter__(), key=lambda member: member.variable))


def test_first_env_scalar_names_the_same_set_member_whatever_the_iteration_order():
    """A set keeps no document order (YAML's ``!!set`` parses into one), so the
    member that comes back is chosen by variable name: the smallest, on every
    run. With the members iterating in ascending order, a walk that took them
    as they come would return the largest."""
    # A reference is a str, so members with the same text would collapse to
    # one set entry: each member gets its own text.
    members = [
        env_resolved_scalar(f"{CANARY}{number}", f"ASH_SHAPE_MEMBER_{number:02d}")
        for number in range(8)
    ]

    found = first_env_scalar(_AscendingSet(members))

    assert found is not None
    assert found.variable == "ASH_SHAPE_MEMBER_00", found.variable


def test_first_env_scalar_names_the_smallest_name_in_a_large_plain_set():
    """The same contract on a plain set, where the hash table decides the
    iteration order: 64 members make an unordered pick land on the smallest
    name about once in 64 runs."""
    members = {
        env_resolved_scalar(f"{CANARY}{number}", f"ASH_SHAPE_MEMBER_{number:02d}")
        for number in range(64)
    }
    assert len(members) == 64, "control: the members are distinct set entries"

    found = first_env_scalar(members)

    assert found is not None
    assert found.variable == "ASH_SHAPE_MEMBER_00", found.variable


def test_first_env_scalar_still_answers_for_a_set_by_whether_it_holds_a_reference():
    """Ordering a set changes which reference comes back, not whether one
    does: a set of references answers, a set of plain text and an empty set
    answer None, and a reference in a set that follows a plain set inside a
    list is still found."""
    reference = env_resolved_scalar(CANARY, "ASH_SHAPE_FIRST")

    assert first_env_scalar({reference}) is not None
    assert first_env_scalar({"plain", "text"}) is None
    assert first_env_scalar(set()) is None
    found = first_env_scalar([{"plain"}, {reference}])
    assert found is not None
    assert found.variable == "ASH_SHAPE_FIRST", found.variable
