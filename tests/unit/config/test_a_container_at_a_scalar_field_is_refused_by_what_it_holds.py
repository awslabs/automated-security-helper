# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A list or mapping holding an environment reference at a scalar field is
refused for being a container, naming the first reference it holds.

A section field that is a boolean, a number, a str, a Path, a Literal or an
Enum has no slot for a list or a mapping. When the container holds a
``${VAR}`` reference, the section's validator refuses it by name before the
field's own validation can end in pydantic's error, which names no variable.
The refusal says what is wrong, which is the container: the field "holds a
list where a string is expected". A bare reference at a str, a Path-or-str, a
Literal or a str Enum loads, so the message must not call the reference
refused at the field, ask for the value to be written in the file, or tell a
plugin author to declare a type the field already has: following that advice
leads to a second refusal by the same rule.

The opening phrase is pydantic's own for the type ("Input should be a valid
string"), spelled the way pydantic spells it for every scalar, so a load that
pins the standing "Input should be a valid ..." refusal reads this one the
same. The variable named is the first reference in reading order, which is
what the validator's docstring says.

The last cell pins an order the rule has: the section's validator runs before
a field's own BeforeValidator, so a field that joins a list into a str is
refused outright when the list holds a reference. No field of the section
family does this today (the census is in the body of the commit that rewords the
refusal, "a container at a scalar field is refused by what it holds").
"""

import enum
from pathlib import Path
from typing import Annotated, Any, Literal, Optional

import pytest
from pydantic import BeforeValidator, RootModel, SecretStr, ValidationError

from automated_security_helper.utils.redacted_model import (
    RedactedSection,
    env_resolved_scalar,
    first_env_scalar,
)

pytestmark = pytest.mark.unit

CANARY = "424242-the-resolved-text"
VARIABLE = "ASH_CONTAINER_CANARY"


class _Mode(str, enum.Enum):
    a = "a"
    b = "b"


class _Count(RootModel[int]):
    pass


class _Which(RootModel[Literal["a", "b"]]):
    pass


#: annotation, pydantic's opening phrase for it, what the slot expects.
#:
#: The Path-or-str shape is written with ``|``: a ``types.UnionType`` keeps the
#: arms in the order written, where ``typing.Union`` subscriptions are cached by
#: equality, so ``Optional[Union[Path, str]]`` returns the spelling with the arms
#: reversed in a process that subscripted ``Union[str, Path]`` first, and the
#: words below would then depend on which module was imported before this one.
#: SecretStr is not a shape of this rule: a class that builds its own pydantic
#: schema is read as one that may take a container, so the section leaves the
#: container to the field's own validation.
_SHAPES = {
    "bool": (bool, "a valid boolean", "a boolean"),
    "optional-bool": (Optional[bool], "a valid boolean", "a boolean"),
    "int": (int, "a valid integer", "an integer"),
    "float": (float, "a valid number", "a number"),
    "str": (str, "a valid string", "a string"),
    "optional-str": (Optional[str], "a valid string", "a string"),
    "path": (Path, "a valid path", "a path"),
    "optional-path": (Optional[Path], "a valid path", "a path"),
    "path-or-str": (
        Path | str | None,
        "a valid path or string",
        "a path or a string",
    ),
    "literal": (Literal["a", "b"], "'a' or 'b'", "one of 'a', 'b'"),
    "str-enum": (_Mode, "'a' or 'b'", "one of 'a', 'b'"),
}

#: Shapes the refusal also reaches: annotation, pydantic's opening phrase for
#: it, what the slot expects. A RootModel field is worded by the type it
#: validates, not by its class name, and a lone Literal constant is shown bare
#: rather than as "one of 'all'".
_SHAPES_ROOT_AND_LONE = {
    "root-model-int": (_Count, "a valid integer", "an integer"),
    "root-model-literal": (_Which, "'a' or 'b'", "one of 'a', 'b'"),
    "optional-root-model-int": (_Count | None, "a valid integer", "an integer"),
    "single-literal": (Literal["all"], "'all'", "'all'"),
    "optional-single-literal": (Literal["all"] | None, "'all'", "'all'"),
}

_FILE_ROUTE = {"strict": True, "context": {"strict_file_load": True}}
_ROUTES = {"file": _FILE_ROUTE, "plugin": {}}

#: A tuple or a set holds a reference as a list does. No parser yields either:
#: a Python caller's section value reaches the refusal this way.
_OTHER_CONTAINERS = {
    "tuple": lambda marker: (marker,),
    "set": lambda marker: {marker},
}


def _section(annotation):
    class Section(RedactedSection):
        value: annotation = None  # type: ignore[valid-type]

    return Section


def _refusal(model_type, payload, **arguments) -> str:
    """The one error pydantic holds for a container the section validator
    refused: a value error whose message is the validator's."""
    with pytest.raises(ValidationError) as refused:
        model_type.model_validate(payload, **arguments)
    problems = refused.value.errors(include_url=False)
    assert len(problems) == 1, problems
    assert problems[0]["type"] == "value_error", problems
    return problems[0]["msg"]


@pytest.mark.parametrize("route", sorted(_ROUTES))
@pytest.mark.parametrize("shape", sorted(_SHAPES))
@pytest.mark.parametrize(
    ("container", "payload_of"),
    [
        ("a list", lambda marker: [marker]),
        ("a mapping", lambda marker: {"key": marker}),
    ],
    ids=["list", "mapping"],
)
def test_a_container_at_a_scalar_field_says_what_it_holds_and_what_is_expected(
    shape, route, container, payload_of
):
    annotation, opener, expected = _SHAPES[shape]
    marker = env_resolved_scalar(CANARY, VARIABLE)

    message = _refusal(
        _section(annotation), {"value": payload_of(marker)}, **_ROUTES[route]
    )

    assert message == (
        f"Value error, Input should be {opener}: value holds {container} "
        f"where {expected} is expected; it holds a reference to {VARIABLE}."
    )
    assert CANARY not in message


def _assert_refused_for_what_it_holds(message: str, opener: Optional[str]) -> None:
    """The parts of the refusal every shape and every container shares: pydantic's
    opening phrase (where *opener* is given), the field, what it holds, and the
    reference, with the resolved text left out. The word for the container and
    the words for what the slot expects are not asserted."""
    head = "Value error, Input should be "
    tail = f" is expected; it holds a reference to {VARIABLE}."
    assert message.startswith(head), message
    if opener is not None:
        assert message.startswith(f"{head}{opener}: value holds "), message
    assert ": value holds " in message, message
    assert message.endswith(tail), message
    assert CANARY not in message


@pytest.mark.parametrize("route", sorted(_ROUTES))
@pytest.mark.parametrize("shape", sorted(_SHAPES))
@pytest.mark.parametrize("container", sorted(_OTHER_CONTAINERS))
def test_a_tuple_or_a_set_at_a_scalar_field_is_refused_for_what_it_holds(
    shape, route, container
):
    annotation, opener, _expected = _SHAPES[shape]
    marker = env_resolved_scalar(CANARY, VARIABLE)

    message = _refusal(
        _section(annotation),
        {"value": _OTHER_CONTAINERS[container](marker)},
        **_ROUTES[route],
    )

    _assert_refused_for_what_it_holds(message, opener)


@pytest.mark.parametrize("route", sorted(_ROUTES))
@pytest.mark.parametrize("shape", sorted(_SHAPES_ROOT_AND_LONE))
@pytest.mark.parametrize(
    "container",
    ["list", "mapping", *sorted(_OTHER_CONTAINERS)],
)
def test_a_container_is_refused_at_a_root_model_and_at_a_lone_literal(
    shape, route, container
):
    annotation, opener, expected = _SHAPES_ROOT_AND_LONE[shape]
    marker = env_resolved_scalar(CANARY, VARIABLE)
    payloads = {
        "list": [marker],
        "mapping": {"key": marker},
        **{name: make(marker) for name, make in _OTHER_CONTAINERS.items()},
    }
    words = {
        "list": "a list",
        "mapping": "a mapping",
        "tuple": "a tuple",
        "set": "a set",
    }

    message = _refusal(
        _section(annotation), {"value": payloads[container]}, **_ROUTES[route]
    )

    _assert_refused_for_what_it_holds(message, opener)
    assert message == (
        f"Value error, Input should be {opener}: value holds {words[container]} "
        f"where {expected} is expected; it holds a reference to {VARIABLE}."
    )


@pytest.mark.parametrize("route", sorted(_ROUTES))
@pytest.mark.parametrize("shape", sorted(_SHAPES))
@pytest.mark.parametrize(
    ("container", "word"), [("tuple", "a tuple"), ("set", "a set")]
)
def test_a_tuple_or_a_set_is_named_by_its_kind_not_as_a_list(
    shape, route, container, word
):
    annotation, opener, expected = _SHAPES[shape]
    marker = env_resolved_scalar(CANARY, VARIABLE)

    message = _refusal(
        _section(annotation),
        {"value": _OTHER_CONTAINERS[container](marker)},
        **_ROUTES[route],
    )

    assert message == (
        f"Value error, Input should be {opener}: value holds {word} "
        f"where {expected} is expected; it holds a reference to {VARIABLE}."
    )


@pytest.mark.parametrize("shape", sorted(_SHAPES))
def test_the_refusal_of_a_container_gives_no_advice_a_second_refusal_follows(shape):
    """The container is the problem. The reference is not refused at the field,
    the value is not asked for in the file, and a plugin author is not told to
    declare a type the field may already have."""
    annotation, _opener, _expected = _SHAPES[shape]
    marker = env_resolved_scalar(CANARY, VARIABLE)

    message = _refusal(_section(annotation), {"value": [marker]})

    for advice in (
        "refused at this field",
        "Write the value in the file",
        "Plugin authors",
        "declare this option as",
        "Path | str",
    ):
        assert advice not in message, message


def test_a_container_at_the_scanner_option_that_is_a_path_or_a_str_names_the_list():
    """The real shape the review named: checkov's ``config_file``, a
    ``Path | str | None``. A list there is refused for being a list, not
    advised to declare the type the field has."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        CheckovScannerConfigOptions,
    )

    marker = env_resolved_scalar(CANARY, VARIABLE)

    message = _refusal(CheckovScannerConfigOptions, {"config_file": [marker]})

    assert message == (
        "Value error, Input should be a valid path or string: config_file holds "
        "a list where a path or a string is expected; it holds a reference to "
        f"{VARIABLE}."
    )


@pytest.mark.parametrize(
    ("annotation", "text"),
    [
        (str, "x"),
        (Optional[str], "x"),
        (SecretStr, "x"),
        (Path | str | None, "x"),
        (Literal["a", "b"], "a"),
        (_Mode, "a"),
    ],
    ids=["str", "optional-str", "secret-str", "path-or-str", "literal", "str-enum"],
)
def test_a_lone_reference_at_the_same_fields_still_loads(annotation, text):
    """The control for the wording above: it is the container that is refused,
    because a bare reference is kept as text at each of these fields."""
    section = _section(annotation).model_validate(
        {"value": env_resolved_scalar(text, VARIABLE)}
    )

    assert section.value is not None


_FIRST = env_resolved_scalar("the-first-text", "ASH_THE_FIRST_REFERENCE")
_SECOND = env_resolved_scalar("the-second-text", "ASH_THE_SECOND_REFERENCE")


def _shared():
    inner = [_FIRST]
    return [inner, inner, _SECOND]


def _cyclic():
    loop: list[Any] = [_FIRST]
    loop.append(loop)
    loop.append(_SECOND)
    return loop


@pytest.mark.parametrize(
    "value",
    [
        [_FIRST, _SECOND],
        [_FIRST, "plain", _SECOND],
        ["plain", _FIRST, _SECOND],
        [[_FIRST], _SECOND],
        [[_FIRST, _SECOND]],
        [{"key": _FIRST}, _SECOND],
        {"first": _FIRST, "second": _SECOND},
        {"first": [_FIRST], "second": _SECOND},
        {"first": {"deeper": [_FIRST]}, "second": [_SECOND]},
        [[[[_FIRST]]], [[_SECOND]]],
        (_FIRST, _SECOND),
        _shared(),
        _cyclic(),
    ],
    ids=[
        "list",
        "list-after-plain",
        "list-before-plain",
        "nested-first",
        "nested-both",
        "dict-in-list",
        "dict",
        "dict-of-list",
        "dict-deeper",
        "deep",
        "tuple",
        "shared",
        "cyclic",
    ],
)
def test_the_first_reference_in_reading_order_is_the_one_returned(value):
    assert first_env_scalar(value) is _FIRST


def test_a_reference_alone_and_a_value_with_none_are_answered():
    assert first_env_scalar(_SECOND) is _SECOND
    assert first_env_scalar(["plain", {"key": ("also", "plain")}]) is None
    # A key is read too, before its value: a reference written as a mapping
    # key would otherwise reach pydantic unseen (tests/unit/utils/
    # test_redacted_model_dict_keys.py pins the whole route).
    assert first_env_scalar({_FIRST: "a key is a value too"}) is _FIRST


@pytest.mark.parametrize("route", sorted(_ROUTES))
@pytest.mark.parametrize(
    "payload",
    [
        [_FIRST, _SECOND],
        {"a": _FIRST, "b": _SECOND},
        [[_FIRST], [_SECOND]],
    ],
    ids=["list", "mapping", "nested"],
)
def test_the_refusal_names_the_first_reference_the_container_holds(payload, route):
    message = _refusal(_section(bool), {"value": payload}, **_ROUTES[route])

    assert "ASH_THE_FIRST_REFERENCE" in message, message
    assert "ASH_THE_SECOND_REFERENCE" not in message, message


def test_a_field_that_joins_a_list_is_refused_when_the_list_holds_a_reference():
    """The pinned order and its limit. The section's validator runs before a
    field's own BeforeValidator, so a field that downcasts a list is refused
    outright when the list holds a reference, naming the variable. The same
    list with no reference reaches the field's validator and is joined, so the
    refusal is the order and not a field that never accepted a list. A field of
    a section that later adds such a validator is refused the same way: this
    cell documents that order, and the shape that would lift the limit (a wrap
    validator handing on the downcast value) is not built."""

    def join(value: Any) -> Any:
        return ",".join(value) if isinstance(value, list) else value

    section_type = _section(Annotated[str, BeforeValidator(join)])

    assert section_type.model_validate({"value": ["a", "b"]}).value == "a,b"

    message = _refusal(section_type, {"value": [_FIRST, "b"]})
    assert "ASH_THE_FIRST_REFERENCE" in message, message
    assert "the-first-text" not in message, message
