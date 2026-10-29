# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Models whose repr and str show what their configuration read from the
environment as ``<value>``.

A configuration (config/ash_config.AshConfig) records the values its files read
through ``${VAR}``. Its sections hold those values in their fields too, and a
section is printed on its own wherever a traceback with locals
(show_debug_locals) renders a frame that holds one, or a model or list that
holds one. Each model a configuration can hold is a :class:`RedactedSection`:
it carries the configuration's values in a record of its own, and its repr and
str redact with them. Imports only pydantic (and typing_extensions, which
pydantic itself requires) and the standard library, so the models of every
layer can use it.
"""

import collections.abc
import contextlib
import contextvars
import dataclasses
import enum
import os
import pathlib
import types
import typing
from typing import (
    Annotated,
    Any,
    ClassVar,
    Dict,
    FrozenSet,
    Iterable,
    Iterator,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
    TypeVar,
    Union,
    get_args,
    get_origin,
    get_type_hints,
)

import typing_extensions
from pydantic import networks as pydantic_networks
from pydantic import (
    AliasChoices,
    AliasPath,
    BaseModel,
    ConfigDict,
    PrivateAttr,
    RootModel,
    SecretBytes,
    SecretStr,
    TypeAdapter,
    ValidationInfo,
    field_validator,
)
from pydantic.errors import PydanticSchemaGenerationError
from pydantic.fields import FieldInfo
from pydantic_core import MultiHostUrl, Url


def environment_strings(values: Any) -> Tuple[str, ...]:
    """*values* as the strings a redaction takes, each non-empty: the one
    normalizer every sink reads a caller's values through.

    One string given on its own is ONE value, never its characters. A str is
    an iterable of strings too, one per character, so ``list()``, ``tuple()``,
    unpacking and ``dict.fromkeys`` of a value given on its own are its
    characters. Each is shorter than any band config_validator.redact_values
    replaces, so the value would print whole, and nothing would show that
    redaction had stopped. A bare ``os.PathLike`` is one value too
    (:func:`_path_text`), and a PathLike entry inside an iterable is converted
    rather than filtered out: an environment-chosen directory is a value a
    command line and a report both print. Any other iterable yields its
    non-empty string entries; a non-iterable gives none.

    What this does not cover, and what it costs:

    - Only the top level and one iterable level are read. A Path nested in a
      list inside the iterable is not a string, so it is dropped, and its
      value prints in clear.
    - A path's needle is the one text :func:`_path_text` takes: its
      ``os.fspath`` spelling, that spelling decoded when it is bytes, or its
      ``str()`` when ``os.fspath`` raises. Text that prints the path another
      way, such as a Windows path printed with ``as_posix``'s forward slashes,
      is not matched.
    - A path is a substring needle like any value: a short one such as
      ``Path("/tmp")`` replaces itself wherever that text appears, exactly as
      the str ``"/tmp"`` would. The ``str()`` fallback costs the same way: an
      object whose ``__str__`` gives ``"None"`` redacts the word None wherever
      it is printed.
    """
    if isinstance(values, (str, os.PathLike)):
        values = (values,)
    try:
        entries = tuple(values)
    except TypeError:
        return ()
    normalized = []
    for value in entries:
        if isinstance(value, os.PathLike):
            value = _path_text(value)
        if isinstance(value, str) and value:
            normalized.append(value)
    return tuple(normalized)


def _path_text(value: "os.PathLike[Any]") -> Optional[str]:
    """The text of a PathLike *value* as a needle: ``os.fspath``, decoded when it
    gives bytes, else ``str(value)`` when ``os.fspath`` raises (as it does when
    ``__fspath__`` raises or returns something other than str or bytes); None
    when neither gives text.

    Taking the text another way rather than dropping the entry keeps its value
    redacted: a dropped entry's value printed in clear. Nothing here raises,
    because the callers are printers and raising would replace the text being
    printed.
    """
    try:
        text = os.fspath(value)
    except Exception:  # noqa: BLE001 -- see the docstring
        try:
            return str(value)
        except Exception:  # noqa: BLE001 -- see the docstring
            return None
    if isinstance(text, bytes):
        try:
            return os.fsdecode(text)
        except Exception:  # noqa: BLE001 -- see the docstring
            return None
    return text


def value_tuple(values: Iterable[str]) -> Tuple[str, ...]:
    """*values* through :func:`environment_strings`, under the name the
    needle-building callers read. One string given on its own is one value."""
    return environment_strings(values)


class _EnvironmentRecord:
    """The values a section's configuration read from the environment.

    Not part of the section's value: every record equals every other, so two
    sections with the same fields are equal whatever each carries, and a
    section stays equal to its default (model_dump's exclude_defaults compares
    the two).
    """

    __slots__ = ("values",)

    def __init__(self, values: Tuple[str, ...] = ()) -> None:
        self.values = values

    def __eq__(self, other: object) -> Any:
        if isinstance(other, _EnvironmentRecord):
            return True
        # Not this record's comparison to answer: left to the other side, so a
        # stand-in that equals anything (unittest.mock.ANY) equals a record
        # from either side, and anything else compares unequal as usual.
        return NotImplemented

    __hash__ = None  # type: ignore[assignment]

    def __getstate__(self) -> Tuple[str, ...]:
        return self.values

    def __setstate__(self, state: Tuple[str, ...]) -> None:
        self.values = state

    def __repr__(self) -> str:
        return "_EnvironmentRecord(...)"


def _no_rich_repr(model: Any) -> Any:
    raise AttributeError("__rich_repr__")


#: ``__rich_repr__`` for a model whose repr is redacted. Rich's pretty printer,
#: which a traceback with locals (show_debug_locals) renders with, calls a
#: model's ``__rich_repr__`` when the model has one, and pydantic gives every
#: model one that yields each field's raw value, around the redacted repr.
#: Reading this one raises AttributeError, so the model has none and Rich
#: prints its repr.
NO_RICH_REPR = property(_no_rich_repr)


class EnvResolvedScalar(str):
    """A config scalar resolved from an environment reference.

    ``resolve_env_references`` (the YAML ``!ENV`` constructor, shared by the
    TOML config source) returns one for text read from the environment, or
    from a reference's default. It is a plain str to every consumer; the
    variable's name rides along so a typed field that cannot parse the text
    can name the variable without echoing the value, which may have been
    read from the environment. The form a surface shows in the value's place
    rides along too (``shown``), with the branch the resolver took
    (``from_environment``). When the variable was read, ``shown`` is the
    reference without its default and with any glued tail, ``${VAR}tail``: a
    default printed beside a variable that was set would show a level that is
    not the one in effect. When the default was used, ``shown`` is the value
    itself, which is the file's own text and not a secret. ``shown`` is not
    the reference as the file wrote it, which is what
    ``EnvironmentReference.written`` holds. Neither slot is named ``read``: a
    str with a ``read`` attribute passes the ``hasattr(x, "read")`` file-like
    test, and a caller such as ``ElementTree.parse`` would call it.

    Built only through :func:`env_resolved_scalar`. The class defines no
    constructor of its own: the shown-text invariant forbids any ``__new__``
    outside the one maker of shown text, and str's own copy protocol
    (``__getnewargs__`` plus the slots' state) carries all three slots,
    ``variable``, ``shown`` and ``from_environment``, through copy, deepcopy
    and pickle without one. tests/unit/utils/
    test_env_resolved_scalar_survives_copying.py pins that for each copy form.

    Instances never survive into a validated model: at a field whose type
    cannot keep the text as it is (a number, Decimal, date, Path, URL, or a
    container with such a slot) the section base's before-validator refuses
    the reference, or for a field the section names in
    :attr:`RedactedSection._env_scalar_typed_fields` hands the text to the
    field's own validation, which types it or refuses it; every other field
    (str, SecretStr, an Enum whose members are all str and whose
    ``_missing_`` is the stock one, a union with a str arm, ...) keeps the
    text downcast to plain str, because a str subclass has no representer in
    PyYAML's SafeDumper and would fail a config dump.

    A section a model keeps without validating it still carries instances:
    the segment models hold an external plugin's config as an extra, and a
    python-mode ``model_dump`` returns its values as they are. Such a section
    is validated later, by the plugin's own config model, and the instances
    must survive until then so a typed field there can still name the
    variable. A consumer that reads the section WITHOUT validating it views
    it through :func:`without_env_scalars` first: read directly, an instance
    answers ``type(value).__name__`` with this class's name, which is no
    answer a message about a config value should give (a reporter's
    not-enabled warning printed it), and a str subclass fails any later
    SafeDumper write.
    """

    __slots__ = ("variable", "shown", "from_environment")

    variable: str
    shown: str
    from_environment: bool


def env_resolved_scalar(
    text: str,
    variable: str,
    shown: Optional[str] = None,
    from_environment: bool = True,
) -> EnvResolvedScalar:
    """*text* as an :class:`EnvResolvedScalar` carrying *variable*'s name.

    *shown* is the form a shown surface prints in the value's place (see
    the class); *from_environment* is False when the reference's default
    supplied the text because the variable was unset. A caller that has only
    the name (the test fixtures) leaves both out and gets the bare
    ``${variable}`` form of a variable that was read.
    """
    resolved = EnvResolvedScalar(text)
    resolved.variable = variable
    resolved.shown = shown or "${" + variable + "}"
    resolved.from_environment = from_environment
    return resolved


#: pydantic's own noun for each scalar type, as its "Input should be a valid
#: ..." messages spell it. The refusal below opens with that exact phrase so a
#: reader (and the standing tests) see the one wording whether the refusal
#: came from this validator or from a strict load's own typing.
_ENV_SCALAR_SPELLING = {
    bool: "boolean",
    int: "integer",
    float: "number",
    str: "string",
    SecretStr: "string",
    SecretBytes: "bytes",
}


#: The classes a type alias (``type X = ...``, or ``TypeAliasType("X", ...)``)
#: is an instance of. On Python 3.12 and 3.13 typing_extensions defines a
#: TypeAliasType of its own instead of re-exporting typing's, so an alias the
#: ``type`` statement makes (a typing.TypeAliasType) matched an isinstance
#: check against typing_extensions' class on neither version and was never
#: unwrapped: a scalar alias over a number admitted a reference, and a
#: container or section alias hid its slots. Both classes are read.
_TYPE_ALIAS_TYPES: Tuple[type, ...] = tuple(
    dict.fromkeys(
        kind
        for kind in (
            typing_extensions.TypeAliasType,
            getattr(typing, "TypeAliasType", None),
        )
        if isinstance(kind, type)
    )
)


def _unwrap_annotated(annotation: Any, seen: Optional[Set[Any]] = None) -> Any:
    """The underlying type of an Annotated shape, a NewType or a TypeAliasType
    (parameterized or not), which pydantic expands to the type they stand for;
    anything else unchanged.

    None of the three is a type, a union or a generic alias with arguments of
    its own, so a reader that looks only at those finds no slot in them. An
    alias that names itself comes back as Any the second time it is met in
    *seen* (shared by a caller that recurses), so the unwrapping ends."""
    if seen is None:
        seen = set()
    while True:
        origin = get_origin(annotation)
        if origin is Annotated:
            annotation = get_args(annotation)[0]
        elif hasattr(annotation, "__supertype__"):
            annotation = annotation.__supertype__
        elif isinstance(annotation, _TYPE_ALIAS_TYPES) or isinstance(
            origin, _TYPE_ALIAS_TYPES
        ):
            if annotation in seen:
                return Any
            seen.add(annotation)
            alias = annotation if origin is None else origin
            try:
                value = alias.__value__
            except Exception:  # a name the alias refers to is not defined
                return Any
            parameters = getattr(alias, "__type_params__", ()) if origin else ()
            annotation = (
                _bound(value, dict(zip(parameters, get_args(annotation))))
                if parameters
                else value
            )
        else:
            return annotation


def _admits_plain_str(annotation: Any, text: Optional[str] = None) -> bool:
    """Whether a plain str can land at *annotation* without conversion.

    *text* is the marker's resolved text when the caller has it. It matters
    to one family only: an Enum that overrides ``_missing_`` admits *text*
    that equals a member value exactly, and refuses any other.

    The refusal of environment references keys on this, not on a list of
    known scalar types. An earlier version recognized only bare and Optional
    int, float and bool, so every other typed shape -- a constrained or
    Annotated number, a union of numbers, Decimal, date -- was downcast and
    typed silently by a lax model, converting the env-read text into a
    spelling the redaction needle never matches ("067" read as 67). A slot
    that cannot keep the text would convert it, so it refuses; a shape this
    reader cannot interpret (a TypeVar, a protocol, an unparameterized
    container at the slot) admits, which keeps the downcast the default
    where nothing is known to convert.

    Two typed families admit although they convert. SecretStr and
    SecretBytes mask their value in repr and str, so the converted value
    never prints. An Enum whose members are all str selects among the code's
    own declared constants: the text equals one of them, and the member
    prints as that constant, the text the needle matches. An Enum with a
    non-str member (IntEnum, IntFlag, a plain Enum of numbers) stays
    refused: a lax model matches "067" to member 67 through int coercion
    and the member prints as 67, a spelling the needle never matches. So
    does an Enum that overrides ``_missing_``, for text that equals no
    member value: the hook runs on that text and may map it to a member
    spelled differently. Text that equals a member value exactly never
    reaches the hook, so it is admitted.
    A Literal of str constants keeps a text that equals one of them, and any
    other text falls to the union's other arms, so in a union a Literal arm
    admits only when no other arm converts a str (:func:`_converts_a_plain_str`):
    ``Literal["all"] | int`` is refused, because a lax union turns "067" into 67
    through the int arm, and ``Literal["all"] | List[int]`` still admits.
    A str-valued Enum arm and a constrained str arm are read the same way
    in a union (:func:`_admits_conditionally`): each keeps SOME text and
    refuses the rest, and the rest falls to a sibling, so ``int | StrEnum``
    admits only text that equals a member value, and ``int | Annotated[str,
    Field(pattern=...)]`` is refused outright, since the pattern is not read.
    Path and URL types stay refused: their normalization
    rewrites the spelling ("./x" to "x", "a//b" to "a/b", a lowercased
    scheme and host), which the redaction needle then fails to match; a
    ``Path | str`` (or ``AnyUrl | str``) option accepts a reference through
    the union's str arm.
    """
    annotation = _unwrap_annotated(annotation)
    if annotation is Any or annotation is object or annotation is str:
        return True
    origin = get_origin(annotation)
    if origin in (Union, types.UnionType):
        arms = [arg for arg in get_args(annotation) if arg is not type(None)]
        # An arm that keeps ANY str (str, Any, SecretStr, a union of those)
        # admits the text whatever it is. An arm that keeps the text only
        # when it matches (a Literal's constants, an Enum's member values, a
        # constrained str's pattern or length) is conditional: text that
        # fails it falls through to a sibling arm, and a smart-mode union
        # lets a sibling that converts a str take it (the int arm of
        # Literal["all"] | int turns "067" into 67; int | StrEnum types a
        # non-member "067" the same way). So a conditional arm admits only
        # when the text is known to equal one of its constants, or when no
        # sibling converts; a sibling that holds a container takes no scalar
        # text and does not count.
        unconditional = [arm for arm in arms if not _admits_conditionally(arm)]
        if any(_admits_plain_str(arm, text) for arm in unconditional):
            return True
        conditional = [arm for arm in arms if _admits_conditionally(arm)]
        if text is not None and any(_keeps_this_text(arm, text) for arm in conditional):
            return True
        return not any(_converts_a_plain_str(arm) for arm in unconditional) and any(
            _admits_plain_str(arm, text) for arm in conditional
        )
    if origin is Literal:
        return any(isinstance(arg, str) for arg in get_args(annotation))
    if isinstance(annotation, type):
        # str on either side: a slot that takes any str keeps the text, and a
        # str SUBCLASS (a str-valued Enum, a constrained str) converts to a
        # value that still spells the text, which the needle matches. A
        # secret type never prints its value, and an Enum of str members
        # selects among the code's own constants; one with any other member
        # converts through the member's type and is refused, and so is one
        # that overrides _missing_ for text that equals no member value: the
        # hook may re-spell that text (a case-folding lookup turns "high"
        # into HIGH). Text that equals a member value exactly is found
        # before the hook runs.
        try:
            if issubclass(annotation, enum.Enum):
                # Every Flag is refused before any member is read: a Flag's
                # values are numbers.
                if issubclass(annotation, enum.Flag) or not all(
                    isinstance(member.value, str)
                    for member in annotation.__members__.values()
                ):
                    return False
                # A _missing_ with no underlying function (not a classmethod)
                # is an override too: only an identical function keeps text
                # that equals no member value.
                missing_func = getattr(annotation._missing_, "__func__", None)
                base_missing_func = getattr(enum.Enum._missing_, "__func__", None)
                if missing_func is not None and missing_func is base_missing_func:
                    return True
                return text is not None and text in annotation._value2member_map_
            return issubclass(str, annotation) or issubclass(
                annotation, (str, SecretStr, SecretBytes)
            )
        except TypeError:
            return False
    return origin is None


def _admits_conditionally(annotation: Any) -> bool:
    """Whether *annotation* keeps a plain str only when the text satisfies it:
    a Literal (its constants), an Enum (its member values), a str under
    ``Annotated`` metadata that may refuse some text (a pattern, a length, a
    validator), or a str subclass, which pydantic checks by isinstance so a
    plain str never satisfies it. Such an arm keeps SOME strings and not
    others, and in a union the text it refuses falls to a sibling arm."""
    metadata: List[Any] = []
    while get_origin(annotation) is Annotated:
        annotation, *more = get_args(annotation)
        metadata.extend(more)
    annotation = _unwrap_annotated(annotation)
    if get_origin(annotation) is Literal:
        return True
    if annotation is str:
        return any(_may_refuse_some_text(item) for item in metadata)
    if isinstance(annotation, type):
        try:
            return issubclass(annotation, (enum.Enum, str))
        except TypeError:
            return False
    return False


def _may_refuse_some_text(item: Any) -> bool:
    """Whether an ``Annotated`` metadata *item* on a str may refuse some text:
    anything but a ``Field(...)`` that carries no constraint of its own (a
    description, a title, an alias add no check)."""
    if isinstance(item, FieldInfo):
        return bool(item.metadata)
    return True


def _keeps_this_text(annotation: Any, text: str) -> bool:
    """Whether a conditional arm (:func:`_admits_conditionally`) is known to
    keep *text* as it is: a Literal that lists it, or an Enum whose members
    are all str and one of whose values is exactly *text* (found before any
    ``_missing_`` hook runs). A constrained str's constraint is not read, so
    it answers False and the arm admits only when no sibling converts."""
    annotation = _unwrap_annotated(annotation)
    if get_origin(annotation) is Literal:
        return any(isinstance(arg, str) and arg == text for arg in get_args(annotation))
    if isinstance(annotation, type):
        try:
            if issubclass(annotation, enum.Enum) and not issubclass(
                annotation, enum.Flag
            ):
                return (
                    all(
                        isinstance(member.value, str)
                        for member in annotation.__members__.values()
                    )
                    and text in annotation._value2member_map_
                )
        except TypeError:
            return False
    return False


def _converts_a_plain_str(annotation: Any) -> bool:
    """Whether a plain str handed to *annotation* is converted to another
    value, as a lax model converts "067" at an int slot.

    The sibling test for a Literal arm in a union (:func:`_admits_plain_str`).
    A parameterized container takes no scalar text, a Literal keeps it or
    refuses it, and a model or dataclass takes a mapping and not a str, so
    none of those converts. A root model is read through what it wraps, as the
    walk reads it. Every other class that does not keep the text does convert
    it: the numbers, Decimal, dates, Path and the URL types, an Enum with a
    non-str member. A shape this reader cannot interpret does not count,
    which matches :func:`_admits_plain_str`'s default for one.
    """
    annotation = _root_annotation(annotation)
    origin = get_origin(annotation)
    if origin in (Union, types.UnionType):
        return any(
            _converts_a_plain_str(arg)
            for arg in get_args(annotation)
            if arg is not type(None)
        )
    if origin is not None:
        return False
    if isinstance(annotation, type) and (
        issubclass(annotation, BaseModel) or dataclasses.is_dataclass(annotation)
    ):
        return False
    return isinstance(annotation, type) and not _admits_plain_str(annotation)


def _public_url_types() -> Tuple[type, ...]:
    """pydantic's URL and DSN types, read from the module's public export
    list (``pydantic.networks.__all__``) and not from a private base class:
    the single-host types and the multi-host DSNs (PostgresDsn, MongoDsn,
    NatsDsn) derive from different private bases, and a private name can
    change between releases. pydantic-core's own Url and MultiHostUrl are the
    types older pydantic releases used for AnyUrl."""
    exported = (
        getattr(pydantic_networks, name, None) for name in pydantic_networks.__all__
    )
    return (
        Url,
        MultiHostUrl,
        *(
            kind
            for kind in exported
            if isinstance(kind, type) and kind.__name__.endswith(("Url", "Dsn"))
        ),
    )


_URL_TYPES: Tuple[type, ...] = _public_url_types()


def _path_or_url_family(annotation: Any) -> Optional[str]:
    """The name to write in the ``<name> | str`` idiom when *annotation* is,
    or is a union with an arm that is, a Path or a pydantic URL type; None
    otherwise. Looks at the slot itself and its union arms only and stops at
    any container: a Path inside ``List[Path]`` is not this slot's type."""
    annotation = _unwrap_annotated(annotation)
    if isinstance(annotation, type):
        if issubclass(annotation, pathlib.PurePath):
            return "Path"
        if issubclass(annotation, _URL_TYPES):
            return annotation.__name__
        return None
    if get_origin(annotation) in (Union, types.UnionType):
        for arm in get_args(annotation):
            found = _path_or_url_family(arm)
            if found is not None:
                return found
    return None


def _idiom_sentence(annotation: Any, in_item: bool = False) -> str:
    """The refusal message's pointer to the sanctioned idiom, for exactly the
    Path and URL families; empty for every other refused shape.

    Addressed to plugin authors, who own the field: an operator who wrote the
    reference in a config file cannot retype it (the caller passes no
    annotation on that route). *in_item* says *annotation* is the slot of a
    container's item, so the advice names the item and a ``List[Path]`` option
    keeps its list. A lone reference at a container option draws no sentence:
    the message's opening phrase already names the shape ("Input should be a
    valid list"), and no retype of the items fixes a bare reference there."""
    family = _path_or_url_family(annotation)
    if family is None:
        return ""
    target = (
        "declare each item of this option as" if in_item else "declare this option as"
    )
    return (
        f" Plugin authors: to accept an environment reference here, {target} "
        f"`{family} | str`: the union's str arm keeps the text as written."
    )


def _refused_noun(annotation: Any) -> str:
    """The refusal message's noun for *annotation*, pydantic's where known."""
    annotation = _unwrap_annotated(annotation)
    origin = get_origin(annotation)
    if origin in (Union, types.UnionType):
        nouns = [
            _refused_noun(arg) for arg in get_args(annotation) if arg is not type(None)
        ]
        return " or ".join(dict.fromkeys(nouns)) or "value"
    if annotation in _ENV_SCALAR_SPELLING:
        return _ENV_SCALAR_SPELLING[annotation]
    named = origin if origin is not None else annotation
    if named is dict:
        # pydantic's dict_type message spells the noun "dictionary", not the
        # class's __name__; the other container names match their classes.
        return "dictionary"
    return getattr(named, "__name__", str(named)).lower()


def _listed_values(annotation: Any) -> Optional[List[Any]]:
    """The constants a Literal or an Enum *annotation* lists, in order; None
    for any other shape."""
    annotation = _unwrap_annotated(annotation)
    if get_origin(annotation) is Literal:
        return list(get_args(annotation))
    if isinstance(annotation, type) and issubclass(annotation, enum.Enum):
        return [member.value for member in annotation]
    return None


def _with_article(noun: str) -> str:
    return f"{'an' if noun[:1].lower() in 'aeio' else 'a'} {noun}"


def _slot_words(annotation: Any) -> Tuple[str, str]:
    """What pydantic says the input should be at *annotation*, and what the
    slot expects: ``("a valid integer", "an integer")``, or for a Literal or an
    Enum pydantic's own listing, ``("'a' or 'b'", "one of 'a', 'b'")``. A union
    gives each arm's words joined by "or", the None arm left out."""
    nouns: List[str] = []
    constants: List[Any] = []
    for arm in _slot_arms(annotation):
        listed = _listed_values(arm)
        if listed is None:
            noun = _refused_noun(arm)
            if noun not in nouns:
                nouns.append(noun)
            continue
        for value in listed:
            if value not in constants:
                constants.append(value)
    said: List[str] = []
    expected: List[str] = []
    if nouns:
        said.append("a valid " + " or ".join(nouns))
        expected.append(" or ".join(_with_article(noun) for noun in nouns))
    if constants:
        shown = [repr(value) for value in constants]
        said.append(
            shown[0] if len(shown) == 1 else ", ".join(shown[:-1]) + " or " + shown[-1]
        )
        expected.append(shown[0] if len(shown) == 1 else "one of " + ", ".join(shown))
    return " or ".join(said), " or ".join(expected)


def _slot_arms(annotation: Any, seen: Optional[Set[Any]] = None) -> List[Any]:
    """The arms *annotation* offers a value, None left out: a union's arms, and
    what a RootModel wraps (:func:`_root_annotation`) in place of the model, as
    :func:`_shape_can_hold` reads them, so a RootModel is worded by the type it
    validates and never by its class name. A RootModel met again while its own
    arms are being read is kept as it is, so a chain that names itself ends."""
    annotation = _root_annotation(annotation)
    if get_origin(annotation) in (Union, types.UnionType):
        opened = seen if seen is not None else set()
        arms: List[Any] = []
        for arm in get_args(annotation):
            if arm is type(None):
                continue
            if isinstance(arm, type) and issubclass(arm, RootModel):
                if arm in opened:
                    arms.append(arm)
                    continue
                opened = opened | {arm}
            arms.extend(_slot_arms(arm, opened))
        return arms
    return [annotation]


_SEQUENCE_TYPES = (list, tuple, set, frozenset)

#: The modules whose Collection classes pydantic itself converts a list into.
_STDLIB_COLLECTION_MODULES = frozenset(
    {"builtins", "collections", "collections.abc", "_collections_abc", "typing"}
)


def _root_annotation(annotation: Any, seen: Optional[Set[Any]] = None) -> Any:
    """What a RootModel subclass wraps: its ``root`` field's annotation (through
    nested RootModels), so a container value is read against the shape the
    model validates it as. Anything else is returned unchanged. A RootModel
    over a list takes a list, which a plain BaseModel does not. *seen* is
    :func:`_unwrap_annotated`'s. A chain of RootModels whose roots name one
    another is opened once per class and then returned as the class the
    chain revisits, so the loop ends."""
    annotation = _unwrap_annotated(annotation, seen)
    opened: Set[Any] = set()
    while isinstance(annotation, type) and issubclass(annotation, RootModel):
        if annotation in opened:
            break
        opened.add(annotation)
        root_field = annotation.model_fields.get("root")
        if root_field is None:
            break
        annotation = _unwrap_annotated(root_field.annotation, seen)
    return annotation


def _has_opaque_schema(annotation: Any) -> bool:
    """Whether *annotation* is a class that builds its own pydantic core
    schema (a ``__get_pydantic_core_schema__`` of its own), other than a model,
    an Enum or a dataclass, which pydantic builds and this module reads. What
    such a class does with the text it is given is not readable."""
    return (
        isinstance(annotation, type)
        and not issubclass(annotation, (BaseModel, enum.Enum))
        and not dataclasses.is_dataclass(annotation)
        and callable(getattr(annotation, "__get_pydantic_core_schema__", None))
    )


def _shape_can_hold(arm: Any, value: Any) -> bool:
    """Whether a union *arm* can describe the container *value* at all.

    A scalar-shaped arm (int, str, a date, a Path) describes no container, and
    a mapping shape describes no sequence or the reverse; such an arm has no
    slot for the value's markers, so it must neither admit them nor be
    walked. A shape this reader cannot interpret (a TypeVar, a forward
    reference, a nested union, a model or dataclass that may take a dict)
    can hold, which keeps the downcast the default where nothing is known to
    convert. A value that is not a container is held by any arm.
    """
    if not isinstance(value, (dict, list, tuple, set, frozenset)):
        return True
    arm = _root_annotation(arm)
    if arm is Any or arm is object:
        return True
    base = get_origin(arm) or arm
    if base is Literal:
        # A Literal names scalar constants; no container value equals one.
        return False
    if base in (Union, types.UnionType) or not isinstance(base, type):
        return True
    if _has_opaque_schema(base):
        return True
    try:
        if isinstance(value, dict):
            return (
                issubclass(base, collections.abc.Mapping)
                or issubclass(dict, base)
                or issubclass(base, BaseModel)
                or hasattr(base, "__dataclass_fields__")
                or _is_named_tuple(base)
            )
        if issubclass(base, (str, bytes, bytearray)):
            return False
        # A parameterized iterable (Deque[int], Sequence[str], a custom
        # generic) or a non-Enum Collection holds a sequence value: a list
        # converts into a deque, a Sequence, a custom collection, so the arm
        # is walked. A bare class that merely iterates does not: an Enum
        # iterates its members (IntFlag too, from Python 3.11) and an
        # IPv4Network iterates its addresses, yet neither takes a list, and
        # counting it as the arm that holds the value would admit a list that
        # a sibling arm converts. (BaseModel defines __iter__ over its
        # fields, and a RootModel that wraps a list is reached through its
        # root annotation, not here.) Nor does a bare Collection class of the
        # code's own: pydantic checks instances of it, so it takes no list,
        # and counting it as the arm that holds the value would admit a list
        # that a sibling arm converts. Only a stdlib collection, which
        # pydantic converts a list into, is held. A NamedTuple class of the
        # code's own is held too: pydantic converts a list into it by position.
        if issubclass(base, collections.abc.Iterable) and not issubclass(
            base, (collections.abc.Mapping, BaseModel)
        ):
            if (
                get_args(arm)
                or _is_named_tuple(base)
                or (
                    issubclass(base, collections.abc.Collection)
                    and not issubclass(base, enum.Enum)
                    and base.__module__ in _STDLIB_COLLECTION_MODULES
                )
            ):
                return True
        return any(issubclass(kind, base) for kind in _SEQUENCE_TYPES)
    except TypeError:
        # A TypedDict or a non-runtime protocol refuses class checks.
        return True


class _AliasSlots(List[Tuple[Tuple[Any, ...], Any]]):
    """The fields one dict key can reach when a validation alias is a path or
    shares its first key with another name: ``(rest of the path, annotation)``
    pairs, where an empty rest means the key's own value is the field's."""


_ABSENT = object()


def _alias_paths(alias: Any) -> Iterable[Tuple[Any, ...]]:
    """Every key path a validation alias names: a str, an AliasPath, or the
    members of an AliasChoices (which may themselves be either)."""
    if isinstance(alias, str):
        yield (alias,)
    elif isinstance(alias, AliasPath):
        if alias.path:
            yield tuple(alias.path)
    elif isinstance(alias, AliasChoices):
        for choice in alias.choices:
            yield from _alias_paths(choice)


def _add_alias_slot(
    fields: Dict[Any, Any], path: Tuple[Any, ...], annotation: Any
) -> None:
    key, rest = path[0], tuple(path[1:])
    if key not in fields:
        fields[key] = _AliasSlots([(rest, annotation)]) if rest else annotation
        return
    existing = fields[key]
    if not rest and existing is annotation:
        return
    if not isinstance(existing, _AliasSlots):
        existing = fields[key] = _AliasSlots([((), existing)])
    existing.append((rest, annotation))


def _value_at(value: Any, path: Tuple[Any, ...]) -> Any:
    """The entry *path* names inside *value*, or _ABSENT."""
    for step in path:
        if isinstance(value, dict) and step in value:
            value = value[step]
        elif (
            isinstance(value, (list, tuple))
            and isinstance(step, int)
            and -len(value) <= step < len(value)
        ):
            value = value[step]
        else:
            return _ABSENT
    return value


def _is_named_tuple(annotation: Any) -> bool:
    """Whether *annotation* is a NamedTuple class (typing or collections)."""
    return (
        isinstance(annotation, type)
        and issubclass(annotation, tuple)
        and hasattr(annotation, "_fields")
    )


def _typed_container_class(
    annotation: Any,
) -> Tuple[Any, Dict[Any, Any]]:
    """The TypedDict, NamedTuple or dataclass class *annotation* names, with
    the type variables a parameterized form (``NT[int]``) binds; any other
    annotation comes back unchanged with no bindings. pydantic validates the
    parameterized form as the class with its type variables replaced."""
    origin = get_origin(annotation)
    if isinstance(origin, type) and (
        typing_extensions.is_typeddict(origin)
        or _is_named_tuple(origin)
        or dataclasses.is_dataclass(origin)
    ):
        parameters = getattr(origin, "__parameters__", ())
        return origin, dict(zip(parameters, get_args(annotation)))
    return annotation, {}


def _bound(hint: Any, bindings: Dict[Any, Any]) -> Any:
    """*hint* with the type variables in *bindings* replaced."""
    if isinstance(hint, TypeVar):
        return bindings.get(hint, hint)
    parameters = getattr(hint, "__parameters__", ())
    if bindings and parameters:
        try:
            return hint[tuple(bindings.get(p, p) for p in parameters)]
        except TypeError:  # not subscriptable after all
            return hint
    return hint


#: The config pydantic has in force at the slot the walk is reading: the
#: section's ``model_config`` to start with, then the config of each model,
#: dataclass or TypedDict the walk descends into. A TypedDict or NamedTuple
#: without a config of its own is built under the one around it, and an
#: ``alias_generator`` in it names the keys of their fields.
_WALK_CONFIG: "contextvars.ContextVar[Optional[Any]]" = contextvars.ContextVar(
    "_WALK_CONFIG", default=None
)

#: Whether the walk treats a slot annotated as a RedactedSection subclass as
#: opaque. Set for the walk of a field that reaches a section: the section's
#: own before-validator coerces and downcasts the markers it holds, and only
#: it knows every key its fields accept, so the walk answers nothing for the
#: section's own slots and still reads the slots beside them.
_SECTIONS_OPAQUE: "contextvars.ContextVar[bool]" = contextvars.ContextVar(
    "_SECTIONS_OPAQUE", default=False
)


@contextlib.contextmanager
def _config_in_force(annotation: Any) -> Iterator[None]:
    """Make the config of the model, dataclass or TypedDict *annotation* names
    the one in force while its fields are read; a holder with none keeps the
    config around it, as pydantic does."""
    holder, _ = _typed_container_class(annotation)
    own: Any = None
    if isinstance(holder, type):
        if issubclass(holder, BaseModel):
            own = holder.model_config
        else:
            own = getattr(holder, "__pydantic_config__", None)
    if own is None:
        yield
        return
    token = _WALK_CONFIG.set(own)
    try:
        yield
    finally:
        _WALK_CONFIG.reset(token)


def _alias_object(form: Any) -> Any:
    """The alias a core schema carries (a str, a path, or a list of paths) as
    the object :func:`_alias_paths` reads."""
    if form is None or isinstance(form, str):
        return form
    if form and isinstance(form[0], list):
        return AliasChoices(*(AliasPath(*path) for path in form))
    return AliasPath(*form)


def _holder_core_schema(schema: Any) -> Any:
    """The ``typed-dict`` or ``call`` node of a ``List[holder]`` core schema,
    through ``definitions`` and ``definition-ref``; None when it is not found."""
    definitions: Dict[Any, Any] = {}
    for _ in range(16):
        if not isinstance(schema, dict):
            return None
        kind = schema.get("type")
        if kind == "definitions":
            for definition in schema.get("definitions", ()):
                definitions[definition.get("ref")] = definition
            schema = schema.get("schema")
        elif kind == "definition-ref":
            schema = definitions.get(schema.get("schema_ref"))
        elif kind == "list":
            schema = schema.get("items_schema")
        else:
            return schema
    return None


_GENERATED_ALIAS_CACHE: Dict[Tuple[Any, int], Tuple[Any, Optional[Dict[str, Any]]]] = {}


def _generated_aliases(
    annotation: Any, alias_generator: Any
) -> Optional[Dict[str, Any]]:
    """The validation alias of each field of the TypedDict or NamedTuple
    *annotation* once *alias_generator* has been applied, by field name; None
    when it cannot be read.

    pydantic applies the generator while it builds the schema, to a copy of
    each field's metadata, so neither the class nor a bare ``FieldInfo``
    carries the result. It is read from the public ``core_schema`` of a
    ``TypeAdapter`` over ``List[annotation]``: TypeAdapter refuses a config for
    a TypedDict itself, so the config goes with the wrapper, and a TypedDict
    with a config of its own keeps it. The read depends on the core schema's
    dict shape (a ``typed-dict`` field's ``validation_alias``, a NamedTuple
    parameter's ``alias``), which is documented but less stable than a field
    object; a schema of another shape reads as None and the caller falls back
    to the metadata. Built once per holder and generator (a generator is kept
    alive by its entry, which is cleared at 256)."""
    key = (annotation, id(alias_generator))
    cached = _GENERATED_ALIAS_CACHE.get(key)
    if cached is not None and cached[0] is alias_generator:
        return cached[1]
    result: Optional[Dict[str, Any]] = None
    try:
        adapter = TypeAdapter(
            List[annotation],
            config=ConfigDict(alias_generator=alias_generator),
        )
        node = _holder_core_schema(adapter.core_schema)
        if isinstance(node, dict) and node.get("type") == "typed-dict":
            result = {
                name: _alias_object(field.get("validation_alias"))
                for name, field in node["fields"].items()
            }
        elif isinstance(node, dict) and node.get("type") == "call":
            arguments = node.get("arguments_schema")
            if isinstance(arguments, dict) and arguments.get("type") == "arguments":
                result = {
                    parameter["name"]: _alias_object(parameter.get("alias"))
                    for parameter in arguments["arguments_schema"]
                }
    except Exception:  # a holder pydantic cannot build is not read
        result = None
    if len(_GENERATED_ALIAS_CACHE) >= 256:
        _GENERATED_ALIAS_CACHE.clear()
    _GENERATED_ALIAS_CACHE[key] = (alias_generator, result)
    return result


def _typed_container_fields(annotation: Any) -> Optional[Dict[Any, Any]]:
    """The annotation of each field a TypedDict or NamedTuple *annotation*
    (or a parameterized form of one) declares, by field name and by every key
    its validation alias reads.

    pydantic validates both shapes and reads a field's ``Field(alias=...)`` or
    ``Field(validation_alias=...)`` off its ``Annotated`` metadata, as it does
    for a model or a dataclass, so the keys are listed through the same slot
    helpers. When a config in force has an ``alias_generator`` the aliases come
    from the built schema instead (:func:`_generated_aliases`), which holds
    the explicit ones and the generated ones as pydantic resolved them. None
    when the hints cannot be resolved."""
    whole = annotation
    annotation, bindings = _typed_container_class(annotation)
    config = getattr(annotation, "__pydantic_config__", None)
    if config is None:
        config = _WALK_CONFIG.get()
    generator = config.get("alias_generator") if config else None
    generated = _generated_aliases(whole, generator) if generator is not None else None
    try:
        hints = {
            name: _bound(hint, bindings)
            for name, hint in typing_extensions.get_type_hints(annotation).items()
        }
        declared = typing_extensions.get_type_hints(annotation, include_extras=True)
    except Exception:  # an unresolvable forward reference
        return None
    names = tuple(annotation._fields) if _is_named_tuple(annotation) else tuple(hints)
    by_name = {name: hints.get(name, Any) for name in names}
    for name in names:
        if generated is not None:
            aliases: Tuple[Any, ...] = (generated.get(name),)
        else:
            try:
                info = FieldInfo.from_annotation(declared.get(name, Any))
            except Exception:  # metadata pydantic would refuse as well
                continue
            aliases = (info.alias, info.validation_alias)
        for alias in aliases:
            for path in _alias_paths(alias):
                _add_alias_slot(by_name, path, by_name[name])
    return by_name


def _dataclass_fields(
    annotation: Any, bindings: Dict[Any, Any]
) -> Optional[Dict[Any, Any]]:
    """The annotation of each field a dataclass declares, by field name and by
    every key a pydantic dataclass's validation alias reads, with the type
    variables in *bindings* replaced. None when the hints cannot be resolved."""
    try:
        hints = get_type_hints(annotation)
    except Exception:  # an unresolvable forward reference
        return None
    by_name = {
        field.name: _bound(hints.get(field.name, Any), bindings)
        for field in dataclasses.fields(annotation)
    }
    # A pydantic dataclass carries validation aliases like a model does.
    for name, field in getattr(annotation, "__pydantic_fields__", {}).items():
        for alias in (field.alias, field.validation_alias):
            for path in _alias_paths(alias):
                _add_alias_slot(by_name, path, by_name.get(name, Any))
    return by_name


def _no_arm_can_hold(annotation: Any, value: Any) -> bool:
    """Whether *annotation* has no slot at all for the container *value*: it
    is not a union and its shape cannot hold the value, or it is a union and
    no arm besides None can (:func:`_shape_can_hold`). A shape this reader
    cannot interpret can hold, so it answers False and the value is left to
    the walk and the downcast. A union of only None answers False."""
    annotation = _unwrap_annotated(annotation)
    if get_origin(annotation) in (Union, types.UnionType):
        arms = [arm for arm in get_args(annotation) if arm is not type(None)]
        return bool(arms) and not any(_shape_can_hold(arm, value) for arm in arms)
    return not _shape_can_hold(annotation, value)


def _inert_metadata(item: Any) -> bool:
    """Whether an ``Annotated`` metadata *item* is known to add no validator and
    no schema of its own: an ``annotated_types`` constraint object, or a
    ``Field(...)`` whose own metadata is inert. Anything else (a
    ``BeforeValidator``, ``PlainValidator``, ``WrapValidator``, ``SkipValidation``,
    a ``GetPydanticSchema``, a class this module has not seen) is not known to
    be inert."""
    if isinstance(item, FieldInfo):
        return item.discriminator is None and all(
            _inert_metadata(inner) for inner in item.metadata
        )
    return type(item).__module__.split(".")[0] == "annotated_types"


def _is_type_checked_class(arm: Any) -> bool:
    """Whether *arm* is PROVEN to be validated by pydantic as an isinstance
    check, with no validator in the way.

    An allowlist: True only for a plain class (an attrs class, a class of the
    code's own, a Collection of the code's own) that pydantic builds no schema
    for (``TypeAdapter`` refuses it without ``arbitrary_types_allowed``), that
    has neither ``__get_pydantic_core_schema__`` nor the legacy
    ``__get_validators__``. An ``Annotated`` shape, a NewType, a type alias, a
    generic alias, a builtin or any type pydantic has a schema for, and
    anything this reader cannot classify, answers False."""
    if get_origin(arm) is not None or not isinstance(arm, type):
        return False
    if (
        issubclass(arm, (BaseModel, enum.Enum))
        or dataclasses.is_dataclass(arm)
        or _is_named_tuple(arm)
        or hasattr(arm, "__get_pydantic_core_schema__")
        or hasattr(arm, "__get_validators__")
    ):
        return False
    try:
        TypeAdapter(arm)
    except PydanticSchemaGenerationError:
        return True
    except Exception:  # not a class this reader can classify
        return False
    return False


def _type_check_decides(annotation: Any, metadata: Iterable[Any]) -> bool:
    """Whether the type check, not this module's walk, speaks for a container
    that no arm of *annotation* can hold: every arm (but None) is a class that
    pydantic checks by isinstance (:func:`_is_type_checked_class`) and the
    field's own metadata (*metadata*, which pydantic moves out of a top-level
    ``Annotated``) is inert. Where an arm may carry a validator that accepts
    the container, or this reader cannot tell, the answer is False and the named
    refusal stays."""
    if not all(_inert_metadata(item) for item in metadata):
        return False
    arms = _leaf_arms(annotation)
    return bool(arms) and all(_is_type_checked_class(arm) for arm in arms or ())


def _leaf_arms(annotation: Any, depth: int = 0) -> Optional[List[Any]]:
    """The arms of *annotation* below its ``Annotated`` layers and unions,
    None excluded; None when an ``Annotated`` layer carries metadata that is not
    known to be inert, or the nesting is deeper than this reader follows."""
    if depth > 8:
        return None
    while get_origin(annotation) is Annotated:
        annotation, *metadata = get_args(annotation)
        if not all(_inert_metadata(item) for item in metadata):
            return None
    if get_origin(annotation) not in (Union, types.UnionType):
        return [annotation]
    arms: List[Any] = []
    for arm in get_args(annotation):
        if arm is type(None):
            continue
        inner = _leaf_arms(arm, depth + 1)
        if inner is None:
            return None
        arms.extend(inner)
    return arms


def _declared_field_annotations(annotation: Any) -> Optional[Dict[Any, Any]]:
    """The annotation of each field a plain model, dataclass, TypedDict or
    NamedTuple *annotation* declares, by every name a dict can give it (the
    field name, its str aliases, and the keys an AliasChoices or AliasPath
    validation alias reads); None for any other annotation.

    A RedactedSection is walked like any other model, with one deliberate
    difference: its ``_env_scalar_typed_fields`` opt-in is not honored, so a
    reference at an opted field is refused here. The walk only reaches a
    section that sits under a plain model's field, because an annotation that
    names a section on its own path is left to that section's validator
    (:func:`_annotation_reaches_a_section`), and the plain model between
    hides the markers from it: the outer validator downcasts the whole value
    before the section is built, so the section's own validator would see
    plain text. The opt-in hands the marker itself to the field's own
    validation, and a downcast value has no marker left to hand over: the
    config-file load would then get pydantic's own error for the text (which
    names no variable) instead of the named refusal. Refusing is the safe
    side of that gap. It is latent today: the one known path from a plain
    model to a section, ``build.custom_scanners``, refuses every non-empty
    value in its own validator before this walk runs.
    """
    holder, bindings = _typed_container_class(annotation)
    if holder is not annotation:
        if dataclasses.is_dataclass(holder):
            return _dataclass_fields(holder, bindings)
        return _typed_container_fields(annotation)
    if not isinstance(annotation, type):
        return None
    fields: Dict[Any, Any] = {}
    if issubclass(annotation, BaseModel):
        # Own names first, alias keys second, as _dataclass_fields does: in
        # one pass a later field's own-name write replaced the _AliasSlots an
        # earlier field's alias had put under the shared key, so the refusal
        # depended on declaration order.
        for name, field in annotation.model_fields.items():
            fields[name] = field.annotation
        for name, field in annotation.model_fields.items():
            for alias in (field.alias, field.validation_alias):
                for path in _alias_paths(alias):
                    _add_alias_slot(fields, path, field.annotation)
        return fields
    if dataclasses.is_dataclass(annotation):
        return _dataclass_fields(annotation, {})
    if typing_extensions.is_typeddict(annotation) or _is_named_tuple(annotation):
        return _typed_container_fields(annotation)
    return None


def _marker_a_slot_would_type(
    annotation: Any, value: Any, as_item: bool = False
) -> Optional[Tuple["EnvResolvedScalar", Any, bool]]:
    """The first marker in *value* at a slot that would convert it, with that
    slot's annotation and whether the slot is the item of a sequence or a
    mapping; None when every marker sits where a plain str lands.

    Walks the annotation beside the value: a dict's keys against the key
    argument and its values against the value argument, a sequence's items
    against the item argument (positionally for a fixed tuple, whether the
    value is a list or a tuple), a union against each arm that can describe
    the value at all (:func:`_shape_can_hold`), where one such arm that keeps
    every marker as text admits the value. An arm that cannot describe the
    value is skipped, never counted as admitting it. A slot the annotation
    does not describe is left to the downcast, as before.

    *as_item* says the slot being walked is a sequence's or a mapping's item.
    The field of a model sitting in such an item is not one: it is a field,
    so the walk of a model's entries starts over with it False.

    Under :data:`_SECTIONS_OPAQUE` a slot annotated as a RedactedSection
    subclass answers None whatever sits in it: those markers are the
    section's own validator's to judge.
    """
    if (
        _SECTIONS_OPAQUE.get()
        and isinstance(annotation, type)
        and issubclass(annotation, RedactedSection)
    ):
        return None
    if isinstance(annotation, _AliasSlots):
        for rest, slot in annotation:
            leaf = _value_at(value, rest)
            if leaf is not _ABSENT:
                typed = _marker_a_slot_would_type(slot, leaf)
                if typed is not None:
                    return typed
        return None
    if isinstance(value, EnvResolvedScalar):
        if _admits_plain_str(annotation, str(value)):
            return None
        return value, annotation, as_item
    # A RootModel is read through what it wraps, after the scalar check
    # above: a bare marker at the model itself keeps its standing answer.
    annotation = _root_annotation(annotation)
    origin = get_origin(annotation)
    if origin in (Union, types.UnionType):
        found = None
        for arm in get_args(annotation):
            if arm is type(None) or not _shape_can_hold(arm, value):
                continue
            typed = _marker_a_slot_would_type(arm, value, as_item)
            if typed is None:
                return None
            found = found or typed
        return found
    if isinstance(value, dict):
        fields = _declared_field_annotations(annotation)
        if fields is not None:
            # A model or dataclass takes the dict by field name: each entry
            # is walked against the annotation of the field it lands on, as
            # a section's own validator would walk it, except that a
            # section's _env_scalar_typed_fields opt-in is not honored (see
            # _declared_field_annotations). An entry no field names is left
            # to the model's own extra-key policy.
            with _config_in_force(annotation):
                for key, item in value.items():
                    if key in fields:
                        typed = _marker_a_slot_would_type(fields[key], item)
                        if typed is not None:
                            return typed
            return None
    holder, bindings = _typed_container_class(annotation)
    if isinstance(value, (list, tuple)) and _is_named_tuple(holder):
        # A NamedTuple takes its fields by position too: pair each item with
        # the field it lands on. A length mismatch pairs the shared prefix.
        try:
            hints = typing_extensions.get_type_hints(holder)
        except Exception:  # an unresolvable forward reference
            return None
        for name, item in zip(holder._fields, value):
            typed = _marker_a_slot_would_type(
                _bound(hints.get(name, Any), bindings), item
            )
            if typed is not None:
                return typed
        return None
    if origin is Literal:
        # The args are constants, not annotations: no slot to walk. A
        # container value at a bare Literal field matches none of them and
        # fails validation without converting anything.
        return None
    args = get_args(annotation)
    if not args:
        if isinstance(
            value, (list, tuple, set, frozenset, dict)
        ) and _has_opaque_schema(annotation):
            # The class builds its own core schema, so what it does with the
            # text in the container it is given cannot be read: fail closed,
            # as the scalar slot of the same class already does.
            marker = first_env_scalar(value)
            if marker is not None:
                return marker, annotation, as_item
        return None
    if isinstance(value, dict):
        key_annotation = args[0]
        value_annotation = args[1] if len(args) > 1 else Any
        for key, item in value.items():
            typed = _marker_a_slot_would_type(
                key_annotation, key, True
            ) or _marker_a_slot_would_type(value_annotation, item, True)
            if typed is not None:
                return typed
        return None
    if isinstance(value, (list, tuple, set, frozenset)):
        if (
            origin is tuple
            and Ellipsis not in args
            and isinstance(value, (list, tuple))
        ):
            # YAML only ever gives lists, so a fixed tuple pairs by position
            # for a list as for a tuple. On a length mismatch zip pairs the
            # shared prefix: the model's own validation owns the length error.
            pairs: Iterable[Tuple[Any, Any]] = zip(args, value)
        else:
            pairs = ((args[0], item) for item in value)
        for item_annotation, item in pairs:
            typed = _marker_a_slot_would_type(item_annotation, item, True)
            if typed is not None:
                return typed
        return None
    return None


def _refuse_env_reference(
    value: EnvResolvedScalar,
    noun: str,
    field_name: str,
    annotation: Any = None,
    in_item: bool = False,
) -> None:
    """Refuse the reference at a typed field, naming field and variable.

    Never the value, which may have been read from the environment, and never
    pydantic's own error for the field, whose rendering echoes the input. The
    message opens with pydantic's phrase for the type so a load that pins the
    standing "Input should be a valid ..." refusal reads this one the same.
    When the refused *annotation* is a Path or a pydantic URL type, or a
    union with an arm that is, the message also names the sanctioned idiom,
    ``Path | str`` (or ``AnyUrl | str``), whose str arm admits a reference;
    *in_item* says *annotation* is a container's item slot, so the advice
    names the item. A lone reference at a container option (``List[Path]``)
    gets no idiom sentence, because retyping the items does not fix it. A
    caller that passes no annotation (the operator's config-file route) gets
    no idiom sentence either.
    """
    raise ValueError(
        f"Input should be a valid {noun}: "
        f"{field_name} was set from an environment reference "
        f"({value.variable}), which is refused at this field. A typed value "
        "cannot be shown by its reference, so the value read from "
        f"{value.variable} would print wherever this section is shown. "
        "Write the value in the file instead."
        f"{_idiom_sentence(annotation, in_item)}"
    )


def _container_word(value: Any) -> str:
    """What the refusal calls the container *value*: "a mapping" for a dict,
    otherwise its own kind ("a list", "a tuple", "a set", "a frozenset")."""
    if isinstance(value, dict):
        return "a mapping"
    for kind in (tuple, frozenset, set):
        if isinstance(value, kind):
            return f"a {kind.__name__}"
    return "a list"


def _refuse_container_at_scalar(
    marker: EnvResolvedScalar, value: Any, annotation: Any, field_name: str
) -> None:
    """Refuse a list or mapping that holds a reference at a field with no slot
    for a container, naming the field and the variable of the first reference
    it holds.

    The container is what is wrong, so the message says so and gives no advice:
    a lone reference loads at a str, a Path-or-str, a Literal or a str Enum, and
    writing the value in the file, or declaring the type the field already has,
    would be refused by this rule again. It opens with pydantic's phrase for the
    type (:func:`_slot_words`), as :func:`_refuse_env_reference` does:
    pydantic's spelling for a scalar, a Literal or an Enum, and a RootModel's
    wrapped type. A Path is the exception: pydantic words a refused Path
    "Input is not a valid path for <class 'pathlib.Path'>", and this opening
    keeps the "Input should be a valid ..." form every other type here has."""
    said, expected = _slot_words(annotation)
    container = _container_word(value)
    raise ValueError(
        f"Input should be {said}: {field_name} holds {container} where "
        f"{expected} is expected; it holds a reference to {marker.variable}."
    )


def _refuse_typed_env_reference(
    annotation: Any,
    value: Any,
    field_name: str,
    *,
    operator_route: bool = False,
    config: Optional[Any] = None,
    metadata: Iterable[Any] = (),
    sections_opaque: bool = False,
) -> None:
    """Refuse the first reference in *value* that sits at a slot of
    *annotation* that would convert its text, naming *field_name* and the
    variable; return when every reference sits where a plain str lands.

    The section base's validator runs this for every container field and is
    its only caller. A field that can never be filled does not call it: its
    refusal says so once, and advice to write the value in the file would
    lead to a second refusal. *operator_route* is the config-file
    load (the ``strict_file_load`` context): the reader wrote the reference
    and cannot retype a plugin's field, so the refusal carries no idiom hint.
    *config* is the ``model_config`` of the section that holds the field: the
    config in force for the TypedDict and NamedTuple fields under it.
    *sections_opaque* makes the walk answer nothing for a slot annotated as a
    RedactedSection subclass (:data:`_SECTIONS_OPAQUE`): the caller hands the
    value on whole afterwards, so those markers reach the section itself.

    A container at a field whose annotation has no slot for a container (a
    boolean, a number, a str) is refused as well, naming the variable of the
    first reference it holds in reading order (:func:`first_env_scalar`), in
    words of its own (:func:`_refuse_container_at_scalar`). Downcast and
    handed on, it would end in pydantic's own error for the field, which names
    no variable and whose input is a plain copy of the container with the
    resolved text in it and the reference marker gone. The refusal keeps the
    original value as the error's input, as the refusal of a bare reference
    does.

    The section's validator runs before a field's own ``BeforeValidator``, so
    a field that turns a list into a str that way is refused here when the list
    holds a reference. That is the rule's limit, and the order is pinned by a
    cell (a wrap-mode validator handing on the downcast value would lift it).

    Where every arm is a class that pydantic checks by isinstance and nothing
    in the annotation or in *metadata* (the field's own ``Annotated``
    metadata, which pydantic moves out of the annotation) is known to carry a
    validator or a schema hook (:func:`_type_check_decides`), the type check
    speaks for the container instead. Any other shape, and any shape this
    reader cannot classify, keeps the named refusal.
    """
    if _no_arm_can_hold(annotation, value) and not _type_check_decides(
        annotation, metadata
    ):
        marker = first_env_scalar(value)
        if marker is not None:
            _refuse_container_at_scalar(marker, value, annotation, field_name)
    token = _WALK_CONFIG.set(config)
    opaque_token = _SECTIONS_OPAQUE.set(sections_opaque)
    try:
        typed = _marker_a_slot_would_type(annotation, value)
    finally:
        _SECTIONS_OPAQUE.reset(opaque_token)
        _WALK_CONFIG.reset(token)
    if typed is not None:
        marker, slot, in_item = typed
        _refuse_env_reference(
            marker,
            _refused_noun(slot),
            field_name,
            None if operator_route else slot,
            in_item=in_item,
        )


class _TypedEnvironmentValue:
    """Stands in for an opted typed field's number in a section's repr when a
    carried environment value types to it: ``scan_timeout=<value>``. The
    spelling matches the stand-in the redaction needle writes, so a reader
    sees one marker whichever layer hid the value."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "<value>"


_TYPED_ENVIRONMENT_VALUE = _TypedEnvironmentValue()


def without_env_scalars(value: Any) -> Any:
    """*value* with every EnvResolvedScalar inside downcast to plain str, a
    dict's keys included.

    Walks lists, tuples, sets, frozensets and dicts on its own stack, in
    post-order: each container is rebuilt after its entries. The input is a config
    value at whatever depth the operator wrote it, so a walk that recursed
    per nesting level crashed with a RecursionError past the interpreter's
    limit (the shape config_validator's _string_leaves already walks
    iteratively for the same reason).

    Two kinds of caller. The section base's validator calls it for a field
    whose annotation reaches no section (the section's own validator must
    see the markers), so what is walked would otherwise carry the subclass
    into the validated model and fail a config dump. And a consumer that
    reads a never-validated raw section (an external plugin's config, which
    the segment models keep as an extra) takes this view before formatting
    or storing a value, so a message about the value names the type the
    file gave -- a str -- and never this module's marker class.

    A container that holds itself is refused with a ValueError: there is no
    acyclic downcast copy to build. No config file parser produces one (the
    YAML loader refuses recursive aliases; TOML and JSON cannot write one),
    so a cycle only arrives from a Python caller, and refusing it beats
    walking it forever. A merely *shared* container is not a cycle: the walk
    rebuilds it once and every parent holds the same copy. The cycle check
    rides the walk's own stack discipline: a container's expansion frame is
    popped again before its completion frame only when its own subtree
    pushed it, which is exactly a cycle, while a second parent's frame for a
    shared container is always below the first's completed subtree.
    """
    rebuilt: Dict[int, Any] = {}
    in_progress: Set[int] = set()
    stack: List[Tuple[Any, bool]] = [(value, False)]
    while stack:
        node, entries_done = stack.pop()
        if id(node) in rebuilt:
            continue
        if isinstance(node, EnvResolvedScalar):
            rebuilt[id(node)] = str(node)
        elif not isinstance(node, (list, tuple, set, frozenset, dict)):
            rebuilt[id(node)] = node
        elif not entries_done:
            if id(node) in in_progress:
                raise ValueError(
                    "the value contains itself, so no downcast copy of it "
                    "can be built. A config file cannot write such a value; "
                    "pass an acyclic structure."
                )
            in_progress.add(id(node))
            stack.append((node, True))
            if isinstance(node, dict):
                # Keys are entries too: a marker written as a mapping key is
                # downcast like one written as a value.
                stack.extend((key, False) for key in node)
                stack.extend((entry, False) for entry in node.values())
            else:
                stack.extend((entry, False) for entry in node)
        else:
            in_progress.discard(id(node))
            if isinstance(node, dict):
                rebuilt[id(node)] = {
                    rebuilt[id(key)]: rebuilt[id(entry)] for key, entry in node.items()
                }
            elif isinstance(node, list):
                rebuilt[id(node)] = [rebuilt[id(entry)] for entry in node]
            elif isinstance(node, tuple):
                rebuilt[id(node)] = tuple(rebuilt[id(entry)] for entry in node)
            elif isinstance(node, frozenset):
                rebuilt[id(node)] = frozenset(rebuilt[id(entry)] for entry in node)
            else:
                rebuilt[id(node)] = {rebuilt[id(entry)] for entry in node}
    return rebuilt[id(value)]


def _set_member_order(member: Any) -> Tuple[int, str]:
    """Sort key for the members of a set: references first, by variable name.

    Every other member (a plain str, or a tuple that may hold a reference)
    sorts after the references and ties with its peers, so those keep the
    set's own iteration order among themselves. A set of references, which is
    what a YAML ``!!set`` of environment references loads as, is fully
    ordered.
    """
    if isinstance(member, EnvResolvedScalar):
        return (0, member.variable)
    return (1, "")


def first_env_scalar(value: Any) -> Optional["EnvResolvedScalar"]:
    """The first EnvResolvedScalar *value* is or contains; None when it holds
    none. Dict keys are walked as well as values, each key before its value:
    a YAML mapping key can be a reference too (``${VAR}: 1``), and a key the
    detector skipped reached pydantic as a str subclass, which a typed key
    slot converted silently and an untyped one kept into the validated model.

    Iterative, on its own stack, like :func:`without_env_scalars`: this one
    answers for every container field of every section, nested however deep
    the config file wrote it. Containers are tracked by id, so a container
    that holds itself (a Python caller's value; no config file parser
    produces one) is walked once and the detector answers from what the
    structure holds instead of spinning on the cycle.

    First means document order: children are pushed onto the stack reversed,
    so the depth-first walk reads a dict's values and a sequence's items in
    the order the config file wrote them and returns the first scalar it
    meets. A set has no document order: YAML's ``!!set`` is parsed into a
    Python set, which drops the order the file wrote, so that order cannot be
    recovered. The members of a set are read in order of their variable
    names, so the member returned is the same on every run; which member is
    first is the one with the smallest name, not the one the file wrote
    first.

    Callers: :func:`_holds_env_scalar`, :func:`_marker_a_slot_would_type` and
    :func:`_refuse_typed_env_reference` within this module, and
    ``BuildConfig._refuse_custom_scanner_entries`` in ``config/ash_config.py``.
    """
    seen: Set[int] = set()
    stack: List[Any] = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, EnvResolvedScalar):
            return current
        if isinstance(current, (list, tuple, set, frozenset, dict)):
            if id(current) in seen:
                continue
            seen.add(id(current))
            if isinstance(current, dict):
                entries: List[Any] = []
                for key, item in current.items():
                    entries.append(key)
                    entries.append(item)
                stack.extend(reversed(entries))
            elif isinstance(current, (set, frozenset)):
                stack.extend(sorted(current, key=_set_member_order, reverse=True))
            else:
                stack.extend(reversed(current))
    return None


def _holds_env_scalar(value: Any) -> bool:
    """Whether *value* is or contains an EnvResolvedScalar."""
    return first_env_scalar(value) is not None


def _annotation_reaches_a_section(
    annotation: Any, seen: Optional[Set[Any]] = None
) -> bool:
    """Whether *annotation* names a RedactedSection anywhere in its shape.

    A value under such a field is handed on undowncast once the walk, with
    the section-typed slots opaque, has refused nothing: the section's own
    before-validator coerces and downcasts the markers it holds. A RootModel
    is read through what it wraps (:func:`_root_annotation`), as the walk
    does: a section behind it still needs the markers, since only the
    section knows every key its fields accept. *seen* is shared down the
    recursion, so a type alias that names itself is read once: a second visit
    could only repeat an answer that was already False. A RootModel class is
    read once the same way: one whose root annotation names the class itself
    (through a List or Dict argument, say) would otherwise be opened without
    bound, and the second visit could only repeat an answer that was already
    False.
    """
    if seen is None:
        seen = set()
    if isinstance(annotation, type) and issubclass(annotation, RootModel):
        if annotation in seen:
            return False
        seen.add(annotation)
    annotation = _root_annotation(annotation, seen)
    if isinstance(annotation, type):
        return issubclass(annotation, RedactedSection)
    return any(_annotation_reaches_a_section(arg, seen) for arg in get_args(annotation))


class RedactedSection(BaseModel):
    """A model a configuration holds: its repr and str redact the values the
    configuration read from the environment.

    pydantic builds both ``__repr__`` and ``__str__`` from ``__repr_str__``,
    and a model that holds this one prints it through ``repr`` of the value, so
    an env-read value shows ``<value>`` in this model and in whatever holds it.
    Any field can be env-read (``!ENV``), so the whole text is redacted rather
    than chosen fields; a literal value stays readable. The model has no
    ``__rich_repr__`` (:data:`NO_RICH_REPR`), so Rich prints it through
    ``repr`` too.

    The values come from the configuration (:func:`carry_environment_values`):
    it gives them to every section it holds when it is built, when its values
    change, and when a section is put in it; a section gives its own to a model
    put in one of its fields, and its copy (``model_copy``) gives its own to
    whatever the copy holds, an entry passed in ``update`` among it. A model
    built some other way, as from a section's dump, carries none until it is
    put into a configuration, a section or a plugin -- and so does an entry
    written in place into a container field, which tells the section nothing:
    ``append``, ``insert``, ``extend``, assigning an item or a slice, and
    writing a dict key all land that way. Assigning the field itself
    (``section.items = section.items``) carries into every section it holds
    through sections, lists, tuples, sets and dicts; a model of another kind
    is left alone, sections under it included: a plugin takes its values
    itself (carry_environment_values).
    """

    _environment_record: _EnvironmentRecord = PrivateAttr(
        default_factory=_EnvironmentRecord
    )

    #: The fields whose env-resolved text is handed to the field's own
    #: validation instead of being refused: a per-field opt-in, empty by
    #: default. The default is refusal because printers show an env-read
    #: value by its reference, and a typed slot that converts the text (a
    #: number, Decimal, date, Path, URL, or a container with such a slot)
    #: cannot carry the reference text, so the value read from the
    #: environment would print wherever the section is shown (a
    #: suppression's line numbers, say). SecretStr and SecretBytes slots,
    #: and an Enum slot whose members are all str and whose ``_missing_``
    #: is the stock one, are the exceptions that admit.
    #: A field goes in this set only once its printers are measured to
    #: guard the value: every line that shows the field redacts the
    #: recorded text (ScannerOptionsBase.scan_timeout is the one member).
    #: For an opted field the text is typed by the model itself, exactly
    #: as a plain string would be: a config-file load raises the named
    #: refusal instead (strict typing would refuse any string there), and
    #: a lax model reads it as the field's type, so no str subclass
    #: survives validation either way.
    _env_scalar_typed_fields: ClassVar[FrozenSet[str]] = frozenset()

    @field_validator("*", mode="before")
    @classmethod
    def _env_resolved_text_reads_as_the_field_type(
        cls, value: Any, info: ValidationInfo
    ) -> Any:
        """Refuse or hand on env-resolved text at a typed field.

        A ``${ASH_X}`` reference resolves to text whose value may have been
        read from the environment, and a field whose type converts the text
        (a number, Decimal, date, Path, URL, or a container with such a
        slot) cannot carry the reference text, so the converted value would
        print by value wherever the section is shown. The reference is
        therefore refused at such a field, naming the field and the variable and
        never the value (:func:`_refuse_env_reference`) -- except for the
        fields the section opts in through
        :attr:`_env_scalar_typed_fields`, whose printers are measured to
        guard the value: those keep the marker, and the field's own
        validation types the text or refuses it as it would a plain
        string -- except under a config-file load (the
        ``strict_file_load`` context), where strict typing would refuse
        the text anyway and the named refusal is raised instead so the
        message names the variable. A field whose type admits a string keeps the text,
        downcast to plain str so no str subclass reaches a config dump
        (SafeDumper has no representer for one). A list, tuple, set or dict
        that holds a reference at a field with no slot for a container (a
        boolean, a number) is refused by name, saying it holds a container
        where the type is expected, so the field's own validation never sees
        a copy with the text downcast.
        Values under a field that reaches another section are handed on as
        given, after a walk that treats the section-typed slots as opaque:
        that section's own validator sees its markers, and a typed slot
        beside a section in the same shape still refuses.
        """
        field_name = info.field_name
        if field_name is None:
            return value
        # The idiom hint ("type it `Path | str`") advises whoever owns the
        # field. On a config-file load the reader is the operator who wrote
        # the reference, and cannot retype a plugin's field: no hint there.
        operator_route = bool((info.context or {}).get("strict_file_load"))
        if isinstance(value, EnvResolvedScalar):
            annotation = cls.model_fields[field_name].annotation
            hint = None if operator_route else annotation
            if field_name in cls._env_scalar_typed_fields:
                # A config FILE cannot put a reference at a typed field even
                # when it is opted in: strict typing refuses the text anyway,
                # and without this arm the refusal is pydantic's own, which
                # calls the resolved text not-an-integer and names no
                # variable. The lax plugin route carries no such context and
                # keeps the marker for the field's own validation.
                if operator_route:
                    _refuse_env_reference(
                        value, _refused_noun(annotation), field_name, hint
                    )
                return value
            if _admits_plain_str(annotation, str(value)):
                return str(value)
            _refuse_env_reference(value, _refused_noun(annotation), field_name, hint)
        if isinstance(value, (list, tuple, set, frozenset, dict)) and _holds_env_scalar(
            value
        ):
            annotation = cls.model_fields[field_name].annotation
            if _annotation_reaches_a_section(annotation):
                # The sections in the shape must receive their markers (only
                # their own validators know every key their fields accept),
                # so the value is handed on undowncast. A slot BESIDE a
                # section (the int of Tuple[Section, int]) still converts
                # text, so the walk runs first with section-typed slots
                # opaque.
                _refuse_typed_env_reference(
                    annotation,
                    value,
                    field_name,
                    operator_route=operator_route,
                    config=cls.model_config,
                    metadata=cls.model_fields[field_name].metadata,
                    sections_opaque=True,
                )
                return value
            _refuse_typed_env_reference(
                annotation,
                value,
                field_name,
                operator_route=operator_route,
                config=cls.model_config,
                metadata=cls.model_fields[field_name].metadata,
            )
            return without_env_scalars(value)
        return value

    def redaction_values(self) -> Tuple[str, ...]:
        """The values this section's repr and str are redacted with: the
        environment values its configuration carried into it. The public read
        for a caller outside the model's own machinery (the MCP runner builds
        its redaction set from the limits section's); the underscore twin
        below stays the internal spelling the machinery calls."""
        return self._redaction_values()

    def _redaction_values(self) -> Tuple[str, ...]:
        """The values this model's text is redacted with."""
        return self._environment_record.values

    def __repr_args__(self) -> Any:
        """Each repr arg, with an opted typed field's number replaced.

        The text needle in ``__repr_str__`` matches the values as the
        environment wrote them, which a field in
        :attr:`_env_scalar_typed_fields` no longer holds: a lax model typed
        the text, so the field shows a number -- below the needle's length
        band ("67"), or in a spelling the needle never saw ("0067" read as
        67). Where any carried value's text types to the field's number
        (``config_validator.typed_from``), the repr shows ``<value>``, the
        same stand-in the needle writes. A number no carried value types to
        stays readable.
        """
        # Imported here: the config package imports this module at start-up.
        from automated_security_helper.config.config_validator import typed_from

        values = self._redaction_values()
        opted = type(self)._env_scalar_typed_fields
        for name, value in super().__repr_args__():
            if (
                name in opted
                and values
                and any(typed_from(value, text) for text in values)
            ):
                yield name, _TYPED_ENVIRONMENT_VALUE
            else:
                yield name, value

    def __repr_str__(self, join_str: str) -> str:
        # Imported here: utils.error_text defers imports of the config package,
        # which imports this module.
        from automated_security_helper.utils.error_text import text_without_values

        return text_without_values(
            super().__repr_str__(join_str),  # type: ignore[misc]
            self._redaction_values(),
        )

    __rich_repr__ = NO_RICH_REPR

    def __setattr__(self, name: str, value: Any) -> None:
        super().__setattr__(name, value)
        if name in type(self).model_fields:
            carry_environment_values(value, self._redaction_values())

    def model_copy(self, *, update: Any = None, deep: bool = False) -> Any:
        copied = super().model_copy(update=update, deep=deep)
        # A model passed in ``update`` was never put in a section: the copy
        # carries its values into everything it holds, as a config's copy does.
        carry_environment_values(copied, copied._redaction_values())
        return copied


def carry_environment_values(value: Any, values: Iterable[str]) -> None:
    """Give every section in *value* the environment values *values*.

    Walks models of this kind and the lists, tuples, sets and dicts their
    fields and extras hold; another model is left alone, a plugin among them,
    which takes its context's values itself.
    """
    record_values = environment_strings(values)
    pending: List[Any] = [value]
    seen: Set[int] = set()
    while pending:
        item = pending.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, RedactedSection):
            # A record of its own, not one shared with a copy of the model.
            BaseModel.__setattr__(
                item, "_environment_record", _EnvironmentRecord(record_values)
            )
            pending.extend(item.__dict__.values())
            pending.extend((item.__pydantic_extra__ or {}).values())
        elif isinstance(item, (list, tuple, set, frozenset)):
            pending.extend(item)
        elif isinstance(item, dict):
            pending.extend(item.values())
