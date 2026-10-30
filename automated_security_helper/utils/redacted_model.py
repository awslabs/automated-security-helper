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
import copy
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
    NoReturn,
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
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
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

    def __reduce__(self) -> Tuple[Any, ...]:
        # Rebuilt through the constructor and not through a state: pickle
        # protocols 0 and 1 skip __setstate__ when __getstate__ is falsy, and
        # a record with no values (the empty tuple) is, so its only slot stayed
        # unset and reading it raised AttributeError.
        return (_EnvironmentRecord, (self.values,))

    def __repr__(self) -> str:
        return "_EnvironmentRecord(...)"


def _merged_values(held: Tuple[str, ...], values: Tuple[str, ...]) -> Tuple[str, ...]:
    """*held* followed by the entries of *values* it does not hold yet."""
    if not held:
        return values
    added = tuple(value for value in values if value not in held)
    return held + added if added else held


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
    ``${variable}`` form of a variable that was read. An empty *shown* is
    left out too, on purpose: ``shown`` is what a summary row prints, and an
    empty one would print nothing where the value came from the environment
    (tests/unit/utils/test_env_resolved_scalar_survives_copying.py pins it).
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
    anything else unchanged (:func:`_unwrap_with_metadata`, the type alone)."""
    return _unwrap_with_metadata(annotation, seen)[0]


def _unwrap_with_metadata(
    annotation: Any, seen: Optional[Set[Any]] = None
) -> Tuple[Any, List[Any]]:
    """The underlying type of an Annotated shape, a NewType or a TypeAliasType
    (parameterized or not), which pydantic expands to the type they stand for,
    with the ``Annotated`` metadata of every layer met on the way, outermost
    layer first; anything else unchanged with no metadata.

    None of the three is a type, a union or a generic alias with arguments of
    its own, so a reader that looks only at those finds no slot in them. An
    alias that names itself comes back as Any the second time it is met in
    *seen* (shared by a caller that recurses), so the unwrapping ends.

    The metadata is read through an alias and a NewType as well as off the
    outer layers, because pydantic validates the alias's body, metadata
    included: ``type Lower = Annotated[str, AfterValidator(str.lower)]`` is a
    str slot that re-spells its text, and a reader that unwrapped the alias to
    the bare str while collecting metadata from the outer layers only took it
    for a slot that keeps the text."""
    if seen is None:
        seen = set()
    metadata: List[Any] = []
    while True:
        origin = get_origin(annotation)
        if origin is Annotated:
            annotation, *more = get_args(annotation)
            metadata.extend(more)
        elif hasattr(annotation, "__supertype__"):
            annotation = annotation.__supertype__
        elif isinstance(annotation, _TYPE_ALIAS_TYPES) or isinstance(
            origin, _TYPE_ALIAS_TYPES
        ):
            if annotation in seen:
                return Any, metadata
            seen.add(annotation)
            alias = annotation if origin is None else origin
            try:
                value = alias.__value__
            except Exception:  # a name the alias refers to is not defined
                return Any, metadata
            parameters = getattr(alias, "__type_params__", ()) if origin else ()
            annotation = (
                _bound(value, dict(zip(parameters, get_args(annotation))))
                if parameters
                else value
            )
        else:
            return annotation, metadata


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
    reader cannot interpret (a forward reference, an unparameterized container
    at the slot) admits, which keeps the downcast the default where nothing is
    known to convert. A TypeVar is read as pydantic validates it: through its
    bound, or as the union of its constraints, and as anything when it has
    neither. A class that the subclass check refuses to read (a TypedDict, a
    Protocol that is not runtime-checkable) is the one refused shape that is
    not a converter: no str can land in it, since pydantic checks the first
    as a mapping and cannot build a schema for the second without
    ``arbitrary_types_allowed``, whose isinstance check then raises on every
    value. A refusal by name is the better answer there than the error
    pydantic would give.

    A slot whose ``Annotated`` metadata is not known to leave the text alone
    (a validator, a ``StringConstraints`` that lowers or strips, a
    ``union_mode``, a pattern) is read by validating *text* through the
    whole annotation: the text is refused when the validation gives back
    something else (:func:`_text_survives`). Reading the underlying type alone
    admitted a str slot that re-spells the text, which then printed in a
    spelling the needle never matched.

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
    metadata = _annotated_metadata(annotation)
    admitted = _admits_unwrapped_str(_unwrap_annotated(annotation), text)
    if (
        admitted
        and text is not None
        and any(not _inert_metadata(item) for item in metadata)
    ):
        return _text_survives(annotation, text)
    return admitted


def _annotated_metadata(annotation: Any) -> List[Any]:
    """The metadata of the ``Annotated`` layers around *annotation* and of
    those inside the NewTypes and type aliases it unwraps to
    (:func:`_unwrap_with_metadata`), outermost layer first; empty when it has
    none."""
    return _unwrap_with_metadata(annotation)[1]


def _typevar_bound(annotation: Any) -> Any:
    """What pydantic validates an unparameterized TypeVar as: its bound, or the
    union of its constraints; None when it has neither (it validates anything)
    or when a lazily evaluated bound cannot be read."""
    try:
        bound = annotation.__bound__
        constraints = annotation.__constraints__
    except Exception:  # a bound or constraint that names something undefined
        return None
    if bound is not None:
        return bound
    if constraints:
        return Union[constraints]
    return None


def _admits_unwrapped_str(annotation: Any, text: Optional[str]) -> bool:
    """:func:`_admits_plain_str` for an *annotation* whose ``Annotated`` layers,
    NewTypes and aliases are already unwrapped."""
    if annotation is Any or annotation is object or annotation is str:
        return True
    if isinstance(annotation, TypeVar):
        bound = _typevar_bound(annotation)
        return bound is None or _admits_plain_str(bound, text)
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
        if text is not None:
            for index, arm in enumerate(arms):
                if not (_admits_conditionally(arm) and _keeps_this_text(arm, text)):
                    continue
                # A Literal or constrained-str match is exact and wins
                # whatever the order. pydantic reads a str into an Enum
                # member laxly, as a sibling reads it into a number, and the
                # earlier arm wins a tie, so an Enum match counts only when no
                # converting arm before it takes this text.
                if _is_enum_arm(arm) and any(
                    _converts_a_plain_str(earlier) and _arm_accepts(earlier, text)
                    for earlier in arms[:index]
                ):
                    continue
                return True
        # Every arm counts as a possible converter, a conditional one too: an
        # IntEnum arm converts the text it matches by number.
        return not any(_converts_a_plain_str(arm) for arm in arms) and any(
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
            if issubclass(annotation, (SecretStr, SecretBytes)):
                return True
            if issubclass(annotation, str):
                # A str subclass that builds its own core schema may re-spell
                # the text it is given (a normalizing type), and what it does
                # cannot be read from the class: the container walk fails
                # closed on the same classes (_has_opaque_schema), and here
                # the text is validated and refused when it comes back as
                # something else.
                if text is not None and _has_opaque_schema(annotation):
                    return _text_survives(annotation, text)
                return True
            return issubclass(str, annotation)
        except TypeError:
            # Only a class the subclass check refuses to read lands here (a
            # TypedDict, a Protocol that is not runtime-checkable): no str
            # lands in either, so the slot refuses (see the docstring).
            return False
    return origin is None


def _admits_conditionally(annotation: Any) -> bool:
    """Whether *annotation* keeps a plain str only when the text satisfies it:
    a Literal (its constants), an Enum (its member values), a str under
    ``Annotated`` metadata that may refuse some text (a pattern, a length, a
    validator), or a str subclass, which pydantic checks by isinstance so a
    plain str never satisfies it. Such an arm keeps SOME strings and not
    others, and in a union the text it refuses falls to a sibling arm. The
    metadata is read through an alias or a NewType too (``int | Lower`` with
    ``type Lower = Annotated[str, AfterValidator(str.lower)]`` has a
    conditional arm, not a str arm that keeps every text)."""
    annotation, metadata = _unwrap_with_metadata(annotation)
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


#: The TypeAdapters that read a text or a container against a union arm (a
#: constrained str's own constraint, a converting sibling's acceptance, an
#: arm's validation of a container), one per annotation, and one per
#: annotation and config for the adapters built under a holder's config
#: (keyed by the config's id, the config kept alive by its entry so the id is
#: not reused); cleared at 256 as the alias cache is.
_ARM_ADAPTERS: Dict[Any, Any] = {}


def _arm_adapter(annotation: Any, config: Any = None) -> Any:
    """A TypeAdapter for *annotation*, cached by the annotation when it is
    hashable; None when pydantic cannot build one.

    With a *config* (the config in force around the slot, :data:`_WALK_CONFIG`)
    the adapter is built over ``List[annotation]`` under that config, the way
    :func:`_generated_aliases` builds its reader: a TypeAdapter refuses a
    config for a model, a dataclass or a TypedDict itself, so the config goes
    with the wrapper, and a TypedDict, NamedTuple or stdlib dataclass with no
    config of its own is then built under it, as pydantic builds it under the
    holder's (its ``alias_generator`` names the keys, its ``extra`` refuses
    undeclared ones), while a model keeps its own. A caller that passes a
    config validates ``[value]`` and reads the one item back."""
    key: Any = annotation if config is None else (annotation, id(config))
    try:
        cached = _ARM_ADAPTERS.get(key)
    except TypeError:  # an unhashable annotation is built each time
        cached = None
    if cached is not None:
        if config is None:
            return cached
        if cached[0] is config:
            return cached[1]
    try:
        adapter = (
            TypeAdapter(annotation)
            if config is None
            else TypeAdapter(List[annotation], config=config)  # type: ignore[valid-type]
        )
    except Exception:  # a shape pydantic cannot build is not read
        return None
    if len(_ARM_ADAPTERS) >= 256:
        _ARM_ADAPTERS.clear()
    with contextlib.suppress(TypeError):
        _ARM_ADAPTERS[key] = adapter if config is None else (config, adapter)
    return adapter


def _arm_accepts(annotation: Any, text: str) -> bool:
    """Whether pydantic's lax read of *text* at *annotation* succeeds (an int
    arm takes "067", not "30s"); False when it raises or cannot be built."""
    adapter = _arm_adapter(annotation)
    if adapter is None:
        return False
    try:
        adapter.validate_python(text)
    except Exception:
        return False
    return True


def _text_survives(annotation: Any, text: str) -> bool:
    """Whether pydantic validates *text* at *annotation* and gives it back as
    it went in, which is what a slot must do for the text to print in the
    spelling the redaction needle matches.

    Read for a slot the type alone cannot answer for: ``Annotated`` metadata
    that may re-spell the text (a validator, ``StringConstraints(to_lower=True)``,
    a ``union_mode`` that lets an earlier arm convert it) and a str subclass
    that builds its own core schema. The answer is the validation's own, so no
    list of metadata kinds has to be kept. A secret type masks what it holds,
    so it counts as keeping the text; an Enum member counts through its value.

    Only a validation that succeeds and gives back something else makes the
    text unsafe: that is the conversion the refusal exists for. Text the slot
    refuses is admitted, because nothing is converted: pydantic fails the load
    there with an error of its own, and the printers of ASH never quote an
    error's input. A validation that raises anything else (a validator that
    needs the surrounding model's data, say) cannot be read, and the text is
    admitted as for any shape this reader cannot interpret. The text is handed
    over as a plain str, as the downcast hands it to the model."""
    adapter = _arm_adapter(annotation)
    if adapter is None:
        return True
    try:
        result = adapter.validate_python(str(text))
    except Exception:  # refused by the slot, or a validator that cannot be run
        return True
    if isinstance(result, (SecretStr, SecretBytes)):
        return True
    if isinstance(result, enum.Enum):
        result = result.value
    return isinstance(result, str) and result == text


def _is_enum_arm(annotation: Any) -> bool:
    annotation = _unwrap_annotated(annotation)
    try:
        return isinstance(annotation, type) and issubclass(annotation, enum.Enum)
    except TypeError:
        return False


def _keeps_this_text(annotation: Any, text: str) -> bool:
    """Whether a conditional arm (:func:`_admits_conditionally`) is known to
    keep *text* as it is: a Literal that lists it; an Enum whose members are
    all str and one of whose values is exactly *text* (found before any
    ``_missing_`` hook runs); or a constrained str whose strict read of *text*
    gives *text* back unchanged (a pattern or length it passes; a
    ``to_lower`` that re-spells it does not count). The constrained str is
    read through an alias or a NewType as well (:func:`_unwrap_with_metadata`),
    and validated as the annotation it was given, which is what pydantic
    validates."""
    bare, metadata = _unwrap_with_metadata(annotation)
    if bare is str and metadata:
        adapter = _arm_adapter(annotation)
        if adapter is None:
            return False
        try:
            return adapter.validate_python(text, strict=True) == text
        except Exception:
            return False
    annotation = bare
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
    if isinstance(annotation, TypeVar):
        bound = _typevar_bound(annotation)
        return bound is not None and _converts_a_plain_str(bound)
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
    if isinstance(annotation, TypeVar):
        # Worded by what pydantic validates it as: its bound, or its constraints.
        bound = _typevar_bound(annotation)
        if bound is not None:
            return _refused_noun(bound)
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
    for any other shape, and for an Enum with no members, which lists nothing
    to say (the caller words it by its name, as any other class)."""
    annotation = _unwrap_annotated(annotation)
    if get_origin(annotation) is Literal:
        return list(get_args(annotation)) or None
    if isinstance(annotation, type) and issubclass(annotation, enum.Enum):
        return [member.value for member in annotation] or None
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

#: Whether the walk runs for a config-file load (the ``strict_file_load``
#: context the loader passes). A union arm's validation (:func:`_arm_validates`)
#: is run with the same context, so a section arm answers as it will in the
#: real load: without it, a section arm accepted a reference at an opted typed
#: field that the load then refuses, and the walk vouched for a value the
#: union hands to a converting sibling.
_OPERATOR_ROUTE: "contextvars.ContextVar[bool]" = contextvars.ContextVar(
    "_OPERATOR_ROUTE", default=False
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
    """The validation alias of each field of the TypedDict, NamedTuple or
    standard-library dataclass *annotation* once *alias_generator* has been
    applied, by field name; None when it cannot be read.

    pydantic applies the generator while it builds the schema, to a copy of
    each field's metadata, so neither the class nor a bare ``FieldInfo``
    carries the result. It is read from the public ``core_schema`` of a
    ``TypeAdapter`` over ``List[annotation]``: TypeAdapter refuses a config for
    a TypedDict itself, so the config goes with the wrapper, and a TypedDict
    with a config of its own keeps it. The read depends on the core schema's
    dict shape (a ``typed-dict`` field's ``validation_alias``, a NamedTuple
    parameter's ``alias``, a ``dataclass-args`` field's ``validation_alias``),
    which is documented but less stable than a field
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
        elif isinstance(node, dict) and node.get("type") == "dataclass":
            arguments = node.get("schema")
            if (
                isinstance(arguments, dict)
                and arguments.get("type") == "dataclass-args"
            ):
                result = {
                    field["name"]: _alias_object(field.get("validation_alias"))
                    for field in arguments["fields"]
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
    # Each field's own annotation is read from a map no alias key is added
    # to: an earlier field's alias can land under a later field's own name
    # and turn that entry into an _AliasSlots, and the later field's alias
    # must then record the field's annotation, not the merged entry.
    own = {name: hints.get(name, Any) for name in names}
    by_name = dict(own)
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
                _add_alias_slot(by_name, path, own[name])
    return by_name


def _dataclass_field_info(dc_field: Any, hint: Any) -> FieldInfo:
    """pydantic's ``FieldInfo`` for the standard-library dataclass field
    *dc_field* annotated *hint* (the hint with its ``Annotated`` metadata): off
    the metadata, and off a ``Field(...)`` given as the field's default, which
    pydantic's ``collect_dataclass_fields`` reads the same way (``x: int =
    Field(alias="X")`` is read under the key ``X`` and is required when the
    Field carries no default). Raises what pydantic raises for metadata it
    refuses."""
    default = dc_field.default
    if isinstance(default, FieldInfo):
        return FieldInfo.from_annotated_attribute(hint, default)
    return FieldInfo.from_annotation(hint)


def _dataclass_field_is_required(dc_field: Any, info: FieldInfo) -> bool:
    """Whether pydantic requires the standard-library dataclass field
    *dc_field*: it has no default and no default factory, or its default is a
    ``Field(...)`` (read as *info*) that carries none."""
    if isinstance(dc_field.default, FieldInfo):
        return info.is_required()
    return (
        dc_field.default is dataclasses.MISSING
        and dc_field.default_factory is dataclasses.MISSING
    )


def _dataclass_fields(
    annotation: Any, bindings: Dict[Any, Any]
) -> Optional[Dict[Any, Any]]:
    """The annotation of each field a dataclass declares, by field name and by
    every key its validation alias reads, with the type variables in
    *bindings* replaced. None when the hints cannot be resolved.

    A pydantic dataclass carries its aliases in ``__pydantic_fields__``, like
    a model. A standard-library dataclass has none of its own, and pydantic
    reads a field's ``Field(alias=...)`` or ``Field(validation_alias=...)``
    off its ``Annotated`` metadata or off a ``Field(...)`` given as the field's
    default (:func:`_dataclass_field_info`), under the dataclass's own config
    (``pydantic.with_config``) or, without one, the config in force around it
    (the holder's, which pydantic applies to a stdlib dataclass used as a
    field), whose ``alias_generator`` names the keys of its fields
    (:func:`_generated_aliases`), as for a TypedDict."""
    try:
        hints = get_type_hints(annotation)
    except Exception:  # an unresolvable forward reference
        return None
    dc_fields = dataclasses.fields(annotation)
    own = {
        field.name: _bound(hints.get(field.name, Any), bindings) for field in dc_fields
    }
    by_name = dict(own)
    pydantic_fields = getattr(annotation, "__pydantic_fields__", None)
    if pydantic_fields is not None:
        for name, field in pydantic_fields.items():
            for alias in (field.alias, field.validation_alias):
                for path in _alias_paths(alias):
                    _add_alias_slot(by_name, path, own.get(name, Any))
        return by_name
    config = getattr(annotation, "__pydantic_config__", None)
    if config is None:
        config = _WALK_CONFIG.get()
    generator = config.get("alias_generator") if config else None
    generated = (
        _generated_aliases(annotation, generator) if generator is not None else None
    )
    try:
        declared = get_type_hints(annotation, include_extras=True)
    except Exception:  # an unresolvable forward reference
        declared = {}
    for field in dc_fields:
        name = field.name
        if generated is not None:
            aliases: Tuple[Any, ...] = (generated.get(name),)
        else:
            try:
                info = _dataclass_field_info(field, declared.get(name, Any))
            except Exception:  # metadata pydantic would refuse as well
                continue
            aliases = (info.alias, info.validation_alias)
        for alias in aliases:
            for path in _alias_paths(alias):
                _add_alias_slot(by_name, path, own[name])
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
        # depended on declaration order. Each annotation is rebuilt with the
        # field's own metadata (``Field(pattern=...)``, ``union_mode``, a
        # validator), which pydantic moves out of ``field.annotation``: a
        # reader of the bare annotation took a str slot that re-spells its
        # text for one that keeps it.
        own = {
            name: field.rebuild_annotation()
            for name, field in annotation.model_fields.items()
        }
        fields.update(own)
        for name, field in annotation.model_fields.items():
            for alias in (field.alias, field.validation_alias):
                for path in _alias_paths(alias):
                    _add_alias_slot(fields, path, own[name])
        return fields
    if dataclasses.is_dataclass(annotation):
        return _dataclass_fields(annotation, {})
    if typing_extensions.is_typeddict(annotation) or _is_named_tuple(annotation):
        return _typed_container_fields(annotation)
    return None


def _own_config(holder: Any) -> Any:
    """The config *holder* (a model, dataclass, TypedDict or NamedTuple class)
    carries itself; None when it has none of its own."""
    if isinstance(holder, type) and issubclass(holder, BaseModel):
        return holder.model_config
    return getattr(holder, "__pydantic_config__", None)


def _config_that_builds(holder: Any) -> Any:
    """The config pydantic builds *holder* under: its own, or, for a holder
    with no config of its own (a TypedDict, a NamedTuple, a stdlib dataclass),
    the one in force around it (:data:`_WALK_CONFIG`). A model keeps its own
    config, so the one around it does not reach its fields. None when there is
    neither."""
    config = _own_config(holder)
    if config is None and not (
        isinstance(holder, type) and issubclass(holder, BaseModel)
    ):
        config = _WALK_CONFIG.get()
    return config


def _forbids_extra_keys(holder: Any) -> bool:
    """Whether *holder* refuses a key it does not declare (``extra="forbid"``
    in the config it is built under, :func:`_config_that_builds`: a TypedDict
    under a section that forbids extras forbids them too)."""
    config = _config_that_builds(holder)
    return bool(config) and config.get("extra") == "forbid"


def _alias_generator_in_force(holder: Any) -> bool:
    """Whether an ``alias_generator`` names *holder*'s keys (in the config it
    is built under, :func:`_config_that_builds`)."""
    config = _config_that_builds(holder)
    return bool(config) and config.get("alias_generator") is not None


def _keys_for(name: str, *aliases: Any) -> Set[Any]:
    """The dict keys a field *name* can be given under: its own name and the
    first key of every path its *aliases* read."""
    keys: Set[Any] = {name}
    for alias in aliases:
        for path in _alias_paths(alias):
            keys.add(path[0])
    return keys


def _required_field_keys(holder: Any) -> Optional[List[Set[Any]]]:
    """For each field *holder* requires, the keys a dict can give it under;
    None when the holder cannot be read, or an alias generator names its keys
    (the generated keys are not resolved here, so every required field would
    read as absent)."""
    if _alias_generator_in_force(holder):
        return None
    if isinstance(holder, type) and issubclass(holder, BaseModel):
        return [
            _keys_for(name, field.alias, field.validation_alias)
            for name, field in holder.model_fields.items()
            if field.is_required()
        ]
    pydantic_fields = getattr(holder, "__pydantic_fields__", None)
    if dataclasses.is_dataclass(holder) and pydantic_fields is not None:
        return [
            _keys_for(name, field.alias, field.validation_alias)
            for name, field in pydantic_fields.items()
            if field.is_required()
        ]
    if dataclasses.is_dataclass(holder):
        # A stdlib dataclass field's Field(...) default is read as pydantic
        # reads it (_dataclass_field_info): its alias names a key, and it
        # leaves the field required when it carries no default.
        try:
            declared = typing_extensions.get_type_hints(holder, include_extras=True)
        except Exception:  # an unresolvable forward reference
            return None
        required: List[Set[Any]] = []
        for field in dataclasses.fields(holder):
            try:
                info = _dataclass_field_info(field, declared.get(field.name, Any))
            except Exception:  # metadata pydantic would refuse as well
                return None
            if _dataclass_field_is_required(field, info):
                required.append(
                    _keys_for(field.name, info.alias, info.validation_alias)
                )
        return required
    if typing_extensions.is_typeddict(holder):
        names = list(getattr(holder, "__required_keys__", ()))
    elif _is_named_tuple(holder):
        defaults = getattr(holder, "_field_defaults", {})
        names = [name for name in holder._fields if name not in defaults]
    else:
        return None
    try:
        declared = typing_extensions.get_type_hints(holder, include_extras=True)
    except Exception:  # an unresolvable forward reference
        return None
    required = []
    for name in names:
        try:
            info = FieldInfo.from_annotation(declared.get(name, Any))
        except Exception:  # metadata pydantic would refuse as well
            return None
        required.append(_keys_for(name, info.alias, info.validation_alias))
    return required


def _arm_would_take(arm: Any, value: Any) -> bool:
    """Whether a union *arm* that can hold the container *value* would also
    accept it as pydantic validates it: by the shape it can read
    (:func:`_arm_structurally_takes`) and by validating the value at the arm
    (:func:`_arm_validates`)."""
    return _arm_structurally_takes(arm, value) and _arm_validates(arm, value)


def _arm_validates(arm: Any, value: Any) -> bool:
    """Whether pydantic validates the container *value* at the union *arm* at
    all, which the arm must do before it can speak for the value's markers.

    The shape test cannot see a rest of the value that the arm refuses: an
    arm ``List[str]`` keeps a marker as text yet fails on a sibling item that
    is a number, and then the union hands the whole list to ``List[int]``,
    which types the marker. Likewise a ``List[Literal["a"]]`` arm admits any
    text at its item slot while pydantic refuses text that is no constant. So
    the value goes through the arm's own validation, with the markers downcast
    as the validator hands them on, and an arm that raises a ValidationError
    does not vouch. A section arm under :data:`_SECTIONS_OPAQUE` is handed the
    value with its markers, since its own before-validator is what refuses
    the ones it cannot keep: a section that refuses the value is no arm for it
    either, and the sibling's finding is the union's answer.

    The arm is validated as pydantic will validate it: under the config in
    force around the slot (:data:`_WALK_CONFIG`, through :func:`_arm_adapter`'s
    wrapper), so a TypedDict, NamedTuple or stdlib dataclass arm with no config
    of its own reads its keys through the holder's ``alias_generator`` and
    refuses an undeclared key under the holder's ``extra="forbid"``, and with
    the load's context (:data:`_OPERATOR_ROUTE`), so a section arm refuses what
    it will refuse in the real load. Read under the default config, a
    camelCase arm was refused for a key it does read, and a forbidding arm
    vouched for a value pydantic hands to a converting sibling.

    A value that holds no marker has nothing for the arm to vouch for, and an
    arm pydantic cannot build, or whose validation raises anything but a
    ValidationError, cannot be read: both answer True, as before this read."""
    if not isinstance(value, (list, tuple, set, frozenset, dict)):
        return True
    if not _holds_env_scalar(value):
        return True
    config = _WALK_CONFIG.get()
    adapter = _arm_adapter(arm, config)
    if adapter is None:
        return True
    try:
        named = _root_annotation(arm)
        opaque = (
            _SECTIONS_OPAQUE.get()
            and isinstance(named, type)
            and issubclass(named, RedactedSection)
        )
        given = value if opaque else without_env_scalars(value)
        adapter.validate_python(
            [given] if config is not None else given,
            context={"strict_file_load": True} if _OPERATOR_ROUTE.get() else None,
        )
    except ValidationError:
        return False
    except Exception:  # an arm whose validation this reader cannot run
        return True
    return True


def _arm_structurally_takes(arm: Any, value: Any) -> bool:
    """Whether a union *arm* that can hold the container *value* would also
    accept it as pydantic validates it, as far as this reader can tell.

    A fixed tuple takes a sequence of its own length, and a NamedTuple one
    with at least its required fields and at most all of them. A model,
    dataclass, TypedDict or NamedTuple takes a dict only when it declares
    every key under which the value holds a marker (a marker under an
    undeclared key is never read, so the arm cannot vouch for it), is given
    every field it requires, and, when it forbids extras, is given no key it
    does not declare. pydantic refuses an arm that fails one of these, and a
    smart-mode union then hands the value to a sibling, so such an arm must
    not speak for the markers. Anything this reader cannot classify is taken.
    """
    arm = _root_annotation(arm)
    holder, _ = _typed_container_class(arm)
    if isinstance(value, (list, tuple, set, frozenset)):
        if get_origin(arm) is tuple:
            args = get_args(arm)
            return not args or Ellipsis in args or len(args) == len(value)
        if _is_named_tuple(holder):
            defaults = getattr(holder, "_field_defaults", {})
            return (
                len(holder._fields) - len(defaults) <= len(value) <= len(holder._fields)
            )
        return True
    if not isinstance(value, dict):
        return True
    fields = _declared_field_annotations(arm)
    if fields is None:
        return True
    for key, item in value.items():
        if key not in fields and (
            isinstance(key, EnvResolvedScalar) or _holds_env_scalar(item)
        ):
            return False
    if _forbids_extra_keys(holder) and any(key not in fields for key in value):
        return False
    required = _required_field_keys(holder)
    return required is None or all(
        any(key in value for key in keys) for keys in required
    )


def _marker_a_slot_would_type(
    annotation: Any, value: Any, as_item: bool = False
) -> Optional[Tuple[Any, ...]]:
    """The first marker in *value* at a slot that would convert it, with that
    slot's annotation and whether the slot is the item of a sequence or a
    mapping, as ``(marker, slot, as_item)``; None when every marker sits
    where a plain str lands. A container sitting at a slot no arm of which
    can hold a container comes back as ``(marker, slot, as_item, container)``,
    so the refusal can speak of the container rather than the reference.

    Walks the annotation beside the value: a dict's keys against the key
    argument and its values against the value argument, a sequence's items
    against the item argument (positionally for a fixed tuple, whether the
    value is a list or a tuple), a union against each arm that can describe
    the value at all (:func:`_shape_can_hold`) and that pydantic would accept
    it at (:func:`_arm_would_take`), where one such arm that keeps every
    marker as text admits the value. An arm that cannot describe the value,
    or that pydantic would refuse for a reason the walk can read (a fixed
    tuple's length, a model's undeclared or missing keys), is skipped, never
    counted as admitting it: a smart-mode union hands the value to a sibling
    arm instead. A slot the annotation does not describe is left to the
    downcast, as before.

    *as_item* says the slot being walked is a sequence's or a mapping's item.
    The field of a model sitting in such an item is not one: it is a field,
    so the walk of a model's entries starts over with it False.

    Under :data:`_SECTIONS_OPAQUE` a slot annotated as a RedactedSection
    subclass, bare or behind ``Annotated`` or a RootModel, answers None
    whatever sits in it: those markers are the section's own validator's to
    judge (its ``_env_scalar_typed_fields`` opt-in among them).
    """
    if _SECTIONS_OPAQUE.get():
        named = _root_annotation(annotation)
        if isinstance(named, type) and issubclass(named, RedactedSection):
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
    if (
        isinstance(value, (list, tuple, set, frozenset, dict))
        and _no_arm_can_hold(annotation, value)
        and not _type_check_decides(annotation, ())
    ):
        # The slot has no shape for a container at all (an int, a str, a
        # Path, a Literal), so pydantic would refuse the container with its
        # own error, which names no variable and echoes the downcast copy's
        # resolved text as the input. Refuse by name instead, in the words the
        # top level uses for the same shape (_refuse_container_at_scalar): the
        # container is what the slot cannot take, so neither "write the value
        # in the file" nor the Path | str idiom would help. Where the type
        # check speaks for the slot, as there, it is left to it.
        marker = first_env_scalar(value)
        if marker is not None:
            return marker, annotation, as_item, value
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
            if typed is not None:
                found = found or typed
            elif _arm_would_take(arm, value):
                # Only an arm pydantic would accept speaks for every marker
                # as kept. An arm it would refuse (a fixed tuple of another
                # length, a model given a key it does not declare) still
                # refuses a marker at a converting slot it does read, so the
                # shared prefix of a too-long tuple is read as before.
                return None
        return found
    if isinstance(value, dict):
        fields = _declared_field_annotations(annotation)
        if fields is not None:
            # A model or dataclass takes the dict by field name: each entry
            # is walked against the annotation of the field it lands on, as
            # a section's own validator would walk it, except that a
            # section's _env_scalar_typed_fields opt-in is not honored (see
            # _declared_field_annotations). An entry no field names is left
            # to the model's own extra-key policy, which reads it against
            # the model's declared ``__pydantic_extra__`` type when there is
            # one (_typed_extras_annotation).
            with _config_in_force(annotation):
                extras_annotation: Any = _ABSENT
                for key, item in value.items():
                    if key in fields:
                        typed = _marker_a_slot_would_type(fields[key], item)
                    elif _holds_env_scalar(item):
                        if extras_annotation is _ABSENT:
                            extras_annotation = _typed_extras_annotation(annotation)
                        typed = (
                            None
                            if extras_annotation is None
                            else _marker_a_slot_would_type(extras_annotation, item)
                        )
                    else:
                        typed = None
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
        if len(args) > 1:
            value_annotation = args[1]
        elif isinstance(origin, type) and issubclass(origin, collections.Counter):
            # A Counter names its keys only: pydantic validates its values as
            # int, so the walk reads them as int and not as anything.
            value_annotation = int
        else:
            value_annotation = Any
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
            # A set has no order of its own: its members are read references
            # first, by variable name (_set_member_order), so the reference a
            # refusal names is the same on every run and not the one a hash
            # seed put first.
            members = (
                sorted(value, key=_set_member_order)
                if isinstance(value, (set, frozenset))
                else value
            )
            if origin is tuple and Ellipsis not in args:
                # A set or frozenset at a fixed tuple (a Python caller's
                # value): pydantic lands its members by iteration order, which
                # a set does not fix, so any member may reach any positional
                # slot. Each member is read against every slot, and a marker
                # is admitted only where every slot would keep it.
                pairs = ((arg, item) for item in members for arg in args)
            else:
                pairs = ((args[0], item) for item in members)
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


def _refuse_value_nested_too_deeply(value: Any, field_name: str) -> NoReturn:
    """Refuse a value whose nesting ran the typed walk past the interpreter's
    recursion limit, naming the field and the variable of the first reference
    it holds (:func:`first_env_scalar` is iterative, so it still answers) and
    never the value. The walk re-raises when the value holds no reference: the
    error was not this rule's to turn into a refusal."""
    marker = first_env_scalar(value)
    if marker is None:
        raise RecursionError("maximum recursion depth exceeded")
    raise ValueError(
        f"Input is nested too deeply to check: {field_name} holds a value "
        "nested deeper than a reference in it can be placed against the "
        f"field's type; it holds a reference to {marker.variable}. Write the "
        "value in the file, or write it with less nesting."
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
    route_token = _OPERATOR_ROUTE.set(operator_route)
    try:
        typed = _marker_a_slot_would_type(annotation, value)
    except RecursionError:
        # The walk descends once per nesting level of the value, beside a
        # recursive annotation, so a value nested past the interpreter's limit
        # ends here. It cannot be read, so it is refused by name, which is
        # the answer for a value whose references cannot be placed.
        _refuse_value_nested_too_deeply(value, field_name)
    finally:
        _OPERATOR_ROUTE.reset(route_token)
        _SECTIONS_OPAQUE.reset(opaque_token)
        _WALK_CONFIG.reset(token)
    if typed is not None:
        marker, slot, in_item, *container = typed
        if container:
            _refuse_container_at_scalar(marker, container[0], slot, field_name)
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

    Each container comes back as its base type (list, tuple, set, frozenset,
    dict), and a subclass (an OrderedDict, a NamedTuple, a list subclass) is
    no exception. That is the plain-builtin view a config file would have
    given, since no parser produces anything else, and it is what a dump
    needs: PyYAML's SafeDumper has a representer for the base types and none
    for a subclass, as it has none for a str subclass. A value that has to stay
    an instance of its own class is not passed through here.

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

    A member that holds a reference (a tuple or frozenset with one inside)
    sorts after the bare references, by the variable of the first reference it
    holds. Every other member (a plain str) sorts last and ties with its
    peers, so those keep the set's own iteration order among themselves; none
    holds a reference, so nothing that is read or named depends on it. A set
    of references, which is what a YAML ``!!set`` of environment references
    loads as, is fully ordered, and so is a set of tuples that hold some.
    """
    if isinstance(member, EnvResolvedScalar):
        return (0, member.variable)
    if isinstance(member, (tuple, frozenset)):
        held = first_env_scalar(member)
        if held is not None:
            return (1, held.variable)
    return (2, "")


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


def _downcast_outside_sections(annotation: Any, value: Any) -> Any:
    """*value*, a container at a field whose *annotation* reaches a section,
    with the EnvResolvedScalars at every slot that reaches NO section downcast
    to plain str, and every section-typed slot's value handed on as given.

    The section-reaching route of the section base's validator hands the
    value on whole so each section in the shape receives its markers (only its
    own validator knows every key its fields accept). A slot BESIDE a section
    that admits a string without converting it -- ``Any``, ``object``, a
    ``str`` -- then kept the marker class too: the walk refuses nothing there,
    and pydantic validates an Any slot by passing the object through, so the
    validated model carried the str subclass into a config dump (SafeDumper
    has no representer for one) and into whatever printed the slot by type.
    This walk follows the annotation's shape beside the sections:

    - a section-typed slot (a RedactedSection, through Annotated and RootModel
      wrappers) keeps its value as given;
    - a slot whose shape reaches no section is downcast whole
      (:func:`without_env_scalars`), as the non-section route downcasts;
    - a list, tuple, set or dict shape is walked per slot: a list's or set's
      item type, a tuple's per-position types or its one repeated type, a
      dict's key and value types;
    - a union of several non-None arms keeps the value as given: which arm
      describes a dict (``Union[Section, Dict[str, str]]``) is the arm's
      validation to decide, and downcasting under the wrong arm would strip
      the markers a section needs. ``Optional[X]`` is read as X.

    A value whose Python shape does not match the annotation's (a dict at a
    list slot) is kept as given; the field's own validation refuses it. The
    walk recurses per nesting level of the ANNOTATION, which is finite and
    written by the field's owner, so the config value's depth does not bound it.
    """
    annotation = _root_annotation(annotation)
    if isinstance(annotation, type) and issubclass(annotation, RedactedSection):
        return value
    if not _annotation_reaches_a_section(annotation):
        return without_env_scalars(value)
    origin = get_origin(annotation)
    args = get_args(annotation)
    if origin in (Union, types.UnionType):
        arms = [arm for arm in args if arm is not type(None)]
        if value is None or len(arms) != 1:
            return value
        return _downcast_outside_sections(arms[0], value)
    if not isinstance(origin, type) or not args:
        return value
    if issubclass(origin, collections.abc.Mapping):
        if not isinstance(value, dict) or len(args) != 2:
            return value
        key_type, value_type = args
        return {
            _downcast_outside_sections(key_type, key): _downcast_outside_sections(
                value_type, item
            )
            for key, item in value.items()
        }
    if issubclass(origin, tuple):
        if not isinstance(value, (list, tuple)):
            return value
        if len(args) == 2 and args[1] is Ellipsis:
            slots = [args[0]] * len(value)
        elif len(args) == len(value):
            slots = list(args)
        else:
            return value
        walked = [
            _downcast_outside_sections(slot, item) for slot, item in zip(slots, value)
        ]
        return tuple(walked) if isinstance(value, tuple) else walked
    if issubclass(origin, (collections.abc.Set, collections.abc.Sequence)):
        if not isinstance(value, (list, tuple, set, frozenset)) or len(args) != 1:
            return value
        walked = [_downcast_outside_sections(args[0], item) for item in value]
        if isinstance(value, (set, frozenset)):
            try:
                return type(value)(walked)
            except TypeError:
                # An unhashable item (a dict a section will take) cannot sit in
                # a set; the field's own validation says so.
                return value
        return tuple(walked) if isinstance(value, tuple) else walked
    return value


def _downcast_what_validation_kept(value: Any) -> Any:
    """*value*, validated, with every EnvResolvedScalar still in it downcast to
    plain str: in its lists, tuples, sets, frozensets, deques and dicts (keys
    too), in the fields of the dataclass instances it holds and in the
    attributes and extras of the plain models it holds, every container kept
    as the instance pydantic built.

    A validated value is pydantic's output, not the plain view a config file
    gives, so unlike :func:`without_env_scalars` this walk keeps each
    container's own class: a container that changes is rebuilt as a shallow
    copy of its own class (``copy.copy``: a defaultdict keeps its factory, an
    OrderedDict or a Counter its class, a deque its maxlen; a tuple is rebuilt
    as its class, a NamedTuple through ``_make``), a plain model as
    ``model_copy()`` and a dataclass instance as a copy, with the attributes
    rewritten on the copy past their own validation, which is the point: the
    marker is a str subclass the slot kept because it accepts anything.
    Rebuilt as base types, a validated ``OrderedDict`` came back a dict and a
    NamedTuple a tuple whose fields no longer answered by name; a deque and a
    dataclass instance were not walked and kept the marker. The text is
    unchanged, so equality, hashing and the model's dump are not.

    Nothing is written into the objects given: pydantic's Any and object
    slots return their input by identity, and a union of several arms is
    handed to pydantic as written (:func:`_downcast_outside_sections`), so a
    container in the validated value can be the caller's own payload object,
    and a rewrite in place would strip the markers out of the loader's payload
    (a second read of the same object, or of a sub-object it shares with
    another field, would then see plain text where a typed slot has to be
    refused by name). A section is left alone: its own validator downcast what
    it holds. A container that holds no marker comes back as it is, the same
    object. Iterative, in post-order, and cycle-safe like the walks above: a
    container that holds itself (no validated value does) is left as it is."""
    done: Dict[int, Any] = {}
    in_progress: Set[int] = set()
    stack: List[Tuple[Any, bool]] = [(value, False)]
    while stack:
        node, entries_done = stack.pop()
        if id(node) in done:
            continue
        if isinstance(node, EnvResolvedScalar):
            done[id(node)] = str(node)
        elif isinstance(node, RedactedSection) or not _is_kept_container(node):
            done[id(node)] = node
        elif not entries_done:
            if id(node) in in_progress:
                done[id(node)] = node
                continue
            in_progress.add(id(node))
            stack.append((node, True))
            stack.extend((entry, False) for entry in _kept_entries(node))
        else:
            in_progress.discard(id(node))
            done[id(node)] = _rebuilt_kept(node, done)
    return done[id(value)]


def _is_kept_container(node: Any) -> bool:
    """Whether :func:`_downcast_what_validation_kept` walks into *node*: a
    list, tuple, set, frozenset, deque or dict (or a subclass of one), a plain
    model, or a dataclass instance."""
    return isinstance(
        node, (list, tuple, set, frozenset, dict, collections.deque, BaseModel)
    ) or (dataclasses.is_dataclass(node) and not isinstance(node, type))


def _kept_entries(node: Any) -> List[Any]:
    """The entries of the container *node* (:func:`_is_kept_container`): a
    dict's keys and values, a model's attributes and extras, a dataclass
    instance's fields, a sequence's or set's items."""
    if isinstance(node, BaseModel):
        entries = list(node.__dict__.values())
        extras = node.__pydantic_extra__
        if extras:
            entries.extend(extras.values())
        return entries
    if isinstance(node, dict):
        return list(node.keys()) + list(node.values())
    if isinstance(node, (list, tuple, set, frozenset, collections.deque)):
        return list(node)
    return [
        entry
        for entry in (
            getattr(node, field.name, _ABSENT) for field in dataclasses.fields(node)
        )
        if entry is not _ABSENT
    ]


def _rebuilt_kept(node: Any, done: Dict[int, Any]) -> Any:
    """*node* with each entry replaced by its downcast form in *done* (keyed
    by the entry's id; an entry not there is kept), as a NEW object of
    *node*'s own class: a shallow copy with the entries rewritten for a
    mutable container, a model (``model_copy``) or a dataclass instance, a new
    instance for a tuple, a NamedTuple or a frozenset; *node* itself, not
    copied, when nothing in it changed. *node* is never written into: it may
    be the caller's own object (:func:`_downcast_what_validation_kept`)."""
    if isinstance(node, BaseModel):
        changed = False
        for entries in (node.__dict__, node.__pydantic_extra__):
            for entry in (entries or {}).values():
                if done.get(id(entry), entry) is not entry:
                    changed = True
        if not changed:
            return node
        fresh = node.model_copy()
        for entries in (fresh.__dict__, fresh.__pydantic_extra__):
            for name, entry in list((entries or {}).items()):
                replacement = done.get(id(entry), entry)
                if replacement is not entry:
                    entries[name] = replacement  # type: ignore[index]
        return fresh
    if isinstance(node, dict):
        items = [
            (done.get(id(key), key), done.get(id(entry), entry))
            for key, entry in node.items()
        ]
        if all(
            key is new_key and entry is new_entry
            for (new_key, new_entry), (key, entry) in zip(items, node.items())
        ):
            return node
        fresh = _shallow_copy_of(node, dict)
        fresh.clear()
        # One item at a time: a Counter's update() counts an iterable's
        # elements, a defaultdict's and an OrderedDict's take pairs; setting
        # each key is the one spelling every dict reads as a mapping write.
        for key, entry in items:
            fresh[key] = entry
        return fresh
    if isinstance(node, (list, tuple, set, frozenset, collections.deque)):
        given = list(node)
        entries = [done.get(id(entry), entry) for entry in given]
        if all(entry is new for entry, new in zip(given, entries)):
            return node
        if isinstance(node, list):
            fresh = _shallow_copy_of(node, list)
            fresh[:] = entries
            return fresh
        if isinstance(node, set):
            fresh = _shallow_copy_of(node, set)
            fresh.clear()
            fresh.update(entries)
            return fresh
        if isinstance(node, collections.deque):
            fresh = _shallow_copy_of(node, collections.deque)
            fresh.clear()
            fresh.extend(entries)
            return fresh
        kind = type(node)
        if isinstance(node, tuple):
            if _is_named_tuple(kind):
                return kind._make(entries)
            if kind is tuple:
                return tuple(entries)
            try:
                return kind(entries)
            except Exception:  # a tuple subclass with a constructor of its own
                return tuple(entries)
        if kind is frozenset:
            return frozenset(entries)
        try:
            return kind(entries)
        except Exception:  # a frozenset subclass with a constructor of its own
            return frozenset(entries)
    replacements = {}
    for field in dataclasses.fields(node):
        entry = getattr(node, field.name, _ABSENT)
        if entry is _ABSENT:
            continue
        replacement = done.get(id(entry), entry)
        if replacement is not entry:
            replacements[field.name] = replacement
    if not replacements:
        return node
    fresh = copy.copy(node)
    for name, replacement in replacements.items():
        # Past the dataclass's own validation, a frozen one included: the
        # text is unchanged, only its class.
        object.__setattr__(fresh, name, replacement)
    return fresh


def _shallow_copy_of(node: Any, base: type) -> Any:
    """A shallow copy of the container *node* as its own class (``copy.copy``
    keeps a defaultdict's factory, a Counter's or an OrderedDict's class, a
    deque's maxlen); a container of the plain *base* class when the class
    cannot be copied."""
    try:
        return copy.copy(node)
    except Exception:  # a subclass whose copy protocol fails
        return base(node)


#: The value annotation a model's declared ``__pydantic_extra__`` gives its
#: extras, by model; None for a model that declares none. Cleared at 256.
_EXTRAS_ANNOTATIONS: Dict[Any, Any] = {}


def _typed_extras_annotation(model: Any) -> Any:
    """The annotation pydantic validates each extra of *model* against: X of a
    ``__pydantic_extra__: Dict[str, X]`` declared on a model with
    ``extra="allow"``. None for a model that declares none, for one that
    declares a bare mapping (nothing is typed), and for a declaration that
    cannot be resolved (a forward reference to a local name)."""
    if not (isinstance(model, type) and issubclass(model, BaseModel)):
        return None
    if model in _EXTRAS_ANNOTATIONS:
        return _EXTRAS_ANNOTATIONS[model]
    found: Any = None
    if model.model_config.get("extra") == "allow":
        try:
            declared = typing_extensions.get_type_hints(model).get("__pydantic_extra__")
        except Exception:  # an annotation that names something undefined
            declared = None
        if declared is not None:
            args = get_args(_unwrap_annotated(declared))
            found = args[1] if len(args) == 2 else None
    if len(_EXTRAS_ANNOTATIONS) >= 256:
        _EXTRAS_ANNOTATIONS.clear()
    _EXTRAS_ANNOTATIONS[model] = found
    return found


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

    #: Whether the section's extras (``extra="allow"``) are downcast as its
    #: fields are: every EnvResolvedScalar an extra holds, a mapping key
    #: included, leaves the validated model as a plain str. False by default,
    #: because a segment model keeps an external plugin's raw config as an
    #: extra, and that config must still hold its markers when the plugin's own
    #: model validates it (a typed field there names the variable). A section
    #: whose extras are validated data, never a plugin's raw section, sets it
    #: True: a marker left in one is a str subclass in a validated model, which
    #: fails a config dump (SafeDumper has no representer for one).
    _downcast_extras: ClassVar[bool] = False

    @model_validator(mode="before")
    @classmethod
    def _env_resolved_text_in_typed_extras(cls, data: Any, info: ValidationInfo) -> Any:
        """Refuse a reference at an extra whose declared type would convert it.

        The field validator below sees declared fields only. A section that
        declares ``__pydantic_extra__: Dict[str, X]`` with ``extra="allow"``
        has pydantic validate each extra as X, so an X that converts the text
        (an int, a Path) typed an env-read value silently, in a spelling the
        redaction needle never matched. Each extra that holds a reference is
        walked against X as a field's value is, and refused by name where X
        cannot keep the text. A section with no declared extras type, or one
        whose X keeps the text (Any, str, a union with such an arm), is left
        as it was."""
        if not isinstance(data, dict):
            return data
        annotation = _typed_extras_annotation(cls)
        if annotation is None:
            return data
        operator_route = bool((info.context or {}).get("strict_file_load"))
        declared: Optional[Dict[Any, Any]] = None
        for key, item in data.items():
            if not _holds_env_scalar(item):
                continue
            if declared is None:
                declared = _declared_field_annotations(cls) or {}
            if key in declared:
                continue
            _refuse_typed_env_reference(
                annotation,
                item,
                # A key that is itself a reference prints as its text, which
                # is the value: name no key then.
                key if type(key) is str else "an extra",
                operator_route=operator_route,
                config=cls.model_config,
            )
        return data

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
        Values under a field that reaches another section are handed on with
        the section-typed slots' values as given, after a walk that treats
        those slots as opaque: that section's own validator sees its markers,
        and a typed slot beside a section in the same shape still refuses. A
        slot beside a section that admits a string as it is (``Any``, a
        ``str``) is downcast to plain str (:func:`_downcast_outside_sections`),
        as a field that reaches no section is: handed on whole, the marker
        class survived validation there and reached config dumps.
        """
        field_name = info.field_name
        if field_name is None:
            return value
        # The idiom hint ("type it `Path | str`") advises whoever owns the
        # field. On a config-file load the reader is the operator who wrote
        # the reference, and cannot retype a plugin's field: no hint there.
        operator_route = bool((info.context or {}).get("strict_file_load"))
        if isinstance(value, EnvResolvedScalar):
            field = cls.model_fields[field_name]
            annotation = field.annotation
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
            # The field's own metadata is read with the type: it may re-spell
            # the text (a pattern, a validator, a union_mode), and pydantic
            # keeps it apart from ``field.annotation``.
            if _admits_plain_str(field.rebuild_annotation(), str(value)):
                return str(value)
            _refuse_env_reference(value, _refused_noun(annotation), field_name, hint)
        if isinstance(value, (list, tuple, set, frozenset, dict)) and _holds_env_scalar(
            value
        ):
            annotation = cls.model_fields[field_name].annotation
            if _annotation_reaches_a_section(annotation):
                # The sections in the shape must receive their markers (only
                # their own validators know every key their fields accept),
                # so the section-typed slots' values are handed on
                # undowncast. A slot BESIDE a section (the int of
                # Tuple[Section, int]) still converts text, so the walk runs
                # first with section-typed slots opaque; a slot beside one
                # that admits the text as it is (the Any of Tuple[Section,
                # Any]) is then downcast, so the marker class reaches no
                # validated model.
                _refuse_typed_env_reference(
                    annotation,
                    value,
                    field_name,
                    operator_route=operator_route,
                    config=cls.model_config,
                    metadata=cls.model_fields[field_name].metadata,
                    sections_opaque=True,
                )
                return _downcast_outside_sections(annotation, value)
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

    @field_validator("*", mode="after")
    @classmethod
    def _env_resolved_text_validation_kept_reads_as_text(
        cls, value: Any, info: ValidationInfo
    ) -> Any:
        """Downcast the references that validation of a section-reaching field
        left in its value.

        A value under a field that reaches a section is handed to pydantic with
        its markers (the before-validator above), so the sections in it receive
        them. A slot beside a section that keeps its input as it is (an Any or
        object slot, a dict arm of a union with a section) keeps the marker
        too, and a union that picks the sibling arm leaves a str subclass in
        the validated model, which fails a config dump. The sections built in
        the value have downcast their own, so what is left sits outside them:
        it is downcast here, in containers and in the plain models the value
        holds."""
        if (
            not isinstance(value, (list, tuple, set, frozenset, dict, BaseModel))
            or info.field_name is None
            or not _annotation_reaches_a_section(
                cls.model_fields[info.field_name].annotation
            )
        ):
            return value
        return _downcast_what_validation_kept(value)

    @model_validator(mode="after")
    def _env_resolved_text_in_extras_reads_as_text(self) -> "RedactedSection":
        """Downcast the references an extra holds, for a section that sets
        :attr:`_downcast_extras`. The extras dict is changed in place.

        A value given for a field typed as a section is handed through its
        validators unchanged when it is already an instance
        (``revalidate_instances="never"``), and this validator then runs on it.
        A stand-in that passes the instance check without being one of these
        models (a ``MagicMock`` built with ``spec=``) has no class attributes
        and no extras dict to read, so it is left as given.

        The class is read as ``type(self)`` at each use and never bound to a
        name: the package's shown-text guard
        (tests/unit/utils/test_shown_text_is_shown_once.py) treats a name bound
        to a class taken from a value as that class everywhere in the module,
        so a ``cls`` bound here would make every classmethod's ``cls`` argument
        in this file read as a class from a value."""
        if not (
            isinstance(type(self), type) and issubclass(type(self), RedactedSection)
        ):
            return self
        if type(self)._downcast_extras:
            extras = self.__pydantic_extra__
            if extras and _holds_env_scalar(extras):
                downcast = without_env_scalars(extras)
                extras.clear()
                extras.update(downcast)
        return self

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

    def __pretty__(self, fmt: Any, **kwargs: Any) -> Any:
        """The pretty printer of devtools, which pydantic serves with each
        field's raw value taken from ``__repr_args__``, without the redaction
        :meth:`__repr_str__` applies to the text. It gets the redacted repr, as
        Rich does through :data:`NO_RICH_REPR`."""
        yield repr(self)

    def __setattr__(self, name: str, value: Any) -> None:
        super().__setattr__(name, value)
        if name in type(self).model_fields:
            # What the section now holds, not the argument: a model that
            # validates assignment stores a new object built from it (a dict
            # becomes a section), and the argument is not what it prints.
            stored = self.__dict__.get(name, value)
        else:
            # An extra (extra="allow") is stored beside the fields.
            extras = self.__pydantic_extra__
            if not extras or name not in extras:
                return
            stored = extras[name]
        carry_environment_values(stored, self._redaction_values())

    def model_copy(self, *, update: Any = None, deep: bool = False) -> Any:
        copied = super().model_copy(update=update, deep=deep)
        # A model passed in ``update`` was never put in a section: the copy
        # carries its values into everything it holds, as a config's copy does.
        carry_environment_values(copied, copied._redaction_values())
        return copied


def carry_environment_values(value: Any, values: Iterable[str]) -> None:
    """Give every section in *value* the environment values *values*.

    Walks models of this kind and the lists, tuples, sets and dicts their
    fields and extras hold, and a RootModel's root (a wrapper that holds one
    section and nothing else); another model is left alone, a plugin among
    them, which takes its context's values itself.

    A section keeps the values it already carries and takes *values* beside
    them. A section put into a holder with fewer values, or none, or into a
    second holder, would otherwise cease to redact what the first holder gave
    it, and its text would print the value again. The cost of keeping a value
    the holder no longer reads is a needle that redacts nothing.
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
            held = getattr(item, "_environment_record", None)
            BaseModel.__setattr__(
                item,
                "_environment_record",
                _EnvironmentRecord(
                    _merged_values(
                        held.values if held is not None else (), record_values
                    )
                ),
            )
            pending.extend(item.__dict__.values())
            pending.extend((item.__pydantic_extra__ or {}).values())
        elif isinstance(item, RootModel):
            pending.append(item.root)
        elif isinstance(item, (list, tuple, set, frozenset)):
            pending.extend(item)
        elif isinstance(item, dict):
            pending.extend(item.values())
