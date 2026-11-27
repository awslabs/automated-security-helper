"""Say which plugin config models break which of ten schema rules.

A plugin is configured through a pydantic model: its config class (C), whose
``options`` field holds an options model (O). The JSON schema of C is what ASH
publishes for the plugin and what an editor validates a config file against.
This module checks that schema, and the declarations around it, with one pure
function per rule. The command for plugin authors, and the walk over the shipped
plugins that finds what to check, are in ``cli/config_schema_check.py``.

The rules
---------

``RULES`` holds the one-sentence form of each. In short:

* P1 declared. The scanner class names C (``ScannerPluginBase[C]``), C types
  ``options`` with an options class of its own that derives from
  ``ScannerOptionsBase``, the manifest names that class as ``options_model``, and
  C's ``name`` default is the manifest's name.
* P2 generates. C and O produce a JSON schema, and so does the generator behind
  the published config schema.
* P3 closed. Every model in the schema refuses undeclared keys, or types them (a
  map), and validating with an undeclared key added at each nested model raises an
  error naming the key. A key that is kept or dropped without a word fails.
* P4 typed. Every value node has a type: no ``Any``, no array without items, no
  map without a typed value.
* P5 described. Every property has a non-empty description.
* P6 defaulted. C and O construct with no arguments, no model reached through
  properties requires a key, and every default validates against its own field.
* P7 bounded. Every integer or number property of a hand-written model declares a
  lower bound.
* P8 consistent keys. Every published key is snake_case, with one trailing
  underscore allowed on a reserved name; no two keys of one object fold to the
  same form once case, ``-`` and ``_`` are ignored; an alias never becomes the
  published spelling of a key that is not snake_case.
* P9 published. The committed AshConfig.json has a section for the scanner, with
  a description, that refers to its config class.
* P10 route declared. The manifest's ``tool_config`` route says how the tool's own
  configuration relates to the schema, and its claims hold: where the version
  comes from and that it matches, why an options model has no field of its own,
  and, for an upstream route, that the generated model is the pinned one.

Problems
--------

Each check function takes classes (or a schema dict) and returns a list of
``Problem(rule, path, text)`` rows. None of them prints or raises: a check that
fails to run comes back as a row of its own rule saying so, so a broken check
cannot read as a pass. ``path`` is a JSON pointer into what the rule reads:

* P2 to P8: C's JSON schema. ``""`` is C itself, ``/properties/options`` is its
  options field, ``/$defs/<Name>/properties/<key>`` a key of a nested model.
* P9: the committed AshConfig.json.
* P1 and P10: the plugin's manifest read as data, for example ``/options_model``
  or ``/tool_config/version``. The class-side facts of P1 use ``/config``,
  ``/config/options`` and ``/config/name``.

There is one row per (rule, path): rows that share both are joined into one text.
The root surface (the keys of AshConfig.json and AshWorkspaceConfig.json outside
the plugin sections) is checked by ``check_root_keys``.

Layering
--------

This module is in the contract layer and names no package above it, by an import
statement or by a string. It reads the classes, manifests and schema dicts it is
given, the committed schema files beside it, and the contract layer's own tables
(the ToolPins, the pins of the tool schemas, the generated modules). A manifest's
own references (its entry point, its options model, the constant of a route's
version source) are resolved with ``resolve_ref``, the way the manifest names them.
The two P10 sources that live in layers above this one, the versions in the
license table and the sentence that says only the operator sets an option, are
supplied through ``RouteSources`` by the command in ``cli/config_schema_check.py``,
which is in the layer that may read the whole tree.
"""

from __future__ import annotations

import functools
import hashlib
import importlib.util
import json
import keyword
import re
import typing
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple, ParamSpec
from urllib.parse import unquote

from pydantic import BaseModel, ValidationError

from automated_security_helper.base.plugin_manifest import resolve_ref

__all__ = [
    "RULES",
    "GeneratedModule",
    "Problem",
    "RouteSources",
    "body_sha256",
    "check_bounded",
    "check_closed",
    "check_config_model",
    "check_declared",
    "check_declared_class",
    "check_declared_manifest",
    "check_defaulted",
    "check_described",
    "check_generates",
    "check_keys",
    "check_published",
    "check_root_keys",
    "check_route",
    "check_scanner",
    "check_typed",
    "load_published",
    "options_model_of",
    "own_option_fields",
    "split_generated_module",
]

#: One sentence per rule, as the command's help prints them.
RULES: dict[str, str] = {
    "P1": (
        "declared: the scanner class names its config class, which types options "
        "with an options class of its own (not a generic base), and the manifest "
        "names that options class and the scanner's name"
    ),
    "P2": (
        "generates: the config class and the options class produce a JSON schema, "
        "including through the generator behind the published config schema"
    ),
    "P3": (
        "closed: every model in the schema refuses undeclared keys or types them, "
        "and validating with an undeclared key raises an error that names it"
    ),
    "P4": (
        "typed: every value has a type; no Any, no array without items, no map "
        "without a typed value"
    ),
    "P5": "described: every property has a non-empty description",
    "P6": (
        "defaulted: the config and options classes construct with no arguments, no "
        "model reached through properties requires a key, and every default "
        "validates against its own field"
    ),
    "P7": (
        "bounded: every integer or number property of a hand-written model "
        "declares a lower bound"
    ),
    "P8": (
        "consistent keys: every published key is snake_case (one trailing "
        "underscore on a reserved name), no two keys of one object differ only in "
        "case, '-' or '_', and no alias publishes a spelling that is not snake_case"
    ),
    "P9": (
        "published: the committed AshConfig.json has a described section for the "
        "scanner that refers to its config class"
    ),
    "P10": (
        "route declared: the manifest says how the tool's own configuration "
        "relates to the schema, and what it says about versions, options and the "
        "generated model is true"
    ),
}

#: The root properties of the config schema whose members are plugin sections:
#: their keys are plugin names, which follow the manifest-name rule, and each
#: section is checked as the config class of its plugin.
_PLUGIN_SEGMENTS = ("scanners", "reporters", "converters")

#: An undeclared key no model declares, used to probe what a model does with one.
PROBE_KEY = "ash_schema_check_undeclared_key"

#: Values of the wrong type for almost any value schema. A map that types its
#: values must refuse at least one of them; a scalar, a list, a nested object
#: and a string between them cover the types a value schema can name.
_WRONG_VALUES: tuple[Any, ...] = ([], {PROBE_KEY: []}, PROBE_KEY)

_KEY = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*")
_READ_AT = re.compile(r"[^/@\s]+/[^@\s]+@\S+")
_ABSENT = object()

P = ParamSpec("P")


@dataclass(frozen=True, slots=True)
class Problem:
    """One way a plugin's config schema falls short of one rule."""

    rule: str
    path: str
    text: str

    def sort_key(self) -> tuple[int, str, str]:
        number = self.rule[1:]
        return (int(number) if number.isdigit() else 0, self.path, self.text)


def _row(rule: str, path: str, text: str) -> Problem:
    """A problem whose text is one line, so a line of output holds one problem."""
    return Problem(rule, path, " ".join(text.split()))


def _describe(error: BaseException, limit: int = 300) -> str:
    text = " ".join(f"{type(error).__name__}: {error}".split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _merged(rows: Iterable[Problem]) -> list[Problem]:
    """One row per (rule, path), in rule order; texts that share both are joined."""
    texts: dict[tuple[str, str], list[str]] = {}
    for row in rows:
        parts = texts.setdefault((row.rule, row.path), [])
        if row.text not in parts:
            parts.append(row.text)
    joined = [Problem(rule, path, "; ".join(t)) for (rule, path), t in texts.items()]
    return sorted(joined, key=Problem.sort_key)


def _total(
    rule: str,
) -> Callable[[Callable[P, list[Problem]]], Callable[P, list[Problem]]]:
    """Make a check return its rows merged, and never raise.

    An error inside a check comes back as one row of the check's rule saying it
    could not run, so a defect in the checker, or in the model it was given, fails
    the gate with a message instead of passing it or stopping it with a traceback.
    """

    def decorate(check: Callable[P, list[Problem]]) -> Callable[P, list[Problem]]:
        @functools.wraps(check)
        def run(*args: P.args, **kwargs: P.kwargs) -> list[Problem]:
            try:
                return _merged(check(*args, **kwargs))
            except Exception as error:
                return [_row(rule, "", f"the check could not run: {_describe(error)}")]

        return run

    return decorate


# ---------------------------------------------------------------------------
# Reading a JSON schema.
# ---------------------------------------------------------------------------


def _esc(name: object) -> str:
    """A key as one JSON pointer segment."""
    return str(name).replace("~", "~0").replace("/", "~1")


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: object) -> Sequence[Any]:
    return value if isinstance(value, (list, tuple)) else ()


def _children(
    path: str, node: Mapping[str, Any]
) -> Iterator[tuple[str, Mapping[str, Any], str]]:
    """The schema nodes directly under ``node``: (pointer, node, role).

    The role says what the child is to its parent: ``def``, ``property``,
    ``item`` (an array's items), ``value`` (the value schema of a map), ``arm``
    (a member of anyOf, oneOf or allOf) or ``other`` (a constraint such as
    ``propertyNames``, which is not a value and has no type of its own).
    """
    for key in ("$defs", "definitions"):
        for name, child in _mapping(node.get(key)).items():
            if isinstance(child, Mapping):
                yield f"{path}/{key}/{_esc(name)}", child, "def"
    for name, child in _mapping(node.get("properties")).items():
        if isinstance(child, Mapping):
            yield f"{path}/properties/{_esc(name)}", child, "property"
    for name, child in _mapping(node.get("patternProperties")).items():
        if isinstance(child, Mapping):
            yield f"{path}/patternProperties/{_esc(name)}", child, "value"
    items = node.get("items")
    if isinstance(items, Mapping):
        yield f"{path}/items", items, "item"
    for index, child in enumerate(_sequence(node.get("prefixItems"))):
        if isinstance(child, Mapping):
            yield f"{path}/prefixItems/{index}", child, "item"
    extra = node.get("additionalProperties")
    if isinstance(extra, Mapping):
        yield f"{path}/additionalProperties", extra, "value"
    for key in ("anyOf", "oneOf", "allOf"):
        for index, child in enumerate(_sequence(node.get(key))):
            if isinstance(child, Mapping):
                yield f"{path}/{key}/{index}", child, "arm"
    for key in ("propertyNames", "not", "if", "then", "else", "contains"):
        child = node.get(key)
        if isinstance(child, Mapping):
            yield f"{path}/{key}", child, "other"


def _walk(
    node: Mapping[str, Any], path: str = "", role: str = "root"
) -> Iterator[tuple[str, Mapping[str, Any], str]]:
    """Every schema node of a document at its literal location, parents first.

    References are not followed: a definition is visited once, where it is
    defined, however many properties refer to it.
    """
    yield path, node, role
    for child_path, child, child_role in _children(path, node):
        yield from _walk(child, child_path, child_role)


def _lookup(
    schema: Mapping[str, Any], ref: str
) -> tuple[str, Mapping[str, Any]] | None:
    """The node a local ``$ref`` names, with its pointer, or None."""
    if not ref.startswith("#/"):
        return None
    node: Any = schema
    parts: list[str] = []
    for raw in ref[2:].split("/"):
        part = unquote(raw).replace("~1", "/").replace("~0", "~")
        if not isinstance(node, Mapping) or part not in node:
            return None
        node = node[part]
        parts.append(part)
    if not isinstance(node, Mapping):
        return None
    return "".join("/" + _esc(part) for part in parts), node


def _follow(
    schema: Mapping[str, Any], path: str, node: Mapping[str, Any]
) -> tuple[str, Mapping[str, Any]] | None:
    """The node a chain of ``$ref`` ends at, or None when a reference is broken."""
    for _ in range(16):
        ref = node.get("$ref")
        if not isinstance(ref, str):
            return path, node
        target = _lookup(schema, ref)
        if target is None:
            return None
        path, node = target
    return None


def _types(node: Mapping[str, Any]) -> set[str]:
    declared = node.get("type")
    if isinstance(declared, str):
        return {declared}
    return {t for t in _sequence(declared) if isinstance(t, str)}


def _is_model(node: Mapping[str, Any]) -> bool:
    """An object that declares keys: a model, as opposed to a map."""
    return isinstance(node.get("properties"), Mapping)


def _is_map(node: Mapping[str, Any]) -> bool:
    return "object" in _types(node) and not _is_model(node)


def _object_targets(
    schema: Mapping[str, Any], path: str, node: Mapping[str, Any], depth: int = 0
) -> list[tuple[str, Mapping[str, Any]]]:
    """The models and maps a property's schema stands for.

    Through ``$ref`` and through the arms of anyOf, oneOf and allOf (an optional
    model is an anyOf of the model and null), but not through arrays or maps.
    """
    if depth > 8:
        return []
    followed = _follow(schema, path, node)
    if followed is None:
        return []
    path, node = followed
    found: list[tuple[str, Mapping[str, Any]]] = []
    for key in ("anyOf", "oneOf", "allOf"):
        for index, arm in enumerate(_sequence(node.get(key))):
            if isinstance(arm, Mapping):
                found += _object_targets(
                    schema, f"{path}/{key}/{index}", arm, depth + 1
                )
    if _is_model(node) or _is_map(node):
        found.append((path, node))
    return found


def _property_graph(
    schema: Mapping[str, Any],
) -> Iterator[tuple[tuple[str, ...], str, Mapping[str, Any]]]:
    """Each model or map reachable from the root through properties alone.

    Yields the property names on the way (the chain a document must nest them
    under), the node's pointer and the node, the root first. A node reached twice
    is yielded once.
    """
    root = _follow(schema, "", schema)
    if root is None:
        return
    seen = {root[0]}

    def visit(
        chain: tuple[str, ...], path: str, node: Mapping[str, Any]
    ) -> Iterator[tuple[tuple[str, ...], str, Mapping[str, Any]]]:
        yield chain, path, node
        for name, child in _mapping(node.get("properties")).items():
            if not isinstance(child, Mapping):
                continue
            where = f"{path}/properties/{_esc(name)}"
            for target_path, target in _object_targets(schema, where, child):
                if target_path in seen:
                    continue
                seen.add(target_path)
                yield from visit((*chain, str(name)), target_path, target)

    yield from visit((), root[0], root[1])


def _reachable(
    schema: Mapping[str, Any], skip: Iterable[str] = ()
) -> list[tuple[str, Mapping[str, Any]]]:
    """Every node reachable from the root, references followed, in document order.

    The properties of the root named in ``skip`` are not entered.
    """
    skipped = set(skip)
    seen: set[str] = set()
    found: list[tuple[str, Mapping[str, Any]]] = []
    stack: list[tuple[str, Mapping[str, Any], bool]] = [("", schema, True)]
    while stack:
        path, node, is_root = stack.pop()
        followed = _follow(schema, path, node)
        if followed is None:
            continue
        path, node = followed
        if path in seen:
            continue
        seen.add(path)
        found.append((path, node))
        children: list[tuple[str, Mapping[str, Any]]] = []
        for name, child in _mapping(node.get("properties")).items():
            if is_root and name in skipped:
                continue
            if isinstance(child, Mapping):
                children.append((f"{path}/properties/{_esc(name)}", child))
        for child_path, child, role in _children(path, node):
            if role in ("item", "value", "arm"):
                children.append((child_path, child))
        for child_path, child in reversed(children):
            stack.append((child_path, child, False))
    return found


def _schema_or_none(config_class: type[BaseModel]) -> dict[str, Any] | None:
    """C's JSON schema in validation mode, or None when it cannot be generated
    (P2 says why)."""
    try:
        return config_class.model_json_schema()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Reading the classes.
# ---------------------------------------------------------------------------


def _as_model(annotation: Any) -> type[BaseModel] | None:
    if isinstance(annotation, type) and typing.get_origin(annotation) is None:
        try:
            return annotation if issubclass(annotation, BaseModel) else None
        except TypeError:
            return None
    return None


def _first_model(annotation: Any) -> type[BaseModel] | None:
    """The first model an annotation names, through Optional, unions and Annotated."""
    found = _as_model(annotation)
    if found is not None:
        return found
    for argument in typing.get_args(annotation):
        found = _first_model(argument)
        if found is not None:
            return found
    return None


def _collect_models(annotation: Any, found: dict[type[BaseModel], None]) -> None:
    model = _as_model(annotation)
    if model is not None:
        if model not in found:
            found[model] = None
            for info in model.model_fields.values():
                _collect_models(info.annotation, found)
        return
    for argument in typing.get_args(annotation):
        _collect_models(argument, found)


def _models_in(config_class: type[BaseModel]) -> list[type[BaseModel]]:
    """The class and every model its fields name, directly or inside containers."""
    found: dict[type[BaseModel], None] = {}
    _collect_models(config_class, found)
    return list(found)


def options_model_of(config_class: type[BaseModel]) -> type[BaseModel] | None:
    """The model C types its ``options`` field with, or None."""
    info = config_class.model_fields.get("options")
    return None if info is None else _first_model(info.annotation)


def _generic_option_bases() -> tuple[type[BaseModel], ...]:
    from automated_security_helper.base.options import _GENERIC_OPTION_BASES

    return tuple(_GENERIC_OPTION_BASES)


def own_option_fields(options_class: type[BaseModel]) -> list[str]:
    """The fields O declares for itself.

    A field that O, or a base between O and ``ScannerOptionsBase``, declares and
    that no generic options base declares. A scanner that only redeclares
    ``offline`` to describe it has none.
    """
    generic: set[str] = set()
    for base in _generic_option_bases():
        generic.update(base.model_fields)
    return [name for name in options_class.model_fields if name not in generic]


def _ref_of(cls: type) -> str:
    return f"{cls.__module__}:{cls.__qualname__}"


def _name_default(config_class: type[BaseModel] | None) -> str:
    if config_class is None:
        return ""
    info = config_class.model_fields.get("name")
    default = getattr(info, "default", None)
    return default if isinstance(default, str) else ""


def _declared_config(scanner_class: type) -> type[BaseModel] | None:
    from automated_security_helper.base.plugin_config import declared_config_model
    from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase

    return declared_config_model(scanner_class, ScannerPluginConfigBase)


def _tool_config_base() -> type | None:
    """The base of models generated from a tool's own schema file, if it exists.

    The module that defines it is not in this tree yet. Until it is, every model
    is hand-written, the exemptions that depend on it do not apply, and the
    import is skipped.
    """
    try:
        found = resolve_ref("automated_security_helper.base.tool_config:ToolConfigBase")
    except Exception:
        return None
    return found if isinstance(found, type) else None


# ---------------------------------------------------------------------------
# P1: declared.
# ---------------------------------------------------------------------------


@_total("P1")
def check_declared_class(scanner_class: type) -> list[Problem]:
    """The class half of P1: C is declared, O is the scanner's own, C has a name."""
    from automated_security_helper.base.options import ScannerOptionsBase

    config = _declared_config(scanner_class)
    if config is None:
        return [
            _row(
                "P1",
                "/config",
                f"{scanner_class.__name__} does not declare its config class: write "
                "ScannerPluginBase[<Config>] with a Config that derives from "
                "ScannerPluginConfigBase",
            )
        ]
    rows: list[Problem] = []
    options = options_model_of(config)
    if options is None:
        rows.append(
            _row(
                "P1",
                "/config/options",
                f"{config.__name__} declares no options model: type its options "
                "field with a class of the scanner's own",
            )
        )
    elif options in _generic_option_bases():
        rows.append(
            _row(
                "P1",
                "/config/options",
                f"{config.__name__} types options with the generic {options.__name__}, "
                "which declares none of the scanner's settings: give the scanner an "
                "options class of its own",
            )
        )
    elif not issubclass(options, ScannerOptionsBase):
        rows.append(
            _row(
                "P1",
                "/config/options",
                f"{options.__name__} does not derive from ScannerOptionsBase",
            )
        )
    if not _name_default(config):
        rows.append(
            _row(
                "P1",
                "/config/name",
                f"{config.__name__} has no name default: the name is the key the "
                "scanner is configured under",
            )
        )
    return rows


@_total("P1")
def check_declared_manifest(
    manifest: Any, scanner_class: type | None = None
) -> list[Problem]:
    """The manifest half of P1: the manifest and the scanner class agree."""
    rows: list[Problem] = []
    entry = str(getattr(getattr(manifest, "entry_points", None), "scanner", "") or "")
    if scanner_class is None:
        rows.append(
            _row(
                "P1",
                "/entry_points/scanner",
                f"names {entry!r} as its scanner class, but no plugin package "
                "registers a class by that name in ASH_SCANNERS",
            )
        )
    elif entry != _ref_of(scanner_class):
        rows.append(
            _row(
                "P1",
                "/entry_points/scanner",
                f"names {entry!r}, but the registered class is "
                f"{_ref_of(scanner_class)!r}",
            )
        )
    config = _declared_config(scanner_class) if scanner_class is not None else None
    expected = options_model_of(config) if config is not None else None
    options_ref = str(getattr(manifest, "options_model", "") or "")
    try:
        resolved = resolve_ref(options_ref)
    except Exception as error:
        rows.append(
            _row(
                "P1",
                "/options_model",
                f"{options_ref!r} does not resolve: {_describe(error)}",
            )
        )
    else:
        if _as_model(resolved) is None:
            rows.append(
                _row("P1", "/options_model", f"{options_ref!r} is not a model class")
            )
        elif expected is not None and resolved is not expected:
            rows.append(
                _row(
                    "P1",
                    "/options_model",
                    f"names {options_ref!r}, but the scanner's config types options "
                    f"as {_ref_of(expected)!r}",
                )
            )
    name = str(getattr(manifest, "name", "") or "")
    declared_name = _name_default(config)
    if config is not None and declared_name != name:
        rows.append(
            _row(
                "P1",
                "/name",
                f"is {name!r}, but the config class's name default is "
                f"{declared_name!r}",
            )
        )
    return rows


def check_declared(scanner_class: type | None, manifest: Any | None) -> list[Problem]:
    """P1: both halves, for a scanner that has a manifest."""
    rows: list[Problem] = []
    if scanner_class is not None:
        rows += check_declared_class(scanner_class)
    if manifest is not None:
        rows += check_declared_manifest(manifest, scanner_class)
    return _merged(rows)


# ---------------------------------------------------------------------------
# P2: generates.
# ---------------------------------------------------------------------------


@_total("P2")
def check_generates(config_class: type[BaseModel]) -> list[Problem]:
    """P2: the schemas of C and O generate, as the published file generates them."""
    from automated_security_helper.schemas.generate_schemas import ConfigFileJsonSchema

    builders: list[tuple[str, str, Callable[[], object]]] = [
        ("", "the config class's JSON schema", config_class.model_json_schema),
        (
            "",
            "the config file's JSON schema (the generator behind AshConfig.json)",
            lambda: config_class.model_json_schema(
                schema_generator=ConfigFileJsonSchema
            ),
        ),
    ]
    options = options_model_of(config_class)
    if options is not None:
        builders.append(
            (
                "/properties/options",
                "the options class's JSON schema",
                options.model_json_schema,
            )
        )
    rows: list[Problem] = []
    for path, what, build in builders:
        try:
            build()
        except Exception as error:
            rows.append(
                _row("P2", path, f"{what} cannot be generated: {_describe(error)}")
            )
    return rows


# ---------------------------------------------------------------------------
# P3: closed.
# ---------------------------------------------------------------------------


def _where(chain: tuple[str, ...]) -> str:
    return "the section itself" if not chain else "'" + ".".join(chain) + "'"


def _nest(chain: tuple[str, ...], payload: Any) -> Any:
    document = payload
    for name in reversed(chain):
        document = {name: document}
    return document


def _names_probe_key(error: ValidationError) -> bool:
    for entry in error.errors(include_input=False):
        parts = [*entry.get("loc", ()), entry.get("msg", "")]
        if any(PROBE_KEY in str(part) for part in parts):
            return True
    return False


def _kept(result: BaseModel, chain: tuple[str, ...]) -> bool:
    try:
        node: Any = result.model_dump(by_alias=True)
    except Exception:
        return False
    for name in chain:
        node = node.get(name) if isinstance(node, Mapping) else None
    return isinstance(node, Mapping) and PROBE_KEY in node


def _undeclared_key_row(
    config_class: type[BaseModel], chain: tuple[str, ...], path: str
) -> Problem | None:
    """A row when the model at ``chain`` does not refuse an undeclared key by name.

    Three outcomes are rows: the key is accepted and kept, accepted and dropped, or
    refused with an error that does not name it. Any other exception ends the probe
    without a row.
    """
    try:
        result = config_class.model_validate(_nest(chain, {PROBE_KEY: True}))
    except ValidationError as error:
        if _names_probe_key(error):
            return None
        return _row(
            "P3",
            path,
            f"validating with an undeclared key at {_where(chain)} is refused, but "
            "the error does not name the key: name it, so a misspelled option is "
            "easy to find",
        )
    except Exception:
        return None
    effect = "keeps it as an extra" if _kept(result, chain) else "drops it silently"
    return _row(
        "P3",
        path,
        f"validating with an undeclared key at {_where(chain)} raises no error: the "
        f"model {effect}; refuse unknown keys so a misspelled option is not ignored",
    )


def _wrong_type_row(
    config_class: type[BaseModel], chain: tuple[str, ...], path: str
) -> Problem | None:
    """A row when a node whose schema types its values accepts a wrong-typed one."""
    accepted = False
    for value in _WRONG_VALUES:
        try:
            config_class.model_validate(_nest(chain, {PROBE_KEY: value}))
        except ValidationError as error:
            if _names_probe_key(error):
                return None
        except Exception:
            continue
        else:
            accepted = True
    if not accepted:
        return None
    return _row(
        "P3",
        path,
        f"the schema types the values of undeclared keys at {_where(chain)}, but "
        "the model accepts values of the wrong type: type the extras or the map "
        "values on the model, not only in the schema",
    )


def _probe_rows(
    config_class: type[BaseModel], schema: Mapping[str, Any], skip: set[str]
) -> list[Problem]:
    try:
        config_class.model_validate({})
    except Exception:
        # The probe needs a valid empty section to add its key to. P6 reports that
        # the section does not construct, and says that this probe is skipped.
        return []
    rows: list[Problem] = []
    for chain, path, node in _property_graph(schema):
        if path in skip:
            continue
        extra = node.get("additionalProperties")
        row: Problem | None = None
        if isinstance(extra, Mapping) and extra:
            row = _wrong_type_row(config_class, chain, path)
        elif _is_model(node):
            row = _undeclared_key_row(config_class, chain, path)
        if row is not None:
            rows.append(row)
    return rows


@_total("P3")
def check_closed(
    config_class: type[BaseModel],
    schema: Mapping[str, Any] | None = None,
    *,
    open_nodes: Iterable[str] = (),
) -> list[Problem]:
    """P3: no model takes an undeclared key, in the schema or at run time.

    Schema half: every model (an object that declares properties) says
    ``additionalProperties: false`` or gives a value schema, never ``true`` and
    never nothing. Run-time half: validating C with an undeclared key added at
    each model reachable through properties must raise an error naming the key.
    For a node that types its undeclared keys, a map or a model with typed extras,
    the probe adds a key with a value of the wrong type instead and expects the
    same. A model reached only through a list or a map is checked by the schema
    half alone. A map whose values are untyped is P4's to report.

    ``open_nodes`` are pointers left open on purpose by the tool's own schema.
    """
    document = schema if schema is not None else _schema_or_none(config_class)
    if document is None:
        return []
    skip = set(open_nodes)
    rows: list[Problem] = []
    for path, node, _role in _walk(document):
        if path in skip or not _is_model(node):
            continue
        extra = node.get("additionalProperties", _ABSENT)
        if extra is False or (isinstance(extra, Mapping) and extra):
            continue
        if extra is _ABSENT:
            said = "absent"
        elif extra is True:
            said = "true"
        else:
            said = "an empty schema"
        rows.append(
            _row(
                "P3",
                path,
                f"the schema leaves this object open: additionalProperties is {said}; "
                "declare every key and set additionalProperties to false, or type "
                "the extras",
            )
        )
    rows += _probe_rows(config_class, document, skip)
    return rows


# ---------------------------------------------------------------------------
# P4: typed.
# ---------------------------------------------------------------------------

_TYPE_KEYS = ("type", "enum", "const", "$ref")
_COMBINATORS = ("anyOf", "oneOf", "allOf")
_VALUE_ROLES = ("root", "def", "property", "item", "value", "arm")


def _has_type(node: Mapping[str, Any]) -> bool:
    if any(key in node for key in _TYPE_KEYS):
        return True
    return any(_sequence(node.get(key)) for key in _COMBINATORS)


@_total("P4")
def check_typed(
    schema: Mapping[str, Any], *, open_nodes: Iterable[str] = ()
) -> list[Problem]:
    """P4: every value node has a type.

    A value node has ``type``, ``enum``, ``const``, ``$ref`` or an anyOf, oneOf or
    allOf whose members are each typed (each member is checked as a node of its
    own). An array declares ``items`` (or ``prefixItems``) and a map declares a
    value schema. pydantic's ``Any`` writes an empty schema, which fails.
    """
    skip = set(open_nodes)
    rows: list[Problem] = []
    for path, node, role in _walk(schema):
        if path in skip or role not in _VALUE_ROLES:
            continue
        if not _has_type(node):
            rows.append(
                _row(
                    "P4",
                    path,
                    "has no type: the schema is empty (an Any field, or a list or "
                    "dict with no item or value type); type the value",
                )
            )
            continue
        types = _types(node)
        if (
            "array" in types
            and not isinstance(node.get("items"), Mapping)
            and not _sequence(node.get("prefixItems"))
        ):
            rows.append(
                _row("P4", path, "is an array that declares no items: type its items")
            )
        if _is_map(node):
            extra = node.get("additionalProperties")
            typed_values = (isinstance(extra, Mapping) and bool(extra)) or bool(
                _mapping(node.get("patternProperties"))
            )
            if not typed_values:
                rows.append(
                    _row(
                        "P4",
                        path,
                        "is a map with no typed value schema: declare what its "
                        "values are, or declare its keys",
                    )
                )
    return rows


# ---------------------------------------------------------------------------
# P5: described.
# ---------------------------------------------------------------------------


@_total("P5")
def check_described(schema: Mapping[str, Any]) -> list[Problem]:
    """P5: every property of every model in the schema has a description."""
    rows: list[Problem] = []
    for path, node, _role in _walk(schema):
        for name, child in _mapping(node.get("properties")).items():
            description = (
                child.get("description") if isinstance(child, Mapping) else None
            )
            if not (isinstance(description, str) and description.strip()):
                rows.append(
                    _row(
                        "P5",
                        f"{path}/properties/{_esc(name)}",
                        f"property {name!r} has no description: say what it does "
                        "and what its values mean",
                    )
                )
    return rows


# ---------------------------------------------------------------------------
# P6: defaulted.
# ---------------------------------------------------------------------------


def _round_trip_rows(
    path: str, model: type[BaseModel], instance: BaseModel
) -> list[Problem]:
    try:
        dumped = instance.model_dump(mode="json", by_alias=True)
        again = model.model_validate(dumped)
    except ValidationError as error:
        rows: list[Problem] = []
        for entry in error.errors(include_input=False):
            loc = entry.get("loc", ())
            where = f"{path}/properties/{_esc(loc[0])}" if loc else path
            rows.append(
                _row(
                    "P6",
                    where,
                    f"a default does not validate against its own field: "
                    f"{entry.get('msg', '')}",
                )
            )
        return rows or [
            _row("P6", path, f"the defaults do not round trip: {_describe(error)}")
        ]
    except Exception as error:
        return [_row("P6", path, f"the defaults do not round trip: {_describe(error)}")]
    if again != instance:
        return [
            _row(
                "P6",
                path,
                "the defaults change when dumped and validated again: a default "
                "is not the value its own field accepts",
            )
        ]
    return []


#: What P6 adds when the config class does not construct: P3's run-time probe
#: validates an empty section with one undeclared key added, so it cannot run.
_PROBE_SKIPPED = (
    "the undeclared-key probe of P3 needs a valid empty section, so it is skipped"
)


def _options_pointer(schema: Mapping[str, Any] | None) -> str:
    """Where O sits in C's schema: its definition when the ``options`` property
    refers to one (``/$defs/<Name>``, where P5, P7 and P8 report O's keys), else
    the property itself."""
    where = "/properties/options"
    if schema is None:
        return where
    node = _mapping(_mapping(schema.get("properties")).get("options"))
    for target, _model in _object_targets(schema, where, node):
        return target
    return where


@_total("P6")
def check_defaulted(
    config_class: type[BaseModel], schema: Mapping[str, Any] | None = None
) -> list[Problem]:
    """P6: an empty section is valid, and a default is a value its field accepts.

    C and O construct with no arguments. No model reached from C through
    properties lists a required property (an item of a list or a value of a map
    may). And ``O.model_validate(O().model_dump(mode="json", by_alias=True))``
    equals ``O()``; a default that fails is reported at its key in O's
    definition. When C does not construct, the row says that P3's undeclared-key
    probe is skipped.
    """
    rows: list[Problem] = []
    document = schema if schema is not None else _schema_or_none(config_class)
    options = options_model_of(config_class)
    subjects: list[tuple[str, type[BaseModel], str]] = [
        ("", config_class, "the config class")
    ]
    if options is not None:
        subjects.append(("/properties/options", options, "the options class"))
    for path, model, label in subjects:
        try:
            instance = model()
        except Exception as error:
            text = f"{label} does not construct with no arguments: {_describe(error)}"
            if model is config_class:
                text += f"; {_PROBE_SKIPPED}"
            rows.append(_row("P6", path, text))
            continue
        if model is options:
            rows += _round_trip_rows(_options_pointer(document), model, instance)
    if document is not None:
        for _chain, path, node in _property_graph(document):
            required = [str(name) for name in _sequence(node.get("required"))]
            if required:
                rows.append(
                    _row(
                        "P6",
                        path,
                        f"lists required properties ({', '.join(required)}): an "
                        "empty section must be valid, so give each a default",
                    )
                )
    return rows


# ---------------------------------------------------------------------------
# P7: bounded.
# ---------------------------------------------------------------------------


def _is_unbounded_number(prop: Mapping[str, Any]) -> bool:
    arms = [prop]
    for key in ("anyOf", "oneOf"):
        arms += [arm for arm in _sequence(prop.get(key)) if isinstance(arm, Mapping)]
    for arm in arms:
        if not _types(arm) & {"integer", "number"}:
            continue
        if "enum" in arm or "const" in arm:
            continue
        if "minimum" not in arm and "exclusiveMinimum" not in arm:
            return True
    return False


def _generated_defs(
    config_class: type[BaseModel], schema: Mapping[str, Any]
) -> frozenset[str]:
    """The pointers of the definitions that models generated from a tool's own
    schema file define. Matched by class name, which is the definition's title."""
    base = _tool_config_base()
    if base is None:
        return frozenset()
    names = {m.__name__ for m in _models_in(config_class) if issubclass(m, base)}
    return frozenset(
        path
        for path, node, role in _walk(schema)
        if role == "def" and node.get("title") in names
    )


@_total("P7")
def check_bounded(
    schema: Mapping[str, Any], *, generated: Iterable[str] = ()
) -> list[Problem]:
    """P7: every integer or number property of a hand-written model has a floor.

    The schema must declare ``minimum`` or ``exclusiveMinimum`` for it. A model
    generated from a tool's own schema follows that schema and is exempt
    (``generated`` lists the pointers of its definitions); a property with an
    ``enum`` or a ``const`` is a closed set and needs no bound.
    """
    exempt = tuple(generated)
    rows: list[Problem] = []
    for path, node, _role in _walk(schema):
        if any(path == p or path.startswith(p + "/") for p in exempt):
            continue
        for name, child in _mapping(node.get("properties")).items():
            if isinstance(child, Mapping) and _is_unbounded_number(child):
                rows.append(
                    _row(
                        "P7",
                        f"{path}/properties/{_esc(name)}",
                        f"{name!r} is a number with no lower bound: give the field "
                        "ge or gt, so the schema declares minimum or exclusiveMinimum",
                    )
                )
    return rows


# ---------------------------------------------------------------------------
# P8: consistent keys.
# ---------------------------------------------------------------------------


def _is_reserved(bare: str, base: type | None) -> bool:
    return (
        keyword.iskeyword(bare)
        or bare in keyword.softkwlist
        or hasattr(BaseModel, bare)
        or (base is not None and hasattr(base, bare))
    )


def _fold(name: str) -> str:
    return re.sub(r"[-_]", "", name.lower())


def _key_rows(path: str, names: Sequence[str], base: type | None) -> list[Problem]:
    rows: list[Problem] = []
    for name in names:
        if _KEY.fullmatch(name):
            continue
        bare = name[:-1] if name.endswith("_") else ""
        where = f"{path}/properties/{_esc(name)}"
        if bare and _KEY.fullmatch(bare):
            if not _is_reserved(bare, base):
                rows.append(
                    _row(
                        "P8",
                        where,
                        f"{name!r} ends in an underscore, which is allowed only "
                        f"where {bare!r} is a Python keyword or an attribute of "
                        "pydantic's BaseModel; drop the underscore",
                    )
                )
            continue
        rows.append(
            _row(
                "P8",
                where,
                f"key {name!r} is not snake_case: publish snake_case, and keep the "
                "tool's own spelling as a validation alias whose first choice is "
                "the snake_case key",
            )
        )
    groups: dict[str, list[str]] = {}
    for name in names:
        groups.setdefault(_fold(name), []).append(name)
    for members in groups.values():
        if len(members) > 1:
            ordered = sorted(members)
            rows.append(
                _row(
                    "P8",
                    f"{path}/properties/{_esc(ordered[0])}",
                    "keys " + ", ".join(repr(m) for m in ordered) + " differ only in "
                    "case, '-' or '_': keep one",
                )
            )
    return rows


def _alias_rows(
    config_class: type[BaseModel], schema: Mapping[str, Any]
) -> list[Problem]:
    """A plain alias on a model that validates by name only.

    The schema publishes the alias while the model reads the field by its name,
    so the file ASH publishes and the file ASH reads disagree.
    """
    titles = {
        node.get("title"): path
        for path, node, role in _walk(schema)
        if role == "def" and isinstance(node.get("title"), str)
    }
    rows: list[Problem] = []
    for model in _models_in(config_class):
        if model.model_config.get("validate_by_alias", True) is not False:
            continue
        base = "" if model is config_class else titles.get(model.__name__, "")
        node: Mapping[str, Any] = schema
        if model is not config_class:
            found = _lookup(schema, f"#{base}") if base else None
            node = found[1] if found is not None else {}
        published = _mapping(node.get("properties"))
        for field_name, info in model.model_fields.items():
            alias = info.alias
            if alias is None and isinstance(info.validation_alias, str):
                alias = info.validation_alias
            if alias is None or alias == field_name:
                continue
            key = alias if alias in published else field_name
            rows.append(
                _row(
                    "P8",
                    f"{base}/properties/{_esc(key)}",
                    f"{model.__name__}.{field_name} has the alias {alias!r} but the "
                    "model validates by name only, so the published key and the key "
                    "the model reads disagree: drop the alias, or validate by alias",
                )
            )
    return rows


@_total("P8")
def check_keys(
    config_class: type[BaseModel], schema: Mapping[str, Any] | None = None
) -> list[Problem]:
    """P8: the keys a plugin's schema publishes follow one convention."""
    document = schema if schema is not None else _schema_or_none(config_class)
    if document is None:
        return []
    base = _tool_config_base()
    rows: list[Problem] = []
    for path, node, _role in _walk(document):
        properties = node.get("properties")
        if isinstance(properties, Mapping):
            rows += _key_rows(path, [str(name) for name in properties], base)
    rows += _alias_rows(config_class, document)
    return rows


@_total("P8")
def check_root_keys(
    root: type[BaseModel] | Mapping[str, Any],
    *,
    plugin_segments: Iterable[str] = _PLUGIN_SEGMENTS,
) -> list[Problem]:
    """P8 for the root surface: the keys of a config schema outside its plugins.

    ``root`` is the root model, or the schema as a dict (the committed
    AshConfig.json). The plugin segments of the root are not entered: their keys
    are plugin names, which follow the manifest-name rule, and each plugin's
    section is checked as the config class of that plugin.
    """
    document = root if isinstance(root, Mapping) else root.model_json_schema()
    base = _tool_config_base()
    rows: list[Problem] = []
    for path, node in _reachable(document, skip=plugin_segments):
        properties = node.get("properties")
        if isinstance(properties, Mapping):
            rows += _key_rows(path, [str(name) for name in properties], base)
    return rows


# ---------------------------------------------------------------------------
# P2 to P8 for one config model.
# ---------------------------------------------------------------------------


def check_config_model(
    config_class: type[BaseModel], *, open_nodes: Iterable[str] = ()
) -> list[Problem]:
    """P2 to P8 for any plugin's config class: a scanner's, a reporter's or a
    converter's. The rules that read the schema are skipped when P2 reports that
    it cannot be generated."""
    skip = tuple(open_nodes)
    rows = check_generates(config_class)
    schema = _schema_or_none(config_class)
    rows += check_defaulted(config_class, schema)
    if schema is not None:
        rows += check_closed(config_class, schema, open_nodes=skip)
        rows += check_typed(schema, open_nodes=skip)
        rows += check_described(schema)
        rows += check_bounded(schema, generated=_generated_defs(config_class, schema))
        rows += check_keys(config_class, schema)
    return _merged(rows)


# ---------------------------------------------------------------------------
# P9: published.
# ---------------------------------------------------------------------------


def _scanner_segment(
    published: Mapping[str, Any],
) -> tuple[str, Mapping[str, Any]] | None:
    start = _follow(published, "", published)
    if start is not None:
        root_path, root = start
        section = _mapping(root.get("properties")).get("scanners")
        if isinstance(section, Mapping):
            followed = _follow(published, f"{root_path}/properties/scanners", section)
            if followed is not None and _is_model(followed[1]):
                return followed
    fallback = _mapping(published.get("$defs")).get("ScannerConfigSegment")
    if isinstance(fallback, Mapping):
        return "/$defs/ScannerConfigSegment", fallback
    return None


@_total("P9")
def check_published(
    published: Mapping[str, Any],
    name: str,
    config_class: type[BaseModel] | None = None,
) -> list[Problem]:
    """P9: the committed AshConfig.json has this scanner's section.

    ``published`` is the schema as a dict. The section sits under the scanners
    segment, has a description and refers (``$ref``) to the scanner's config class.
    """
    segment = _scanner_segment(published)
    if segment is None:
        return [_row("P9", "", "the published schema has no scanners segment")]
    segment_path, node = segment
    section_path = f"{segment_path}/properties/{_esc(name)}"
    section = _mapping(node.get("properties")).get(name)
    if not isinstance(section, Mapping):
        return [
            _row(
                "P9",
                section_path,
                f"the published schema has no section for {name!r} under scanners: "
                "give the plugin a typed section so editors and docs show it",
            )
        ]
    rows: list[Problem] = []
    description = section.get("description")
    if not (isinstance(description, str) and description.strip()):
        rows.append(
            _row("P9", section_path, "the published section has no description")
        )
    ref = section.get("$ref")
    if not isinstance(ref, str):
        rows.append(
            _row("P9", section_path, "the published section does not refer to a model")
        )
    elif config_class is not None:
        target = ref.rsplit("/", 1)[-1]
        if target != config_class.__name__ and not target.endswith(
            "__" + config_class.__name__
        ):
            rows.append(
                _row(
                    "P9",
                    section_path,
                    f"the published section refers to {target!r}, not to the "
                    f"scanner's config class {config_class.__name__!r}",
                )
            )
    return rows


# ---------------------------------------------------------------------------
# P10: route declared.
# ---------------------------------------------------------------------------


class GeneratedModule(NamedTuple):
    """What P10 reads of a generated module: its text and its root class."""

    source: str
    root: Any


@dataclass(frozen=True)
class RouteSources:
    """Where P10 reads what a route is compared with.

    A field left as None is read from this installation where this module may read
    it: the ToolPins of ``base.plugin_provisioning``, the pins of
    ``plugin_manifests.tool_schemas`` (an empty mapping while that module does not
    exist) and the generated modules on the import path. Two sources are in layers
    above this module's, so the caller that checks the installed tree supplies
    them (``default_sources`` in ``cli/config_schema_check.py``): the versions of
    the license table, and the sentence an option's description ends with when only
    the operator sets it. Left as None they are empty: no license entry is found,
    and a route that needs the sentence is reported as one that cannot be checked.
    Tests inject their own.
    """

    pins: Mapping[str, Any] | None = None
    tool_pins: Mapping[str, str] | None = None
    license_versions: Mapping[str, str] | None = None
    load_module: Callable[[str, str], GeneratedModule | None] | None = None
    operator_sentence: str | None = None

    def pin(self, key: str) -> Any:
        if self.pins is not None:
            return self.pins.get(key)
        try:
            table = resolve_ref(
                "automated_security_helper.plugin_manifests.tool_schemas:PINS"
            )
        except Exception:
            return None
        return _mapping(table).get(key)

    def tool_version(self, name: str) -> str | None:
        if self.tool_pins is not None:
            return self.tool_pins.get(name)
        from automated_security_helper.base.plugin_provisioning import tool_versions

        return tool_versions().get(name)

    def license_version(self, key: str) -> str | None:
        if self.license_versions is None:
            return None
        return self.license_versions.get(key)

    def module(self, dotted: str, root_class: str) -> GeneratedModule | None:
        if self.load_module is not None:
            return self.load_module(dotted, root_class)
        return _load_generated_module(dotted, root_class)

    def operator_only_sentence(self) -> str:
        return self.operator_sentence or ""


def _load_generated_module(dotted: str, root_class: str) -> GeneratedModule | None:
    try:
        spec = importlib.util.find_spec(dotted)
    except (ImportError, ValueError):
        return None
    if spec is None or not spec.origin or not Path(spec.origin).is_file():
        return None
    source = Path(spec.origin).read_text(encoding="utf-8")
    try:
        root = resolve_ref(f"{dotted}:{root_class}")
    except AttributeError:
        root = None
    return GeneratedModule(source, root)


def split_generated_module(source: str) -> tuple[dict[str, str], str]:
    """The header fields and the body of a generated module's text.

    The header is the leading run of ``#`` lines; a ``# key: value`` line is a
    field (``source sha256``, ``body sha256``). The body is everything after the
    header, as written (a blank line that follows the header belongs to the body),
    with CRLF read as LF. The body hash is the SHA-256 of the body's UTF-8 bytes.
    """
    lines = source.replace("\r\n", "\n").split("\n")
    fields: dict[str, str] = {}
    end = 0
    while end < len(lines) and lines[end].startswith("#"):
        key, separator, value = lines[end][1:].partition(":")
        if separator:
            fields[key.strip().lower()] = value.strip()
        end += 1
    return fields, "\n".join(lines[end:])


def body_sha256(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _same_version(left: str, right: str) -> bool:
    return left.removeprefix("v") == right.removeprefix("v")


def _provisioned(
    source: str, sources: RouteSources
) -> tuple[str | None, list[Problem]]:
    """The version a ``version_source`` names, or the problems with naming it."""
    kind, _, rest = source.partition(":")
    where = "/tool_config/version_source"
    if kind == "toolpin" and rest:
        found = sources.tool_version(rest)
        if found is None:
            return None, [_row("P10", where, f"no ToolPin is named {rest!r}")]
        return found, []
    if kind == "third_party_licenses" and rest:
        found = sources.license_version(rest)
        if found is None:
            return None, [
                _row("P10", where, f"THIRD_PARTY_LICENSES has no entry for {rest!r}")
            ]
        return found, []
    if kind == "module" and ":" in rest:
        module, _, constant = rest.rpartition(":")
        try:
            value = resolve_ref(f"{module}:{constant}")
        except Exception as error:
            return None, [
                _row(
                    "P10",
                    where,
                    f"cannot read the constant {constant!r} of {module!r}: "
                    f"{_describe(error)}",
                )
            ]
        if not isinstance(value, str):
            return None, [
                _row("P10", where, f"{module}:{constant} is not a string constant")
            ]
        return value, []
    return None, [
        _row(
            "P10",
            where,
            f"{source!r} is not toolpin:<name>, third_party_licenses:<key>, "
            "module:<dotted.module>:<NAME> or unpinned",
        )
    ]


def _version_rows(manifest: Any, route: Any, sources: RouteSources) -> list[Problem]:
    rows: list[Problem] = []
    source = str(getattr(route, "version_source", "") or "")
    version = str(getattr(route, "version", "") or "")
    read_at = str(getattr(route, "read_at", "") or "")
    owned = [
        str(pin.tool)
        for pin in getattr(getattr(manifest, "provisioning", None), "tool_pins", ())
        or ()
    ]
    kind, _, rest = source.partition(":")
    provisioned: str | None = None
    if source == "unpinned":
        reason = str(getattr(route, "unpinned_reason", "") or "")
        if not reason.strip():
            rows.append(
                _row(
                    "P10",
                    "/tool_config/unpinned_reason",
                    "version_source is unpinned, so say why nothing pins the tool",
                )
            )
    else:
        provisioned, problems = _provisioned(source, sources)
        rows += problems
    if owned and not (kind == "toolpin" and rest in owned):
        rows.append(
            _row(
                "P10",
                "/tool_config/version_source",
                f"the scanner's Provisioning pins {', '.join(owned)}, so the route "
                f"must read its version from toolpin:{owned[0]}, not from {source!r}",
            )
        )
    if not version:
        rows.append(_row("P10", "/tool_config/version", "is empty"))
    elif provisioned is not None and not _same_version(provisioned, version):
        rows.append(
            _row(
                "P10",
                "/tool_config/version",
                f"is {version!r}, but {source} provisions {provisioned!r}: read the "
                "tool's tree again at the provisioned tag and update the route",
            )
        )
    if not _READ_AT.fullmatch(read_at):
        rows.append(
            _row("P10", "/tool_config/read_at", f"{read_at!r} is not 'owner/repo@tag'")
        )
    elif version and version.removeprefix("v") not in read_at.partition("@")[2]:
        rows.append(
            _row(
                "P10",
                "/tool_config/read_at",
                f"the tag in {read_at!r} does not contain the version {version!r}",
            )
        )
    return rows


def _options_rows(route: Any, options_class: type[BaseModel] | None) -> list[Problem]:
    if options_class is None:
        return []
    own = own_option_fields(options_class)
    reason = str(getattr(route, "no_options_reason", "") or "").strip()
    where = "/tool_config/no_options_reason"
    if not own and not reason:
        return [
            _row(
                "P10",
                where,
                f"{options_class.__name__} declares no field of its own: say why the "
                "scanner takes no setting from ASH",
            )
        ]
    if own and reason:
        return [
            _row(
                "P10",
                where,
                f"{options_class.__name__} declares {', '.join(own[:5])}, so the "
                "reason a scanner has no option of its own no longer holds: remove it",
            )
        ]
    return []


def _upstream_rows(
    route: Any, options_class: type[BaseModel] | None, sources: RouteSources
) -> list[Problem]:
    key = str(getattr(route, "pin", "") or "")
    pin = sources.pin(key) if key else None
    if pin is None:
        return [
            _row(
                "P10",
                "/tool_config/pin",
                f"an upstream route names the pin {key!r}, which tool_schemas.PINS "
                "does not hold",
            )
        ]
    rows: list[Problem] = []
    read_at = str(getattr(route, "read_at", "") or "")
    expected = f"{pin.repository}@{pin.tag}"
    if read_at != expected:
        rows.append(
            _row(
                "P10",
                "/tool_config/read_at",
                f"is {read_at!r}, but the pin reads {expected!r}",
            )
        )
    loaded = sources.module(str(pin.module), str(pin.root_class))
    root: Any = None
    if loaded is None:
        rows.append(
            _row(
                "P10",
                "/tool_config/pin",
                f"the generated module {pin.module} does not exist or does not import",
            )
        )
    else:
        header, body = split_generated_module(loaded.source)
        if header.get("source sha256") != pin.sha256:
            rows.append(
                _row(
                    "P10",
                    "/tool_config/pin",
                    f"the generated module's header records source sha256 "
                    f"{header.get('source sha256')!r}, but the pin's is {pin.sha256!r}",
                )
            )
        if header.get("body sha256") != body_sha256(body):
            rows.append(
                _row(
                    "P10",
                    "/tool_config/pin",
                    "the generated module's body does not match the body sha256 in "
                    "its header: it was edited by hand; regenerate it",
                )
            )
        root = loaded.root
        if root is None:
            rows.append(
                _row(
                    "P10",
                    "/tool_config/pin",
                    f"the generated module has no root class {pin.root_class!r}",
                )
            )
        elif not getattr(root, "model_fields", None):
            rows.append(
                _row(
                    "P10",
                    "/tool_config/pin",
                    f"the root class {pin.root_class!r} declares no field: the model "
                    "must keep at least one key of the tool's schema",
                )
            )
    option = str(getattr(route, "option", "tool_config") or "tool_config")
    if options_class is not None:
        info = options_class.model_fields.get(option)
        where = "/tool_config/option"
        if info is None:
            rows.append(
                _row("P10", where, f"{options_class.__name__} has no field {option!r}")
            )
        else:
            if root is not None and _first_model(info.annotation) is not root:
                rows.append(
                    _row(
                        "P10",
                        where,
                        f"{option!r} is not typed by the generated root class "
                        f"{pin.root_class!r}",
                    )
                )
            sentence = sources.operator_only_sentence()
            if not sentence:
                rows.append(
                    _row(
                        "P10",
                        where,
                        "no operator-only sentence was supplied, so the description "
                        f"of {option!r} cannot be checked against it",
                    )
                )
            elif sentence not in (info.description or ""):
                rows.append(
                    _row(
                        "P10",
                        where,
                        f"the description of {option!r} does not say that only the "
                        "operator sets it: end it with the operator-only sentence",
                    )
                )
    return rows


@_total("P10")
def check_route(
    manifest: Any,
    options_class: type[BaseModel] | None = None,
    *,
    sources: RouteSources | None = None,
) -> list[Problem]:
    """P10: the manifest's ``tool_config`` route is declared and what it says holds.

    The route and its pin are read by attribute name. Five checks:

    (a) declared: the manifest has a route (until the manifest model gains the
        field, every scanner gets this one problem and no other from P10);
    (b) version: ``version_source`` names where the provisioned version comes from
        (``toolpin:<name>``, ``third_party_licenses:<key>``,
        ``module:<dotted.module>:<NAME>`` or ``unpinned`` with a reason), a scanner
        whose Provisioning pins a tool reads it from that ToolPin, the route's
        version equals the provisioned one (a leading ``v`` ignored) and occurs in
        the tag of ``read_at``;
    (c) options: ``no_options_reason`` is set exactly when O declares no field of
        its own (``own_option_fields``);
    (d) upstream: the pin exists, ``read_at`` is its repository and tag, the
        generated module's header carries the pin's source sha256 and a body
        sha256 that matches its body, its root class declares a field, and O's
        ``option`` field is typed by that class and described as set by the
        operator only;
    (e) ash: ``reason`` says why no upstream schema is used.
    """
    use = sources or RouteSources()
    route = getattr(manifest, "tool_config", None)
    if route is None:
        return [
            _row(
                "P10",
                "/tool_config",
                "the manifest declares no tool_config route: say how the tool's "
                "own configuration relates to this schema",
            )
        ]
    rows: list[Problem] = []
    kind = getattr(route, "kind", None)
    if kind not in ("upstream", "ash"):
        rows.append(
            _row(
                "P10",
                "/tool_config/kind",
                f"{kind!r} is neither 'upstream' nor 'ash'",
            )
        )
    rows += _version_rows(manifest, route, use)
    rows += _options_rows(route, options_class)
    if kind == "upstream":
        rows += _upstream_rows(route, options_class, use)
    elif kind == "ash" and not str(getattr(route, "reason", "") or "").strip():
        rows.append(
            _row(
                "P10",
                "/tool_config/reason",
                "an ash route says why no upstream schema is used",
            )
        )
    return rows


# ---------------------------------------------------------------------------
# One scanner.
# ---------------------------------------------------------------------------


def _manifest_options(manifest: Any) -> type[BaseModel] | None:
    try:
        return _as_model(resolve_ref(str(getattr(manifest, "options_model", ""))))
    except Exception:
        return None


def check_scanner(
    scanner_class: type | None,
    manifest: Any | None = None,
    *,
    published: Mapping[str, Any] | None = None,
    sources: RouteSources | None = None,
    require_manifest: bool = True,
    name: str | None = None,
) -> list[Problem]:
    """Every rule that applies to one scanner.

    P1 and P2 to P8 from its class, P1's manifest half and P10 from its manifest,
    and P9 when the committed schema is given. A scanner with no manifest gets a
    P1 problem unless ``require_manifest`` is False (a package not shipped with
    ASH has none).
    """
    rows: list[Problem] = []
    config = None
    if scanner_class is not None:
        rows += check_declared_class(scanner_class)
        config = _declared_config(scanner_class)
    if manifest is not None:
        rows += check_declared_manifest(manifest, scanner_class)
    elif require_manifest:
        rows.append(
            _row(
                "P1",
                "/entry_points/scanner",
                "no manifest names this class as its scanner: add one under "
                "automated_security_helper/plugin_manifests",
            )
        )
    options = options_model_of(config) if config is not None else None
    if options is None and manifest is not None:
        options = _manifest_options(manifest)
    if config is not None:
        rows += check_config_model(config)
    label = name or str(getattr(manifest, "name", "") or "") or _name_default(config)
    if published is not None and label:
        rows += check_published(published, label, config)
    if manifest is not None:
        rows += check_route(manifest, options, sources=sources)
    return _merged(rows)


def load_published(name: str = "AshConfig.json") -> dict[str, Any]:
    """A committed schema file of this package, as a dict."""
    text = (Path(__file__).resolve().parent / name).read_text(encoding="utf-8")
    loaded = json.loads(text)
    return loaded if isinstance(loaded, dict) else {}
