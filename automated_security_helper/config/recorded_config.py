# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A configuration read from a results file's record, and the fields it cannot hold.

A results file records the configuration its scan ran with, and keeps each
value the configuration read from the environment as its reference, exactly as
the file wrote it (config_validator.record_of_config). A command that reads the
record (``ash merge``, ``ash report``, the outer process of a container or Nix
scan, ``ash scan --existing-results``) does not read the environment again. A
reference is a string, though, and a fixed-choice field such as
``severity_threshold`` cannot hold one, so the record is read with that field's
default (AshAggregatedResults.validate_ash_config), and the field is listed on
the configuration as unreadable.

A command that acts on such a field takes its value from its own configuration
(take_own_values). ``ash merge`` and ``ash report`` refuse, exit 3, when their
operator does not supply it: acting on the default instead would merge or report
under a threshold the scan never used. The outer process of a container or Nix
scan, and ``--existing-results``, load the operator's own configuration, and use
its value. A reader that computes nothing from the field keeps the default, with
the warning the load logged.
"""

from __future__ import annotations

import copy
from typing import Any, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple

from automated_security_helper.core.exceptions import ASHConfigValidationError

#: (field, reference): the field as a dotted path of the record's keys.
UnreadableReference = Tuple[str, str]


def _is_reference(value: Any) -> bool:
    from automated_security_helper.config.ash_config import ENV_REFERENCE_PATTERN

    if not isinstance(value, str):
        return False
    text = value.removeprefix("!ENV ")
    return ENV_REFERENCE_PATTERN.match(text) is not None


def _data_path(data: Any, loc: Sequence[Any], value: Any) -> Optional[List[Any]]:
    """The keys of ``data`` at an error's location, or None.

    pydantic's location can name the member of a union it tried as well as the
    keys of the data; those are not keys of ``data``, and are skipped.
    """
    path: List[Any] = []
    node = data
    for segment in loc:
        if isinstance(node, dict) and segment in node:
            node = node[segment]
            path.append(segment)
        elif (
            isinstance(node, list)
            and isinstance(segment, int)
            and 0 <= segment < len(node)
        ):
            node = node[segment]
            path.append(segment)
    return path if path and node == value else None


#: The refusals of a field that holds one of fixed choices: a Literal's and an
#: Enum's. ``output_formats`` entries are refused by their own BeforeValidator
#: (ash_config._export_format_name), as a value error at the entry.
_CHOICE_REFUSALS = frozenset({"literal_error", "enum"})


def _a_choice_refused(item: Any) -> bool:
    """Whether a pydantic error is a fixed-choice field refusing its input.

    Only such a field cannot hold a reference and still has a default that
    stands for "not given". A true/false or a number field refuses a reference
    as it refuses any other wrong value: read as its default (``True``, ``3``),
    it would act on a value the scan never had.
    """
    kind = item.get("type")
    if kind in _CHOICE_REFUSALS:
        return True
    loc = tuple(item.get("loc", ()))
    return kind == "value_error" and loc[:1] == ("output_formats",)


def without_unreadable_references(
    data: Any, error: Any
) -> Tuple[Any, List[UnreadableReference]]:
    """``data`` without each field whose refusal is a reference it cannot hold.

    Only a fixed-choice field (_a_choice_refused). All or nothing: when any
    refusal in ``error`` is not of a reference in such a field, returns
    ``data`` and no fields, and the caller raises ``error``. A reference in a
    list (a fixed-choice item of a scanner's ``additional_formats``, an
    ``output_formats`` entry) takes the whole list out, so the field is its
    default, not a list with one item missing.
    """
    if not isinstance(data, dict):
        return data, []
    kept = copy.deepcopy(data)
    found: List[UnreadableReference] = []
    for item in error.errors():
        value = item.get("input")
        if not _is_reference(value) or not _a_choice_refused(item):
            return data, []
        path = _data_path(data, item.get("loc", ()), value)
        if path is None:
            return data, []
        while path and isinstance(path[-1], int):
            path = path[:-1]
        field = ".".join(str(segment) for segment in path)
        if field not in {known for known, _ in found}:
            found.append((field, value))
        node: Any = kept
        for segment in path[:-1]:
            node = node.get(segment) if isinstance(node, dict) else None
        if isinstance(node, dict):
            node.pop(path[-1], None)
    return kept, found


def unreadable_references(config: Any) -> List[UnreadableReference]:
    return list(getattr(config, "_unreadable_references", None) or [])


def _attribute(model: Any, segment: str) -> Tuple[Optional[str], Any]:
    """The field ``segment`` names on ``model`` (by its name or alias), and its value."""
    from pydantic import BaseModel

    if isinstance(model, BaseModel):
        for name, field in type(model).model_fields.items():
            if segment in (name, field.alias):
                return name, getattr(model, name, None)
        extra = model.model_extra or {}
        if segment in extra:
            return segment, extra[segment]
    elif isinstance(model, dict) and segment in model:
        return segment, model[segment]
    return None, None


def _value_at(model: Any, segments: Sequence[str]) -> Tuple[bool, Any]:
    node = model
    for segment in segments:
        name, node = _attribute(node, segment)
        if name is None:
            return False, None
    return True, node


def _sets(model: Any, segments: Sequence[str]) -> bool:
    """Whether ``model``'s operator set the field.

    A freshly parsed model answers from ``model_fields_set``: every model on
    the way has the field there, as a configuration file that writes it does.
    A model ``apply_config_overrides`` rebuilt answers from the record it
    stamped: the rebuild re-validates a full dump, which puts every field in
    ``model_fields_set``, so the rebuilt model's own sets would say the
    operator wrote every field whatever the file held."""
    from pydantic import BaseModel

    record = getattr(model, "_written_before_overrides", None)
    if record is not None:
        # The record is authoritative and is never re-derived here: it was
        # stamped when the overrides were applied, and a resolved config
        # mutated after that point diverges from it silently. Any change
        # that mutates a resolved config between the resolve and a
        # record-based read must refresh or invalidate the record.
        return ".".join(_canonical_segments(model, segments)) in record
    node = model
    for segment in segments:
        if isinstance(node, BaseModel):
            name, child = _attribute(node, segment)
            if name is None:
                return False
            if name in type(node).model_fields and name not in node.model_fields_set:
                return False
            node = child
        elif isinstance(node, dict):
            if segment not in node:
                return False
            node = node[segment]
        else:
            return False
    return True


def _canonical_segments(model: Any, segments: Sequence[str]) -> List[str]:
    """``segments`` with each alias respelled as its field's name, resolved
    against ``model``; a segment the model does not hold stays as written."""
    from pydantic import BaseModel

    canonical: List[str] = []
    node = model
    for segment in segments:
        if isinstance(node, BaseModel):
            name, node = _attribute(node, segment)
            canonical.append(name if name is not None else segment)
            if name is None:
                node = None
        elif isinstance(node, dict):
            canonical.append(segment)
            node = node.get(segment)
        else:
            canonical.append(segment)
            node = None
    return canonical


def written_field_paths(model: Any) -> FrozenSet[str]:
    """Every dotted field path ``model`` was written with, as ``_sets`` walks
    them: a field in a model's ``model_fields_set`` (which on a freshly parsed
    configuration holds exactly what the file wrote, extra keys included), or
    a string key of a dict under one, recursively. ``apply_config_overrides``
    records this before its rebuild."""
    paths: Set[str] = set()
    _written_under(model, (), paths)
    return frozenset(paths)


def _written_under(node: Any, prefix: Tuple[str, ...], paths: Set[str]) -> None:
    from pydantic import BaseModel

    if isinstance(node, BaseModel):
        for name in node.model_fields_set:
            if not isinstance(name, str):
                continue
            path = (*prefix, name)
            paths.add(".".join(path))
            # Through _attribute, which reads an extra key from model_extra:
            # getattr on an extra section named like a BaseModel attribute
            # ("json", "copy", "schema") returned the bound method, so
            # nothing the file wrote under it was recorded.
            _written_under(_attribute(node, name)[1], path, paths)
    elif isinstance(node, dict):
        for key, value in node.items():
            if not isinstance(key, str):
                continue
            path = (*prefix, key)
            paths.add(".".join(path))
            _written_under(value, path, paths)


def override_field_paths(
    model: Any,
    written_before: Iterable[str],
    applied: Iterable[Tuple[Sequence[str], Any, bool]],
) -> FrozenSet[str]:
    """The written-field record after a set of applied overrides.

    Starts from what the file wrote (``written_before``). Each entry of
    ``applied`` is what ``_apply_config_override`` reported: the key segments
    it resolved and wrote to (so a folded spelling counts as the key it
    landed on, which is the spelling ``_sets`` resolves a query to), the
    parsed value, and whether it appended. A replacing override overwrote the
    whole subtree under its key, so the record drops what the file wrote
    under it, which is gone, and takes the string-keyed paths inside the
    parsed value, which are written now. Every prefix is written too, as a
    file writing the field marks its parents. An append changes one list in
    place and unwrites nothing. Spellings are canonicalized against ``model``
    (the rebuilt configuration), as ``_sets`` canonicalizes its queries."""
    paths: Set[str] = set(written_before)
    for segments, parsed_value, appended in applied:
        canonical = _canonical_segments(model, list(segments))
        if not appended:
            under = ".".join(canonical) + "."
            paths = {path for path in paths if not path.startswith(under)}
        for depth in range(1, len(canonical) + 1):
            paths.add(".".join(canonical[:depth]))
        inside: Set[str] = set()
        _written_under(parsed_value, tuple(canonical), inside)
        for path in inside:
            paths.add(".".join(_canonical_segments(model, path.split("."))))
    return frozenset(paths)


def _set_value(model: Any, segments: Sequence[str], value: Any) -> None:
    from pydantic import BaseModel

    found, parent = _value_at(model, segments[:-1])
    if not found:
        return
    name, _ = _attribute(parent, segments[-1])
    if name is None:
        return
    if isinstance(parent, BaseModel):
        if name in type(parent).model_fields:
            # The operator's value, already validated by its own configuration.
            parent.__dict__[name] = value
        elif parent.model_extra is not None:
            parent.model_extra[name] = value
    elif isinstance(parent, dict):
        parent[name] = value


def _normalized(field: str) -> str:
    return field.replace("-", "_")


def take_own_values(
    record: Any,
    own: Any,
    *,
    references: Optional[Iterable[UnreadableReference]] = None,
    override_keys: Iterable[str] = (),
    refuse_unless_supplied: Optional[str] = None,
) -> None:
    """Give each field ``record`` cannot hold the value ``own`` has for it.

    Args:
        record: A configuration read from a results file, changed in place.
        own: This invocation's own configuration, the operator's.
        references: The unreadable fields to take, ``record``'s own by
            default (``ash merge`` passes every shard's).
        override_keys: The keys of this invocation's ``--config-overrides``,
            each of which supplies its field.
        refuse_unless_supplied: For a command that refuses a field its
            operator does not supply (``ash merge``, ``ash report``): how the
            operator supplies one, for the refusal. A field counts as supplied
            when an override names it or ``own`` sets it. Without it, ``own``'s
            value is taken whether or not it sets the field: the outer process
            of a container or Nix scan, and ``--existing-results``.

    Raises:
        ASHConfigValidationError: A field is not supplied, for a command that
            refuses then. The message names each field and its reference, never
            a value.
    """
    pending = (
        list(references) if references is not None else unreadable_references(record)
    )
    if not pending or record is None:
        return
    overrides = {_normalized(key) for key in override_keys}
    missing: List[UnreadableReference] = []
    for field, reference in pending:
        segments = field.split(".")
        supplied = _normalized(field) in overrides or (
            own is not None and _sets(own, segments)
        )
        if refuse_unless_supplied is not None and not supplied:
            missing.append((field, reference))
            continue
        found, value = _value_at(own, segments) if own is not None else (False, None)
        if found:
            _set_value(record, segments, value)
            # When the operator's own value was read from the environment, the
            # record keeps its reference too (config_validator.record_of_config).
            for rewrite in getattr(own, "_written_references", None) or []:
                if rewrite.kind == "value" and [
                    _normalized(str(segment)) for segment in rewrite.path
                ] == [_normalized(segment) for segment in segments]:
                    record._written_references = [
                        *(getattr(record, "_written_references", None) or []),
                        rewrite._replace(path=tuple(segments)),
                    ]
    if missing and refuse_unless_supplied is not None:
        named = "; ".join(
            f"{field} is recorded as {reference}" for field, reference in missing
        )
        first = missing[0][0]
        raise ASHConfigValidationError(
            f"The configuration recorded in these results cannot be used as it is: "
            f"{named}. That is a reference read from the environment where the scan "
            "ran, which is not read again here, and the field cannot hold it. "
            f"{refuse_unless_supplied.format(field=first)}"
        )
