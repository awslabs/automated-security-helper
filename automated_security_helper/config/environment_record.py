# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The values a configuration read from the environment, and the record of it.

A config file reads a value from the environment with a plain YAML scalar or key
that starts with a ``${VAR}`` or ``${VAR:default}`` reference, the same with an
explicit ``!ENV`` tag, or a TOML string that starts with one
(``ash_config.resolve_env_references``). The scan runs with the values. What it
writes of its configuration does not hold them:

* the ``ash_config`` of a results file, which ``ash merge`` and ``ash report``
  read later instead of the configuration's files
  (``AshAggregatedResults.ash_config``'s serializer);
* the ``scanners`` keys a results file lists in ``metadata.expected_scanners``;
* the plugin section ``AshConfig.get_plugin_config`` logs at DEBUG;
* what ``ash config get`` and the MCP ``get_config`` tool show, and the profile
  file the MCP server writes for a session, which the scan then loads and
  resolves itself.

Each holds every such value or key as the file wrote it instead, ``!ENV `` and
any text after the reference included, and a command reading the record does
not resolve it again.

What counts
-----------
Only a value read from the environment. A reference whose variable is unset
resolves to the default the file wrote, which is the file's own text, so the
record keeps that default; one that resolves to nothing records null. A
reference to a name that may not be read is left as written by the loader, so
there is nothing to replace.

Where
-----
Each reference is replaced at its own position: the path of keys at which the
file wrote it, spelled with ``-`` or ``_`` (the record keys a built-in plugin's
section by its field name), and moved to where a ``patch`` operation puts its
value. In a list a string equal to the value is recorded as the reference at any
index. A string elsewhere that happens to equal the value is left alone, so a
field the file set to "us-east-1" is not recorded as ``${AWS_REGION}`` because
that variable holds the same text. At its own position, index included, a string
the load changed after reading it (a relative path the load takes from the
file's directory) has the part read from the environment replaced inside it; a
neighboring entry that only contains the same text is left as it is. If the entry
at the reference's own index no longer carries its value because the list is not
the length the file wrote (defaults before it, a patch), the reference is looked
for at any index of the list instead. A position the configuration no longer holds the value at, because a later
file or an override set it, is left as the configuration holds it.

Reading a record
----------------
A recorded reference loads back into a free string as the reference. A field
that takes a fixed choice, a validated value, a boolean or a number cannot hold
one, and ``load_recorded_config`` takes that field's default instead, with one
warning naming the field and the reference, and notes it on the configuration
(``AshConfig._unread_references``). ``ash merge`` and ``ash report`` compute their
reports and verdicts from the record, so for them such a field refuses the
command (exit 3) unless the operator supplies it, with ``--config-overrides`` or
in the file ``--config`` names (``supply_unread_references``): a default in
place of the scan's value could drop findings or turn a failing verdict into a
passing one.
"""

from __future__ import annotations

import copy
import os
from dataclasses import dataclass, replace
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from automated_security_helper.config.ash_config import (
    ENV_REFERENCE_PATTERN,
    EXPLICIT_ENV_TAG,
    config_env_var_is_interpolatable,
)
from automated_security_helper.utils.log import ASH_LOGGER

#: One step of a path into a configuration: a mapping key or a list index.
PathSegment = Union[str, int]

#: A list index in a normalized path: any position matches.
_ANY_INDEX = "*"

#: A list index a reference's path cannot name, such as the ``-`` of a patch
#: operation that appends: the entry is found by the shape the load gives it.
UNKNOWN_INDEX = _ANY_INDEX


@dataclass(frozen=True)
class EnvironmentReference:
    """A value or a mapping key a config file read from the environment.

    ``path`` is the keys and list indices at which the file wrote it; for a key,
    the path of its mapping. ``written`` is the reference as the file wrote it,
    ``resolved`` the string it resolved to, and ``value`` the part of that the
    environment supplied. Held in memory only: ``value`` is the value itself.
    """

    path: Tuple[PathSegment, ...]
    written: str
    resolved: str
    value: str
    key: bool = False
    #: How many entries the innermost list the file wrote it in had, when it
    #: wrote it in a list (as an entry, or inside a mapping that is one); None
    #: otherwise.
    length: Optional[int] = None
    #: Where in ``path`` the index of that list entry sits; set with ``length``.
    index_at: Optional[int] = None

    def at(self, path: Tuple[PathSegment, ...]) -> "EnvironmentReference":
        """The reference at an unrelated ``path``: what it says about the list the
        file wrote it in does not carry over."""
        return replace(self, path=path, length=None, index_at=None)

    def rebase(
        self, prefix_len: int, prefix: Tuple[PathSegment, ...]
    ) -> "EnvironmentReference":
        """The reference with the first ``prefix_len`` segments of its path
        replaced by ``prefix``. The list it was written in carries over when its
        index lies beyond the replaced part."""
        path = (*prefix, *self.path[prefix_len:])
        if self.index_at is None or self.index_at < prefix_len:
            return replace(self, path=path, length=None, index_at=None)
        return replace(
            self, path=path, index_at=self.index_at - prefix_len + len(prefix)
        )

    @property
    def position_unknown(self) -> bool:
        """Whether the list index in ``path`` says nothing about where the entry
        is: the path names an unknown index, or holds an index with no record of
        the list it was written in."""
        if UNKNOWN_INDEX in self.path:
            return True
        return self.length is None and any(isinstance(s, int) for s in self.path)


@dataclass(frozen=True)
class UnreadReference:
    """A recorded reference a field could not hold; see "Reading a record"."""

    #: The field, as dotted keys of the record.
    field: str
    #: The reference the record holds there.
    reference: str


def _without_tag(text: str) -> str:
    return text.removeprefix(EXPLICIT_ENV_TAG)


def reads_as_reference(text: Any) -> bool:
    """Whether ``text`` is a reference as a record holds one."""
    return isinstance(text, str) and bool(
        ENV_REFERENCE_PATTERN.match(_without_tag(text).strip())
    )


def _value_read(written: str) -> Optional[str]:
    """What ``written``'s reference read from the environment, or None if nothing.

    None for a name ``resolve_env_references`` does not read and for a variable
    that is unset, whose default came from the file. The same rule as the
    resolver, read in the same process right after it.
    """
    match = ENV_REFERENCE_PATTERN.match(_without_tag(written).strip())
    if not match or not config_env_var_is_interpolatable(match.group(1)):
        return None
    value = os.environ.get(match.group(1))
    if value is None or not value.strip():
        return None
    return value.strip()


def _reference(
    written: Any, resolved: Any, path: Tuple[PathSegment, ...], key: bool = False
) -> Optional[EnvironmentReference]:
    if not (
        isinstance(written, str)
        and "${" in written
        and isinstance(resolved, str)
        and resolved != written
    ):
        return None
    value = _value_read(written)
    if value is None:
        return None
    return EnvironmentReference(path, written, resolved, value, key)


def _has_reference(key: Any) -> bool:
    return isinstance(key, str) and "${" in key


def environment_references(
    written: Any, resolved: Any, path: Tuple[PathSegment, ...] = ()
) -> List[EnvironmentReference]:
    """What one file read from the environment, by comparing two readings of it.

    ``written`` is the file read with each reference left as written
    (``load_yaml_config(..., env="written")``, or a TOML document before
    ``_resolve_toml_env``), ``resolved`` the same text read as a scan reads it.

    Mapping entries are paired by key: a key written without a reference with
    the same key, and the keys holding one, in order, with the resolved keys the
    file does not write. A key read from the environment that resolves to
    another key of its mapping merges the two; pairing by position would then
    compare every later value with the wrong one.
    """
    found: List[EnvironmentReference] = []
    if isinstance(written, dict) and isinstance(resolved, dict):
        plain = [(k, v) for k, v in written.items() if not _has_reference(k)]
        referenced = [(k, v) for k, v in written.items() if _has_reference(k)]
        plain_keys = {k for k, _ in plain}
        for key, value in plain:
            if key in resolved:
                found += environment_references(value, resolved[key], (*path, str(key)))
        others = [(k, v) for k, v in resolved.items() if k not in plain_keys]
        for (written_key, written_value), (key, value) in zip(referenced, others):
            read = _reference(written_key, key, path, key=True)
            if read is not None:
                found.append(read)
            found += environment_references(written_value, value, (*path, str(key)))
    elif isinstance(written, list) and isinstance(resolved, list):
        for index, (written_item, item) in enumerate(zip(written, resolved)):
            entry = (*path, index)
            for read in environment_references(written_item, item, entry):
                # The innermost list a value was written in gives its length,
                # whether the entry is the reference or a mapping holding it.
                if read.length is None and not read.key:
                    read = replace(read, length=len(written), index_at=len(path))
                found.append(read)
    else:
        read = _reference(written, resolved, path)
        if read is not None:
            found.append(read)
    return found


def _normal(segment: PathSegment) -> PathSegment:
    if isinstance(segment, int):
        return _ANY_INDEX
    return segment.replace("-", "_").lower()


def _normal_path(path: Iterable[PathSegment]) -> Tuple[PathSegment, ...]:
    return tuple(_normal(segment) for segment in path)


def _exact_path(path: Iterable[PathSegment]) -> Tuple[PathSegment, ...]:
    """``path`` with its keys normalized and its list indices kept."""
    return tuple(
        segment if isinstance(segment, int) else _normal(segment) for segment in path
    )


def _bare(written: str) -> str:
    """The reference alone, ``${VAR}`` or ``${VAR:default}``, from ``written``."""
    text = _without_tag(written).strip()
    match = ENV_REFERENCE_PATTERN.match(text)
    return match.group(0) if match else text


def _anchored(text: str, reference: EnvironmentReference) -> bool:
    """Whether ``text`` is what ``reference`` resolved to, or that after a prefix
    the load put on it (a relative path anchored at the file's directory)."""
    return text == reference.resolved or text.endswith(reference.resolved)


def _recorded_string(
    text: str,
    references: Sequence[EnvironmentReference],
    unclaimed: Optional[Sequence[EnvironmentReference]] = None,
) -> str:
    """``text`` as the file wrote it, where ``references`` are those at its position.

    A string equal to what a reference resolved to is the reference. Only the
    ``unclaimed`` references (``_Index.own``, all of them by default) are also
    read into a longer string: those the file wrote at this very entry, since the
    reference of a neighboring entry does not write this one.
    """
    for reference in references:
        if text == reference.resolved:
            return reference.written
    pending = references if unclaimed is None else unclaimed
    for reference in pending:
        if text.endswith(reference.resolved):
            # A path the load anchored: the file's text after a prefix.
            prefix = text[: len(text) - len(reference.resolved)]
            return prefix + _without_tag(reference.written)
    for reference in pending:
        if reference.value in text:
            text = text.replace(reference.value, _bare(reference.written))
    return text


def written_without_tag(written: str) -> str:
    """``written``, a reference as a file wrote it, without an ``!ENV`` tag."""
    return _without_tag(written)


def fill_environment_references(
    data: Any, references: Sequence[EnvironmentReference]
) -> Any:
    """``data``, the document of a profile's copy a client patched, with each
    reference the operator's copy wrote read again.

    ``references`` are the operator's copy's. Where ``data`` holds, at the
    position of one of them, exactly the reference that copy wrote (without its
    tag), as ``AshConfig.save(as_written=True, env_tags=False)`` writes it for a
    position the client did not change, it gets the value the operator's copy
    read there. Nothing else is read: a client that writes a reference anywhere
    else has it left as text, and one that writes it at such a position gets the
    value the operator's copy holds there, which is what the profile gives it
    unpatched. A copy: ``data`` itself is not changed.
    """
    if not references:
        return data
    return _Index(references).fill(data, ())


def environment_marker(written: str) -> str:
    """``<from ${VAR}>``, how a view of a configuration shows a value read from
    the environment: the reference without its tag, never the value. Told apart
    from a reference left as written, which is shown as written."""
    return f"<from {_bare(written)}>"


class _Index:
    def __init__(
        self,
        references: Iterable[EnvironmentReference],
        mark: Optional[Callable[[str], Any]] = None,
        whole_only: bool = False,
    ) -> None:
        self.values: Dict[Tuple[PathSegment, ...], List[EnvironmentReference]] = {}
        self.keys: Dict[Tuple[PathSegment, ...], List[EnvironmentReference]] = {}
        self.mark = mark
        self.whole_only = whole_only
        #: The data's strings by exact position, and its lists' lengths (``scan``).
        self.strings: Dict[Tuple[PathSegment, ...], str] = {}
        self.lengths: Dict[Tuple[PathSegment, ...], int] = {}
        for reference in references:
            target = self.keys if reference.key else self.values
            target.setdefault(_normal_path(reference.path), []).append(reference)

    def scan(self, item: Any, exact: Tuple[PathSegment, ...]) -> None:
        """Note the strings of ``item`` by exact position and the length of each
        list, before ``record`` reads references into them."""
        if isinstance(item, dict):
            for key, value in item.items():
                spelled = key if isinstance(key, str) else str(key)
                self.scan(value, (*exact, _normal(spelled)))
        elif isinstance(item, (list, tuple)):
            self.lengths[exact] = len(item)
            for index, value in enumerate(item):
                self.scan(value, (*exact, index))
        elif isinstance(item, str):
            self.strings[exact] = item

    def _moved(self, reference: EnvironmentReference) -> bool:
        """Whether the entry the file wrote ``reference`` at no longer holds it.

        True when the list is not the length the file wrote (defaults put before
        the entry, a patch) and the entry at the same index is neither the value
        nor a path the load anchored on it (``_anchored``). A list of the same
        length whose entry changed is an entry the load or an override changed,
        not one that moved.
        """
        if reference.length is None or reference.index_at is None:
            return False
        exact = _exact_path(reference.path)
        text = self.strings.get(exact)
        if text is not None and _anchored(text, reference):
            return False
        return self.lengths.get(exact[: reference.index_at]) != reference.length

    def pending(
        self,
        exact: Tuple[PathSegment, ...],
        references: List[EnvironmentReference],
        text: str,
    ) -> List[EnvironmentReference]:
        """The references that may be read into ``text``, the string at ``exact``.

        A list can hold ``${ASH_SCOPE}`` and ``vendor2``, or ``vendor`` and an
        entry the load changed. The string at a reference's own index has that
        reference read into it, whole or inside a longer string. A neighboring
        entry that happens to start or end with the same text keeps what the file
        wrote, and does not hide the reference an entry the load changed is read
        from. Only when the entry at a reference's own index no longer carries its
        value (the list was lengthened or patched) is the reference read at the
        other indices, and then only into a string of the shape the load gives
        its entry (``_anchored``): another entry that merely contains the text
        is not that entry.

        A reference whose list index says nothing about where its entry is
        (``EnvironmentReference.position_unknown``: the append of a ``patch``
        operation, or a position inside a list the record does not know the
        length of) has no entry of its own: it is read only into a string of that
        shape, at any index, and a base entry that merely contains the text is
        left as the file wrote it.
        """
        return [
            r
            for r in references
            if (
                _anchored(text, r)
                if r.position_unknown or self._moved(r)
                else _exact_path(r.path) == exact
            )
        ]

    def record(
        self,
        item: Any,
        path: Tuple[PathSegment, ...],
        exact: Optional[Tuple[PathSegment, ...]] = None,
    ) -> Any:
        exact = path if exact is None else exact
        if isinstance(item, dict):
            renames = self.keys.get(path, ())
            result: Dict[Any, Any] = {}
            for key, value in item.items():
                spelled = key if isinstance(key, str) else str(key)
                recorded = self.record(
                    value, (*path, _normal(spelled)), (*exact, _normal(spelled))
                )
                for reference in renames:
                    if _normal(spelled) == _normal(reference.resolved):
                        key = self._whole(reference)
                        break
                result[key] = recorded
            return result
        if isinstance(item, (list, tuple)):
            return type(item)(
                self.record(value, (*path, _ANY_INDEX), (*exact, index))
                for index, value in enumerate(item)
            )
        if isinstance(item, str):
            here = self.values.get(path)
            if here:
                return self._string(item, here, self.pending(exact, here, item))
        return item

    def fill(self, item: Any, path: Tuple[PathSegment, ...]) -> Any:
        """``fill_environment_references``: the inverse of ``record``."""
        if isinstance(item, dict):
            renames = self.keys.get(path, ())
            result: Dict[Any, Any] = {}
            for key, value in item.items():
                for reference in renames:
                    if key == _without_tag(reference.written):
                        key = reference.resolved
                        break
                spelled = key if isinstance(key, str) else str(key)
                result[key] = self.fill(value, (*path, _normal(spelled)))
            return result
        if isinstance(item, (list, tuple)):
            return type(item)(self.fill(value, (*path, _ANY_INDEX)) for value in item)
        if isinstance(item, str):
            for reference in self.values.get(path, ()):
                if item == _without_tag(reference.written):
                    return reference.resolved
        return item

    def _whole(self, reference: EnvironmentReference) -> Any:
        return reference.written if self.mark is None else self.mark(reference.written)

    def _string(
        self,
        text: str,
        references: List[EnvironmentReference],
        unclaimed: List[EnvironmentReference],
    ) -> Any:
        if self.mark is None:
            return _recorded_string(text, references, unclaimed)
        for reference in references:
            if text == reference.resolved:
                return self._whole(reference)
        if self.whole_only:
            return text
        for reference in unclaimed:
            if reference.value in text:
                text = text.replace(reference.value, self.mark(reference.written))
        return text


def record_environment_references(
    data: Any,
    references: Sequence[EnvironmentReference],
    at: Sequence[PathSegment] = (),
    mark: Optional[Callable[[str], Any]] = None,
    whole_only: bool = False,
) -> Any:
    """``data``, a dump of a configuration, with what ``references`` read written
    as the file wrote it; see "Where".

    ``at`` is where ``data`` sits in the configuration, for a dump of one section
    of it (``("reporters", "gitlab-cyclonedx")`` for that reporter's section).
    ``mark``, when given, is applied to each reference as written, and replaces
    it: ``environment_marker`` for a view of the config, or a type a file writer
    tags ``!ENV``. ``whole_only`` replaces only a string that is the whole value,
    for a file that is loaded again (``AshConfig.save(as_written=True)``). A
    copy: ``data`` itself is not changed.
    """
    if not references:
        return data
    index = _Index(references, mark, whole_only)
    index.scan(data, _exact_path(at))
    return index.record(data, _normal_path(at), _exact_path(at))


def setting_names(
    section: Any,
    references: Sequence[EnvironmentReference] = (),
    at: Sequence[PathSegment] = (),
) -> str:
    """The keys of ``section``, a config section or a dump of one, for a log line
    that shows which settings it holds and none of their values.

    One level of mapping below each key is listed too, as ``options (a, b)``. A
    key read from the environment is shown as the file wrote it
    (``record_environment_references``, with ``references`` and ``at``).
    """
    data = (
        section.model_dump(by_alias=True) if hasattr(section, "model_dump") else section
    )
    if not isinstance(data, dict):
        return f"a {type(data).__name__}"
    data = record_environment_references(data, references, at=at)
    parts = []
    for key, value in data.items():
        if isinstance(value, dict) and value:
            parts.append(f"{key} ({', '.join(str(inner) for inner in value)})")
        else:
            parts.append(str(key))
    return ", ".join(parts) if parts else "no settings"


def recorded_names(
    names: Sequence[str],
    references: Sequence[EnvironmentReference],
    mapping: Sequence[PathSegment],
) -> List[str]:
    """``names``, keys of the mapping at ``mapping``, each one read from the
    environment as the file wrote it: ``metadata.expected_scanners`` lists the
    keys of ``scanners``."""
    renames = _Index(references).keys.get(_normal_path(mapping), [])
    result = []
    for name in names:
        for reference in renames:
            if _normal(name) == _normal(reference.resolved):
                name = reference.written
                break
        result.append(name)
    return result


def _drop(data: Any, location: Sequence[Any]) -> Optional[List[str]]:
    """Remove from ``data`` the entry a validation error's ``location`` names.

    The location's steps that are not keys of the record (a union member's name,
    a model's) are passed over. Returns the keys removed along, or None when the
    location names nothing the record holds.
    """
    node = data
    steps: List[Tuple[Any, Any]] = []
    for step in location:
        if isinstance(node, dict):
            match = None
            if step in node:
                match = step
            elif isinstance(step, str):
                for key in node:
                    if isinstance(key, str) and _normal(key) == _normal(step):
                        match = key
                        break
            if match is None:
                continue
            steps.append((node, match))
            node = node[match]
        elif isinstance(node, list) and isinstance(step, int) and 0 <= step < len(node):
            steps.append((node, step))
            node = node[step]
    if not steps or not reads_as_reference(node):
        return None
    container, last = steps[-1]
    if isinstance(container, list):
        container.pop(last)
    else:
        del container[last]
    return [str(key) for _, key in steps]


#: How many times load_recorded_config validates again after taking defaults.
_MAX_PASSES = 8


def load_recorded_config(data: Any) -> Any:
    """``data``, a recorded configuration, as an ``AshConfig``; see "Reading a record".

    Raises the first ``ValidationError`` when a field the record holds is
    invalid for any other reason, or when taking defaults does not leave a
    configuration that validates.
    """
    from pydantic import ValidationError

    from automated_security_helper.config.ash_config import AshConfig

    try:
        return AshConfig.model_validate(data)
    except ValidationError as raised:
        first = raised
    if not isinstance(data, dict):
        raise first
    working = copy.deepcopy(data)
    unread: List[UnreadReference] = []
    current = first
    for _ in range(_MAX_PASSES):
        for item in current.errors():
            reference = item.get("input")
            removed = (
                _drop(working, item.get("loc", ()))
                if reads_as_reference(reference)
                else None
            )
            if removed is None:
                raise first
            unread.append(UnreadReference(".".join(removed), str(reference)))
        try:
            config = AshConfig.model_validate(working)
        except ValidationError as again:
            current = again
            continue
        config._unread_references = tuple(unread)
        for entry in unread:
            ASH_LOGGER.warning(
                f"The recorded configuration holds {entry.reference} for "
                f"{entry.field}, a value the scan read from the environment, and "
                "the field cannot hold a reference, so it reads as its default."
            )
        return config
    raise first


def _covers(override_path: str, field: str) -> bool:
    key = _normal_path(override_path.rstrip("+").split("."))
    wanted = _normal_path(field.split("."))
    return wanted[: len(key)] == key


def _value_at(data: Any, field: str) -> Tuple[bool, Any]:
    node = data
    for step in field.split("."):
        if isinstance(node, dict):
            match = next(
                (
                    key
                    for key in node
                    if isinstance(key, str) and _normal(key) == _normal(step)
                ),
                None,
            )
            if match is None:
                return False, None
            node = node[match]
        elif isinstance(node, list) and step.isdigit() and int(step) < len(node):
            node = node[int(step)]
        else:
            return False, None
    return True, node


def supply_unread_references(
    config: Any,
    *,
    overrides: Sequence[str],
    overrides_applied: bool,
    operator_config: Any,
    operator_document: Any,
    command: str,
) -> Any:
    """``config``, a recorded configuration, with each field ``load_recorded_config``
    could not read supplied by the operator; see "Reading a record".

    A field an override sets (``--config-overrides``) or the operator's config
    file writes (``operator_document``, that file's merged document, or None
    when no file is named) is the operator's. It takes ``operator_config``'s
    value, unless an override sets it and ``overrides_applied`` says the
    overrides were applied to ``config`` already, as ``ash merge`` applies them.
    Any other field refuses ``command``.

    Raises:
        ASHConfigValidationError: A field nothing supplies, naming the field and
            the reference and the override that supplies it.
    """
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    unread = tuple(getattr(config, "_unread_references", ()) or ())
    if not unread:
        return config
    missing: List[UnreadReference] = []
    supplied: Dict[str, Any] = {}
    for entry in unread:
        overridden = any(
            _covers(override.partition("=")[0], entry.field) for override in overrides
        )
        if overridden and overrides_applied:
            continue
        if overridden or (
            operator_document is not None
            and _value_at(operator_document, entry.field)[0]
        ):
            found, value = _value_at(
                operator_config.model_dump(by_alias=True), entry.field
            )
            if found:
                supplied[entry.field] = value
                continue
        missing.append(entry)
    if missing:
        fields = "; ".join(
            f"{entry.field} holds {entry.reference}" for entry in missing
        )
        example = missing[0].field
        raise ASHConfigValidationError(
            f"The recorded configuration reads fields from the environment that "
            f"{command} cannot use as recorded ({fields}). {command} does not read "
            "the environment for a recorded setting. Supply each one, as in "
            f"--config-overrides '{example}=<value>', or in the file --config names."
        )
    if not supplied:
        config._unread_references = ()
        return config
    from automated_security_helper.config.ash_config import AshConfig

    data = config.model_dump(by_alias=True)
    for field, value in supplied.items():
        node = data
        steps = field.split(".")
        for step in steps[:-1]:
            node = node.setdefault(_matching_key(node, step), {})
        node[_matching_key(node, steps[-1])] = value
    return AshConfig.model_validate(data)


def _matching_key(mapping: Dict[Any, Any], step: str) -> Any:
    """The key of ``mapping`` that spells ``step``, with ``-`` or ``_``; else ``step``."""
    return next(
        (
            key
            for key in mapping
            if isinstance(key, str) and _normal(key) == _normal(step)
        ),
        step,
    )
