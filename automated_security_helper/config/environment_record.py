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
value. A string equal to the value is recorded as the reference at the
reference's own index. A string elsewhere that happens to equal the value is left
alone, so a field the file set to "us-east-1" is not recorded as
``${AWS_REGION}`` because that variable holds the same text, and a list entry the
file wrote as the same text as the value of an entry beside it stays as written.
At its own position, index included, a string the load changed after reading it
(a relative path the load takes from the file's directory) has the part read from
the environment replaced inside it; a neighboring entry that only contains the
same text is left as it is. If the entry at the reference's own index no longer
carries its value because the list is not the length the file wrote (defaults
before it, a patch), the reference is looked for at any index of the list
instead, in a string that is the value or a path anchored on it. A reference whose
list index the file's layout does not give (the append of a ``patch`` operation)
is looked for the same way. A position the configuration no longer holds the
value at, because a later file or an override set it, is left as the
configuration holds it.

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
passing one. The outer process of a container or Nix scan, and
``ash scan --use-existing``, resolve the scan's own configuration, so such a
field takes the value that configuration gives it (``take_own_values``), and the
exit code is computed with the threshold the scan used.
"""

from __future__ import annotations

import copy
import os
import re
from dataclasses import dataclass, replace
from dataclasses import field as dataclass_field
from pathlib import Path
from typing import (
    Any,
    Callable,
    Collection,
    Dict,
    FrozenSet,
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
    resolve_env_references,
)
from automated_security_helper.utils.log import ASH_LOGGER

#: One step of a path into a configuration: a mapping key or a list index.
PathSegment = Union[str, int, "_AnyIndex"]


class _AnyIndex:
    """The marker for "any list position" in a path. An object of its own, never
    a string, so no mapping key (``"*"`` included) can equal it. Paths are held in
    memory only, so the marker is never written out."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "<any index>"

    def __reduce__(self) -> str:
        # A copy (deepcopy, pickle, a pydantic deep model_copy) resolves back
        # to the module's one sentinel instead of a new, unequal instance.
        return "_ANY_INDEX"


#: A list index in a normalized path: any position matches.
_ANY_INDEX = _AnyIndex()

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
    #: The file that wrote it, resolved, and the path it holds in that file's
    #: own document, kept when ``at`` moves it: how the record of the
    #: configuration (config_validator.environment_record_read) finds where
    #: the reference it reads in the file ended up. Not compared.
    origin: Optional[Tuple[Path, Tuple[PathSegment, ...]]] = dataclass_field(
        default=None, compare=False
    )

    def at(self, path: Tuple[PathSegment, ...]) -> "EnvironmentReference":
        """The reference moved to ``path``. The move invalidates what the
        reference knew about the list it sat in, so ``length`` and ``index_at``
        are dropped; a measure step (``_measured_in``) records the new list
        from the post-move document. ``origin`` is kept."""
        return replace(self, path=path, length=None, index_at=None)

    def moved_to_unknown_list(
        self, path: Tuple[PathSegment, ...]
    ) -> "EnvironmentReference":
        """The reference at an unrelated ``path``, with ``length`` and
        ``index_at`` dropped: what it says about the list the file wrote it in
        does not carry over, so an int index in ``path`` reads as an unknown
        position until a measure step records the new list."""
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

    def read_in(self, file: Path) -> "EnvironmentReference":
        """This reference, read in ``file`` (resolved) at its path there."""
        return replace(self, origin=(file, tuple(self.path)))

    @property
    def position_unknown(self) -> bool:
        """Whether the list index in ``path`` says nothing about where the entry
        is: the path names an unknown index, or holds an index with no record of
        the list it was written in."""
        if any(isinstance(segment, _AnyIndex) for segment in self.path):
            return True
        return self.length is None and any(isinstance(s, int) for s in self.path)

    @property
    def place_key(self) -> Tuple[Any, ...]:
        """The reference as its file wrote it, for a record of the file's text
        to find it by: where in which file, value or key, and its text."""
        return (self.origin, self.key, self.written)


@dataclass(frozen=True)
class UnreadReference:
    """A recorded reference a field could not hold; see "Reading a record"."""

    #: The field, as dotted keys of the record.
    field: str
    #: The reference the record holds there.
    reference: str


def _without_tag(text: str) -> str:
    return text.removeprefix(EXPLICIT_ENV_TAG)


def _reference_match(written: str) -> Optional[re.Match[str]]:
    """``written``'s reference, matched as the loader matches it
    (resolve_env_references and the YAML and TOML loaders): from the first
    character, after an ``!ENV`` tag, with nothing stripped, so a text with
    leading whitespace is no reference. Every reader of a written reference
    here matches through this, so all share one whitespace rule."""
    return ENV_REFERENCE_PATTERN.match(_without_tag(written))


def reads_as_reference(text: Any) -> bool:
    """Whether ``text`` is a reference as a record holds one: as its file
    wrote it, which the loader read (``_reference_match``)."""
    return isinstance(text, str) and bool(_reference_match(text))


def referenced_name(written: str) -> Optional[str]:
    """The variable ``written``, a reference as a file wrote it (``${VAR}``,
    ``${VAR:default}``, with or without the ``!ENV`` tag), names; None for text
    that is not one.

    Matched as the loader matches it (``_reference_match``): a text with
    leading whitespace names nothing, as the loader reads nothing for it. The
    one parser of a written reference's variable here: a value's
    (``_value_read``), a key's (``_written_key_reference``), and the Bedrock
    reporter's knob rule all ask it.
    """
    match = _reference_match(written)
    return match.group(1) if match else None


def _value_read(written: str) -> Optional[str]:
    """What ``written``'s reference read from the environment, or None if nothing.

    None for a name ``resolve_env_references`` does not read and for a variable
    that is unset, whose default came from the file. The same rule as the
    resolver, read in the same process right after it.
    """
    name = referenced_name(written)
    if name is None or not config_env_var_is_interpolatable(name):
        return None
    value = os.environ.get(name)
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
        # A value resolution left as its own text read nothing: with an
        # explicit tag, the two readings differ by the tag alone (a composite
        # or embedded reference, which is not resolved). The variable it
        # names can be set, so _value_read alone would record its value for
        # a place that holds the file's own text.
        and resolved != _without_tag(written)
    ):
        return None
    value = _value_read(written)
    if value is None:
        return None
    return EnvironmentReference(path, written, resolved, value, key)


def _has_reference(key: Any) -> bool:
    return isinstance(key, str) and "${" in key


_UNRESOLVED: Any = object()


def _resolved_key(written_key: str, resolved: Dict[Any, Any]) -> Any:
    """The key of ``resolved`` that ``written_key``, a mapping key as its file
    wrote it, came to; ``_UNRESOLVED`` when it came to none.

    A reference the loader resolves comes to its value; any other key came to
    its own text.
    """
    name = referenced_name(written_key)
    if name is not None and config_env_var_is_interpolatable(name):
        try:
            key = resolve_env_references(_without_tag(written_key))
        except Exception:  # noqa: BLE001 - a key that does not resolve came to none
            return _UNRESOLVED
        return key if key in resolved else _UNRESOLVED
    for key in (written_key, _without_tag(written_key)):
        if key in resolved:
            return key
    return _UNRESOLVED


def environment_references(
    written: Any, resolved: Any, path: Tuple[PathSegment, ...] = ()
) -> List[EnvironmentReference]:
    """What one file read from the environment, by comparing two readings of it.

    ``written`` is the file read with each reference left as written
    (``load_yaml_config(..., env="written")``, or a TOML document before
    ``_resolve_toml_env``), ``resolved`` the same text read as a scan reads it.

    Mapping entries are paired by key: a key written without a reference with
    the same key, and a key holding one with the key it resolves to. A key read
    from the environment that resolves to another key of its mapping merges the
    two; pairing by position would then compare every later value with the
    wrong one. The key's own read is recorded whether or not its entry is the
    one the merge keeps; only the kept entry's value is paired.
    """
    found: List[EnvironmentReference] = []
    if isinstance(written, dict) and isinstance(resolved, dict):
        plain = [(k, v) for k, v in written.items() if not _has_reference(k)]
        referenced = [(k, v) for k, v in written.items() if _has_reference(k)]
        plain_keys = {k for k, _ in plain}
        for key, value in plain:
            if key in resolved:
                found += environment_references(value, resolved[key], (*path, str(key)))
        names = [(k, v, _resolved_key(k, resolved)) for k, v in referenced]
        # The loader keeps the last entry written under a name.
        last = {name: index for index, (_, _, name) in enumerate(names)}
        for index, (written_key, written_value, name) in enumerate(names):
            if name is _UNRESOLVED:
                continue
            read = _reference(written_key, name, path, key=True)
            if read is not None:
                found.append(read)
            if name not in plain_keys and last[name] == index:
                found += environment_references(
                    written_value, resolved[name], (*path, str(name))
                )
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


def _written_key_reference(key: Any) -> bool:
    """Whether ``key``, a mapping key as its file wrote it, is a reference the
    loader resolves: one starting with ``${VAR}`` or ``${VAR:default}`` that
    names a variable it may read, whether or not the variable is set."""
    if not isinstance(key, str):
        return False
    name = referenced_name(key)
    return name is not None and config_env_var_is_interpolatable(name)


#: A mapping that holds a key its file writes as a reference: the mapping's path
#: in the file's own document, or None where that document does not place it in
#: the configuration, and the keys the file writes there as text.
WrittenKeyMapping = Tuple[Optional[Tuple[PathSegment, ...]], FrozenSet[str]]


def mappings_with_written_reference_keys(
    written: Any, unplaced: Collection[str] = ()
) -> List[WrittenKeyMapping]:
    """Each mapping of ``written``, a file read as written
    (read_config_file_as_written), that holds a key written as a reference,
    whatever its variable holds and whether or not it is set.

    The record of what a file read (environment_references) has no such key
    where the variable is unset, since the key is then the default the file
    wrote, nor where it resolves to another key of its mapping and merges with
    it. A rule that decides from the record answers by the variable's value;
    one that decides from these answers the same for every value. A mapping
    under a top-level key ``unplaced`` names (``extends``, ``patch``), or under
    a key written as a reference, gets no path: where it ends up in the
    configuration depends on more than this file.
    """
    found: List[WrittenKeyMapping] = []

    def walk(node: Any, path: Optional[Tuple[PathSegment, ...]]) -> None:
        if isinstance(node, dict):
            if any(_written_key_reference(key) for key in node):
                text = frozenset(
                    str(key) for key in node if not _written_key_reference(key)
                )
                found.append((path, text))
            for key, value in node.items():
                placed = (
                    path is not None
                    and not _written_key_reference(key)
                    and not (path == () and key in unplaced)
                )
                walk(value, (*path, str(key)) if placed and path is not None else None)
        elif isinstance(node, list):
            for index, item in enumerate(node):
                walk(item, None if path is None else (*path, index))

    walk(written, ())
    return found


def _normal(segment: PathSegment, exact_indices: bool = False) -> PathSegment:
    if isinstance(segment, (int, _AnyIndex)):
        if exact_indices and isinstance(segment, int):
            return segment
        return _ANY_INDEX
    return segment.replace("-", "_").lower()


def _normal_path(
    path: Iterable[PathSegment], exact_indices: bool = False
) -> Tuple[PathSegment, ...]:
    return tuple(_normal(segment, exact_indices) for segment in path)


def _exact_path(path: Iterable[PathSegment]) -> Tuple[PathSegment, ...]:
    """``path`` with its keys normalized and its list indices kept."""
    return tuple(
        segment if isinstance(segment, int) else _normal(segment) for segment in path
    )


def _bare(written: str) -> str:
    """The reference alone, ``${VAR}`` or ``${VAR:default}``, from ``written``
    (``_reference_match``); the text without its tag when it is none."""
    match = _reference_match(written)
    return match.group(0) if match else _without_tag(written)


def _anchored(text: str, reference: EnvironmentReference) -> bool:
    """Whether ``text`` is what ``reference`` resolved to, or that after a path
    prefix the load put on it (a relative path anchored at the file's
    directory): the prefix is empty or ends with ``/``, so a neighbor that
    merely ends with the same characters is not the entry."""
    if text == reference.resolved:
        return True
    if not text.endswith(reference.resolved):
        return False
    prefix = text[: len(text) - len(reference.resolved)]
    return prefix.endswith("/")


def _recorded_string(text: str, candidates: Sequence[EnvironmentReference]) -> str:
    """``text`` as the file wrote it, where ``candidates`` are the references that
    apply at its position (``_Index.pending``).

    A string equal to what a candidate resolved to is the reference; one that ends
    with it has the reference in its place; any other string has the value of each
    candidate replaced by it. A neighboring entry's reference is not a candidate,
    since it does not write this entry.
    """
    for reference in candidates:
        if text == reference.resolved:
            return reference.written
    for reference in candidates:
        if text.endswith(reference.resolved):
            # A path the load anchored: the file's text after a prefix.
            prefix = text[: len(text) - len(reference.resolved)]
            return prefix + _without_tag(reference.written)
    for reference in candidates:
        if reference.value in text:
            text = text.replace(reference.value, _bare(reference.written))
    return text


def written_without_tag(written: str) -> str:
    """``written``, a reference as a file wrote it, without an ``!ENV`` tag."""
    return _without_tag(written)


def fill_environment_references(
    data: Any,
    references: Sequence[EnvironmentReference],
    filled: Optional[List[EnvironmentReference]] = None,
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
    unpatched. ``filled``, when given, receives each reference at the exact
    position it was read into ``data``, with its list length, so a record of the
    filled document matches only where the fill wrote. A copy: ``data`` itself
    is not changed.
    """
    if not references:
        return data
    return _Index(references).fill(data, (), (), filled)


def environment_marker(written: str) -> str:
    """``<from ${VAR}>``, how a view of a configuration shows a value read from
    the environment: the reference without its tag, never the value. Told apart
    from a reference left as written, which is shown as written."""
    return f"<from {_bare(written)}>"


#: How a check's message shows a value or key a config file read from the
#: environment (``with_environment_values_shown``).
ENVIRONMENT_VALUE_SHOWN = "<value>"


def _shown_marker(_written: str) -> str:
    return ENVIRONMENT_VALUE_SHOWN


def with_environment_values_shown(
    data: Any,
    references: Sequence[EnvironmentReference],
    at: Sequence[PathSegment] = (),
    *,
    exact_indices: bool = False,
) -> Any:
    """``data`` with each value and key ``references`` read from the environment
    shown as ``<value>``, at its own position; see "Where".

    For the messages of a check: the check decides on ``data``, and a message
    quotes this copy at the same position, so a value read from the environment
    is never in the text while what the file wrote itself is. A copy: ``data``
    itself is not changed.

    ``exact_indices`` (record_environment_references) shows a reference written
    at a list index in the entry at that index only. Without it, the reference
    follows its entry when the list is no longer the length the file wrote, or
    when its index is unknown (see "Where"): an entry of the shape the load
    gives it is then shown with ``<value>`` at any index, while an entry the
    file wrote as the same text stays as written.
    """
    return record_environment_references(
        data, references, at=at, mark=_shown_marker, exact_indices=exact_indices
    )


class _Index:
    def __init__(
        self,
        references: Iterable[EnvironmentReference],
        mark: Optional[Callable[[str], Any]] = None,
        whole_only: bool = False,
        exact_indices: bool = False,
    ) -> None:
        self.values: Dict[Tuple[PathSegment, ...], List[EnvironmentReference]] = {}
        self.keys: Dict[Tuple[PathSegment, ...], List[EnvironmentReference]] = {}
        self.mark = mark
        self.whole_only = whole_only
        self.exact_indices = exact_indices
        #: The data's strings by exact position, and its lists' lengths (``scan``).
        self.strings: Dict[Tuple[PathSegment, ...], str] = {}
        self.lengths: Dict[Tuple[PathSegment, ...], int] = {}
        for reference in references:
            target = self.keys if reference.key else self.values
            target.setdefault(_normal_path(reference.path, exact_indices), []).append(
                reference
            )

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
                self.record(
                    value,
                    (*path, index if self.exact_indices else _ANY_INDEX),
                    (*exact, index),
                )
                for index, value in enumerate(item)
            )
        if isinstance(item, str):
            here = self.values.get(path)
            if here:
                # A whole string is read against the same references as a longer
                # one: a plain entry equal to the value, beside the reference's
                # own entry, is the file's own text and stays as written.
                candidates = self.pending(exact, here, item)
                return self._string(item, candidates)
        return item

    def fill(
        self,
        item: Any,
        path: Tuple[PathSegment, ...],
        exact: Tuple[PathSegment, ...] = (),
        filled: Optional[List[EnvironmentReference]] = None,
        length: Optional[int] = None,
        index_at: Optional[int] = None,
    ) -> Any:
        """``fill_environment_references``: the inverse of ``record``. When
        ``filled`` is given, every reference read into the document is appended
        to it at the EXACT position it was filled, with the enclosing list's
        length, so the record made from the filled document matches only there."""
        if isinstance(item, dict):
            renames = self.keys.get(path, ())
            result: Dict[Any, Any] = {}
            for key, value in item.items():
                for reference in renames:
                    if key == _without_tag(reference.written):
                        key = reference.resolved
                        break
                spelled = key if isinstance(key, str) else str(key)
                result[key] = self.fill(
                    value,
                    (*path, _normal(spelled)),
                    (*exact, _normal(spelled)),
                    filled,
                    length,
                    index_at,
                )
            return result
        if isinstance(item, (list, tuple)):
            return type(item)(
                self.fill(
                    value,
                    (*path, _ANY_INDEX),
                    (*exact, index),
                    filled,
                    len(item),
                    len(exact),
                )
                for index, value in enumerate(item)
            )
        if isinstance(item, str):
            for reference in self.values.get(path, ()):
                if item == _without_tag(reference.written):
                    if filled is not None:
                        filled.append(
                            replace(
                                reference,
                                path=exact,
                                length=length,
                                index_at=index_at,
                            )
                        )
                    return reference.resolved
        return item

    def _whole(self, reference: EnvironmentReference) -> Any:
        return reference.written if self.mark is None else self.mark(reference.written)

    def _string(self, text: str, candidates: List[EnvironmentReference]) -> Any:
        if self.mark is None:
            return _recorded_string(text, candidates)
        for reference in candidates:
            if text == reference.resolved:
                return self._whole(reference)
        if self.whole_only:
            return text
        for reference in candidates:
            if reference.value in text:
                text = text.replace(reference.value, self.mark(reference.written))
        return text


def record_environment_references(
    data: Any,
    references: Sequence[EnvironmentReference],
    at: Sequence[PathSegment] = (),
    mark: Optional[Callable[[str], Any]] = None,
    whole_only: bool = False,
    *,
    exact_indices: bool = False,
) -> Any:
    """``data``, a dump of a configuration, with what ``references`` read written
    as the file wrote it; see "Where".

    ``at`` is where ``data`` sits in the configuration, for a dump of one section
    of it (``("reporters", "gitlab-cyclonedx")`` for that reporter's section).
    ``mark``, when given, is applied to each reference as written, and replaces
    it: ``environment_marker`` for a view of the config, or a type a file writer
    tags ``!ENV``. ``whole_only`` replaces only a string that is the whole value,
    for a file that is loaded again (``AshConfig.save(as_written=True)``).
    ``exact_indices`` places a reference at the list index its file wrote it at,
    and at no other entry of that list, for a view of a configuration as its
    files hold it (the MCP get_config tool): an entry beside it with the same
    text is shown as it is, and a reference whose index the file's layout does
    not give is placed nowhere. Without it, a reference is read at its own
    index and, when its entry moved or its index is unknown (see "Where"), at
    any index of its list, so it follows an entry a patch moves. A copy:
    ``data`` itself is not changed.
    """
    if not references:
        return data
    index = _Index(references, mark, whole_only, exact_indices)
    index.scan(data, _exact_path(at))
    return index.record(data, _normal_path(at, exact_indices), _exact_path(at))


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


def record_unread_references(data: Any, unread: Sequence[UnreadReference]) -> Any:
    """``data``, a dump of a configuration read from a record, with each field
    ``load_recorded_config`` could not read written as the reference the record
    held there, not the default it was read with. A copy: ``data`` itself is not
    changed."""
    if not unread or not isinstance(data, dict):
        return data
    data = copy.deepcopy(data)
    for entry in unread:
        node = data
        steps = entry.field.split(".")
        for step in steps[:-1]:
            if isinstance(node, list) and step.isdigit() and int(step) < len(node):
                node = node[int(step)]
            elif isinstance(node, dict):
                node = node.setdefault(_matching_key(node, step), {})
            else:
                break
        else:
            if isinstance(node, dict):
                node[_matching_key(node, steps[-1])] = entry.reference
            elif (
                isinstance(node, list)
                and steps[-1].isdigit()
                and int(steps[-1]) < len(node)
            ):
                node[int(steps[-1])] = entry.reference
    return data


def _field_path(field: str) -> Tuple[PathSegment, ...]:
    """``field``, dotted keys of a record, as a path: list indices as numbers."""
    return tuple(int(step) if step.isdigit() else step for step in field.split("."))


def take_own_values(config: Any, own: Any) -> Any:
    """``config``, a recorded configuration, with each field ``load_recorded_config``
    could not read given ``own``'s value for it; see "Reading a record".

    ``own`` is this invocation's own configuration, resolved as the scan resolved
    its: the outer process of a container or Nix scan resolves the scan's
    configuration, and ``ash scan --use-existing`` has the orchestrator's. A field
    ``own`` does not hold (an option of a plugin it does not configure) keeps the
    default the record was read with, which is what ``own`` uses too, and stays
    noted in ``_unread_references``. Where ``own``
    read the field from the environment, the result keeps that reference
    (``_environment_references``), so a record written from it holds the
    reference, not the value.
    """
    unread = tuple(getattr(config, "_unread_references", ()) or ())
    if not unread or own is None:
        return config
    from automated_security_helper.config.ash_config import AshConfig

    own_data = own.model_dump(by_alias=True)
    own_references = tuple(getattr(own, "_environment_references", ()) or ())
    data = config.model_dump(by_alias=True)
    carried: List[EnvironmentReference] = []
    kept: List[UnreadReference] = []
    for entry in unread:
        found, value = _value_at(own_data, entry.field)
        if not found:
            kept.append(entry)
            continue
        node = data
        steps = entry.field.split(".")
        for step in steps[:-1]:
            node = node.setdefault(_matching_key(node, step), {})
        node[_matching_key(node, steps[-1])] = value
        wanted = _normal_path(_field_path(entry.field))
        carried += [
            reference.at(_field_path(entry.field))
            for reference in own_references
            if not reference.key and _normal_path(reference.path) == wanted
        ]
    updated = AshConfig.model_validate(data)
    updated._environment_references = (
        *tuple(getattr(config, "_environment_references", ()) or ()),
        *carried,
    )
    updated._unread_references = tuple(kept)
    return updated


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
