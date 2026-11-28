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
that takes a fixed choice cannot hold one, so the record is read with that
field's default, one warning names the field and the reference, and the field is
listed on the configuration (``AshConfig._unreadable_references``, set by
``AshAggregatedResults.validate_ash_config``). A true/false or a number field
refuses the record instead. What ``ash merge``, ``ash report``, the outer process
of a container or Nix scan and ``ash scan --use-existing`` then do with a listed
field is in ``config/recorded_config.py``.
"""

from __future__ import annotations

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
    cast,
)

from automated_security_helper.config.ash_config import (
    ENV_REFERENCE_PATTERN,
    EXPLICIT_ENV_TAG,
    config_env_var_is_interpolatable,
    list_made_of,
    reduced_plugin_name,
    resolve_env_references,
)

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
    #: The file that wrote it, resolved, and the path it holds in that file's
    #: own document, kept when ``moved_to_unknown_list`` moves it: how the
    #: record of the configuration (config_validator.environment_record_read)
    #: finds where the reference it reads in the file ended up. Not compared.
    origin: Optional[Tuple[Path, Tuple[PathSegment, ...]]] = dataclass_field(
        default=None, compare=False
    )
    #: How many entries the innermost list the file wrote it in had, when it
    #: wrote it in a list (as an entry, or inside a mapping that is one); None
    #: otherwise.
    length: Optional[int] = None
    #: Where in ``path`` the index of that list entry sits; set with ``length``.
    index_at: Optional[int] = None
    #: For a relative path the load anchored at its file's directory: the text
    #: the anchoring made of it, normalized (a ``..`` or ``./`` folded, so the
    #: text holds neither ``resolved`` nor ``resolved`` after a path prefix) or
    #: kept whole, and the directory it was anchored at, or ``<value>`` when
    #: that directory's path came from the environment
    #: (``ResolvedConfigDocument.environment_paths``), recorded at the anchoring
    #: (``with_anchored_forms``). A view shows such a text as the directory and
    #: the reference. None when the anchoring left the value as it was. Not
    #: compared.
    anchored: Optional[Tuple[str, str]] = dataclass_field(default=None, compare=False)
    #: Set where a document of the chain merged after this reference's file
    #: writes its place (config_sources._mark_written_over): the configuration
    #: holds that document's value there, whatever it is, so no view, record or
    #: session copy describes the place by this reference. It stays one of the
    #: chain's reads, so redaction still masks its value. Not compared.
    written_over: bool = dataclass_field(default=False, compare=False)
    #: A display-only entry for a literal relative path that a file whose own
    #: path came from the environment wrote, and the anchoring took from that
    #: file's directory (``anchored_literals``). Nothing was read from the
    #: environment at its place, so ``value`` is empty: ``written`` is the text a
    #: view shows (the directory as ``<value>`` and the path as the file wrote
    #: it), and ``resolved`` and ``anchored[0]`` are the anchored text. It is in
    #: ``ResolvedConfigDocument.displayed_environment_references`` only, never
    #: in ``environment_references``, so no record, redaction or session copy
    #: reads one; a view shows the path by ``written`` (``_Index._string``).
    literal: bool = False

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

    @property
    def position_unknown(self) -> bool:
        """Whether the list index in ``path`` says nothing about where the entry
        is: the path names an unknown index, or holds an index with no record of
        the list it was written in."""
        if any(isinstance(segment, _AnyIndex) for segment in self.path):
            return True
        return self.length is None and any(isinstance(s, int) for s in self.path)

    def read_in(self, file: Path) -> "EnvironmentReference":
        """This reference, read in ``file`` (resolved) at its path there."""
        return replace(self, origin=(file, tuple(self.path)))

    @property
    def place_key(self) -> Tuple[Any, ...]:
        """The reference as its file wrote it, for a record of the file's text
        to find it by: where in which file, value or key, and its text."""
        return (self.origin, self.key, self.written)


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
        # The same, for text with blanks around it (a quoted or TOML string):
        # the resolver returns what it leaves as written stripped.
        and resolved != _without_tag(written).strip()
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

    The resolved document was folded to each known plugin's declared spelling
    before the two views are paired (``fold_known_plugin_sections`` in
    ``config_sources._file_references``), so a value in another spelling of a
    known plugin (``Bandit``, ``cdk_nag``) came to the folded key: that key is
    answered when the value itself is not one. A key the loader never resolves
    (a TOML key, a quoted YAML key) came to its own text, whatever its value
    resolves to; an exact lookup of the value alone answered none for it, and
    every environment read beneath the key went unrecorded. Its own text is
    looked up first: where the variable's value is also a key of the mapping,
    the lookup of the value paired the literal key with that other entry and
    recorded a key read from the environment that the loader never read. A
    reference the resolver leaves as written comes back stripped of blanks
    around it, so that spelling is looked up last. A resolved key never keeps
    its ``${`` text, so a key found by its own text (tagged or not) was never
    resolved, and the value's match is not tried for it.
    """
    untagged = _without_tag(written_key)
    for own_text in (written_key, untagged):
        if own_text in resolved:
            return own_text
    name = referenced_name(written_key)
    if name is not None and config_env_var_is_interpolatable(name):
        try:
            key = resolve_env_references(_without_tag(written_key))
        except Exception:  # noqa: BLE001 - a key that does not resolve came to none
            key = _UNRESOLVED
        if key is not _UNRESOLVED and key in resolved:
            return key
        if isinstance(key, str):
            folded = reduced_plugin_name(key)
            for candidate in resolved:
                if (
                    isinstance(candidate, str)
                    and reduced_plugin_name(candidate) == folded
                ):
                    return candidate
    if untagged.strip() in resolved:
        return untagged.strip()
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
    one the merge keeps; only the kept entry's value is paired. The kept entry
    is the one written LAST under the name, whether that name was written as
    text or came from a reference: the loader keeps the last. Pairing the plain
    key's value whenever it was present compared it with the value a later
    referenced key wrote over it, recording a reference the file never made
    there and missing the one the kept entry read.
    """
    found: List[EnvironmentReference] = []
    if isinstance(written, dict) and isinstance(resolved, dict):
        entries = list(written.items())
        names = [
            _resolved_key(key, resolved) if _has_reference(key) else key
            for key, _ in entries
        ]
        # The loader keeps the last entry written under a name, and the
        # written reading's mapping order is the write order of the entries it
        # kept (``load_yaml_config(..., env="written")`` moves a repeated key to
        # its last writing; a dict alone would hold it at its first), so the
        # highest index under a name is the entry the loader kept.
        last = {
            name: index for index, name in enumerate(names) if name is not _UNRESOLVED
        }
        for index, (written_key, written_value) in enumerate(entries):
            name = names[index]
            if name is _UNRESOLVED:
                continue
            if _has_reference(written_key):
                read = _reference(written_key, name, path, key=True)
                if read is not None:
                    found.append(read)
            if last[name] == index and name in resolved:
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
    if isinstance(segment, _AnyIndex):
        # Already "any position": a reference at an unknown index keeps it.
        return segment
    if isinstance(segment, int):
        return segment if exact_indices else _ANY_INDEX
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


def _case_kept_path(path: Iterable[PathSegment]) -> Tuple[PathSegment, ...]:
    """``path`` with ``-`` and ``_`` folded in its keys, the case kept, and its
    list indices and unknown index as they are: the names the display walk
    reads a reference into when a mapping holds two keys that differ only in
    case (``_Index._references_at``), which ``_exact_path`` would run together."""
    return tuple(
        segment.replace("-", "_") if isinstance(segment, str) else segment
        for segment in path
    )


def _bare(written: str) -> str:
    """The reference alone, ``${VAR}`` or ``${VAR:default}``, from ``written``
    (``_reference_match``); the text without its tag when it is none."""
    match = _reference_match(written)
    return match.group(0) if match else _without_tag(written)


def _ends_with_resolved(text: str, resolved: str) -> bool:
    """Whether ``text`` ends with ``resolved``, a path's separators aside on Windows.

    A relative path the load anchored is a ``Path`` once configured, and a
    ``Path`` on Windows writes its separators as ``\\`` where the environment
    value wrote ``/``. Each separator is one character either way, so the
    prefix length is the same for both spellings.
    """
    if text.endswith(resolved):
        return True
    return os.sep == "\\" and text.replace("\\", "/").endswith(
        resolved.replace("\\", "/")
    )


def _anchored(text: str, reference: EnvironmentReference) -> bool:
    """Whether ``text`` is what ``reference`` resolved to, or that after a path
    prefix the load put on it (a relative path anchored at the file's
    directory): the prefix is empty or ends with a path separator, so a neighbor
    that merely ends with the same characters is not the entry."""
    if text == reference.resolved:
        return True
    if not _ends_with_resolved(text, reference.resolved):
        return False
    prefix = text[: len(text) - len(reference.resolved)]
    return prefix.endswith(("/", os.sep))


def holds_reference(text: str, reference: EnvironmentReference) -> bool:
    """Whether ``text`` is the entry ``reference`` wrote: what it resolved to,
    that after a path prefix the load put on it (``_anchored``), or the text the
    anchoring made of it (``EnvironmentReference.anchored``)."""
    return _anchored(text, reference) or (
        reference.anchored is not None and text == reference.anchored[0]
    )


def with_anchored_forms(
    references: Sequence[EnvironmentReference], document: Any, base_dir: str
) -> List[EnvironmentReference]:
    """``references``, one file's, each with the text the anchoring made of its
    value recorded (``EnvironmentReference.anchored``) where ``document``, the
    document after that file's relative paths were anchored at ``base_dir`` (its
    own, or the one its patch made), holds a string at the reference's place
    other than what the reference resolved to: the anchoring made a path of it,
    normalized or kept whole behind the directory. Every other reference, keys
    included, is returned as it is, so ``anchored`` stays None where the
    anchoring left the value as it was."""
    found: List[EnvironmentReference] = []
    for reference in references:
        node = _node_at(document, reference.path)
        if reference.key or not isinstance(node, str) or node == reference.resolved:
            found.append(reference)
        else:
            found.append(replace(reference, anchored=(str(node), base_dir)))
    return found


#: The scheme of a ``file://`` entry, which the anchoring puts the directory
#: after (``operator_paths._anchored_file_entry``).
_FILE_SCHEME = "file://"


def _literal_shown(written: str, shown_dir: str) -> str:
    """``written``, a relative path a file wrote, as a view shows it: after
    ``shown_dir``, the directory the anchoring took it from, and for a
    ``file://`` entry after the scheme."""
    if written.startswith(_FILE_SCHEME):
        return _FILE_SCHEME + os.path.join(shown_dir, "") + written[len(_FILE_SCHEME) :]
    return os.path.join(shown_dir, "") + written


def anchored_literals(
    written: Any,
    anchored: Any,
    *,
    skip: Collection[Tuple[PathSegment, ...]],
    shown_dir: str,
    resolved_as_written: bool = False,
    path: Tuple[PathSegment, ...] = (),
) -> List[EnvironmentReference]:
    """A display-only entry (``EnvironmentReference.literal``) for each string of
    ``written`` that ``anchored``, the same document after its relative paths were
    anchored, holds as another string, and that is no place of ``skip`` (the
    places the file read from the environment, whose references record their own
    anchored text).

    ``written`` is a file's document, or the value of one of its ``patch``
    operations, as the file wrote it; ``anchored`` the same after the
    anchoring. The entry is shown after ``shown_dir`` (``_literal_shown``), and
    for a list entry it records the length of the innermost list and where its
    index is, as ``environment_references`` does. With ``resolved_as_written``,
    for a value of an operation, ``resolved`` is the text the operation wrote
    and ``anchored`` is left to ``with_anchored_forms``, which records the anchored
    text where the operation puts it (``config_sources._placed_through_patch``).
    ``path`` is where ``written`` sits, for the recursion.
    """
    found: List[EnvironmentReference] = []
    if isinstance(written, dict) and isinstance(anchored, dict):
        for key, value in written.items():
            if key in anchored:
                found += anchored_literals(
                    value,
                    anchored[key],
                    skip=skip,
                    shown_dir=shown_dir,
                    resolved_as_written=resolved_as_written,
                    path=(*path, str(key)),
                )
    elif (
        isinstance(written, list)
        and isinstance(anchored, list)
        and len(written) == len(anchored)
    ):
        for index, (item, anchored_item) in enumerate(zip(written, anchored)):
            for entry in anchored_literals(
                item,
                anchored_item,
                skip=skip,
                shown_dir=shown_dir,
                resolved_as_written=resolved_as_written,
                path=(*path, index),
            ):
                # The innermost list the entry was written in gives its length.
                if entry.length is None:
                    entry = replace(entry, length=len(written), index_at=len(path))
                found.append(entry)
    elif (
        isinstance(written, str)
        and isinstance(anchored, str)
        and written != anchored
        and path not in skip
    ):
        found.append(
            EnvironmentReference(
                path=path,
                written=_literal_shown(written, shown_dir),
                resolved=written if resolved_as_written else anchored,
                value="",
                anchored=None if resolved_as_written else (anchored, shown_dir),
                literal=True,
            )
        )
    return found


def _node_at(document: Any, path: Sequence[PathSegment]) -> Any:
    """The value at ``path`` in ``document``, or None when the place is gone."""
    node = document
    for segment in path:
        if not isinstance(node, (dict, list)):
            return None
        try:
            node = cast(Any, node)[segment]
        except (TypeError, KeyError, IndexError):
            return None
    return node


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
        if _ends_with_resolved(text, reference.resolved):
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
    placed: Optional[List[EnvironmentReference]] = None,
) -> Any:
    """``data``, the document of a profile's copy a client patched, with each
    reference the operator's copy wrote read again.

    ``references`` are the operator's copy's. Where ``data`` holds, at the
    position of one of them, exactly the reference that copy wrote (without its
    tag), as ``AshConfig.save(as_written=True, env_tags=False)`` writes it for a
    position the client did not change, it gets the value the operator's copy
    read there. A position is the reference's keys; in a list it is any entry of
    the list the operator's copy wrote it in, since a client's patch can move
    the entry (see ``placed``). Nothing else is read: a client that writes a
    reference under other keys has it left as text, and one that writes it at
    such a position gets the value the operator's copy holds there, which is
    what the profile gives it unpatched. A copy: ``data`` itself is not changed.

    ``placed``, when given, is extended with a copy of each reference that was
    read, at the path ``data`` holds it at. The fill finds a list entry at any
    index, so an entry the client added ahead of one has moved it: the path of
    the operator's copy would name the client's entry. A record of the
    configuration built from ``data`` is built from these paths
    (config_validator.environment_record_of_references).
    """
    if not references:
        return data
    return _Index(references).fill(data, (), (), placed)


def environment_marker(written: str) -> str:
    """``<from ${VAR}>``, how a view of a configuration shows a value read from
    the environment: the reference without its tag, never the value. Told apart
    from a reference left as written, which is shown as written.

    Text the file wrote after the reference is the file's own and follows the
    marker (``<from ${VAR}>-a``), so two keys of one mapping read from one
    variable with different tails stay two keys. A string the load changed is
    marked inside, with the reference alone (``_Index._string``), and its own
    text after the value is kept there. Blanks at the end are not part of the
    tail: the resolver strips them from the value, so the marker does too."""
    bare = _bare(written)
    if not _reference_match(written):
        return f"<from {bare}>"
    tail = _without_tag(written)[len(bare) :].rstrip()
    return f"<from {bare}>{tail}"


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
    at a list index in the entry at that index only. Without it, every entry of
    the list that holds the value's text is shown with ``<value>`` in its place,
    an entry the file wrote too.
    """
    return record_environment_references(
        data, references, at=at, mark=_shown_marker, exact_indices=exact_indices
    )


class EnvironmentValueInPath(RuntimeError):
    """A value read from the environment sits inside a longer string, so a copy
    written for a session could not hold it as the reference.

    Raised by ``record_environment_references(..., whole_only=True)`` where a
    string is a path the load anchored on the value (``_anchored``), or the text
    the anchoring made of one (a ``..`` or ``./`` folded out of it,
    ``EnvironmentReference.anchored``), and not the value itself: written as it
    is, the copy would hold the value. It is also raised where a list the field
    made of one reference's text holds an entry a later step appended beside it,
    which written as names would be the value. The message names the key path
    and the variable, never the value.
    """

    def __init__(self, key_path: str, variable: str) -> None:
        super().__init__(
            f"This profile can't be written to a session: at {key_path}, the value "
            f"read from environment variable {variable} is part of a longer string. "
            f"Set {variable} to an absolute path, or to the whole string."
        )
        self.key_path = key_path
        self.variable = variable


def _renamed_keys(
    keys: Iterable[Any], references: Sequence[EnvironmentReference]
) -> Dict[Any, EnvironmentReference]:
    """The key reference that renames each of ``keys``, a mapping's keys.

    A reference renames the key spelled as it resolved, or else one key spelled
    the other way (``-`` or ``_``, any case), which is how the record keys a
    built-in plugin's section by its field name. Each reference renames one
    key: a mapping that holds both ``foo-bar`` and ``foo_bar`` renamed both to
    the same reference, and one of the two entries was lost.
    """
    if not references:
        return {}
    spelled = {key: key if isinstance(key, str) else str(key) for key in keys}
    renamed: Dict[Any, EnvironmentReference] = {}
    for reference in references:
        free = [key for key in spelled if key not in renamed]
        exact = [key for key in free if spelled[key] == reference.resolved]
        normal = _normal(reference.resolved)
        found = exact or [key for key in free if _normal(spelled[key]) == normal]
        if found:
            renamed[found[0]] = reference
    return renamed


class _Index:
    def __init__(
        self,
        references: Iterable[EnvironmentReference],
        mark: Optional[Callable[[str], Any]] = None,
        whole_only: bool = False,
        exact_indices: bool = False,
        list_as_reference: bool = False,
    ) -> None:
        self.values: Dict[Tuple[PathSegment, ...], List[EnvironmentReference]] = {}
        self.keys: Dict[Tuple[PathSegment, ...], List[EnvironmentReference]] = {}
        self.mark = mark
        self.whole_only = whole_only
        self.exact_indices = exact_indices
        self.list_as_reference = list_as_reference
        #: The data's strings by exact position, and its lists' lengths (``scan``).
        self.strings: Dict[Tuple[PathSegment, ...], str] = {}
        self.lengths: Dict[Tuple[PathSegment, ...], int] = {}
        for reference in references:
            if whole_only and reference.written_over:
                # A session copy writes what the configuration holds: a later
                # document's value is written as that document wrote it.
                continue
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
        the entry, a patch) and the entry at the same index is neither the value,
        nor a path the load anchored on it, nor the text the anchoring made of it
        (``holds_reference``). A list of the same length whose entry changed is
        an entry the load or an override changed, not one that moved.
        """
        if reference.length is None or reference.index_at is None:
            return False
        exact = _exact_path(reference.path)
        text = self.strings.get(exact)
        if text is not None and holds_reference(text, reference):
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
        its entry (``holds_reference``: what it resolved to, that after a path
        prefix, or the text the anchoring made of it): another entry that merely
        contains the text is not that entry.

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
                holds_reference(text, r)
                if r.position_unknown or self._moved(r)
                else _exact_path(r.path) == exact
            )
        ]

    def _references_at(
        self,
        table: Dict[Tuple[PathSegment, ...], List[EnvironmentReference]],
        path: Tuple[PathSegment, ...],
        pinned: Tuple[Tuple[int, str], ...],
    ) -> Sequence[EnvironmentReference]:
        """The references of ``table`` at ``path``, narrowed by ``pinned``: the
        (depth, key) pairs of the mappings the walk went through that hold two
        keys with one normal form (``AWS_Region`` and ``aws_region``). A
        reference is read into one of those keys' values only when its own path
        names that key, ``-`` and ``_`` folded and the case kept; with no such
        pair the lookup is the case-insensitive one."""
        found = table.get(path, ())
        if not pinned or not found:
            return found

        def names(reference: EnvironmentReference, depth: int, key: str) -> bool:
            segment = reference.path[depth] if len(reference.path) > depth else None
            return isinstance(segment, str) and segment.replace("-", "_") == key

        return [
            reference
            for reference in found
            if all(names(reference, depth, key) for depth, key in pinned)
        ]

    def _list_made_from(
        self,
        item: Any,
        path: Tuple[PathSegment, ...],
        exact: Tuple[PathSegment, ...],
        pinned: Tuple[Tuple[int, str], ...],
    ) -> Optional[Tuple[EnvironmentReference, int]]:
        """The reference a file wrote at the place of a list itself, which resolved
        to one string, and how many of the list's first entries the field made of
        that string (``ash_config.list_made_of``). None in an unmarked record, for
        a list the file wrote as a list (its references sit at its entries), and
        for a list that does not start with those entries (a later file's list, a
        replacing override's), which is walked as written. A copy written to be
        loaded again (``whole_only``) finds it too: it writes the reference
        itself, which loads back as the list."""
        if self.mark is None:
            return None
        entries = list(item)
        for reference in self._references_at(self.values, path, pinned):
            if (
                reference.key
                or reference.literal
                or not isinstance(reference.resolved, str)
            ):
                continue
            if _exact_path(reference.path) != exact:
                continue
            count = list_made_of(reference.resolved, entries)
            if count:
                return reference, count
        return None

    def record(
        self,
        item: Any,
        path: Tuple[PathSegment, ...],
        exact: Optional[Tuple[PathSegment, ...]] = None,
        pinned: Tuple[Tuple[int, str], ...] = (),
    ) -> Any:
        exact = path if exact is None else exact
        if isinstance(item, dict):
            renamed = _renamed_keys(item, self._references_at(self.keys, path, pinned))
            normals: Dict[Any, int] = {}
            for key in item:
                normal = _normal(key if isinstance(key, str) else str(key))
                normals[normal] = normals.get(normal, 0) + 1
            result: Dict[Any, Any] = {}
            for key, value in item.items():
                spelled = key if isinstance(key, str) else str(key)
                below = pinned
                if normals[_normal(spelled)] > 1:
                    below = (*pinned, (len(path), spelled.replace("-", "_")))
                recorded = self.record(
                    value,
                    (*path, _normal(spelled)),
                    (*exact, _normal(spelled)),
                    below,
                )
                if key in renamed:
                    key = self._whole(renamed[key])
                else:
                    key = self._unreplaced(key)
                result[key] = recorded
            return result
        if isinstance(item, (list, tuple)):
            made = self._list_made_from(item, path, exact, pinned)
            if made is not None:
                whole, count = made
                if self.whole_only:
                    if count < len(item):
                        # A copy cannot hold entries a later step appended
                        # beside the reference: written as names, they would
                        # be the value.
                        raise EnvironmentValueInPath(
                            self._key_path(exact),
                            referenced_name(whole.written) or "?",
                        )
                    # The reference itself, which loads back as the list.
                    return self._whole(whole)
                if self.list_as_reference:
                    # Written to be loaded again (`ash config get`): the
                    # reference once, which loads back as the entries it made,
                    # with each entry a later step appended after it.
                    tail = "".join(f",{entry}" for entry in list(item)[count:])
                    return self._whole(replace(whole, written=whole.written + tail))
                # A view of a list the load made of one reference's text
                # (``output_formats`` splits "sarif,html" into names): each entry
                # the text made is part of the value and is shown as the
                # reference, and no such entry is shown in clear. An entry a
                # later step appended (an appending ``--config-overrides``) is
                # walked as any entry is.
                return type(item)(
                    [self._whole(whole) for _ in range(count)]
                    + [
                        self.record(
                            value,
                            (*path, index if self.exact_indices else _ANY_INDEX),
                            (*exact, index),
                            pinned,
                        )
                        for index, value in enumerate(item)
                        if index >= count
                    ]
                )
            return type(item)(
                self.record(
                    value,
                    (*path, index if self.exact_indices else _ANY_INDEX),
                    (*exact, index),
                    pinned,
                )
                for index, value in enumerate(item)
            )
        if isinstance(item, (set, frozenset)):
            # A set has no positions: each member is read as an entry whose
            # position is unknown (``EnvironmentReference.position_unknown``),
            # by the shape the reference resolved to, and the set keeps its type.
            return type(item)(
                self._member(value, path, exact, pinned) for value in item
            )
        if isinstance(item, str):
            return self._read_string(item, path, exact, pinned)
        return item

    def _read_string(
        self,
        text: Any,
        path: Tuple[PathSegment, ...],
        exact: Tuple[PathSegment, ...],
        pinned: Tuple[Tuple[int, str], ...],
    ) -> Any:
        """The string ``text`` at ``path``, read against the references there.

        A whole string is read against the same references as a longer one: a
        plain entry equal to the value, beside the reference's own entry, is the
        file's own text and stays as written. With ``mark`` (a view, not
        ``whole_only``) a string that carries the loader's mark and that no
        candidate resolved to as a whole is shown as the reference its own mark
        carries, with no part replaced: a part replacement makes a plain string
        of it, and the rest of the value it read would be shown."""
        here = self._references_at(self.values, path, pinned)
        if not here:
            return self._unreplaced(text)
        candidates = self.pending(exact, list(here), text)
        if (
            self.mark is not None
            and not self.whole_only
            and getattr(text, "from_environment", False)
            and not any(text == reference.resolved for reference in candidates)
        ):
            return self.mark(text.shown)
        return self._unreplaced(self._string(text, candidates, exact))

    def _member(
        self,
        member: Any,
        path: Tuple[PathSegment, ...],
        exact: Tuple[PathSegment, ...],
        pinned: Tuple[Tuple[int, str], ...] = (),
    ) -> Any:
        """One member of a set at ``path``: read against the references at an
        unknown position there (the entry's own shape), and shown as the
        reference its mark carries when none replaced it."""
        if not isinstance(member, str):
            return member
        return self._read_string(
            member, (*path, _ANY_INDEX), (*exact, _ANY_INDEX), pinned
        )

    def _unreplaced(self, text: Any) -> Any:
        """``text``, a string or a mapping key the walk left as it was, shown as
        the reference its own mark carries when it still carries the loader's
        mark (``EnvResolvedScalar.from_environment``): a value read from the
        environment that no reference replaced, whole or in part, is never shown.
        Only for a view (``mark`` given); text without the mark, and text the
        walk replaced (a plain string by then), is returned as it is. Not for a
        file written to be loaded again (``whole_only``), whose writer refuses a
        value left as text by its own check."""
        if (
            self.mark is not None
            and not self.whole_only
            and getattr(text, "from_environment", False)
        ):
            return self.mark(text.shown)
        return text

    def fill(
        self,
        item: Any,
        path: Tuple[PathSegment, ...],
        where: Tuple[PathSegment, ...] = (),
        placed: Optional[List[EnvironmentReference]] = None,
    ) -> Any:
        """``fill_environment_references``: the inverse of ``record``.

        ``path`` is the normalized path that finds a reference, ``where`` the
        keys and list indices ``item`` is at in the document. A reference that
        is read is added to ``placed``, when given, at ``where``: for a key, the
        path of its mapping, as a reference's path is.
        """
        if isinstance(item, dict):
            renames = self.keys.get(path, ())
            result: Dict[Any, Any] = {}
            for key, value in item.items():
                for reference in renames:
                    if key == _without_tag(reference.written):
                        key = reference.resolved
                        if placed is not None:
                            placed.append(reference.moved_to_unknown_list(where))
                        break
                spelled = key if isinstance(key, str) else str(key)
                result[key] = self.fill(
                    value, (*path, _normal(spelled)), (*where, spelled), placed
                )
            return result
        if isinstance(item, (list, tuple)):
            return type(item)(
                self.fill(value, (*path, _ANY_INDEX), (*where, index), placed)
                for index, value in enumerate(item)
            )
        if isinstance(item, str):
            for reference in self.values.get(path, ()):
                if item == _without_tag(reference.written):
                    if placed is not None:
                        placed.append(reference.moved_to_unknown_list(where))
                    return reference.resolved
        return item

    def _whole(self, reference: EnvironmentReference) -> Any:
        return reference.written if self.mark is None else self.mark(reference.written)

    def _key_path(self, exact: Tuple[PathSegment, ...]) -> str:
        """``exact`` as a dotted key path, a key the environment named shown as
        ``<key>``: the path is named in a refusal, and the key is a value."""
        named = {_normal(r.resolved) for refs in self.keys.values() for r in refs}
        return ".".join("<key>" if s in named else str(s) for s in exact)

    def _string(
        self,
        text: str,
        candidates: List[EnvironmentReference],
        exact: Tuple[PathSegment, ...] = (),
    ) -> Any:
        if self.mark is None:
            return _recorded_string(text, candidates)
        for reference in candidates:
            if (
                reference.literal
                and reference.anchored is not None
                and text == reference.anchored[0]
            ):
                # A literal relative path of a file whose own path the
                # environment chose: nothing was read at its place, so it is
                # shown as the file wrote it after the shown directory, and
                # not as a reference.
                return reference.written
        # A literal entry names no value, and an empty value is part of every
        # string, so the searches below never read one.
        candidates = [reference for reference in candidates if not reference.literal]
        for reference in candidates:
            if text == reference.resolved:
                return self._whole(reference)
        if self.whole_only:
            for reference in candidates:
                if holds_reference(text, reference):
                    # Written as the text, the copy would hold the value.
                    raise EnvironmentValueInPath(
                        self._key_path(exact),
                        referenced_name(reference.written) or "?",
                    )
            return text
        for reference in candidates:
            if reference.anchored is not None and text == reference.anchored[0]:
                # A relative path the load anchored, normalized or kept whole, is
                # shown as its file's directory and the reference. The text the
                # anchoring made of it need not hold the value's text (a folded
                # ``..``, a path separator a platform rewrote), so it is matched
                # as a whole and not searched for the value.
                return os.path.join(reference.anchored[1], "") + self._whole(reference)
        for reference in candidates:
            if reference.value in text:
                # The value's part alone takes the reference alone, as the
                # unmarked record does (_recorded_string): the text the file
                # wrote after the reference is still in ``text``, and the whole
                # written reference put it there a second time.
                text = text.replace(
                    reference.value, self.mark(_bare(reference.written))
                )
        return text


def record_environment_references(
    data: Any,
    references: Sequence[EnvironmentReference],
    at: Sequence[PathSegment] = (),
    mark: Optional[Callable[[str], Any]] = None,
    whole_only: bool = False,
    *,
    exact_indices: bool = False,
    list_as_reference: bool = False,
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
    text is shown as it is. Without it, a reference matches every entry of its
    list, so it follows an entry a patch moves. ``list_as_reference``, for a view
    written to be loaded again (``ash config get``): a list the load made of one
    reference's text is written as that reference once, with each entry a later
    step appended after it, so the text loads back as the list. A copy: ``data``
    itself is not changed.

    A set or frozenset is walked too, and keeps its type: a set has no
    positions, so each member is an entry whose position is unknown and is read
    against the references at the set's place by the shape they resolved to.
    A file's own record holds no reference for a set member (the loader pairs
    mappings and lists only); ``references_to_marked_values`` makes one for each
    member the loader marked, under the built-in reporters' destination options
    and, with ``sets_only``, in the whole dump of a configuration, which
    ``resolve_config.load_config_file_for_run`` walks at the end of every load.

    With ``mark`` (a view; not ``whole_only``), a string, a mapping key or a set member that still
    carries the loader's mark after the walk (``EnvResolvedScalar``: no
    reference replaced it, whole or in part) is shown as ``mark(x.shown)``, the
    reference its own mark carries: a value no reference describes is never
    shown in clear. It changes nothing where a reference replaced the value, and
    nothing in text the loader did not mark.
    """
    if not references and mark is None:
        return data
    index = _Index(references, mark, whole_only, exact_indices, list_as_reference)
    index.scan(data, _exact_path(at))
    return index.record(data, _normal_path(at, exact_indices), _exact_path(at))


def _marked(text: Any) -> bool:
    """Whether ``text`` is a string the loader read from the environment."""
    return isinstance(text, str) and bool(getattr(text, "from_environment", False))


def references_to_marked_values(
    data: Any,
    at: Sequence[PathSegment],
    described: Iterable[EnvironmentReference] = (),
    *,
    sets_only: bool = False,
) -> List[EnvironmentReference]:
    """A reference for each string and mapping key of ``data`` that carries the
    loader's mark (``EnvResolvedScalar.from_environment``) and that none of
    ``described`` already describes at its exact place.

    ``data`` is the value of the option at ``at`` (a path of keys) in a python-mode
    dump of a configuration, which holds the loader's marked strings as they
    are. A load that copies a value from one place of the configuration to
    another (the reporter confinement and the settle) copies the mark with it,
    while the reference the file wrote stays at the place it wrote it: the copy
    is described from the value's own mark instead. Mapping keys and values, list
    and tuple entries, and set and frozenset members are walked.

    With ``sets_only``, only the set and frozenset members are described, and
    the walk goes through every mapping, list and tuple to reach them: for the
    whole dump of a configuration (``at`` empty). The loader's own record pairs
    mappings and lists only (``environment_references``), so a set member any
    file read has no reference of its own, whichever option holds it.
    ``resolve_config.load_config_file_for_run`` makes this walk, through
    ``resolve_config._take_destination_references``, at the end of every load,
    and the confinement steps make it again after they have run: a member the
    first walk described is one of ``described`` the second time, at the same
    place (the unknown index ends its path, and a set member has no other), so
    the second walk makes no reference for it.

    Each reference is shaped as ``environment_references`` shapes the one the
    loader makes for the same text at that place: ``written`` is the text the
    mark shows (``${VAR}`` or ``${VAR}tail``), ``resolved`` the string, ``value``
    the part the variable gave, ``key`` for a mapping key (its path is the
    mapping's), and for a list entry the ``length`` and ``index_at`` of the
    innermost list. A set member has no position: its path ends in the unknown
    index, so a walk reads the reference into the member by its shape at any
    position (``EnvironmentReference.position_unknown``).

    ``described`` are the references already at hand. A marked value or key is
    described when one of them is at its place and resolved to it as a whole:
    the place is compared with ``-`` and ``_`` folded in its keys and the case
    kept (``_case_kept_path``), a list index kept, so two keys that differ only
    in case are two places, as the display walk reads them. A string that a
    reference describes only in part is not described. The marks never leave
    this module in clear: a reference holds ``value``, as every one does, and
    is held in memory only.
    """
    from automated_security_helper.config.config_validator import _rewrite_for

    known = {
        (_case_kept_path(reference.path), reference.key, reference.resolved)
        for reference in described
    }
    found: List[EnvironmentReference] = []

    def make(
        path: Tuple[PathSegment, ...],
        text: Any,
        key: bool,
        innermost: Optional[Tuple[int, int]],
    ) -> None:
        resolved = str(text)
        if (_case_kept_path(path), key, resolved) in known:
            return
        written = str(text.shown)
        part = _rewrite_for("key" if key else "value", path, written, resolved)
        length, index_at = (None, None) if innermost is None or key else innermost
        reference = EnvironmentReference(
            path, written, resolved, part.environment_part, key, None, length, index_at
        )
        known.add((_case_kept_path(path), key, resolved))
        found.append(reference)

    def walk(
        node: Any, path: Tuple[PathSegment, ...], innermost: Optional[Tuple[int, int]]
    ) -> None:
        if isinstance(node, dict):
            for name, value in node.items():
                if _marked(name) and not sets_only:
                    make(path, name, True, innermost)
                walk(value, (*path, str(name)), innermost)
        elif isinstance(node, (list, tuple)):
            for index, value in enumerate(node):
                walk(value, (*path, index), (len(node), len(path)))
        elif isinstance(node, (set, frozenset)):
            for member in node:
                if _marked(member):
                    make((*path, _ANY_INDEX), member, False, None)
        elif _marked(node) and not sets_only:
            make(path, node, False, innermost)

    walk(data, tuple(at), None)
    return found


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
    renamed = _renamed_keys(
        names, _Index(references).keys.get(_normal_path(mapping), [])
    )
    return [renamed[name].written if name in renamed else name for name in names]
