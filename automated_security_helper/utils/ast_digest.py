# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Canonical syntax-tree digests: what ``.ash.lock`` records of a source file.

A digest is the SHA-256 of a stream of records produced by walking a
tree-sitter parse of the file. It changes when the code changes and does not
change when only the layout between tokens does, so a re-indented file keeps
its suppressions while an edited one does not.

What a digest hashes
--------------------

Every node's type, its named flag and the field it holds in its parent; every
token's text, named or anonymous (identifiers, keywords, operators,
punctuation, numbers); string-like literals as their exact text (``verbatim``,
because their bytes are their meaning); comments, which are tokens; and any
byte between nodes that is not layout. Layout is space, tab and line feed
(``LAYOUT``): form feed, vertical tab and every other byte count as content.

In JavaScript and TypeScript a line break can change what code means
(automatic semicolon insertion, restricted productions, TypeScript's rule that
a modifier before a line break is an identifier), so there every token also
carries one bit: whether a line feed precedes it. Python's logical lines are
statement structure in the tree, and Java gives line breaks no meaning.

The prelude
-----------

Some bytes change the meaning of a definition without touching its lines: a
UTF-8 byte order mark, a Python encoding declaration, a ``#!`` line, Python
``from __future__`` imports, and the leading comments and directives of a
JavaScript or TypeScript file (``"use strict"``, ``@jsx`` pragmas,
``// @ts-nocheck``). They form the prelude, which is part of the file digest
and of every symbol digest of the file.

The symbol digest
-----------------

A symbol-scoped suppression covers a finding whose lines lie inside one of the
symbol's spans, and a span is whole lines. So a symbol's digest covers every
token on the lines its spans cover (the line window), every definition that
bears the name, the headers of its enclosing definitions (decorators, name,
parameters, bases, modifiers) and the prelude. It does not cover imports other
than ``from __future__``, module constants, class attributes, other
definitions, callers, or the control flow around the definition.

This module is the standard library only. It never imports tree-sitter: it is
handed parse trees and ``Language`` objects by ``utils/symbol_spans.py``, which
owns the grammars and their tables.
"""

from __future__ import annotations

import hashlib
import io
import json
import struct
import tokenize
from dataclasses import dataclass
from typing import Any, Iterable, List, Optional, Sequence, Tuple

#: The id of the canonical form: the record format, ``LAYOUT``, the prelude and
#: the policy tables together. Recorded in every tree entry and part of every
#: preimage, so digests are never compared across two forms.
ALGORITHM = "ash-ast-1"

#: The bytes that are layout between tokens: space, tab and line feed.
LAYOUT = b" \t\n"

#: SHA-256 of the canonical rendering of the policy tables (``policy_sha256``).
#: ``check_policy_pin`` compares the running tables with it, so an edit to a
#: table that changes what a digest means fails until it comes with a new
#: ``ALGORITHM`` and this value.
POLICY_SHA256 = "1d386e9d12f2cae41ad65936787932953efadbfd6d41e2ac161f20fcf4e81539"

_BOM = b"\xef\xbb\xbf"
_LENGTH = struct.Struct(">I").pack
#: Bytes the walker gathers before it hands them to the hash.
_FLUSH_AT = 1 << 16


class DigestUnavailable(ValueError):
    """A file cannot be digested; ``str()`` says why."""


@dataclass(frozen=True)
class Occurrence:
    """One definition that bears a qualified name.

    ``node`` is the definition node, ``start`` the node its span starts at
    (an outer span wrapper, or a decorator the grammar places beside it),
    ``enclosing`` the definitions it sits in, outer to inner, and ``lines``
    its 1-based inclusive line span.
    """

    name: str
    node: Any
    start: Any
    enclosing: Tuple[Any, ...]
    lines: Tuple[int, int]


def _field(value: bytes) -> bytes:
    return _LENGTH(len(value)) + value


class _Walker:
    """Writes the records of one digest into one SHA-256.

    A record is a one-byte tag and its fields; a field is a 4-byte big-endian
    length and its bytes. ``(`` opens an interior node (named flag, type,
    field), ``)`` closes it, ``T`` is a token or a verbatim node (named flag,
    type, field, text, line-feed bit) and ``G`` a gap between nodes that holds
    a byte outside ``LAYOUT`` (the whole gap, then the line-feed bit).
    """

    __slots__ = (
        "_hash",
        "out",
        "source",
        "verbatim",
        "skip",
        "line_breaks",
        "last",
        "_names",
    )

    def __init__(self, source: bytes, policy: Any) -> None:
        self._hash = hashlib.sha256()
        self.out = bytearray()
        self.source = source
        self.verbatim = policy.verbatim
        self.skip = policy.skip
        self.line_breaks = policy.line_breaks
        # The end of the last T or G record, for the line-feed bit.
        self.last = 0
        self._names: dict = {}

    def raw(self, data: bytes) -> None:
        self.out += data

    def field(self, data: bytes) -> None:
        self.out += _LENGTH(len(data))
        self.out += data

    def hexdigest(self) -> str:
        self._hash.update(self.out)
        self.out.clear()
        return self._hash.hexdigest()

    def _flush(self) -> None:
        self._hash.update(self.out)
        self.out.clear()

    def _name(self, text: Optional[str]) -> bytes:
        if not text:
            return b""
        encoded = self._names.get(text)
        if encoded is None:
            encoded = text.encode("utf-8", "surrogatepass")
            self._names[text] = encoded
        return encoded

    def _lf(self, start: int, end: int) -> bytes:
        if not self.line_breaks:
            return b""
        bit = b"1" if self.source.find(b"\n", self.last, start) != -1 else b"0"
        self.last = end
        return bit

    def gap(self, start: int, end: int) -> None:
        if start >= end:
            return
        gap = self.source[start:end]
        if not gap.strip(LAYOUT):
            return
        out = self.out
        out += b"G"
        out += _LENGTH(len(gap))
        out += gap
        bit = self._lf(start, end)
        out += _LENGTH(len(bit))
        out += bit

    def stream(self, pairs: Sequence[Tuple[Any, str]]) -> None:
        """The records of sibling nodes in source order, given with their field
        names, and of the gaps between them."""
        if not pairs:
            return
        position = pairs[0][0].start_byte
        self.last = position
        for node, field_name in pairs:
            self.gap(position, node.start_byte)
            self.walk(node, field_name)
            position = node.end_byte

    def walk(self, node: Any, field_name: str) -> None:
        """The records of ``node`` and everything under it.

        A tree cursor walk, iterative, so a deeply nested file cannot exhaust
        the recursion limit; the cursor gives each node's field without a
        lookup per child. Children are named and anonymous nodes alike, extras
        (comments) included.
        """
        verbatim = self.verbatim
        skip = self.skip
        out = self.out
        name = self._name
        pack = _LENGTH
        source = self.source
        cursor = node.walk()
        # The end byte of each interior node whose ")" is still to come.
        ends: List[int] = []
        position = node.start_byte
        top = True
        while True:
            current = cursor.node
            node_field = field_name if top else cursor.field_name
            top = False
            start = current.start_byte
            if start > position:
                self.gap(position, start)
            node_type = current.type
            if node_type in skip:
                position = current.end_byte
            else:
                named = b"1" if current.is_named else b"0"
                type_bytes = name(node_type)
                field_bytes = name(node_field)
                if current.child_count == 0 or (
                    named == b"1" and node_type in verbatim
                ):
                    end = current.end_byte
                    text = source[start:end]
                    out += b"T"
                    out += pack(1)
                    out += named
                    out += pack(len(type_bytes))
                    out += type_bytes
                    out += pack(len(field_bytes))
                    out += field_bytes
                    out += pack(len(text))
                    out += text
                    bit = self._lf(start, end)
                    out += pack(len(bit))
                    out += bit
                    position = end
                else:
                    out += b"("
                    out += pack(1)
                    out += named
                    out += pack(len(type_bytes))
                    out += type_bytes
                    out += pack(len(field_bytes))
                    out += field_bytes
                    if len(out) >= _FLUSH_AT:
                        self._flush()
                    if cursor.goto_first_child():
                        ends.append(current.end_byte)
                        position = start
                        continue
                    # A node that reports children it does not give: its text
                    # is all there is, so it counts as a gap and is closed.
                    self.gap(start, current.end_byte)
                    out += b")"
                    position = current.end_byte
            # Next sibling, or close every parent that has none left.
            while True:
                if not ends:
                    return
                if cursor.goto_next_sibling():
                    break
                end = ends.pop()
                if end > position:
                    self.gap(position, end)
                out += b")"
                position = end
                cursor.goto_parent()


def _child_fields(parent: Any) -> List[Tuple[Any, str]]:
    field_for = parent.field_name_for_child
    return [(child, field_for(i) or "") for i, child in enumerate(parent.children)]


def _field_in_parent(node: Any) -> str:
    parent = node.parent
    if parent is None:
        return ""
    for index, child in enumerate(parent.children):
        if child.start_byte == node.start_byte and child == node:
            return parent.field_name_for_child(index) or ""
    return ""


def python_encoding(raw: bytes) -> str:
    """The encoding Python decodes ``raw`` with, as ``importlib`` finds it.

    ``utf-8-sig`` reads as ``utf-8``: the byte order mark is recorded on its
    own. Raises DigestUnavailable when the declaration cannot be read (an
    unknown encoding, or a byte order mark with a declaration that is not
    UTF-8).
    """
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
    except SyntaxError:
        raise DigestUnavailable("the encoding declaration cannot be read") from None
    return "utf-8" if encoding == "utf-8-sig" else encoding


def _is_directive(node: Any) -> bool:
    if node.type != "expression_statement" or node.named_child_count != 1:
        return False
    child = node.named_children[0]
    return child.type == "string"


def prologue_nodes(root: Any, policy: Any) -> List[Tuple[Any, str]]:
    """The prologue of a file, in source order: Python's top-level
    ``from __future__`` imports, or the leading run of ``#!`` line, comments
    and directive statements of a JavaScript or TypeScript program."""
    pairs = _child_fields(root)
    if policy.prologue == "python":
        return [(n, f) for n, f in pairs if n.type == "future_import_statement"]
    if policy.prologue == "ecmascript":
        run = []
        for node, field_name in pairs:
            if node.type in ("hash_bang_line", "comment") or _is_directive(node):
                run.append((node, field_name))
            else:
                break
        return run
    return []


def _prelude(walker: _Walker, raw: bytes, root: Any, policy: Any) -> None:
    source = walker.source
    walker.raw(b"P")
    walker.field(b"bom=1" if raw.startswith(_BOM) else b"bom=0")
    walker.field(
        python_encoding(raw).encode("ascii", "replace")
        if policy.prologue == "python"
        else b""
    )
    shebang = b""
    if policy.prologue in ("python", "ecmascript") and source.startswith(b"#!"):
        end = source.find(b"\n")
        shebang = source if end == -1 else source[:end]
    walker.field(shebang)
    nodes = prologue_nodes(root, policy)
    walker.field(str(len(nodes)).encode("ascii"))
    for node, field_name in nodes:
        walker.raw(b"[")
        walker.stream([(node, field_name)])
        walker.raw(b"]")


def _preimage_head(walker: _Walker, policy: Any, fingerprint: str, kind: bytes) -> None:
    walker.field(ALGORITHM.encode("ascii"))
    walker.field(policy.lock_id.encode("ascii"))
    walker.field(fingerprint.encode("ascii"))
    walker.field(kind)


def file_digest(
    raw: bytes, source: bytes, root: Any, policy: Any, fingerprint: str
) -> str:
    """The digest of a whole file.

    ``raw`` is the file's bytes as read, ``source`` the parse input (line
    endings to LF, a leading byte order mark dropped) and ``root`` the root of
    its clean parse. Bytes of ``source`` outside the root node count as gaps,
    so a form feed before the first token is content too.
    """
    walker = _Walker(source, policy)
    _preimage_head(walker, policy, fingerprint, b"file")
    _prelude(walker, raw, root, policy)
    walker.raw(b"F")
    walker.last = 0
    walker.gap(0, root.start_byte)
    walker.walk(root, "")
    walker.gap(root.end_byte, len(source))
    return walker.hexdigest()


def line_starts(source: bytes) -> List[int]:
    """The byte offset where each line of ``source`` starts."""
    starts = [0]
    position = source.find(b"\n")
    while position != -1:
        starts.append(position + 1)
        position = source.find(b"\n", position + 1)
    return starts


def _index_of(siblings: Sequence[Any], node: Any) -> int:
    for index, sibling in enumerate(siblings):
        if (
            sibling.start_byte == node.start_byte
            and sibling.end_byte == node.end_byte
            and sibling == node
        ):
            return index
    raise DigestUnavailable("a definition is not among its parent's children")


def _outermost_wrapper(node: Any, policy: Any) -> Any:
    top = node
    while top.parent is not None and top.parent.type in policy.span_wrappers:
        top = top.parent
    return top


def region(
    source: bytes, starts: Sequence[int], occurrence: Occurrence, policy: Any
) -> List[Tuple[Any, str]]:
    """The sibling run whose records cover every token on the occurrence's lines.

    Starts from the span's own nodes and takes in the siblings that reach its
    first line or start on its last; when bytes that are not layout still share
    those lines (another statement, a class header on a one-line class), it
    climbs to the parent and tries again, up to the whole file.
    """
    first_line, last_line = occurrence.lines
    window_start = starts[first_line - 1]
    window_end = starts[last_line] - 1 if last_line < len(starts) else len(source)
    first = occurrence.start
    last = _outermost_wrapper(occurrence.node, policy)
    while True:
        parent = first.parent
        if parent is None:
            return [(first, "")]
        siblings = parent.children
        i = _index_of(siblings, first)
        j = _index_of(siblings, last)
        while i > 0 and siblings[i - 1].end_byte > window_start:
            i -= 1
        while j + 1 < len(siblings) and siblings[j + 1].start_byte < window_end:
            j += 1
        residue = (
            source[window_start : siblings[i].start_byte]
            + source[siblings[j].end_byte : window_end]
        )
        if not residue.strip(LAYOUT):
            field_for = parent.field_name_for_child
            return [(siblings[k], field_for(k) or "") for k in range(i, j + 1)]
        first = last = parent


def _path_child(ancestor: Any, target: Any) -> Optional[Any]:
    """The child of ``ancestor`` on the path down to ``target``."""
    current = target
    while current is not None:
        parent = current.parent
        if parent is not None and parent == ancestor:
            return current
        current = parent
    return None


def _children_except(parent: Any, keep_out: Optional[Any]) -> List[Tuple[Any, str]]:
    pairs = _child_fields(parent)
    if keep_out is None:
        return pairs
    return [
        (node, field_name)
        for node, field_name in pairs
        if not (
            node.start_byte == keep_out.start_byte
            and node.end_byte == keep_out.end_byte
            and node == keep_out
        )
    ]


def header(enclosing: Any, target: Any, policy: Any) -> List[Tuple[Any, str]]:
    """The nodes of an enclosing definition's header, each streamed on its own.

    Its decorators the grammar places beside it; for each span wrapper from
    the outermost down, the wrapper's children other than the one on the path
    to the definition (Python decorators, ``export``, ``default``); the
    definition's children other than the one on the path to ``target`` (name,
    parameters, bases, heritage, modifiers, return type); and for an assigned
    definition entered through its function value, that value's children other
    than the one on the path (an arrow function's parameters and ``=>``).
    """
    nodes: List[Tuple[Any, str]] = []
    wrappers = []
    top = enclosing
    while top.parent is not None and top.parent.type in policy.span_wrappers:
        wrappers.append(top.parent)
        top = top.parent
    leading = []
    sibling = top.prev_named_sibling
    while sibling is not None and sibling.type in policy.leading_siblings:
        leading.append(sibling)
        sibling = sibling.prev_named_sibling
    for decorator in reversed(leading):
        nodes.append((decorator, _field_in_parent(decorator)))
    inner = enclosing
    chain = [enclosing, *wrappers]
    for wrapper in reversed(wrappers):
        below = chain[chain.index(wrapper) - 1]
        nodes.extend(_children_except(wrapper, below))
    path = _path_child(inner, target)
    nodes.extend(_children_except(inner, path))
    assigned = policy.assigned_definitions.get(inner.type)
    if assigned is not None and path is not None:
        value = inner.child_by_field_name(assigned[1])
        if (
            value is not None
            and value.type in policy.function_values
            and value.start_byte == path.start_byte
            and value == path
        ):
            nodes.extend(_children_except(value, _path_child(value, target)))
    return nodes


def symbol_digest(
    raw: bytes,
    source: bytes,
    root: Any,
    policy: Any,
    fingerprint: str,
    name: str,
    occurrences: Iterable[Occurrence],
    starts: Sequence[int],
) -> Optional[str]:
    """The digest of one qualified name, or None when no definition bears it.

    Covers, for every occurrence by start byte, the headers of its enclosing
    definitions and every token on its span's lines, plus the prelude.
    """
    found = sorted(occurrences, key=lambda o: (o.start.start_byte, o.node.start_byte))
    if not found or name.startswith("\x00"):
        return None
    walker = _Walker(source, policy)
    _preimage_head(walker, policy, fingerprint, b"symbol")
    walker.field(name.encode("utf-8", "surrogatepass"))
    _prelude(walker, raw, root, policy)
    walker.field(str(len(found)).encode("ascii"))
    for occurrence in found:
        walker.raw(b"O")
        for enclosing in occurrence.enclosing:
            walker.raw(b"H")
            for node, field_name in header(enclosing, occurrence.node, policy):
                walker.raw(b"[")
                walker.stream([(node, field_name)])
                walker.raw(b"]")
        walker.raw(b"|")
        walker.stream(region(source, starts, occurrence, policy))
    return walker.hexdigest()


def language_fingerprint(language: Any) -> str:
    """SHA-256 over a grammar's tables: its ABI version, parse state count,
    every node kind with its name and named and visible flags, and every
    field with its name.

    The same on every platform for one grammar build, and it exists for the
    grammars whose ``semantic_version`` is None. An attribute error from a
    binding without this API propagates; the caller treats it as a grammar
    that is not available.
    """
    digest = hashlib.sha256()

    def put(value: bytes) -> None:
        digest.update(_field(value))

    put(b"ash-grammar-fingerprint-1")
    put(str(language.abi_version).encode("ascii"))
    put(str(language.parse_state_count).encode("ascii"))
    kinds = language.node_kind_count
    put(str(kinds).encode("ascii"))
    for kind in range(kinds):
        kind_name = language.node_kind_for_id(kind)
        put(str(kind).encode("ascii"))
        put(
            b"-"
            if kind_name is None
            else b"=" + kind_name.encode("utf-8", "surrogatepass")
        )
        put(b"1" if language.node_kind_is_named(kind) else b"0")
        put(b"1" if language.node_kind_is_visible(kind) else b"0")
    fields = language.field_count
    put(str(fields).encode("ascii"))
    for field_id in range(1, fields + 1):
        field_name = language.field_name_for_id(field_id)
        put(str(field_id).encode("ascii"))
        put(
            b"-"
            if field_name is None
            else b"=" + field_name.encode("utf-8", "surrogatepass")
        )
    return digest.hexdigest()


def policy_node_types(policy: Any) -> List[str]:
    """Every node type a grammar's digest and definition tables name."""
    names = set(policy.verbatim) | set(policy.skip)
    if policy.prologue == "python":
        names.add("future_import_statement")
    elif policy.prologue == "ecmascript":
        names.update(("hash_bang_line", "comment", "expression_statement", "string"))
    names.update(policy.definitions)
    for node_type, parents in policy.member_definitions.items():
        names.add(node_type)
        names.update(parents)
    names.update(policy.assigned_definitions)
    names.update(policy.function_values)
    names.update(policy.span_wrappers)
    names.update(policy.leading_siblings)
    return sorted(names)


def validate_policy(language: Any, policy: Any) -> None:
    """Raise DigestUnavailable when a node type the tables name is not a named
    kind of the running grammar: the tables no longer describe it, so its files
    are not digested (fail closed)."""
    missing = [
        name
        for name in policy_node_types(policy)
        if not language.id_for_node_kind(name, True)
    ]
    if missing:
        raise DigestUnavailable(
            f"the running {policy.language} grammar has no node type "
            f"{', '.join(missing)}, which ASH's digest rules name, so its files "
            "cannot be digested"
        )


def policy_rendering(grammars: Iterable[Any]) -> bytes:
    """The canonical JSON of the policy tables: ``LAYOUT`` and, per grammar,
    every table a digest depends on."""
    tables = {}
    for grammar in grammars:
        tables[grammar.lock_id] = {
            "verbatim": sorted(grammar.verbatim),
            "skip": sorted(grammar.skip),
            "line_breaks": bool(grammar.line_breaks),
            "prologue": grammar.prologue,
            "definitions": sorted(grammar.definitions),
            "member_definitions": {
                k: sorted(v) for k, v in sorted(grammar.member_definitions.items())
            },
            "assigned_definitions": {
                k: list(v) for k, v in sorted(grammar.assigned_definitions.items())
            },
            "function_values": sorted(grammar.function_values),
            "span_wrappers": sorted(grammar.span_wrappers),
            "leading_siblings": sorted(grammar.leading_siblings),
        }
    document = {"algorithm": ALGORITHM, "layout": list(LAYOUT), "grammars": tables}
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")


def policy_sha256(grammars: Iterable[Any]) -> str:
    return hashlib.sha256(policy_rendering(grammars)).hexdigest()


def check_policy_pin(grammars: Iterable[Any]) -> None:
    """Raise DigestUnavailable when the running tables are not the ones
    ``ALGORITHM`` names (``POLICY_SHA256``)."""
    if policy_sha256(grammars) != POLICY_SHA256:
        raise DigestUnavailable(
            f"the digest tables differ from the ones {ALGORITHM} names, so no "
            "digest is computed until they come with a new algorithm id"
        )
