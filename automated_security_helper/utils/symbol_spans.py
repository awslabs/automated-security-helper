# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Resolve a suppression's ``symbol`` to the line spans that define it.

A suppression with ``symbol: MyClass.my_method`` covers a finding when the
finding's lines fall inside a definition with that qualified name in the
finding's file. A line-number suppression points at whatever sits on those lines
after an edit; a symbol suppression keeps pointing at the definition, wherever
it moves.

Spans come from a tree-sitter parse. The grammars are the optional ``symbols``
extra, and every way of not knowing a span fails closed: the suppression does
not match, the finding stays visible, and a warning names the cause. The causes
are a missing extra or grammar, a file extension with no grammar, a file that
cannot be read or lies outside the scan root, and a file that tree-sitter
cannot parse without errors. A partial tree is not trusted, because an error
node can swallow or truncate a definition and give it the wrong span.

The same parse yields the syntax-tree digests ``.ash.lock`` records
(``utils/ast_digest.py``): one read of a file gives its spans, the digest of the
whole file and the digest of each symbol a suppression is scoped to, so the
lines a finding must lie in and the bytes a lock entry covers come from the same
bytes. Analyses are cached by the bytes' SHA-256, never by a file's stat.

Qualified names
---------------

A qualified name is the chain of enclosing definition names from the top of the
file, joined with ``.``: ``Outer.Inner.method``, ``module_function``,
``outer_function.inner_function``. Only definitions contribute a segment.
Control flow and other blocks are transparent, so a function defined inside an
``if`` at module level is just ``name``. Names are exact and case-sensitive,
and there is no suffix matching: ``method`` alone names a top-level ``method``,
not ``Outer.method``. A definition's span contains every definition nested in
it, so ``Outer`` also covers findings inside ``Outer.Inner.method``.

When several definitions share a qualified name -- a Python property getter and
setter, ``typing.overload`` stubs, Java or TypeScript overloads, a function
redefined further down -- the name covers all of them.

A definition's span runs from its first line to its last. Decorators and Java
annotations are part of it, as is an ``export`` keyword in front of a JS/TS
declaration, so a finding reported on a decorator line is inside the symbol.
"""

from __future__ import annotations

import functools
import hashlib
import importlib
import importlib.metadata
import re
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Tuple

from automated_security_helper.core.constants import ASH_DOCS_URL
from automated_security_helper.utils import ash_lock as _ash_lock
from automated_security_helper.utils import ast_digest
from automated_security_helper.utils.ash_install import extra_install_command
from automated_security_helper.utils.ash_lock import (
    LOCK_RELATIVE_PATH,
    AshLock,
    file_is_gone,
    lock_key,
    stale_notice,
)
from automated_security_helper.utils.ast_digest import DigestUnavailable, Occurrence
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.undecodable_text import undecodable_of_text

#: The optional-dependency extra that provides tree-sitter and its grammars.
SYMBOLS_EXTRA = "symbols"


@functools.cache
def symbols_extra_install_command() -> str:
    """The command that installs the symbols extra's packages into ASH's environment.

    Used by the scan warning and by the config lint, so ``ash config lint`` and
    a scan never name different installs. The packages are read from the
    running distribution's metadata, so the command matches this ASH whatever
    its version or source.

    Built once per process. Reading the metadata walks every installed
    distribution (about 0.46 s with 205 of them), and the scan warning is built
    once per file a symbol suppression is checked against, under the index lock.
    The answer cannot change while the process runs.
    """
    # Names the extra's packages rather than ASH's distribution with the extra
    # (the earlier "install automated-security-helper[symbols]"): on PyPI that
    # name belongs to an unrelated project with no such extra, and a git tag
    # pinned to the version can lack the extra on a build between releases
    # (v3.7.0 has none).
    return extra_install_command(SYMBOLS_EXTRA)


#: The docs section with the uvx form of the install: the how-to page's own URL
#: (docs/content/how-to/suppress-findings.md renders there; the anchor is the
#: explicit ``{#installing-the-extra}`` on its heading). The earlier
#: ``/docs/suppressions/`` spelling reached the same section only through two
#: redirect hops.
SYMBOLS_EXTRA_DOCS_URL = (
    f"{ASH_DOCS_URL}/how-to/suppress-findings/#installing-the-extra"
)


def symbols_extra_install_hint() -> str:
    """The install advice the scan warning and the config lint both print.

    The command runs uv through the interpreter that runs ASH and installs into
    that interpreter's environment, which covers a virtualenv, a ``uv tool`` or
    ``pipx`` install and a checkout's ``uv sync`` environment. uvx rebuilds its
    cached environment from its own arguments, so for uvx the hint links the docs
    section that gives the uvx form instead.
    """
    return (
        f"install it with `{symbols_extra_install_command()}`, or for an ASH "
        f"run by uvx see {SYMBOLS_EXTRA_DOCS_URL}"
    )


#: One identifier. ``\w`` is Unicode-aware, so non-ASCII Python identifiers are
#: allowed; ``$`` covers JavaScript and ``#`` a JavaScript private member.
_SEGMENT = r"#?(?!\d)[\w$]+"
SYMBOL_PATTERN = re.compile(rf"^{_SEGMENT}(?:\.{_SEGMENT})*$")


def is_valid_symbol(symbol: str) -> bool:
    """Return True if ``symbol`` is a well-formed dotted qualified name.

    Matched whole: the pattern's ``$`` also matches before a trailing newline,
    so ``match`` accepted a symbol ending in one, which then matched no span.
    """
    return bool(SYMBOL_PATTERN.fullmatch(symbol))


@dataclass(frozen=True)
class SymbolGrammar:
    """How one tree-sitter grammar spells a named definition, and how its files
    are digested for ``.ash.lock``."""

    language: str
    """Display name, for messages."""
    module: str
    """Importable module that provides the grammar."""
    loader: str
    """Function in ``module`` that returns the grammar's language pointer."""
    definitions: frozenset[str]
    """Node types that define a symbol named by their ``name`` field."""
    member_definitions: Mapping[str, frozenset[str]] = field(default_factory=dict)
    """Node types that define a symbol only when their parent is one of these.

    JavaScript spells a class method and a method in an object literal the same
    way. Only the class method is addressable by a qualified name.
    """
    assigned_definitions: Mapping[str, Tuple[str, str]] = field(default_factory=dict)
    """Node type -> (name field, value field) for a binding that defines a
    function when its value is one of ``function_values``, like
    ``const handler = () => {}``."""
    function_values: frozenset[str] = frozenset()
    span_wrappers: frozenset[str] = frozenset()
    """Parent node types whose span counts as the definition's own."""
    leading_siblings: frozenset[str] = frozenset()
    """Node types that, placed right before a definition among its siblings,
    count as the definition's own lines.

    tree-sitter-typescript parses a class member's decorator as a sibling of the
    member inside ``class_body``, not as the member's child (Python's decorator is
    a ``decorated_definition`` parent, Java's annotation a ``modifiers`` child, and
    plain JavaScript's a field of the method), so a span that started at the
    member left its decorator line out. A comment between such a decorator and
    the definition does not end the run.
    """
    lock_id: str = ""
    """The grammar's name in a ``.ash.lock`` entry: ``python``, ``javascript``,
    ``typescript``, ``tsx`` or ``java``."""
    distribution: str = ""
    """The distribution that ships the grammar; a lock entry records its version."""
    verbatim: frozenset[str] = frozenset()
    """Node types a digest hashes as their exact text: string-like literals,
    whose bytes are their meaning (an f-string's spacing, a text block's
    indentation)."""
    skip: frozenset[str] = frozenset()
    """Node types a digest leaves out: Python's backslash line continuation,
    which joins two physical lines into the same logical line."""
    line_breaks: bool = False
    """Whether a digest records, for every token, if a line feed precedes it:
    in JavaScript and TypeScript a line break can change what code means."""
    prologue: str = ""
    """Which prelude rules apply: ``python`` (encoding declaration, ``#!``
    line, ``from __future__`` imports), ``ecmascript`` (``#!`` line and the
    leading comments and directives) or none."""


_PYTHON = SymbolGrammar(
    language="Python",
    module="tree_sitter_python",
    loader="language",
    definitions=frozenset({"class_definition", "function_definition"}),
    span_wrappers=frozenset({"decorated_definition"}),
    lock_id="python",
    distribution="tree-sitter-python",
    verbatim=frozenset({"string"}),
    skip=frozenset({"line_continuation"}),
    prologue="python",
)

_JS_FUNCTION_VALUES = frozenset(
    {"arrow_function", "function_expression", "generator_function", "class"}
)

_JAVASCRIPT = SymbolGrammar(
    language="JavaScript",
    module="tree_sitter_javascript",
    loader="language",
    definitions=frozenset(
        {"class_declaration", "function_declaration", "generator_function_declaration"}
    ),
    member_definitions={"method_definition": frozenset({"class_body"})},
    assigned_definitions={
        "variable_declarator": ("name", "value"),
        "field_definition": ("property", "value"),
    },
    function_values=_JS_FUNCTION_VALUES,
    span_wrappers=frozenset({"export_statement"}),
    lock_id="javascript",
    distribution="tree-sitter-javascript",
    verbatim=frozenset({"string", "template_string", "regex"}),
    line_breaks=True,
    prologue="ecmascript",
)

_TYPESCRIPT = SymbolGrammar(
    language="TypeScript",
    module="tree_sitter_typescript",
    loader="language_typescript",
    definitions=frozenset(
        {
            "abstract_class_declaration",
            "class_declaration",
            "enum_declaration",
            "function_declaration",
            "function_signature",
            "generator_function_declaration",
            "interface_declaration",
            "internal_module",
            "module",
            # A type alias contributes a segment, so a member of its type
            # literal is ``T.member``, not the enclosing scope's ``member``.
            "type_alias_declaration",
        }
    ),
    member_definitions={
        "abstract_method_signature": frozenset({"class_body"}),
        "method_definition": frozenset({"class_body"}),
        "method_signature": frozenset({"class_body", "interface_body", "object_type"}),
    },
    assigned_definitions={
        "variable_declarator": ("name", "value"),
        "public_field_definition": ("name", "value"),
    },
    function_values=_JS_FUNCTION_VALUES,
    span_wrappers=frozenset({"export_statement"}),
    leading_siblings=frozenset({"decorator"}),
    lock_id="typescript",
    distribution="tree-sitter-typescript",
    verbatim=frozenset({"string", "template_string", "template_literal_type", "regex"}),
    line_breaks=True,
    prologue="ecmascript",
)

_TSX = SymbolGrammar(
    language="TSX",
    module=_TYPESCRIPT.module,
    loader="language_tsx",
    definitions=_TYPESCRIPT.definitions,
    member_definitions=_TYPESCRIPT.member_definitions,
    assigned_definitions=_TYPESCRIPT.assigned_definitions,
    function_values=_TYPESCRIPT.function_values,
    span_wrappers=_TYPESCRIPT.span_wrappers,
    leading_siblings=_TYPESCRIPT.leading_siblings,
    lock_id="tsx",
    distribution=_TYPESCRIPT.distribution,
    verbatim=_TYPESCRIPT.verbatim,
    skip=_TYPESCRIPT.skip,
    line_breaks=_TYPESCRIPT.line_breaks,
    prologue=_TYPESCRIPT.prologue,
)

_JAVA = SymbolGrammar(
    language="Java",
    module="tree_sitter_java",
    loader="language",
    definitions=frozenset(
        {
            "annotation_type_declaration",
            "class_declaration",
            "compact_constructor_declaration",
            "constructor_declaration",
            "enum_declaration",
            "interface_declaration",
            "method_declaration",
            "record_declaration",
        }
    ),
    lock_id="java",
    distribution="tree-sitter-java",
    # Text blocks are string_literal nodes too; their indentation is meaning.
    verbatim=frozenset({"string_literal", "character_literal"}),
)

#: File extension (lower case) -> grammar. The only place a language is
#: selected; a file whose extension is not here fails closed.
GRAMMARS_BY_EXTENSION: Mapping[str, SymbolGrammar] = {
    ".py": _PYTHON,
    ".pyi": _PYTHON,
    ".js": _JAVASCRIPT,
    ".jsx": _JAVASCRIPT,
    ".mjs": _JAVASCRIPT,
    ".cjs": _JAVASCRIPT,
    ".ts": _TYPESCRIPT,
    ".mts": _TYPESCRIPT,
    ".cts": _TYPESCRIPT,
    ".tsx": _TSX,
    ".java": _JAVA,
}


def digest_grammars() -> List[SymbolGrammar]:
    """Each grammar once, by its lock id: the tables ``ast_digest.ALGORITHM``
    names and ``ast_digest.POLICY_SHA256`` pins."""
    unique = {g.lock_id: g for g in GRAMMARS_BY_EXTENSION.values()}
    return [unique[k] for k in sorted(unique)]


def grammar_for_path(file_path: str) -> Optional[SymbolGrammar]:
    """Return the grammar for ``file_path`` by extension, or None."""
    suffix = PurePosixPath(file_path.replace("\\", "/")).suffix.lower()
    return GRAMMARS_BY_EXTENSION.get(suffix)


class SymbolsUnavailableError(RuntimeError):
    """tree-sitter or a grammar module could not be imported."""


class SymbolParseError(ValueError):
    """tree-sitter parsed the file with errors, so its spans are not trusted."""


_language_cache: Dict[Tuple[str, str], Any] = {}
_language_lock = threading.Lock()


def _load_language(grammar: SymbolGrammar) -> Any:
    """Return the tree-sitter ``Language`` for ``grammar``.

    Raises SymbolsUnavailableError when tree-sitter or the grammar module is not
    installed, which is the missing-extra case, or when the installed binding's
    API is not the one this module calls (a TypeError from ``Language``), which
    is as much "no usable grammar" as a missing one and fails closed the same way.
    """
    key = (grammar.module, grammar.loader)
    with _language_lock:
        if key in _language_cache:
            return _language_cache[key]
        try:
            tree_sitter = importlib.import_module("tree_sitter")
            module = importlib.import_module(grammar.module)
            # The grammar's loader hands back the language pointer; py-tree-sitter
            # marks the int overload of Language() deprecated in favor of a
            # capsule, which the loaders here do not return.
            language = tree_sitter.Language(getattr(module, grammar.loader)())  # ty: ignore[deprecated]
        except (ImportError, AttributeError, TypeError, ValueError) as exc:
            raise SymbolsUnavailableError(f"{type(exc).__name__}: {exc}") from exc
        _language_cache[key] = language
        return language


def _new_parser(grammar: SymbolGrammar) -> Any:
    """A tree-sitter ``Parser`` for ``grammar``.

    Every import of tree-sitter goes through here or ``_load_language``, so a
    missing extra is always SymbolsUnavailableError and never an ImportError
    escaping into the suppression pass; a binding whose ``Parser`` takes other
    arguments (TypeError) is refused the same way.
    """
    language = _load_language(grammar)
    try:
        tree_sitter = importlib.import_module("tree_sitter")
        return tree_sitter.Parser(language)
    except (ImportError, AttributeError, TypeError) as exc:
        raise SymbolsUnavailableError(f"{type(exc).__name__}: {exc}") from exc


def _parse(source: bytes, grammar: SymbolGrammar) -> Any:
    """The one place a file is parsed: the tree of ``source``, the parse input
    (``_normalize_source``). Errors in the tree are the caller's to check."""
    return _new_parser(grammar).parse(source)


def _normalize_source(source: bytes) -> bytes:
    """Line endings to LF and a leading UTF-8 BOM dropped.

    tree-sitter counts rows at ``\\n`` only. CRLF already agrees with that, but a
    lone ``\\r`` is a line break to Python's tokenizer (and so to bandit) and not
    to tree-sitter, which would put every later definition on the wrong line.
    Neither change moves a line break, so rows still match the file.
    """
    if source.startswith(b"\xef\xbb\xbf"):
        source = source[3:]
    return _ash_lock.normalize_line_endings(source)


def _line_span(start_node: Any, node: Any) -> Tuple[int, int]:
    """1-based inclusive line span from ``start_node``'s start to ``node``'s end."""
    start_row = start_node.start_point[0]
    end_row, end_column = node.end_point
    # A node whose end is column 0 of a later row ends with the line break
    # before that row, so its last line is the one above.
    if end_column == 0 and end_row > start_row:
        end_row -= 1
    return start_row + 1, end_row + 1


def _definition_name(node: Any, grammar: SymbolGrammar) -> Optional[str]:
    """The symbol name ``node`` defines, or None if it defines none."""
    node_type = node.type
    name_node = None
    if node_type in grammar.definitions:
        name_node = node.child_by_field_name("name")
    elif node_type in grammar.member_definitions:
        parent = node.parent
        if parent is not None and parent.type in grammar.member_definitions[node_type]:
            name_node = node.child_by_field_name("name")
    elif node_type in grammar.assigned_definitions:
        name_field, value_field = grammar.assigned_definitions[node_type]
        value = node.child_by_field_name(value_field)
        if value is not None and value.type in grammar.function_values:
            name_node = node.child_by_field_name(name_field)
    if name_node is None or name_node.text is None:
        return None
    # A dotted name (TypeScript's ``namespace A.B {}``) contributes its segments,
    # so a member is ``A.B.member``. A name that is not identifiers -- a
    # string-named module (``module "x" {}``), a computed or string-keyed
    # method, a destructuring pattern -- cannot be written as a qualified name,
    # and neither can anything defined inside it: it is kept as a segment no
    # symbol can spell, so its members are not indexed under the enclosing scope
    # and a suppression for an enclosing name does not cover them by that name.
    # Bytes that are not UTF-8 decode to U+FFFD, which is not an identifier
    # character, so such a name never matches rather than matching by accident.
    name = name_node.text.decode("utf-8", errors="replace")
    if SYMBOL_PATTERN.fullmatch(name):
        return name
    return _UNSPELLABLE + name


#: Prefixed to a definition's name that no symbol can spell (``_definition_name``):
#: a character outside every identifier, so the qualified names under it match no
#: suppression.
_UNSPELLABLE = chr(0x00)


def _first_error_line(root: Any) -> int:
    """1-based line of the first ERROR or MISSING node under ``root``."""
    stack = [root]
    while stack:
        node = stack.pop()
        if node.is_error or node.is_missing:
            return node.start_point[0] + 1
        stack.extend(
            reversed([c for c in node.children if c.has_error or c.is_missing])
        )
    return root.start_point[0] + 1


def _parse_error(root: Any, grammar: SymbolGrammar) -> str:
    return (
        f"tree-sitter's {grammar.language} grammar reports a syntax error at "
        f"line {_first_error_line(root)}"
    )


def _definitions(
    root: Any, grammar: SymbolGrammar
) -> Iterator[Tuple[str, Any, Any, Tuple[Any, ...]]]:
    """Every definition under ``root``: its qualified name, its node, the node
    its span starts at and the definitions it sits in, outer to inner.

    The one walk both the spans (``index_symbols``) and the symbol digests read,
    so the lines a finding must lie in and the bytes a digest covers cannot
    drift apart. Iterative, so a deeply nested file cannot exhaust the
    recursion limit.
    """
    stack: List[Tuple[Any, Tuple[str, ...], Tuple[Any, ...]]] = [(root, (), ())]
    while stack:
        node, scope, enclosing = stack.pop()
        name = _definition_name(node, grammar)
        if name is not None:
            scope = (*scope, name)
            start = node
            while (
                start.parent is not None and start.parent.type in grammar.span_wrappers
            ):
                start = start.parent
            # A decorator the grammar places beside the definition, not inside it
            # (leading_siblings), begins the definition's own lines, and a comment
            # between the two does not end the run.
            decorators = ast_digest.leading_decorators(start, grammar.leading_siblings)
            if decorators:
                start = decorators[0]
            yield ".".join(scope), node, start, enclosing
            enclosing = (*enclosing, node)
        for child in reversed(node.children):
            if child.is_named:
                stack.append((child, scope, enclosing))


def _spans_of(root: Any, grammar: SymbolGrammar) -> Dict[str, List[Tuple[int, int]]]:
    spans: Dict[str, List[Tuple[int, int]]] = {}
    for name, node, start, _ in _definitions(root, grammar):
        spans.setdefault(name, []).append(_line_span(start, node))
    return spans


def index_symbols(
    source: bytes, grammar: SymbolGrammar
) -> Dict[str, List[Tuple[int, int]]]:
    """Map each qualified name defined in ``source`` to its line spans.

    Raises SymbolsUnavailableError if the grammar cannot be loaded and
    SymbolParseError if the parse tree contains an error.
    """
    tree = _parse(_normalize_source(source), grammar)
    root = tree.root_node
    if root.has_error:
        raise SymbolParseError(_parse_error(root, grammar))
    return _spans_of(root, grammar)


@dataclass(frozen=True)
class _Indexed:
    spans: Mapping[str, Tuple[Tuple[int, int], ...]]


@dataclass(frozen=True)
class _Unresolvable:
    reason: str


@dataclass(frozen=True)
class GrammarIdentity:
    """The grammar a digest was computed under, as a lock entry records it."""

    language: str
    """``SymbolGrammar.lock_id``."""
    fingerprint: str
    """``ast_digest.language_fingerprint`` of the loaded grammar."""
    distribution: str
    """The grammar's distribution and version, e.g. ``tree-sitter-python 0.25.0``."""
    tree_sitter: str
    """The tree-sitter binding's version."""


def _distribution_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


_identity_cache: Dict[Tuple[str, str], GrammarIdentity] = {}
_validated: Dict[Tuple[str, str], Optional[str]] = {}


def grammar_identity(grammar: SymbolGrammar) -> GrammarIdentity:
    """The identity of the running ``grammar``: its lock id, the fingerprint of
    its tables and the versions that shipped it. Raises SymbolsUnavailableError
    when the grammar cannot be loaded, or its binding does not expose the
    tables the fingerprint reads."""
    key = (grammar.module, grammar.loader)
    cached = _identity_cache.get(key)
    if cached is not None:
        return cached
    language = _load_language(grammar)
    try:
        fingerprint = ast_digest.language_fingerprint(language)
    except (AttributeError, TypeError, ValueError) as exc:
        raise SymbolsUnavailableError(f"{type(exc).__name__}: {exc}") from exc
    identity = GrammarIdentity(
        language=grammar.lock_id,
        fingerprint=fingerprint,
        distribution=(
            f"{grammar.distribution} {_distribution_version(grammar.distribution)}"
        ),
        tree_sitter=_distribution_version("tree-sitter"),
    )
    _identity_cache[key] = identity
    return identity


def _policy_problem(grammar: SymbolGrammar) -> Optional[str]:
    """Why the digest rules do not describe ``grammar``'s running tables, or
    None. Decided once per language per process."""
    key = (grammar.module, grammar.loader)
    if key in _validated:
        return _validated[key]
    problem: Optional[str] = None
    try:
        ast_digest.check_policy_pin(digest_grammars())
        ast_digest.validate_policy(_load_language(grammar), grammar)
    except DigestUnavailable as exc:
        problem = str(exc)
    except (AttributeError, TypeError) as exc:
        problem = (
            f"the {grammar.language} grammar's binding does not expose the "
            f"tables a digest reads ({type(exc).__name__}: {exc})"
        )
    _validated[key] = problem
    return problem


def _unavailable_reason(grammar: SymbolGrammar, exc: Exception) -> str:
    return (
        f"the {grammar.language} grammar is not available ({exc}). "
        f"Symbol suppressions need the optional '{SYMBOLS_EXTRA}' extra: "
        f"{symbols_extra_install_hint()}"
    )


class Analysis:
    """What one read of one file gives: its spans and its syntax-tree digests.

    A pure function of the raw bytes and the grammar. The spans are computed
    when the analysis is made; the file digest and each symbol digest when
    first asked for, from the same parse, and kept with it.
    """

    def __init__(
        self,
        raw: bytes,
        raw_sha256: str,
        grammar: Optional[SymbolGrammar],
        *,
        reason: Optional[str] = None,
        parse_error: Optional[str] = None,
        source: Optional[bytes] = None,
        tree: Any = None,
        spans: Optional[Mapping[str, Tuple[Tuple[int, int], ...]]] = None,
    ) -> None:
        self.raw = raw
        self.raw_sha256 = raw_sha256
        self.grammar = grammar
        #: Why the spans cannot be known, or None.
        self.reason = reason
        self._parse_error = parse_error
        self._source = source
        self._tree = tree
        self.spans = spans
        self._lock = threading.Lock()
        self._file_digest: Optional[str] = None
        self._symbol_digests: Dict[str, Optional[str]] = {}
        self._occurrences: Optional[Dict[str, List[Occurrence]]] = None
        self._starts: Optional[List[int]] = None

    @property
    def size(self) -> int:
        return len(self.raw)

    def indexed(self) -> Any:
        """The spans as ``_index_file`` answers them."""
        if self.spans is None:
            return _Unresolvable(self.reason or "the file's spans are unknown")
        return _Indexed(self.spans)

    def require_digestible(self) -> None:
        """Raise DigestUnavailable when no digest of this file can be computed:
        no grammar or extra, a parse error, digest rules that do not describe
        the running grammar, or an encoding declaration that cannot be read."""
        if self.grammar is None:
            raise DigestUnavailable(self.reason or "the file has no grammar")
        if self._parse_error is not None:
            raise DigestUnavailable(self._parse_error)
        if self._tree is None:
            raise DigestUnavailable(self.reason or "the file was not parsed")
        problem = _policy_problem(self.grammar)
        if problem is not None:
            raise DigestUnavailable(problem)
        if self.grammar.prologue == "python":
            ast_digest.python_encoding(self.raw)

    def identity(self) -> GrammarIdentity:
        """The identity of the grammar the digests are computed under."""
        if self.grammar is None:
            raise DigestUnavailable(self.reason or "the file has no grammar")
        try:
            return grammar_identity(self.grammar)
        except SymbolsUnavailableError as exc:
            raise DigestUnavailable(_unavailable_reason(self.grammar, exc)) from None

    def _parsed(self) -> Tuple[SymbolGrammar, bytes, Any]:
        """The grammar, parse input and tree a digest is computed from."""
        if self.grammar is None or self._source is None or self._tree is None:
            raise DigestUnavailable(self.reason or "the file was not parsed")
        return self.grammar, self._source, self._tree

    def file_digest(self) -> str:
        """The digest of the whole file (``ast_digest.file_digest``)."""
        self.require_digestible()
        identity = self.identity()
        grammar, source, tree = self._parsed()
        with self._lock:
            if self._file_digest is None:
                self._file_digest = ast_digest.file_digest(
                    self.raw,
                    source,
                    tree.root_node,
                    grammar,
                    identity.fingerprint,
                )
            return self._file_digest

    def symbol_digest(self, name: str) -> Optional[str]:
        """The digest of one qualified name, or None when the file defines none
        that bears it (``ast_digest.symbol_digest``)."""
        self.require_digestible()
        identity = self.identity()
        grammar, source, tree = self._parsed()
        with self._lock:
            if name in self._symbol_digests:
                return self._symbol_digests[name]
            root = tree.root_node
            if self._occurrences is None:
                found: Dict[str, List[Occurrence]] = {}
                for qualified, node, start, enclosing in _definitions(root, grammar):
                    found.setdefault(qualified, []).append(
                        Occurrence(
                            name=qualified,
                            node=node,
                            start=start,
                            enclosing=enclosing,
                            lines=_line_span(start, node),
                        )
                    )
                self._occurrences = found
            if self._starts is None:
                self._starts = ast_digest.line_starts(source)
            digest = ast_digest.symbol_digest(
                self.raw,
                source,
                root,
                grammar,
                identity.fingerprint,
                name,
                self._occurrences.get(name, ()),
                self._starts,
            )
            self._symbol_digests[name] = digest
            return digest


# Analyses, keyed by the SHA-256 of the bytes read and the grammar's lock id,
# never by stat: a same-size rewrite that keeps the mtime is another key.
# Module-level so a file is parsed once per content however many times
# suppressions are applied (once per scanner's SARIF and once more to the
# aggregate) and whoever asks (``ash suppress add`` and a scan in one process).
# An analysis keeps its tree for its digests, so the cache is bounded by count
# and by the source bytes it holds. Measured with the pinned grammars on five
# of this repository's largest Python files (945 KB of source), the cached
# analyses held 15 MB resident with their trees, about 16 times the source, so
# the byte bound keeps a long-lived process (the MCP server) near 130 MB at most.
_ANALYSIS_CACHE: "OrderedDict[Tuple[str, str], Analysis]" = OrderedDict()
_ANALYSIS_CACHE_MAX = 512
_ANALYSIS_CACHE_MAX_BYTES = 8 * 1024 * 1024
_ANALYSIS_BYTES = [0]
_INDEX_LOCK = threading.Lock()


def _cache(key: Tuple[str, str], analysis: Analysis) -> None:
    while _ANALYSIS_CACHE and (
        len(_ANALYSIS_CACHE) >= _ANALYSIS_CACHE_MAX
        or _ANALYSIS_BYTES[0] + analysis.size > _ANALYSIS_CACHE_MAX_BYTES
    ):
        _, evicted = _ANALYSIS_CACHE.popitem(last=False)
        _ANALYSIS_BYTES[0] -= evicted.size
    _ANALYSIS_CACHE[key] = analysis
    _ANALYSIS_BYTES[0] += analysis.size


def analyze(raw: bytes, file_name: str) -> Analysis:
    """The analysis of the bytes ``raw`` of a file named ``file_name``.

    Cached by the bytes' SHA-256 and the grammar. An analysis is cached only
    when it is the bytes' own: a parse, clean or not. A grammar that is not
    available and a file with no grammar are answered but not cached, since
    the first can change without the bytes changing (the extra installed).
    """
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    grammar = grammar_for_path(file_name)
    if grammar is None:
        return Analysis(raw, raw_sha256, None, reason=_unsupported_reason(file_name))
    key = (raw_sha256, grammar.lock_id)
    with _INDEX_LOCK:
        cached = _ANALYSIS_CACHE.get(key)
        if cached is not None:
            _ANALYSIS_CACHE.move_to_end(key)
            return cached
        source = _normalize_source(raw)
        try:
            tree = _parse(source, grammar)
        except SymbolsUnavailableError as exc:
            return Analysis(
                raw, raw_sha256, grammar, reason=_unavailable_reason(grammar, exc)
            )
        root = tree.root_node
        if root.has_error:
            error = _parse_error(root, grammar)
            analysis = Analysis(
                raw,
                raw_sha256,
                grammar,
                reason=f"the file does not parse cleanly: {error}",
                parse_error=error,
            )
        else:
            spans = _spans_of(root, grammar)
            analysis = Analysis(
                raw,
                raw_sha256,
                grammar,
                source=source,
                tree=tree,
                spans={k: tuple(v) for k, v in spans.items()},
            )
        _cache(key, analysis)
        return analysis


def _read_reason(exc: BaseException) -> str:
    return f"the file cannot be read ({type(exc).__name__}: {exc})"


def _index_file(path: Path) -> Any:
    """The spans of ``path``, from one read of it and the analysis cache.

    A read that fails is answered but not cached: a permission can be fixed
    without the file changing.
    """
    try:
        raw = _ash_lock.read_bounded(path)
    except (OSError, ValueError) as exc:
        return _Unresolvable(_read_reason(exc))
    return analyze(raw, path.name).indexed()


def _unsupported_reason(file_name: str) -> str:
    suffix = PurePosixPath(file_name).suffix.lower() or "(none)"
    supported = ", ".join(sorted(GRAMMARS_BY_EXTENSION))
    return (
        f"ASH has no symbol grammar for extension '{suffix}' (supported: {supported})"
    )


def clear_symbol_cache() -> None:
    """Drop every cached analysis. For tests.

    The lock notices a scan has printed are not kept here: they live on the
    scan's own context (``PluginContext.lock_notices``), so the next scan in
    the same process starts with none printed.
    """
    with _INDEX_LOCK:
        _ANALYSIS_CACHE.clear()
        _ANALYSIS_BYTES[0] = 0


class SymbolResolver:
    """Answers "is this finding inside that symbol?" for one scan root.

    Parses lazily, only for a file that a symbol suppression otherwise matches,
    and through a cache shared by every resolver, so each file is parsed at most
    once per content. Each distinct reason a file cannot be resolved is logged
    once per resolver at WARNING.
    """

    def __init__(
        self,
        source_dir: Path,
        lock: "Optional[AshLock]" = None,
        lock_error: Optional[str] = None,
        noticed: Optional[set[Any]] = None,
    ):
        self._source_dir = Path(source_dir).resolve()
        self._warned: set[Tuple[str, str]] = set()
        # The lock notices already printed in this scan: the scan's
        # PluginContext.lock_notices, shared by the resolver of every
        # suppression pass (each scanner's, then the merged one), so a stale
        # file or symbol is named once per scan. A resolver given none keeps its
        # own. Kept per process before, a long-lived process (the MCP server,
        # the express daemon) named a file once and then never again, though
        # later scans dropped its suppressions just the same.
        self._noticed: set[Any] = noticed if noticed is not None else set()
        # The scan root's ``.ash.lock``, or None to resolve spans with no lock
        # binding (the span resolver on its own). With a lock, a suppression
        # whose recorded scope is not current, or that was never recorded, gets
        # no match: it is inert and a notice says so once. ``lock_error`` is
        # the reason the lock could not be read: every symbol suppression is
        # then inert (fail closed), and the per-file notices do not run, since
        # "no entry; lock it with `ash suppress add`" would be false of a lock
        # that exists and is broken, and ``add`` would fail on the same broken
        # lock.
        self._lock = lock
        self._lock_error = lock_error
        # One read per file for the life of the resolver: the lock state and
        # the spans a finding is checked against come from the same bytes.
        self._files: Dict[str, Any] = {}
        self._scope_states: Dict[Tuple[str, str, str], str] = {}
        self._indexed: Dict[str, Any] = {}

    def contains(
        self,
        file_path: Optional[str],
        line_start: Optional[int],
        line_end: Optional[int],
        symbol: str,
        *,
        rule_id: Optional[str] = None,
    ) -> bool:
        """Return True if lines ``line_start``..``line_end`` of ``file_path``
        lie wholly inside a definition named ``symbol``.

        ``file_path`` is relative to the scan root, as suppressions match it.
        With a lock, the suppression's own recorded scope, ``(rule_id,
        symbol)``, must be current; a caller that passes no rule id asks for
        the rule-less scope, which only a rule-less suppression records.
        Returns False, never raises, whenever the span cannot be known.
        """
        if not file_path or line_start is None:
            return False
        end = line_end if line_end is not None else line_start
        if end < line_start:
            # A region that ends before it starts is no region: fail closed
            # rather than let its end alone put it inside a span.
            return False

        resolved = self._resolve(file_path)
        if resolved is None:
            self._warn(
                file_path,
                symbol,
                f"the file is outside the scan root '{self._source_dir.as_posix()}'",
            )
            return False

        if self._lock_error is not None:
            # The one warning for the broken lock was printed where it was
            # loaded (sarif_utils._symbol_resolver_for).
            return False

        if self._lock is not None:
            key = lock_key(resolved.relative_to(self._source_dir).as_posix())
            if key is None:
                return False
            # The lock is asked first. A file it does not hold and a scope it
            # does not record are decided from the lock alone, so such a file is
            # never opened: a FIFO or a device a finding names is not waited on.
            if not self._scope_is_current(self._lock, key, symbol, rule_id):
                return False
            locked = self._locked_file(key)
            if locked.raw is None:
                return False
            indexed = locked.analysis().indexed()
        else:
            indexed = self._indexed.get(str(resolved))
            if indexed is None:
                indexed = _index_file(resolved)
                self._indexed[str(resolved)] = indexed

        if isinstance(indexed, _Unresolvable):
            self._warn(file_path, symbol, indexed.reason)
            return False
        return any(
            first <= line_start and end <= last
            for first, last in indexed.spans.get(symbol, ())
        )

    def _locked_file(self, key: str) -> Any:
        locked = self._files.get(key)
        if locked is None:
            locked = _ash_lock.LockedFile.load(self._source_dir, key)
            self._files[key] = locked
        return locked

    def _notice(self, noticed: Tuple[Any, ...], message: str) -> None:
        if noticed in self._noticed:
            return
        self._noticed.add(noticed)
        ASH_LOGGER.warning(message, extra=NO_MARKUP)

    def _scope_is_current(
        self,
        lock: AshLock,
        key: str,
        symbol: str,
        rule_id: Optional[str],
    ) -> bool:
        """Whether the lock records the suppression's scope and it is current.

        Decided once per scope for the life of the resolver, from the one read
        of the file. The read is made only when the lock records the scope: a
        file with no entry, and a scope the entry does not record, are answered
        from the lock alone and the file is not opened. Each notice is printed
        once per scan (``noticed``): per file for a file-scope or version 1
        entry and for a file that cannot be read or checked, per symbol for a
        symbol-scope one, and per scope for a scope the lock never recorded.
        """
        wanted = (rule_id or "").casefold()
        memo = (key, wanted, symbol)
        state = self._scope_states.get(memo)
        if state is not None:
            return state == "ok"
        root = str(self._source_dir)
        entry = lock.entries.get(key)
        if entry is None:
            state = "unlocked"
            self._notice(
                (root, key, state),
                f"Symbol suppressions for '{key}' do not apply: the file has "
                f"no entry in {LOCK_RELATIVE_PATH}. Lock it with "
                f"`ash suppress add <rule-id> --symbol <name> --file {key} "
                "--reason <text>`.",
            )
        else:
            scope = _ash_lock.recorded_scope(entry, rule_id, symbol)
            if scope is None:
                state = "unrecorded"
                rule = rule_id or "(any rule)"
                self._notice(
                    (root, key, state, wanted, symbol),
                    f"Symbol suppression {rule} in {symbol} for '{key}' does "
                    f"not apply: {LOCK_RELATIVE_PATH} records no such scope for "
                    f"the file, so it was never reviewed. Record it with "
                    f"`{_ash_lock.add_command_for(rule_id, symbol, key)}`.",
                )
            else:
                checked = lock.scope_state(key, scope, self._locked_file(key))
                state = checked.state
                if state != "ok":
                    per_symbol = checked.per_symbol
                    noticed = (
                        (root, key, state, scope.symbol)
                        if per_symbol
                        else (root, key, state)
                    )
                    self._notice(
                        noticed,
                        stale_notice(
                            key,
                            entry,
                            state,
                            gone=file_is_gone(self._source_dir, key),
                            symbol=scope.symbol if per_symbol else None,
                            reason=checked.reason or None,
                            scopes=_ash_lock.scopes_of_problem(
                                entry, scope.symbol if per_symbol else None, checked
                            ),
                        ),
                    )
        self._scope_states[memo] = state
        return state == "ok"

    def _resolve(self, file_path: str) -> Optional[Path]:
        # Opened by the name the file has on disk: a finding holds a file name that
        # is not UTF-8 in its record form (\udcNN, utils/undecodable_text.py), read
        # back first. The path is taken as the finding wrote it: on Windows, Path
        # reads either separator; on POSIX a backslash is a character of a file
        # name, and rewriting it to "/" checked a suppression against a file other
        # than the finding's.
        if "\x00" in file_path:
            # No file name holds a NUL. Refused here explicitly: whether
            # Path.resolve() raises ValueError for an embedded NUL varies by
            # interpreter and platform (3.14 on Windows returns a path), and a
            # NUL-holding path must never read as inside the source dir.
            return None
        candidate = Path(undecodable_of_text(file_path))
        if not candidate.is_absolute():
            candidate = self._source_dir / candidate
        try:
            resolved = candidate.resolve()
        except (OSError, RuntimeError, ValueError):
            # ValueError: an embedded NUL, or a lone surrogate the file system's
            # encoding cannot hold (UnicodeEncodeError). Such a path names no
            # file, and contains() promises never to raise.
            return None
        if not resolved.is_relative_to(self._source_dir):
            return None
        return resolved

    def _warn(self, file_path: str, symbol: str, reason: str) -> None:
        key = (file_path, reason)
        if key in self._warned:
            return
        self._warned.add(key)
        ASH_LOGGER.warning(
            f"A suppression scoped to symbol '{symbol}' cannot be checked against "
            f"'{file_path}': {reason}. It does not match there, so findings in that "
            f"file stay visible.",
            extra=NO_MARKUP,
        )


def symbols_extra_available() -> bool:
    """Return True if tree-sitter and every grammar in the table import."""
    grammars: Iterable[SymbolGrammar] = {
        (g.module, g.loader): g for g in GRAMMARS_BY_EXTENSION.values()
    }.values()
    try:
        for grammar in grammars:
            _load_language(grammar)
    except SymbolsUnavailableError:
        return False
    return True
