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
import importlib
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from automated_security_helper.core.constants import ASH_DOCS_URL
from automated_security_helper.utils.ash_install import extra_install_command
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


#: The docs section with the uvx form of the install.
SYMBOLS_EXTRA_DOCS_URL = f"{ASH_DOCS_URL}/docs/suppressions/#installing-the-extra"


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
    """How one tree-sitter grammar spells a named definition."""

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
    member left its decorator line out.
    """


_PYTHON = SymbolGrammar(
    language="Python",
    module="tree_sitter_python",
    loader="language",
    definitions=frozenset({"class_definition", "function_definition"}),
    span_wrappers=frozenset({"decorated_definition"}),
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
            language = tree_sitter.Language(getattr(module, grammar.loader)())
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


def _normalize_source(source: bytes) -> bytes:
    """Line endings to LF and a leading UTF-8 BOM dropped.

    tree-sitter counts rows at ``\\n`` only. CRLF already agrees with that, but a
    lone ``\\r`` is a line break to Python's tokenizer (and so to bandit) and not
    to tree-sitter, which would put every later definition on the wrong line.
    Neither change moves a line break, so rows still match the file.
    """
    if source.startswith(b"\xef\xbb\xbf"):
        source = source[3:]
    return source.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


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


def index_symbols(
    source: bytes, grammar: SymbolGrammar
) -> Dict[str, List[Tuple[int, int]]]:
    """Map each qualified name defined in ``source`` to its line spans.

    Raises SymbolsUnavailableError if the grammar cannot be loaded and
    SymbolParseError if the parse tree contains an error.
    """
    parser = _new_parser(grammar)
    tree = parser.parse(_normalize_source(source))
    root = tree.root_node
    if root.has_error:
        raise SymbolParseError(
            f"tree-sitter's {grammar.language} grammar reports a syntax error at "
            f"line {_first_error_line(root)}"
        )

    spans: Dict[str, List[Tuple[int, int]]] = {}
    # Iterative, so a deeply nested file cannot exhaust the recursion limit.
    stack: List[Tuple[Any, Tuple[str, ...]]] = [(root, ())]
    while stack:
        node, scope = stack.pop()
        name = _definition_name(node, grammar)
        if name is not None:
            scope = (*scope, name)
            start = node
            while (
                start.parent is not None and start.parent.type in grammar.span_wrappers
            ):
                start = start.parent
            # A decorator the grammar places beside the definition, not inside it
            # (leading_siblings), begins the definition's own lines.
            while (
                start.prev_named_sibling is not None
                and start.prev_named_sibling.type in grammar.leading_siblings
            ):
                start = start.prev_named_sibling
            spans.setdefault(".".join(scope), []).append(_line_span(start, node))
        for child in reversed(node.children):
            if child.is_named:
                stack.append((child, scope))
    return spans


@dataclass(frozen=True)
class _Indexed:
    spans: Mapping[str, Tuple[Tuple[int, int], ...]]


@dataclass(frozen=True)
class _Unresolvable:
    reason: str


# Parsed files, keyed by resolved path and the stat fields that change when the
# file does. Module-level so one scan parses a file once, however many times
# suppressions are applied: once per scanner's SARIF and once more to the
# aggregate. Bounded so a long-lived process (the MCP server) cannot grow it
# without limit.
_INDEX_CACHE: Dict[Tuple[str, int, int], Any] = {}
_INDEX_CACHE_MAX = 4096
_INDEX_LOCK = threading.Lock()


def _index_file(path: Path) -> Any:
    """The spans of ``path``, from the cache or a parse.

    A result is cached under the file's stat only when it is the file's own: a
    parse, clean or not, of bytes whose stat read the same before and after the
    read. A grammar that is not available and a file that cannot be read are
    answered but not cached, since both can change without the file changing
    (the extra installed, a permission fixed), and a file whose stat moved
    during the read is answered from the bytes read but not cached under the
    stat read first, which may be another content's.
    """
    try:
        stat = path.stat()
    except OSError as exc:
        return _Unresolvable(f"the file cannot be read ({type(exc).__name__}: {exc})")
    key = (str(path), stat.st_mtime_ns, stat.st_size)
    with _INDEX_LOCK:
        cached = _INDEX_CACHE.get(key)
        if cached is not None:
            return cached
        grammar = grammar_for_path(path.name)
        result: Any
        cacheable = True
        if grammar is None:
            result = _Unresolvable(_unsupported_reason(path.name))
        else:
            try:
                source = path.read_bytes()
                spans = index_symbols(source, grammar)
                result = _Indexed({k: tuple(v) for k, v in spans.items()})
            except SymbolsUnavailableError as exc:
                cacheable = False
                result = _Unresolvable(
                    f"the {grammar.language} grammar is not available ({exc}). "
                    f"Symbol suppressions need the optional '{SYMBOLS_EXTRA}' extra: "
                    f"{symbols_extra_install_hint()}"
                )
            except SymbolParseError as exc:
                result = _Unresolvable(f"the file does not parse cleanly: {exc}")
            except OSError as exc:
                cacheable = False
                result = _Unresolvable(
                    f"the file cannot be read ({type(exc).__name__}: {exc})"
                )
            if cacheable:
                try:
                    after = path.stat()
                except OSError:
                    cacheable = False
                else:
                    cacheable = (after.st_mtime_ns, after.st_size) == key[1:]
        if cacheable:
            if len(_INDEX_CACHE) >= _INDEX_CACHE_MAX:
                _INDEX_CACHE.clear()
            _INDEX_CACHE[key] = result
        return result


def _unsupported_reason(file_name: str) -> str:
    suffix = PurePosixPath(file_name).suffix.lower() or "(none)"
    supported = ", ".join(sorted(GRAMMARS_BY_EXTENSION))
    return (
        f"ASH has no symbol grammar for extension '{suffix}' (supported: {supported})"
    )


def clear_symbol_cache() -> None:
    """Drop every cached parse. For tests."""
    with _INDEX_LOCK:
        _INDEX_CACHE.clear()


class SymbolResolver:
    """Answers "is this finding inside that symbol?" for one scan root.

    Parses lazily, only for a file that a symbol suppression otherwise matches,
    and through a cache shared by every resolver, so each file is parsed at most
    once while it is unchanged. Each distinct reason a file cannot be resolved is
    logged once per resolver at WARNING.
    """

    def __init__(self, source_dir: Path):
        self._source_dir = Path(source_dir).resolve()
        self._warned: set[Tuple[str, str]] = set()

    def contains(
        self,
        file_path: Optional[str],
        line_start: Optional[int],
        line_end: Optional[int],
        symbol: str,
    ) -> bool:
        """Return True if lines ``line_start``..``line_end`` of ``file_path``
        lie wholly inside a definition named ``symbol``.

        ``file_path`` is relative to the scan root, as suppressions match it.
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

        indexed = _index_file(resolved)
        if isinstance(indexed, _Unresolvable):
            self._warn(file_path, symbol, indexed.reason)
            return False
        return any(
            first <= line_start and end <= last
            for first, last in indexed.spans.get(symbol, ())
        )

    def _resolve(self, file_path: str) -> Optional[Path]:
        # Opened by the name the file has on disk: a finding holds a file name that
        # is not UTF-8 in its record form (\udcNN, utils/undecodable_text.py), read
        # back first. The path is taken as the finding wrote it: on Windows, Path
        # reads either separator; on POSIX a backslash is a character of a file
        # name, and rewriting it to "/" checked a suppression against a file other
        # than the finding's.
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
