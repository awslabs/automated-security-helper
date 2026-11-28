"""The model every support matrix is written in.

Why a model and not strings
---------------------------
Every table that says what ASH supports (which scanners, on which platforms, by which
install route) used to be typed by hand into the README and into several docs pages, and
the copies drifted. They are now rendered by ``scripts/generate_support_matrices.py``
from one typed ``Matrix`` per family, and this module is what makes a matrix mean
something: what a cell may say, which views a family must have, and which text no cell
may carry. A generator that accepted any string would only move the drift into the
generator, so every rule below refuses instead of repairing, and names what it refused.

The parts
---------
``Column``, ``Row`` and ``Matrix`` are plain frozen data that validate themselves when
they are built, so a collector cannot hand the generator a matrix that breaks a rule.

* Views. A column is in the README view, the docs view, or both, and a family has both:
  "a docs view and no README view, or the reverse, is refused", because every matrix is
  published in the README and in the docs. The check is on the views the family
  declares, not on the destinations written so far.
* A closed vocabulary of state phrases (``VOCABULARY``). A state cell is one of them, a
  value cell matches its column's own closed pattern, and a name cell is the row's key.
  A cell outside the set is refused, so "not measured" can never be spelled three ways.
* Plain cells. A cell is one line of text with no pipe, no angle bracket and no repeated
  space, so it renders the same in every markdown reader. Only a value cell may hold a
  code span.
* No license or provenance text. The register records both, and this model refuses
  them in any header, cell, note or intro: a matrix states what ASH supports, and a
  statement about a license is not one the generator may make.
* No unread ``ash`` command. Text that shows an ``ash`` command line must have read the
  spelling from the Typer app (``ash_command``), so a renamed command fails the generator
  instead of leaving a stale sentence between two markers.
* The README budget (``check_readme_budget``): at most six columns, and sixteen rows
  unless the block is a declared exception inside a collapsed element.

Per-platform refusals
---------------------
A scanner states that it cannot run on a platform in ``unsupported_platform_reason()``.
``platform_refusal`` asks it under ``mock.patch("platform.system", ...)``, so the answer
for Windows is the same on every host that renders the page. That is only sound while an
override reads the platform through ``platform.system()`` and nowhere else, so
``override_platform_reads`` finds every other read (``sys.platform``, ``os.name``,
``platform.uname()`` and the rest, through an alias or a name imported from those
modules), and a unit test requires none for every scanner the registry ships.

This module imports only the standard library, so the generator, the docs checks and a
unit test can all load it without ASH.
"""

from __future__ import annotations

import ast
import contextlib
import inspect
import re
import textwrap
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol
from unittest import mock

__all__ = [
    "DOCS",
    "KINDS",
    "NAME",
    "OS_NAMES",
    "README",
    "README_MAX_COLUMNS",
    "README_MAX_ROWS",
    "STATE",
    "VALUE",
    "VIEWS",
    "VOCABULARY",
    "Collector",
    "CollectContext",
    "Column",
    "Matrix",
    "ModelError",
    "Row",
    "SecondSource",
    "ash_command",
    "check_readme_budget",
    "forget_commands",
    "heading_slug",
    "isolated_commands",
    "override_platform_reads",
    "platform_reads",
    "platform_refusal",
    "read_commands",
    "refuse_unread_commands",
    "state_problem",
    "typer_command_exists",
]

README = "readme"
DOCS = "docs"
VIEWS = (README, DOCS)

NAME = "name"
STATE = "state"
VALUE = "value"
KINDS = (NAME, STATE, VALUE)


class ModelError(ValueError):
    """A matrix, a cell or a command spelling the model refuses; the message says why."""


# --- the closed vocabulary --------------------------------------------------------

#: The phrases a state cell may hold, as full-match patterns. A phrase with a hole
#: (``refused: <reason>``) has a pattern that accepts any plain reason. The list is
#: closed: a new phrase is an edit here, in the same change that renders it.
VOCABULARY: tuple[str, ...] = (
    r"yes",
    r"no",
    r"provisioned",
    r"no asset",
    r"refused: \S.*",
    r"off by default",
    r"package-defined \(not declared\)",
    r"not declared",
    r"not measured",
    r"tested on \S.*",
    r"not tested",
    r"declared, not tested",
    r"stub runtime: build and run calls checked",
    r"documented, not run in ASH's CI",
    r"missing: [a-z0-9][a-z0-9-]* \(needs [^()]+\)",
    r"loads only when its module is listed",
    r"no deployment recorded",
    r"static|glibc|musl|unread",
    r"in image",
    r"not in image: \S.*",
    r"hint only",
    r"needs \S.*",
)
_VOCABULARY = tuple(re.compile(pattern) for pattern in VOCABULARY)

#: What no header, cell, note or intro may state (a license, a provenance).
_LICENSE = re.compile(r"licen[cs]e|provenance", re.IGNORECASE)
#: A header with this word makes the docs checks read the table as a table of options.
_KEYED_HEADER = re.compile(r"\bdefaults?\b", re.IGNORECASE)
_KEY = re.compile(r"[a-z][a-z0-9_]*")
_ROW_KEY = re.compile(r"[a-z0-9][a-z0-9-]*")
_MATRIX_NAME = re.compile(r"[a-z][a-z0-9-]*")
_PAGE_PATH = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*")


def _plain_problem(text: object, *, code_span: bool) -> str | None:
    """Why ``text`` is not a plain one-line cell, or None."""
    if not isinstance(text, str):
        return f"{text!r} is not a string"
    if not text:
        return "the cell is empty"
    if text != " ".join(text.split()):
        return (
            f"{text!r} has a line break, a tab, a space at either end or two spaces in "
            "a row"
        )
    if "|" in text:
        return f"{text!r} holds a pipe, which ends a table cell"
    if "<" in text or ">" in text:
        return f"{text!r} holds an angle bracket, which a reader may take for a tag"
    if "`" in text and not code_span:
        return f"{text!r} holds a backtick; only a value cell may hold a code span"
    if _LICENSE.search(text):
        return f"{text!r} states a license or a provenance, which no matrix does"
    return None


def state_problem(text: object) -> str | None:
    """Why ``text`` is not a state cell (plain, and one of the closed phrases), or None."""
    problem = _plain_problem(text, code_span=False)
    if problem is not None:
        return problem
    # _plain_problem refused anything that is not a string, so this is the text itself.
    phrase = str(text)
    if any(pattern.fullmatch(phrase) for pattern in _VOCABULARY):
        return None
    return f"{phrase!r} is not one of the closed set of state phrases"


# --- columns, rows and matrices ---------------------------------------------------


@dataclass(frozen=True)
class Column:
    """One column: its key, its header, the views it is in and where its facts come from.

    ``kind`` says how a cell is judged: a ``NAME`` column holds the row's key, a
    ``STATE`` column holds one phrase of the closed vocabulary, and a ``VALUE`` column
    holds text that matches its own closed ``pattern``. ``source`` is the sentence the
    page prints under "Where each column comes from".
    """

    key: str
    header: str
    views: frozenset
    kind: str
    source: str
    pattern: str | None = None
    _regex: Any = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not _KEY.fullmatch(self.key):
            raise ModelError(f"column key {self.key!r} is not a lower-case name")
        if not isinstance(self.header, str) or not self.header.strip():
            raise ModelError(f"column {self.key!r} has no header")
        if "|" in self.header or "<" in self.header or "`" in self.header:
            raise ModelError(f"column {self.key!r}: the header holds markup")
        if self.header != " ".join(self.header.split()):
            raise ModelError(f"column {self.key!r}: the header has stray spaces")
        if _LICENSE.search(self.header):
            raise ModelError(
                f"column {self.key!r}: the header {self.header!r} states a license or "
                "a provenance, which no matrix does"
            )
        if _KEYED_HEADER.search(self.header):
            raise ModelError(
                f"column {self.key!r}: the header {self.header!r} has the word "
                "default, which makes the docs checks read the table as a table of "
                "options; name the fact another way"
            )
        views = frozenset(self.views)
        if not views or not views <= set(VIEWS):
            raise ModelError(
                f"column {self.key!r} names views {sorted(views)}, not a non-empty "
                f"subset of {list(VIEWS)}"
            )
        object.__setattr__(self, "views", views)
        if self.kind not in KINDS:
            raise ModelError(f"column {self.key!r} has kind {self.kind!r}, not {KINDS}")
        if not isinstance(self.source, str) or not self.source.strip():
            raise ModelError(f"column {self.key!r} names no source")
        if self.kind == VALUE:
            if not self.pattern:
                raise ModelError(f"value column {self.key!r} needs its own pattern")
            try:
                object.__setattr__(self, "_regex", re.compile(self.pattern))
            except re.error as error:
                raise ModelError(
                    f"column {self.key!r}: pattern {self.pattern!r} is not a regular "
                    f"expression ({error})"
                ) from None
        elif self.pattern is not None:
            raise ModelError(f"column {self.key!r}: only a value column has a pattern")

    def cell_problem(self, text: object) -> str | None:
        """Why ``text`` is not a cell of this column, or None."""
        if self.kind == STATE:
            return state_problem(text)
        problem = _plain_problem(text, code_span=self.kind == VALUE)
        if problem is not None:
            return problem
        # _plain_problem refused anything that is not a string.
        value = str(text)
        if self.kind == NAME:
            if not _ROW_KEY.fullmatch(value):
                return f"{value!r} is not a lower-case name"
            return None
        if not self._regex.fullmatch(value):
            return (
                f"{value!r} does not match the pattern {self.pattern!r} of the column"
            )
        return None


@dataclass(frozen=True, eq=False)
class Row:
    """One row: the key (the item's name), its cells by column key, and its links.

    ``anchor`` is the id the row's name gets on the support-matrix page (the key when
    None), and ``page`` is the repository-relative path of the item's own page when it
    has one.
    """

    key: str
    cells: Mapping[str, str]
    anchor: str | None = None
    page: str | None = None

    def __post_init__(self) -> None:
        if not _ROW_KEY.fullmatch(self.key):
            raise ModelError(f"row key {self.key!r} is not a lower-case name")
        object.__setattr__(self, "cells", MappingProxyType(dict(self.cells)))
        if self.anchor is not None and not _ROW_KEY.fullmatch(self.anchor):
            raise ModelError(f"row {self.key!r}: anchor {self.anchor!r} is not a name")
        if self.page is not None and (
            not _PAGE_PATH.fullmatch(self.page) or ".." in self.page.split("/")
        ):
            raise ModelError(
                f"row {self.key!r}: page {self.page!r} is not a repository-relative "
                "path with forward slashes and no '..'"
            )


def heading_slug(title: str) -> str:
    """The id a markdown heading of ``title`` gets: lower case, words joined by hyphens."""
    words = re.sub(r"[^a-z0-9\s-]", "", title.lower()).split()
    return "-".join(words)


@dataclass(frozen=True, eq=False)
class Matrix:
    """One support matrix: its columns, its rows, and the set of items it must cover.

    ``members`` is the enumeration the family's totality rests on (the manifests, the
    tiers, the platform pairs): the rows must be exactly that set, so an item added to
    the source and missing here fails when the matrix is built.
    """

    name: str
    title: str
    columns: tuple[Column, ...]
    rows: tuple[Row, ...]
    members: frozenset
    intro: str = ""
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _MATRIX_NAME.fullmatch(self.name):
            raise ModelError(f"matrix name {self.name!r} is not a lower-case name")
        if not isinstance(self.title, str) or heading_slug(self.title) != self.name:
            raise ModelError(
                f"matrix {self.name!r}: the heading {self.title!r} must become the id "
                f"{self.name!r}, so a link to the section holds"
            )
        columns, rows = tuple(self.columns), tuple(self.rows)
        object.__setattr__(self, "columns", columns)
        object.__setattr__(self, "rows", rows)
        object.__setattr__(self, "members", frozenset(self.members))
        object.__setattr__(self, "notes", tuple(self.notes))
        self._check_columns()
        self._check_rows()
        self._check_text()

    def _check_columns(self) -> None:
        keys = [column.key for column in self.columns]
        repeated = sorted({key for key in keys if keys.count(key) > 1})
        if repeated:
            raise ModelError(
                f"matrix {self.name!r} has two columns with the key {repeated[0]!r}"
            )
        names = [column for column in self.columns if column.kind == NAME]
        if len(names) != 1 or self.columns[0].kind != NAME:
            raise ModelError(
                f"matrix {self.name!r} needs exactly one name column, and it comes first"
            )
        seen = set().union(*(column.views for column in self.columns))
        for view in VIEWS:
            if view not in seen:
                have = [other for other in VIEWS if other in seen]
                raise ModelError(
                    f"matrix {self.name!r} declares no {view} view (it has "
                    f"{', '.join(have) or 'none'}): a family is published in the README "
                    "and in the docs, so it declares both"
                )
        if names[0].views != seen:
            raise ModelError(
                f"matrix {self.name!r}: the name column must carry every view the "
                "matrix has, or a view would list no names"
            )

    def _check_rows(self) -> None:
        keys = [row.key for row in self.rows]
        repeated = sorted({key for key in keys if keys.count(key) > 1})
        if repeated:
            raise ModelError(
                f"matrix {self.name!r} has two rows with the key {repeated[0]!r}"
            )
        if set(keys) != self.members:
            missing = sorted(self.members - set(keys))
            extra = sorted(set(keys) - self.members)
            raise ModelError(
                f"the rows of matrix {self.name!r} are not its members: no row for "
                f"{missing}, a row for {extra} that is not a member"
            )
        wanted = {column.key for column in self.columns}
        for row in self.rows:
            if set(row.cells) != wanted:
                raise ModelError(
                    f"matrix {self.name!r}, row {row.key!r}: its cells are "
                    f"{sorted(row.cells)}, not the columns {sorted(wanted)}"
                )
            for column in self.columns:
                text = row.cells[column.key]
                problem = column.cell_problem(text)
                if problem is None and column.kind == NAME and text != row.key:
                    problem = f"the name cell {text!r} is not the key of its row"
                if problem is None:
                    problem = _unread_problem(text, "the cell")
                if problem is not None:
                    raise ModelError(
                        f"matrix {self.name!r}, row {row.key!r}, column "
                        f"{column.key!r}: {problem}"
                    )

    def _check_text(self) -> None:
        texts = [("the intro", self.intro), ("the title", self.title)]
        texts += [(f"note {n}", note) for n, note in enumerate(self.notes, start=1)]
        texts += [(f"the source of column {c.key!r}", c.source) for c in self.columns]
        for where, text in texts:
            if not isinstance(text, str):
                raise ModelError(f"matrix {self.name!r}: {where} is not text")
            if _LICENSE.search(text):
                raise ModelError(
                    f"matrix {self.name!r}: {where} states a license or a "
                    "provenance, which no matrix does"
                )
            problem = _unread_problem(text, where)
            if problem is not None:
                raise ModelError(f"matrix {self.name!r}: {problem}")

    def columns_in(self, view: str) -> tuple[Column, ...]:
        """The columns a view shows, in column order."""
        if view not in VIEWS:
            raise ModelError(f"{view!r} is not a view; the views are {list(VIEWS)}")
        return tuple(column for column in self.columns if view in column.views)


# --- ash command text -------------------------------------------------------------

#: The spellings (``ash scan``) that were read from the CLI in this process.
_READ_COMMANDS: set[str] = set()
#: ``ash`` followed by a lower-case word, not part of a longer word, path or option.
_ASH_TEXT = re.compile(r"(?<![\w./-])ash(?= [a-z])")
_ASH_SPAN = re.compile(r"ash(?: [a-z][\w-]*){1,3}")
#: What may not follow a read spelling: more of a word, or another bare word that could
#: be a subcommand nobody read (``ash scan fs`` when only ``ash scan`` was read).
_CONTINUES = re.compile(r"[\w-]|\s+[a-z]")


def typer_command_exists(path: Sequence[str]) -> bool:
    """Whether the ``ash`` Typer app has the command at ``path`` (a tuple of words)."""
    import typer.main

    from automated_security_helper.cli.main import app

    command = typer.main.get_command(app)
    for word in path:
        children = getattr(command, "commands", None)
        if not children or word not in children:
            return False
        command = children[word]
    return True


def ash_command(
    path: Sequence[str], exists: Callable[[tuple[str, ...]], bool] | None = None
) -> str:
    """The spelling of the ``ash`` command at ``path``, after checking the CLI has it.

    ``ash_command(("scan",))`` is ``"ash scan"``. The spelling is registered, so text
    that shows it passes ``refuse_unread_commands``; a path that is no command raises.
    ``exists`` is how a test avoids loading ASH.
    """
    words = tuple(path)
    if not words:
        raise ModelError("an ash command path has at least one word")
    found = exists if exists is not None else typer_command_exists
    if not found(words):
        raise ModelError(f"`ash {' '.join(words)}` is not a command of the ash CLI")
    spelling = "ash " + " ".join(words)
    _READ_COMMANDS.add(spelling)
    return spelling


def read_commands() -> frozenset[str]:
    """The spellings read from the CLI so far."""
    return frozenset(_READ_COMMANDS)


def forget_commands() -> None:
    """Forget every spelling read (for a test or a self-test that plants its own)."""
    _READ_COMMANDS.clear()


@contextlib.contextmanager
def isolated_commands() -> Iterator[None]:
    """Run with no spelling read, and put the earlier ones back afterwards."""
    saved = set(_READ_COMMANDS)
    _READ_COMMANDS.clear()
    try:
        yield
    finally:
        _READ_COMMANDS.clear()
        _READ_COMMANDS.update(saved)


def _unread_problem(text: str, where: str) -> str | None:
    """Why ``text`` shows an ``ash`` command nobody read from the CLI, or None."""
    for match in _ASH_TEXT.finditer(text):
        rest = text[match.start() :]
        for spelling in sorted(_READ_COMMANDS, key=len, reverse=True):
            if rest.startswith(spelling) and not _CONTINUES.match(
                rest[len(spelling) :]
            ):
                break
        else:
            span = _ASH_SPAN.match(rest)
            shown = span.group(0) if span else "ash"
            return (
                f"{where} shows `{shown}`, command text that was not read from the "
                "CLI; read its spelling with ash_command() so a renamed command "
                "fails the generator"
            )
    return None


def refuse_unread_commands(text: str, where: str) -> None:
    """Raise ModelError when ``text`` shows ``ash`` command text nobody read from the CLI.

    ``where`` names the text for the message and starts it ("the intro", "note 2").
    """
    problem = _unread_problem(text, where)
    if problem is not None:
        raise ModelError(problem)


# --- the README budget ------------------------------------------------------------

README_MAX_COLUMNS = 6
README_MAX_ROWS = 16


def check_readme_budget(
    columns: int,
    rows: int,
    *,
    row_cap_exempt: bool = False,
    collapsed: bool = False,
    where: str = "a README block",
) -> None:
    """Refuse a README block with more than six columns, or sixteen rows.

    The row cap is waived only for a block declared exempt AND shown inside a collapsed
    element, the way the scanner table sits in a ``<details>`` today. ``collapsed`` is a
    declaration the generator cannot verify: the element is written by hand around the
    markers, so the registry states it and a reviewer reads it.
    """
    if columns > README_MAX_COLUMNS:
        raise ModelError(
            f"{where}: {columns} columns, over the README budget of {README_MAX_COLUMNS}"
        )
    if rows > README_MAX_ROWS and not (row_cap_exempt and collapsed):
        raise ModelError(
            f"{where}: {rows} rows, over the README budget of {README_MAX_ROWS}; only "
            "a block declared row_cap_exempt and collapsed may list more"
        )


# --- the refusal accessor and the check that makes it sound ----------------------

#: The three values ``platform.system()`` has on the platforms ASH supports.
OS_NAMES = ("Linux", "Darwin", "Windows")


def platform_refusal(instance: Any, os_name: str) -> str | None:
    """Why ``instance`` refuses to run on ``os_name``, or None when it does not.

    One accessor, so a later change that moves the refusals into declared data changes
    one function. It patches ``platform.system`` for the call, so the answer is the
    same on every host.
    """
    if os_name not in OS_NAMES:
        raise ModelError(f"{os_name!r} is not one of {list(OS_NAMES)}")
    with mock.patch("platform.system", return_value=os_name):
        return instance.unsupported_platform_reason()


_HOST_MODULES = frozenset({"sys", "os", "platform", "sysconfig"})
#: The attributes of each module (all of ``platform``'s except ``system()`` called)
#: that tell a program which host it runs on.
_HOST_ATTRIBUTES = {
    "sys": frozenset({"platform", "getwindowsversion", "getandroidapilevel", "winver"}),
    "os": frozenset(
        {"name", "uname", "sep", "linesep", "pathsep", "altsep", "devnull"}
    ),
    "sysconfig": frozenset({"get_platform"}),
}


def _host_imports(tree: ast.AST) -> tuple[dict[str, str], dict[str, str]]:
    """(local name -> module, local name -> ``module.attr``) for host-reading imports."""
    aliases: dict[str, str] = {}
    names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _HOST_MODULES:
                    aliases[alias.asname or alias.name] = alias.name
        elif (
            isinstance(node, ast.ImportFrom)
            and node.level == 0
            and node.module in _HOST_MODULES
        ):
            for alias in node.names:
                if node.module == "platform" or alias.name in _HOST_ATTRIBUTES.get(
                    node.module, ()
                ):
                    names[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases, names


def platform_reads(
    source: str,
    aliases: Mapping[str, str] | None = None,
    names: Mapping[str, str] | None = None,
) -> list[str]:
    """Every way ``source`` reads the host other than a call of ``platform.system()``.

    ``sys.platform``, ``os.name``, ``platform.uname()``, ``sysconfig.get_platform()``
    and the like, as a sorted list of dotted names. ``aliases`` maps a local name to the
    module it is (``import sys as _sys``) and ``names`` maps a local name to what it was
    imported as (``from sys import platform as host``): both come from the module the
    source sits in, and an import inside the source counts too. A name imported from
    ``platform`` counts even for ``system``, because ``mock.patch("platform.system")``
    cannot reach a name bound at import.

    A limit: it reads the spellings it knows. A read through ``getattr(sys,
    "platform")`` or through a function the override calls is not seen, so the
    override's own source is the thing a reviewer reads once more when one grows.
    """
    tree = ast.parse(textwrap.dedent(source))
    local_aliases, local_names = _host_imports(tree)
    modules = {name: name for name in _HOST_MODULES}
    modules.update(aliases or {})
    modules.update(local_aliases)
    bare = dict(names or {})
    bare.update(local_names)
    called = {id(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            module = modules.get(node.value.id)
            if module is None:
                continue
            if module == "platform":
                if node.attr == "system" and id(node) in called:
                    continue
                found.add(f"platform.{node.attr}")
            elif node.attr in _HOST_ATTRIBUTES.get(module, ()):
                found.add(f"{module}.{node.attr}")
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id in bare:
                found.add(bare[node.id])
    return sorted(found)


def override_platform_reads(cls: type) -> list[str]:
    """The host reads of ``cls.unsupported_platform_reason``, as ``platform_reads`` lists them."""
    function = inspect.unwrap(cls.unsupported_platform_reason)  # type: ignore[attr-defined]
    source = inspect.getsource(function)
    module = inspect.getmodule(function)
    aliases: dict[str, str] = {}
    names: dict[str, str] = {}
    if module is not None:
        aliases, names = _host_imports(ast.parse(inspect.getsource(module)))
    return platform_reads(source, aliases, names)


# --- what a collector hands the generator -----------------------------------------


@dataclass(frozen=True)
class CollectContext:
    """What a collector may read: the docs tree it is rendering for."""

    docs_root: Path


@dataclass(frozen=True)
class SecondSource:
    """An independent inventory of a matrix's members, to hold the rendered page to.

    The generator renders a matrix from the collector's own rows, so a row it dropped
    would be missing from the page and from the check that compares the page with the
    rows. ``names`` reads the same enumeration from somewhere else (the config models
    for the scanners), and the freshness gate compares the committed table's first
    column with it, ``header_cell`` naming that column.
    """

    label: str
    matrix: str
    header_cell: str
    names: Callable[[], Mapping[str, str]]


class Collector(Protocol):
    """One module of ``scripts/_matrix_<domain>.py`` exposes one of these as COLLECTOR."""

    name: str

    def collect(self, context: CollectContext) -> Sequence[Matrix]:
        """The matrices of this domain, built from the source of truth."""

    def second_sources(self) -> Sequence[SecondSource]:
        """The independent inventories that hold those matrices to account."""
