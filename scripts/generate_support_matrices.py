#!/usr/bin/env python3
"""Generate the support matrices: docs/content/reference/support-matrix.md and the
generated blocks of the pages a person writes.

Usage:
    uv run python scripts/generate_support_matrices.py            # write every page and block
    uv run python scripts/generate_support_matrices.py --check    # exit 1 with a diff if stale
    uv run python scripts/generate_support_matrices.py --self-test

Why one generator for every matrix
----------------------------------
The README and several docs pages each used to state which scanners, modes, channels
and platforms ASH supports, in their own words, and the statements drifted. A support
matrix is now a typed ``Matrix`` (``scripts/_support_model.py``) that a collector module
builds from the code, and this script renders it twice: whole, in
``docs/content/reference/support-matrix.md``, and in part, in the blocks of hand-written
pages that name it.

A collector is a module ``scripts/_matrix_<domain>.py`` that exposes ``COLLECTOR`` (a
``name``, ``collect(context)`` and ``second_sources()``); this script finds every such
module and names no scanner, mode or channel itself, so a new matrix is one new file and
one new line in ``scripts/_matrix_destinations.py``. That file is data: the pages this
script writes whole (``PAGES``) and the blocks it fills in other pages (``BLOCKS``).

What a run does
---------------
* Collects every matrix, refusing two collectors that return one name.
* Renders each page, and each block's body, as a list of lines. A block lands between
  its markers with the generated-blocks library (``scripts/_generated_blocks.py``),
  which refuses a missing, repeated, nested or misspelled marker, an orphan block, a
  body holding a placeholder, and a file it cannot read as LF text.
* Writes a page whole and a block in place. A refusal comes before any write: a file
  the registry names that cannot take its block leaves every other file as it was.
* With ``--check``, writes nothing: it prints each page that differs with a diff, and
  each block that differs with the diff the library computed, and exits 1.
* ``--output FILE`` is for the one whole page: it writes (or with ``--check``,
  compares) that page at FILE and leaves every block alone. ``--output -`` prints it.

The second source
-----------------
The page is rendered from the same rows a matrix holds, so a renderer that dropped a row
would drop it from the page and from ``--check`` alike. ``second_source_failures`` holds
the committed page to an inventory each collector reads from somewhere else, as the
docs-freshness gate does for the scanner and reporter pages, so a dropped row is red.

``--self-test`` plants the defects this script exists to refuse (a cell outside the
vocabulary, a family with one view, ``ash`` text nobody read from the CLI, a collector
module with no collector, a hand edit inside a block, a deleted end marker, a block
nobody registered) and requires each to be refused, then renders a clean tree and
requires it to pass. It reads no ASH, so it runs anywhere the script does.

Limits
------
* ``--output`` skips the blocks, so a block can drift while that flag is the only run.
* A README block's ``collapsed`` flag is a declaration: the element around the markers
  is written by hand, and nothing here checks that it is there.
* The second source reads the committed page, not README blocks: a row filter makes a
  block a subset, and the same renderer writes both.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import importlib.util
import posixpath
import re
import sys
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import _support_model
from _generated_blocks import (
    TEMPLATE_SUFFIX,
    WRITTEN,
    MarkerError,
    check_blocks,
    write_blocks,
)
from _reference_docs import (
    add_docs_root_argument,
    banner,
    code,
    generated_note,
    md_cell,
    prepare_environment,
    refuse_check_to_stdout,
    write_or_check,
)
from _support_model import (
    DOCS,
    NAME,
    README,
    STATE,
    VALUE,
    VIEWS,
    CollectContext,
    Column,
    Matrix,
    ModelError,
    Row,
    check_readme_budget,
    heading_slug,
)

GENERATOR = "scripts/generate_support_matrices.py"
DESTINATIONS_MODULE = "_matrix_destinations"

_PAGE_KEYS = ("file", "title", "source", "intro", "sections")
_BLOCK_KEYS = ("file", "block", "matrix", "view")
_BLOCK_OPTIONAL_KEYS = ("rows", "row_cap_exempt", "collapsed")
_ANCHOR = re.compile(r'<a id="[^"]*"></a>')


# --- the destinations ---------------------------------------------------------------


def _check_file(where: str, file: object) -> None:
    if not isinstance(file, str) or not file:
        raise ModelError(f"{where}: file {file!r} is not a path")
    parts = file.split("/")
    if file.startswith("/") or ".." in parts or "" in parts or "\\" in file:
        raise ModelError(
            f"{where}: file {file!r} is not a repository-relative path with forward "
            "slashes and no '..'"
        )


@dataclass(frozen=True, eq=False)
class Destinations:
    """Where the matrices are written: whole pages and blocks of other pages.

    ``pages`` and ``blocks`` hold the entries of ``scripts/_matrix_destinations.py``
    (see its docstring for their keys). They are checked when this is built, so a
    registry with a typo in a key fails before anything is rendered.
    """

    pages: tuple[Mapping, ...]
    blocks: tuple[Mapping, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "pages", tuple(self.pages))
        object.__setattr__(self, "blocks", tuple(self.blocks))
        for number, page in enumerate(self.pages, start=1):
            where = f"PAGES entry {number}"
            self._keys(where, page, _PAGE_KEYS, ())
            _check_file(where, page["file"])
            if not all(isinstance(page[key], str) for key in _PAGE_KEYS[:4]):
                raise ModelError(f"{where}: file, title, source and intro are text")
            sections = page["sections"]
            if not isinstance(sections, (tuple, list)) or not all(
                isinstance(name, str) for name in sections
            ):
                raise ModelError(f"{where}: sections is not a tuple of matrix names")
        for number, block in enumerate(self.blocks, start=1):
            where = f"BLOCKS entry {number}"
            self._keys(where, block, _BLOCK_KEYS, _BLOCK_OPTIONAL_KEYS)
            _check_file(where, block["file"])
            if not all(isinstance(block[key], str) for key in _BLOCK_KEYS):
                raise ModelError(f"{where}: file, block, matrix and view are text")
            if block["view"] not in VIEWS:
                raise ModelError(
                    f"{where}: view {block['view']!r} is not one of {list(VIEWS)}"
                )
            rows = block.get("rows")
            if rows is not None and not (
                isinstance(rows, Mapping)
                and all(
                    isinstance(k, str) and isinstance(v, str) for k, v in rows.items()
                )
            ):
                raise ModelError(
                    f"{where}: rows maps column keys to the one value shown"
                )
            for flag in ("row_cap_exempt", "collapsed"):
                if flag in block and not isinstance(block[flag], bool):
                    raise ModelError(f"{where}: {flag} is true or false")
        seen = set()
        for block in self.blocks:
            ident = (block["file"].removesuffix(TEMPLATE_SUFFIX), block["block"])
            if ident in seen:
                raise ModelError(
                    f"the registry lists block {block['block']!r} twice for {ident[0]}"
                )
            seen.add(ident)

    @staticmethod
    def _keys(where: str, entry: object, required: tuple, optional: tuple) -> None:
        if not isinstance(entry, Mapping):
            raise ModelError(f"{where} is not a mapping")
        missing = [key for key in required if key not in entry]
        unknown = sorted(set(entry) - set(required) - set(optional))
        if missing or unknown:
            raise ModelError(
                f"{where}: missing keys {missing}, unknown keys {unknown}; the keys "
                f"are {list(required + optional)}"
            )


def load_destinations(directory: Path) -> Destinations:
    """The registry in ``directory/_matrix_destinations.py``, read as data.

    The file is parsed with ``ast`` and each of ``PAGES`` and ``BLOCKS`` read with
    ``ast.literal_eval``; nothing in it runs, so a registry that is only data stays
    data and a statement that is not an assignment of a literal cannot do anything.
    """
    import ast

    path = Path(directory) / f"{DESTINATIONS_MODULE}.py"
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), path.name)
    except (OSError, SyntaxError, UnicodeDecodeError) as error:
        raise ModelError(f"{path.name} cannot be read: {error}") from error
    values: dict[str, object] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id in ("PAGES", "BLOCKS"):
            if target.id in values:
                raise ModelError(f"{path.name} assigns {target.id} more than once")
            try:
                values[target.id] = ast.literal_eval(node.value)
            except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                raise ModelError(
                    f"{path.name}: {target.id} is not a literal, so it cannot be read "
                    "without running the file"
                ) from None
    for name in ("PAGES", "BLOCKS"):
        value = values.get(name)
        if not isinstance(value, (tuple, list)):
            raise ModelError(f"{path.name} does not assign {name} a tuple of entries")
    return Destinations(pages=tuple(values["PAGES"]), blocks=tuple(values["BLOCKS"]))


# --- the collectors -----------------------------------------------------------------


def _load_collector_module(path: Path):
    """``path`` as a module under a name of its own, so two runs never share a cache."""
    digest = hashlib.sha256(str(path.resolve()).encode()).hexdigest()[:10]
    name = f"_ash_matrix_collector_{path.stem}_{digest}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ModelError(f"{path.name}: cannot be loaded as a module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    folder = str(path.parent)
    added = folder not in sys.path
    if added:
        sys.path.insert(0, folder)
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        del sys.modules[name]
        raise ModelError(
            f"{path.name}: cannot be imported ({type(error).__name__}: {error})"
        ) from error
    finally:
        if added:
            sys.path.remove(folder)
    return module


def discover_collectors(directory: Path) -> list:
    """The ``COLLECTOR`` of every ``_matrix_*.py`` in ``directory``, in file order.

    The registry (``_matrix_destinations.py``) is data and is skipped. A module with no
    ``COLLECTOR``, or one that lacks what a collector offers, is refused by name: a
    module that was added to hold a matrix and holds none would otherwise publish
    nothing, and nothing would say so.
    """
    collectors = []
    for path in sorted(Path(directory).glob("_matrix_*.py")):
        if path.stem == DESTINATIONS_MODULE:
            continue
        module = _load_collector_module(path)
        collector = getattr(module, "COLLECTOR", None)
        if collector is None:
            raise ModelError(
                f"{path.name} has no COLLECTOR object; a _matrix_<domain>.py module "
                "exposes one (see Collector in scripts/_support_model.py)"
            )
        if not (
            isinstance(getattr(collector, "name", None), str)
            and callable(getattr(collector, "collect", None))
            and callable(getattr(collector, "second_sources", None))
        ):
            raise ModelError(
                f"{path.name}: its COLLECTOR has no name, collect() or second_sources()"
            )
        collectors.append(collector)
    return collectors


def collect_matrices(
    collectors: Sequence, context: CollectContext
) -> dict[str, Matrix]:
    """Every matrix the collectors return, by name; two with one name are refused."""
    matrices: dict[str, Matrix] = {}
    owners: dict[str, str] = {}
    for collector in collectors:
        for matrix in collector.collect(context):
            if not isinstance(matrix, Matrix):
                raise ModelError(
                    f"collector {collector.name!r} returned a {type(matrix).__name__}, "
                    "not a Matrix"
                )
            if matrix.name in matrices:
                raise ModelError(
                    f"collectors {owners[matrix.name]!r} and {collector.name!r} both "
                    f"return a matrix named {matrix.name!r}"
                )
            matrices[matrix.name] = matrix
            owners[matrix.name] = collector.name
    return matrices


# --- rendering ----------------------------------------------------------------------


@dataclass(frozen=True)
class Target:
    """The file a table lands in, so its links are right for that file.

    ``file`` and ``support_page`` are repository-relative paths. ``anchors`` is true
    only on the support-matrix page itself, where each row's name carries the id a link
    from another page points at.
    """

    file: str
    support_page: str
    anchors: bool = False


@dataclass(frozen=True, eq=False)
class Rendering:
    """What a run would write: each page whole, and each block's lines by file."""

    pages: Mapping[str, str]
    blocks: Mapping[str, Mapping[str, list[str]]]


def _relative(from_file: str, path: str) -> str:
    """``path`` as a link from the directory of ``from_file``, both repository-relative."""
    start = "/" + posixpath.dirname(from_file)
    return posixpath.relpath("/" + path, start)


def _name_cell(row: Row, view: str, target: Target) -> str:
    anchor = row.anchor or row.key
    label = code(row.key)
    if view == README:
        return f"[{label}]({_relative(target.file, target.support_page)}#{anchor})"
    if row.page is not None:
        link = f"[{label}]({_relative(target.file, row.page)})"
    elif target.anchors:
        link = label
    else:
        link = f"[{label}]({_relative(target.file, target.support_page)}#{anchor})"
    return f'<a id="{anchor}"></a>{link}' if target.anchors else link


def _select_rows(matrix: Matrix, rows: Mapping[str, str] | None) -> list[Row]:
    """The rows of ``matrix`` a block shows: all, or those whose cells equal ``rows``."""
    if not rows:
        return list(matrix.rows)
    keys = {column.key for column in matrix.columns}
    for key in rows:
        if key not in keys:
            raise ModelError(
                f"the row filter names the column {key!r}, which matrix "
                f"{matrix.name!r} does not have (its columns are {sorted(keys)})"
            )
    chosen = [
        row
        for row in matrix.rows
        if all(row.cells[key] == value for key, value in rows.items())
    ]
    if not chosen:
        raise ModelError(
            f"the row filter {dict(rows)} shows no row of matrix {matrix.name!r}"
        )
    return chosen


def render_table(
    matrix: Matrix, view: str, target: Target, rows: Mapping[str, str] | None = None
) -> list[str]:
    """The markdown table of ``matrix`` in ``view``, as lines, for the file ``target``."""
    columns = matrix.columns_in(view)
    lines = [
        "| " + " | ".join(column.header for column in columns) + " |",
        "|" + "|".join("-" * (len(column.header) + 2) for column in columns) + "|",
    ]
    for row in _select_rows(matrix, rows):
        cells = [
            _name_cell(row, view, target)
            if column.kind == NAME
            else md_cell(row.cells[column.key])
            for column in columns
        ]
        lines.append("| " + " | ".join(cells) + " |")
    return lines


def _matrix_named(matrices: Mapping[str, Matrix], name: str, why: str) -> Matrix:
    try:
        return matrices[name]
    except KeyError:
        raise ModelError(
            f"{why}, but no collector returned a matrix named {name!r} "
            f"(the matrices are {sorted(matrices)})"
        ) from None


def render_page(spec: Mapping, matrices: Mapping[str, Matrix]) -> str:
    """The whole support-matrix page ``spec`` describes: banner, intro, one section each."""
    target = Target(file=spec["file"], support_page=spec["file"], anchors=True)
    lines = banner(GENERATOR, spec["source"])
    lines += [f"# {spec['title']}", "", generated_note(GENERATOR, spec["source"]), ""]
    if spec["intro"]:
        lines += [spec["intro"], ""]
    for name in spec["sections"]:
        matrix = _matrix_named(
            matrices, name, f"the page {spec['file']} has a section for {name!r}"
        )
        lines += [f"## {matrix.title}", ""]
        if matrix.intro:
            lines += [matrix.intro, ""]
        lines += [*render_table(matrix, DOCS, target), ""]
        for note in matrix.notes:
            lines += [note, ""]
        lines += ["Where each column comes from:", ""]
        lines += [
            f"- {code(column.header)}: {column.source}"
            for column in matrix.columns_in(DOCS)
        ]
        lines.append("")
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines) + "\n"


def _block_body(
    entry: Mapping, matrix: Matrix, target: Target, support_page: str
) -> list[str]:
    view = entry["view"]
    table = render_table(matrix, view, target, entry.get("rows"))
    if view != README:
        return table
    check_readme_budget(
        len(matrix.columns_in(README)),
        len(table) - 2,
        row_cap_exempt=bool(entry.get("row_cap_exempt")),
        collapsed=bool(entry.get("collapsed")),
        where=f"the README view of block {entry['block']!r} in {entry['file']}",
    )
    link = f"{_relative(target.file, support_page)}#{matrix.name}"
    return [*table, "", f"The full table is on the [support matrix page]({link})."]


def render_all(matrices: Mapping[str, Matrix], registry: Destinations) -> Rendering:
    """Every page and block body the registry asks for, each checked as it is built."""
    pages: dict[str, str] = {}
    page_of: dict[str, str] = {}
    for spec in registry.pages:
        pages[spec["file"]] = render_page(spec, matrices)
        for name in spec["sections"]:
            page_of.setdefault(name, spec["file"])
    blocks: dict[str, dict[str, list[str]]] = {}
    for entry in registry.blocks:
        name = entry["matrix"]
        matrix = _matrix_named(
            matrices,
            name,
            f"block {entry['block']!r} of {entry['file']} renders {name!r}",
        )
        if name not in page_of:
            raise ModelError(
                f"block {entry['block']!r} of {entry['file']} renders {name!r}, which "
                "no page of the registry holds, so its README footer has no page to "
                "link the full table to"
            )
        target = Target(
            file=entry["file"].removesuffix(TEMPLATE_SUFFIX), support_page=page_of[name]
        )
        blocks.setdefault(entry["file"], {})[entry["block"]] = _block_body(
            entry, matrix, target, page_of[name]
        )
    return Rendering(pages=pages, blocks=blocks)


# --- writing and checking -----------------------------------------------------------


def _refuse_before_writing(root: Path, rendering: Rendering) -> None:
    """Raise MarkerError for any file that cannot take its blocks, before any write.

    ``check_blocks`` refuses what ``write_blocks`` would refuse, except an orphan block,
    which it reports as drift; an orphan is a refusal here, as it is when writing.
    """
    for file, bodies in sorted(rendering.blocks.items()):
        for drift in check_blocks(root, file, bodies, GENERATOR):
            if drift.orphan:
                raise MarkerError(
                    drift.file,
                    drift.block,
                    f"the begin marker names {GENERATOR}, but the registry in "
                    f"scripts/{DESTINATIONS_MODULE}.py gives it no body: register it, "
                    "or delete its markers",
                )


def _write_page(path: Path, text: str) -> bool:
    current = path.read_text(encoding="utf-8") if path.exists() else None
    if current == text:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return True


def write_all(root: Path, rendering: Rendering) -> list[str]:
    """Write every block and page under ``root``; the files that changed, as given.

    A refusal (MarkerError) comes before the first write, so a registry that names a
    file that cannot take its block changes nothing.
    """
    root = Path(root)
    _refuse_before_writing(root, rendering)
    written: list[str] = []
    for file, bodies in sorted(rendering.blocks.items()):
        written += [
            result.file
            for result in write_blocks(root, file, bodies, GENERATOR)
            if result.status == WRITTEN
        ]
    for file, text in sorted(rendering.pages.items()):
        if _write_page(root / file, text):
            written.append(file)
    return written


def _page_diff(file: str, current: str, text: str) -> str:
    return "".join(
        difflib.unified_diff(
            current.splitlines(keepends=True),
            text.splitlines(keepends=True),
            fromfile=f"{file} (on disk)",
            tofile=f"{file} (regenerated)",
            n=2,
        )
    )


def check_all(root: Path, rendering: Rendering) -> list[str]:
    """What differs between ``rendering`` and the files under ``root``, one entry each.

    Every entry names the file, and a block's or a page's difference as a diff. Nothing
    is written. A block the library refuses (a marker lost or misspelled) is an entry
    too, with the library's message.
    """
    root = Path(root)
    failures: list[str] = []
    for file, bodies in sorted(rendering.blocks.items()):
        try:
            drifts = check_blocks(root, file, bodies, GENERATOR)
        except MarkerError as error:
            failures.append(str(error))
            continue
        for drift in drifts:
            what = (
                f"is generated by {GENERATOR} but the registry gives it no body"
                if drift.orphan
                else f"differs from what {GENERATOR} renders"
            )
            failures.append(f"{drift.file}: block `{drift.block}` {what}\n{drift.diff}")
    for file, text in sorted(rendering.pages.items()):
        path = root / file
        if not path.exists():
            failures.append(
                f"{file} does not exist.\nRegenerate with: uv run python {GENERATOR}"
            )
        elif path.read_text(encoding="utf-8") != text:
            failures.append(
                f"{file} is stale relative to the matrices it renders.\n"
                f"Regenerate with: uv run python {GENERATOR}\n\n"
                + _page_diff(file, path.read_text(encoding="utf-8"), text)
            )
    return failures


def _summary(
    rendering: Rendering, matrices: Mapping[str, Matrix], started: float
) -> str:
    rows = sum(len(matrix.rows) for matrix in matrices.values())
    blocks = sum(len(bodies) for bodies in rendering.blocks.values())
    return (
        f"{len(rendering.pages)} pages and {blocks} blocks from {len(matrices)} "
        f"matrices and {rows} rows, in {time.monotonic() - started:.1f} s."
    )


def run(
    root: Path,
    matrices: Mapping[str, Matrix],
    registry: Destinations,
    *,
    check: bool = False,
    started: float | None = None,
) -> int:
    """Render ``matrices`` into the registry's pages and blocks under ``root``.

    Returns the exit code: 0 when written or current, 1 when ``check`` found a
    difference or a file refused its block. ``started`` is the ``time.monotonic()`` the
    caller began at, for the elapsed time in the summary.
    """
    started = time.monotonic() if started is None else started
    rendering = render_all(matrices, registry)
    if check:
        failures = check_all(root, rendering)
        for failure in failures:
            print(failure, file=sys.stderr)
        if failures:
            print(
                f"{len(failures)} files are stale or refused; regenerate with: "
                f"uv run python {GENERATOR}",
                file=sys.stderr,
            )
            return 1
        print(f"Up to date: {_summary(rendering, matrices, started)}", file=sys.stderr)
        return 0
    try:
        written = write_all(root, rendering)
    except MarkerError as error:
        print(f"{GENERATOR}: refused, nothing written: {error}", file=sys.stderr)
        return 1
    for file in written:
        print(f"Wrote {file}.", file=sys.stderr)
    print(
        f"{len(written)} files written: {_summary(rendering, matrices, started)}",
        file=sys.stderr,
    )
    return 0


# --- the second source --------------------------------------------------------------


def _section_text(text: str, matrix_name: str) -> str | None:
    """The part of a page under the ``##`` heading whose id is ``matrix_name``."""
    lines = text.split("\n")
    start = None
    for index, line in enumerate(lines):
        if not line.startswith("## "):
            continue
        if start is not None:
            return "\n".join(lines[start:index])
        if heading_slug(line[3:]) == matrix_name:
            start = index
    return None if start is None else "\n".join(lines[start:])


def second_source_failures(
    root: Path,
    compare_inventories: Callable[..., list[str]],
    *,
    collectors: Sequence | None = None,
    destinations: Destinations | None = None,
) -> list[str]:
    """Hold each committed page to the independent inventory of the matrix it renders.

    For every second source of every collector, the table of that matrix in the page
    that holds it is compared, both ways, with the names the source reads from
    elsewhere. ``compare_inventories`` is the docs-freshness gate's comparison, passed
    in so this module does not import the gate. A source whose matrix no page renders,
    and a page or a section that is missing, are failures: a comparison that finds
    nothing to compare must not read as agreement.
    """
    root = Path(root)
    collectors = discover_collectors(_SCRIPTS) if collectors is None else collectors
    registry = load_destinations(_SCRIPTS) if destinations is None else destinations
    failures: list[str] = []
    for collector in collectors:
        for source in collector.second_sources():
            pages = [
                spec for spec in registry.pages if source.matrix in spec["sections"]
            ]
            if not pages:
                failures.append(
                    f"{source.label}: no page of the destination registry renders the "
                    f"matrix {source.matrix!r}, so its second source compares nothing"
                )
            names = dict(source.names()) if pages else {}
            for spec in pages:
                path = root / spec["file"]
                if not path.is_file():
                    failures.append(f"{source.label}: {spec['file']} does not exist")
                    continue
                section = _section_text(path.read_text(encoding="utf-8"), source.matrix)
                if section is None:
                    failures.append(
                        f"{source.label}: {spec['file']} has no section for the matrix "
                        f"{source.matrix!r}"
                    )
                    continue
                failures += compare_inventories(
                    source.label,
                    names,
                    _ANCHOR.sub("", section),
                    source.header_cell,
                    spec["file"],
                )
    return failures


# --- the self-test ------------------------------------------------------------------


class _Tally:
    """What the self-test saw: failures, planted defects refused, controls accepted."""

    def __init__(self) -> None:
        self.failures: list[str] = []
        self.refused = 0
        self.accepted = 0

    def refuses(self, label: str, action: Callable[[], object], errors=(ModelError,)):
        try:
            action()
        except errors:
            self.refused += 1
        except Exception as error:
            self.failures.append(
                f"{label}: raised {type(error).__name__}, not a refusal ({error})"
            )
        else:
            self.failures.append(f"{label}: was accepted")

    def accepts(self, label: str, action: Callable[[], object]) -> None:
        try:
            action()
        except Exception as error:
            self.failures.append(f"{label}: the control was refused ({error})")
        else:
            self.accepted += 1


def _planted_matrix(
    *,
    views: frozenset | None = None,
    cell: str = "yes",
    intro: str = "A planted table.",
) -> Matrix:
    both = frozenset({README, DOCS})
    shown = views or both
    columns = (
        Column("thing", "Thing", shown, NAME, "The planted names."),
        Column("works", "Works on Linux", shown, STATE, "The planted answers."),
        Column("size", "Size", shown, VALUE, "The planted sizes.", pattern="big|small"),
    )
    rows = tuple(
        Row(key=name, cells={"thing": name, "works": cell, "size": "big"})
        for name in ("alpha", "beta")
    )
    return Matrix(
        name="things",
        title="Things",
        columns=columns,
        rows=rows,
        members=frozenset({"alpha", "beta"}),
        intro=intro,
    )


_PLANTED_README = (
    "# Project\n\n"
    f"<!-- BEGIN generated: support/things.readme ({GENERATOR}) -->\nstale\n"
    "<!-- END generated: support/things.readme -->\n\nThe end.\n"
)
_PLANTED_GUIDE = (
    "# Guide\n\n"
    f"<!-- BEGIN generated: support/things.docs ({GENERATOR}) -->\nstale\n"
    "<!-- END generated: support/things.docs -->\n\nThe end.\n"
)
_PLANTED_REGISTRY = Destinations(
    pages=(
        {
            "file": "docs/support.md",
            "title": "Support",
            "source": "the planted matrices",
            "intro": "How to read a cell.",
            "sections": ("things",),
        },
    ),
    blocks=(
        {
            "file": "README.md.template",
            "block": "support/things.readme",
            "matrix": "things",
            "view": "readme",
        },
        {
            "file": "docs/guide.md",
            "block": "support/things.docs",
            "matrix": "things",
            "view": "docs",
        },
    ),
)


def _plant_tree(root: Path) -> None:
    for file, text in (
        ("README.md.template", _PLANTED_README),
        ("README.md", _PLANTED_README),
        ("docs/guide.md", _PLANTED_GUIDE),
    ):
        path = root / file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def _self_test_model(tally: _Tally) -> None:
    """The model refuses what it exists to refuse, and accepts the controls."""
    tally.accepts("a valid planted matrix", _planted_matrix)
    tally.refuses(
        "the vocabulary refuses 'mostly' in a state cell",
        lambda: _planted_matrix(cell="mostly"),
    )
    for only, missing in ((DOCS, README), (README, DOCS)):
        tally.refuses(
            f"a family with a {only} view and no {missing} view",
            lambda only=only: _planted_matrix(views=frozenset({only})),
        )
    tally.refuses(
        "a column headed with the word default",
        lambda: Column("on", "On by default", frozenset({DOCS}), STATE, "x"),
    )
    tally.refuses(
        "a column headed with a license",
        lambda: Column("terms", "License", frozenset({DOCS}), STATE, "x"),
    )
    tally.refuses(
        "the README budget of 7 columns", lambda: check_readme_budget(7, 3, where="x")
    )
    tally.refuses(
        "the README budget of 17 rows", lambda: check_readme_budget(3, 17, where="x")
    )
    tally.accepts(
        "an exempt, collapsed README block of 17 rows",
        lambda: check_readme_budget(
            3, 17, row_cap_exempt=True, collapsed=True, where="x"
        ),
    )
    with _support_model.isolated_commands():
        tally.refuses(
            "ash command text nobody read from the CLI",
            lambda: _planted_matrix(intro="Run ash scan."),
        )
        _support_model.ash_command(("scan",), exists=lambda path: True)
        tally.accepts(
            "ash command text that was read",
            lambda: _planted_matrix(intro="Run ash scan."),
        )
        tally.refuses(
            "ash command text that goes on past the command that was read",
            lambda: _planted_matrix(intro="Run ash scan fs."),
        )


def _self_test_collectors(tally: _Tally) -> None:
    with tempfile.TemporaryDirectory(prefix="ash-matrix-self-test-") as folder:
        directory = Path(folder)
        (directory / "_matrix_empty.py").write_text("VALUE = 1\n", encoding="utf-8")
        tally.refuses(
            "a collector module with no COLLECTOR",
            lambda: discover_collectors(directory),
        )
        (directory / "_matrix_empty.py").unlink()
        (directory / "_matrix_fine.py").write_text(
            "class _C:\n    name = 'fine'\n"
            "    def collect(self, context):\n        return []\n"
            "    def second_sources(self):\n        return []\n"
            "COLLECTOR = _C()\n",
            encoding="utf-8",
        )
        tally.accepts(
            "a collector module with a COLLECTOR",
            lambda: discover_collectors(directory),
        )


def _self_test_blocks(tally: _Tally) -> None:
    """A planted tree: a clean write checks clean, and each defect is caught."""
    matrices = {"things": _planted_matrix()}
    try:
        rendering = render_all(matrices, _PLANTED_REGISTRY)
    except ModelError as error:
        tally.failures.append(f"the planted registry could not be rendered ({error})")
        return
    with tempfile.TemporaryDirectory(prefix="ash-matrix-self-test-") as folder:
        root = Path(folder)
        _plant_tree(root)
        tally.accepts("writing the planted tree", lambda: write_all(root, rendering))
        clean = check_all(root, rendering)
        if clean:
            tally.failures.append(f"a freshly written tree is stale: {clean[0]}")
        else:
            tally.accepted += 1
        guide = root / "docs" / "guide.md"
        written = guide.read_text(encoding="utf-8")
        guide.write_text(written.replace("| yes |", "| edited |", 1), encoding="utf-8")
        if check_all(root, rendering):
            tally.refused += 1
        else:
            tally.failures.append("a hand edit inside a block passed the check")
        guide.write_text(written, encoding="utf-8")
        for label, text in (
            (
                "a deleted end marker",
                written.replace("<!-- END generated: support/things.docs -->\n", ""),
            ),
            ("a registered block with no markers", "# Guide\n\nNothing here.\n"),
            (
                "a block the registry does not list",
                written
                + f"\n<!-- BEGIN generated: support/other.docs ({GENERATOR}) -->\nx\n"
                "<!-- END generated: support/other.docs -->\n",
            ),
        ):
            guide.write_text(text, encoding="utf-8")
            tally.refuses(label, lambda: write_all(root, rendering), (MarkerError,))
            if guide.read_text(encoding="utf-8") != text:
                tally.failures.append(f"{label}: the refused file was changed")
        guide.write_text(written, encoding="utf-8")


def _self_test_cases() -> tuple[list[str], int, int]:
    tally = _Tally()
    _self_test_model(tally)
    _self_test_collectors(tally)
    _self_test_blocks(tally)
    return tally.failures, tally.refused, tally.accepted


def self_test() -> list[str]:
    """Plant what this script must refuse; the failures, empty when each was refused.

    Reads no ASH and writes only to a temporary directory.
    """
    return _self_test_cases()[0]


# --- the command line ---------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="Write nothing; exit 1 with a diff for every page and block that is stale.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help=(
            "Write (or with --check, compare) the one whole page at this path, or "
            "print it with '-'. The blocks of other pages are left alone. Default: "
            "every page and block, under the docs root."
        ),
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Plant the defects this script must refuse and require each to be refused.",
    )
    add_docs_root_argument(parser)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    started = time.monotonic()
    parser = _build_parser()
    args = parser.parse_args(argv)
    refuse_check_to_stdout(parser, args)
    if args.self_test:
        failures, refused, accepted = _self_test_cases()
        for failure in failures:
            print(f"self-test: FAILED {failure}", file=sys.stderr)
        print(
            f"self-test: {refused} planted defects refused, {accepted} controls "
            f"accepted, {len(failures)} failures, in {time.monotonic() - started:.1f} s.",
            file=sys.stderr,
        )
        return 1 if failures else 0
    docs_root = Path(args.docs_root).resolve()
    try:
        registry = load_destinations(_SCRIPTS)
        if args.output is not None and len(registry.pages) != 1:
            parser.error(
                f"--output names one file, and the registry has {len(registry.pages)} "
                "pages; omit it to write them all"
            )
        prepare_environment(docs_root)
        matrices = collect_matrices(
            discover_collectors(_SCRIPTS), CollectContext(docs_root=docs_root)
        )
        if args.output is None:
            return run(docs_root, matrices, registry, check=args.check, started=started)
        rendering = render_all(matrices, registry)
        content = rendering.pages[registry.pages[0]["file"]]
        summary = _summary(rendering, matrices, started)
        if args.output == "-":
            sys.stdout.write(content)
            print(summary, file=sys.stderr)
            return 0
        return write_or_check(
            Path(args.output), content, args.check, GENERATOR, summary
        )
    except (ModelError, MarkerError) as error:
        print(f"{GENERATOR}: refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
