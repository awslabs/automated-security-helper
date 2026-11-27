"""The support-matrix generator, the model it renders and the scanners matrix.

A generator that accepted every matrix, every cell and every page would pass each
positive test below, so the tests first plant what must be refused (a family with one
view, a cell outside the closed vocabulary, ``ash`` text that was not read from the
CLI, a collector module with no collector, a block the registry does not list) and
require a refusal that names the thing. They then show that rendering is stable and
honest: the same matrices give the same bytes, a template and its page get the same
block, a hand edit inside a block fails ``--check`` with a diff, the second source goes
red when the renderer loses a row, and a process that believes it runs on Windows or
macOS writes the same page as one on Linux.

The model and the pure parts of the scanners collector need no ASH and run in the unit
tier. The tests that import the plugin registry run in process, and the ones that write
the real page start the generator as a child process under the planted environment of
tests/unit/test_generated_docs_freshness.py, so they are integration tests.

Each test imports the script it checks inside the test, so a script that is missing
fails its own tests and no others.
"""

from __future__ import annotations

import ast
import dataclasses
import importlib.util
import os as _os
import re
import subprocess
import sys
import sys as _sys
import textwrap
from pathlib import Path
from sys import platform as _bare_platform

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"
GENERATOR = "scripts/generate_support_matrices.py"
GENERATOR_PATH = SCRIPTS / "generate_support_matrices.py"
SUPPORT_PAGE = "docs/content/reference/support-matrix.md"
#: The six platform pairs the tool-download table publishes, in the order a page lists them.
PAIRS = (
    "linux/amd64",
    "linux/arm64",
    "darwin/amd64",
    "darwin/arm64",
    "windows/amd64",
    "windows/arm64",
)


def _script(name: str):
    """Import scripts/<name>.py by its plain name, as the scripts import each other."""
    sys.path.insert(0, str(SCRIPTS))
    try:
        return __import__(name)
    finally:
        sys.path.remove(str(SCRIPTS))


def model():
    return _script("_support_model")


def gen():
    return _script("generate_support_matrices")


def scan():
    return _script("_matrix_scan")


def blocks_library():
    return _script("_generated_blocks")


def gate():
    """scripts/verify_docs_freshness.py, loaded by path as the other tests load it."""
    name = "_ash_docs_gate_for_support_matrices"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(
        name, SCRIPTS / "verify_docs_freshness.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def commands():
    """The model with an empty list of spellings read from the CLI, restored after."""
    m = model()
    with m.isolated_commands():
        yield m


# ---------------------------------------------------------------------------
# Planted matrices
# ---------------------------------------------------------------------------


def small_matrix(rows=("alpha", "beta"), pages=False, **overrides):
    """A valid matrix of the shape a collector returns, for a test to break one way."""
    m = model()
    both = frozenset({m.README, m.DOCS})
    columns = (
        m.Column(
            key="thing", header="Thing", views=both, kind=m.NAME, source="the test"
        ),
        m.Column(
            key="tier",
            header="Tier",
            views=both,
            kind=m.VALUE,
            source="the test",
            pattern="supported|alpha",
        ),
        m.Column(
            key="works",
            header="Works on Linux",
            views=frozenset({m.DOCS}),
            kind=m.STATE,
            source="the test",
        ),
    )
    built = tuple(
        m.Row(
            key=name,
            cells={"thing": name, "tier": "alpha", "works": "yes"},
            page=f"docs/content/docs/plugins/builtin/{name}.md"
            if pages and name == "alpha"
            else None,
        )
        for name in rows
    )
    fields = {
        "name": "things",
        "title": "Things",
        "columns": columns,
        "rows": built,
        "members": frozenset(rows),
        "intro": "The things this test plants.",
        "notes": ("Each thing is planted.",),
    }
    fields.update(overrides)
    return m.Matrix(**fields)


def with_cell(matrix, row_key, column_key, text):
    """``matrix`` with one cell replaced, built again so every rule runs on it."""
    rows = tuple(
        dataclasses.replace(row, cells={**row.cells, column_key: text})
        if row.key == row_key
        else row
        for row in matrix.rows
    )
    return dataclasses.replace(matrix, rows=rows)


def text_matrix(text):
    """A matrix whose one free-text VALUE column holds ``text``."""
    m = model()
    both = frozenset({m.README, m.DOCS})
    columns = (
        m.Column(key="thing", header="Thing", views=both, kind=m.NAME, source="x"),
        m.Column(
            key="note",
            header="Note",
            views=both,
            kind=m.VALUE,
            source="x",
            pattern=".+",
        ),
    )
    return m.Matrix(
        name="notes",
        title="Notes",
        columns=columns,
        rows=(m.Row(key="a", cells={"thing": "a", "note": text}),),
        members=frozenset({"a"}),
    )


# ---------------------------------------------------------------------------
# The model: views, the closed vocabulary and plain cells
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("only,missing", [("docs", "readme"), ("readme", "docs")])
def test_a_family_with_one_view_only_is_refused(only, missing):
    m = model()
    base = small_matrix()
    columns = tuple(
        dataclasses.replace(c, views=frozenset({only})) for c in base.columns
    )
    with pytest.raises(m.ModelError, match=f"no {missing} view"):
        dataclasses.replace(base, columns=columns)


@pytest.mark.unit
def test_a_family_with_both_views_names_the_columns_of_each():
    m = model()
    matrix = small_matrix()
    assert [c.header for c in matrix.columns_in(m.README)] == ["Thing", "Tier"]
    assert [c.header for c in matrix.columns_in(m.DOCS)] == [
        "Thing",
        "Tier",
        "Works on Linux",
    ]


@pytest.mark.unit
def test_the_name_column_is_in_every_view_the_matrix_has():
    m = model()
    base = small_matrix()
    narrowed = (
        dataclasses.replace(base.columns[0], views=frozenset({m.DOCS})),
        *base.columns[1:],
    )
    with pytest.raises(m.ModelError, match="name column"):
        dataclasses.replace(base, columns=narrowed)


#: One concrete cell for every phrase of the closed vocabulary.
VOCABULARY_SAMPLES = (
    "yes",
    "no",
    "provisioned",
    "no asset",
    "refused: semgrep publishes no Windows build",
    "off by default",
    "package-defined (not declared)",
    "not declared",
    "not measured",
    "tested on pull_request, push",
    "not tested",
    "declared, not tested",
    "stub runtime: build and run calls checked",
    "documented, not run in ASH's CI",
    "missing: trivy (needs docker)",
    "loads only when its module is listed",
    "no deployment recorded",
    "static",
    "glibc",
    "musl",
    "unread",
    "in image",
    "not in image: the tool is not installed there",
    "hint only",
    "needs a repository checkout",
)
OFF_VOCABULARY = (
    "Yes",
    "n/a",
    "partial",
    "mostly",
    "refused:",
    "refused",
    "tested on",
    "missing: trivy",
    "in image: x",
    "not measured.",
    "yes ",
    " yes",
    "not  measured",
    "yes|no",
    "`yes`",
)


@pytest.mark.unit
@pytest.mark.parametrize("phrase", VOCABULARY_SAMPLES)
def test_every_phrase_of_the_closed_vocabulary_is_accepted(phrase):
    assert model().state_problem(phrase) is None


@pytest.mark.unit
@pytest.mark.parametrize("phrase", OFF_VOCABULARY)
def test_a_cell_outside_the_closed_vocabulary_is_refused(phrase):
    assert model().state_problem(phrase)


@pytest.mark.unit
def test_a_matrix_refuses_an_off_vocabulary_state_cell_and_names_it():
    m = model()
    with pytest.raises(m.ModelError) as excinfo:
        with_cell(small_matrix(), "beta", "works", "mostly")
    message = str(excinfo.value)
    assert "beta" in message and "works" in message and "mostly" in message


@pytest.mark.unit
def test_a_value_cell_must_match_the_pattern_of_its_own_column():
    m = model()
    with pytest.raises(m.ModelError, match="tier"):
        with_cell(small_matrix(), "alpha", "tier", "experimental")
    assert with_cell(small_matrix(), "alpha", "tier", "supported")


@pytest.mark.unit
def test_a_name_cell_is_the_key_of_its_row():
    m = model()
    with pytest.raises(m.ModelError, match="thing"):
        with_cell(small_matrix(), "alpha", "thing", "gamma")
    with pytest.raises(m.ModelError, match="thing"):
        with_cell(small_matrix(), "alpha", "thing", "Alpha")


@pytest.mark.unit
def test_the_rows_of_a_matrix_are_exactly_its_members():
    m = model()
    base = small_matrix()
    with pytest.raises(m.ModelError, match="members"):
        dataclasses.replace(base, rows=base.rows[:1])
    with pytest.raises(m.ModelError, match="members"):
        dataclasses.replace(base, members=frozenset({"alpha", "beta", "gamma"}))


@pytest.mark.unit
def test_two_rows_or_two_columns_may_not_share_a_key():
    m = model()
    base = small_matrix()
    with pytest.raises(m.ModelError, match="alpha"):
        dataclasses.replace(base, rows=(base.rows[0], base.rows[0]))
    with pytest.raises(m.ModelError, match="tier"):
        dataclasses.replace(
            base,
            columns=(
                *base.columns,
                dataclasses.replace(base.columns[1], header="Tier again"),
            ),
        )


@pytest.mark.unit
@pytest.mark.parametrize(
    "text",
    ["a|b", "a\nb", "<b>x</b>", "a  b", " lead", "trail ", ""],
)
def test_a_cell_is_plain_text_on_one_line(text):
    m = model()
    with pytest.raises(m.ModelError):
        text_matrix(text)


@pytest.mark.unit
def test_a_value_cell_may_hold_a_code_span_and_a_state_cell_may_not():
    m = model()
    assert text_matrix("module `ash_x`")
    with pytest.raises(m.ModelError):
        with_cell(small_matrix(), "alpha", "works", "`yes`")


@pytest.mark.unit
@pytest.mark.parametrize(
    "header", ["License", "License status", "Provenance", "Source licence"]
)
def test_a_license_or_provenance_column_is_refused(header):
    m = model()
    base = small_matrix()
    with pytest.raises(m.ModelError, match="licen|provenance"):
        dataclasses.replace(base.columns[2], header=header)


@pytest.mark.unit
@pytest.mark.parametrize(
    "text", ["MIT license", "under a licence", "provenance: PyPI", "License: MIT"]
)
def test_a_cell_that_states_a_license_or_a_provenance_is_refused(text):
    m = model()
    with pytest.raises(m.ModelError, match="licen|provenance"):
        text_matrix(text)


@pytest.mark.unit
@pytest.mark.parametrize("header", ["Default", "Defaults", "On by default"])
def test_a_header_with_the_word_default_is_refused(header):
    """A header with that word makes the docs checks read the table as one of options."""
    m = model()
    base = small_matrix()
    with pytest.raises(m.ModelError, match="default"):
        dataclasses.replace(base.columns[2], header=header)
    assert dataclasses.replace(base.columns[2], header="Loads on its own")


# ---------------------------------------------------------------------------
# The model: command text, the README budget and the refusal accessor
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_ash_text_is_refused_until_the_spelling_is_read_from_the_cli(commands):
    m = commands
    with pytest.raises(m.ModelError, match="ash scan"):
        m.refuse_unread_commands("Run ash scan now.", "the intro")
    spelling = m.ash_command(("scan",), exists=lambda path: path == ("scan",))
    assert spelling == "ash scan"
    m.refuse_unread_commands(f"Run {spelling} --mode container.", "the intro")
    with pytest.raises(m.ModelError, match="ash scan fs"):
        m.refuse_unread_commands("Run ash scan fs here.", "the intro")


@pytest.mark.unit
@pytest.mark.parametrize(
    "text",
    [
        "ASH scan runs scanners.",
        "Name it in ash_plugin_modules.",
        "The --ash-plugin-modules option.",
        "The /usr/bin/ash scan wrapper.",
        "A pot of ash. Then more.",
    ],
)
def test_text_that_only_looks_like_a_command_is_not_refused(commands, text):
    commands.refuse_unread_commands(text, "the intro")


@pytest.mark.unit
def test_a_path_that_is_no_command_is_refused_and_nothing_is_registered(commands):
    m = commands
    with pytest.raises(m.ModelError, match="not a command"):
        m.ash_command(("nope",), exists=lambda path: False)
    with pytest.raises(m.ModelError):
        m.ash_command((), exists=lambda path: True)
    assert m.read_commands() == frozenset()


@pytest.mark.unit
def test_ash_text_in_a_cell_an_intro_or_a_note_is_refused(commands):
    m = commands
    with pytest.raises(m.ModelError, match="ash scan"):
        text_matrix("run ash scan")
    with pytest.raises(m.ModelError, match="ash scan"):
        small_matrix(intro="Run ash scan.")
    with pytest.raises(m.ModelError, match="ash scan"):
        small_matrix(notes=("Then run ash scan.",))
    m.ash_command(("scan",), exists=lambda path: True)
    assert small_matrix(intro="Run ash scan.")
    assert text_matrix("run ash scan")


@pytest.mark.unit
def test_the_spelling_is_read_from_the_real_typer_app(commands):
    m = commands
    assert m.ash_command(("scan",)) == "ash scan"
    with pytest.raises(m.ModelError, match="not a command"):
        m.ash_command(("no-such-command",))


@pytest.mark.unit
def test_the_readme_budget_is_six_columns_and_sixteen_rows():
    m = model()
    assert (m.README_MAX_COLUMNS, m.README_MAX_ROWS) == (6, 16)
    m.check_readme_budget(6, 16, where="a block")
    with pytest.raises(m.ModelError, match="columns"):
        m.check_readme_budget(7, 3, where="a block")
    with pytest.raises(m.ModelError, match="rows"):
        m.check_readme_budget(3, 17, where="a block")
    m.check_readme_budget(3, 17, row_cap_exempt=True, collapsed=True, where="a block")
    with pytest.raises(m.ModelError, match="rows"):
        m.check_readme_budget(3, 17, row_cap_exempt=True, where="a block")
    with pytest.raises(m.ModelError, match="rows"):
        m.check_readme_budget(3, 17, collapsed=True, where="a block")
    with pytest.raises(m.ModelError, match="columns"):
        m.check_readme_budget(
            7, 17, row_cap_exempt=True, collapsed=True, where="a block"
        )


class _WindowsOnly:
    """A refusal that reads the platform the way the real overrides do."""

    def unsupported_platform_reason(self):
        import platform

        if platform.system().lower() == "windows":
            return "planted: no Windows build"
        return None


@pytest.mark.unit
@pytest.mark.parametrize(
    "os_name,expected",
    [("Linux", None), ("Darwin", None), ("Windows", "planted: no Windows build")],
)
def test_the_refusal_is_read_for_the_named_platform_whatever_the_host_is(
    monkeypatch, os_name, expected
):
    import platform

    m = model()
    assert m.OS_NAMES == ("Linux", "Darwin", "Windows")
    for host in m.OS_NAMES:
        monkeypatch.setattr(platform, "system", lambda host=host: host)
        assert m.platform_refusal(_WindowsOnly(), os_name) == expected


@pytest.mark.unit
def test_the_real_overrides_refuse_windows_and_only_windows():
    import types

    from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
        SemgrepScanner,
    )
    from automated_security_helper.plugin_modules.ash_guarddog_plugins.guarddog_scanner import (
        GuardDogScanner,
    )

    m = model()
    for scanner, words in ((SemgrepScanner, "Windows"), (GuardDogScanner, "Windows")):
        probe = types.SimpleNamespace(
            unsupported_platform_reason=lambda s=scanner: s.unsupported_platform_reason(
                object()
            )
        )
        assert m.platform_refusal(probe, "Linux") is None
        assert m.platform_refusal(probe, "Darwin") is None
        assert words in m.platform_refusal(probe, "Windows")


class _ReadsSysPlatform:
    def unsupported_platform_reason(self):
        return "no" if _sys.platform == "win32" else None


class _ReadsOsName:
    def unsupported_platform_reason(self):
        return "no" if _os.name == "nt" else None


class _ReadsABareImport:
    def unsupported_platform_reason(self):
        return "no" if _bare_platform == "win32" else None


class _ReadsPlatformSystem:
    def unsupported_platform_reason(self):
        import platform

        return "no" if platform.system().lower() == "windows" else None


@pytest.mark.unit
@pytest.mark.parametrize(
    "body,expected",
    [
        ("return 'x' if sys.platform == 'win32' else None", ["sys.platform"]),
        ("return 'x' if os.name == 'nt' else None", ["os.name"]),
        (
            "return 'x' if platform.uname().system == 'Windows' else None",
            ["platform.uname"],
        ),
        ("return 'x' if platform.machine() == 'arm64' else None", ["platform.machine"]),
        ("return 'x' if platform.system == 'Windows' else None", ["platform.system"]),
        (
            "return 'x' if sysconfig.get_platform().startswith('win') else None",
            ["sysconfig.get_platform"],
        ),
        ("return 'x' if platform.system().lower() == 'windows' else None", []),
        ("return 'x' if platform.system() == 'Windows' else None", []),
        ("return None", []),
    ],
)
def test_the_override_check_flags_every_read_of_the_platform_but_platform_system(
    body, expected
):
    source = "def unsupported_platform_reason(self):\n    " + body + "\n"
    assert model().platform_reads(source) == expected


@pytest.mark.unit
def test_the_override_check_follows_an_alias_and_a_name_imported_from_a_module():
    m = model()
    assert m.override_platform_reads(_ReadsSysPlatform) == ["sys.platform"]
    assert m.override_platform_reads(_ReadsOsName) == ["os.name"]
    assert m.override_platform_reads(_ReadsABareImport) == ["sys.platform"]
    assert m.override_platform_reads(_ReadsPlatformSystem) == []


@pytest.mark.unit
def test_every_scanner_that_overrides_the_refusal_reads_the_platform_only_through_system():
    """What makes the patched accessor enough: no override reads the host another way."""
    from automated_security_helper.base.plugin_manifest import resolve_ref
    from automated_security_helper.base.scanner_plugin import ScannerPluginBase
    from automated_security_helper.plugin_manifests import scanner_manifests

    m = model()
    overriding = {}
    for manifest in scanner_manifests():
        cls = resolve_ref(manifest.entry_points.scanner)
        if (
            cls.unsupported_platform_reason
            is not ScannerPluginBase.unsupported_platform_reason
        ):
            overriding[manifest.name] = m.override_platform_reads(cls)
    assert {"semgrep", "guarddog"} <= set(overriding), overriding
    assert {name: reads for name, reads in overriding.items() if reads} == {}


# ---------------------------------------------------------------------------
# Collectors: discovery, one matrix name, the destination registry
# ---------------------------------------------------------------------------

TRIVIAL_COLLECTOR = """
class _Collector:
    name = "{name}"

    def collect(self, context):
        return []

    def second_sources(self):
        return []


COLLECTOR = _Collector()
"""


@pytest.mark.unit
def test_a_collector_module_with_no_collector_object_is_refused(tmp_path):
    g, m = gen(), model()
    (tmp_path / "_matrix_empty.py").write_text("VALUE = 1\n", encoding="utf-8")
    with pytest.raises(m.ModelError, match="_matrix_empty.py"):
        g.discover_collectors(tmp_path)


@pytest.mark.unit
def test_collectors_are_found_in_sorted_order_and_the_registry_is_skipped(tmp_path):
    g = gen()
    for stem in ("_matrix_b", "_matrix_a", "_matrix_destinations"):
        (tmp_path / f"{stem}.py").write_text(
            TRIVIAL_COLLECTOR.format(name=stem), encoding="utf-8"
        )
    (tmp_path / "other.py").write_text(
        TRIVIAL_COLLECTOR.format(name="other"), encoding="utf-8"
    )
    assert [c.name for c in g.discover_collectors(tmp_path)] == [
        "_matrix_a",
        "_matrix_b",
    ]


class PlantedCollector:
    """A collector with its matrices and second sources given."""

    def __init__(self, matrices, second_sources=(), name="planted"):
        self.name = name
        self._matrices = list(matrices)
        self._second_sources = list(second_sources)

    def collect(self, context):
        return list(self._matrices)

    def second_sources(self):
        return list(self._second_sources)


@pytest.mark.unit
def test_two_collectors_may_not_return_one_matrix_name(tmp_path):
    g, m = gen(), model()
    context = m.CollectContext(docs_root=tmp_path)
    first = PlantedCollector([small_matrix()], name="one")
    second = PlantedCollector([small_matrix()], name="two")
    with pytest.raises(m.ModelError, match="things"):
        g.collect_matrices([first, second], context)
    assert set(g.collect_matrices([first], context)) == {"things"}


@pytest.mark.unit
def test_the_destination_registry_is_data_only_and_names_the_support_page():
    path = SCRIPTS / "_matrix_destinations.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        assert isinstance(node, (ast.Assign, ast.AnnAssign, ast.Expr)), ast.dump(node)
    values = {
        node.targets[0].id: ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
    }
    assert [page["file"] for page in values["PAGES"]] == [SUPPORT_PAGE]
    assert values["PAGES"][0]["sections"] == ("scanners",)
    assert isinstance(values["BLOCKS"], tuple)


@pytest.mark.unit
def test_load_destinations_reads_the_registry_without_importing_it(tmp_path):
    g = gen()
    (tmp_path / "_matrix_destinations.py").write_text(
        textwrap.dedent(
            f"""\
            PAGES = (
                {{
                    "file": {SUPPORT_PAGE!r},
                    "title": "Support matrix",
                    "source": "the test",
                    "intro": "x",
                    "sections": ("things",),
                }},
            )
            BLOCKS = ()
            raise SystemExit("imported")
            """
        ),
        encoding="utf-8",
    )
    registry = g.load_destinations(tmp_path)
    assert [p["file"] for p in registry.pages] == [SUPPORT_PAGE]
    assert registry.blocks == ()


# ---------------------------------------------------------------------------
# Rendering and writing: a planted tree
# ---------------------------------------------------------------------------

README_TEXT = textwrap.dedent(
    f"""\
    # Project

    Hand-written intro.

    <!-- BEGIN generated: support/things.readme ({GENERATOR}) -->
    stale
    <!-- END generated: support/things.readme -->

    Hand-written outro.
    """
)
GUIDE_TEXT = textwrap.dedent(
    f"""\
    # Guide

    <!-- BEGIN generated: support/things.docs ({GENERATOR}) -->
    stale
    <!-- END generated: support/things.docs -->

    The end.
    """
)
README_BLOCK = {
    "file": "README.md.template",
    "block": "support/things.readme",
    "matrix": "things",
    "view": "readme",
}
GUIDE_BLOCK = {
    "file": "docs/content/guide.md",
    "block": "support/things.docs",
    "matrix": "things",
    "view": "docs",
}


def planted_tree(tmp_path):
    root = tmp_path / "tree"
    for rel, text in (
        ("README.md.template", README_TEXT),
        ("README.md", README_TEXT),
        ("docs/content/guide.md", GUIDE_TEXT),
    ):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def destinations(g, blocks=(README_BLOCK, GUIDE_BLOCK), sections=("things",)):
    return g.Destinations(
        pages=(
            {
                "file": SUPPORT_PAGE,
                "title": "Support matrix",
                "source": "the planted matrices",
                "intro": "How to read a cell.",
                "sections": sections,
            },
        ),
        blocks=tuple(blocks),
    )


def render_and_write(g, root, matrix=None, blocks=(README_BLOCK, GUIDE_BLOCK)):
    matrices = {"things": matrix or small_matrix(pages=True)}
    registry = destinations(g, blocks)
    rendering = g.render_all(matrices, registry)
    g.write_all(root, rendering)
    return matrices, registry, rendering


def tree_files(root):
    return [
        root / "README.md.template",
        root / "README.md",
        root / "docs/content/guide.md",
        root / SUPPORT_PAGE,
    ]


def delimiter(headers):
    return "|" + "|".join("-" * (len(h) + 2) for h in headers) + "|"


@pytest.mark.unit
def test_a_readme_table_links_each_name_to_the_support_page_from_the_repository_root():
    g = gen()
    target = g.Target(file="README.md", support_page=SUPPORT_PAGE, anchors=False)
    assert g.render_table(small_matrix(), "readme", target) == [
        "| Thing | Tier |",
        delimiter(["Thing", "Tier"]),
        "| [`alpha`](docs/content/reference/support-matrix.md#alpha) | alpha |",
        "| [`beta`](docs/content/reference/support-matrix.md#beta) | alpha |",
    ]


@pytest.mark.unit
def test_a_readme_link_is_relative_to_the_directory_of_its_file():
    g = gen()
    nested = g.Target(file="docs/content/index.md", support_page=SUPPORT_PAGE)
    lines = g.render_table(small_matrix(), "readme", nested)
    assert "](reference/support-matrix.md#alpha)" in lines[2]
    deeper = g.Target(file="docs/content/docs/guide.md", support_page=SUPPORT_PAGE)
    assert (
        "](../reference/support-matrix.md#alpha)"
        in g.render_table(small_matrix(), "readme", deeper)[2]
    )


@pytest.mark.unit
def test_a_docs_table_on_the_support_page_anchors_each_row_and_links_its_own_page():
    g = gen()
    target = g.Target(file=SUPPORT_PAGE, support_page=SUPPORT_PAGE, anchors=True)
    headers = ["Thing", "Tier", "Works on Linux"]
    assert g.render_table(small_matrix(pages=True), "docs", target) == [
        "| Thing | Tier | Works on Linux |",
        delimiter(headers),
        '| <a id="alpha"></a>[`alpha`](../docs/plugins/builtin/alpha.md) | alpha | yes |',
        '| <a id="beta"></a>`beta` | alpha | yes |',
    ]


@pytest.mark.unit
def test_a_docs_table_in_another_page_links_from_that_page_and_adds_no_anchor():
    g = gen()
    target = g.Target(file="docs/content/guide.md", support_page=SUPPORT_PAGE)
    lines = g.render_table(small_matrix(pages=True), "docs", target)
    assert "[`alpha`](docs/plugins/builtin/alpha.md)" in lines[2]
    assert "<a id" not in "\n".join(lines)


@pytest.mark.unit
def test_writing_then_checking_is_clean_and_a_second_write_changes_nothing(tmp_path):
    g = gen()
    root = planted_tree(tmp_path)
    _matrices, _registry, rendering = render_and_write(g, root)
    assert g.check_all(root, rendering) == []
    first = [path.read_bytes() for path in tree_files(root)]
    assert g.write_all(root, rendering) == []
    assert [path.read_bytes() for path in tree_files(root)] == first


@pytest.mark.unit
def test_the_first_write_names_every_file_it_wrote(tmp_path):
    g = gen()
    root = planted_tree(tmp_path)
    matrices = {"things": small_matrix(pages=True)}
    rendering = g.render_all(matrices, destinations(g))
    assert set(g.write_all(root, rendering)) == {
        "README.md.template",
        "README.md",
        "docs/content/guide.md",
        SUPPORT_PAGE,
    }


@pytest.mark.unit
def test_a_template_and_its_page_get_the_same_block_bytes(tmp_path):
    g = gen()
    root = planted_tree(tmp_path)
    render_and_write(g, root)
    template = (root / "README.md.template").read_text(encoding="utf-8")
    page = (root / "README.md").read_text(encoding="utf-8")
    assert template == page
    assert "stale" not in template and "[`alpha`](docs/content/reference" in template


@pytest.mark.unit
def test_a_readme_block_ends_with_one_link_to_its_full_table(tmp_path):
    g = gen()
    root = planted_tree(tmp_path)
    render_and_write(g, root)
    text = (root / "README.md").read_text(encoding="utf-8")
    assert (
        "The full table is on the [support matrix page]"
        "(docs/content/reference/support-matrix.md#things)."
    ) in text
    guide = (root / "docs/content/guide.md").read_text(encoding="utf-8")
    assert "The full table is on" not in guide


@pytest.mark.unit
def test_a_hand_edit_inside_a_block_fails_the_check_and_prints_the_diff(
    tmp_path, capsys
):
    g = gen()
    root = planted_tree(tmp_path)
    matrices, registry, rendering = render_and_write(g, root)
    guide = root / "docs/content/guide.md"
    guide.write_text(
        guide.read_text(encoding="utf-8").replace("| alpha |", "| edited |", 1),
        encoding="utf-8",
    )
    failures = g.check_all(root, rendering)
    assert failures
    joined = "\n".join(failures)
    assert "support/things.docs" in joined and "edited" in joined
    assert g.run(root, matrices, registry, check=True) == 1
    err = capsys.readouterr().err
    assert "support/things.docs" in err and "edited" in err
    assert "edited" in guide.read_text(encoding="utf-8"), "a check never writes"


@pytest.mark.unit
def test_a_hand_edit_to_the_page_fails_the_check(tmp_path, capsys):
    g = gen()
    root = planted_tree(tmp_path)
    matrices, registry, rendering = render_and_write(g, root)
    page = root / SUPPORT_PAGE
    page.write_text(page.read_text(encoding="utf-8") + "extra\n", encoding="utf-8")
    assert g.run(root, matrices, registry, check=True) == 1
    assert SUPPORT_PAGE in capsys.readouterr().err


@pytest.mark.unit
def test_a_registered_block_missing_from_its_file_is_refused_naming_both(tmp_path):
    g = gen()
    library = blocks_library()
    root = planted_tree(tmp_path)
    matrices, registry, rendering = render_and_write(g, root)
    guide = root / "docs/content/guide.md"
    guide.write_text("# Guide\n\nNo markers here.\n", encoding="utf-8")
    with pytest.raises(library.MarkerError) as excinfo:
        g.write_all(root, rendering)
    assert excinfo.value.file == "docs/content/guide.md"
    assert excinfo.value.block == "support/things.docs"
    failures = g.check_all(root, rendering)
    assert any(
        "docs/content/guide.md" in f and "support/things.docs" in f for f in failures
    ), failures


@pytest.mark.unit
def test_a_block_the_generator_owns_and_the_registry_lacks_is_an_orphan(tmp_path):
    g = gen()
    library = blocks_library()
    root = planted_tree(tmp_path)
    matrices, registry, rendering = render_and_write(g, root)
    guide = root / "docs/content/guide.md"
    guide.write_text(
        guide.read_text(encoding="utf-8")
        + f"\n<!-- BEGIN generated: support/other.docs ({GENERATOR}) -->\nx\n"
        "<!-- END generated: support/other.docs -->\n",
        encoding="utf-8",
    )
    with pytest.raises(library.MarkerError, match="support/other.docs"):
        g.write_all(root, rendering)
    assert any("support/other.docs" in f for f in g.check_all(root, rendering))


@pytest.mark.unit
def test_a_deleted_end_marker_is_refused_not_repaired(tmp_path):
    g = gen()
    library = blocks_library()
    root = planted_tree(tmp_path)
    _matrices, _registry, rendering = render_and_write(g, root)
    guide = root / "docs/content/guide.md"
    text = guide.read_text(encoding="utf-8").replace(
        "<!-- END generated: support/things.docs -->\n", ""
    )
    guide.write_text(text, encoding="utf-8")
    with pytest.raises(library.MarkerError, match="support/things.docs"):
        g.write_all(root, rendering)
    assert guide.read_text(encoding="utf-8") == text


@pytest.mark.unit
def test_every_block_body_is_a_list_and_never_an_iterator(tmp_path, monkeypatch):
    g = gen()
    library = blocks_library()
    root = planted_tree(tmp_path)
    seen = []

    def spy(real):
        def call(root_, file, bodies, generator, **kwargs):
            seen.extend(type(body) for body in bodies.values())
            return real(root_, file, bodies, generator, **kwargs)

        return call

    monkeypatch.setattr(g, "write_blocks", spy(library.write_blocks))
    monkeypatch.setattr(g, "check_blocks", spy(library.check_blocks))
    _matrices, _registry, rendering = render_and_write(g, root)
    assert g.check_all(root, rendering) == []
    assert seen and set(seen) == {list}


def wide_matrix(columns, rows):
    m = model()
    both = frozenset({m.README, m.DOCS})
    built = [
        m.Column(key="thing", header="Thing", views=both, kind=m.NAME, source="x"),
        *(
            m.Column(
                key=f"c{n}",
                header=f"Column {n}",
                views=both,
                kind=m.VALUE,
                source="x",
                pattern="x",
            )
            for n in range(columns - 1)
        ),
    ]
    names = [f"row-{n}" for n in range(rows)]
    return m.Matrix(
        name="things",
        title="Things",
        columns=tuple(built),
        rows=tuple(
            m.Row(
                key=name,
                cells={"thing": name, **{f"c{n}": "x" for n in range(columns - 1)}},
            )
            for name in names
        ),
        members=frozenset(names),
    )


@pytest.mark.unit
def test_a_readme_destination_over_the_budget_is_refused_and_a_docs_one_is_not(
    tmp_path,
):
    g, m = gen(), model()
    wide = {"things": wide_matrix(7, 3)}
    with pytest.raises(m.ModelError, match="README"):
        g.render_all(wide, destinations(g, blocks=(README_BLOCK,)))
    g.render_all(wide, destinations(g, blocks=(GUIDE_BLOCK,)))
    tall = {"things": wide_matrix(3, 17)}
    with pytest.raises(m.ModelError, match="rows"):
        g.render_all(tall, destinations(g, blocks=(README_BLOCK,)))
    exempt = {**README_BLOCK, "row_cap_exempt": True, "collapsed": True}
    g.render_all(tall, destinations(g, blocks=(exempt,)))
    with pytest.raises(m.ModelError, match="rows"):
        g.render_all(
            tall,
            destinations(g, blocks=({**README_BLOCK, "row_cap_exempt": True},)),
        )


@pytest.mark.unit
def test_a_block_can_show_only_the_rows_a_filter_names(tmp_path):
    g, m = gen(), model()
    base = small_matrix(rows=("alpha", "beta", "gamma"))
    matrix = with_cell(base, "gamma", "tier", "supported")
    only_supported = {**GUIDE_BLOCK, "rows": {"tier": "supported"}}
    rendering = g.render_all(
        {"things": matrix}, destinations(g, blocks=(only_supported,))
    )
    body = rendering.blocks["docs/content/guide.md"]["support/things.docs"]
    assert any("gamma" in line for line in body)
    assert not any("alpha" in line or "beta" in line for line in body[2:])
    unknown = {**GUIDE_BLOCK, "rows": {"nothing": "x"}}
    with pytest.raises(m.ModelError, match="nothing"):
        g.render_all({"things": matrix}, destinations(g, blocks=(unknown,)))


@pytest.mark.unit
def test_a_block_that_names_a_matrix_nothing_collected_is_refused():
    g, m = gen(), model()
    with pytest.raises(m.ModelError, match="things"):
        g.render_all({}, destinations(g, blocks=(GUIDE_BLOCK,)))


@pytest.mark.unit
def test_the_page_is_the_banner_a_note_the_sections_and_where_each_column_comes_from():
    g = gen()
    text = g.render_page(destinations(g).pages[0], {"things": small_matrix(pages=True)})
    lines = text.split("\n")
    assert lines[0] == "<!--"
    assert f"Generated by {GENERATOR} from the planted matrices." in lines[1]
    assert f"uv run python {GENERATOR}" in text
    assert "# Support matrix" in lines
    assert "This page is generated from the planted matrices by" in text
    assert "How to read a cell." in lines
    assert "## Things" in lines
    assert "| Thing | Tier | Works on Linux |" in lines
    assert "Each thing is planted." in lines
    assert text.endswith("\n") and not text.endswith("\n\n")
    where = text.split("Where each column comes from", 1)[1]
    for header in ("Thing", "Tier", "Works on Linux"):
        assert f"`{header}`" in where
    assert "{{" not in text
    assert not re.search(r"licen[cs]e|provenance", text, re.IGNORECASE)


@pytest.mark.unit
def test_the_page_is_the_same_bytes_whatever_order_the_matrices_arrive_in():
    g = gen()
    matrices = {
        "things": small_matrix(pages=True),
        "more": small_matrix(name="more", title="More", rows=("gamma",)),
    }
    spec = destinations(g, sections=("things", "more")).pages[0]
    text = g.render_page(spec, matrices)
    assert text == g.render_page(spec, dict(reversed(list(matrices.items()))))
    assert text.index("## Things") < text.index("## More")


@pytest.mark.unit
def test_a_section_that_names_no_matrix_is_refused():
    g, m = gen(), model()
    spec = destinations(g, sections=("things", "ghosts")).pages[0]
    with pytest.raises(m.ModelError, match="ghosts"):
        g.render_page(spec, {"things": small_matrix()})


# ---------------------------------------------------------------------------
# The second source
# ---------------------------------------------------------------------------


def planted_second_source(names=("alpha", "beta")):
    m = model()
    return m.SecondSource(
        label="Things",
        matrix="things",
        header_cell="Thing",
        names=lambda: dict.fromkeys(names, "the independent list"),
    )


@pytest.mark.unit
def test_the_second_source_reads_the_committed_page_and_is_green_when_it_agrees(
    tmp_path,
):
    g = gen()
    root = tmp_path / "tree"
    matrix = small_matrix(pages=True)
    collector = PlantedCollector([matrix], [planted_second_source()])
    registry = destinations(g, blocks=())
    g.write_all(root, g.render_all({"things": matrix}, registry))
    failures = g.second_source_failures(
        root, gate().compare_inventories, collectors=[collector], destinations=registry
    )
    assert failures == []


@pytest.mark.unit
def test_the_second_source_goes_red_when_the_renderer_drops_a_row(
    tmp_path, monkeypatch
):
    g = gen()
    root = tmp_path / "tree"
    matrix = small_matrix(pages=True)
    collector = PlantedCollector([matrix], [planted_second_source()])
    registry = destinations(g, blocks=())
    real = g.render_table

    def dropping(matrix_, view, target, rows=None):
        return real(matrix_, view, target, rows)[:-1]

    monkeypatch.setattr(g, "render_table", dropping)
    g.write_all(root, g.render_all({"things": matrix}, registry))
    failures = g.second_source_failures(
        root, gate().compare_inventories, collectors=[collector], destinations=registry
    )
    assert any("beta" in failure for failure in failures), failures


@pytest.mark.unit
def test_the_second_source_goes_red_for_a_row_the_independent_list_lacks(tmp_path):
    g = gen()
    root = tmp_path / "tree"
    matrix = small_matrix(pages=True)
    collector = PlantedCollector([matrix], [planted_second_source(names=("alpha",))])
    registry = destinations(g, blocks=())
    g.write_all(root, g.render_all({"things": matrix}, registry))
    failures = g.second_source_failures(
        root, gate().compare_inventories, collectors=[collector], destinations=registry
    )
    assert any("beta" in failure for failure in failures), failures


@pytest.mark.unit
def test_a_second_source_for_a_matrix_no_page_renders_is_a_failure(tmp_path):
    g = gen()
    collector = PlantedCollector([small_matrix()], [planted_second_source()])
    registry = destinations(g, blocks=(), sections=())
    failures = g.second_source_failures(
        tmp_path,
        gate().compare_inventories,
        collectors=[collector],
        destinations=registry,
    )
    assert any("things" in failure for failure in failures), failures


@pytest.mark.unit
def test_the_gate_runs_the_self_test_and_every_second_source():
    module = gate()
    assert callable(module.check_support_matrices)
    names = [title for title, _check in _gate_checks(module)]
    assert any("support" in title.lower() for title in names), names


def _gate_checks(module):
    """The (title, function) pairs of the gate's registry, read from its source."""
    tree = ast.parse((SCRIPTS / "verify_docs_freshness.py").read_text(encoding="utf-8"))
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "checks" for t in node.targets
        ):
            for element in getattr(node.value, "elts", []):
                if isinstance(element, ast.Tuple) and len(element.elts) == 2:
                    title = ast.literal_eval(element.elts[0])
                    function = element.elts[1]
                    found.append((title, getattr(function, "id", "")))
    return found


# ---------------------------------------------------------------------------
# The self-test and the command line
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_the_self_test_is_green_on_the_real_tree():
    assert gen().self_test() == []


@pytest.mark.unit
def test_the_self_test_goes_red_when_the_vocabulary_accepts_anything(monkeypatch):
    m, g = model(), gen()
    monkeypatch.setattr(m, "state_problem", lambda text: None)
    failures = g.self_test()
    assert any("vocabulary" in failure for failure in failures), failures


@pytest.mark.unit
def test_the_self_test_command_exits_zero_and_says_what_it_planted(capsys):
    assert gen().main(["--self-test"]) == 0
    assert "self-test" in capsys.readouterr().err


@pytest.mark.unit
def test_check_with_output_to_stdout_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as excinfo:
        gen().main(["--check", "--output", "-"])
    assert excinfo.value.code == 2
    assert "--output -" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# The scanners matrix: the pure parts
# ---------------------------------------------------------------------------


def scanner(name, tier="supported", **overrides):
    s = scan()
    fields = {
        "name": name,
        "tier": tier,
        "superseded_by": None,
        "default_enabled": True,
        "plugin_module": "automated_security_helper.plugin_modules.ash_builtin",
        "runtime_kind": "uv_python",
        "provisionable": (),
        "refusals": {"Linux": None, "Darwin": None, "Windows": None},
        "enabled": {"Linux": True, "Darwin": True, "Windows": True},
        "page": None,
    }
    fields.update(overrides)
    return s.ScannerInput(**fields)


def rows_by_key(matrix):
    return {row.key: row for row in matrix.rows}


@pytest.mark.unit
def test_the_scanners_matrix_declares_both_views_in_the_readme_budget():
    m, s = model(), scan()
    matrix = s.scanner_matrix([scanner("bandit")])
    assert [c.header for c in matrix.columns_in(m.README)] == [
        "Scanner",
        "Tier",
        "Install methods",
        "Operating systems",
    ]
    assert [c.header for c in matrix.columns_in(m.DOCS)] == [
        "Scanner",
        "Tier",
        "Loads on its own",
        "Module to list",
        "Install methods",
        "Linux x86-64",
        "Linux arm64",
        "macOS Intel",
        "macOS Apple silicon",
        "Windows x86-64",
        "Windows arm64",
        "Linux libc",
    ]
    assert len(matrix.columns_in(m.README)) <= m.README_MAX_COLUMNS


@pytest.mark.unit
def test_every_plugin_tier_has_a_word_and_a_position():
    from automated_security_helper.base.plugin_manifest import PluginTier

    s = scan()
    assert set(s.TIER_ORDER) == {tier.value for tier in PluginTier}
    assert (
        s.TIER_ORDER["supported"] < s.TIER_ORDER["deprecated"] < s.TIER_ORDER["alpha"]
    )


@pytest.mark.unit
def test_every_runtime_kind_has_a_route_word():
    from automated_security_helper.base.scanner_operational_facets import RuntimeKind

    s = scan()
    assert set(s.RUNTIME_ROUTES) == {kind.value for kind in RuntimeKind}
    assert len(set(s.RUNTIME_ROUTES.values())) == len(s.RUNTIME_ROUTES)


@pytest.mark.unit
def test_every_platform_pair_the_tool_table_publishes_has_a_column():
    from automated_security_helper.base.scanner_operational_facets import PLATFORMS_ALL

    s = scan()
    assert [row[0] for row in s.PLATFORM_COLUMNS] == list(PAIRS)
    assert {row[0] for row in s.PLATFORM_COLUMNS} == set(PLATFORMS_ALL)


@pytest.mark.unit
def test_the_semgrep_row_names_opengrep_as_its_successor():
    s = scan()
    matrix = s.scanner_matrix(
        [
            scanner("opengrep"),
            scanner("semgrep", tier="deprecated", superseded_by="opengrep"),
        ]
    )
    cell = rows_by_key(matrix)["semgrep"].cells["tier"]
    assert cell == "deprecated, superseded by `opengrep`"
    assert rows_by_key(matrix)["opengrep"].cells["tier"] == "supported"


@pytest.mark.unit
def test_a_deprecated_scanner_with_no_successor_is_refused_and_so_is_a_ghost_one():
    m, s = model(), scan()
    with pytest.raises(m.ModelError, match="semgrep"):
        s.scanner_matrix([scanner("semgrep", tier="deprecated")])
    with pytest.raises(m.ModelError, match="semgrep"):
        s.scanner_matrix([scanner("semgrep", tier="deprecated", superseded_by="ghost")])


@pytest.mark.unit
def test_an_alpha_scanner_loads_only_when_its_module_is_listed():
    s = scan()
    module = "automated_security_helper.plugin_modules.ash_snyk_plugins"
    matrix = s.scanner_matrix(
        [
            scanner("bandit"),
            scanner(
                "snyk-code", tier="alpha", default_enabled=False, plugin_module=module
            ),
        ]
    )
    rows = rows_by_key(matrix)
    assert rows["snyk-code"].cells["loads"] == "loads only when its module is listed"
    assert rows["snyk-code"].cells["module"] == f"`{module}`"
    assert rows["snyk-code"].cells["tier"] == "alpha"
    assert rows["bandit"].cells["loads"] == "yes"
    assert rows["bandit"].cells["module"] == "built in"


@pytest.mark.unit
def test_rows_are_sorted_by_tier_then_name_whatever_order_they_arrive_in():
    s = scan()
    matrix = s.scanner_matrix(
        [
            scanner("zeta", tier="alpha"),
            scanner("beta"),
            scanner("old", tier="deprecated", superseded_by="alpha-one"),
            scanner("alpha-one"),
            scanner("beta-two", tier="alpha"),
        ]
    )
    assert [row.key for row in matrix.rows] == [
        "alpha-one",
        "beta",
        "old",
        "beta-two",
        "zeta",
    ]


@pytest.mark.unit
def test_a_scanner_that_appears_in_the_inputs_appears_as_a_row_and_a_member():
    s = scan()
    base = [scanner("bandit"), scanner("checkov")]
    plain = s.scanner_matrix(base)
    extended = s.scanner_matrix([*base, scanner("planted")])
    assert plain.members == frozenset({"bandit", "checkov"})
    assert extended.members == plain.members | {"planted"}
    assert "planted" in rows_by_key(extended)


@pytest.mark.unit
def test_a_row_links_its_own_page_and_anchors_by_its_name():
    s = scan()
    page = "docs/content/docs/plugins/builtin/bandit.md"
    matrix = s.scanner_matrix([scanner("bandit", page=page), scanner("checkov")])
    rows = rows_by_key(matrix)
    assert (rows["bandit"].page, rows["bandit"].anchor) == (page, "bandit")
    assert rows["checkov"].page is None


@pytest.mark.unit
@pytest.mark.parametrize(
    "refusal,provisionable,pair,enabled,expected",
    [
        ("no build", PAIRS[4:5], "windows/amd64", False, "refused: no build"),
        (None, PAIRS[:4], "windows/arm64", False, "no asset"),
        (None, PAIRS[4:5], "windows/amd64", False, "off by default"),
        (None, PAIRS[:1], "linux/amd64", True, "provisioned"),
        (None, (), "linux/amd64", True, "package-defined (not declared)"),
        (None, (), "windows/amd64", False, "off by default"),
    ],
)
def test_a_platform_cell_is_the_first_reading_that_applies(
    refusal, provisionable, pair, enabled, expected
):
    state = scan().os_state(
        refusal=refusal, provisionable=provisionable, pair=pair, enabled=enabled
    )
    assert state == expected
    assert model().state_problem(state) is None


def all_pairs(text, **different):
    return {**dict.fromkeys(PAIRS, text), **different}


@pytest.mark.unit
@pytest.mark.parametrize(
    "states,expected",
    [
        (all_pairs("provisioned"), "Linux, macOS, Windows: provisioned"),
        (
            all_pairs("provisioned", **{"windows/arm64": "no asset"}),
            "Linux, macOS, Windows (x86-64): provisioned; Windows (arm64): no asset",
        ),
        (
            all_pairs(
                "package-defined (not declared)",
                **{"windows/amd64": "refused: r", "windows/arm64": "refused: r"},
            ),
            "Linux, macOS: package-defined (not declared); Windows: refused: r",
        ),
        (
            all_pairs("provisioned", **{"darwin/amd64": "no asset"}),
            "Linux, macOS (Apple silicon), Windows: provisioned; macOS (Intel): no asset",
        ),
        (
            all_pairs("no", **{"linux/arm64": "yes"}),
            "Linux (x86-64), macOS, Windows: no; Linux (arm64): yes",
        ),
    ],
)
def test_the_operating_systems_summary_groups_equal_cells_in_the_canonical_order(
    states, expected
):
    assert scan().os_summary(states) == expected


@pytest.mark.unit
def test_the_summary_column_holds_what_the_summary_function_writes():
    s = scan()
    matrix = s.scanner_matrix(
        [
            scanner(
                "hadolint",
                runtime_kind="pinned_binary",
                provisionable=PAIRS[:5],
            )
        ]
    )
    row = rows_by_key(matrix)["hadolint"]
    assert row.cells["os_summary"] == (
        "Linux, macOS, Windows (x86-64): provisioned; Windows (arm64): no asset"
    )
    assert row.cells["windows_arm64"] == "no asset"
    assert row.cells["linux_x86_64"] == "provisioned"
    assert row.cells["libc"] == "not measured"
    assert row.cells["install"] == s.RUNTIME_ROUTES["pinned_binary"]


@pytest.mark.unit
def test_a_refusal_and_an_off_default_show_on_their_own_platforms_only():
    s = scan()
    matrix = s.scanner_matrix(
        [
            scanner(
                "semgrep-like",
                refusals={"Linux": None, "Darwin": None, "Windows": "no Windows build"},
                enabled={"Linux": True, "Darwin": True, "Windows": False},
            )
        ]
    )
    cells = rows_by_key(matrix)["semgrep-like"].cells
    assert (
        cells["linux_x86_64"]
        == cells["macos_intel"]
        == "package-defined (not declared)"
    )
    assert (
        cells["windows_x86_64"] == cells["windows_arm64"] == "refused: no Windows build"
    )


@pytest.mark.unit
def test_every_state_a_cell_uses_is_explained_in_the_notes():
    s = scan()
    matrix = s.scanner_matrix(
        [
            scanner("a", provisionable=PAIRS[:5], runtime_kind="pinned_binary"),
            scanner(
                "b",
                refusals={"Linux": None, "Darwin": None, "Windows": "no build"},
                enabled={"Linux": True, "Darwin": True, "Windows": False},
            ),
            scanner("c", tier="alpha", default_enabled=False),
        ]
    )
    notes = "\n".join(matrix.notes)
    used = set()
    for row in matrix.rows:
        for column in matrix.columns:
            if column.kind == "state":
                cell = row.cells[column.key]
                used.add("refused: <reason>" if cell.startswith("refused: ") else cell)
    assert {"provisioned", "no asset", "refused: <reason>", "not measured"} <= used
    for phrase in sorted(used):
        assert f"`{phrase}`" in notes, phrase


# ---------------------------------------------------------------------------
# The scanners matrix: the real registry, read in process
# ---------------------------------------------------------------------------


def real_collect(docs_root=REPO_ROOT):
    m, s = model(), scan()
    (matrix,) = s.COLLECTOR.collect(m.CollectContext(docs_root=docs_root))
    return matrix


@pytest.mark.unit
def test_the_scanners_collector_has_a_row_for_every_manifest():
    from automated_security_helper.plugin_manifests import scanner_manifests

    matrix = real_collect()
    manifests = scanner_manifests()
    assert matrix.name == "scanners"
    assert matrix.members == frozenset(m.name for m in manifests)
    assert len(matrix.rows) == len(manifests) >= 23


@pytest.mark.unit
def test_the_real_semgrep_row_names_its_successor_and_refuses_windows_only():
    rows = rows_by_key(real_collect())
    assert rows["semgrep"].cells["tier"] == "deprecated, superseded by `opengrep`"
    assert rows["semgrep"].cells["windows_x86_64"].startswith("refused: ")
    assert rows["semgrep"].cells["linux_x86_64"] == "package-defined (not declared)"
    assert rows["guarddog"].cells["windows_arm64"].startswith("refused: ")
    assert rows["opengrep"].cells["windows_x86_64"] == "off by default"
    assert rows["opengrep"].cells["windows_arm64"] == "no asset"


@pytest.mark.unit
def test_the_real_alpha_rows_load_only_when_their_module_is_listed():
    from automated_security_helper.plugin_manifests import scanner_manifests

    rows = rows_by_key(real_collect())
    alpha = [m for m in scanner_manifests() if m.tier.value == "alpha"]
    built_in = [m for m in scanner_manifests() if m.default_enabled]
    assert alpha and built_in
    for manifest in alpha:
        cells = rows[manifest.name].cells
        assert cells["loads"] == "loads only when its module is listed"
        assert cells["module"] == f"`{manifest.plugin_module}`"
    for manifest in built_in:
        assert rows[manifest.name].cells["loads"] == "yes"


@pytest.mark.unit
def test_the_real_rows_come_in_tier_order():
    s = scan()
    matrix = real_collect()
    tiers = [s.TIER_ORDER[row.cells["tier"].split(",")[0]] for row in matrix.rows]
    assert tiers == sorted(tiers)


@pytest.mark.unit
def test_a_manifest_added_to_the_registry_appears_as_a_row(monkeypatch):
    import automated_security_helper.plugin_manifests as manifests

    real = manifests.scanner_manifests()
    bandit = next(m for m in real if m.name == "bandit")
    extra = bandit.model_copy(update={"name": "planted-scanner"})
    monkeypatch.setattr(manifests, "scanner_manifests", lambda: (*real, extra))
    matrix = real_collect()
    assert "planted-scanner" in matrix.members
    assert len(matrix.rows) == len(real) + 1
    rows = rows_by_key(matrix)
    assert rows["planted-scanner"].cells["install"] == rows["bandit"].cells["install"]


@pytest.mark.unit
def test_a_manifest_whose_class_no_plugin_package_registers_is_refused(monkeypatch):
    import automated_security_helper.plugin_manifests as manifests

    real = manifests.scanner_manifests()
    bandit = next(m for m in real if m.name == "bandit")
    points = bandit.entry_points.model_copy(
        update={
            "scanner": "automated_security_helper.base.scanner_plugin:ScannerPluginBase"
        }
    )
    ghost = bandit.model_copy(update={"name": "ghost-scanner", "entry_points": points})
    monkeypatch.setattr(manifests, "scanner_manifests", lambda: (*real, ghost))
    with pytest.raises(model().ModelError, match="ghost-scanner"):
        real_collect()


@pytest.mark.unit
def test_the_second_source_of_the_scanners_collector_lists_every_scanner():
    from automated_security_helper.plugin_manifests import scanner_manifests

    (source,) = scan().COLLECTOR.second_sources()
    assert (source.matrix, source.header_cell) == ("scanners", "Scanner")

    def folded(names):
        return {re.sub(r"[^a-z0-9]", "", name.lower()) for name in names}

    assert folded(source.names()) == folded(m.name for m in scanner_manifests())


# ---------------------------------------------------------------------------
# The real page, written by a child process under the planted environment
# ---------------------------------------------------------------------------

PLATFORM_DRIVER = """
import platform
import runpy
import sys

system, script, output = sys.argv[1:4]
platform.system = lambda: system
sys.argv = [script, "--output", output]
runpy.run_path(script, run_name="__main__")
"""


def planted_run(tmp_path, *args, seed="1", home=None, name="run"):
    from tests.unit.test_generated_docs_freshness import (
        _planted_environment,
        _run_generator,
    )

    env, _home = _planted_environment(tmp_path / name, seed, home)
    return _run_generator("generate_support_matrices.py", *args, env=env)


def first_table(text, header_cell):
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.startswith(f"| {header_cell} |") and lines[index + 1].startswith("|--"):
            header = [c.strip() for c in line.strip().strip("|").split("|")]
            rows = []
            for row in lines[index + 2 :]:
                if not row.startswith("|"):
                    break
                rows.append([c.strip() for c in row.strip().strip("|").split("|")])
            return header, rows
    raise AssertionError(f"no table whose first header cell is {header_cell!r}")


@pytest.fixture(scope="module")
def real_page(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("real-page")
    out = tmp_path / "support-matrix.md"
    result = planted_run(tmp_path, "--output", str(out))
    assert result.returncode == 0, result.stdout + result.stderr
    return out.read_text(encoding="utf-8"), result.stderr


@pytest.mark.integration
def test_the_page_lists_every_manifest_once_with_an_anchor_and_a_name(real_page):
    from automated_security_helper.plugin_manifests import scanner_manifests

    text, _stderr = real_page
    header, rows = first_table(text, "Scanner")
    names = [re.search(r"`([a-z0-9-]+)`", row[0]).group(1) for row in rows]
    assert names and len(names) == len(set(names))
    assert set(names) == {m.name for m in scanner_manifests()}
    for name, row in zip(names, rows):
        assert row[0].startswith(f'<a id="{name}"></a>')
    assert header[0] == "Scanner" and "Tier" in header


@pytest.mark.integration
def test_the_page_starts_with_its_banner_and_names_no_license_and_no_placeholder(
    real_page,
):
    text, _stderr = real_page
    assert text.startswith("<!--\n  Generated by scripts/generate_support_matrices.py")
    assert "{{" not in text
    assert not re.search(r"licen[cs]e|provenance", text, re.IGNORECASE)


@pytest.mark.integration
def test_the_run_reports_how_long_it_took(real_page):
    _text, stderr = real_page
    assert re.search(r"in \d+\.\d s", stderr), stderr


@pytest.mark.integration
def test_the_check_of_a_current_file_exits_zero_and_a_stale_one_exits_one(
    tmp_path, real_page
):
    text, _stderr = real_page
    current = tmp_path / "current.md"
    current.write_text(text, encoding="utf-8")
    assert (
        planted_run(tmp_path, "--check", "--output", str(current), name="a").returncode
        == 0
    )
    stale = tmp_path / "stale.md"
    stale.write_text(text + "extra\n", encoding="utf-8")
    result = planted_run(tmp_path, "--check", "--output", str(stale), name="b")
    assert result.returncode == 1
    assert "extra" in result.stderr
    assert stale.read_text(encoding="utf-8") == text + "extra\n"


@pytest.mark.integration
def test_the_page_is_the_same_under_another_seed_and_another_home(tmp_path, real_page):
    text, _stderr = real_page
    out = tmp_path / "second.md"
    result = planted_run(
        tmp_path, "--output", str(out), seed="2", home="/d", name="two"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert out.read_text(encoding="utf-8") == text


@pytest.mark.integration
@pytest.mark.parametrize("system", ["Windows", "Darwin"])
def test_the_page_is_the_same_in_a_process_that_believes_it_runs_on_another_system(
    tmp_path, real_page, system
):
    """The lint job runs on one platform and a contributor may regenerate on another."""
    from tests.unit.test_generated_docs_freshness import _planted_environment

    text, _stderr = real_page
    driver = tmp_path / "driver.py"
    driver.write_text(PLATFORM_DRIVER, encoding="utf-8")
    out = tmp_path / f"{system}.md"
    env, _home = _planted_environment(tmp_path / "env", "1", None)
    result = subprocess.run(
        [sys.executable, str(driver), system, str(GENERATOR_PATH), str(out)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert out.read_text(encoding="utf-8") == text


@pytest.mark.integration
def test_the_committed_page_is_what_the_generator_writes(real_page):
    text, _stderr = real_page
    committed = REPO_ROOT / SUPPORT_PAGE
    assert committed.is_file(), f"{SUPPORT_PAGE} is missing"
    assert committed.read_text(encoding="utf-8") == text


@pytest.mark.integration
def test_the_self_test_flag_runs_in_a_child_process_and_exits_zero(tmp_path):
    result = planted_run(tmp_path, "--self-test")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "self-test" in result.stderr
