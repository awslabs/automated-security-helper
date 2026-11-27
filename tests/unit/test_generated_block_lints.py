"""The docs checks know a generated block in a page a person writes.

A table a generator writes inside a hand-written page is not the author's prose: a
finding on one of its rows has to say the generator wrote it, as a finding on a row of
a generated reference page does, and the markers around it have to be well formed in
every page, whichever script owns the block. These tests plant pages with exactly one
defect each and require the finding, then plant the same text where the rule does not
apply (outside a block, in a block of another script, inside a code fence) and require
silence, so a check that rejected everything would fail the controls.

The registry the generator reads, scripts/_matrix_destinations.py, is read here by
``ast`` from the tree under check, like the list of generated reference pages, so a tree
with no registry is not held to one.
"""

from __future__ import annotations

import importlib.util
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKS_PATH = REPO_ROOT / "scripts" / "docs_checks.py"
GENERATOR = "scripts/generate_support_matrices.py"
OTHER_GENERATOR = "scripts/generate_deploy_patterns.py"
REGISTRY_FILE = "scripts/_matrix_destinations.py"
FENCE = "```"


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


dc = _load("_ash_docs_checks", CHECKS_PATH)


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def begin(name: str, generator: str = GENERATOR) -> str:
    return f"<!-- BEGIN generated: {name} ({generator}) -->"


def end(name: str) -> str:
    return f"<!-- END generated: {name} -->"


def lines(*parts: str) -> str:
    return "\n".join(parts) + "\n"


@pytest.fixture
def root(tmp_path):
    """A tree the CLI check can run in: it reads the repository's hook manifest."""
    tree = tmp_path / "repo"
    _write(
        tree,
        dc.PRE_COMMIT_HOOKS,
        (REPO_ROOT / dc.PRE_COMMIT_HOOKS).read_text(encoding="utf-8"),
    )
    return tree


def _messages(findings) -> list[str]:
    return [str(f) for f in findings]


def _registry(*blocks: tuple[str, str]) -> str:
    entries = "".join(
        f'    {{"file": {file!r}, "block": {block!r}, "matrix": "things", "view": "docs"}},\n'
        for file, block in blocks
    )
    return f"PAGES = ()\nBLOCKS = (\n{entries})\n"


# ---------------------------------------------------------------------------
# The rows of a block
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_generated_block_rows_maps_each_line_between_the_markers_to_the_generator(root):
    text = lines(
        "# Page",
        "",
        begin("support/a.docs"),
        "row a",
        "row b",
        end("support/a.docs"),
        "after",
    )
    page = dc.parse_page(_write(root, "docs/p.md", text), root)
    assert dc.generated_block_rows(page) == {4: GENERATOR, 5: GENERATOR}


@pytest.mark.unit
def test_generated_block_rows_names_the_generator_each_block_says():
    text = lines(
        "# Page",
        begin("support/a.docs"),
        "row",
        end("support/a.docs"),
        begin("deploy/b.docs", OTHER_GENERATOR),
        "row",
        end("deploy/b.docs"),
    )
    page = dc.Page(path=Path("docs/p.md"), rel="docs/p.md", text=text)
    assert dc.generated_block_rows(page) == {3: GENERATOR, 6: OTHER_GENERATOR}


@pytest.mark.unit
def test_generated_block_rows_ignores_markers_shown_inside_a_code_fence(root):
    text = lines(
        "# Page",
        f"{FENCE}markdown",
        begin("support/a.docs"),
        "row",
        end("support/a.docs"),
        FENCE,
        "after",
    )
    page = dc.parse_page(_write(root, "docs/p.md", text), root)
    assert dc.generated_block_rows(page) == {}


@pytest.mark.unit
def test_generated_block_rows_is_empty_for_a_pair_that_is_not_well_formed(root):
    text = lines("# Page", begin("support/a.docs"), "row")
    page = dc.parse_page(_write(root, "docs/p.md", text), root)
    assert dc.generated_block_rows(page) == {}


# ---------------------------------------------------------------------------
# A finding on a row of a block names the generator
# ---------------------------------------------------------------------------

#: The same row, once in the author's own table (line 5) and once in a block (line 10).
ATTRIBUTION_PAGE = lines(
    "# Page",
    "",
    "| Thing | Note |",
    "|-------|------|",
    "| outside | {note} |",
    "",
    begin("support/things.docs"),
    "| Thing | Note |",
    "|-------|------|",
    "| inside | {note} |",
    end("support/things.docs"),
)


@pytest.mark.unit
def test_a_valid_option_is_reported_in_a_block_naming_the_generator_and_not_outside(
    root,
):
    text = ATTRIBUTION_PAGE.format(note="Pass `--config` here.")
    page = _write(root, "docs/page.md", text)
    findings = [f for f in dc.check_cli([page], root) if "`--config`" in f.message]
    assert [f.line for f in findings] == [10], _messages(findings)
    assert GENERATOR in findings[0].message
    assert "change the text in the generator" in findings[0].message


@pytest.mark.unit
def test_an_invalid_option_is_reported_in_both_places_with_the_generator_wording_only_in_the_block(
    root,
):
    text = ATTRIBUTION_PAGE.format(note="Pass `--no-such-flag` here.")
    page = _write(root, "docs/page.md", text)
    findings = [f for f in dc.check_cli([page], root) if "--no-such-flag" in f.message]
    by_line = {f.line: f.message for f in findings}
    assert sorted(by_line) == [5, 10], _messages(findings)
    assert "is not an option of any ash command" in by_line[5]
    assert GENERATOR not in by_line[5]
    assert GENERATOR in by_line[10]
    assert "is not an option of any ash command" not in by_line[10]


@pytest.mark.unit
def test_a_span_that_names_its_program_passes_inside_a_block(root):
    text = ATTRIBUTION_PAGE.format(note="Run `zizmor --config` here.")
    page = _write(root, "docs/page.md", text)
    assert dc.check_cli([page], root) == []


@pytest.mark.unit
def test_a_block_of_another_generator_gets_that_generators_name(root):
    text = lines(
        "# Page",
        begin("deploy/things.docs", OTHER_GENERATOR),
        "| Thing | Note |",
        "|-------|------|",
        "| inside | Pass `--config` here. |",
        end("deploy/things.docs"),
    )
    page = _write(root, "docs/page.md", text)
    findings = [f for f in dc.check_cli([page], root) if "`--config`" in f.message]
    assert len(findings) == 1 and OTHER_GENERATOR in findings[0].message


@pytest.mark.unit
def test_a_bad_scanner_name_inside_a_block_is_still_reported(root):
    text = lines(
        "# Page",
        "",
        begin("support/things.docs"),
        "| Scanner | Tier |",
        "|---------|------|",
        "| gitleakz | alpha |",
        end("support/things.docs"),
    )
    page = _write(root, "docs/page.md", text)
    findings = dc.check_scanner_names([page], root)
    hits = [f for f in findings if "'gitleakz' in the Scanner column" in f.message]
    assert [f.line for f in hits] == [6], _messages(findings)


@pytest.mark.unit
def test_a_command_block_inside_a_generated_block_is_not_an_unexecuted_command_block(
    root,
):
    text = lines(
        "# Page",
        "",
        begin("support/things.docs"),
        f"{FENCE}text",
        "$ ash scan .",
        FENCE,
        end("support/things.docs"),
        "",
        f"{FENCE}text",
        "$ ash scan .",
        FENCE,
    )
    page = dc.parse_page(_write(root, "docs/page.md", text), root)
    found = dc.unexecuted_command_blocks(page, {})
    assert [block.fence_line for block, _command in found] == [9]


# ---------------------------------------------------------------------------
# The corpus-wide marker check
# ---------------------------------------------------------------------------

#: (case, the lines from line 3 of the page, what the finding says, the line it is at).
#: A pair the library refuses is reported where its own message says the trouble is.
MALFORMED = [
    (
        "a begin with no end",
        [begin("support/a.docs", OTHER_GENERATOR), "row"],
        "has no end marker",
        3,
    ),
    (
        "a marker with a typo",
        [
            "<!-- BEGIN generated support/a.docs (scripts/other.py) -->",
            "row",
            end("support/a.docs"),
        ],
        "looks like a generated-block marker",
        3,
    ),
    (
        "a begin repeated",
        [
            begin("support/a.docs", OTHER_GENERATOR),
            "row",
            end("support/a.docs"),
            begin("support/a.docs", OTHER_GENERATOR),
            "row",
            end("support/a.docs"),
        ],
        "begin marker is repeated",
        3,
    ),
    (
        "an end before its begin",
        [end("support/a.docs"), begin("support/a.docs", OTHER_GENERATOR), "row"],
        "comes before the begin marker",
        3,
    ),
    (
        "two blocks nested",
        [
            begin("support/a.docs", OTHER_GENERATOR),
            begin("support/b.docs", OTHER_GENERATOR),
            end("support/b.docs"),
            end("support/a.docs"),
        ],
        "blocks do not nest",
        4,
    ),
]


@pytest.mark.unit
@pytest.mark.parametrize(
    "case,body,expected,line", MALFORMED, ids=[case[0] for case in MALFORMED]
)
def test_a_malformed_pair_fails_the_marker_check_for_any_generator(
    root, case, body, expected, line
):
    page = _write(root, "docs/page.md", lines("# Page", "", *body))
    findings = [f for f in dc.check_markers([page], root) if f.check == "markers"]
    hits = [f for f in findings if expected in f.message]
    assert hits, _messages(findings)
    assert hits[0].path == "docs/page.md"
    assert hits[0].line == line, _messages(hits)
    assert "docs/page.md" in hits[0].message


@pytest.mark.unit
def test_a_well_formed_pair_of_any_generator_passes_when_there_is_no_registry(root):
    text = lines(
        "# Page",
        begin("support/a.docs"),
        "row",
        end("support/a.docs"),
        begin("deploy/b.docs", OTHER_GENERATOR),
        "row",
        end("deploy/b.docs"),
    )
    page = _write(root, "docs/page.md", text)
    assert dc.check_markers([page], root) == []


@pytest.mark.unit
def test_a_marker_shown_inside_a_code_fence_is_text_for_the_marker_check(root):
    text = lines(
        "# Page",
        f"{FENCE}markdown",
        begin("support/a.docs"),
        "row",
        FENCE,
    )
    page = _write(root, "docs/page.md", text)
    assert dc.check_markers([page], root) == []


@pytest.mark.unit
def test_a_registered_block_that_is_present_passes(root):
    _write(root, REGISTRY_FILE, _registry(("docs/page.md", "support/things.docs")))
    text = lines(
        "# Page", begin("support/things.docs"), "row", end("support/things.docs")
    )
    page = _write(root, "docs/page.md", text)
    assert dc.check_markers([page], root) == []


@pytest.mark.unit
def test_a_block_the_generator_owns_and_the_registry_lacks_is_an_orphan(root):
    _write(root, REGISTRY_FILE, _registry(("docs/page.md", "support/things.docs")))
    text = lines(
        "# Page",
        begin("support/things.docs"),
        "row",
        end("support/things.docs"),
        "",
        begin("support/other.docs"),
        "row",
        end("support/other.docs"),
    )
    page = _write(root, "docs/page.md", text)
    findings = dc.check_markers([page], root)
    hits = [f for f in findings if "support/other.docs" in f.message]
    assert len(hits) == 1, _messages(findings)
    assert (hits[0].check, hits[0].path, hits[0].line) == ("markers", "docs/page.md", 6)
    assert "not registered" in hits[0].message and REGISTRY_FILE in hits[0].message


@pytest.mark.unit
def test_a_registered_block_missing_from_its_file_fails(root):
    _write(root, REGISTRY_FILE, _registry(("docs/page.md", "support/things.docs")))
    page = _write(root, "docs/page.md", lines("# Page", "", "Nothing generated here."))
    findings = dc.check_markers([page], root)
    hits = [f for f in findings if "support/things.docs" in f.message]
    assert len(hits) == 1, _messages(findings)
    assert hits[0].path == "docs/page.md"
    assert "registered" in hits[0].message and "missing" in hits[0].message


@pytest.mark.unit
def test_a_registered_file_that_does_not_exist_fails(root):
    _write(root, REGISTRY_FILE, _registry(("docs/gone.md", "support/things.docs")))
    page = _write(root, "docs/page.md", lines("# Page"))
    findings = dc.check_markers([page], root)
    hits = [f for f in findings if "docs/gone.md" in f.message]
    assert len(hits) == 1, _messages(findings)
    assert "does not exist" in hits[0].message


@pytest.mark.unit
def test_a_block_of_another_generator_is_not_held_to_the_registry(root):
    _write(root, REGISTRY_FILE, _registry(("docs/page.md", "support/things.docs")))
    text = lines(
        "# Page",
        begin("support/things.docs"),
        "row",
        end("support/things.docs"),
        begin("deploy/b.docs", OTHER_GENERATOR),
        "row",
        end("deploy/b.docs"),
    )
    page = _write(root, "docs/page.md", text)
    assert dc.check_markers([page], root) == []


@pytest.mark.unit
def test_a_template_and_its_page_are_one_registered_file(root):
    _write(
        root, REGISTRY_FILE, _registry(("docs/page.md.template", "support/things.docs"))
    )
    body = lines(
        "# Page", begin("support/things.docs"), "row", end("support/things.docs")
    )
    template = _write(root, "docs/page.md.template", body)
    page = _write(root, "docs/page.md", body)
    assert dc.check_markers([template, page], root) == []
    bare = _write(root, "docs/page.md", lines("# Page"))
    findings = dc.check_markers([template, bare], root)
    hits = [f for f in findings if "support/things.docs" in f.message]
    assert len(hits) == 1 and hits[0].path == "docs/page.md", _messages(findings)


@pytest.mark.unit
def test_the_registry_is_read_by_ast_and_what_it_cannot_read_is_a_finding(root):
    assert dc.read_matrix_blocks(root) == (None, [])
    _write(root, REGISTRY_FILE, _registry(("docs/a.md", "support/x.docs")))
    registry, findings = dc.read_matrix_blocks(root)
    assert registry == {"docs/a.md": {"support/x.docs"}} and findings == []
    for text in (
        "PAGES = ()\nBLOCKS = 5\n",
        "PAGES = ()\n",
        "BLOCKS = ({'file': 'a.md'},)\n",
        "BLOCKS = (open,)\n",
        "BLOCKS = (\n",
    ):
        _write(root, REGISTRY_FILE, text)
        registry, findings = dc.read_matrix_blocks(root)
        assert registry is None, text
        assert len(findings) == 1 and findings[0].path == REGISTRY_FILE, text


@pytest.mark.unit
def test_a_registry_that_cannot_be_read_is_reported_once_and_arms_nothing(root):
    _write(root, REGISTRY_FILE, "BLOCKS = 5\n")
    text = lines("# Page", begin("support/a.docs"), "row", end("support/a.docs"))
    page = _write(root, "docs/page.md", text)
    findings = dc.check_markers([page], root)
    assert [f.path for f in findings] == [REGISTRY_FILE], _messages(findings)


@pytest.mark.unit
def test_the_registry_can_hold_a_comment_and_a_docstring(root):
    _write(
        root,
        REGISTRY_FILE,
        textwrap.dedent(
            '''\
            """Where the generator writes."""

            # Pages.
            PAGES = ()
            # Blocks.
            BLOCKS = ()
            '''
        ),
    )
    assert dc.read_matrix_blocks(root) == ({}, [])
