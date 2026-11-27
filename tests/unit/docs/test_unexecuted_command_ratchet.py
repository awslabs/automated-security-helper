"""A command in a block nothing runs is counted, so relabeling bash as text gets nowhere.

WHY THIS EXISTS
---------------
The illustrative seed freezes the blocks marked as not running. A block can leave the
runs another way: fence a bash block as ``text``, and the runner never sees it, the
marker check has nothing to say (an unmarked text block is fine), and the illustrative
seed does not move. The relabeling check closes that. A block in a language nothing
runs (text and the rest) that holds an ``ash`` command line or a ``$`` prompt line is a
finding, unless it is the output of the run block above it, or it sits in a record of a
past release, or ``scripts/docs_unexecuted_commands_seed.tsv`` lists it. That seed was
measured at main and only shrinks: a line for each such block, the page's path, a tab,
and the first command of the block.

Each case plants the defect the check exists for and requires it to be reported, with a
clean control beside it, so a check that reports everything, or nothing, fails one of
the two.

WHAT THIS DOES NOT CHECK
------------------------
A command in a fence of a language the runner does run, which the runner and the CLI
check already read; or one in a block the parser does not split out (an indented code
block, a fence inside a block quote), which no check of the markers reads.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CHECKS_PATH = REPO_ROOT / "scripts" / "docs_checks.py"
GATE_PATH = REPO_ROOT / "scripts" / "verify_docs_freshness.py"
FENCE = "```"
SCAN = "ash scan --source-dir ."
MESSAGE = "shows a command that nothing runs"


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def checks():
    return _load("_ash_docs_checks", CHECKS_PATH)


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _text(body: str, lang: str = "text") -> str:
    return f"{FENCE}{lang}\n{body}\n{FENCE}\n"


def _page(*blocks: str) -> str:
    return "# Page\n\n" + "\n".join(blocks)


def _seed(root: Path, *lines: str) -> Path:
    """Make root a root that has the seed, which turns the check on for it."""
    return _write(
        root, checks().UNEXECUTED_SEED_FILE, "".join(f"{line}\n" for line in lines)
    )


def _problems(root: Path, *pages: Path):
    return checks().check_markers(list(pages), root)


# ---------------------------------------------------------------------------
# What the check reports
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_a_scan_command_in_a_text_block_fails(tmp_path):
    _seed(tmp_path)
    page = _write(tmp_path, "docs/page.md", _page(_text(SCAN)))

    findings = _problems(tmp_path, page)

    assert [(f.path, f.line) for f in findings] == [("docs/page.md", 3)]
    assert MESSAGE in findings[0].message
    assert SCAN in findings[0].message


@pytest.mark.unit
def test_a_prompt_line_in_a_text_block_fails(tmp_path):
    _seed(tmp_path)
    page = _write(
        tmp_path, "docs/page.md", _page(_text("$ git status\nOn branch main"))
    )

    findings = _problems(tmp_path, page)

    assert [(f.path, f.line) for f in findings] == [("docs/page.md", 3)]
    assert "git status" in findings[0].message


@pytest.mark.unit
@pytest.mark.parametrize("lang", ["markdown", "diff", "console-output", "log", "ini"])
def test_any_language_nothing_runs_is_read_not_only_text(tmp_path, lang):
    _seed(tmp_path)
    body = "+ash scan" if lang == "diff" else SCAN
    page = _write(tmp_path, "docs/page.md", _page(_text(body, lang)))

    findings = _problems(tmp_path, page)

    assert [f.line for f in findings] == [3], findings


@pytest.mark.unit
def test_an_output_sample_after_a_run_block_passes(tmp_path):
    """The output of a block the runner runs is not a command: it is compared with what
    the block prints. A line of it that starts with ash is output."""
    _seed(tmp_path)
    page = _write(
        tmp_path,
        "docs/page.md",
        f"{FENCE}bash\nash --version\n{FENCE}\n\n"
        f"<!-- doctest: output -->\n{FENCE}text\nash 3.8.0\n{FENCE}\n",
    )

    assert _problems(tmp_path, page) == []


@pytest.mark.unit
def test_a_sample_marker_after_a_block_nothing_runs_still_fails(tmp_path):
    """Nothing prints what follows an illustrative block, so it is no output sample, and
    the marker is its own finding."""
    _seed(tmp_path)
    page = _write(
        tmp_path,
        "docs/page.md",
        '<!-- doctest: illustrative reason="needs Docker" -->\n'
        f"{FENCE}bash\ndocker ps\n{FENCE}\n\n"
        f"<!-- doctest: output -->\n{FENCE}text\n{SCAN}\n{FENCE}\n",
    )

    findings = _problems(tmp_path, page)

    assert any(MESSAGE in f.message and f.line == 7 for f in findings), findings
    assert any("marked output but follows no run block" in f.message for f in findings)


@pytest.mark.unit
@pytest.mark.parametrize(
    "rel",
    ["CHANGELOG.md", ".github/release-notes/v3.8.0.md"],
    ids=["changelog", "notes"],
)
def test_a_text_block_in_a_record_of_a_past_release_passes(tmp_path, rel):
    _seed(tmp_path)
    page = _write(tmp_path, rel, _page(_text(SCAN)))

    assert _problems(tmp_path, page) == []


@pytest.mark.unit
def test_a_text_block_that_shows_no_command_passes(tmp_path):
    """Output and prose: the word ash is a command only as the first word of a line, in
    lower case, and a prompt is a ``$`` and a space before a command."""
    _seed(tmp_path)
    page = _write(
        tmp_path,
        "docs/page.md",
        _page(
            _text(
                "Scan complete\nASH finished in 3 seconds\nthe ash command found 3\n"
                "cost: $5 a month\n$HOME is set"
            )
        ),
    )

    assert _problems(tmp_path, page) == []


@pytest.mark.unit
def test_a_command_in_a_block_the_runner_runs_is_left_to_the_cli_check(tmp_path):
    _seed(tmp_path)
    page = _write(
        tmp_path,
        "docs/page.md",
        _page(_text(SCAN, "bash"), _text("print(1)", "python")),
    )

    assert _problems(tmp_path, page) == []


@pytest.mark.unit
def test_a_config_block_is_left_to_the_config_checks(tmp_path):
    _seed(tmp_path)
    page = _write(
        tmp_path,
        "docs/page.md",
        _page(
            '<!-- doctest: config kind=other reason="a settings file" -->\n'
            + _text("run: ash scan\n$ not a prompt here", "yaml")
        ),
    )

    assert _problems(tmp_path, page) == []


@pytest.mark.unit
def test_a_command_continued_over_lines_is_one_command(tmp_path):
    _seed(tmp_path, f"docs/page.md\t{SCAN} --offline")
    page = _write(
        tmp_path,
        "docs/page.md",
        _page(_text("ash scan \\\n  --source-dir . \\\n  --offline")),
    )

    assert _problems(tmp_path, page) == []


@pytest.mark.unit
def test_the_first_command_of_a_block_is_how_the_seed_names_it(tmp_path):
    dc = checks()
    page = _write(
        tmp_path,
        "docs/page.md",
        _page(_text("output first\n  $   uv   run  pytest\nash scan\n")),
    )

    blocks = dc.unexecuted_command_blocks(dc.parse_page(page, tmp_path))

    assert [(block.fence_line, command) for block, command in blocks] == [
        (3, "uv run pytest")
    ]


# ---------------------------------------------------------------------------
# The seed holds what it lists, and only that
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_a_block_the_seed_lists_passes(tmp_path):
    _seed(tmp_path, f"docs/page.md\t{SCAN}")
    page = _write(tmp_path, "docs/page.md", _page(_text(SCAN)))

    assert _problems(tmp_path, page) == []


@pytest.mark.unit
def test_a_block_the_seed_lacks_fails_while_another_is_listed(tmp_path):
    _seed(tmp_path, f"docs/page.md\t{SCAN}")
    page = _write(
        tmp_path, "docs/page.md", _page(_text(SCAN), _text("ash scan --offline"))
    )

    findings = _problems(tmp_path, page)

    assert [f.line for f in findings] == [7]
    assert "ash scan --offline" in findings[0].message


@pytest.mark.unit
def test_two_blocks_with_one_command_need_two_seed_lines(tmp_path):
    _seed(tmp_path, f"docs/page.md\t{SCAN}")
    page = _write(tmp_path, "docs/page.md", _page(_text(SCAN), _text(SCAN)))

    assert [f.line for f in _problems(tmp_path, page)] == [7]

    _seed(tmp_path, f"docs/page.md\t{SCAN}", f"docs/page.md\t{SCAN}")
    assert _problems(tmp_path, page) == []


@pytest.mark.unit
def test_a_converted_block_whose_seed_line_stays_fails(tmp_path):
    seed = _seed(tmp_path, f"docs/page.md\t{SCAN}")
    page = _write(tmp_path, "docs/page.md", _page(_text(SCAN, "bash")))

    findings = _problems(tmp_path, page)

    assert [(f.path, f.line) for f in findings] == [
        (seed.relative_to(tmp_path).as_posix(), 1)
    ]
    assert "no block on this page shows this command" in findings[0].message


@pytest.mark.unit
def test_a_reworded_command_is_a_new_block_and_leaves_its_old_line_behind(tmp_path):
    _seed(tmp_path, f"docs/page.md\t{SCAN}")
    page = _write(tmp_path, "docs/page.md", _page(_text("ash scan --offline")))

    findings = _problems(tmp_path, page)

    assert len(findings) == 2
    assert any(MESSAGE in f.message for f in findings)
    assert any("no block on this page" in f.message for f in findings)


@pytest.mark.unit
def test_relabeling_a_bash_block_as_text_is_caught_where_the_page_already_has_one(
    tmp_path,
):
    """The swap: one text block converted to bash, another bash block fenced as text.
    The count of text blocks is the same, and the commands are not."""
    _seed(tmp_path, f"docs/page.md\t{SCAN}")
    page = _write(
        tmp_path,
        "docs/page.md",
        _page(_text(SCAN, "bash"), _text("ash report --format html")),
    )

    findings = _problems(tmp_path, page)

    assert len(findings) == 2
    assert any("ash report --format html" in f.message for f in findings)


@pytest.mark.unit
@pytest.mark.parametrize(
    "line",
    ["docs/page.md ash scan", "docs/page.md\t", "\tash scan", ""],
    ids=["no tab", "no command", "no page", "blank line"],
)
def test_a_malformed_seed_line_fails(tmp_path, line):
    _seed(tmp_path, line)
    page = _write(tmp_path, "docs/page.md", _page(_text("Scan complete")))

    findings = _problems(tmp_path, page)

    assert any("malformed seed line" in f.message for f in findings), findings


@pytest.mark.unit
def test_a_seed_line_for_a_page_that_does_not_exist_fails(tmp_path):
    seed = _seed(tmp_path, f"docs/gone.md\t{SCAN}")
    page = _write(tmp_path, "docs/page.md", _page(_text("Scan complete")))

    findings = _problems(tmp_path, page)

    assert [(f.path, f.line) for f in findings] == [
        (seed.relative_to(tmp_path).as_posix(), 1)
    ]
    assert "does not exist" in findings[0].message


@pytest.mark.unit
def test_a_root_with_no_seed_file_is_not_held_to_one(tmp_path):
    """The control for the arming rule, as for the illustrative seed."""
    page = _write(tmp_path, "docs/page.md", _page(_text(SCAN)))

    assert _problems(tmp_path, page) == []

    _seed(tmp_path)
    assert [f.line for f in _problems(tmp_path, page)] == [3]


# ---------------------------------------------------------------------------
# The seed is measured at main, and written with the illustrative one
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_the_writer_lists_each_block_in_page_order_with_its_first_command(tmp_path):
    dc = checks()
    first = _write(
        tmp_path,
        "docs/a.md",
        _page(
            _text("ash scan"),
            _text("Scan complete"),
            _text("$ uv tool install ash", "console-output"),
        ),
    )
    second = _write(tmp_path, "docs/b.md", _page(_text(SCAN, "bash")))
    third = _write(tmp_path, "CHANGELOG.md", _page(_text(SCAN)))

    pages = dc.load_pages([first, second, third], tmp_path)

    assert dc.unexecuted_seed_lines(pages) == [
        "docs/a.md\tash scan",
        "docs/a.md\tuv tool install ash",
    ]
    written = dc.write_seeds([first, second, third], tmp_path)
    assert written == [dc.UNEXECUTED_SEED_FILE]
    assert (tmp_path / dc.UNEXECUTED_SEED_FILE).read_text(encoding="utf-8") == (
        "docs/a.md\tash scan\ndocs/a.md\tuv tool install ash\n"
    )
    assert dc.check_markers([first, second, third], tmp_path) == []


@pytest.fixture(scope="module")
def corpus():
    gate = _load("_ash_docs_gate_for_the_unexecuted_ratchet", GATE_PATH)
    return gate.collect_md_files()


def _committed_seed() -> list[str]:
    path = REPO_ROOT / checks().UNEXECUTED_SEED_FILE
    return sorted(path.read_text(encoding="utf-8").splitlines())


@pytest.mark.integration
def test_the_committed_seed_equals_the_baseline_measured_in_the_corpus(corpus):
    dc = checks()

    measured = dc.unexecuted_seed_lines(dc.load_pages(corpus, REPO_ROOT))

    assert _committed_seed() == sorted(measured)
    assert measured, (
        "no block of the corpus shows a command nothing runs; drop the check"
    )


@pytest.mark.integration
def test_the_seed_lists_no_record_of_a_past_release(corpus):
    dc = checks()

    pages = {line.partition("\t")[0] for line in _committed_seed()}

    assert not any(dc.is_historical_doc(page) for page in pages), sorted(pages)


@pytest.mark.integration
def test_the_check_reports_nothing_on_the_corpus(corpus):
    dc = checks()
    pages = dc.load_pages(corpus, REPO_ROOT)

    findings = dc.unexecuted_command_problems(pages, REPO_ROOT)

    assert findings == [], [str(f) for f in findings]
