"""The illustrative blocks only shrink: the seed, the two gates that hold it, and its writer.

WHY THIS EXISTS
---------------
``<!-- doctest: illustrative reason="..." -->`` keeps a block out of the runs, and the
docs are moving to blocks that all run. Without a count, every change that meets a block
it cannot run yet adds one more marker, and the number only grows. So the markers that
exist at main are frozen in a seed (``docs/illustrative-seed/``, one file per page, a
line ``<page path>`` TAB ``<reason>`` for each), and two gates keep it from growing:

* G1, in ``check_markers`` (the lint job, and ``verify_docs_freshness.py`` locally): a
  marker the seed does not list is a finding, and so is a seed line that no marker
  matches, so a commit that converts a block deletes its line in the same commit;
* G2, ``.github/scripts/check-illustrative-ratchet.py`` in the snapshot-trailers job:
  the seed at the head may hold no line the seed at the fork point lacks. G1 alone would
  let a pull request add the line that covers its own new marker.

Each case below plants the defect a gate exists for and requires the gate to report it,
with a clean control beside it, so a gate that reports everything, or nothing, fails one
of the two. G2 reads git history, so its cases build their own repositories in a temporary
directory: a fork point, a head, renames. They never read this checkout's history.

WHAT THIS DOES NOT CHECK
------------------------
That a block runs, or that a reason is a good one: marker_problems and the docs runner
do that. The seed is a count of what is allowed to stay, nothing more.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CHECKS_PATH = REPO_ROOT / "scripts" / "docs_checks.py"
GATE_PATH = REPO_ROOT / "scripts" / "verify_docs_freshness.py"
RATCHET_PATH = REPO_ROOT / ".github" / "scripts" / "check-illustrative-ratchet.py"
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "ash-unified-ci.yml"
CONTRACT_PAGE = "docs/content/contributing/documentation.md"
FENCE = "```"

#: The illustrative markers the parser binds at main, when the seed was first written.
#: Conversions lower the number of lines in the seed; this one never changes.
SEED_AT_MAIN = 599

NEEDS_DOCKER = "needs Docker"
WRITES_BUCKET = "writes to a real bucket"


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


def ratchet():
    return _load("_ash_illustrative_ratchet", RATCHET_PATH)


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _block(reason: str, body: str = "docker ps") -> str:
    return (
        f'<!-- doctest: illustrative reason="{reason}" -->\n{FENCE}bash\n{body}\n'
        f"{FENCE}\n"
    )


def _page(*reasons: str) -> str:
    """A page with one illustrative block per reason; the marker of the n-th is on line
    5n - 2 (the heading and a blank line, then five lines for each block)."""
    return "# Page\n\n" + "\n".join(_block(reason) for reason in reasons)


def _seed_file(page: str) -> str:
    return checks().illustrative_seed_file(page)


def _seed(root: Path, page: str, *reasons: str) -> Path:
    lines = "".join(f"{page}\t{reason}\n" for reason in reasons)
    return _write(root, _seed_file(page), lines)


def _armed(root: Path) -> None:
    """Make root a root that has a seed, which is what turns G1 on for it."""
    (root / checks().ILLUSTRATIVE_SEED_DIR).mkdir(parents=True, exist_ok=True)


def _problems(root: Path, *pages: Path):
    return checks().check_markers(list(pages), root)


# ---------------------------------------------------------------------------
# G1: the seed lists the markers a page has
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_a_seed_that_lists_every_marker_passes_g1(tmp_path):
    page = _write(tmp_path, "docs/page.md", _page(NEEDS_DOCKER, WRITES_BUCKET))
    _seed(tmp_path, "docs/page.md", NEEDS_DOCKER, WRITES_BUCKET)

    assert _problems(tmp_path, page) == []


@pytest.mark.unit
def test_a_new_marker_fails_g1(tmp_path):
    page = _write(tmp_path, "docs/page.md", _page(NEEDS_DOCKER, WRITES_BUCKET))
    _seed(tmp_path, "docs/page.md", NEEDS_DOCKER)

    findings = _problems(tmp_path, page)

    assert [(f.path, f.line) for f in findings] == [("docs/page.md", 8)]
    assert "not in the illustrative seed" in findings[0].message


@pytest.mark.unit
def test_a_converted_marker_whose_seed_line_stays_fails_g1(tmp_path):
    page = _write(tmp_path, "docs/page.md", _page(NEEDS_DOCKER))
    seed = _seed(tmp_path, "docs/page.md", NEEDS_DOCKER, WRITES_BUCKET)

    findings = _problems(tmp_path, page)

    assert [(f.path, f.line) for f in findings] == [
        (seed.relative_to(tmp_path).as_posix(), 2)
    ]
    assert "no illustrative marker" in findings[0].message
    assert WRITES_BUCKET in findings[0].message


@pytest.mark.unit
def test_a_page_with_markers_and_no_seed_file_fails_g1_for_each_marker(tmp_path):
    _armed(tmp_path)
    page = _write(tmp_path, "docs/page.md", _page(NEEDS_DOCKER, WRITES_BUCKET))

    findings = _problems(tmp_path, page)

    assert [f.line for f in findings] == [3, 8]
    assert all("not in the illustrative seed" in f.message for f in findings)


@pytest.mark.unit
def test_two_markers_with_one_reason_need_two_seed_lines(tmp_path):
    page = _write(tmp_path, "docs/page.md", _page(NEEDS_DOCKER, NEEDS_DOCKER))
    _seed(tmp_path, "docs/page.md", NEEDS_DOCKER)

    findings = _problems(tmp_path, page)
    assert [f.line for f in findings] == [8]

    _seed(tmp_path, "docs/page.md", NEEDS_DOCKER, NEEDS_DOCKER)
    assert _problems(tmp_path, page) == []


@pytest.mark.unit
def test_a_reworded_reason_is_a_new_marker_and_leaves_its_old_line_behind(tmp_path):
    page = _write(tmp_path, "docs/page.md", _page("needs the Docker daemon"))
    _seed(tmp_path, "docs/page.md", NEEDS_DOCKER)

    findings = _problems(tmp_path, page)

    assert len(findings) == 2
    assert any("not in the illustrative seed" in f.message for f in findings)
    assert any("no illustrative marker" in f.message for f in findings)


@pytest.mark.unit
def test_a_reason_is_read_with_its_whitespace_collapsed(tmp_path):
    page = _write(tmp_path, "docs/page.md", _page("needs   Docker"))
    _seed(tmp_path, "docs/page.md", NEEDS_DOCKER)

    assert _problems(tmp_path, page) == []


@pytest.mark.unit
def test_a_template_and_the_page_it_renders_each_have_their_own_seed_file(tmp_path):
    page = _write(tmp_path, "docs/page.md", _page(NEEDS_DOCKER))
    template = _write(tmp_path, "docs/page.md.template", _page(NEEDS_DOCKER))
    _seed(tmp_path, "docs/page.md", NEEDS_DOCKER)
    assert _seed_file("docs/page.md") != _seed_file("docs/page.md.template")

    findings = _problems(tmp_path, page, template)
    assert [(f.path, f.line) for f in findings] == [("docs/page.md.template", 3)]

    _seed(tmp_path, "docs/page.md.template", NEEDS_DOCKER)
    assert _problems(tmp_path, page, template) == []


@pytest.mark.unit
def test_a_seed_line_in_another_pages_file_fails_g1(tmp_path):
    first = _write(tmp_path, "docs/a.md", _page(NEEDS_DOCKER))
    second = _write(tmp_path, "docs/b.md", _page(NEEDS_DOCKER))
    # b's line is written into a's file, so two conversion units would share one file.
    _write(
        tmp_path,
        _seed_file("docs/a.md"),
        f"docs/a.md\t{NEEDS_DOCKER}\ndocs/b.md\t{NEEDS_DOCKER}\n",
    )

    findings = _problems(tmp_path, first, second)

    assert any(
        f.path == _seed_file("docs/a.md") and "belongs in" in f.message
        for f in findings
    ), findings


@pytest.mark.unit
@pytest.mark.parametrize(
    "line",
    [
        "docs/page.md needs Docker",
        "docs/page.md\t",
        "\tneeds Docker",
        "",
        "docs/page.md\tneeds  two  spaces",
    ],
    ids=["no tab", "no reason", "no page", "blank line", "uncollapsed whitespace"],
)
def test_a_malformed_seed_line_fails_g1(tmp_path, line):
    page = _write(tmp_path, "docs/page.md", _page(NEEDS_DOCKER))
    _write(tmp_path, _seed_file("docs/page.md"), f"{line}\n")

    findings = _problems(tmp_path, page)

    assert any("malformed seed line" in f.message for f in findings), findings


@pytest.mark.unit
def test_a_seed_line_for_a_page_that_does_not_exist_fails_g1(tmp_path):
    page = _write(tmp_path, "docs/page.md", _page(NEEDS_DOCKER))
    _seed(tmp_path, "docs/page.md", NEEDS_DOCKER)
    gone = _seed(tmp_path, "docs/gone.md", NEEDS_DOCKER)

    findings = _problems(tmp_path, page)

    assert [(f.path, f.line) for f in findings] == [
        (gone.relative_to(tmp_path).as_posix(), 1)
    ]
    assert "does not exist" in findings[0].message


@pytest.mark.unit
def test_a_seed_line_for_a_page_that_exists_but_was_not_handed_over_is_left_alone(
    tmp_path,
):
    """A run over some of the pages, as the tests make, reports no seed line of the rest."""
    page = _write(tmp_path, "docs/page.md", _page(NEEDS_DOCKER))
    _write(tmp_path, "docs/other.md", _page(NEEDS_DOCKER))
    _seed(tmp_path, "docs/page.md", NEEDS_DOCKER)
    _seed(tmp_path, "docs/other.md", NEEDS_DOCKER)

    assert _problems(tmp_path, page) == []


@pytest.mark.unit
def test_a_file_whose_name_encodes_no_page_fails_g1(tmp_path):
    page = _write(tmp_path, "docs/page.md", _page(NEEDS_DOCKER))
    _seed(tmp_path, "docs/page.md", NEEDS_DOCKER)
    stray = _write(tmp_path, f"{checks().ILLUSTRATIVE_SEED_DIR}/notes.tsv", "")

    findings = _problems(tmp_path, page)

    assert [(f.path, f.line) for f in findings] == [
        (stray.relative_to(tmp_path).as_posix(), 1)
    ]
    assert "not the name of a page's seed file" in findings[0].message


@pytest.mark.unit
def test_a_root_with_no_seed_directory_is_not_held_to_one(tmp_path):
    """The control for the arming rule: the checks the unit tests run on a page they
    write in a temporary root say nothing about a seed that root never had. The ratchets
    are armed on this checkout by test_the_ratchets_are_armed_on_this_checkout."""
    page = _write(tmp_path, "docs/page.md", _page(NEEDS_DOCKER))

    assert _problems(tmp_path, page) == []

    _armed(tmp_path)
    assert [f.line for f in _problems(tmp_path, page)] == [3]


@pytest.mark.unit
def test_the_ratchets_are_armed_on_this_checkout():
    """A checkout that loses its seed would stop checking against one without a word, so
    losing it has to fail a test: removing the ratchet is a decision, not a deletion."""
    dc = checks()
    directory = REPO_ROOT / dc.ILLUSTRATIVE_SEED_DIR
    assert directory.is_dir(), f"{dc.ILLUSTRATIVE_SEED_DIR} is gone, and G1 with it"
    assert any(path.suffix == ".tsv" for path in directory.iterdir()), (
        f"{dc.ILLUSTRATIVE_SEED_DIR} holds no seed file"
    )
    assert (REPO_ROOT / dc.UNEXECUTED_SEED_FILE).is_file(), (
        f"{dc.UNEXECUTED_SEED_FILE} is gone, and G4 with it"
    )


# ---------------------------------------------------------------------------
# The seed file of a page: one name, and the name gives the page back
# ---------------------------------------------------------------------------

SEEDED_PAGES = [
    "docs/content/how-to/install.md",
    "docs/content/how-to/install.md.template",
    "ash-agent-plugins/agentic-coding/transpiler/_base/skill.md",
    "ash-agent-plugins/agentic-coding/plugins/cline/.clinerules/01-skill.md",
    "docs/with space/100%.md",
    "docs/a__b/c%2Fd.md",
    "docs/unicode/café.md",
]


@pytest.mark.unit
@pytest.mark.parametrize("page", SEEDED_PAGES)
def test_a_page_has_one_seed_file_name_and_the_name_gives_the_page_back(page):
    dc = checks()

    name = dc.illustrative_seed_name(page)

    assert "/" not in name and name.endswith(".tsv")
    assert dc.illustrative_seed_page(name) == page
    assert dc.illustrative_seed_file(page) == f"{dc.ILLUSTRATIVE_SEED_DIR}/{name}"


@pytest.mark.unit
def test_two_pages_never_share_a_seed_file_name():
    dc = checks()

    names = {dc.illustrative_seed_name(page) for page in SEEDED_PAGES}

    assert len(names) == len(SEEDED_PAGES)


@pytest.mark.unit
def test_the_seed_file_name_of_a_page_is_pinned():
    dc = checks()

    assert (
        dc.illustrative_seed_name("docs/content/how-to/install.md")
        == "docs%2Fcontent%2Fhow-to%2Finstall.md.tsv"
    )
    assert (
        dc.illustrative_seed_name("a/_base/b_c.md.template")
        == "a%2F_base%2Fb_c.md.template.tsv"
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "name",
    ["install.md", "docs%2fpage.md.tsv", "docs/page.md.tsv", "docs%2Fpage.md.tsv.bak"],
    ids=["no suffix", "lower-case escape", "unescaped slash", "other suffix"],
)
def test_a_name_that_is_not_the_one_name_of_a_page_gives_no_page(name):
    assert checks().illustrative_seed_page(name) is None


# ---------------------------------------------------------------------------
# The seed is what the parser binds, written once from main
# ---------------------------------------------------------------------------

BINDING_PAGE = (
    "# Page\n\n"
    '<!-- doctest: illustrative reason="needs Docker" -->\n'
    f"{FENCE}bash\ndocker ps\n{FENCE}\n\n"
    "````markdown\n"
    '<!-- doctest: illustrative reason="inside an example" -->\n'
    f"{FENCE}bash\nash scan\n{FENCE}\n"
    "````\n\n"
    '| `<!-- doctest: illustrative reason="in a table cell" -->` | cell |\n\n'
    '<!-- doctest: illustrative reason="a blank line below" -->\n\n'
    f"{FENCE}bash\ntrue\n{FENCE}\n\n"
    '<!-- doctest: illustrative reason="bound to  python" -->\n'
    f"{FENCE}python\nprint(1)\n{FENCE}\n\n"
    "<!-- doctest: run -->\n"
    f"{FENCE}bash\ntrue\n{FENCE}\n"
)


@pytest.mark.unit
def test_the_seed_lists_the_markers_the_parser_binds_and_no_other(tmp_path):
    """A marker inside an example fence, one in a table cell and one with a blank line
    before its fence govern no block, so none has a line; a run marker is not one."""
    dc = checks()
    page = _write(tmp_path, "docs/page.md", BINDING_PAGE)

    seed = dc.illustrative_seed_lines(dc.load_pages([page], tmp_path))

    assert seed == {
        dc.illustrative_seed_file("docs/page.md"): [
            "docs/page.md\tneeds Docker",
            "docs/page.md\tbound to python",
        ]
    }


@pytest.mark.unit
def test_a_marker_without_a_reason_cannot_be_written_to_the_seed(tmp_path):
    dc = checks()
    page = _write(
        tmp_path,
        "docs/page.md",
        f"<!-- doctest: illustrative -->\n{FENCE}bash\nx\n{FENCE}\n",
    )

    with pytest.raises(ValueError, match="no reason"):
        dc.illustrative_seed_lines(dc.load_pages([page], tmp_path))


@pytest.mark.unit
def test_the_writer_writes_one_file_per_page_and_the_checks_then_pass(tmp_path):
    dc = checks()
    first = _write(tmp_path, "docs/a.md", _page(NEEDS_DOCKER, WRITES_BUCKET))
    second = _write(tmp_path, "docs/b.md.template", _page(NEEDS_DOCKER))
    third = _write(tmp_path, "docs/c.md", "# No markers\n")

    written = dc.write_seeds([first, second, third], tmp_path)

    assert written == sorted(
        [
            dc.illustrative_seed_file("docs/a.md"),
            dc.illustrative_seed_file("docs/b.md.template"),
            dc.UNEXECUTED_SEED_FILE,
        ]
    )
    assert (tmp_path / dc.illustrative_seed_file("docs/a.md")).read_text(
        encoding="utf-8"
    ) == f"docs/a.md\t{NEEDS_DOCKER}\ndocs/a.md\t{WRITES_BUCKET}\n"
    assert dc.check_markers([first, second, third], tmp_path) == []


@pytest.mark.unit
def test_the_writer_refuses_to_run_where_a_seed_exists(tmp_path):
    """It exists to write the seed once, from main. A second run would write the markers
    added since into it, so it refuses, and the seed shrinks by deleting lines."""
    dc = checks()
    page = _write(tmp_path, "docs/a.md", _page(NEEDS_DOCKER))
    dc.write_seeds([page], tmp_path)
    directory = tmp_path / dc.ILLUSTRATIVE_SEED_DIR
    before = {path.name: path.read_bytes() for path in directory.iterdir()}
    page.write_text(_page(NEEDS_DOCKER, WRITES_BUCKET), encoding="utf-8")

    with pytest.raises(FileExistsError, match="already"):
        dc.write_seeds([page], tmp_path)

    assert {path.name: path.read_bytes() for path in directory.iterdir()} == before


# ---------------------------------------------------------------------------
# The seed in this checkout is what the parser binds in it
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def corpus():
    gate = _load("_ash_docs_gate_for_the_ratchet", GATE_PATH)
    return gate.collect_md_files()


def _committed_seed() -> dict[str, list[str]]:
    dc = checks()
    directory = REPO_ROOT / dc.ILLUSTRATIVE_SEED_DIR
    return {
        f"{dc.ILLUSTRATIVE_SEED_DIR}/{path.name}": sorted(
            path.read_text(encoding="utf-8").splitlines()
        )
        for path in sorted(directory.iterdir())
        if path.suffix == ".tsv"
    }


@pytest.mark.integration
def test_the_committed_seed_is_what_the_parser_binds_in_the_corpus(corpus):
    dc = checks()

    expected = dc.illustrative_seed_lines(dc.load_pages(corpus, REPO_ROOT))

    assert _committed_seed() == {
        file: sorted(lines) for file, lines in expected.items()
    }


@pytest.mark.integration
def test_the_seed_holds_no_more_lines_than_main_did(corpus):
    lines = sum(len(text) for text in _committed_seed().values())

    assert 0 < lines <= SEED_AT_MAIN, (
        f"the seed holds {lines} lines; main had {SEED_AT_MAIN}, and it only shrinks"
    )


@pytest.mark.integration
def test_the_two_marker_mentions_that_bind_no_block_have_no_seed_line(corpus):
    """The contract page shows a marker in an example fence and in a table cell. Both are
    text, not markers: only the ones above a block are in the seed."""
    dc = checks()
    path = REPO_ROOT / CONTRACT_PAGE
    page = dc.parse_page(path, REPO_ROOT)
    bound = {line for line, _reason in dc.illustrative_markers(page)}
    lines = path.read_text(encoding="utf-8").split("\n")
    mentioned = {
        number
        for number, line in enumerate(lines, 1)
        if "doctest: illustrative" in line
    }
    unbound = sorted(mentioned - bound)

    seeded = _committed_seed().get(dc.illustrative_seed_file(CONTRACT_PAGE), [])

    assert len(seeded) == len(bound)
    assert len(unbound) >= 2
    texts = [lines[number - 1].lstrip() for number in unbound]
    assert any(text.startswith("<!--") for text in texts), texts
    assert any(text.startswith("|") for text in texts), texts


@pytest.mark.integration
def test_the_seed_checks_report_nothing_on_the_corpus(corpus):
    dc = checks()
    pages = dc.load_pages(corpus, REPO_ROOT)

    findings = dc.illustrative_seed_problems(pages, REPO_ROOT)

    assert findings == [], [str(f) for f in findings]


@pytest.mark.integration
def test_the_seed_writer_refuses_to_run_in_this_checkout():
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(CHECKS_PATH), "write-seeds"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1, result.stdout + result.stderr
    assert "already" in result.stderr


@pytest.mark.integration
def test_the_seed_writer_names_what_it_takes():
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(CHECKS_PATH), "nonsense"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 64, result.stdout + result.stderr
    assert "write-seeds" in result.stderr


# ---------------------------------------------------------------------------
# G2: the seed at the head holds no line the seed at the fork point lacks
# ---------------------------------------------------------------------------

FILLER = "".join(
    f"Line {n} of a page long enough for git to see a rename.\n" for n in range(12)
)


def _long_page(*reasons: str) -> str:
    return "# Page\n\n" + FILLER + "\n" + "\n".join(_block(r) for r in reasons)


class _Repo:
    """A git repository built in a temporary directory. Its base commit holds two pages
    with markers, their seed files and the unexecuted-command seed, unless ``seeded`` is
    false, when it holds one file and no seed at all."""

    def __init__(self, path: Path, seeded: bool = True) -> None:
        self.path = path
        path.mkdir(parents=True)
        self.git("init", "-q")
        if seeded:
            _write(path, "docs/a.md", _long_page(NEEDS_DOCKER, WRITES_BUCKET))
            _write(path, "docs/b.md", _long_page(NEEDS_DOCKER))
            _seed(path, "docs/a.md", NEEDS_DOCKER, WRITES_BUCKET)
            _seed(path, "docs/b.md", NEEDS_DOCKER)
            _write(
                path,
                checks().UNEXECUTED_SEED_FILE,
                "docs/a.md\tash scan --source-dir .\n",
            )
        else:
            _write(path, "README.md", "x\n")
        self.base = self.commit("base")

    def git(self, *args: str) -> str:
        proc = subprocess.run(
            [
                "git",
                "-C",
                str(self.path),
                "-c",
                "user.name=ratchet-test",
                "-c",
                "user.email=ratchet-test@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                *args,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return proc.stdout

    def commit(self, message: str = "change") -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.head()

    def head(self) -> str:
        return self.git("rev-parse", "HEAD").strip()

    def move(self, old: str, new: str) -> None:
        (self.path / new).parent.mkdir(parents=True, exist_ok=True)
        self.git("mv", old, new)

    def added(self) -> list[tuple[str, str]]:
        """(page, text) of each line the head adds to the seeds, by G2's reading."""
        violations, _notes = ratchet().find_added_lines(
            self.path, self.base, self.head()
        )
        return [(v.page, v.text) for v in violations]


@pytest.fixture
def repo(tmp_path):
    return _Repo(tmp_path / "repo")


@pytest.mark.integration
def test_a_range_that_leaves_the_seed_alone_passes_g2(repo):
    repo.commit("empty")

    assert repo.added() == []


@pytest.mark.integration
def test_a_seed_line_added_against_the_base_fails_g2(repo):
    _write(repo.path, "docs/c.md", _long_page(NEEDS_DOCKER))
    _seed(repo.path, "docs/c.md", NEEDS_DOCKER)
    repo.commit("a new page with a new marker, and the line that covers it")

    assert repo.added() == [("docs/c.md", NEEDS_DOCKER)]


@pytest.mark.integration
def test_a_line_added_to_a_page_the_base_seeded_fails_g2(repo):
    _write(repo.path, "docs/b.md", _long_page(NEEDS_DOCKER, WRITES_BUCKET))
    _seed(repo.path, "docs/b.md", NEEDS_DOCKER, WRITES_BUCKET)
    repo.commit("a second marker on b, and its line")

    assert repo.added() == [("docs/b.md", WRITES_BUCKET)]


@pytest.mark.integration
def test_a_second_identical_line_fails_g2(repo):
    _seed(repo.path, "docs/b.md", NEEDS_DOCKER, NEEDS_DOCKER)
    repo.commit("the same reason twice")

    assert repo.added() == [("docs/b.md", NEEDS_DOCKER)]


@pytest.mark.integration
def test_a_converted_marker_passes_g2(repo):
    _write(repo.path, "docs/a.md", _long_page(NEEDS_DOCKER))
    _seed(repo.path, "docs/a.md", NEEDS_DOCKER)
    (repo.path / _seed_file("docs/b.md")).unlink()
    _write(repo.path, "docs/b.md", _long_page())
    repo.commit("one marker of a and all of b converted")

    assert repo.added() == []


@pytest.mark.integration
def test_a_reworded_reason_fails_g2(repo):
    _seed(repo.path, "docs/b.md", "needs the Docker daemon")
    repo.commit("the reason of b reworded")

    assert repo.added() == [("docs/b.md", "needs the Docker daemon")]


@pytest.mark.integration
def test_a_swap_of_one_converted_page_for_a_new_one_fails_g2(repo):
    (repo.path / _seed_file("docs/b.md")).unlink()
    _write(repo.path, "docs/b.md", _long_page())
    _write(repo.path, "docs/c.md", _long_page(NEEDS_DOCKER))
    _seed(repo.path, "docs/c.md", NEEDS_DOCKER)
    repo.commit("b converted, c marked in its place")

    assert repo.added() == [("docs/c.md", NEEDS_DOCKER)]


@pytest.mark.integration
def test_an_edit_of_a_marked_blocks_body_passes_g2(repo):
    text = _long_page(NEEDS_DOCKER, WRITES_BUCKET).replace("docker ps", "docker ps -a")
    _write(repo.path, "docs/a.md", text)
    repo.commit("the body of a marked block edited")

    assert repo.added() == []


@pytest.mark.integration
def test_a_moved_page_with_its_seed_lines_moved_passes_g2(repo):
    repo.move("docs/b.md", "docs/moved/b.md")
    repo.move(_seed_file("docs/b.md"), _seed_file("docs/moved/b.md"))
    _seed(repo.path, "docs/moved/b.md", NEEDS_DOCKER)
    repo.commit("b moved")

    assert repo.added() == []


@pytest.mark.integration
def test_a_moved_page_that_also_gains_a_line_fails_g2_for_that_line_only(repo):
    repo.move("docs/b.md", "docs/moved/b.md")
    repo.move(_seed_file("docs/b.md"), _seed_file("docs/moved/b.md"))
    _seed(repo.path, "docs/moved/b.md", NEEDS_DOCKER, WRITES_BUCKET)
    repo.commit("b moved, and a line added")

    assert repo.added() == [("docs/moved/b.md", WRITES_BUCKET)]


@pytest.mark.integration
def test_a_seed_line_that_names_another_page_without_a_rename_fails_g2(repo):
    """Paths are mapped through git's renames and nothing else, so a line that is simply
    pointed at another page is a new line."""
    _write(repo.path, "docs/c.md", _long_page(NEEDS_DOCKER))
    _seed(repo.path, "docs/b.md")
    _seed(repo.path, "docs/c.md", NEEDS_DOCKER)
    repo.commit("b's line pointed at c")

    assert repo.added() == [("docs/c.md", NEEDS_DOCKER)]


@pytest.mark.integration
def test_the_unexecuted_command_seed_is_held_the_same_way(repo):
    path = repo.path / checks().UNEXECUTED_SEED_FILE
    path.write_text(
        "docs/a.md\tash scan --source-dir .\ndocs/b.md\tash scan --offline\n",
        encoding="utf-8",
    )
    repo.commit("a command line added to the seed")
    assert repo.added() == [("docs/b.md", "ash scan --offline")]

    path.write_text("", encoding="utf-8")
    repo.commit("and then all of them converted")
    assert repo.added() == []


@pytest.mark.integration
def test_a_range_that_introduces_the_seed_has_nothing_to_compare_with(tmp_path):
    """The pull request that adds the seed has no seed at its fork point. It passes with
    a note, and every later range is held to the seed it left."""
    repo = _Repo(tmp_path / "repo", seeded=False)
    _write(repo.path, "docs/a.md", _long_page(NEEDS_DOCKER))
    _seed(repo.path, "docs/a.md", NEEDS_DOCKER)
    head = repo.commit("the seed")

    violations, notes = ratchet().find_added_lines(repo.path, repo.base, head)

    assert violations == []
    assert any("not in the base" in note for note in notes), notes


@pytest.mark.integration
def test_the_script_exits_one_on_an_added_line_and_zero_on_a_clean_range(repo):
    clean = repo.commit("nothing")
    _seed(repo.path, "docs/b.md", NEEDS_DOCKER, "an added reason")
    dirty = repo.commit("a line")

    def run(head: str):
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(RATCHET_PATH),
                "--repo",
                str(repo.path),
                "--base",
                repo.base,
                "--head",
                head,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    passed, failed = run(clean), run(dirty)

    assert passed.returncode == 0, passed.stdout + passed.stderr
    assert failed.returncode == 1, failed.stdout + failed.stderr
    assert "an added reason" in failed.stdout
    assert "::error" in failed.stdout


def _event(tmp_path: Path, monkeypatch, name: str, payload: dict) -> None:
    path = tmp_path / "event.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_NAME", name)
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(path))


@pytest.mark.integration
def test_a_pull_request_is_read_from_its_fork_point_to_its_head(
    repo, tmp_path, monkeypatch
):
    _seed(repo.path, "docs/b.md", NEEDS_DOCKER, "an added reason")
    head = repo.commit("a line")
    payload = {"pull_request": {"base": {"sha": repo.base}, "head": {"sha": head}}}
    _event(tmp_path, monkeypatch, "pull_request", payload)

    assert ratchet().main(["--repo", str(repo.path)]) == 1

    payload["pull_request"]["head"]["sha"] = repo.base
    _event(tmp_path, monkeypatch, "pull_request", payload)
    assert ratchet().main(["--repo", str(repo.path)]) == 0


@pytest.mark.integration
def test_a_merge_queue_entry_is_read_from_its_base_to_its_head(
    repo, tmp_path, monkeypatch
):
    _seed(repo.path, "docs/b.md", NEEDS_DOCKER, "an added reason")
    head = repo.commit("a line")
    payload = {"merge_group": {"base_sha": repo.base, "head_sha": head}}
    _event(tmp_path, monkeypatch, "merge_group", payload)

    assert ratchet().main(["--repo", str(repo.path)]) == 1


@pytest.mark.integration
def test_a_fork_point_is_where_the_pull_request_left_main_not_where_main_is(
    repo, tmp_path, monkeypatch
):
    """Main moved on and shrank the seed (a conversion elsewhere). The pull request, cut
    before that, leaves the seed alone and must not be charged for the difference."""
    main = repo.git("rev-parse", "--abbrev-ref", "HEAD").strip()
    repo.git("checkout", "-q", "-b", "feature")
    feature = repo.commit("the pull request, which leaves the seed alone")
    repo.git("checkout", "-q", main)
    (repo.path / _seed_file("docs/b.md")).unlink()
    _write(repo.path, "docs/b.md", _long_page())
    moved_on = repo.commit("main converted b")
    payload = {"pull_request": {"base": {"sha": moved_on}, "head": {"sha": feature}}}
    _event(tmp_path, monkeypatch, "pull_request", payload)

    assert ratchet().main(["--repo", str(repo.path)]) == 0


# ---------------------------------------------------------------------------
# The self-test, and that it can fail
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_the_script_passes_its_own_self_test():
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(RATCHET_PATH), "--self-test"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "0 failure(s)" in result.stdout


@pytest.mark.integration
def test_the_self_test_fails_when_the_comparison_finds_nothing(monkeypatch):
    """A checker that has degenerated into finding nothing reads as a clean tree, so the
    self-test is what notices: with the comparison neutered, the planted lines it must
    flag go unflagged and the self-test exits non-zero."""
    module = ratchet()
    monkeypatch.setattr(module, "find_added_lines", lambda *_a, **_k: ([], []))

    assert module.self_test() == 1


@pytest.mark.integration
def test_the_self_test_fails_when_the_comparison_flags_everything(monkeypatch):
    module = ratchet()
    real = module.find_added_lines

    def everything(repo, base, head):
        violations, notes = real(repo, base, head)
        planted = module.Violation("planted", "x", "docs/x.md", "docs/x.md", "x", 1)
        return [*violations, planted], notes

    monkeypatch.setattr(module, "find_added_lines", everything)

    assert module.self_test() == 1


# ---------------------------------------------------------------------------
# The workflow runs it, and the contract page says what it holds
# ---------------------------------------------------------------------------


def _snapshot_trailers_steps() -> list[dict]:
    import yaml

    workflow = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    job = workflow["jobs"]["snapshot-trailers"]
    assert "if" not in job, "a job-level `if:` that can be false reads as a failure"
    return job["steps"]


@pytest.mark.unit
def test_the_snapshot_trailers_job_runs_the_ratchet_after_its_trailer_step():
    steps = _snapshot_trailers_steps()
    runs = [str(step.get("run", "")) for step in steps]
    trailers = next(
        i for i, run in enumerate(runs) if "check-snapshot-trailers.py" in run
    )
    ratchets = [i for i, run in enumerate(runs) if "check-illustrative-ratchet" in run]

    assert len(ratchets) == 1, runs
    index = ratchets[0]
    assert index > trailers
    run = runs[index]
    assert "set -euo pipefail" in run
    assert run.index("--self-test") < run.rindex("check-illustrative-ratchet.py")
    assert "if" not in steps[index], "the ratchet is for every event the job runs on"


@pytest.mark.unit
def test_the_contract_page_says_what_fails_how_to_convert_and_that_the_seed_shrinks():
    text = (REPO_ROOT / CONTRACT_PAGE).read_text(encoding="utf-8")

    for needle in (
        "docs/illustrative-seed",
        "only shrinks",
        "check-illustrative-ratchet.py",
        "docs_unexecuted_commands_seed.tsv",
        "%2F",
    ):
        assert needle in text, f"{CONTRACT_PAGE} does not mention {needle}"
