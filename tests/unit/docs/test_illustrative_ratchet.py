"""The illustrative blocks only shrink: the seed, the two checks that hold it, its writer.

WHY THIS EXISTS
---------------
``<!-- doctest: illustrative reason="..." -->`` keeps a block out of the runs, and the
docs are moving to blocks that all run. Without a count, every change that meets a block
it cannot run yet adds one more marker, and the number only grows. So the markers that
exist at main are frozen in a seed (``docs/illustrative-seed/``, one file per page, a
line ``<page path>`` TAB ``<reason>`` for each), and two gates keep it from growing:

* the seed check, in ``check_markers`` (the lint job, and ``verify_docs_freshness.py``
  locally): a marker the seed does not list is a finding, and so is a seed line that no
  marker matches, so a commit that converts a block deletes its line in the same commit;
* the fork-point check, ``.github/scripts/check-illustrative-ratchet.py`` in the
  snapshot-trailers job: the seed at the head may hold no line the seed at the fork
  point lacks. The seed check alone would let a pull request add the line that covers
  its own new marker.

Each case below plants the defect a check exists for and requires the check to report
it, with a clean control beside it, so a check that reports everything, or nothing,
fails one of the two. The fork-point check reads git history, so its cases build their
own repositories in a temporary directory: a fork point, a head, renames. They never
read this checkout's history.

WHAT THIS DOES NOT CHECK
------------------------
That a block runs, or that a reason is a good one: marker_problems and the docs runner
do that. The seed is a count of what is allowed to stay, nothing more.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CHECKS_PATH = REPO_ROOT / "scripts" / "docs_checks.py"
GATE_PATH = REPO_ROOT / "scripts" / "verify_docs_freshness.py"
RATCHET_PATH = REPO_ROOT / ".github" / "scripts" / "check-illustrative-ratchet.py"
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "ash-unified-ci.yml"
CONTRACT_PAGE = "docs/content/contributing/documentation.md"
FENCE = "```"

#: The markers the parser binds at main that keep a block out of the runs, as the seed
#: counts them: 599 ``illustrative`` markers, 25 ``runner=none`` markers and 4 bare
#: ``save-as=`` markers. Conversions lower the number of lines in the seed; this one
#: never changes.
SEED_AT_MAIN = 628

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
    """Write ``text`` with a newline that is the same on every platform: the files are
    committed to git, and a platform newline would put a carriage return in a seed line."""
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def _clean_environment() -> dict[str, str]:
    """This process's environment without the variables git exports to a hook, and with
    no global or system git configuration: what a test's git and script processes get.

    A hook that runs pytest (pre-commit, pre-push) hands it GIT_DIR, GIT_WORK_TREE and
    GIT_INDEX_FILE, which override ``git -C``: every ``add -A`` and ``commit`` of a
    temporary repository below would then land in the caller's own repository. The
    global configuration leaks in the same way, a ``core.fsmonitor`` that starts a
    daemon in each of them among it.
    """
    clean = {
        name: value
        for name, value in os.environ.items()
        if not name.upper().startswith("GIT_")
    }
    clean["GIT_CONFIG_GLOBAL"] = os.devnull
    clean["GIT_CONFIG_NOSYSTEM"] = "1"
    return clean


@contextlib.contextmanager
def _clean_process_environment():
    """This process's environment, cleaned as _clean_environment says, for the calls into
    the script that run git here: its git helper reads the environment from this process.
    """
    with mock.patch.dict(os.environ, _clean_environment(), clear=True):
        yield


@pytest.fixture(autouse=True)
def _what_git_exports_to_a_hook_stays_out_of_every_test(monkeypatch):
    for name in list(os.environ):
        if name.upper().startswith("GIT_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


@pytest.mark.unit
def test_every_test_runs_with_no_git_variable_and_no_global_git_configuration():
    """What the fixture above leaves behind is the only git state a test starts with. The
    variables a hook exports are gone before a test reads them, so nothing else in this
    file would notice the fixture stop running until a hook started pytest."""
    git_variables = sorted(
        name for name in os.environ if name.upper().startswith("GIT_")
    )

    assert git_variables == ["GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM"]
    assert os.environ["GIT_CONFIG_GLOBAL"] == os.devnull
    assert os.environ["GIT_CONFIG_NOSYSTEM"] == "1"


def _plain_git(path: Path, *args: str) -> str:
    """git on a repository this test made, with none of the variables a hook exports."""
    proc = subprocess.run(
        [
            "git",
            "-C",
            str(path),
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
        env=_clean_environment(),
    )
    return proc.stdout


def _run_script(path: Path, *args: str) -> subprocess.CompletedProcess:
    """A script of this checkout as a child process, in an environment a hook cannot
    reach."""
    return subprocess.run(
        [sys.executable, "-I", "-B", str(path), *args],
        capture_output=True,
        text=True,
        check=False,
        env=_clean_environment(),
    )


def _main(*argv: str) -> int:
    """The script's main, in this process, in an environment a hook cannot reach."""
    with _clean_process_environment():
        return ratchet().main(list(argv))


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
    """Make root a root that has a seed, which turns the seed check on for it."""
    (root / checks().ILLUSTRATIVE_SEED_DIR).mkdir(parents=True, exist_ok=True)


def _problems(root: Path, *pages: Path):
    return checks().check_markers(list(pages), root)


# ---------------------------------------------------------------------------
# The seed check: the seed lists the markers a page has
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_a_seed_that_lists_every_marker_passes_the_seed_check(tmp_path):
    page = _write(tmp_path, "docs/page.md", _page(NEEDS_DOCKER, WRITES_BUCKET))
    _seed(tmp_path, "docs/page.md", NEEDS_DOCKER, WRITES_BUCKET)

    assert _problems(tmp_path, page) == []


@pytest.mark.unit
def test_a_new_marker_fails_the_seed_check(tmp_path):
    page = _write(tmp_path, "docs/page.md", _page(NEEDS_DOCKER, WRITES_BUCKET))
    _seed(tmp_path, "docs/page.md", NEEDS_DOCKER)

    findings = _problems(tmp_path, page)

    assert [(f.path, f.line) for f in findings] == [("docs/page.md", 8)]
    assert "not in the illustrative seed" in findings[0].message


@pytest.mark.unit
def test_a_converted_marker_whose_seed_line_stays_fails_the_seed_check(tmp_path):
    page = _write(tmp_path, "docs/page.md", _page(NEEDS_DOCKER))
    seed = _seed(tmp_path, "docs/page.md", NEEDS_DOCKER, WRITES_BUCKET)

    findings = _problems(tmp_path, page)

    assert [(f.path, f.line) for f in findings] == [
        (seed.relative_to(tmp_path).as_posix(), 2)
    ]
    assert "no illustrative marker" in findings[0].message
    assert WRITES_BUCKET in findings[0].message


@pytest.mark.unit
def test_a_page_with_markers_and_no_seed_file_fails_for_each_marker(tmp_path):
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
def test_a_seed_line_in_another_pages_file_fails_the_seed_check(tmp_path):
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
def test_a_malformed_seed_line_fails_the_seed_check(tmp_path, line):
    page = _write(tmp_path, "docs/page.md", _page(NEEDS_DOCKER))
    _write(tmp_path, _seed_file("docs/page.md"), f"{line}\n")

    findings = _problems(tmp_path, page)

    assert any("malformed seed line" in f.message for f in findings), findings


@pytest.mark.unit
def test_a_seed_line_for_a_page_that_does_not_exist_fails_the_seed_check(tmp_path):
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
    """A run over some of the pages, as the tests make, reports no line of the rest."""
    page = _write(tmp_path, "docs/page.md", _page(NEEDS_DOCKER))
    _write(tmp_path, "docs/other.md", _page(NEEDS_DOCKER))
    _seed(tmp_path, "docs/page.md", NEEDS_DOCKER)
    _seed(tmp_path, "docs/other.md", NEEDS_DOCKER)

    assert _problems(tmp_path, page) == []


@pytest.mark.unit
def test_a_file_whose_name_encodes_no_page_fails_the_seed_check(tmp_path):
    page = _write(tmp_path, "docs/page.md", _page(NEEDS_DOCKER))
    _seed(tmp_path, "docs/page.md", NEEDS_DOCKER)
    stray = _write(tmp_path, f"{checks().ILLUSTRATIVE_SEED_DIR}/notes.tsv", "")

    findings = _problems(tmp_path, page)

    assert [(f.path, f.line) for f in findings] == [
        (stray.relative_to(tmp_path).as_posix(), 1)
    ]
    assert "not the name of a page's seed file" in findings[0].message


NEEDS_A_TOKEN = "needs a token"
RUNNER_NONE = f'runner=none reason="{NEEDS_A_TOKEN}"'


def _pipeline(*keys: str) -> str:
    """A GitHub Actions block under a marker that carries ``keys``."""
    marker = " ".join(("config", "kind=github-actions", *keys))
    return f"<!-- doctest: {marker} -->\n{FENCE}yaml\non: push\n{FENCE}\n"


def _saved(path: str, lang: str = "bash", mode: str = "") -> str:
    """A block under a marker that saves it at ``path``, and runs it when ``mode`` says."""
    marker = f"{mode} save-as={path}".strip()
    return f"<!-- doctest: {marker} -->\n{FENCE}{lang}\nash scan\n{FENCE}\n"


@pytest.mark.unit
def test_a_pipeline_no_runner_runs_needs_a_seed_line(tmp_path):
    """``runner=none`` keeps a block out of the runs as ``illustrative`` does, and its
    reason follows the same rules, so the seed counts it, with its reason."""
    _armed(tmp_path)
    page = _write(tmp_path, "docs/page.md", "# Page\n\n" + _pipeline(RUNNER_NONE))

    findings = _problems(tmp_path, page)

    assert [(f.path, f.line) for f in findings] == [("docs/page.md", 3)]
    assert "not in the illustrative seed" in findings[0].message
    assert NEEDS_A_TOKEN in findings[0].message

    _seed(tmp_path, "docs/page.md", f"runner=none: {NEEDS_A_TOKEN}")
    assert _problems(tmp_path, page) == []


@pytest.mark.unit
def test_a_pipeline_a_runner_now_runs_leaves_its_old_seed_line_behind(tmp_path):
    seed = _seed(tmp_path, "docs/page.md", f"runner=none: {NEEDS_A_TOKEN}")
    page = _write(tmp_path, "docs/page.md", "# Page\n\n" + _pipeline())

    findings = _problems(tmp_path, page)

    assert [(f.path, f.line) for f in findings] == [
        (seed.relative_to(tmp_path).as_posix(), 1)
    ]
    assert "no illustrative marker" in findings[0].message


@pytest.mark.unit
@pytest.mark.parametrize(
    ("lang", "path"),
    [
        ("bash", "tools/check.sh"),
        ("python", "tools/check.py"),
        ("powershell", "tools/check.ps1"),
    ],
    ids=["shell", "python", "powershell"],
)
def test_a_block_saved_and_never_run_needs_a_seed_line(tmp_path, lang, path):
    """``save-as=`` alone saves a shell or Python block and does not run it, which takes
    it out of the runs without an ``illustrative`` marker."""
    _armed(tmp_path)
    page = _write(tmp_path, "docs/page.md", "# Page\n\n" + _saved(path, lang))

    findings = _problems(tmp_path, page)

    assert [(f.path, f.line) for f in findings] == [("docs/page.md", 3)]
    assert "not in the illustrative seed" in findings[0].message

    _seed(tmp_path, "docs/page.md", f"save-as={path}")
    assert _problems(tmp_path, page) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    ("block", "why"),
    [
        (_saved("tools/check.sh", "bash", "run"), "it is saved and run"),
        (_saved("tools/check.py", "python", "run"), "it is saved and run"),
        (_saved(".ash.yaml", "yaml"), "a config block is still validated"),
        (_saved("docs/usage.md", "markdown"), "it is a file, not a command"),
        (_saved("notes.txt", "text"), "it is a file, not a command"),
    ],
    ids=["run shell", "run python", "config", "markdown", "text"],
)
def test_a_saved_block_that_is_run_or_is_no_command_has_no_seed_line(
    tmp_path, block, why
):
    """The controls for the case above: each is saved with ``save-as=`` and none is a
    shell or Python block that is saved and never run."""
    _armed(tmp_path)
    page = _write(tmp_path, "docs/page.md", "# Page\n\n" + block)

    assert _problems(tmp_path, page) == [], why


@pytest.mark.unit
def test_the_seed_lists_every_marker_that_keeps_a_block_out_of_the_runs(tmp_path):
    dc = checks()
    text = "\n".join(
        [
            "# Page\n",
            _block(NEEDS_DOCKER),
            _pipeline(RUNNER_NONE),
            _saved("tools/check.sh"),
            _saved("tools/ok.sh", "bash", "run"),
        ]
    )
    page = _write(tmp_path, "docs/page.md", text)

    seed = dc.illustrative_seed_lines(dc.load_pages([page], tmp_path))

    assert seed == {
        dc.illustrative_seed_file("docs/page.md"): [
            f"docs/page.md\t{NEEDS_DOCKER}",
            f"docs/page.md\trunner=none: {NEEDS_A_TOKEN}",
            "docs/page.md\tsave-as=tools/check.sh",
        ]
    }


@pytest.mark.unit
def test_a_runner_none_marker_in_an_example_fence_binds_no_block(tmp_path):
    dc = checks()
    example = f"````markdown\n{_pipeline(RUNNER_NONE)}{_saved('tools/check.sh')}````\n"
    page = _write(tmp_path, "docs/page.md", f"# Page\n\n{example}")

    assert dc.illustrative_seed_lines(dc.load_pages([page], tmp_path)) == {}


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
    assert (REPO_ROOT / dc.ILLUSTRATIVE_SEED_DIR).is_dir(), (
        f"{dc.ILLUSTRATIVE_SEED_DIR} is gone, and the seed check with it. Deleting the "
        "last seed file leaves no directory in git: keep a .gitkeep in it, so that an "
        "empty seed still refuses every marker"
    )
    assert (REPO_ROOT / dc.ILLUSTRATIVE_SEED_DIR / ".gitkeep").is_file(), (
        f"{dc.ILLUSTRATIVE_SEED_DIR}/.gitkeep is gone. It is what keeps the directory in "
        "git once the last page's file is deleted: without it the seed check turns "
        "itself off, and the fork-point check reads every later range as one that "
        "introduces the seed and compares nothing"
    )
    assert (REPO_ROOT / dc.UNEXECUTED_SEED_FILE).is_file(), (
        f"{dc.UNEXECUTED_SEED_FILE} is gone, and the check of commands in blocks "
        "nothing runs with it. Delete its last line, not the file: an empty seed still "
        "refuses every such command"
    )


@pytest.mark.unit
def test_the_ci_script_reads_the_seeds_the_checks_read():
    """The CI script names the two seeds itself. A move of either in docs_checks fails
    here, rather than leave the script comparing files that no longer exist and finding
    nothing."""
    dc, script = checks(), ratchet()

    assert script.ILLUSTRATIVE_SEED_DIR == dc.ILLUSTRATIVE_SEED_DIR
    assert script.ILLUSTRATIVE_SEED_SUFFIX == dc.ILLUSTRATIVE_SEED_SUFFIX
    assert script.UNEXECUTED_SEED_FILE == dc.UNEXECUTED_SEED_FILE


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
    [
        "install.md",
        "docs%2fpage.md.tsv",
        "docs/page.md.tsv",
        "docs%2Fpage.md.tsv.bak",
        "notes.tsv",
        "docs%2Fpage.txt.tsv",
    ],
    ids=[
        "no suffix",
        "lower-case escape",
        "unescaped slash",
        "other suffix",
        "no page",
        "not a markdown page",
    ],
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


def _files_under(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


@pytest.mark.unit
@pytest.mark.parametrize(
    "present",
    ["only the directory", "only the file", "both"],
)
def test_the_writer_refuses_to_run_where_any_seed_exists(tmp_path, present):
    """A writer that refused only when both seeds exist, or looked at one of them, would
    let ``rm -r docs/illustrative-seed`` and ``write-seeds`` rebuild the illustrative
    seed with every marker added since, so each seed alone is refused, and nothing in
    the root changes."""
    dc = checks()
    page = _write(tmp_path, "docs/a.md", _page(NEEDS_DOCKER))
    if present != "only the file":
        _write(tmp_path, f"{dc.ILLUSTRATIVE_SEED_DIR}/.gitkeep", "")
    if present != "only the directory":
        _write(tmp_path, dc.UNEXECUTED_SEED_FILE, "")
    before = _files_under(tmp_path)

    with pytest.raises(FileExistsError, match="already"):
        dc.write_seeds([page], tmp_path)

    assert _files_under(tmp_path) == before


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

    assert 0 <= lines <= SEED_AT_MAIN, (
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
    """Where both seeds are gone the writer does not refuse: it writes about 600 lines of
    seed into the source tree, built from the pages as they are now, and the arming test
    then passes on the next run, so the deletion it exists to report is hidden. So the
    writer is not started unless both seeds are here."""
    dc = checks()
    missing = [
        rel
        for rel, present in (
            (dc.ILLUSTRATIVE_SEED_DIR, (REPO_ROOT / dc.ILLUSTRATIVE_SEED_DIR).is_dir()),
            (dc.UNEXECUTED_SEED_FILE, (REPO_ROOT / dc.UNEXECUTED_SEED_FILE).is_file()),
        )
        if not present
    ]
    assert not missing, (
        f"{missing} is gone from this checkout, so the writer was not started: it would "
        "write both seeds into the tree and hide the deletion. Restore the seeds; "
        "test_the_ratchets_are_armed_on_this_checkout names which"
    )

    result = _run_script(CHECKS_PATH, "write-seeds")

    assert result.returncode == 1, result.stdout + result.stderr
    assert "already" in result.stderr


@pytest.mark.integration
def test_the_seed_writer_names_what_it_takes():
    result = _run_script(CHECKS_PATH, "nonsense")

    assert result.returncode == 64, result.stdout + result.stderr
    assert "write-seeds" in result.stderr


# ---------------------------------------------------------------------------
# The fork-point check: the seed at the head holds no line the fork point lacks
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
        return _plain_git(self.path, *args)

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
        """(page, text) of each line the head adds to the seeds, as the script reads."""
        return [(v.page, v.text) for v in _violations(self)]


@pytest.fixture
def repo(tmp_path):
    return _Repo(tmp_path / "repo")


@pytest.mark.integration
def test_a_range_that_leaves_the_seed_alone_passes(repo):
    repo.commit("empty")

    assert repo.added() == []


@pytest.mark.integration
def test_a_seed_line_added_against_the_base_fails(repo):
    _write(repo.path, "docs/c.md", _long_page(NEEDS_DOCKER))
    _seed(repo.path, "docs/c.md", NEEDS_DOCKER)
    repo.commit("a new page with a new marker, and the line that covers it")

    assert repo.added() == [("docs/c.md", NEEDS_DOCKER)]


@pytest.mark.integration
def test_a_line_added_to_a_page_the_base_seeded_fails(repo):
    _write(repo.path, "docs/b.md", _long_page(NEEDS_DOCKER, WRITES_BUCKET))
    _seed(repo.path, "docs/b.md", NEEDS_DOCKER, WRITES_BUCKET)
    repo.commit("a second marker on b, and its line")

    assert repo.added() == [("docs/b.md", WRITES_BUCKET)]


@pytest.mark.integration
def test_a_second_identical_line_fails(repo):
    _seed(repo.path, "docs/b.md", NEEDS_DOCKER, NEEDS_DOCKER)
    repo.commit("the same reason twice")

    assert repo.added() == [("docs/b.md", NEEDS_DOCKER)]


@pytest.mark.integration
def test_a_converted_marker_passes(repo):
    _write(repo.path, "docs/a.md", _long_page(NEEDS_DOCKER))
    _seed(repo.path, "docs/a.md", NEEDS_DOCKER)
    (repo.path / _seed_file("docs/b.md")).unlink()
    _write(repo.path, "docs/b.md", _long_page())
    repo.commit("one marker of a and all of b converted")

    assert repo.added() == []


@pytest.mark.integration
def test_a_reworded_reason_fails(repo):
    _seed(repo.path, "docs/b.md", "needs the Docker daemon")
    repo.commit("the reason of b reworded")

    assert repo.added() == [("docs/b.md", "needs the Docker daemon")]


@pytest.mark.integration
def test_a_swap_of_one_converted_page_for_a_new_one_fails(repo):
    (repo.path / _seed_file("docs/b.md")).unlink()
    _write(repo.path, "docs/b.md", _long_page())
    _write(repo.path, "docs/c.md", _long_page(NEEDS_DOCKER))
    _seed(repo.path, "docs/c.md", NEEDS_DOCKER)
    repo.commit("b converted, c marked in its place")

    assert repo.added() == [("docs/c.md", NEEDS_DOCKER)]


@pytest.mark.integration
def test_an_edit_of_a_marked_blocks_body_passes(repo):
    text = _long_page(NEEDS_DOCKER, WRITES_BUCKET).replace("docker ps", "docker ps -a")
    _write(repo.path, "docs/a.md", text)
    repo.commit("the body of a marked block edited")

    assert repo.added() == []


@pytest.mark.integration
def test_a_moved_page_with_its_seed_lines_moved_passes(repo):
    repo.move("docs/b.md", "docs/moved/b.md")
    repo.move(_seed_file("docs/b.md"), _seed_file("docs/moved/b.md"))
    _seed(repo.path, "docs/moved/b.md", NEEDS_DOCKER)
    repo.commit("b moved")

    assert repo.added() == []


@pytest.mark.integration
def test_a_moved_page_that_also_gains_a_line_fails_for_that_line_only(repo):
    repo.move("docs/b.md", "docs/moved/b.md")
    repo.move(_seed_file("docs/b.md"), _seed_file("docs/moved/b.md"))
    _seed(repo.path, "docs/moved/b.md", NEEDS_DOCKER, WRITES_BUCKET)
    repo.commit("b moved, and a line added")

    assert repo.added() == [("docs/moved/b.md", WRITES_BUCKET)]


@pytest.mark.integration
def test_a_seed_line_that_names_another_page_without_a_rename_fails(repo):
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

    with _clean_process_environment():
        violations, notes = ratchet().find_added_lines(repo.path, repo.base, head)

    assert violations == []
    assert any("not in the base" in note for note in notes), notes


def _violations(repo: _Repo):
    """What the script finds in the range from the repository's base to its head."""
    with _clean_process_environment():
        violations, _notes = ratchet().find_added_lines(
            repo.path, repo.base, repo.head()
        )
    return violations


def _lose(repo: _Repo, *rels: str) -> str:
    """Delete each of ``rels`` (a file, or a directory with what it holds) and commit
    that, then make the commit the fork point: a base that has lost them. Its sha."""
    for rel in rels:
        target = repo.path / rel
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
    repo.base = repo.commit("the seed deleted")
    return repo.base


def _ratchet_cli(repo: _Repo, head: str) -> subprocess.CompletedProcess:
    """The script as a developer runs it, with ``--base``: a child process comparing the
    repository's base with ``head``."""
    return _run_script(
        RATCHET_PATH, "--repo", str(repo.path), "--base", repo.base, "--head", head
    )


def _summary(capsys) -> str:
    """The one summary line the script printed: the range it compared, and what it found.
    Exit 0 also means "no range, nothing to do", which prints no such line, so a test
    that reads only the exit code cannot tell a clean comparison from none."""
    lines = [
        line
        for line in capsys.readouterr().out.splitlines()
        if line.startswith("illustrative ratchet (")
    ]
    assert len(lines) == 1, f"no range was compared, or two were: {lines}"
    return lines[0]


def _compared(what: str, base: str, head: str, found: int) -> str:
    return (
        f"illustrative ratchet ({what}, {base[:10]}..{head[:10]}): "
        f"{found} line(s) added to the seeds"
    )


@pytest.mark.integration
@pytest.mark.parametrize(
    ("seed", "constant"),
    [
        ("illustrative", "ILLUSTRATIVE_SEED_DIR"),
        ("unexecuted", "UNEXECUTED_SEED_FILE"),
    ],
    ids=["the illustrative seed", "the unexecuted-command seed"],
)
def test_a_fork_point_that_lost_a_seed_fails_while_the_range_leaves_it_gone(
    repo, seed, constant
):
    """Converting the last page deletes its file, and git keeps no empty directory, so the
    seed is gone from every commit after it. A range cut there has no seed at its fork
    point. That used to read as a range that introduces one, with nothing to compare, so
    a marker and the line that covers it were never held to anything again."""
    lost = _lose(repo, getattr(checks(), constant))
    repo.commit("a change that leaves the seed gone")

    violations = _violations(repo)

    assert [(v.seed, v.page, v.text) for v in violations] == [(seed, "", lost)]


@pytest.mark.integration
def test_a_range_that_restores_a_lost_seed_as_it_was_passes(repo):
    dc = checks()
    before = repo.base
    _lose(repo, dc.ILLUSTRATIVE_SEED_DIR, dc.UNEXECUTED_SEED_FILE)
    repo.git(
        "checkout",
        "-q",
        before,
        "--",
        dc.ILLUSTRATIVE_SEED_DIR,
        dc.UNEXECUTED_SEED_FILE,
    )
    repo.commit("the seeds restored")

    assert _violations(repo) == []


@pytest.mark.integration
def test_a_range_that_restores_a_lost_seed_with_an_added_line_fails_for_that_line(repo):
    dc = checks()
    before = repo.base
    _lose(repo, dc.ILLUSTRATIVE_SEED_DIR)
    repo.git("checkout", "-q", before, "--", dc.ILLUSTRATIVE_SEED_DIR)
    _seed(repo.path, "docs/b.md", NEEDS_DOCKER, "an added reason")
    repo.commit("the seed restored, with a line added")

    assert repo.added() == [("docs/b.md", "an added reason")]


@pytest.mark.integration
def test_a_range_that_restores_a_lost_seed_empty_passes(repo):
    dc = checks()
    _lose(repo, dc.ILLUSTRATIVE_SEED_DIR)
    _write(repo.path, f"{dc.ILLUSTRATIVE_SEED_DIR}/.gitkeep", "")
    repo.commit("the directory back, with nothing in it")

    assert _violations(repo) == []


@pytest.mark.integration
def test_converting_every_page_leaves_an_armed_seed_when_a_gitkeep_holds_the_directory(
    repo,
):
    """The control for the lost seed: with a ``.gitkeep``, deleting the last page's file
    leaves the directory in git, the next range is held to an empty seed, and a marker
    with a line of its own is a line the base did not have."""
    dc = checks()
    _write(repo.path, f"{dc.ILLUSTRATIVE_SEED_DIR}/.gitkeep", "")
    repo.base = repo.commit("the directory kept")
    for page in ("docs/a.md", "docs/b.md"):
        (repo.path / _seed_file(page)).unlink()
        _write(repo.path, page, _long_page())
    head = repo.commit("every page converted")

    assert _violations(repo) == []
    assert ratchet().seed_paths(repo.path, head)["illustrative"] == [
        f"{dc.ILLUSTRATIVE_SEED_DIR}/.gitkeep"
    ]

    repo.base = head
    _write(repo.path, "docs/c.md", _long_page(NEEDS_DOCKER))
    _seed(repo.path, "docs/c.md", NEEDS_DOCKER)
    repo.commit("a marker and its line, against the empty seed")
    assert repo.added() == [("docs/c.md", NEEDS_DOCKER)]


@pytest.mark.integration
def test_the_script_exits_one_when_the_fork_point_lost_a_seed(repo):
    _lose(repo, checks().ILLUSTRATIVE_SEED_DIR)
    head = repo.commit("a change that leaves the seed gone")

    result = _ratchet_cli(repo, head)

    assert result.returncode == 1, result.stdout + result.stderr
    assert "::error" in result.stdout
    assert ".gitkeep" in result.stdout


@pytest.mark.unit
def test_the_failure_for_a_command_line_names_console_for_prompts():
    module = ratchet()
    violation = module.Violation(
        module.UNEXECUTED, "seed.tsv", "docs/x.md", "docs/x.md", "ash scan", 3
    )

    message = module.explain(violation, "0123456789abcdef")

    assert "bash" in message and "console" in message


@pytest.mark.unit
def test_the_failure_for_a_moved_page_says_to_move_the_seed_file_and_the_lines_too():
    """Moving the page is not all of it: its seed file takes the new page's name, and each
    line the new page's path, or ``markers`` fails on both. "No other edit" was wrong."""
    module = ratchet()
    violation = module.Violation(
        module.ILLUSTRATIVE, "seed.tsv", "docs/new.md", "docs/old.md", NEEDS_DOCKER, 1
    )

    message = module.explain(violation, "0123456789abcdef")

    assert "no other edit" not in message
    assert "seed file" in message
    assert "each of its lines" in message


@pytest.mark.unit
def test_the_failure_for_a_lost_seed_says_how_to_restore_it():
    module = ratchet()
    lost = module.Violation(
        module.ILLUSTRATIVE, "docs/illustrative-seed", "", "", "a" * 40, 1
    )

    message = module.explain(lost, "0123456789abcdef")

    assert ".gitkeep" in message
    assert "a" * 10 in message


@pytest.mark.integration
def test_what_git_exports_to_a_hook_does_not_reach_the_repositories_a_test_builds(
    tmp_path, monkeypatch
):
    """pytest started by a pre-commit or pre-push hook inherits GIT_DIR, GIT_WORK_TREE
    and GIT_INDEX_FILE, which override ``git -C``. Every ``add -A`` and ``commit`` of
    the temporary repositories below would then land in the developer's own repository.
    The variables are planted here at a second repository that this test makes under
    its own tmp_path, and at nothing else."""
    other = tmp_path / "other"
    other.mkdir()
    _plain_git(other, "init", "-q")
    _write(other, "kept.txt", "kept\n")
    _plain_git(other, "add", "-A")
    _plain_git(other, "commit", "-q", "-m", "other")
    before = (
        _plain_git(other, "rev-parse", "HEAD"),
        _plain_git(other, "status", "--porcelain"),
        _plain_git(other, "ls-files", "--stage"),
    )
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(other))
    monkeypatch.setenv("GIT_INDEX_FILE", str(other / ".git" / "index"))

    repo = _Repo(tmp_path / "repo")
    _seed(repo.path, "docs/b.md", NEEDS_DOCKER, "an added reason")
    head = repo.commit("a line added")

    assert repo.added() == [("docs/b.md", "an added reason")]
    assert _plain_git(repo.path, "log", "--format=%s").split("\n")[:-1] == [
        "a line added",
        "base",
    ]
    # The script itself, as a child process and in this one, reads the repository it is
    # given, not the one the variables name.
    child = _ratchet_cli(repo, head)
    assert child.returncode == 1, child.stdout + child.stderr
    assert "an added reason" in child.stdout
    assert _main("--repo", str(repo.path), "--base", repo.base, "--head", head) == 1
    after = (
        _plain_git(other, "rev-parse", "HEAD"),
        _plain_git(other, "status", "--porcelain"),
        _plain_git(other, "ls-files", "--stage"),
    )
    assert after == before


@pytest.mark.integration
def test_no_seed_line_holds_the_current_version():
    """A line is compared as it is written, and a release bump renders the version into
    every template page again. A line that holds the current version would then be
    stale and its block unlisted, and the only repair is a new line, which the fork-point
    check refuses."""
    dc = checks()
    version = dc.current_version(str(REPO_ROOT))
    texts = [
        line.partition("\t")[2]
        for lines in _committed_seed().values()
        for line in lines
    ]
    texts += [
        line.partition("\t")[2]
        for line in (REPO_ROOT / dc.UNEXECUTED_SEED_FILE)
        .read_text(encoding="utf-8")
        .splitlines()
    ]

    holders = [text for text in texts if version in text]

    assert holders == [], holders


@pytest.mark.integration
def test_the_script_exits_one_on_an_added_line_and_zero_on_a_clean_range(repo):
    clean = repo.commit("nothing")
    _seed(repo.path, "docs/b.md", NEEDS_DOCKER, "an added reason")
    dirty = repo.commit("a line")

    passed, failed = _ratchet_cli(repo, clean), _ratchet_cli(repo, dirty)

    assert passed.returncode == 0, passed.stdout + passed.stderr
    assert (
        f"{repo.base[:10]}..{clean[:10]}): 0 line(s) added to the seeds"
        in passed.stdout
    )
    assert failed.returncode == 1, failed.stdout + failed.stderr
    assert "an added reason" in failed.stdout
    assert "::error" in failed.stdout
    assert (
        f"{repo.base[:10]}..{dirty[:10]}): 1 line(s) added to the seeds"
        in failed.stdout
    )


def _event(tmp_path: Path, monkeypatch, name: str, payload: dict) -> None:
    path = tmp_path / "event.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_NAME", name)
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(path))


@pytest.mark.integration
def test_a_pull_request_is_read_from_its_fork_point_to_its_head(
    repo, tmp_path, monkeypatch, capsys
):
    """Exit 0 also means "no range, nothing to do", so each half reads the summary line:
    the range that was compared, and what was found in it."""
    _seed(repo.path, "docs/b.md", NEEDS_DOCKER, "an added reason")
    head = repo.commit("a line")
    payload = {"pull_request": {"base": {"sha": repo.base}, "head": {"sha": head}}}
    _event(tmp_path, monkeypatch, "pull_request", payload)

    assert _main("--repo", str(repo.path)) == 1
    assert _summary(capsys) == _compared("pull request", repo.base, head, 1)

    # The clean half is a head that is not its base: one that adds nothing to the seeds.
    repo.git("checkout", "-q", "-b", "clean", repo.base)
    clean = repo.commit("a pull request that leaves the seeds alone")
    payload["pull_request"]["head"]["sha"] = clean
    _event(tmp_path, monkeypatch, "pull_request", payload)

    assert _main("--repo", str(repo.path)) == 0
    assert _summary(capsys) == _compared("pull request", repo.base, clean, 0)


@pytest.mark.integration
def test_a_merge_queue_entry_is_read_from_its_base_to_its_head(
    repo, tmp_path, monkeypatch, capsys
):
    _seed(repo.path, "docs/b.md", NEEDS_DOCKER, "an added reason")
    head = repo.commit("a line")
    payload = {"merge_group": {"base_sha": repo.base, "head_sha": head}}
    _event(tmp_path, monkeypatch, "merge_group", payload)

    assert _main("--repo", str(repo.path)) == 1
    assert _summary(capsys) == _compared("merge queue entry", repo.base, head, 1)


@pytest.mark.integration
def test_a_merge_queue_entry_that_leaves_the_seeds_alone_passes(
    repo, tmp_path, monkeypatch, capsys
):
    """The control for the case above: a check that flags every merge queue entry fails
    this one, and one that reads no range at all prints no summary line."""
    head = repo.commit("a change that leaves the seeds alone")
    payload = {"merge_group": {"base_sha": repo.base, "head_sha": head}}
    _event(tmp_path, monkeypatch, "merge_group", payload)

    assert _main("--repo", str(repo.path)) == 0
    assert _summary(capsys) == _compared("merge queue entry", repo.base, head, 0)


@pytest.mark.integration
def test_a_fork_point_is_where_the_pull_request_left_main_not_where_main_is(
    repo, tmp_path, monkeypatch, capsys
):
    """Main moved on and shrank the seed (a conversion elsewhere). The pull request, cut
    before that, leaves the seed alone and must not be charged for the difference. Its
    base is not an ancestor of its head, the shape a range resolver could give up on, and
    giving up exits 0 too, so the summary line has to name the range that was compared."""
    main = repo.git("rev-parse", "--abbrev-ref", "HEAD").strip()
    repo.git("checkout", "-q", "-b", "feature")
    feature = repo.commit("the pull request, which leaves the seed alone")
    repo.git("checkout", "-q", main)
    (repo.path / _seed_file("docs/b.md")).unlink()
    _write(repo.path, "docs/b.md", _long_page())
    moved_on = repo.commit("main converted b")
    payload = {"pull_request": {"base": {"sha": moved_on}, "head": {"sha": feature}}}
    _event(tmp_path, monkeypatch, "pull_request", payload)

    assert _main("--repo", str(repo.path)) == 0
    assert _summary(capsys) == _compared("pull request", repo.base, feature, 0)


# ---------------------------------------------------------------------------
# The self-test, and that it can fail
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_the_script_passes_its_own_self_test():
    result = _run_script(RATCHET_PATH, "--self-test")

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


TRAILERS_COMMAND = "python3 .github/scripts/check-snapshot-trailers.py"
RATCHET_COMMAND = "python3 .github/scripts/check-illustrative-ratchet.py"
SELF_TEST_COMMAND = f"{RATCHET_COMMAND} --self-test"
#: What the ``if:`` of the ratchet step may be: nothing, or the condition that keeps a
#: failed earlier step from skipping it. Any other condition filters the events it runs on.
RATCHET_STEP_CONDITIONS = (None, "${{ !cancelled() }}", "!cancelled()")


def _ratchet_step_problems(workflow: dict) -> list[str]:
    """What lets the ratchet step of the snapshot-trailers job pass over a violation, or
    never run the check, in ``workflow`` (a workflow file, loaded). Empty for a step that
    fails the job: the check is a line of its own, after the self-test, under ``set -e``,
    and nothing in the job or the step makes a failure of it not count."""
    job = workflow["jobs"]["snapshot-trailers"]
    steps = job["steps"]
    problems = [
        f"the job sets `{key}:`, which can read a failure as a pass or a skip"
        for key in ("if", "continue-on-error")
        if key in job
    ]
    runs = [str(step.get("run", "")) for step in steps]
    trailers = [i for i, run in enumerate(runs) if "check-snapshot-trailers.py" in run]
    ratchets = [i for i, run in enumerate(runs) if "check-illustrative-ratchet" in run]
    if len(ratchets) != 1:
        return [*problems, f"{len(ratchets)} steps run the ratchet; one must"]
    index = ratchets[0]
    if "continue-on-error" in steps[index]:
        problems.append(
            "the ratchet step sets `continue-on-error:`, so a failure of it cannot fail "
            "the job"
        )
    if steps[index].get("if") not in RATCHET_STEP_CONDITIONS:
        problems.append(
            f"the ratchet step has the condition `{steps[index]['if']}`: it is for every "
            "event the job runs on, and the one condition that may stand there is "
            "`!cancelled()`, which keeps an earlier failed step from skipping it"
        )
    if not trailers or index < trailers[0]:
        problems.append("the ratchet step does not come after the trailer step")
    lines = [line.strip() for line in runs[index].splitlines()]
    if "set -euo pipefail" not in lines:
        problems.append("the step does not run under `set -euo pipefail`")
    self_tests = [n for n, line in enumerate(lines) if line == SELF_TEST_COMMAND]
    checks = [n for n, line in enumerate(lines) if line == RATCHET_COMMAND]
    if len(self_tests) != 1:
        problems.append(f"{len(self_tests)} lines are the self-test, not one")
    if len(checks) != 1:
        problems.append(f"{len(checks)} lines are the check, not one")
    if self_tests and checks and checks[0] < self_tests[0]:
        problems.append("the check runs before the self-test")
    problems += [
        f"`{line}` lets the step pass when a command in it fails"
        for line in lines
        if "||" in line or line.startswith("set +e")
    ]
    return problems


_SET_E = "set -euo pipefail\n"
_SELF_TEST_LINE = f"{SELF_TEST_COMMAND}\n"
_CHECK_LINE = f"{RATCHET_COMMAND}\n"
_GOOD_RATCHET_RUN = _SET_E + _SELF_TEST_LINE + _CHECK_LINE


def _workflow(
    run: str = _GOOD_RATCHET_RUN,
    *,
    step: dict | None = None,
    job: dict | None = None,
    ratchet_first: bool = False,
) -> dict:
    """A workflow of the shape the real one has: a trailer step, then the ratchet step."""
    trailers = {"name": "trailers", "run": f"{TRAILERS_COMMAND} --orphans"}
    ratchet = {"name": "ratchet", "shell": "bash", "run": run, **(step or {})}
    steps = [ratchet, trailers] if ratchet_first else [trailers, ratchet]
    return {"jobs": {"snapshot-trailers": {**(job or {}), "steps": steps}}}


_BROKEN_RATCHET_STEPS = {
    "the self-test twice, so the check itself never runs": _workflow(
        _SET_E + _SELF_TEST_LINE + _SELF_TEST_LINE
    ),
    "the check forgiven with || true": _workflow(
        _SET_E + _SELF_TEST_LINE + f"{RATCHET_COMMAND} || true\n"
    ),
    "the self-test forgiven with || true": _workflow(
        _SET_E + f"{SELF_TEST_COMMAND} || true\n" + _CHECK_LINE
    ),
    "the check left out": _workflow(_SET_E + _SELF_TEST_LINE),
    "the check commented out": _workflow(_SET_E + _SELF_TEST_LINE + "# " + _CHECK_LINE),
    "the check before the self-test": _workflow(_SET_E + _CHECK_LINE + _SELF_TEST_LINE),
    "no set -e": _workflow(_SELF_TEST_LINE + _CHECK_LINE),
    "set +e after it": _workflow(_SET_E + "set +e\n" + _SELF_TEST_LINE + _CHECK_LINE),
    "continue-on-error on the step": _workflow(step={"continue-on-error": True}),
    "continue-on-error on the job": _workflow(job={"continue-on-error": True}),
    "an event filter on the step": _workflow(
        step={"if": "github.event_name == 'pull_request'"}
    ),
    "an if on the job": _workflow(job={"if": "github.event_name == 'push'"}),
    "the step before the trailer step": _workflow(ratchet_first=True),
}


@pytest.mark.unit
def test_the_snapshot_trailers_job_runs_the_ratchet_after_its_trailer_step():
    import yaml

    workflow = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))

    assert _ratchet_step_problems(workflow) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "step",
    [{}, {"if": "${{ !cancelled() }}"}],
    ids=["no condition", "runs after an earlier failure"],
)
def test_a_ratchet_step_of_the_shape_the_job_needs_has_no_problem(step):
    """The controls for the cases below: the check that finds a problem in each of them
    finds none here."""
    assert _ratchet_step_problems(_workflow(step=step)) == []


@pytest.mark.unit
@pytest.mark.parametrize("name", sorted(_BROKEN_RATCHET_STEPS))
def test_a_ratchet_step_that_cannot_fail_the_job_is_a_problem(name):
    assert _ratchet_step_problems(_BROKEN_RATCHET_STEPS[name]), name


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


def _contract_text() -> str:
    return (REPO_ROOT / CONTRACT_PAGE).read_text(encoding="utf-8")


def _ratchet_section() -> str:
    text = _contract_text()
    start = text.index("### The illustrative ratchet")
    return text[start : text.index("### Output samples")]


@pytest.mark.unit
def test_the_contract_page_keeps_the_seed_directory_in_git():
    """Step 3 and the findings table said to delete a page's file once it has no line
    left. For the last page that deletes the directory, which turns the seed check off.
    Each place that says so says to keep the ``.gitkeep``."""
    text = _contract_text()

    assert ".gitkeep" in text
    for paragraph in text.split("\n\n"):
        if "once it has no line left" in paragraph:
            assert ".gitkeep" in paragraph, paragraph


@pytest.mark.unit
def test_the_contract_page_sends_no_one_to_a_marker_the_ratchet_refuses():
    text = _contract_text()

    for advice in (
        "mark the Windows, zsh, or fish block `illustrative` with a reason",
        "must be marked `illustrative`",
        "must be `illustrative`",
        "or mark it `illustrative`",
        "The block then runs as `run`, like its neighbors.",
        "use a marker without a mode to save a block that must not run",
    ):
        assert advice not in text, advice


@pytest.mark.unit
def test_the_contract_page_names_console_for_prompts_and_what_else_is_counted():
    text = _contract_text()
    row = next(
        line
        for line in text.splitlines()
        if line.startswith("| shows a command that nothing runs")
    )
    section = _ratchet_section()

    assert "`console`" in row
    for needle in ("runner=none", "save-as=", "`console`"):
        assert needle in section, needle


@pytest.mark.unit
def test_the_contract_page_says_a_moved_page_takes_its_seed_file_and_its_lines():
    section = _ratchet_section()

    assert "seed file" in section
    assert "each of its lines" in section
