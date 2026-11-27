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

A page that a generator writes is read for what the generator does not print. The
repository keeps a list of such pages, ``REFERENCE_PAGES`` in the freshness test, which
holds each page on it to its generator's output, and a page is one of them when that
list names it and the page opens with the banner of the generator listed for it. The
usage line that each command's section of the CLI reference prints (``ash scan
[OPTIONS]``) is no command the page tells a reader to run, and without this rule every
new subcommand would add a block that no seed lists, so a block of such a page is left
out when its first command has the shape of a usage line. The help text of a command
holds examples that a person wrote, and the generator fences them as ``text`` as well,
which keeps them out of the runs: they are counted like the blocks of any page. A
banner alone decides nothing: the journey pages open with one and their blocks are
written by hand, and any page can open with a copied one.

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
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CHECKS_PATH = REPO_ROOT / "scripts" / "docs_checks.py"
GATE_PATH = REPO_ROOT / "scripts" / "verify_docs_freshness.py"
FENCE = "```"
SCAN = "ash scan --source-dir ."
MESSAGE = "shows a command that nothing runs"
USAGE = "ash scan [OPTIONS]"
#: An example from the help text of a command, as the generator fences it: a ``text``
#: block in the command's section of the page, before the usage block. HELP_COMMAND is
#: how the seed names it: the first line joined with the line it continues.
HELP_EXAMPLE = (
    "ash suppress add B602 --symbol Handler.run --file src/app.py \\\n"
    '    --reason "The command is a constant."'
)
HELP_COMMAND = (
    "ash suppress add B602 --symbol Handler.run --file src/app.py "
    '--reason "The command is a constant."'
)
#: What the generator prints for a command's usage that a block of a generated page may
#: have as its first command without being counted: the program, the command's path,
#: ``[OPTIONS]`` (click prints it for every command, since ``--help`` is an option), and
#: a placeholder for each argument. Restated here, as the census restates the parser's
#: rules: the check must not be the only place that says what the generator prints.
USAGE_SHAPED = [
    "ash [OPTIONS] COMMAND [ARGS]...",
    "ash scan [OPTIONS]",
    "ash config get [OPTIONS] [config_path]",
    "ash diff [OPTIONS] {before} {after}",
    "ash plugin verify [OPTIONS] [names]...",
    "ash results inspect findings [OPTIONS]",
    "ash suppress add [OPTIONS] {rule_id}",
    "ash new [OPTIONS] NAME",
    "ash new [OPTIONS] [NAME]...",
]
#: First commands that are no usage line, though they begin like one or hold ``[OPTIONS]``:
#: an example is a command with values, and a usage line has none.
NOT_USAGE_SHAPED = [
    "ash scan",
    "ash config lint",
    "ash config validate --config path/to/config.yaml",
    "ash scan --source-dir . [OPTIONS]",
    "ash scan [OPTIONS] --source-dir .",
    "ash scan [OPTIONS] src",
    "ash suppress add B602 --symbol Handler.run",
    "uvx ash scan [OPTIONS]",
]
#: How a usage line begins, for the checks of this checkout that read the page and the
#: seed: the program, the command's path, then ``[OPTIONS]``.
USAGE_START = re.compile(r"^ash(?: [a-z][a-z0-9-]*)* \[OPTIONS\]")
CLI_REFERENCE = "docs/content/reference/cli.md"
JOURNEY_PAGE = "docs/content/getting-started/local.md"
#: The four pages of the two getting-started journeys: written from a journey file by
#: hand, rendered by scripts/generate_journey_pages.py, and opening with its banner.
JOURNEY_PAGES = (
    JOURNEY_PAGE,
    "docs/content/getting-started/local.md.template",
    "docs/content/getting-started/ci.md",
    "docs/content/getting-started/ci.md.template",
)
#: The repository's own list of the reference pages a generator writes: a dict in the
#: freshness test, from each script to the page it writes under docs/content/reference.
FRESHNESS_TEST = "tests/unit/test_generated_docs_freshness.py"
LISTED = {
    "generate_cli_docs.py": "cli.md",
    "generate_config_reference.py": "configuration.md",
}


def _banner(script: str) -> str:
    """What a generated page opens with, as the contributor page asks."""
    return (
        "<!--\n"
        f"  Generated by scripts/{script} from the code it documents.\n"
        "  Do not edit this file by hand: change the code or the generator, then run\n"
        f"    uv run python scripts/{script}\n"
        "-->\n"
    )


BANNER = _banner("generate_cli_docs.py")
JOURNEY_BANNER = _banner("generate_journey_pages.py")
#: The blocks that show a command nothing runs, as the check counts them at main, and the
#: page each is on. The first seed, written when the check was first run over main
#: (c15148192f4), held 51 lines: one on each of four pages a person writes, and 47 on the
#: CLI reference, which a generator writes. Of those 47, 44 are the usage lines the
#: generator prints, which the check leaves out (is_usage_line), and 3 are examples that
#: a person wrote in the help text of ``ash config lint``, ``ash config validate`` and
#: ``ash suppress add``, which it counts. So main carries 7 lines. Conversions lower
#: the number of lines on a page; this table moves only if main's own blocks change
#: before the seed lands. It is the backstop that needs no git: the ratchet job
#: compares the seed with the fork point's, and this holds each page to its own line
#: count, so a change that converts two lines on one page and adds two on another is as
#: much a failure as a seed that grows.
SEED_PAGES_AT_MAIN = {
    "automated_security_helper/plugin_modules/ash_ferret_plugins/DEVELOPMENT.md": 1,
    "deploy/terraform/modules/codepipeline-executor/README.md": 1,
    "docs/content/contributing/documentation.md": 1,
    "docs/content/docs/plugins/alpha/index.md": 1,
    CLI_REFERENCE: 3,
}
SEED_AT_MAIN = 7


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


def _reference(*blocks: str, banner: str = "") -> str:
    """A reference page, with the banner first when a generator writes it."""
    return f"{banner}# CLI reference\n\n" + "\n".join(blocks)


def _journey(*blocks: str) -> str:
    """A journey page: the banner of the journey generator, then the page."""
    return JOURNEY_BANNER + "\n" + _page(*blocks)


def _list_generators(root: Path, listed: dict[str, str] | None = None) -> Path:
    """Plant the repository's list of the reference pages a generator writes under root,
    where the check reads it as source."""
    listed = LISTED if listed is None else listed
    return _write(root, FRESHNESS_TEST, f"REFERENCE_PAGES = {listed!r}\n")


def _fence(text: str) -> int:
    """The line of the first ``text`` fence of a page."""
    return text.split("\n").index(f"{FENCE}text") + 1


def _fences(text: str) -> list[int]:
    """The line of each ``text`` fence of a page, in page order."""
    return [
        number
        for number, line in enumerate(text.split("\n"), 1)
        if line == f"{FENCE}text"
    ]


def _read_real(rel: str) -> str:
    """A file of this checkout, as the text to copy under a temporary root."""
    return (REPO_ROOT / rel).read_text(encoding="utf-8")


def _unexecuted(root: Path, *pages: Path):
    """What the unexecuted-command check alone says about pages, under root."""
    dc = checks()
    return dc.unexecuted_command_problems(dc.load_pages(list(pages), root), root)


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

    blocks = dc.unexecuted_command_blocks(dc.parse_page(page, tmp_path), {})

    assert [(block.fence_line, command) for block, command in blocks] == [
        (3, "uv run pytest")
    ]


#: A line of a block nothing runs, and the command the seed names for it: the line
#: without its prompt. Each starts a line in a way an ``ash`` line or a ``$`` prompt
#: line does not.
SHOWN = [
    ("uvx ash scan --source-dir .", "uvx ash scan --source-dir ."),
    (
        "uvx --from git+https://github.com/awslabs/automated-security-helper ash scan",
        "uvx --from git+https://github.com/awslabs/automated-security-helper ash scan",
    ),
    ("uv run ash scan", "uv run ash scan"),
    ("sudo ash scan", "sudo ash scan"),
    ("sudo -E ash scan", "sudo -E ash scan"),
    ("sudo -E -H ash scan", "sudo -E -H ash scan"),
    (
        "sudo -u root ash scan --source-dir .",
        "sudo -u root ash scan --source-dir .",
    ),
    ("sudo -Eu root ash scan", "sudo -Eu root ash scan"),
    ("sudo --user root ash scan", "sudo --user root ash scan"),
    ("sudo --user=root ash scan", "sudo --user=root ash scan"),
    ("sudo -- ash scan", "sudo -- ash scan"),
    ("env -i ASH_OFFLINE=true ash scan", "env -i ASH_OFFLINE=true ash scan"),
    ("env -u HOME ash scan", "env -u HOME ash scan"),
    ("time -p ash scan", "time -p ash scan"),
    ("time -f %e ash scan", "time -f %e ash scan"),
    ("exec -a scanner ash scan", "exec -a scanner ash scan"),
    ("time ash scan", "time ash scan"),
    ("nohup ash scan", "nohup ash scan"),
    ("exec ash scan", "exec ash scan"),
    ("command ash scan", "command ash scan"),
    ("env ASH_OFFLINE=true ash scan", "env ASH_OFFLINE=true ash scan"),
    (
        "ASH_OFFLINE=true ash scan --source-dir .",
        "ASH_OFFLINE=true ash scan --source-dir .",
    ),
    ("PS> ash scan", "ash scan"),
    ("PS C:\\Users\\me> ash scan", "ash scan"),
    ("% ash scan", "ash scan"),
    ("docker run --rm -v .:/src ash scan", "docker run --rm -v .:/src ash scan"),
    ("podman run ash scan", "podman run ash scan"),
    ("finch run ash scan", "finch run ash scan"),
    ("nerdctl run ash scan", "nerdctl run ash scan"),
    ("pip install automated-security-helper", "pip install automated-security-helper"),
    (
        "git clone https://github.com/awslabs/automated-security-helper.git",
        "git clone https://github.com/awslabs/automated-security-helper.git",
    ),
    ("aws s3 ls", "aws s3 ls"),
    ("automated-security-helper scan", "automated-security-helper scan"),
    ("agentic-security-harness scan", "agentic-security-harness scan"),
    ("ashv3 scan", "ashv3 scan"),
]
#: Lines that mention a program and show no command.
NOT_SHOWN = [
    "ash",
    "git",
    "docker",
    "pip",
    "uvx",
    "sudo ash",
    "time ash",
    "sudo -u root ls -la",
    "sudo -E -H systemctl restart docker",
    "time -p ls -la",
    "sudo -u ash ls -la",
    "sudo --user ash ls -la",
    "env -u ash ls -la",
    "sudo -u ash",
    "Run docker ps to list them",
    "the git command",
    "gitlab ci",
    "pip.conf is read",
    "docker-compose up",
    "uvicorn app:app",
    "aws-cli/2.15.0 Python/3.11",
    "% complete",
    "PS C:\\Users\\me> dir",
    "# git status",
    "> git log",
    "echo git status",
]


@pytest.mark.unit
@pytest.mark.parametrize(("line", "command"), SHOWN, ids=[line for line, _ in SHOWN])
def test_a_command_in_a_block_nothing_runs_is_counted_whatever_starts_the_line(
    tmp_path, line, command
):
    """A bash block fenced as text leaves the runs with no marker, and its seed line can
    then be deleted as if it were converted. Only an ``ash`` line and a ``$`` prompt line
    were counted, so a block got away by starting its line another way: through uvx or
    uv run, behind sudo or an environment assignment, after a ``%`` or ``PS>`` prompt, or
    as a container, pip, git or aws command."""
    dc = checks()
    page = _write(tmp_path, "docs/page.md", _page(_text(f"Run it:\n{line}\ndone")))

    blocks = dc.unexecuted_command_blocks(dc.parse_page(page, tmp_path), {})

    assert [(block.fence_line, found) for block, found in blocks] == [(3, command)]


@pytest.mark.unit
@pytest.mark.parametrize("line", NOT_SHOWN)
def test_a_line_that_only_mentions_a_program_shows_no_command(tmp_path, line):
    """The controls for the case above: a program as a word, a name that starts like one,
    and a prompt before something that is none of them."""
    _seed(tmp_path)
    page = _write(tmp_path, "docs/page.md", _page(_text(f"Output:\n{line}\ndone")))

    assert _problems(tmp_path, page) == []


@pytest.mark.unit
def test_relabeling_a_container_block_as_text_is_caught_with_no_ash_line_or_prompt(
    tmp_path,
):
    """The swap the review planted: a bash block marked illustrative for Docker, fenced
    as text with its marker dropped and its seed line deleted. It shows no ``ash`` line
    and no ``$`` prompt, so no seed counted it."""
    _seed(tmp_path)
    block = _text('docker run --rm -v "$PWD":/src automated-security-helper scan')
    page = _write(tmp_path, "docs/page.md", _page(block))

    findings = _problems(tmp_path, page)

    assert [(f.path, f.line) for f in findings] == [("docs/page.md", 3)]
    assert "docker run" in findings[0].message


@pytest.mark.unit
def test_the_finding_for_a_command_in_a_text_block_names_console_for_prompts(tmp_path):
    _seed(tmp_path)
    page = _write(tmp_path, "docs/page.md", _page(_text("$ ash --version\nash 3.8.0")))

    findings = _problems(tmp_path, page)

    assert len(findings) == 1
    assert "bash" in findings[0].message
    assert "console" in findings[0].message


@pytest.mark.unit
def test_a_seed_line_for_a_page_that_exists_but_was_not_handed_over_is_left_alone(
    tmp_path,
):
    """One seed file names every page, so a run over some of the pages is where a false
    "no block on this page shows this command" would come from."""
    _seed(tmp_path, f"docs/other.md\t{SCAN}", f"docs/page.md\t{SCAN}")
    page = _write(tmp_path, "docs/page.md", _page(_text(SCAN)))
    _write(tmp_path, "docs/other.md", _page(_text(SCAN)))

    assert _problems(tmp_path, page) == []


@pytest.mark.unit
def test_a_template_and_the_page_it_renders_each_need_their_own_seed_line(tmp_path):
    page = _write(tmp_path, "docs/page.md", _page(_text(SCAN)))
    template = _write(tmp_path, "docs/page.md.template", _page(_text(SCAN)))
    _seed(tmp_path, f"docs/page.md\t{SCAN}")

    findings = _problems(tmp_path, page, template)

    assert [(f.path, f.line) for f in findings] == [("docs/page.md.template", 3)]

    _seed(tmp_path, f"docs/page.md\t{SCAN}", f"docs/page.md.template\t{SCAN}")
    assert _problems(tmp_path, page, template) == []


# ---------------------------------------------------------------------------
# A page a generator writes is read for what its generator does not print
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_a_usage_block_in_a_generated_page_passes(tmp_path):
    """The usage line a command's section prints is no command the page tells a reader
    to run, and the freshness test holds the page to its generator's output, so no seed
    line is kept for it. The list names the page, and its banner names the generator
    listed for it."""
    _seed(tmp_path)
    _list_generators(tmp_path)
    page = _write(
        tmp_path, CLI_REFERENCE, _reference(_text(USAGE), banner=BANNER + "\n")
    )

    assert _problems(tmp_path, page) == []


@pytest.mark.unit
def test_the_same_block_in_a_hand_written_page_fails(tmp_path):
    """The control: the page above without its banner is hand-written, though the list
    names it, and its block is read like any other."""
    _seed(tmp_path)
    _list_generators(tmp_path)
    page = _write(tmp_path, CLI_REFERENCE, _reference(_text(USAGE)))

    findings = _problems(tmp_path, page)

    assert [(f.path, f.line) for f in findings] == [(CLI_REFERENCE, 3)]
    assert USAGE in findings[0].message


@pytest.mark.unit
@pytest.mark.parametrize(
    "example_first", [True, False], ids=["example first", "usage first"]
)
def test_a_help_text_example_in_a_generated_page_is_counted_and_its_usage_block_is_not(
    tmp_path, example_first
):
    """The generator prints a usage block for each command and fences the examples that
    a person put in the command's help text as ``text`` too. The usage line is no
    command the page tells a reader to run. An example is one, and fencing it as
    ``text`` keeps it out of the runs with no marker: left out with the usage lines it
    would never run, and nothing would track it, which is the relabeling this check
    exists to stop. So the example is counted like a block of any page, and the usage
    block next to it is not."""
    dc = checks()
    _seed(tmp_path)
    _list_generators(tmp_path)
    blocks = [_text(HELP_EXAMPLE), _text(USAGE)]
    ordered = blocks if example_first else blocks[::-1]
    text = _reference(*ordered, banner=BANNER + "\n")
    page = _write(tmp_path, CLI_REFERENCE, text)
    generated, listing = dc.read_generated_pages(tmp_path)
    example_line = _fences(text)[0 if example_first else 1]

    counted = dc.unexecuted_command_blocks(dc.parse_page(page, tmp_path), generated)
    findings = _problems(tmp_path, page)

    assert listing == []
    assert [(block.fence_line, found) for block, found in counted] == [
        (example_line, HELP_COMMAND)
    ]
    assert [(f.path, f.line) for f in findings] == [(CLI_REFERENCE, example_line)]
    assert HELP_COMMAND in findings[0].message


@pytest.mark.unit
def test_a_seed_line_for_a_help_text_example_of_a_generated_page_lists_it(tmp_path):
    """The twin of the stale usage line below: the example is a block the check counts,
    so the seed line that names it is used, and the page passes with it."""
    _seed(tmp_path, f"{CLI_REFERENCE}\t{HELP_COMMAND}")
    _list_generators(tmp_path)
    page = _write(
        tmp_path,
        CLI_REFERENCE,
        _reference(_text(HELP_EXAMPLE), _text(USAGE), banner=BANNER + "\n"),
    )

    assert _problems(tmp_path, page) == []


@pytest.mark.unit
@pytest.mark.parametrize("command", USAGE_SHAPED)
def test_a_block_with_the_shape_of_a_usage_line_is_left_out_of_a_generated_page(
    tmp_path, command
):
    """What click prints for a command is the program, the command's path, ``[OPTIONS]``
    (every command has it: ``--help`` is an option) and a placeholder for each argument,
    in brackets, in braces, or in capitals as click spells a required one. A block of a
    generated page that shows that and no more is the usage block."""
    dc = checks()
    _list_generators(tmp_path)
    page = _write(
        tmp_path, CLI_REFERENCE, _reference(_text(command), banner=BANNER + "\n")
    )
    generated, _listing = dc.read_generated_pages(tmp_path)

    counted = dc.unexecuted_command_blocks(dc.parse_page(page, tmp_path), generated)

    assert counted == []


@pytest.mark.unit
@pytest.mark.parametrize("command", NOT_USAGE_SHAPED)
def test_a_block_without_the_shape_of_a_usage_line_is_counted_in_a_generated_page(
    tmp_path, command
):
    """The controls for the case above: a command with values, one with flags before or
    after ``[OPTIONS]``, a bare word where a placeholder belongs, and a command that
    starts with another program. Each is something a person wrote, so each is counted."""
    dc = checks()
    _list_generators(tmp_path)
    text = _reference(_text(command), banner=BANNER + "\n")
    page = _write(tmp_path, CLI_REFERENCE, text)
    generated, _listing = dc.read_generated_pages(tmp_path)

    counted = dc.unexecuted_command_blocks(dc.parse_page(page, tmp_path), generated)

    assert [(block.fence_line, found) for block, found in counted] == [
        (_fence(text), command)
    ]


@pytest.mark.unit
@pytest.mark.parametrize("command", USAGE_SHAPED)
def test_a_block_with_the_shape_of_a_usage_line_is_counted_in_a_hand_written_page(
    tmp_path, command
):
    """The shape leaves a block out only on a page a generator writes. On a page a
    person writes, a usage line is a command shown in a block nothing runs, like any
    other."""
    dc = checks()
    _list_generators(tmp_path)
    text = _reference(_text(command))
    page = _write(tmp_path, CLI_REFERENCE, text)
    generated, _listing = dc.read_generated_pages(tmp_path)

    counted = dc.unexecuted_command_blocks(dc.parse_page(page, tmp_path), generated)

    assert [(block.fence_line, found) for block, found in counted] == [
        (_fence(text), command)
    ]


@pytest.mark.unit
@pytest.mark.parametrize(
    "lead",
    ["# CLI reference\n\n", "Some words first.\n\n"],
    ids=["after a heading", "after a sentence"],
)
def test_a_banner_that_does_not_open_the_page_makes_nothing_generated(tmp_path, lead):
    """A page the list names that quotes the banner further down is still read: only a
    page that opens with it is one a generator writes."""
    _seed(tmp_path)
    _list_generators(tmp_path)
    text = f"{lead}{BANNER}\n{_text(USAGE)}"
    page = _write(tmp_path, CLI_REFERENCE, text)

    findings = _problems(tmp_path, page)

    assert [f.line for f in findings] == [_fence(text)], findings


@pytest.mark.unit
@pytest.mark.parametrize(
    ("rel", "script"),
    [
        (CLI_REFERENCE, "generate_config_reference.py"),
        (CLI_REFERENCE, "generate_missing.py"),
        ("docs/content/reference/other.md", "generate_cli_docs.py"),
        ("docs/guide.md", "generate_missing.py"),
    ],
    ids=[
        "a listed page, the banner of another listed script",
        "a listed page, a banner naming a script that does not exist",
        "an unlisted page, the banner of a listed script",
        "an unlisted page, a banner naming a script that does not exist",
    ],
)
def test_a_page_is_generated_only_where_the_list_and_its_banner_agree(
    tmp_path, rel, script
):
    """The list gives each script the page it writes, and the banner that opens the page
    must name the script the list gives that page. A banner is a comment any page can
    open with, a copied one or one naming a script nothing answers to included, so a
    page whose banner and list disagree is read like any other."""
    _seed(tmp_path)
    _list_generators(tmp_path)
    text = _reference(_text(USAGE), banner=_banner(script) + "\n")
    page = _write(tmp_path, rel, text)

    findings = _problems(tmp_path, page)

    assert [(f.path, f.line) for f in findings] == [(rel, _fence(text))], findings
    assert USAGE in findings[0].message


@pytest.mark.unit
@pytest.mark.parametrize(
    "rel", JOURNEY_PAGES, ids=[Path(page).name for page in JOURNEY_PAGES]
)
def test_a_journey_page_is_read_like_a_hand_written_one(tmp_path, rel):
    """A journey page opens with a generator's banner, but its blocks are written by hand
    in a journey file, and the generator pins only a few of them to bash. A block in a
    language nothing runs that shows a command is a finding there as on any page a
    person writes, unless a seed lists it."""
    _seed(tmp_path)
    _list_generators(tmp_path)
    text = _journey(_text(SCAN))
    page = _write(tmp_path, rel, text)

    findings = _problems(tmp_path, page)

    assert [(f.path, f.line) for f in findings] == [(rel, _fence(text))], findings
    assert SCAN in findings[0].message


@pytest.mark.unit
def test_a_block_of_a_journey_page_that_the_seed_lists_passes(tmp_path):
    """So a journey page is seeded like any page a person writes, and a line for it is
    not stale."""
    _seed(tmp_path, f"{JOURNEY_PAGE}\t{SCAN}")
    _list_generators(tmp_path)
    page = _write(tmp_path, JOURNEY_PAGE, _journey(_text(SCAN)))

    assert _problems(tmp_path, page) == []


@pytest.mark.unit
def test_a_seed_line_for_a_usage_block_of_a_generated_page_matches_nothing(tmp_path):
    """Once a page is one a generator writes its usage blocks are not read, so a line
    that names one of them is stale: the seed shrinks in the commit that stops reading
    it."""
    seed = _seed(tmp_path, f"{CLI_REFERENCE}\t{USAGE}")
    _list_generators(tmp_path)
    page = _write(
        tmp_path, CLI_REFERENCE, _reference(_text(USAGE), banner=BANNER + "\n")
    )

    findings = _problems(tmp_path, page)

    assert [(f.path, f.line) for f in findings] == [
        (seed.relative_to(tmp_path).as_posix(), 1)
    ]
    assert "no block on this page shows this command" in findings[0].message


@pytest.mark.unit
def test_the_writer_leaves_a_usage_block_out_and_lists_the_rest_of_the_pages(tmp_path):
    """A generated page's usage block has no line, its help-text example has one, and a
    journey page, which opens with a banner too, is listed like a page a person writes."""
    dc = checks()
    _list_generators(tmp_path)
    generated = _write(
        tmp_path,
        CLI_REFERENCE,
        _reference(_text(HELP_EXAMPLE), _text(USAGE), banner=BANNER + "\n"),
    )
    journey = _write(tmp_path, JOURNEY_PAGE, _journey(_text(SCAN)))
    hand_written = _write(tmp_path, "docs/page.md", _page(_text(SCAN)))

    written = dc.write_seeds([generated, journey, hand_written], tmp_path)

    assert written == [dc.UNEXECUTED_SEED_FILE]
    assert (tmp_path / dc.UNEXECUTED_SEED_FILE).read_text(encoding="utf-8") == (
        f"{CLI_REFERENCE}\t{HELP_COMMAND}\n{JOURNEY_PAGE}\t{SCAN}\ndocs/page.md\t{SCAN}\n"
    )


@pytest.mark.unit
def test_a_real_generated_page_with_a_planted_block_is_read_for_that_block(tmp_path):
    """The real list and the real CLI reference, copied under a temporary root, with a
    block added that no seed lists. The page is one a generator writes, so none of its
    usage blocks is counted, but the block a person planted is, as is any example the
    page's help text holds."""
    _seed(tmp_path)
    _write(tmp_path, FRESHNESS_TEST, _read_real(FRESHNESS_TEST))
    text = f"{_read_real(CLI_REFERENCE)}\n{_text(SCAN)}"
    page = _write(tmp_path, CLI_REFERENCE, text)
    planted = text.count("\n", 0, text.rindex(f"{FENCE}text")) + 1

    findings = _unexecuted(tmp_path, page)

    assert planted in {f.line for f in findings}, [str(f) for f in findings][-3:]
    assert [f.line for f in findings if "[OPTIONS]" in f.message] == [], (
        "the page's usage blocks are left out"
    )


@pytest.mark.unit
def test_a_real_generated_page_whose_banner_names_a_missing_script_is_read(tmp_path):
    """The same page with the script its banner names changed to one that does not
    exist: the list still names the page, the banner no longer agrees with it, and every
    block the page shows is read, the planted one included."""
    _seed(tmp_path)
    _write(tmp_path, FRESHNESS_TEST, _read_real(FRESHNESS_TEST))
    real = _read_real(CLI_REFERENCE)
    changed = real.replace(
        "scripts/generate_cli_docs.py", "scripts/generate_missing.py", 1
    )
    assert changed != real, "the banner names scripts/generate_cli_docs.py"
    body = f"{changed}\n{_text(SCAN)}"
    page = _write(tmp_path, CLI_REFERENCE, body)
    planted = body.count("\n", 0, body.rindex(f"{FENCE}text")) + 1

    findings = _unexecuted(tmp_path, page)

    assert planted in {f.line for f in findings}, [str(f) for f in findings][-3:]
    assert len(findings) > 1, "the usage blocks of the page are read too"


# ---------------------------------------------------------------------------
# The list of generated pages is read as source, and a list nobody can read exempts
# nothing
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_the_list_is_read_as_source_and_never_imported(tmp_path):
    """The freshness test imports the whole test environment, and the docs checks run
    where that is not installed, so the list is read from the syntax tree: a module that
    raises when it is imported is read all the same."""
    dc = checks()
    source = (
        "raise SystemExit('the list was imported')\n"
        "REFERENCE_PAGES = {\n"
        "    'generate_cli_docs.py': 'cli.md',\n"
        "    'generate_x.py': 'x.md',\n"
        "}\n"
    )
    _write(tmp_path, FRESHNESS_TEST, source)

    generated, problems = dc.read_generated_pages(tmp_path)

    assert generated == {
        "generate_cli_docs.py": CLI_REFERENCE,
        "generate_x.py": "docs/content/reference/x.md",
    }
    assert problems == []


@pytest.mark.unit
def test_an_annotated_list_is_read_too(tmp_path):
    dc = checks()
    _write(
        tmp_path,
        FRESHNESS_TEST,
        "REFERENCE_PAGES: dict[str, str] = {'generate_cli_docs.py': 'cli.md'}\n",
    )

    assert dc.read_generated_pages(tmp_path) == (
        {"generate_cli_docs.py": CLI_REFERENCE},
        [],
    )


@pytest.mark.unit
def test_a_root_with_no_list_names_no_generated_page(tmp_path):
    """The arming rule's twin: the pages the unit tests write in a temporary root are
    checked without the list, and a banner there exempts nothing."""
    dc = checks()
    _seed(tmp_path)
    text = _reference(_text(USAGE), banner=BANNER + "\n")
    page = _write(tmp_path, CLI_REFERENCE, text)

    assert dc.read_generated_pages(tmp_path) == ({}, [])
    assert [f.line for f in _problems(tmp_path, page)] == [_fence(text)]


@pytest.mark.unit
@pytest.mark.parametrize(
    "source",
    [
        "REFERENCE_PAGES = {'generate_cli_docs.py': 'cli.md'\n",
        "PAGES = {'generate_cli_docs.py': 'cli.md'}\n",
        "REFERENCE_PAGES = dict(generate_cli_docs_py='cli.md')\n",
        "REFERENCE_PAGES = {'generate_cli_docs.py': 3}\n",
        "REFERENCE_PAGES = {'generate_cli_docs.py': 'cli.md'}\nREFERENCE_PAGES = {}\n",
    ],
    ids=[
        "a file that does not parse",
        "a file that never assigns the name",
        "a call where a dict literal belongs",
        "a page that is not a file name",
        "a name assigned twice",
    ],
)
def test_an_unreadable_list_is_a_finding_and_exempts_nothing(tmp_path, source):
    """A list the check cannot read names no generated page, so every page is read like
    one a person writes, and the finding says why: the alternative is a check that
    reads a banner on trust, or one that fails with no reason."""
    dc = checks()
    _seed(tmp_path)
    _write(tmp_path, FRESHNESS_TEST, source)
    page = _write(
        tmp_path, CLI_REFERENCE, _reference(_text(USAGE), banner=BANNER + "\n")
    )

    generated, problems = dc.read_generated_pages(tmp_path)
    findings = _problems(tmp_path, page)

    assert generated == {}
    assert [f.path for f in problems] == [FRESHNESS_TEST]
    assert "cannot be read" in problems[0].message
    assert sorted({f.path for f in findings}) == [CLI_REFERENCE, FRESHNESS_TEST]


@pytest.mark.unit
def test_the_writer_refuses_a_list_it_cannot_read(tmp_path):
    """The seed is written once, so it is not written from a list the writer cannot read:
    that would list the blocks of every generated page."""
    dc = checks()
    _write(tmp_path, FRESHNESS_TEST, "REFERENCE_PAGES = {\n")
    page = _write(
        tmp_path, CLI_REFERENCE, _reference(_text(USAGE), banner=BANNER + "\n")
    )

    with pytest.raises(ValueError, match="cannot be read"):
        dc.write_seeds([page], tmp_path)

    assert not (tmp_path / dc.UNEXECUTED_SEED_FILE).exists()


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

    assert dc.unexecuted_seed_lines(pages, {}) == [
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


def _listed() -> dict[str, str]:
    """The reference pages a generator writes in this checkout, as its own list gives
    them: each script and the path of the page it writes."""
    generated, problems = checks().read_generated_pages(REPO_ROOT)
    assert problems == [], [str(problem) for problem in problems]
    return generated


@pytest.mark.integration
def test_the_committed_seed_is_what_the_check_counts_in_the_corpus(corpus):
    dc = checks()

    measured = dc.unexecuted_seed_lines(dc.load_pages(corpus, REPO_ROOT), _listed())

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
def test_the_seed_lists_no_usage_line_of_a_page_a_generator_writes(corpus):
    """A page a generator writes has seed lines for what a person put on it, its
    help-text examples, and none for the usage lines the generator prints."""
    dc = checks()
    generated = _listed()
    pages = {page.rel: page for page in dc.load_pages(corpus, REPO_ROOT)}

    usage = []
    for line in _committed_seed():
        rel, _tab, command = line.partition("\t")
        page = pages.get(rel)
        if (
            page is not None
            and dc.is_generated_page(page, generated)
            and USAGE_START.match(command)
        ):
            usage.append(line)

    assert usage == []


@pytest.mark.unit
def test_the_list_names_the_reference_pages_of_this_checkout():
    dc = checks()
    generated = _listed()

    assert generated.get("generate_cli_docs.py") == CLI_REFERENCE, (
        f"{dc.GENERATED_PAGES_LIST_NAME} in {dc.GENERATED_PAGES_LIST} names no page for "
        "generate_cli_docs.py. scripts/docs_checks.py reads the list from that path "
        "(GENERATED_PAGES_LIST there), and without it every generated page is read like "
        "one a person writes and each usage line of the CLI reference is a finding: if "
        "the freshness test moved, change GENERATED_PAGES_LIST to its new path"
    )
    gone = [rel for rel in generated.values() if not (REPO_ROOT / rel).is_file()]
    assert gone == [], "the list names pages this checkout does not have"


@pytest.mark.unit
def test_the_list_says_the_docs_checks_read_it_as_source():
    """scripts/docs_checks.py reads REFERENCE_PAGES with ast.literal_eval and never
    imports the freshness test, so the list has to stay one literal dict assigned once
    at the top of its module: a comprehension, ``{**other}``, an ``update`` or a ``del``
    after it would hide a page from the check, or keep one left out after the freshness
    test stopped holding it. The comment above the list says so, for whoever edits it."""
    dc = checks()
    lines = _read_real(FRESHNESS_TEST).splitlines()
    start = next(
        (
            index
            for index, line in enumerate(lines)
            if line.startswith(f"{dc.GENERATED_PAGES_LIST_NAME} = ")
        ),
        None,
    )
    assert start is not None, f"{FRESHNESS_TEST} no longer assigns the list"
    comment: list[str] = []
    for line in reversed(lines[:start]):
        if not line.startswith("#"):
            break
        comment.append(line.lstrip("#: ").strip())
    text = " ".join(reversed(comment))

    assert "scripts/docs_checks.py" in text, text
    assert "ast.literal_eval" in text, text


@pytest.mark.unit
def test_every_page_the_list_names_opens_with_the_banner_of_its_script():
    """A page that stops opening with its generator's banner stops being left out of the
    check, and its usage lines are reported one by one: this names the page instead."""
    dc = checks()
    generated = _listed()
    pages = [dc.parse_page(REPO_ROOT / rel, REPO_ROOT) for rel in generated.values()]

    read = [page.rel for page in pages if not dc.is_generated_page(page, generated)]

    assert read == [], "these listed pages do not open with their script's banner"


@pytest.mark.unit
def test_the_cli_reference_is_a_page_a_generator_writes():
    """The usage lines of the CLI reference were most of the seed. The list and its
    banner are what leave them out of the check: a banner reworded out of the shape the
    check reads, or a page left off the list, would put them back. What the check still
    counts on the page is the examples of the commands' help text, and the seed lists
    each of those."""
    dc = checks()
    page = dc.parse_page(REPO_ROOT / CLI_REFERENCE, REPO_ROOT)
    generated = _listed()

    assert dc.is_generated_page(page, generated), f"{CLI_REFERENCE} is read as a page"
    counted = [
        command for _block, command in dc.unexecuted_command_blocks(page, generated)
    ]
    assert [command for command in counted if USAGE_START.match(command)] == []
    listed = sorted(
        line.partition("\t")[2]
        for line in _committed_seed()
        if line.startswith(f"{CLI_REFERENCE}\t")
    )
    assert sorted(counted) == listed


@pytest.mark.unit
@pytest.mark.parametrize(
    "rel", JOURNEY_PAGES, ids=[Path(page).name for page in JOURNEY_PAGES]
)
def test_a_journey_page_of_this_checkout_has_a_banner_and_is_still_read(rel):
    """The case the list exists for: the page opens with a generator's banner, and the
    list does not name it, because its blocks are written by hand."""
    dc = checks()
    page = dc.parse_page(REPO_ROOT / rel, REPO_ROOT)

    assert dc.generator_banner(page) == "generate_journey_pages.py"
    assert not dc.is_generated_page(page, _listed())


@pytest.mark.unit
def test_the_seed_at_main_is_the_sum_of_the_pages_it_comes_from():
    """The total and the table it is the sum of are restated together, so a page added
    to the table, or a total changed alone, fails here: the number stays exact."""
    assert sum(SEED_PAGES_AT_MAIN.values()) == SEED_AT_MAIN


@pytest.mark.unit
def test_the_seed_holds_no_more_lines_than_main_had():
    lines = len(_committed_seed())

    assert lines <= SEED_AT_MAIN, (
        f"the seed holds {lines} lines; main had {SEED_AT_MAIN}, and it only shrinks"
    )


@pytest.mark.unit
def test_the_seed_holds_no_more_lines_than_main_had_on_any_page():
    """A bound on the total lets a change convert two lines and add two others. The ratchet
    job catches that against the fork point; this catches it without git, page by page,
    and a page main had no line for may have none."""
    held: dict[str, int] = {}
    for line in _committed_seed():
        page = line.partition("\t")[0]
        held[page] = held.get(page, 0) + 1

    grown = {
        page: (count, SEED_PAGES_AT_MAIN.get(page, 0))
        for page, count in sorted(held.items())
        if count > SEED_PAGES_AT_MAIN.get(page, 0)
    }

    assert grown == {}, (
        f"pages with more seed lines than main had (held, at main): {grown}; "
        "the seed only shrinks"
    )


@pytest.mark.integration
def test_the_check_reports_nothing_on_the_corpus(corpus):
    dc = checks()
    pages = dc.load_pages(corpus, REPO_ROOT)

    findings = dc.unexecuted_command_problems(pages, REPO_ROOT)

    assert findings == [], [str(f) for f in findings]
