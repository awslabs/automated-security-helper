"""Page claims about the scan subjects that the command line decides.

Most tests follow the pattern of test_page_claims.py: ``assert_on_page`` checks that a
sentence is still on its page, and the test then runs the real command to see that the
sentence is true, so a change to either half fails here.

The tests of scale-large-repos.md read their page the other way round. The page is
rendered for the release it pins, and the render respells the commands in its code, so a
sentence of the page can be about another command than the same sentence in its
template. Those tests read every clause of the committed page that names a workspace
scan and an option, and run the command line the clause names, spelled as the page
spells it.

What is pinned:

- scale-large-repos.md: what the page says a workspace scan given ``--source-dir`` or a
  shard option exits, and which of those options it says the command does not take.
- reference/exit-codes.md: where an option typed before a subcommand goes, and the
  example the page gives of one that is refused; the options that belong to a workspace
  scan, which ``ash scan fs`` refuses; what ``ash scan workspace`` refuses; and the
  workspace file that the page's example names.
- how-to/migrate-to-scan-subjects.md: the workspace scan without its subject, the three
  variables that name what a scan scans, the ``--scanners`` row, and what that row says
  ``--add-scanners`` adds to.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import NamedTuple
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli import scan_group
from automated_security_helper.cli.main import app
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.models.workspace import WorkspaceExitCode
from tests.unit.docs.test_page_claims import (
    EXIT_CODES,
    SCALE_LARGE_REPOS,
    _page_text,
    assert_on_page,
)

pytestmark = pytest.mark.unit

MIGRATE = "how-to/migrate-to-scan-subjects.md"

#: How a page names a workspace scan, and the start of its command line: the deprecated
#: option, alone or after ``ash scan``, and the subject 3.9 gives a workspace scan.
_WORKSPACE_COMMANDS = {
    "--workspace": ("scan", "--workspace"),
    "ash scan --workspace": ("scan", "--workspace"),
    "ash scan workspace": ("scan", "workspace"),
}
#: The options whose claims scale-large-repos.md is read for, each with the value a
#: command line gives it.
_DIRECTORY = {"--source-dir": "."}
_SHARDS = {"--shard-index": "0", "--shard-count": "2"}

_FENCE_LINE = re.compile(r"^\s*(```|~~~)")
_SPAN = re.compile(r"`([^`\n]+)`")
#: Where a clause ends: a full stop, a semicolon or a colon, then the next sentence, a
#: list item or a code span.
_CLAUSE_END = re.compile(r"(?<=[.;:])\s+(?=[A-Z`-])")
_STATED_EXIT = re.compile(r"\bexits?(?: code)? (\d)\b", re.IGNORECASE)
_TAKES_NONE = re.compile(r"\b(?:takes no|does not take|has no)\b")

#: exit-codes.md (the usage-error paragraph): where an option typed before a subcommand
#: goes, and an example of one that is refused.
_AN_OPTION_BEFORE_A_SUBCOMMAND = (
    "An option given to `ash` before a subcommand goes to the command that the words "
    "after it name, as though it were typed after that command: to `get` in "
    "`ash config get`, and to `report` in `ash results report`. It is a usage error "
    "when that command does not take the option: `ash --source-dir . results report` "
    "exits 5, because `ash results report` has no `--source-dir`, while "
    "`ash --source-dir . config get` works, because `ash config get` takes it."
)

#: exit-codes.md (`ash scan`, code 4): a workspace option given with no workspace.
_THE_WORKSPACE_OPTIONS_WITHOUT_A_WORKSPACE = (
    "| 4 | A workspace error (see [Workspace mode](#workspace)); or, with the deprecated "
    "`ash scan` with no subject or `ash` with no subcommand, `--dry-run`, "
    "`--allow-missing-projects`, or `--workspace-config` given without `--workspace`. "
    "`ash scan fs` has none of the three and refuses each with 5 |"
)

#: exit-codes.md (`ash scan`, examples): the workspace file that the example names.
_A_MISSING_WORKSPACE_FILE = (
    "A workspace file that does not exist is a workspace error, 4:"
)
_THE_EXAMPLE_COMMAND = "ash scan workspace no-such.code-workspace"

#: exit-codes.md (`ash scan`, code 0, and Workspace mode, codes 4 and 5).
_A_WORKSPACE_DRY_RUN_EXITS_0 = (
    "Also `--version`, and `ash scan workspace` with `--dry-run`."
)
_THE_DIRECTORY_AND_THE_WORKSPACE = (
    "the deprecated `--workspace` is given with `--source-dir` or `ASH_SOURCE_DIR`, "
    "which `ash scan workspace` does not take (it refuses the option with 5 and does "
    "not read the variable)"
)
_THE_WORKSPACE_SUBJECT_REFUSES = (
    "`ash scan workspace` also exits 5 when it is given no file, or an option it does "
    "not define, such as `--source-dir` or a shard option."
)

#: migrate-to-scan-subjects.md: the workspace scan, and the deprecated forms of it.
_THE_WORKSPACE_ROW = (
    "| `ash scan --workspace project.code-workspace` | "
    "`ash scan workspace project.code-workspace` | "
    "`ash --workspace project.code-workspace` moves the same way. "
    "`--workspace-config`, `--allow-missing-projects` and `--dry-run` go with the "
    "subject: `ash scan fs` does not take them. |"
)
_A_WORKSPACE_SCAN_WITHOUT_ITS_SUBJECT = (
    "A workspace scan reached without its subject, `ash scan --workspace "
    "project.code-workspace` or `ash --workspace project.code-workspace`, still runs "
    "in 3.9 and prints one deprecation line that names `ash scan workspace <file>`."
)

#: migrate-to-scan-subjects.md: the variables that name what a scan scans.
_THE_VARIABLES = (
    "`ASH_SOURCE_DIR` still names the directory to scan when you give no path "
    "argument, and `ASH_WORKSPACE` and `ASH_WORKSPACE_CONFIG` still name the file and "
    "the policy file of a workspace scan when you give no file argument and no "
    "`--workspace-config`."
)
_THE_VARIABLES_ARE_TOLD = (
    "A scan that reads one of them that way prints one deprecation line for it, as "
    "`--source-dir` does, and ASH 4.0 stops reading them for a scan. The argument, or "
    "`--workspace-config`, takes its place and prints no line."
)

#: migrate-to-scan-subjects.md: what `--add-scanners` adds to. A default set exists only
#: in `--mode precommit` or as the operator's `default_scanners.only`; elsewhere the
#: names the flag gives are the whole selection.
_THE_ADD_SCANNERS_SENTENCE = (
    "`--only-scanners` states the whole selection. `--add-scanners` adds scanners to "
    "the default set of `--mode precommit`, or to the operator's "
    "`default_scanners.only`; with neither, the scanners it names are the whole "
    "selection."
)
#: migrate-to-scan-subjects.md: `--scanners`, whose line names no removal release.
_THE_SCANNERS_ROW = (
    "| `ash scan fs --scanners bandit,semgrep` | "
    "`ash scan fs --only-scanners bandit,semgrep` | "
    + _THE_ADD_SCANNERS_SENTENCE
    + " `ASH_SCANNERS` is deprecated with `--scanners`. `--scanners` keeps its behavior "
    "and prints one `DeprecationWarning:` line that names no removal release. |"
)

ORCHESTRATOR_CREATE = (
    "automated_security_helper.core.orchestrator.ASHScanOrchestrator.create"
)
_THE_SCANNERS_LINE_NAMES_NO_RELEASE = (
    "ASH 4.0 removes the old spellings, and their deprecation lines say so, except the "
    "line for `--scanners` and `ASH_SCANNERS`, which names no removal release."
)


def _invoke(args: list[str]):
    return CliRunner().invoke(app, args, prog_name="ash")


def _one_line(text: str) -> str:
    return " ".join(text.split())


def _deprecation_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith("Deprecated:")]


@pytest.fixture(autouse=True)
def _in_an_empty_directory(tmp_path, monkeypatch):
    """The working directory holds nothing, and no variable of the host names a file,
    a directory, a shard, a policy or a scanner selection."""
    monkeypatch.chdir(tmp_path)
    for name in (
        "ASH_SOURCE_DIR",
        "ASH_OUTPUT_DIR",
        "ASH_CONFIG",
        "ASH_WORKSPACE",
        "ASH_WORKSPACE_CONFIG",
        "ASH_SHARD_INDEX",
        "ASH_SHARD_COUNT",
        "ASH_SCANNERS",
        "ASH_EXCLUDED_SCANNERS",
        "ASH_MODE",
        "ASH_IN_CONTAINER",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def engine(monkeypatch):
    """Stands in for the engine behind the subjects, so that no scan can start, and
    records what it was handed."""
    calls: list[dict] = []
    monkeypatch.setattr(
        scan_group,
        "run_ash_scan_cli_command",
        lambda *args, **kwargs: calls.append(kwargs),
    )
    return calls


def _workspace(root: Path) -> Path:
    (root / "api").mkdir()
    path = root / "dev.code-workspace"
    path.write_text(json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8")
    return path


class _Claim(NamedTuple):
    """One clause of a page about a workspace scan: the command line it names, the
    options it names, the exits it states, and whether it says the command takes none
    of the options."""

    command: tuple[str, ...]
    options: tuple[str, ...]
    exits: frozenset[int]
    takes_none: bool
    clause: str


def _prose_paragraphs(text: str) -> list[str]:
    """The paragraphs of a page outside its fenced blocks, each on one line."""
    paragraphs: list[str] = []
    lines: list[str] = []
    fenced = False
    for line in [*text.splitlines(), ""]:
        if _FENCE_LINE.match(line):
            fenced = not fenced
        elif fenced:
            continue
        elif line.strip():
            lines.append(line)
            continue
        # A blank line or a fence ends the paragraph before it.
        if lines:
            paragraphs.append(_one_line(" ".join(lines)))
            lines = []
    return paragraphs


def _clauses(paragraph: str) -> list[str]:
    """``paragraph`` cut where each of its clauses ends, never inside a code span."""
    masked = _SPAN.sub(lambda span: f"`{'x' * len(span[1])}`", paragraph)
    cuts = list(_CLAUSE_END.finditer(masked))
    starts = [0, *(cut.end() for cut in cuts)]
    ends = [*(cut.start() for cut in cuts), len(paragraph)]
    return [paragraph[start:end] for start, end in zip(starts, ends, strict=True)]


def _paragraph_claims(paragraph: str, options: dict[str, str]) -> list[_Claim]:
    """The claims ``paragraph`` makes about a workspace scan given one of ``options``.

    A clause makes one for each workspace scan it names in a code span, when it names
    one of the options in a code span too. Its exits are the codes its prose states
    (``exit 4``, ``exits 5``), and it says that the command takes none of the options it
    names when its prose says ``takes no``, ``does not take`` or ``has no``.
    """
    claims: list[_Claim] = []
    for clause in _clauses(paragraph):
        spans = _SPAN.findall(clause)
        named = tuple(dict.fromkeys(span for span in spans if span in options))
        commands = {_WORKSPACE_COMMANDS.get(span) for span in spans} - {None}
        if not named:
            continue
        prose = _SPAN.sub("", clause)
        exits = frozenset(int(code) for code in _STATED_EXIT.findall(prose))
        takes_none = _TAKES_NONE.search(prose) is not None
        for command in sorted(commands):
            claims.append(_Claim(command, named, exits, takes_none, clause))
    return claims


def _page_claims(page: str, options: dict[str, str]) -> list[_Claim]:
    """Every claim the committed ``docs/content/<page>`` makes about a workspace scan
    given one of ``options``.

    The page is read as it is committed, rendered for the release it pins, so each
    command is named as that release spells it. The claims are not copied from its
    template and respelled: a respelling can turn a sentence about one command into a
    sentence about another, and the copy would be held to the first.
    """
    return [
        claim
        for paragraph in _prose_paragraphs(_page_text(page))
        for claim in _paragraph_claims(paragraph, options)
    ]


def _held_to_the_cli(
    claims: list[_Claim], options: dict[str, str], workspace: Path
) -> list[str]:
    """What is false in ``claims``, each run as the command lines it is about.

    Those are the command line with each option the claim names, alone, and with all of
    them, when it names more than one. Each has to exit with the code the claim states.
    A claim that the command takes none of the options holds only when the command
    refuses each of them, alone, as an option it does not define, with 5. No command
    line may be given two exits, by one claim or by two.
    """
    problems: list[str] = []
    stated: dict[tuple[str, ...], set[int]] = {}
    for claim in claims:
        command = " ".join(["ash", *claim.command])
        option_sets = [(option,) for option in claim.options]
        if len(claim.options) > 1:
            option_sets.append(claim.options)
        for given in option_sets:
            argv = [*claim.command, str(workspace)]
            for option in given:
                argv += [option, options[option]]
            stated.setdefault(tuple(argv), set()).update(claim.exits)
            result = _invoke(argv)
            output = _one_line(result.output)
            for code in sorted(claim.exits - {result.exit_code}):
                problems.append(
                    f"{claim.clause!r}: `{command}` with {' '.join(given)} exits "
                    f"{result.exit_code}, not {code}: {output}"
                )
            undefined = (
                result.exit_code == ASH_EXIT_USAGE_ERROR
                and "No such option" in output
                and given[0] in output
            )
            if claim.takes_none and len(given) == 1 and not undefined:
                problems.append(
                    f"{claim.clause!r}: `{command}` takes {given[0]}, and with it "
                    f"exits {result.exit_code}: {output}"
                )
    for argv, exits in stated.items():
        if len(exits) > 1:
            problems.append(
                f"the page gives `ash {' '.join(argv)}` two exits, {sorted(exits)}"
            )
    return problems


def test_the_page_says_what_a_sharded_workspace_scan_exits(tmp_path):
    """scale-large-repos.md (What sharding does not do).

    Every clause of the page, as committed, that names a workspace scan and a shard
    option is run as the command line it names. A workspace scan with ``--shard-index``
    or ``--shard-count`` exits 5 in either spelling, for two reasons: the subject has no
    shard options, while the deprecated ``--workspace`` has both and refuses either
    beside it (``_validate_shard_options`` in cli/scan.py, in 3.8.0 as in this tree).
    So a page that names the deprecated form cannot say that it takes neither. The
    workspace holds a project that a scan would read, so an exit of 5 is the refusal and
    not a scan.
    """
    claims = _page_claims(SCALE_LARGE_REPOS, _SHARDS)
    workspace = _workspace(tmp_path)

    problems = _held_to_the_cli(claims, _SHARDS, workspace)

    assert not problems, "\n".join(problems)
    assert any(claim.exits for claim in claims), claims


def test_the_page_says_what_a_workspace_scan_given_a_directory_exits(tmp_path):
    """scale-large-repos.md (Scan a multi-project workspace, the exit code).

    Every clause of the page, as committed, that names a workspace scan and
    ``--source-dir`` is run as the command line it names. The deprecated ``--workspace``
    takes ``--source-dir`` and refuses the pair as the workspace error, 4
    (``_handle_workspace_mode`` in cli/scan.py, in 3.8.0 as in this tree), and the page
    has to say that and give the command line no other exit. The subject has no
    ``--source-dir`` and refuses it with 5, and a page that names the subject is held to
    that instead.
    """
    claims = _page_claims(SCALE_LARGE_REPOS, _DIRECTORY)
    workspace = _workspace(tmp_path)

    problems = _held_to_the_cli(claims, _DIRECTORY, workspace)

    assert not problems, "\n".join(problems)
    deprecated = {
        code
        for claim in claims
        if claim.command == ("scan", "--workspace")
        for code in claim.exits
    }
    assert deprecated == {WorkspaceExitCode.WORKSPACE_ERROR}, claims


def test_the_page_reader_reads_one_claim_from_each_clause():
    """The reader of the two tests above.

    A paragraph is cut into its clauses outside its code spans, and a clause that names
    a workspace scan and one of the options is a claim: its command line, the options,
    the exits it states, and whether it says the command takes none of them. Read so, a
    sentence that gives the deprecated option and ``--source-dir`` exit 4 and then says
    that ``ash scan --workspace`` takes no ``--source-dir``, so it exits 5, gives one
    command line two exits. The text of a fenced block is not read.
    """
    deprecated = ("scan", "--workspace")
    first = (
        "The deprecated `--workspace` option and `--source-dir` together also exit 4"
    )
    second = "`ash scan --workspace` takes no `--source-dir`, so it exits 5 instead."
    sharded = "`ash scan workspace` with `--shard-index` or `--shard-count` exits 5."

    def read(paragraph: str, options: dict[str, str]) -> list[tuple]:
        return [
            (claim.command, claim.options, claim.exits, claim.takes_none)
            for claim in _paragraph_claims(paragraph, options)
        ]

    assert read(f"{first}; {second}", _DIRECTORY) == [
        (deprecated, ("--source-dir",), {4}, False),
        (deprecated, ("--source-dir",), {5}, True),
    ]
    assert read(f"{first}.", _DIRECTORY) == [
        (deprecated, ("--source-dir",), {4}, False)
    ]
    assert read(sharded, _SHARDS) == [
        (("scan", "workspace"), ("--shard-index", "--shard-count"), {5}, False)
    ]
    assert _prose_paragraphs(f"```text\n{second}\n```\n\n{first}.\n") == [f"{first}."]


def test_an_option_before_a_subcommand_goes_to_the_command_it_names(tmp_path):
    """exit-codes.md (the usage-error paragraph).

    ``ash --source-dir . results report`` exits 5 and names the command the option was
    judged against, because ``report`` has no ``--source-dir``. The same option before
    ``config get``, which takes it, is not refused, and it reaches that command as
    though it were typed after it: the config ``get`` prints is the one in the
    directory the option names, whichever side of ``config get`` the option is on.
    """
    assert_on_page(EXIT_CODES, _AN_OPTION_BEFORE_A_SUBCOMMAND)
    refusal = "'ash results report' does not take --source-dir, given before it"
    project = tmp_path / "proj"
    project.mkdir()
    config = project / ".ash.yaml"
    config.write_text("project_name: payments-api\n", encoding="utf-8")

    refused = _invoke(["--source-dir", ".", "results", "report"])
    taken = _invoke(["--source-dir", ".", "config", "get"])
    before = _invoke(["--source-dir", "proj", "config", "get"])
    after = _invoke(["config", "get", "--source-dir", "proj"])

    assert refused.exit_code == ASH_EXIT_USAGE_ERROR, refused.output
    assert refusal in _one_line(refused.output), refused.output
    assert taken.exit_code == 0, taken.output
    assert before.exit_code == after.exit_code == 0, (before.output, after.output)
    assert "payments-api" in before.output, before.output
    assert "payments-api" in after.output, after.output


@pytest.mark.parametrize(
    "given",
    [
        pytest.param(["--dry-run"], id="dry-run"),
        pytest.param(["--allow-missing-projects"], id="allow-missing-projects"),
        pytest.param(["--workspace-config", "policy.yaml"], id="workspace-config"),
    ],
)
def test_the_options_of_a_workspace_scan_need_a_workspace(given):
    """exit-codes.md (`ash scan`, code 4).

    Given to the deprecated form with no subject, which has no workspace, each option
    is the workspace error, 4. ``ash scan fs`` has none of the three, so it refuses
    each as a usage error, 5, and runs nothing.
    """
    assert_on_page(EXIT_CODES, _THE_WORKSPACE_OPTIONS_WITHOUT_A_WORKSPACE)

    deprecated = _invoke(["scan", *given])
    on_fs = _invoke(["scan", "fs", ".", *given])

    assert deprecated.exit_code == WorkspaceExitCode.WORKSPACE_ERROR, deprecated.output
    assert "only applies in workspace mode" in _one_line(deprecated.output)
    assert on_fs.exit_code == ASH_EXIT_USAGE_ERROR, on_fs.output
    text = _one_line(on_fs.output)
    assert "No such option" in text, text
    assert given[0] in text, text


def test_a_workspace_file_that_does_not_exist_is_the_workspace_error():
    """exit-codes.md (`ash scan`, examples): the command the page runs."""
    assert_on_page(EXIT_CODES, _A_MISSING_WORKSPACE_FILE)
    assert_on_page(EXIT_CODES, _THE_EXAMPLE_COMMAND)

    result = _invoke(["scan", "workspace", "no-such.code-workspace"])

    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR, result.output


def test_the_workspace_subject_takes_no_directory(tmp_path, monkeypatch):
    """exit-codes.md (`ash scan`, code 0; Workspace mode, codes 4 and 5).

    ``ash scan workspace`` refuses ``--source-dir``, a shard option and a missing file
    with 5. It does not read ``ASH_SOURCE_DIR``, so a dry run with the variable set
    still exits 0, while the deprecated ``--workspace`` refuses the same variable with 4.
    """
    assert_on_page(EXIT_CODES, _A_WORKSPACE_DRY_RUN_EXITS_0)
    assert_on_page(EXIT_CODES, _THE_DIRECTORY_AND_THE_WORKSPACE)
    assert_on_page(EXIT_CODES, _THE_WORKSPACE_SUBJECT_REFUSES)
    workspace = _workspace(tmp_path)

    refused = _invoke(["scan", "workspace", str(workspace), "--source-dir", "."])
    sharded = _invoke(["scan", "workspace", str(workspace), "--shard-index", "0"])
    no_file = _invoke(["scan", "workspace"])
    monkeypatch.setenv("ASH_SOURCE_DIR", str(tmp_path))
    dry_run = _invoke(["scan", "workspace", str(workspace), "--dry-run"])
    deprecated = _invoke(["scan", "--workspace", str(workspace), "--dry-run"])

    assert refused.exit_code == ASH_EXIT_USAGE_ERROR, refused.output
    assert "--source-dir" in _one_line(refused.output), refused.output
    assert sharded.exit_code == ASH_EXIT_USAGE_ERROR, sharded.output
    assert "No such option" in _one_line(sharded.output), sharded.output
    assert "--shard-index" in _one_line(sharded.output), sharded.output
    assert no_file.exit_code == ASH_EXIT_USAGE_ERROR, no_file.output
    assert dry_run.exit_code == WorkspaceExitCode.SUCCESS, dry_run.output
    assert deprecated.exit_code == WorkspaceExitCode.WORKSPACE_ERROR, deprecated.output
    assert "ASH_SOURCE_DIR" in deprecated.output, deprecated.output


@pytest.mark.parametrize(
    "prefix",
    [pytest.param(["scan"], id="scan"), pytest.param([], id="bare-ash")],
)
def test_a_workspace_scan_without_its_subject_names_the_subject(tmp_path, prefix):
    """migrate-to-scan-subjects.md (Old and new spellings).

    ``ash scan --workspace FILE`` and ``ash --workspace FILE`` still run, each printing
    one deprecation line that names ``ash scan workspace <file>``, and the subject
    prints none. A dry run shows the plan and scans nothing.
    """
    assert_on_page(MIGRATE, _THE_WORKSPACE_ROW)
    assert_on_page(MIGRATE, _A_WORKSPACE_SCAN_WITHOUT_ITS_SUBJECT)
    workspace = _workspace(tmp_path)

    deprecated = _invoke([*prefix, "--workspace", str(workspace), "--dry-run"])
    subject = _invoke(["scan", "workspace", str(workspace), "--dry-run"])

    assert deprecated.exit_code == WorkspaceExitCode.SUCCESS, deprecated.output
    assert subject.exit_code == WorkspaceExitCode.SUCCESS, subject.output
    (line,) = _deprecation_lines(deprecated.stderr)
    assert "ash scan workspace <file>" in line, line
    assert _deprecation_lines(subject.stderr) == [], subject.stderr


def test_the_variables_that_name_what_to_scan_are_told_once_each(engine, monkeypatch):
    """migrate-to-scan-subjects.md (below the table).

    A scan that reads ``ASH_SOURCE_DIR``, ``ASH_WORKSPACE`` or ``ASH_WORKSPACE_CONFIG``
    for what the command line left out prints one line for each variable it reads. A
    scan that is given the path, the file or the option prints none.
    """
    assert_on_page(MIGRATE, _THE_VARIABLES)
    assert_on_page(MIGRATE, _THE_VARIABLES_ARE_TOLD)
    monkeypatch.setenv("ASH_SOURCE_DIR", "/from/env")
    monkeypatch.setenv("ASH_WORKSPACE", "dev.code-workspace")
    monkeypatch.setenv("ASH_WORKSPACE_CONFIG", "policy.yaml")

    directory = _invoke(["scan", "fs"])
    workspace = _invoke(["scan", "workspace"])
    given = [
        _invoke(["scan", "fs", "given"]),
        _invoke(
            [
                "scan",
                "workspace",
                "given.code-workspace",
                "--workspace-config",
                "given.yaml",
            ]
        ),
    ]

    (directory_line,) = _deprecation_lines(directory.stderr)
    assert "ASH_SOURCE_DIR" in directory_line, directory_line
    file_line, policy_line = _deprecation_lines(workspace.stderr)
    assert "`ASH_WORKSPACE` " in file_line, file_line
    assert "`ASH_WORKSPACE_CONFIG` " in policy_line, policy_line
    for result in given:
        assert result.exit_code == 0, result.output
        assert _deprecation_lines(result.stderr) == [], result.stderr


def test_the_scanners_option_prints_one_line_that_names_no_removal_release(
    tmp_path, monkeypatch
):
    """migrate-to-scan-subjects.md (the introduction and the ``--scanners`` row).

    ``--scanners`` still selects what it did and prints one ``DeprecationWarning:``
    line that names ``--only-scanners`` and ``--add-scanners`` and no release.
    """
    from automated_security_helper.cli import scan as scan_module
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    assert_on_page(MIGRATE, _THE_SCANNERS_ROW)
    assert_on_page(MIGRATE, _THE_SCANNERS_LINE_NAMES_NO_RELEASE)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    forwarded: dict = {}

    def fake_run_ash_scan(**kwargs):
        forwarded.update(kwargs)
        return AshAggregatedResults()

    monkeypatch.setattr(scan_module, "run_ash_scan", fake_run_ash_scan)
    source = tmp_path / "src"
    source.mkdir()

    result = _invoke(
        [
            "scan",
            "fs",
            str(source),
            "--output-dir",
            str(tmp_path / "out"),
            "--no-progress",
            "--scanners",
            "bandit",
        ]
    )

    lines = [
        line
        for line in result.output.splitlines()
        if line.startswith("DeprecationWarning:")
    ]
    assert len(lines) == 1, result.output
    assert "--only-scanners" in lines[0] and "--add-scanners" in lines[0], lines[0]
    assert "4.0" not in lines[0], lines[0]
    assert forwarded["scanners"] == ["bandit"], forwarded


def _selection_handed_to_the_orchestrator(
    monkeypatch, root: Path, *options: str
) -> dict:
    """What ``ash scan fs`` with *options* hands ``ASHScanOrchestrator.create``, which
    stops the run there, so no scanner starts."""
    # Besides the fixture's: each of these, exported, can stop the run before the
    # orchestrator is asked, with no defect in the selection.
    for name in (
        "ASH_STAGED",
        "ASH_CHANGED_FILES_ONLY",
        "ASH_BASE_REF",
        "ASH_BASELINE",
        "ASH_PLUGIN_MODULES",
    ):
        monkeypatch.delenv(name, raising=False)
    source = root / "src"
    source.mkdir(parents=True)
    with patch(ORCHESTRATOR_CREATE, side_effect=RuntimeError("stop")) as create:
        result = _invoke(
            [
                "scan",
                "fs",
                str(source),
                "--output-dir",
                str(root / "out"),
                "--no-progress",
                *options,
            ]
        )
    assert create.call_count == 1, result.output
    return create.call_args.kwargs


def test_add_scanners_adds_to_a_default_set_and_is_the_whole_selection_without_one(
    tmp_path, monkeypatch
):
    """migrate-to-scan-subjects.md (the ``--scanners`` row, on ``--add-scanners``).

    Outside ``--mode precommit``, with no ``default_scanners.only`` from the operator,
    the scanners ``--add-scanners`` names are the whole selection. In precommit mode
    they join the mode's default set, and beside the operator's ``only`` list they
    join that list. The page said the flag adds to the mode's default set in every
    mode. The command runs before the page is read, so a red at the page is the
    page's alone.
    """
    from automated_security_helper.interactions.run_ash_scan import (
        PRECOMMIT_MODE_SCANNERS,
    )

    local = _selection_handed_to_the_orchestrator(
        monkeypatch, tmp_path / "local", "--add-scanners", "bandit"
    )
    layers = local["selection_layers"]
    # The local mode has no default set, and no config gives one here.
    assert list(layers.mode_default) == [], layers
    assert local["enabled_scanners"] == ["bandit"], local["enabled_scanners"]
    # The orchestrator folds in the operator's default_scanners: empty, the flag is
    # still the whole selection; an only list, and the flag adds to it.
    assert layers.fold([], []).names == ["bandit"], layers
    assert set(layers.fold(["checkov"], []).names) == {"bandit", "checkov"}, layers

    precommit = _selection_handed_to_the_orchestrator(
        monkeypatch,
        tmp_path / "precommit",
        "--mode",
        "precommit",
        "--add-scanners",
        "grype",
    )
    assert set(precommit["enabled_scanners"]) == {"grype", *PRECOMMIT_MODE_SCANNERS}

    assert_on_page(MIGRATE, _THE_ADD_SCANNERS_SENTENCE)
