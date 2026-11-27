"""Page claims about the scan subjects that the command line decides.

Each test follows the pattern of test_page_claims.py: ``assert_on_page`` checks that a
sentence is still on its page, and the test then runs the real command to see that the
sentence is true, so a change to either half fails here.

What is pinned:

- scale-large-repos.md: a sharded workspace scan is a usage error, with exit 5, in the
  spelling 3.9 gives a workspace scan and in the deprecated one.
- reference/exit-codes.md: where an option typed before a subcommand goes, and the
  example the page gives of one that is refused; the options that belong to a workspace
  scan, which ``ash scan fs`` refuses; what ``ash scan workspace`` refuses; and the
  workspace file that the page's example names.
- how-to/migrate-to-scan-subjects.md: the workspace scan without its subject, the three
  variables that name what a scan scans, and the ``--scanners`` row.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli import scan_group
from automated_security_helper.cli.main import app
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.models.workspace import WorkspaceExitCode
from tests.unit.docs.test_page_claims import (
    EXIT_CODES,
    SCALE_LARGE_REPOS,
    assert_on_page,
)

pytestmark = pytest.mark.unit

MIGRATE = "how-to/migrate-to-scan-subjects.md"

#: scale-large-repos.md (What sharding does not do).
_SHARDS_DO_NOT_COMBINE_WITH_A_WORKSPACE = (
    "It does not combine with workspace scans: `ash scan workspace` takes no "
    "`--shard-index` or `--shard-count`, and the scan exits 5."
)

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

#: migrate-to-scan-subjects.md: `--scanners`, whose line names no removal release.
_THE_SCANNERS_ROW = (
    "| `ash scan fs --scanners bandit,semgrep` | "
    "`ash scan fs --only-scanners bandit,semgrep` | `--only-scanners` states the whole "
    "selection, and `--add-scanners` adds scanners to the mode's default set. "
    "`ASH_SCANNERS` is deprecated with `--scanners`. `--scanners` keeps its behavior "
    "and prints one `DeprecationWarning:` line that names no removal release. |"
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


@pytest.mark.parametrize(
    ("scan", "refusal"),
    [
        pytest.param(
            ["scan", "workspace"],
            "--shard-index",
            id="the-workspace-subject",
        ),
        pytest.param(
            ["scan", "--workspace"],
            "cannot be combined with --workspace",
            id="the-deprecated-option",
        ),
    ],
)
def test_a_sharded_workspace_scan_exits_5(tmp_path, scan, refusal):
    """scale-large-repos.md (What sharding does not do).

    ``ash scan workspace FILE --shard-index 0 --shard-count 2`` must exit 5, because the
    subject has no shard options, and so must the deprecated ``ash scan --workspace FILE``
    with the same options, which names the combination it refuses. The workspace holds a
    project that a scan would read, so an exit of 5 is the refusal and not a scan.
    """
    assert_on_page(SCALE_LARGE_REPOS, _SHARDS_DO_NOT_COMBINE_WITH_A_WORKSPACE)
    workspace = _workspace(tmp_path)

    result = _invoke(
        [*scan, str(workspace), "--shard-index", "0", "--shard-count", "2"]
    )

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert refusal in _one_line(result.output), result.output


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

    ``ash scan workspace`` refuses ``--source-dir`` and a missing file with 5. It does
    not read ``ASH_SOURCE_DIR``, so a dry run with the variable set still exits 0, while
    the deprecated ``--workspace`` refuses the same variable with 4.
    """
    assert_on_page(EXIT_CODES, _A_WORKSPACE_DRY_RUN_EXITS_0)
    assert_on_page(EXIT_CODES, _THE_DIRECTORY_AND_THE_WORKSPACE)
    assert_on_page(EXIT_CODES, _THE_WORKSPACE_SUBJECT_REFUSES)
    workspace = _workspace(tmp_path)

    refused = _invoke(["scan", "workspace", str(workspace), "--source-dir", "."])
    no_file = _invoke(["scan", "workspace"])
    monkeypatch.setenv("ASH_SOURCE_DIR", str(tmp_path))
    dry_run = _invoke(["scan", "workspace", str(workspace), "--dry-run"])
    deprecated = _invoke(["scan", "--workspace", str(workspace), "--dry-run"])

    assert refused.exit_code == ASH_EXIT_USAGE_ERROR, refused.output
    assert "--source-dir" in _one_line(refused.output), refused.output
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
