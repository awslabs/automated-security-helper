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
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.models.workspace import WorkspaceExitCode
from tests.unit.docs.test_page_claims import (
    EXIT_CODES,
    SCALE_LARGE_REPOS,
    assert_on_page,
)

pytestmark = pytest.mark.unit

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


def _invoke(args: list[str]):
    return CliRunner().invoke(app, args, prog_name="ash")


def _one_line(text: str) -> str:
    return " ".join(text.split())


@pytest.fixture(autouse=True)
def _in_an_empty_directory(tmp_path, monkeypatch):
    """The working directory holds nothing, and no variable of the host names a file,
    a directory, a shard or a policy."""
    monkeypatch.chdir(tmp_path)
    for name in (
        "ASH_SOURCE_DIR",
        "ASH_OUTPUT_DIR",
        "ASH_CONFIG",
        "ASH_WORKSPACE",
        "ASH_WORKSPACE_CONFIG",
        "ASH_SHARD_INDEX",
        "ASH_SHARD_COUNT",
    ):
        monkeypatch.delenv(name, raising=False)


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
