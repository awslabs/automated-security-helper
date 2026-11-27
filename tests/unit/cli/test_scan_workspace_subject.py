"""``ash scan workspace FILE`` scans the projects of a workspace file, and only that.

What is pinned here:

* FILE is the workspace file the engine is handed, and ASH_WORKSPACE names it when no
  argument does. The subject's own options are the workspace scan's
  (``--workspace-config``, which ASH_WORKSPACE_CONFIG sets, ``--allow-missing-projects``
  and ``--dry-run``) beside the options every scan takes.
* The options of a directory scan, of an image scan and of a remote repository are not
  the subject's: click refuses them as unknown options, with ASH's usage-error code.
  ``ash scan fs`` takes none of the workspace options.
* The subject prints no deprecation line. The two forms with no subject that scan a
  workspace, ``ash --workspace FILE`` and ``ash scan --workspace FILE``, still run, exit
  as they did, and print one line naming ``ash scan workspace <file>``.
* Options typed before ``scan workspace`` reach the subject, or are refused by name.

Rows that need the engine's own answer (a line, an exit code) run it for real against a
workspace file in a temporary directory, with ``--dry-run`` or the scan entry point
replaced so nothing is scanned. The others replace the engine with a stand-in that
records what it was handed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import typer.main
from typer.testing import CliRunner

from automated_security_helper.cli import scan_group
from automated_security_helper.cli.main import app
from automated_security_helper.cli.scan_deprecation import (
    SCAN_NOUN_META,
    WORKSPACE_WITHOUT_SUBJECT_LINE,
)
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.models.workspace import WorkspaceExitCode

pytestmark = pytest.mark.unit

#: The options a workspace scan has, which `ash scan fs` does not take.
WORKSPACE_OPTION_NAMES = {
    "workspace",
    "workspace_config",
    "allow_missing_projects",
    "dry_run",
}

#: The options that read one directory, as the arguments that give each and the
#: spelling a refusal names.
DIRECTORY_ONLY = [
    pytest.param(["--source-dir", "src"], "--source-dir", id="source-dir"),
    pytest.param(
        ["--changed-files-only"], "--changed-files-only", id="changed-files-only"
    ),
    pytest.param(["--base-ref", "main"], "--base-ref", id="base-ref"),
    pytest.param(["--staged"], "--staged", id="staged"),
    pytest.param(["--baseline", "baseline.json"], "--baseline", id="baseline"),
    pytest.param(["--use-existing"], "--use-existing", id="use-existing"),
    pytest.param(["--shard-index", "1"], "--shard-index", id="shard-index"),
    pytest.param(["--shard-count", "2"], "--shard-count", id="shard-count"),
]

#: The options that name an image or a remote repository to scan.
OTHER_SUBJECTS = [
    pytest.param(["--image", "alpine:3"], "--image", id="image"),
    pytest.param(
        ["--image-archive", "image.tar"], "--image-archive", id="image-archive"
    ),
    pytest.param(["--image-layout", "layout"], "--image-layout", id="image-layout"),
    pytest.param(
        ["--source-git", "https://example.com/repo.git"],
        "--source-git",
        id="source-git",
    ),
    pytest.param(["--git-ref", "main"], "--git-ref", id="git-ref"),
    pytest.param(["--git-depth", "1"], "--git-depth", id="git-depth"),
]

#: The options of a workspace scan, as the arguments that give each.
WORKSPACE_ONLY = [
    pytest.param(["--workspace", "dev.code-workspace"], "--workspace", id="workspace"),
    pytest.param(
        ["--workspace-config", "policy.yaml"],
        "--workspace-config",
        id="workspace-config",
    ),
    pytest.param(
        ["--allow-missing-projects"],
        "--allow-missing-projects",
        id="allow-missing-projects",
    ),
    pytest.param(["--dry-run"], "--dry-run", id="dry-run"),
]


def _invoke(args: list[str], **kwargs):
    return CliRunner().invoke(app, args, prog_name="ash", **kwargs)


def _deprecation_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith("Deprecated:")]


def _one_line(text: str) -> str:
    return " ".join(text.split())


@pytest.fixture(autouse=True)
def _clear_ash_env(monkeypatch):
    """A variable of the host would name a directory, a file or a policy for a row
    that names none."""
    for name in (
        "ASH_SOURCE_DIR",
        "ASH_OUTPUT_DIR",
        "ASH_CONFIG",
        "ASH_WORKSPACE",
        "ASH_WORKSPACE_CONFIG",
    ):
        monkeypatch.delenv(name, raising=False)


class _EngineStub:
    """Stands in for the engine behind the subjects: records what it was handed."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def __call__(self, *args, **kwargs):
        self.calls.append(kwargs)


@pytest.fixture
def engine(monkeypatch):
    stub = _EngineStub()
    monkeypatch.setattr(scan_group, "run_ash_scan_cli_command", stub)
    return stub


@pytest.fixture
def no_scan(monkeypatch):
    """Replace the scan entry point with a recorder, so reaching it is visible."""
    calls: list[dict] = []

    def _record(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr(
        "automated_security_helper.cli.scan.run_ash_scan", _record, raising=True
    )
    return calls


def _workspace(root: Path, folders: tuple[str, ...] = ("api",)) -> Path:
    """A workspace file naming *folders*, each of which exists."""
    for folder in folders:
        (root / folder).mkdir(parents=True, exist_ok=True)
    path = root / "dev.code-workspace"
    path.write_text(
        json.dumps({"folders": [{"path": folder} for folder in folders]}),
        encoding="utf-8",
    )
    return path


# --------------------------------------------------------------------------- #
# The file and the options the engine is handed
# --------------------------------------------------------------------------- #


def test_the_subject_hands_the_engine_the_workspace_file(engine):
    result = _invoke(["scan", "workspace", "dev.code-workspace"])

    assert result.exit_code == 0, result.output
    (call,) = engine.calls
    assert call["workspace"] == "dev.code-workspace"
    assert "file" not in call, "the engine has no `file` parameter"
    assert "source_dir" not in call, "a workspace scan names no directory"
    assert call["ctx"].meta[SCAN_NOUN_META] == scan_group.WORKSPACE_SUBJECT


def test_the_options_of_a_workspace_scan_reach_the_engine(engine):
    result = _invoke(
        [
            "scan",
            "workspace",
            "dev.code-workspace",
            "--workspace-config",
            "policy.yaml",
            "--allow-missing-projects",
            "--dry-run",
            "--output-dir",
            "out",
        ]
    )

    assert result.exit_code == 0, result.output
    (call,) = engine.calls
    assert call["workspace_config"] == "policy.yaml"
    assert call["allow_missing_projects"] is True
    assert call["dry_run"] is True
    assert call["output_dir"] == "out"


def test_the_options_of_a_workspace_scan_are_off_unless_given(engine):
    result = _invoke(["scan", "workspace", "dev.code-workspace"])

    assert result.exit_code == 0, result.output
    (call,) = engine.calls
    assert call["workspace_config"] is None
    assert call["allow_missing_projects"] is False
    assert call["dry_run"] is False


def test_a_file_named_like_an_option_is_given_after_a_double_dash(engine):
    result = _invoke(["scan", "workspace", "--", "-odd.code-workspace"])

    assert result.exit_code == 0, result.output
    assert [call["workspace"] for call in engine.calls] == ["-odd.code-workspace"]


def test_the_subject_without_a_file_is_refused(engine):
    result = _invoke(["scan", "workspace"])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert "FILE" in result.output
    assert engine.calls == []


def test_the_file_may_come_from_the_environment(engine, monkeypatch):
    monkeypatch.setenv("ASH_WORKSPACE", "from-env.code-workspace")

    result = _invoke(["scan", "workspace"])

    assert result.exit_code == 0, result.output
    assert [call["workspace"] for call in engine.calls] == ["from-env.code-workspace"]


def test_the_argument_beats_the_environment_variable(engine, monkeypatch):
    monkeypatch.setenv("ASH_WORKSPACE", "from-env.code-workspace")

    result = _invoke(["scan", "workspace", "given.code-workspace"])

    assert result.exit_code == 0, result.output
    assert [call["workspace"] for call in engine.calls] == ["given.code-workspace"]


def test_the_policy_may_come_from_the_environment(engine, monkeypatch):
    monkeypatch.setenv("ASH_WORKSPACE_CONFIG", "policy.yaml")

    result = _invoke(["scan", "workspace", "dev.code-workspace"])

    assert result.exit_code == 0, result.output
    assert [call["workspace_config"] for call in engine.calls] == ["policy.yaml"]


def test_a_json_document_may_name_the_file_and_the_policy(engine, tmp_path):
    document = tmp_path / "scan.json"
    document.write_text(
        json.dumps({"file": "doc.code-workspace", "workspace_config": "policy.yaml"}),
        encoding="utf-8",
    )

    result = _invoke(["scan", "workspace", "--cli-json-input", str(document)])

    assert result.exit_code == 0, result.output
    (call,) = engine.calls
    assert call["workspace"] == "doc.code-workspace"
    assert call["workspace_config"] == "policy.yaml"


# --------------------------------------------------------------------------- #
# What belongs to another subject is not on this one, and the other way round
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("given", "spelling"), [*DIRECTORY_ONLY, *OTHER_SUBJECTS])
def test_the_subject_refuses_what_belongs_to_another_subject(engine, given, spelling):
    result = _invoke(["scan", "workspace", "dev.code-workspace", *given])

    text = _one_line(result.output)
    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert "No such option" in text, text
    assert spelling in text, text
    assert engine.calls == []


@pytest.mark.parametrize(("given", "spelling"), WORKSPACE_ONLY)
def test_fs_refuses_the_options_of_a_workspace_scan(engine, given, spelling):
    result = _invoke(["scan", "fs", ".", *given])

    text = _one_line(result.output)
    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert "No such option" in text, text
    assert spelling in text, text
    assert engine.calls == []


def test_the_subject_declares_none_of_the_options_that_belong_to_another_subject():
    group = typer.main.get_command(app).commands["scan"]
    taken = {param.name for param in group.commands["workspace"].params}
    other_subjects = {
        "source_dir",
        "use_existing",
        "changed_files_only",
        "base_ref",
        "staged",
        "baseline",
        "shard_index",
        "shard_count",
        "image",
        "image_archive",
        "image_layout",
        "source_git",
        "git_ref",
        "git_depth",
        # The engine's name for the file, which the subject takes as FILE.
        "workspace",
    }

    assert taken.isdisjoint(other_subjects), sorted(taken & other_subjects)
    assert {"file", "workspace_config", "allow_missing_projects", "dry_run"} <= taken
    assert {"output_dir", "mode", "scanners", "config", "fail_on_findings"} <= taken


def test_fs_declares_none_of_the_workspace_options_and_every_directory_one():
    group = typer.main.get_command(app).commands["scan"]
    taken = {param.name for param in group.commands["fs"].params}

    assert taken.isdisjoint(WORKSPACE_OPTION_NAMES), sorted(
        taken & WORKSPACE_OPTION_NAMES
    )
    assert {
        "path",
        "source_dir",
        "use_existing",
        "changed_files_only",
        "base_ref",
        "staged",
        "baseline",
        "shard_index",
        "shard_count",
        "image",
        "source_git",
    } <= taken


def test_the_file_argument_and_the_policy_option_read_their_variables():
    group = typer.main.get_command(app).commands["scan"]
    params = {param.name: param for param in group.commands["workspace"].params}

    assert params["file"].param_type_name == "argument"
    assert params["file"].required is True
    assert params["file"].envvar == "ASH_WORKSPACE"
    assert params["workspace_config"].envvar == "ASH_WORKSPACE_CONFIG"


def test_the_fs_skeleton_lists_no_workspace_key():
    result = _invoke(["scan", "fs", "--generate-cli-skeleton"])

    assert result.exit_code == 0, result.output
    skeleton = json.loads(result.stdout)
    assert WORKSPACE_OPTION_NAMES.isdisjoint(skeleton), sorted(
        WORKSPACE_OPTION_NAMES & set(skeleton)
    )
    assert "path" in skeleton


# --------------------------------------------------------------------------- #
# Where the subject sits in the command line
# --------------------------------------------------------------------------- #


def test_a_subject_may_follow_options(engine):
    result = _invoke(["scan", "--output-dir", "out", "workspace", "dev.code-workspace"])

    assert result.exit_code == 0, result.output
    (call,) = engine.calls
    assert call["workspace"] == "dev.code-workspace"
    assert call["output_dir"] == "out"


def test_root_options_given_before_scan_reach_the_subject(engine):
    result = _invoke(["--output-dir", "out", "scan", "workspace", "dev.code-workspace"])

    assert result.exit_code == 0, result.output
    (call,) = engine.calls
    assert call["workspace"] == "dev.code-workspace"
    assert call["output_dir"] == "out"


def test_a_root_option_the_subject_does_not_take_is_refused_by_name(engine):
    result = _invoke(["--source-dir", "src", "scan", "workspace", "dev.code-workspace"])

    text = _one_line(result.output)
    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert "'ash scan workspace' does not take --source-dir" in text, text
    assert engine.calls == []


def test_the_form_with_no_subject_still_takes_the_workspace_options(engine):
    """``ash scan --workspace FILE`` keeps running: it is the form the subject
    replaces, and removing the options from ``fs`` must not take them from it."""
    result = _invoke(
        [
            "scan",
            "--workspace",
            "dev.code-workspace",
            "--workspace-config",
            "policy.yaml",
            "--allow-missing-projects",
            "--dry-run",
        ]
    )

    assert result.exit_code == 0, result.output
    (call,) = engine.calls
    assert call["workspace"] == "dev.code-workspace"
    assert call["workspace_config"] == "policy.yaml"
    assert call["allow_missing_projects"] is True
    assert call["dry_run"] is True
    assert call["ctx"].meta.get(SCAN_NOUN_META) is None


# --------------------------------------------------------------------------- #
# The engine's own answers, for a real workspace file
# --------------------------------------------------------------------------- #


def test_the_subject_plans_the_workspace_and_prints_no_deprecation_line(
    tmp_path, no_scan
):
    workspace = _workspace(tmp_path, ("api", "web"))

    result = _invoke(["scan", "workspace", str(workspace), "--dry-run"])

    assert result.exit_code == WorkspaceExitCode.SUCCESS, result.output
    assert "api" in result.stdout and "web" in result.stdout
    assert _deprecation_lines(result.stderr) == [], result.stderr
    assert _deprecation_lines(result.stdout) == [], result.stdout
    assert no_scan == []


def test_the_subject_reaches_the_scan_with_the_plan_of_the_file(tmp_path, no_scan):
    workspace = _workspace(tmp_path, ("api", "web"))

    result = _invoke(["scan", "workspace", str(workspace)])

    assert result.exit_code == WorkspaceExitCode.SUCCESS, result.output
    (call,) = no_scan
    assert [project.key for project in call["workspace_plan"].projects] == [
        "api",
        "web",
    ]
    assert Path(call["source_dir"]).resolve() == tmp_path.resolve()
    assert _deprecation_lines(result.stderr) == [], result.stderr


def test_allow_missing_projects_works_on_the_subject(tmp_path, no_scan):
    workspace = _workspace(tmp_path, ("api",))
    workspace.write_text(
        json.dumps({"folders": [{"path": "api"}, {"path": "not-cloned-yet"}]}),
        encoding="utf-8",
    )

    refused = _invoke(["scan", "workspace", str(workspace)])
    allowed = _invoke(["scan", "workspace", str(workspace), "--allow-missing-projects"])

    assert refused.exit_code == WorkspaceExitCode.WORKSPACE_ERROR, refused.output
    assert "not-cloned-yet" in refused.stderr
    assert allowed.exit_code == WorkspaceExitCode.SUCCESS, allowed.output
    (call,) = no_scan
    assert call["allow_missing_projects"] is True


def test_auto_names_the_single_workspace_file_of_the_working_directory(
    tmp_path, no_scan, monkeypatch
):
    _workspace(tmp_path)
    monkeypatch.chdir(tmp_path)

    result = _invoke(["scan", "workspace", "auto", "--dry-run"])

    assert result.exit_code == WorkspaceExitCode.SUCCESS, result.output
    assert "api" in result.stdout
    assert _deprecation_lines(result.stderr) == [], result.stderr


def test_a_missing_workspace_file_is_the_workspace_error(tmp_path, no_scan):
    result = _invoke(["scan", "workspace", str(tmp_path / "gone.code-workspace")])

    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR, result.output
    assert "does not exist" in result.stderr, result.stderr
    assert _deprecation_lines(result.stderr) == [], result.stderr
    assert no_scan == []


def test_the_file_may_come_from_the_environment_without_a_deprecation_line(
    tmp_path, no_scan, monkeypatch
):
    monkeypatch.setenv("ASH_WORKSPACE", str(_workspace(tmp_path)))

    result = _invoke(["scan", "workspace", "--dry-run"])

    assert result.exit_code == WorkspaceExitCode.SUCCESS, result.output
    assert _deprecation_lines(result.stderr) == [], result.stderr


def test_the_subject_takes_no_directory_so_the_directory_variable_names_none(
    tmp_path, no_scan, monkeypatch
):
    """ASH_SOURCE_DIR names a directory for the scans that take one. A workspace scan
    takes none, so the variable is not a second name for one beside the file: the
    forms that take both refuse the pair, as they did."""
    workspace = _workspace(tmp_path)
    monkeypatch.setenv("ASH_SOURCE_DIR", str(tmp_path))

    subject = _invoke(["scan", "workspace", str(workspace), "--dry-run"])
    legacy = _invoke(["scan", "--workspace", str(workspace), "--dry-run"])

    assert subject.exit_code == WorkspaceExitCode.SUCCESS, subject.output
    assert legacy.exit_code == WorkspaceExitCode.WORKSPACE_ERROR, legacy.output
    assert "ASH_SOURCE_DIR" in legacy.output


# --------------------------------------------------------------------------- #
# The forms with no subject that scan a workspace
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "prefix",
    [
        pytest.param([], id="bare-ash"),
        pytest.param(["scan"], id="scan-without-subject"),
    ],
)
def test_a_workspace_scan_with_no_subject_prints_one_line_naming_the_subject(
    prefix, tmp_path, no_scan
):
    workspace = _workspace(tmp_path)

    result = _invoke([*prefix, "--workspace", str(workspace), "--dry-run"])

    assert result.exit_code == WorkspaceExitCode.SUCCESS, result.output
    lines = _deprecation_lines(result.stderr)
    assert len(lines) == 1, result.stderr
    assert WORKSPACE_WITHOUT_SUBJECT_LINE in lines[0], lines[0]
    assert "ash scan workspace <file>" in lines[0]
    assert "4.0" in lines[0]
    assert _deprecation_lines(result.stdout) == [], "stdout is never handed the line"
    assert "api" in result.stdout, "the scan runs as it did"


def test_the_line_is_the_workspace_one_not_the_no_subject_one(tmp_path, no_scan):
    """``ash scan --workspace FILE`` is also ``ash scan`` with no subject, which
    prints its own line for a directory scan; a workspace scan is told the subject
    it has instead, and only that."""
    workspace = _workspace(tmp_path)

    result = _invoke(["scan", "--workspace", str(workspace), "--dry-run"])

    (line,) = _deprecation_lines(result.stderr)
    assert "ash scan fs" not in line, line


def test_a_workspace_file_named_only_by_the_environment_with_no_subject_is_told_too(
    tmp_path, no_scan, monkeypatch
):
    monkeypatch.setenv("ASH_WORKSPACE", str(_workspace(tmp_path)))

    result = _invoke(["scan", "--dry-run"])

    assert result.exit_code == WorkspaceExitCode.SUCCESS, result.output
    (line,) = _deprecation_lines(result.stderr)
    assert WORKSPACE_WITHOUT_SUBJECT_LINE in line, line


def test_a_workspace_scan_with_no_subject_keeps_its_exit_code(tmp_path, no_scan):
    gone = str(tmp_path / "gone.code-workspace")

    legacy = _invoke(["scan", "--workspace", gone])
    subject = _invoke(["scan", "workspace", gone])

    assert legacy.exit_code == subject.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
    assert len(_deprecation_lines(legacy.stderr)) == 1, legacy.stderr
    assert _deprecation_lines(subject.stderr) == [], subject.stderr


# --------------------------------------------------------------------------- #
# Help
# --------------------------------------------------------------------------- #


def test_the_subject_help_names_the_file_and_the_options_of_a_workspace_scan():
    result = _invoke(["scan", "workspace", "--help"])

    assert result.exit_code == 0, result.output
    assert "Usage: ash scan workspace [OPTIONS] FILE" in result.output
    for option in ("--dry-run", "--allow-missing-projects", "--mode", "--output-dir"):
        assert option in result.output, option
    text = _one_line(result.output)
    assert "Subjects of `ash scan`: fs" in text
    assert "workspace (scan the projects of a .code-workspace file)" in text


def test_the_help_of_every_subject_says_where_the_workspace_options_went():
    for args in (["scan", "--help"], ["scan", "fs", "--help"]):
        result = _invoke(args)

        assert result.exit_code == 0, result.output
        assert "ash scan workspace" in _one_line(result.output), args


def test_the_workspace_option_names_the_subject_that_replaces_it():
    root = typer.main.get_command(app)
    group = root.commands["scan"]

    for command in (root, group.legacy_command()):
        (option,) = [p for p in command.params if "--workspace" in p.opts]

        assert "ash scan workspace" in option.help, option.help
        assert "ASH v4.0" in option.help, option.help
