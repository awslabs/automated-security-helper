"""The variables that name what a scan subject scans are told once, when nothing else does.

``ASH_SOURCE_DIR`` names the directory of ``ash scan fs``, ``ASH_WORKSPACE`` the file
of ``ash scan workspace``, and ``ASH_WORKSPACE_CONFIG`` its policy file. Each is
deprecated as the way to name that, and removed in ASH v4.0, so a scan that reads one
because no argument named the same thing prints one line on stderr that gives the
spelling that replaces it.

What is pinned here:

* a scan whose directory (or workspace file, or policy file) comes only from its
  variable prints one line per variable it read, which names the variable and the
  spelling that replaces it;
* a scan that was given the argument prints none: the PATH argument, an archive, a
  clone, ``--source-dir`` (which prints its own line), a ``--cli-json-input`` document
  that names the directory, the FILE argument and ``--workspace-config``;
* a scan that names a ``--cli-json-input`` document prints no line for
  ``ASH_SOURCE_DIR``, whatever the document holds: the container run of ``./ash``
  hands the directory over in the variable and cannot give a PATH beside a document;
* a form with no subject prints the line of its own form and nothing more, so no run
  prints two;
* ``ash config`` reads ``ASH_SOURCE_DIR`` for its own option and prints nothing.

The rows that need only what a subject hands the engine replace the engine with a
stand-in; the others run the real engine against a workspace file in a temporary
directory, with the scan entry point replaced so nothing is scanned.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli import scan_group
from automated_security_helper.cli.main import app
from automated_security_helper.cli.scan_deprecation import (
    SCAN_WITHOUT_SUBJECT_LINE,
    SOURCE_DIR_LINE,
    SOURCE_DIR_VARIABLE_LINE,
    WORKSPACE_CONFIG_VARIABLE_LINE,
    WORKSPACE_VARIABLE_LINE,
)
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.models.workspace import WorkspaceExitCode

pytestmark = pytest.mark.unit


def _invoke(args: list[str], **kwargs):
    return CliRunner().invoke(app, args, prog_name="ash", **kwargs)


def _deprecation_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith("Deprecated:")]


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


def _workspace(root: Path) -> Path:
    (root / "api").mkdir(parents=True, exist_ok=True)
    path = root / "dev.code-workspace"
    path.write_text(json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8")
    return path


def _zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("app.py", "x = 1\n")
    return path


# --------------------------------------------------------------------------- #
# ASH_SOURCE_DIR, for `ash scan fs`
# --------------------------------------------------------------------------- #


def test_a_directory_named_only_by_the_variable_is_told_once(engine, monkeypatch):
    monkeypatch.setenv("ASH_SOURCE_DIR", "/from/env")

    result = _invoke(["scan", "fs"])

    assert result.exit_code == 0, result.output
    assert [call["source_dir"] for call in engine.calls] == ["/from/env"], "still runs"
    (line,) = _deprecation_lines(result.stderr)
    assert SOURCE_DIR_VARIABLE_LINE in line, line
    assert "ASH_SOURCE_DIR" in line and "ash scan fs <path>" in line, line
    assert "4.0" in line, line
    assert _deprecation_lines(result.stdout) == [], "stdout is never handed the line"


def test_the_path_argument_beside_the_variable_is_not_told(engine, monkeypatch):
    monkeypatch.setenv("ASH_SOURCE_DIR", "/from/env")

    result = _invoke(["scan", "fs", "given"])

    assert result.exit_code == 0, result.output
    assert [call["source_dir"] for call in engine.calls] == ["given"]
    assert _deprecation_lines(result.stderr) == [], result.stderr


def test_an_archive_beside_the_variable_is_not_told(engine, tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_SOURCE_DIR", "/from/env")
    archive = _zip(tmp_path / "source.zip")

    result = _invoke(["scan", "fs", "--archive", str(archive)])

    assert result.exit_code == 0, result.output
    assert _deprecation_lines(result.stderr) == [], result.stderr


def test_a_clone_beside_the_variable_is_not_told(engine, monkeypatch):
    monkeypatch.setenv("ASH_SOURCE_DIR", "/from/env")

    result = _invoke(["scan", "fs", "--source-git", "https://example.com/repo.git"])

    assert result.exit_code == 0, result.output
    assert _deprecation_lines(result.stderr) == [], result.stderr


@pytest.mark.parametrize(
    "image_option",
    [
        pytest.param(["--image", "registry.example.com/team/app:1.2.3"], id="image"),
        pytest.param(["--image-archive", "image.tar"], id="image-archive"),
        pytest.param(["--image-layout", "layout"], id="image-layout"),
    ],
)
def test_an_image_beside_the_variable_is_refused_with_no_line_ahead_of_it(
    image_option, no_scan, tmp_path, monkeypatch
):
    """The engine refuses an image beside the variable in its own words, so the variable
    is not told as the directory of that scan: the refusal is the first thing said."""
    monkeypatch.setenv("ASH_SOURCE_DIR", str(tmp_path))

    result = _invoke(["scan", "fs", *image_option])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert f"{image_option[0]} cannot be combined with ASH_SOURCE_DIR" in result.output
    assert _deprecation_lines(result.stderr) == [], result.stderr
    assert no_scan == []


def test_the_option_beside_the_variable_prints_the_options_line_only(
    engine, monkeypatch
):
    monkeypatch.setenv("ASH_SOURCE_DIR", "/from/env")

    result = _invoke(["scan", "fs", "--source-dir", "given"])

    assert result.exit_code == 0, result.output
    assert [call["source_dir"] for call in engine.calls] == ["given"]
    (line,) = _deprecation_lines(result.stderr)
    assert SOURCE_DIR_LINE in line, line
    assert SOURCE_DIR_VARIABLE_LINE not in line, line


def test_no_variable_and_no_argument_is_not_told(engine):
    result = _invoke(["scan", "fs"])

    assert result.exit_code == 0, result.output
    assert _deprecation_lines(result.stderr) == [], result.stderr


def test_a_json_document_that_names_the_path_beside_the_variable_is_not_told(
    engine, tmp_path, monkeypatch
):
    monkeypatch.setenv("ASH_SOURCE_DIR", "/from/env")
    document = tmp_path / "scan.json"
    document.write_text(json.dumps({"path": "given"}), encoding="utf-8")

    result = _invoke(["scan", "fs", "--cli-json-input", str(document)])

    assert result.exit_code == 0, result.output
    assert [call["source_dir"] for call in engine.calls] == ["given"]
    assert _deprecation_lines(result.stderr) == [], result.stderr


def test_a_json_document_that_names_no_directory_beside_the_variable_is_not_told(
    engine, tmp_path, monkeypatch
):
    """``./ash scan fs --cli-json-input DOC`` runs the scan inside its container with
    ``ASH_SOURCE_DIR=/src`` and no PATH, since the document may name a clone or an
    image, which a PATH would conflict with. A document that names none of them leaves
    the variable as the only name of the directory, and the line that asks for a PATH
    would tell its reader to type what the wrapper cannot pass."""
    monkeypatch.setenv("ASH_SOURCE_DIR", "/from/env")
    document = tmp_path / "scan.json"
    document.write_text(json.dumps({"only_scanners": ["bandit"]}), encoding="utf-8")

    told = _invoke(["scan", "fs"])
    result = _invoke(["scan", "fs", "--cli-json-input", str(document)])

    assert len(_deprecation_lines(told.stderr)) == 1, "the control: no document, told"
    assert result.exit_code == 0, result.output
    call = engine.calls[-1]
    assert call["source_dir"] == "/from/env", "the variable still names the directory"
    assert list(call["only_scanners"]) == ["bandit"], "the document was read"
    assert _deprecation_lines(result.stderr) == [], result.stderr


def test_the_form_with_no_subject_prints_the_line_of_its_own_form_only(
    tmp_path, no_scan, monkeypatch
):
    monkeypatch.setenv("ASH_SOURCE_DIR", str(tmp_path))

    result = _invoke(["scan", "--output-dir", str(tmp_path / "out")])

    assert result.exit_code == 0, result.output
    (line,) = _deprecation_lines(result.stderr)
    assert SCAN_WITHOUT_SUBJECT_LINE in line, line
    assert "ASH_SOURCE_DIR" not in line, line


# --------------------------------------------------------------------------- #
# ASH_WORKSPACE and ASH_WORKSPACE_CONFIG, for `ash scan workspace`
# --------------------------------------------------------------------------- #


def test_a_workspace_file_named_only_by_the_variable_is_told_once(
    tmp_path, no_scan, monkeypatch
):
    monkeypatch.setenv("ASH_WORKSPACE", str(_workspace(tmp_path)))

    result = _invoke(["scan", "workspace", "--dry-run"])

    assert result.exit_code == WorkspaceExitCode.SUCCESS, result.output
    assert "api" in result.stdout, "the scan runs as it did"
    (line,) = _deprecation_lines(result.stderr)
    assert WORKSPACE_VARIABLE_LINE in line, line
    assert "ASH_WORKSPACE" in line and "ash scan workspace <file>" in line, line
    assert "4.0" in line, line


def test_the_file_argument_beside_the_variable_is_not_told(
    tmp_path, no_scan, monkeypatch
):
    monkeypatch.setenv("ASH_WORKSPACE", str(tmp_path / "from-env.code-workspace"))

    result = _invoke(["scan", "workspace", str(_workspace(tmp_path)), "--dry-run"])

    assert result.exit_code == WorkspaceExitCode.SUCCESS, result.output
    assert _deprecation_lines(result.stderr) == [], result.stderr


def test_a_policy_named_only_by_the_variable_is_told_once(engine, monkeypatch):
    monkeypatch.setenv("ASH_WORKSPACE_CONFIG", "policy.yaml")

    result = _invoke(["scan", "workspace", "dev.code-workspace"])

    assert result.exit_code == 0, result.output
    assert [call["workspace_config"] for call in engine.calls] == ["policy.yaml"]
    (line,) = _deprecation_lines(result.stderr)
    assert WORKSPACE_CONFIG_VARIABLE_LINE in line, line
    assert "ASH_WORKSPACE_CONFIG" in line and "--workspace-config <path>" in line, line


def test_the_policy_option_beside_the_variable_is_not_told(engine, monkeypatch):
    monkeypatch.setenv("ASH_WORKSPACE_CONFIG", "from-env.yaml")

    result = _invoke(
        ["scan", "workspace", "dev.code-workspace", "--workspace-config", "given.yaml"]
    )

    assert result.exit_code == 0, result.output
    assert [call["workspace_config"] for call in engine.calls] == ["given.yaml"]
    assert _deprecation_lines(result.stderr) == [], result.stderr


def test_both_variables_are_told_one_line_each_file_first(engine, monkeypatch):
    monkeypatch.setenv("ASH_WORKSPACE", "dev.code-workspace")
    monkeypatch.setenv("ASH_WORKSPACE_CONFIG", "policy.yaml")

    result = _invoke(["scan", "workspace"])

    assert result.exit_code == 0, result.output
    lines = _deprecation_lines(result.stderr)
    assert len(lines) == 2, result.stderr
    assert WORKSPACE_VARIABLE_LINE in lines[0], lines
    assert WORKSPACE_CONFIG_VARIABLE_LINE in lines[1], lines


def test_a_workspace_scan_with_no_subject_prints_the_line_of_its_own_form_only(
    tmp_path, no_scan, monkeypatch
):
    monkeypatch.setenv("ASH_WORKSPACE", str(_workspace(tmp_path)))

    result = _invoke(["scan", "--dry-run"])

    assert result.exit_code == WorkspaceExitCode.SUCCESS, result.output
    (line,) = _deprecation_lines(result.stderr)
    assert "ASH_WORKSPACE" not in line, line


# --------------------------------------------------------------------------- #
# `ash config` is not a scan
# --------------------------------------------------------------------------- #


def test_the_config_commands_read_the_variable_and_print_no_line(
    engine, tmp_path, monkeypatch
):
    monkeypatch.setenv("ASH_SOURCE_DIR", str(tmp_path))

    scan = _invoke(["scan", "fs"])
    config = _invoke(["config", "validate"])

    assert len(_deprecation_lines(scan.stderr)) == 1, "the control: a scan is told"
    assert _deprecation_lines(config.stderr) == [], config.stderr
