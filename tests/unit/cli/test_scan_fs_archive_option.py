"""``ash scan fs --archive FILE`` scans a zip of source code, and only ``fs`` takes it.

What is pinned here:

* The scan is handed the archive's members, extracted to a directory of their own, as
  the directory to scan; the engine has no ``archive`` parameter, and the form with no
  subject and the workspace subject have no such option.
* The temporary directory is gone when the command ends, whether the scan finished,
  the engine refused the run, or the archive was refused (one whose extraction stopped
  partway included).
* The results go to ``.ash/ash_output`` in the working directory unless ``--output-dir``
  says otherwise, since the default beside the source would be inside the temporary
  tree.
* ``--archive`` is refused beside the PATH argument, ``--source-dir``, the git options,
  the image options, ``--staged``, ``--use-existing`` and ``--changed-files-only``,
  each refusal naming both options, before anything is extracted.
* An archive the source-archive rules refuse prints the rules' own message and exits
  with the usage-error code. A problem with the disk exits 1.
* ``ASH_SOURCE_DIR`` is ambient: the archive replaces it.

The engine is replaced by a stand-in that reads the tree it is handed while the tree
still exists, or the scan entry point is, so nothing is scanned. The temporary tree is
made under a directory of the test's own, so what is left of it can be listed.
"""

from __future__ import annotations

import errno
import json
import tempfile
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
import typer
import typer.main
from typer.testing import CliRunner

from automated_security_helper.cli import scan_group
from automated_security_helper.cli.main import app
from automated_security_helper.cli.scan_deprecation import SCAN_NOUN_META
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.core.enums import AshExitCode

pytestmark = pytest.mark.unit

#: The refusal's opening, which every exclusivity refusal shares.
CANNOT_BE_COMBINED = "--archive cannot be combined with"

#: What each option that cannot be given with ``--archive`` looks like on a command
#: line, and the words its refusal names it by.
EXCLUDED = [
    pytest.param(["src"], "the PATH argument", id="path"),
    pytest.param(["--source-dir", "src"], "--source-dir", id="source-dir"),
    pytest.param(
        ["--source-git", "https://example.com/repo.git"],
        "--source-git",
        id="source-git",
    ),
    pytest.param(["--git-ref", "main"], "--git-ref", id="git-ref"),
    pytest.param(["--git-depth", "1"], "--git-depth", id="git-depth"),
    pytest.param(["--image", "alpine:3"], "--image", id="image"),
    pytest.param(
        ["--image-archive", "image.tar"], "--image-archive", id="image-archive"
    ),
    pytest.param(["--image-layout", "layout"], "--image-layout", id="image-layout"),
    pytest.param(["--staged"], "--staged", id="staged"),
    pytest.param(["--use-existing"], "--use-existing", id="use-existing"),
    pytest.param(
        ["--changed-files-only"], "--changed-files-only", id="changed-files-only"
    ),
]


def _invoke(args: list[str], **kwargs):
    return CliRunner().invoke(app, args, prog_name="ash", **kwargs)


def _one_line(text: str) -> str:
    return " ".join(text.split())


def _zip(path: Path, members: dict[str, str]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, text in members.items():
            archive.writestr(name, text)
    return path


def _zip_whose_second_member_is_damaged(path: Path) -> Path:
    """A zip that passes every check made before extraction and fails when
    extraction reaches its second member, after the first was written: the member's
    data is stored, and one byte of it is not the byte its CRC-32 was made from."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("a.py", "A" * 40)
        archive.writestr("b.py", "B" * 40)
    raw = bytearray(path.read_bytes())
    raw[raw.index(b"B" * 40)] = ord("X")
    path.write_bytes(bytes(raw))
    return path


@pytest.fixture(autouse=True)
def _clear_ash_env(monkeypatch):
    for name in ("ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_CONFIG"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def scratch(tmp_path, monkeypatch) -> Path:
    """The directory the temporary tree of an extraction is made under. It holds
    nothing once the command has ended, which is what the removal rows read."""
    root = tmp_path / "scratch"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    return root


class _Engine:
    """Stands in for the engine behind ``fs``. It reads the tree it was handed while
    the tree still exists, and can end the run as the engine ends one it refuses."""

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.trees: list[dict[str, str]] = []
        self.then: BaseException | None = None

    def __call__(self, *args, **kwargs):
        source_dir = Path(kwargs["source_dir"])
        self.calls.append(kwargs)
        self.trees.append(
            {
                member.relative_to(source_dir).as_posix(): member.read_text(
                    encoding="utf-8"
                )
                for member in sorted(source_dir.rglob("*"))
                if member.is_file()
            }
        )
        if self.then is not None:
            raise self.then


@pytest.fixture
def engine(monkeypatch) -> _Engine:
    stub = _Engine()
    monkeypatch.setattr(scan_group, "run_ash_scan_cli_command", stub)
    return stub


@pytest.fixture
def scan_entry(monkeypatch) -> list[dict]:
    """The scan entry point, replaced by a recorder that reads the tree it is handed
    while the tree still exists. Everything between the command line and it is the
    real engine."""
    seen: list[dict] = []

    def _record(**kwargs):
        source_dir = Path(kwargs["source_dir"])
        seen.append(
            {
                "kwargs": kwargs,
                "existed": source_dir.is_dir(),
                "files": sorted(
                    member.relative_to(source_dir).as_posix()
                    for member in source_dir.rglob("*")
                    if member.is_file()
                ),
            }
        )

    monkeypatch.setattr(
        "automated_security_helper.cli.scan.run_ash_scan", _record, raising=True
    )
    return seen


# --------------------------------------------------------------------------- #
# What the scan is handed
# --------------------------------------------------------------------------- #


def test_the_engine_is_handed_the_members_extracted_as_the_directory_to_scan(
    engine, scratch, tmp_path
):
    archive = _zip(
        tmp_path / "source.zip", {"app.py": "print('hi')\n", "pkg/mod.py": "X = 1\n"}
    )

    result = _invoke(["scan", "fs", "--archive", str(archive)])

    assert result.exit_code == 0, result.output
    (call,) = engine.calls
    assert engine.trees == [{"app.py": "print('hi')\n", "pkg/mod.py": "X = 1\n"}]
    assert Path(call["source_dir"]).parent == scratch
    assert "archive" not in call, "the engine has no `archive` parameter"
    assert "path" not in call
    assert call["ctx"].meta[SCAN_NOUN_META] == scan_group.DEFAULT_SUBJECT


def test_the_scan_entry_point_is_handed_the_members_by_the_real_engine(
    scan_entry, scratch, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    archive = _zip(tmp_path / "source.zip", {"app.py": "SECRET = 1\n", "lib/b.py": ""})

    result = _invoke(["scan", "fs", "--archive", str(archive)])

    assert result.exit_code == 0, result.output
    (seen,) = scan_entry
    assert seen["existed"] is True
    assert seen["files"] == ["app.py", "lib/b.py"]
    assert Path(seen["kwargs"]["source_dir"]).parent == scratch
    assert "Deprecated:" not in result.stderr, result.stderr


def test_a_container_scan_is_handed_the_extracted_directory(
    scratch, tmp_path, monkeypatch
):
    """The archive is extracted on the host before the mode is dispatched, so the
    container mounts the extracted directory at /src, as it does any directory."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_MODE", raising=False)
    handed: list[dict] = []

    def _record(**kwargs):
        source_dir = Path(kwargs["source_dir"])
        handed.append(
            {
                "parent": source_dir.parent,
                "files": sorted(member.name for member in source_dir.iterdir()),
            }
        )
        return SimpleNamespace(returncode=0, stdout="", stderr="", args=[])

    monkeypatch.setattr(
        "automated_security_helper.interactions.run_ash_scan.run_ash_container",
        _record,
        raising=True,
    )
    archive = _zip(tmp_path / "source.zip", {"app.py": "print('hi')\n"})

    _invoke(
        ["scan", "fs", "--archive", str(archive), "--mode", "container", "--no-run"]
    )

    (container,) = handed
    assert container["parent"] == scratch
    assert "app.py" in container["files"]
    assert list(scratch.iterdir()) == []


def test_the_option_may_be_given_by_a_json_document(engine, scratch, tmp_path):
    archive = _zip(tmp_path / "source.zip", {"app.py": "x = 1\n"})
    document = tmp_path / "scan.json"
    document.write_text(json.dumps({"archive": str(archive)}), encoding="utf-8")

    result = _invoke(["scan", "fs", "--cli-json-input", str(document)])

    assert result.exit_code == 0, result.output
    assert engine.trees == [{"app.py": "x = 1\n"}]


def test_a_directory_variable_in_the_environment_is_replaced(
    engine, scratch, tmp_path, monkeypatch
):
    """ASH_SOURCE_DIR is how a wrapper hands a mount to the scan inside it; it is not a
    second name for the tree, so it neither conflicts with the archive nor wins."""
    monkeypatch.setenv("ASH_SOURCE_DIR", "/from/env")
    archive = _zip(tmp_path / "source.zip", {"app.py": "x = 1\n"})

    result = _invoke(["scan", "fs", "--archive", str(archive)])

    assert result.exit_code == 0, result.output
    assert Path(engine.calls[0]["source_dir"]).parent == scratch
    assert engine.trees == [{"app.py": "x = 1\n"}]


# --------------------------------------------------------------------------- #
# Where the results go
# --------------------------------------------------------------------------- #


def test_the_results_default_to_the_working_directory_not_the_temporary_tree(
    engine, scratch, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    archive = _zip(tmp_path / "source.zip", {"app.py": "x = 1\n"})

    result = _invoke(["scan", "fs", "--archive", str(archive)])

    assert result.exit_code == 0, result.output
    output_dir = Path(engine.calls[0]["output_dir"])
    assert output_dir.resolve() == (tmp_path / ".ash" / "ash_output").resolve()
    assert scratch not in output_dir.parents


def test_an_output_directory_that_was_named_is_kept(
    engine, scratch, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    archive = _zip(tmp_path / "source.zip", {"app.py": "x = 1\n"})

    result = _invoke(["scan", "fs", "--archive", str(archive), "--output-dir", "out"])

    assert result.exit_code == 0, result.output
    assert engine.calls[0]["output_dir"] == "out"


# --------------------------------------------------------------------------- #
# The temporary tree is gone when the command ends
# --------------------------------------------------------------------------- #


def test_the_temporary_tree_is_gone_after_a_scan(engine, scratch, tmp_path):
    archive = _zip(tmp_path / "source.zip", {"app.py": "x = 1\n"})

    result = _invoke(["scan", "fs", "--archive", str(archive)])

    assert result.exit_code == 0, result.output
    assert engine.trees == [{"app.py": "x = 1\n"}], "the tree was there for the scan"
    assert not Path(engine.calls[0]["source_dir"]).exists()
    assert list(scratch.iterdir()) == []


def test_the_temporary_tree_is_gone_after_the_engine_refuses_the_run(
    engine, scratch, tmp_path
):
    engine.then = typer.Exit(ASH_EXIT_USAGE_ERROR)
    archive = _zip(tmp_path / "source.zip", {"app.py": "x = 1\n"})

    result = _invoke(["scan", "fs", "--archive", str(archive)])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert engine.trees == [{"app.py": "x = 1\n"}]
    assert list(scratch.iterdir()) == []


def test_the_temporary_tree_is_gone_after_the_engine_fails(engine, scratch, tmp_path):
    engine.then = RuntimeError("the engine failed")
    archive = _zip(tmp_path / "source.zip", {"app.py": "x = 1\n"})

    result = _invoke(["scan", "fs", "--archive", str(archive)])

    assert result.exit_code != 0
    assert isinstance(result.exception, RuntimeError)
    assert list(scratch.iterdir()) == []


def test_the_temporary_tree_is_gone_after_a_refused_archive(engine, scratch, tmp_path):
    refused = tmp_path / "not-a-zip.zip"
    refused.write_text("not a zip\n", encoding="utf-8")

    result = _invoke(["scan", "fs", "--archive", str(refused)])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert engine.calls == []
    assert list(scratch.iterdir()) == []


def test_the_temporary_tree_is_gone_after_an_extraction_that_stopped_partway(
    engine, scratch, tmp_path
):
    damaged = _zip_whose_second_member_is_damaged(tmp_path / "damaged.zip")

    result = _invoke(["scan", "fs", "--archive", str(damaged)])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert "b.py" in result.output
    assert engine.calls == []
    assert list(scratch.iterdir()) == []


# --------------------------------------------------------------------------- #
# What is refused
# --------------------------------------------------------------------------- #


def test_a_refused_archive_prints_the_rules_own_message_with_the_usage_error_code(
    engine, scratch, tmp_path
):
    from automated_security_helper.utils.source_archive import (
        SourceArchiveRefused,
        extract_source_archive,
    )

    refused = tmp_path / "not-a-zip.zip"
    refused.write_text("not a zip\n", encoding="utf-8")
    with pytest.raises(SourceArchiveRefused) as expected:
        extract_source_archive(refused, tmp_path / "probe-destination")

    result = _invoke(["scan", "fs", "--archive", str(refused)])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert "--archive" in result.output
    assert _one_line(str(expected.value)) in _one_line(result.output), result.output
    assert engine.calls == []


def test_an_archive_that_is_not_there_is_refused_not_a_traceback(
    engine, scratch, tmp_path
):
    result = _invoke(["scan", "fs", "--archive", str(tmp_path / "gone.zip")])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert "--archive" in result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert engine.calls == []
    assert list(scratch.iterdir()) == []


def test_a_problem_with_the_disk_exits_one_and_leaves_nothing(
    engine, scratch, tmp_path, monkeypatch
):
    def _disk_full(archive, destination):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(
        "automated_security_helper.utils.source_archive.extract_source_archive",
        _disk_full,
    )
    archive = _zip(tmp_path / "source.zip", {"app.py": "x = 1\n"})

    result = _invoke(["scan", "fs", "--archive", str(archive)])

    assert result.exit_code == AshExitCode.SCAN_ERRORS, result.output
    assert "No space left on device" in result.output
    assert "--archive" in result.output
    assert engine.calls == []
    assert list(scratch.iterdir()) == []


@pytest.mark.parametrize(("given", "spelling"), EXCLUDED)
def test_the_archive_is_refused_beside_what_it_replaces_naming_both_options(
    engine, scratch, tmp_path, given, spelling
):
    archive = _zip(tmp_path / "source.zip", {"app.py": "x = 1\n"})

    result = _invoke(["scan", "fs", *given, "--archive", str(archive)])

    text = _one_line(result.output)
    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert f"{CANNOT_BE_COMBINED} {spelling}:" in text, text
    assert engine.calls == []
    assert list(scratch.iterdir()) == [], "nothing is extracted for a refused command"


def test_the_archive_is_refused_beside_a_directory_a_json_document_names(
    engine, scratch, tmp_path
):
    archive = _zip(tmp_path / "source.zip", {"app.py": "x = 1\n"})
    document = tmp_path / "scan.json"
    document.write_text(
        json.dumps({"archive": str(archive), "source_dir": "src"}), encoding="utf-8"
    )

    result = _invoke(["scan", "fs", "--cli-json-input", str(document)])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert f"{CANNOT_BE_COMBINED} --source-dir:" in _one_line(result.output)
    assert engine.calls == []


# --------------------------------------------------------------------------- #
# Only `fs` takes it
# --------------------------------------------------------------------------- #


def test_only_the_fs_subject_declares_the_option():
    root = typer.main.get_command(app)
    group = root.commands["scan"]

    assert "archive" in {param.name for param in group.commands["fs"].params}
    assert "archive" not in {param.name for param in group.legacy_command().params}
    assert "archive" not in {param.name for param in group.commands["workspace"].params}
    assert "archive" not in {param.name for param in root.params}


def test_the_option_is_refused_by_the_subjects_that_do_not_take_it(tmp_path):
    archive = _zip(tmp_path / "source.zip", {"app.py": "x = 1\n"})

    workspace = _invoke(["scan", "workspace", "dev.code-workspace", "--archive", "x"])
    no_subject = _invoke(["scan", "--archive", str(archive)])

    assert workspace.exit_code == ASH_EXIT_USAGE_ERROR, workspace.output
    assert "No such option" in _one_line(workspace.output)
    assert no_subject.exit_code == ASH_EXIT_USAGE_ERROR, no_subject.output
    assert "No such option" in _one_line(no_subject.output)


def test_the_fs_skeleton_lists_the_key_and_the_other_skeletons_do_not():
    fs = json.loads(_invoke(["scan", "fs", "--generate-cli-skeleton"]).stdout)
    no_subject = json.loads(_invoke(["scan", "--generate-cli-skeleton"]).stdout)
    workspace = json.loads(
        _invoke(["scan", "workspace", "--generate-cli-skeleton"]).stdout
    )

    assert "archive" in fs and fs["archive"] is None
    assert "archive" not in no_subject
    assert "archive" not in workspace


def test_the_fs_help_lists_the_option_and_the_help_of_the_other_forms_does_not():
    fs = _invoke(["scan", "fs", "--help"])
    no_subject = _invoke(["scan", "--help"])

    assert fs.exit_code == 0, fs.output
    assert "--archive" in fs.output
    assert no_subject.exit_code == 0, no_subject.output
    assert "--archive" not in no_subject.output
