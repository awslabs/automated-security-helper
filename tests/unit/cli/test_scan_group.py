# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash scan`` is a group of subjects, and ``fs`` is the one that scans a directory.

What is pinned here:

* ``ash scan fs [PATH]`` takes the directory as an argument and prints no
  deprecation line.
* The three older spellings still run the scan and print ONE line to stderr, never
  stdout, with the exit code unchanged: bare ``ash [options]``, ``ash scan
  [options]`` with no subject, and ``--source-dir`` on ``fs``.
* A subject may follow options, as ``ash --output-dir out scan fs .`` hands the
  root's option on in front of it.
* ``ash scan --help`` lists the subjects without importing the scan engine.

Every case that reaches the engine passes ``--shard-index 3`` without
``--shard-count``, which the engine refuses with ASH's usage-error code right after
the deprecation line would print, so no case scans anything.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli import scan_group
from automated_security_helper.cli.main import app
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

pytestmark = pytest.mark.unit

#: The line each spelling prints, up to the part that names the replacement.
BARE_LINE = "`ash` without a subcommand runs a scan"
NO_SUBJECT_LINE = "`ash scan` without a subject is deprecated"
SOURCE_DIR_LINE = "`--source-dir` is deprecated"

#: Fails at once in the engine: a shard index needs a shard count.
FAILS_FAST = ["--shard-index", "3"]


def _invoke(args: list[str], **kwargs):
    return CliRunner().invoke(app, args, prog_name="ash", **kwargs)


def _deprecation_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith("Deprecated:")]


def test_scan_help_still_lists_the_scan_options():
    # Tools read `ash scan --help` for the scan's options (the deploy gates probe it
    # for --fail-on-incomplete-scanners), so a no-subject --help is fs's.
    result = _invoke(["scan", "--help"])

    assert result.exit_code == 0, result.output
    assert "Usage: ash scan fs [OPTIONS] [PATH]" in result.output
    assert "--shard-count" in result.output
    assert "--mode" in result.output
    # The subjects are listed in the epilog: this help is `fs`'s, so the group's own
    # command list is never printed.
    assert "Subjects of `ash scan`: fs" in result.output


def test_a_path_key_in_a_json_document_is_accepted_without_a_subject(engine, tmp_path):
    document = tmp_path / "params.json"
    document.write_text(json.dumps({"path": "from/json"}), encoding="utf-8")

    result = _invoke(["scan", "--cli-json-input", str(document)])

    assert result.exit_code == 0, result.output
    assert [call["source_dir"] for call in engine.calls] == ["from/json"]


def test_a_directory_after_a_double_dash_is_not_a_subject_less_scan_of_it(engine):
    result = _invoke(["scan", "--", "somewhere"])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert "'somewhere' is not a scan subject" in result.output
    assert engine.calls == []


def test_fs_help_takes_a_path_argument_and_every_scan_option():
    result = _invoke(["scan", "fs", "--help"])

    assert result.exit_code == 0, result.output
    assert "Usage: ash scan fs [OPTIONS] [PATH]" in result.output
    assert "--mode" in result.output
    assert "--shard-index" in result.output


def test_fs_prints_no_deprecation_line():
    result = _invoke(["scan", "fs", *FAILS_FAST])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert _deprecation_lines(result.output) == []


@pytest.mark.parametrize(
    ("args", "line"),
    [
        pytest.param(["scan", *FAILS_FAST], NO_SUBJECT_LINE, id="scan-without-subject"),
        pytest.param([*FAILS_FAST], BARE_LINE, id="bare-ash"),
        pytest.param(
            ["scan", "fs", "--source-dir", ".", *FAILS_FAST],
            SOURCE_DIR_LINE,
            id="source-dir-on-fs",
        ),
    ],
)
def test_a_legacy_spelling_prints_one_line_on_stderr_and_keeps_its_exit_code(
    args, line
):
    result = _invoke(args)

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    lines = _deprecation_lines(result.stderr)
    assert len(lines) == 1, result.stderr
    assert line in lines[0]
    assert "will be removed in ASH v4.0" in lines[0]
    assert "ash scan fs" in lines[0]
    assert _deprecation_lines(result.stdout) == [], (
        "a script's stdout is never handed it"
    )


def test_the_subject_less_line_still_prints_inside_the_container(monkeypatch):
    # `./ash --source-dir X` leaves the one deprecation line to the scan inside the
    # container, so that scan must not silence it there.
    monkeypatch.setenv("ASH_IN_CONTAINER", "1")

    result = _invoke(["scan", *FAILS_FAST])

    lines = _deprecation_lines(result.stderr)
    assert len(lines) == 1 and NO_SUBJECT_LINE in lines[0], result.stderr


def test_scan_without_subject_and_with_source_dir_prints_one_line_not_two():
    result = _invoke(["scan", "--source-dir", ".", *FAILS_FAST])

    assert len(_deprecation_lines(result.stderr)) == 1, result.stderr


def test_a_subject_may_follow_options():
    # `3` is the value of --shard-index; the first word that is not an option or a
    # value is the subject, so this is `scan fs`, not the subject-less form.
    result = _invoke(["scan", "--shard-index", "3", "fs"])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert _deprecation_lines(result.output) == []


def test_root_options_given_before_scan_reach_fs():
    result = _invoke(["--shard-index", "3", "scan", "fs"])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert "does not take" not in result.output
    assert "--shard-index requires --shard-count" in result.output
    assert _deprecation_lines(result.output) == []


def test_an_unknown_subject_is_refused_and_names_the_way_to_scan_a_directory():
    result = _invoke(["scan", "somewhere"])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert "'somewhere' is not a scan subject" in result.output
    assert "ash scan fs somewhere" in result.output


def test_naming_the_directory_twice_is_refused():
    result = _invoke(["scan", "fs", "a", "--source-dir", "b", *FAILS_FAST])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert "Name the directory once" in result.output


def test_the_same_directory_given_twice_is_not_a_conflict():
    result = _invoke(["scan", "fs", "a", "--source-dir", "a", *FAILS_FAST])

    assert "Name the directory once" not in result.output


class _EngineStub:
    """Stands in for the engine behind ``fs``: records what it was handed."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def __call__(self, *args, **kwargs):
        self.calls.append(kwargs)


@pytest.fixture
def engine(monkeypatch):
    stub = _EngineStub()
    monkeypatch.setattr(scan_group, "run_ash_scan_cli_command", stub)
    return stub


def test_the_path_argument_is_the_source_dir_the_engine_gets(engine):
    result = _invoke(["scan", "fs", "some/dir"])

    assert result.exit_code == 0, result.output
    assert [call["source_dir"] for call in engine.calls] == ["some/dir"]
    assert "path" not in engine.calls[0], "the engine has no `path` parameter"


def test_with_no_path_the_environment_variable_still_names_the_directory(
    engine, monkeypatch
):
    monkeypatch.setenv("ASH_SOURCE_DIR", "/from/env")

    result = _invoke(["scan", "fs"])

    assert result.exit_code == 0, result.output
    assert [call["source_dir"] for call in engine.calls] == ["/from/env"]
    assert _deprecation_lines(result.output) == [], (
        "ASH_SOURCE_DIR is how the container hands the mount to the scan inside"
    )


def test_the_path_beats_the_environment_variable(engine, monkeypatch):
    monkeypatch.setenv("ASH_SOURCE_DIR", "/from/env")

    result = _invoke(["scan", "fs", "given"])

    assert result.exit_code == 0, result.output
    assert [call["source_dir"] for call in engine.calls] == ["given"]


def test_fs_skeleton_lists_the_path_key():
    result = _invoke(["scan", "fs", "--generate-cli-skeleton"])

    assert result.exit_code == 0, result.output
    skeleton = json.loads(result.stdout)
    assert "path" in skeleton
    assert "source_dir" in skeleton


def test_the_subject_less_form_still_reads_a_skeleton():
    result = _invoke(["scan", "--generate-cli-skeleton"])

    assert result.exit_code == 0, result.output
    assert "path" in json.loads(result.stdout)


def test_every_scan_subject_is_known_to_the_group_and_not_a_non_scan_command():
    from automated_security_helper.express.client import NON_SCAN_SUBCOMMANDS

    import typer.main

    group = typer.main.get_command(app).commands["scan"]

    assert list(group.commands) == ["fs"]
    assert not set(group.commands) & set(NON_SCAN_SUBCOMMANDS)
