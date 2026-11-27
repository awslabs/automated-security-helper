#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Terraform CodeCommit gate names the scan's subject when its ASH has one.

Why this exists
---------------
ASH 3.9 scans a directory with ``ash scan fs PATH``. The subject-less
``ash scan --source-dir PATH`` still scans there but prints a deprecation line, and it
goes in ASH v4.0. The gate's image is built from ``ash_version``, which can name a
release older than 3.9 (the module's own default does until the release commit moves
it), and that release has no ``fs`` subject. So the gate asks the image's ASH, once
per execution environment, and scans the way it answers. A gate that always used the
new form would fail every pull request on an older image; one that always used the
old form would put a deprecation line in every scan log on a current one.

The clone is the subject's PATH argument, right after ``fs`` and ahead of the
operator's extra arguments, so a bare word among those cannot become the scanned
directory: ASH refuses it as an extra argument, which the gate reports as an error.

Only an answer picks the older spelling: ``ash scan fs --help`` exiting 0 with a help
that does not name ``scan fs``, or a usage error that names ``fs``. A probe that fails
any other way (a crash, an import error, an out-of-memory kill) says nothing about the
ASH's commands. It is not read as an older ASH, it refuses the scan, nothing about it
is remembered for the warm execution environment, and the next scan asks again. The
spelling chosen and the reason, or what a failed probe printed, go to the function's
log.

The gate's subprocess runner is replaced with a recorder that answers the help probes
(tests/unit/deploy/gate_probe_answers.py); argv is resolved through this tree's real
CLI where what matters is what ASH would do with it.
"""

from __future__ import annotations

import importlib.util
import logging
import pathlib
import sys
from types import ModuleType, SimpleNamespace

import pytest

from tests.unit.deploy.gate_probe_answers import (
    FLAG,
    FS_PROBE,
    RELEASE_WITH_SUBJECT,
    RELEASE_WITHOUT_SUBJECT,
    SCAN_PROBE,
    answer,
    fs_arguments,
)

pytestmark = pytest.mark.unit

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
GATE_PATH = (
    REPO_ROOT
    / "deploy"
    / "terraform"
    / "modules"
    / "codecommit-gate"
    / "files"
    / "ash_pr_gate.py"
)


@pytest.fixture
def gate() -> ModuleType:
    """The gate loaded by path, fresh per test, so its probe cache starts empty."""
    spec = importlib.util.spec_from_file_location(
        "_ash_pr_gate_scan_subject", GATE_PATH
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _record(gate, monkeypatch, tmp_path, answers) -> tuple[list, list]:
    """Replace the gate's runner: probes are answered by *answers*, the rest recorded.

    Returns (scans, probes): the argv of every call that was not a probe, and the
    argv of every probe, in call order.
    """
    scans: list[list[str]] = []
    probes: list[list[str]] = []

    def _fake_run(argv, cwd=None, env=None):
        reply = answers(list(argv))
        if reply is not None:
            probes.append(list(argv))
            return reply
        scans.append(list(argv))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(gate, "_run", _fake_run)
    monkeypatch.setattr(gate, "WORK_ROOT", tmp_path / "ash-gate")
    monkeypatch.delenv("ASH_SCAN_EXTRA_ARGS", raising=False)
    monkeypatch.delenv("ASH_SOURCE_DIR", raising=False)
    return scans, probes


def _as_release(release):
    return lambda argv: answer(argv, release)


def _resolve(argv: list[str]):
    """The parameters this tree's ``ash scan fs`` resolves from a gate argv."""
    import typer.main

    from automated_security_helper.cli.main import app

    fs = typer.main.get_command(app).commands["scan"].commands["fs"]
    return fs.make_context("fs", fs_arguments(argv), resilient_parsing=False).params


def test_an_ash_with_the_subject_scans_the_clone_as_its_path(
    gate, monkeypatch, tmp_path
):
    scans, probes = _record(
        gate, monkeypatch, tmp_path, _as_release(RELEASE_WITH_SUBJECT)
    )
    source = tmp_path / "src"

    gate.run_scan(source, "low", True)

    assert probes == [FS_PROBE], probes
    assert len(scans) == 1, scans
    argv = scans[0]
    assert argv[:4] == ["ash", "scan", "fs", str(source)], argv
    assert "--source-dir" not in argv, argv
    params = _resolve(argv)
    assert params["path"] == str(source)
    assert params["source_dir"] is None
    assert params["fail_on_incomplete_scanners"] is True


@pytest.mark.parametrize(
    "fs_probe_reply",
    [
        # An older ASH: click shows the subject-less scan's help for `scan fs --help`.
        None,
        # An ASH that refuses the word `fs` as a usage error, with nothing on stdout.
        # 5 is the code ASH releases after 3.7.1 give a usage error; 3.7.1 and earlier
        # give click's 2.
        SimpleNamespace(
            returncode=5,
            stdout="",
            stderr=(
                "Usage: ash scan [OPTIONS]\n"
                "Try 'ash scan --help' for help.\n"
                "Error: Got unexpected extra argument (fs)\n"
            ),
        ),
        SimpleNamespace(
            returncode=2,
            stdout="",
            stderr="Error: No such command 'fs'.\n",
        ),
    ],
    ids=[
        "shows-the-subjectless-help",
        "refuses-fs-as-an-extra-argument",
        "refuses-fs-as-a-command",
    ],
)
def test_an_ash_without_the_subject_scans_with_source_dir(
    gate, monkeypatch, tmp_path, fs_probe_reply
):
    def answers(argv):
        if argv == FS_PROBE and fs_probe_reply is not None:
            return fs_probe_reply
        return answer(argv, RELEASE_WITHOUT_SUBJECT)

    scans, probes = _record(gate, monkeypatch, tmp_path, answers)
    source = tmp_path / "src"

    gate.run_scan(source, "low", True)

    # The second probe reads the subject-less scan's own options.
    assert probes == [FS_PROBE, SCAN_PROBE], probes
    assert len(scans) == 1, scans
    argv = scans[0]
    assert argv[:2] == ["ash", "scan"] and argv[2] != "fs", argv
    assert argv[argv.index("--source-dir") + 1] == str(source), argv
    assert _resolve(argv)["source_dir"] == str(source)


@pytest.mark.parametrize("release", [RELEASE_WITH_SUBJECT, RELEASE_WITHOUT_SUBJECT])
def test_the_probes_run_once_per_execution_environment(
    gate, monkeypatch, tmp_path, release
):
    """The image cannot change under a warm execution environment, so ASH is asked once."""
    scans, probes = _record(gate, monkeypatch, tmp_path, _as_release(release))

    gate.run_scan(tmp_path / "src", "low", True)
    first = list(probes)
    gate.run_scan(tmp_path / "src", "low", True)

    assert probes == first, probes
    assert len(scans) == 2, scans
    assert scans[0] == scans[1]


def test_a_bare_word_in_the_extra_args_cannot_become_the_scanned_directory(
    gate, monkeypatch, tmp_path
):
    """The clone comes first, so a word in ASH_SCAN_EXTRA_ARGS is a second PATH, refused."""
    scans, _ = _record(gate, monkeypatch, tmp_path, _as_release(RELEASE_WITH_SUBJECT))
    source = tmp_path / "src"

    # Control: without the word the argv resolves, to the clone.
    gate.run_scan(source, "low", True)
    assert _resolve(scans[-1])["path"] == str(source)

    monkeypatch.setenv("ASH_SCAN_EXTRA_ARGS", "elsewhere --offline")
    gate.run_scan(source, "low", True)
    argv = scans[-1]
    assert argv[3] == str(source), argv
    assert "elsewhere" in argv[4:], argv
    # By class name: typer carries its own copy of click, whose UsageError is not the
    # importable one.
    with pytest.raises(
        Exception, match=r"unexpected extra argument.*elsewhere"
    ) as refused:
        _resolve(argv)
    assert type(refused.value).__name__ == "UsageError"


@pytest.mark.parametrize("release", [RELEASE_WITH_SUBJECT, RELEASE_WITHOUT_SUBJECT])
def test_the_gates_own_options_come_after_the_extras_on_either_ash(
    gate, monkeypatch, tmp_path, release
):
    scans, _ = _record(gate, monkeypatch, tmp_path, _as_release(release))
    monkeypatch.setenv("ASH_SCAN_EXTRA_ARGS", "--offline --output-formats html")

    gate.run_scan(tmp_path / "src", "medium", False)

    argv = scans[0]
    last_extra = max(argv.index("--offline"), argv.index("html"))
    owned = ["--output-dir", "--min-severity", "--no-fail-on-findings", FLAG]
    if release == RELEASE_WITHOUT_SUBJECT:
        owned.append("--source-dir")
    for option in owned:
        assert argv.index(option) > last_extra, (option, argv)
    params = _resolve(argv)
    assert params["fail_on_incomplete_scanners"] is True
    assert params["fail_on_findings"] is False
    assert params["min_severity"] == "medium"


def test_a_subject_whose_help_lacks_the_completeness_flag_is_refused(
    gate, monkeypatch, tmp_path
):
    """The completeness check reads the help of the command the gate will run."""

    def answers(argv):
        if argv == FS_PROBE:
            return SimpleNamespace(
                returncode=0, stdout="Usage: ash scan fs [OPTIONS] [PATH]\n", stderr=""
            )
        return answer(argv, RELEASE_WITH_SUBJECT)

    scans, _ = _record(gate, monkeypatch, tmp_path, answers)

    with pytest.raises(RuntimeError, match=FLAG):
        gate.run_scan(tmp_path / "src", "low", True)
    assert scans == [], scans


#: A probe that dies instead of answering: the interpreter's traceback and a non-zero
#: status, as an import error or an out-of-memory kill leaves them.
CRASH = SimpleNamespace(
    returncode=1,
    stdout="",
    stderr=(
        "Traceback (most recent call last):\n"
        '  File "/usr/local/bin/ash", line 3, in <module>\n'
        "MemoryError\n"
    ),
)


def test_a_subject_probe_that_crashes_is_not_read_as_an_older_ash(
    gate, monkeypatch, tmp_path
):
    """The failed probe refuses the scan; the second probe would have chosen --source-dir."""

    def answers(argv):
        if argv == FS_PROBE:
            return CRASH
        return answer(argv, RELEASE_WITHOUT_SUBJECT)

    scans, probes = _record(gate, monkeypatch, tmp_path, answers)

    with pytest.raises(RuntimeError, match="could not be checked"):
        gate.run_scan(tmp_path / "src", "low", True)
    assert probes == [FS_PROBE], probes
    assert scans == [], scans


@pytest.mark.parametrize(
    "refusal",
    [
        SimpleNamespace(returncode=5, stdout="", stderr="Error: no such command"),
        SimpleNamespace(
            returncode=5,
            stdout="",
            stderr="Error: Invalid value for --config: File 'x' does not exist.\n",
        ),
        # Names the word, but is not a usage error about it.
        SimpleNamespace(returncode=1, stdout="", stderr="OSError: /mnt/fs is full\n"),
    ],
    ids=["names-no-word", "an-unrelated-usage-error", "names-fs-in-a-path"],
)
def test_a_refusal_that_does_not_say_fs_is_unknown_is_not_an_older_ash(
    gate, monkeypatch, tmp_path, refusal
):
    def answers(argv):
        if argv == FS_PROBE:
            return refusal
        return answer(argv, RELEASE_WITHOUT_SUBJECT)

    scans, probes = _record(gate, monkeypatch, tmp_path, answers)

    with pytest.raises(RuntimeError, match="could not be checked"):
        gate.run_scan(tmp_path / "src", "low", True)
    assert probes == [FS_PROBE], probes
    assert scans == [], scans


def test_a_probe_that_crashed_is_asked_again_and_the_answer_then_stands(
    gate, monkeypatch, tmp_path
):
    """Nothing of a failed probe is kept for the warm execution environment.

    The first ``ash scan fs --help`` crashes and the next ones answer as an ASH with
    the subject. Read as an older ASH, the first would have been remembered, and every
    later pull request in the environment would have scanned with ``--source-dir``.
    """
    asked = {"fs_probes": 0}

    def answers(argv):
        if argv == FS_PROBE:
            asked["fs_probes"] += 1
            if asked["fs_probes"] == 1:
                return CRASH
        return answer(argv, RELEASE_WITH_SUBJECT)

    scans, probes = _record(gate, monkeypatch, tmp_path, answers)
    source = tmp_path / "src"

    with pytest.raises(RuntimeError, match="could not be checked"):
        gate.run_scan(source, "low", True)
    assert scans == [], scans

    gate.run_scan(source, "low", True)
    assert [argv[:4] for argv in scans] == [["ash", "scan", "fs", str(source)]], scans

    # The answer that followed the crash is the one remembered.
    gate.run_scan(source, "low", True)
    assert probes == [FS_PROBE, FS_PROBE], probes
    assert len(scans) == 2, scans


@pytest.mark.parametrize(
    "fs_probe_reply, spelling, reason",
    [
        (None, "'ash scan fs PATH'", "its help names 'scan fs'"),
        (
            SimpleNamespace(
                returncode=0,
                stdout="Usage: ash scan [OPTIONS]\n" + FLAG + "\n",
                stderr="",
            ),
            "'ash scan --source-dir PATH'",
            "its help does not name 'scan fs'",
        ),
        (
            SimpleNamespace(
                returncode=5,
                stdout="",
                stderr="Error: Got unexpected extra argument (fs)\n",
            ),
            "'ash scan --source-dir PATH'",
            "refusing the word 'fs' (unexpected extra argument (fs))",
        ),
    ],
    ids=["with-the-subject", "answers-without-it", "refuses-the-word"],
)
def test_the_spelling_chosen_and_the_reason_are_logged(
    gate, monkeypatch, tmp_path, caplog, fs_probe_reply, spelling, reason
):
    def answers(argv):
        if argv == FS_PROBE and fs_probe_reply is not None:
            return fs_probe_reply
        return answer(
            argv,
            RELEASE_WITH_SUBJECT if fs_probe_reply is None else RELEASE_WITHOUT_SUBJECT,
        )

    _record(gate, monkeypatch, tmp_path, answers)

    with caplog.at_level(logging.INFO):
        gate.run_scan(tmp_path / "src", "low", True)

    chosen = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("scanning with")
    ]
    assert len(chosen) == 1, chosen
    assert spelling in chosen[0] and reason in chosen[0], chosen[0]


def test_what_a_failed_probe_printed_is_logged(gate, monkeypatch, tmp_path, caplog):
    _record(
        gate,
        monkeypatch,
        tmp_path,
        lambda argv: CRASH if argv == FS_PROBE else None,
    )

    with caplog.at_level(logging.ERROR), pytest.raises(RuntimeError):
        gate.run_scan(tmp_path / "src", "low", True)

    failures = [record.getMessage() for record in caplog.records]
    assert any(
        "ash scan fs --help exited 1" in message and "MemoryError" in message
        for message in failures
    ), failures
