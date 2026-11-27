#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Terraform pipeline's shards and merge spell ASH's commands the way its ASH does.

Why this exists
---------------
The shard and merge actions run inside the ASH image the module builds from
``ash_version``. ASH 3.9 scans a directory with ``ash scan fs PATH`` and merges with
``ash results merge``; the older spellings, ``ash scan --source-dir PATH`` and
``ash merge``, still run there but print a deprecation line, and they go in ASH v4.0.
An ``ash_version`` older than 3.9 (the module's default, until the release commit
moves it) has only the older spellings. So each command asks the image's ASH first,
and only an ASH with the new spelling prints it in that help.

Only an answer picks a spelling: a help that names the command (the new spelling), a
help that does not or a usage error naming the missing word (an older ASH). A probe
that fails any other way (a crash, an import error, an out-of-memory kill) says
nothing about the ASH's commands, so the action fails with what the probe printed
instead of guessing the older spelling. Each choice and its reason is printed to
stderr.

These run the committed build commands with a stand-in ``ash`` that answers the help
probes as each kind of release and records every other call, and a stand-in
``ash-container-init`` that only runs what it is given.
test_deploy_pipeline_config_source.py runs the same commands with this tree's real
ASH, which takes the new spelling.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tests.unit.deploy.gate_probe_answers import (
    FS_HELP,
    RELEASE_WITH_SUBJECT,
    RELEASE_WITHOUT_SUBJECT,
    SUBJECTLESS_HELP,
)

#: An ASH older than 3.9 whose ``scan fs --help`` refuses the word instead of showing
#: the subject-less scan's help.
RELEASE_REFUSING_FS = "refusing-fs"
#: An ASH whose every help probe dies with a traceback, as an out-of-memory kill or an
#: import error leaves it.
RELEASE_CRASHING = "crashing"

REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE = REPO_ROOT / "deploy" / "terraform" / "modules" / "codepipeline-executor"
CONTAINER_INIT_PATH = "/usr/local/bin/ash-container-init"

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        os.name == "nt",
        reason="executes a POSIX buildspec command destined for a Linux build container",
    ),
]

#: The stand-in ``ash``. Probes are answered as RELEASE and not recorded; every other
#: call is recorded, one JSON argv per line, and exits 0. A scan call also leaves the
#: results file that a shard checks for in its ``--output-dir``, as a finished scan does.
_FAKE_ASH = """import json, os, sys
argv = sys.argv[1:]
RELEASE = {release}
IS_PROBE = (
    argv[:3] == ["scan", "fs", "--help"]
    or argv[:2] == ["scan", "--help"]
    or argv[:3] == ["results", "merge", "--help"]
)
if IS_PROBE and RELEASE == {crashing}:
    sys.stderr.write("Traceback (most recent call last):\\nMemoryError\\n")
    sys.exit(1)
if argv[:3] == ["scan", "fs", "--help"] and RELEASE == {refusing_fs}:
    sys.stderr.write("Usage: ash scan [OPTIONS]\\nError: Got unexpected extra argument (fs)\\n")
    sys.exit(5)
if argv[:3] == ["scan", "fs", "--help"] or argv[:2] == ["scan", "--help"]:
    sys.stdout.write({fs_help} if RELEASE == {with_subject} else {subjectless_help})
    sys.exit(0)
if argv[:3] == ["results", "merge", "--help"]:
    if RELEASE == {with_subject}:
        print("Usage: ash results merge [OPTIONS]")
        sys.exit(0)
    print("Error: No such command 'results'.", file=sys.stderr)
    sys.exit(2)
with open({record}, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(argv) + "\\n")
if argv[:1] == ["scan"] and "--output-dir" in argv:
    out = argv[argv.index("--output-dir") + 1]
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "ash_aggregated_results.json"), "w") as handle:
        handle.write("{{}}")
"""


def _build_command(name: str, marker: str) -> str:
    """The one build-phase command of buildspec *name* that contains *marker*."""
    spec = yaml.safe_load((MODULE / name).read_text(encoding="utf-8"))
    matches = [c for c in spec["phases"]["build"]["commands"] if marker in c]
    assert len(matches) == 1, f"expected one build command with {marker!r} in {name}"
    assert CONTAINER_INIT_PATH in matches[0], (
        f"{name} no longer runs ash-container-init"
    )
    return matches[0]


def _run_process(
    tmp_path: Path, command: str, release: str, env: dict[str, str]
) -> tuple[list[list[str]], subprocess.CompletedProcess]:
    """Run *command* against the stand-ins, answering as *release*.

    Returns the calls the stand-in recorded and the finished shell, whose status and
    stderr say what the command itself did.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    record = tmp_path / "ash.jsonl"
    ash = bin_dir / "ash"
    ash.write_text(
        f"#!{sys.executable} -I\n"
        + _FAKE_ASH.format(
            release=json.dumps(release),
            with_subject=json.dumps(RELEASE_WITH_SUBJECT),
            crashing=json.dumps(RELEASE_CRASHING),
            refusing_fs=json.dumps(RELEASE_REFUSING_FS),
            fs_help=json.dumps(FS_HELP),
            subjectless_help=json.dumps(SUBJECTLESS_HELP),
            record=json.dumps(str(record)),
        ),
        encoding="utf-8",
    )
    ash.chmod(0o755)
    init = bin_dir / "ash-container-init"
    init.write_text('#!/bin/sh\nexec "$@"\n', encoding="utf-8")
    init.chmod(0o755)
    shell = shutil.which("sh")
    assert shell, "no sh on PATH"

    work = tmp_path / "work"
    work.mkdir()
    finished = subprocess.run(
        [shell, "-c", command.replace(CONTAINER_INIT_PATH, str(init))],
        cwd=work,
        env={
            "PATH": f"{bin_dir}{os.pathsep}/usr/bin{os.pathsep}/bin",
            "TMPDIR": str(tmp_path),
            "ASH_BASE_CONFIG_SSM_PARAMETER": "",
            **env,
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if not record.exists():
        return [], finished
    return [
        json.loads(line) for line in record.read_text(encoding="utf-8").splitlines()
    ], finished


def _run(
    tmp_path: Path, command: str, release: str, env: dict[str, str]
) -> list[list[str]]:
    """Run *command* against the stand-ins, answering as *release*; return the calls."""
    return _run_process(tmp_path, command, release, env)[0]


@pytest.mark.parametrize(
    "release, prefix",
    [
        (RELEASE_WITH_SUBJECT, ["scan", "fs", "."]),
        (RELEASE_WITHOUT_SUBJECT, ["scan", "--source-dir", "."]),
    ],
    ids=["with-subject", "without-subject"],
)
def test_a_shard_scans_the_checkout_the_way_its_ash_names_a_directory(
    tmp_path, release, prefix
):
    command = _build_command("buildspec-shard.yml.tftpl", "--shard-index")

    calls = _run(tmp_path, command, release, {"SHARD_INDEX": "1", "SHARD_COUNT": "3"})

    # One call: the probe is answered, not recorded.
    assert len(calls) == 1, calls
    argv = calls[0]
    assert argv[:3] == prefix, argv
    if release == RELEASE_WITH_SUBJECT:
        assert "--source-dir" not in argv, argv
    for pair in (["--shard-index", "1"], ["--shard-count", "3"]):
        start = argv.index(pair[0])
        assert argv[start : start + 2] == pair, argv
    assert "--no-fail-on-findings" in argv, argv


@pytest.mark.parametrize(
    "release, prefix",
    [
        (RELEASE_WITH_SUBJECT, ["results", "merge"]),
        (RELEASE_WITHOUT_SUBJECT, ["merge"]),
    ],
    ids=["with-subject", "without-subject"],
)
def test_the_merge_runs_the_merge_its_ash_has(tmp_path, release, prefix):
    command = _build_command("buildspec-merge.yml.tftpl", "MERGE_EXIT=$?")

    calls = _run(
        tmp_path,
        command,
        release,
        {"SHARD_COUNT": "3", "MIN_SEVERITY": "low", "FAIL_ON_FINDINGS": "true"},
    )

    assert len(calls) == 1, calls
    argv = calls[0]
    assert argv[: len(prefix)] == prefix, argv
    assert argv[argv.index("--min-severity") + 1] == "low", argv
    assert "--fail-on-findings" in argv, argv
    results = [argv[i + 1] for i, word in enumerate(argv) if word == "--results"]
    assert results == [f"shard-results/shard-{i}" for i in range(3)], argv


SHARD_ENV = {"SHARD_INDEX": "1", "SHARD_COUNT": "3"}
MERGE_ENV = {"SHARD_COUNT": "3", "MIN_SEVERITY": "low", "FAIL_ON_FINDINGS": "true"}


def test_a_shard_whose_probe_crashes_does_not_guess_the_older_spelling(tmp_path):
    """The crash is not an answer: the action fails, naming the probe's output."""
    command = _build_command("buildspec-shard.yml.tftpl", "--shard-index")

    calls, finished = _run_process(tmp_path, command, RELEASE_CRASHING, SHARD_ENV)

    assert calls == [], calls
    assert finished.returncode != 0, finished.stderr
    assert "could not tell whether this ASH has 'ash scan fs'" in finished.stderr
    assert "exited 1" in finished.stderr
    assert "MemoryError" in finished.stderr


def test_a_merge_whose_probe_crashes_does_not_guess_the_older_spelling(tmp_path):
    command = _build_command("buildspec-merge.yml.tftpl", "MERGE_EXIT=$?")

    calls, finished = _run_process(tmp_path, command, RELEASE_CRASHING, MERGE_ENV)

    assert calls == [], calls
    assert finished.returncode != 0, finished.stderr
    assert "could not tell whether this ASH has 'ash results merge'" in finished.stderr
    assert "MemoryError" in finished.stderr


def test_a_shard_scans_with_source_dir_when_its_ash_refuses_the_word_fs(tmp_path):
    command = _build_command("buildspec-shard.yml.tftpl", "--shard-index")

    calls, finished = _run_process(tmp_path, command, RELEASE_REFUSING_FS, SHARD_ENV)

    assert [argv[:3] for argv in calls] == [["scan", "--source-dir", "."]], calls
    assert finished.returncode == 0, finished.stderr
    assert "refused the word 'fs'" in finished.stderr


@pytest.mark.parametrize(
    "release, said",
    [
        (RELEASE_WITH_SUBJECT, "scanning with 'ash scan fs': its help names 'scan fs'"),
        (RELEASE_WITHOUT_SUBJECT, "scanning with the older spelling: the help of"),
        (RELEASE_REFUSING_FS, "scanning with the older spelling: this ASH refused"),
    ],
    ids=["with-subject", "without-subject", "refusing-fs"],
)
def test_a_shard_says_which_spelling_it_chose_and_why(tmp_path, release, said):
    command = _build_command("buildspec-shard.yml.tftpl", "--shard-index")

    _, finished = _run_process(tmp_path, command, release, SHARD_ENV)

    assert said in finished.stderr, finished.stderr


@pytest.mark.parametrize(
    "release, said",
    [
        (RELEASE_WITH_SUBJECT, "merging with 'ash results merge': its help names"),
        (RELEASE_WITHOUT_SUBJECT, "merging with the older spelling: this ASH refused"),
    ],
    ids=["with-subject", "without-subject"],
)
def test_the_merge_says_which_spelling_it_chose_and_why(tmp_path, release, said):
    command = _build_command("buildspec-merge.yml.tftpl", "MERGE_EXIT=$?")

    _, finished = _run_process(tmp_path, command, release, MERGE_ENV)

    assert said in finished.stderr, finished.stderr
