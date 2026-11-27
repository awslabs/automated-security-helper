# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`./ash scan <subject> [PATH]`: the directory after the subject is the mount.

``ash scan fs <path>`` takes the directory as an argument. The entrypoint reads the word
after the subject as its own source directory, mounts it, and does not forward it: a
host path means nothing inside the container, where the scan is given the mount as
``/src``, the PATH argument of the subject, and no ASH_SOURCE_DIR. The forms that name no
subject keep the variable: it is the only way they are told the directory, and a typed
path is refused by the form with no subject. So does a scan that names a clone, an
image or a ``--cli-json-input`` document: the CLI refuses a PATH beside a clone, and
does not count the variable as the only name of the directory then. ``--source-dir``
still names the directory, with one deprecation line on stderr.

``ash scan workspace <file>`` names no directory: the entrypoint mounts one, so it
refuses the subject, and the older ``--workspace`` and ``--workspace-config`` spellings
with it, with exit 3 and a pointer to ``ash scan workspace <file> --mode container``.

A fake OCI runner stands in for docker, as in test_ash_bash_entrypoint_subcommand_args.py,
and prints the argv it was given. The completion rows run the function the entrypoint
prints, in bash, with no CLI and no Python.
"""

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ASH_SCRIPT = REPO_ROOT / "ash"
IMAGE = "automated-security-helper:non-root"

pytestmark = [
    pytest.mark.skipif(
        os.name == "nt",
        reason="bash on Windows runners is the WSL stub; ./ash is the POSIX entrypoint",
    ),
    pytest.mark.skipif(
        shutil.which("bash") is None, reason="the entrypoint under test is bash"
    ),
    pytest.mark.skipif(
        not ASH_SCRIPT.is_file(),
        reason="repository ash entrypoint not present (installed-package layout)",
    ),
]

RECORDING_RUNNER = """#!/bin/bash
echo "FAKE-RUNNER-INVOKED-WITH: $*"
exit 0
"""


@pytest.fixture
def runner(tmp_path):
    path = tmp_path / "fake-oci-runner"
    path.write_text(RECORDING_RUNNER)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    return path


def _ash(runner, tmp_path, *args):
    return subprocess.run(  # nosec B603 B607 - fixed script path, list args, no shell
        [
            "bash",
            str(ASH_SCRIPT),
            "--no-build",
            "--output-dir",
            str(tmp_path / "out"),
            *args,
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env={**os.environ, "OCI_RUNNER": str(runner)},
        timeout=180,
        check=False,
    )


def _run_argv(result):
    lines = [
        line
        for line in result.stdout.splitlines()
        if line.startswith("FAKE-RUNNER-INVOKED-WITH: run ")
    ]
    assert len(lines) == 1, result.stdout + result.stderr
    return lines[0].split()


def _inner_argv(run_argv):
    return run_argv[run_argv.index(IMAGE) + 1 :]


def _mounted_source(run_argv):
    mounts = [
        word
        for word in run_argv
        if word.startswith("source=") and word.endswith("destination=/src,readonly")
    ]
    assert len(mounts) == 1, run_argv
    return mounts[0].split(",")[0][len("source=") :]


#: What the entrypoint gives a scan, right after the subject and the PATH argument it
#: gives that: the scan in the image never sandboxes, the container is the boundary.
SANDBOX_OFF = ["--sandbox", "off"]


@pytest.mark.integration
def test_the_path_after_the_subject_is_the_mount_and_is_not_forwarded(runner, tmp_path):
    source = tmp_path / "project"
    source.mkdir()

    result = _ash(runner, tmp_path, "scan", "fs", str(source))
    run_argv = _run_argv(result)

    assert os.path.realpath(_mounted_source(run_argv)) == os.path.realpath(source)
    assert "ASH_SOURCE_DIR=/src" not in run_argv, (
        "the scan is given the mount as its PATH argument, not as the variable it "
        "tells the reader is deprecated"
    )
    assert _inner_argv(run_argv) == ["ash", "scan", "fs", "/src", *SANDBOX_OFF], (
        "the host path stays out of the container's command line, the mount follows "
        "the subject as its PATH argument, and --sandbox off follows that"
    )
    assert "Deprecated" not in result.stderr


@pytest.mark.integration
def test_options_may_stand_between_scan_and_the_subject(runner, tmp_path):
    source = tmp_path / "project"
    source.mkdir()

    run_argv = _run_argv(
        _ash(runner, tmp_path, "scan", "--scanners", "bandit", "fs", str(source))
    )

    assert os.path.realpath(_mounted_source(run_argv)) == os.path.realpath(source)
    assert _inner_argv(run_argv) == [
        "ash",
        "scan",
        *SANDBOX_OFF,
        "--scanners",
        "bandit",
        "fs",
        "/src",
    ], "the mount is the PATH argument after the subject, wherever the subject stands"


@pytest.mark.integration
def test_a_directory_named_like_a_subcommand_is_still_the_directory(runner, tmp_path):
    source = tmp_path / "report"
    source.mkdir()

    run_argv = _run_argv(_ash(runner, tmp_path, "scan", "fs", str(source)))

    assert os.path.realpath(_mounted_source(run_argv)) == os.path.realpath(source)
    assert _inner_argv(run_argv) == ["ash", "scan", "fs", "/src", *SANDBOX_OFF]


@pytest.mark.integration
def test_options_after_the_path_are_forwarded(runner, tmp_path):
    source = tmp_path / "project"
    source.mkdir()

    run_argv = _run_argv(
        _ash(runner, tmp_path, "scan", "fs", str(source), "--scanners", "bandit")
    )

    assert _inner_argv(run_argv) == [
        "ash",
        "scan",
        "fs",
        "/src",
        *SANDBOX_OFF,
        "--scanners",
        "bandit",
    ]


@pytest.mark.integration
@pytest.mark.parametrize(
    ("words", "inner"),
    [
        pytest.param(
            ["scan", "fs"],
            ["ash", "scan", "fs", "/src", *SANDBOX_OFF],
            id="the-subject-alone",
        ),
        pytest.param(
            ["scan", "fs", "--scanners", "bandit"],
            ["ash", "scan", "fs", "/src", *SANDBOX_OFF, "--scanners", "bandit"],
            id="an-option-after-the-subject",
        ),
        pytest.param(
            ["scan", "--scanners", "bandit", "fs"],
            ["ash", "scan", *SANDBOX_OFF, "--scanners", "bandit", "fs", "/src"],
            id="an-option-before-the-subject",
        ),
        pytest.param(
            ["--quiet", "scan", "fs"],
            ["ash", "--quiet", "scan", "fs", "/src", *SANDBOX_OFF],
            id="a-flag-of-this-script-before-scan",
        ),
        pytest.param(
            ["scan fs --scanners bandit"],
            ["ash", "scan", "fs", "/src", *SANDBOX_OFF, "--scanners", "bandit"],
            id="one-quoted-argument",
        ),
    ],
)
def test_scan_fs_is_given_the_mount_as_its_path_argument_and_no_variable(
    runner, tmp_path, words, inner
):
    """Where the mount goes when the caller names no directory: after the subject
    wherever it stands, and ahead of the --sandbox off the entrypoint adds. The scan
    inside is told nothing by ASH_SOURCE_DIR, which it would answer with a line."""
    result = _ash(runner, tmp_path, *words)
    run_argv = _run_argv(result)

    assert _inner_argv(run_argv) == inner
    assert "ASH_SOURCE_DIR=/src" not in run_argv, run_argv
    assert "ASH_OUTPUT_DIR=/out" in run_argv, run_argv
    assert "Deprecated" not in result.stderr, result.stderr


@pytest.mark.integration
@pytest.mark.parametrize(
    ("words", "inner"),
    [
        pytest.param(
            ["scan"], ["ash", "scan", *SANDBOX_OFF], id="scan-with-no-subject"
        ),
        pytest.param(
            ["--scanners", "bandit"],
            ["ash", *SANDBOX_OFF, "--scanners", "bandit"],
            id="no-command-at-all",
        ),
        pytest.param(
            ["report", "--format", "text"],
            ["ash", "report", "--format", "text"],
            id="report",
        ),
    ],
)
def test_a_form_with_no_scan_subject_is_still_given_the_variable(
    runner, tmp_path, words, inner
):
    """Only `scan fs` can be given a PATH: the form with no subject refuses one, and
    the other commands read the directory from the variable (config as its own
    --source-dir's)."""
    run_argv = _run_argv(_ash(runner, tmp_path, *words))

    assert _inner_argv(run_argv) == inner
    assert "ASH_SOURCE_DIR=/src" in run_argv, run_argv


@pytest.mark.integration
def test_a_path_typed_inside_one_quoted_argument_is_left_as_typed(runner, tmp_path):
    """A path word that is already among the scan's words is the caller's own, and a
    second one would be refused by the scan inside, so nothing is added and the scan
    keeps the variable it had."""
    run_argv = _run_argv(_ash(runner, tmp_path, "scan fs project"))

    assert _inner_argv(run_argv) == ["ash", "scan", "fs", *SANDBOX_OFF, "project"]
    assert "ASH_SOURCE_DIR=/src" in run_argv, run_argv


CLONE = "https://example.com/org/repo.git"


@pytest.mark.integration
@pytest.mark.parametrize(
    ("words", "inner"),
    [
        pytest.param(
            ["scan", "fs", "--source-git", CLONE],
            ["ash", "scan", "fs", *SANDBOX_OFF, "--source-git", CLONE],
            id="a-clone",
        ),
        pytest.param(
            ["scan", "fs", f"--source-git={CLONE}"],
            ["ash", "scan", "fs", *SANDBOX_OFF, f"--source-git={CLONE}"],
            id="a-clone-with-its-value-attached",
        ),
        pytest.param(
            ["scan", "--source-git", CLONE, "fs"],
            ["ash", "scan", *SANDBOX_OFF, "--source-git", CLONE, "fs"],
            id="a-clone-before-the-subject",
        ),
        pytest.param(
            ["--source-git", CLONE, "scan", "fs"],
            ["ash", "--source-git", CLONE, "scan", "fs", *SANDBOX_OFF],
            id="a-clone-before-scan",
        ),
        pytest.param(
            [f"scan fs --source-git {CLONE}"],
            ["ash", "scan", "fs", *SANDBOX_OFF, "--source-git", CLONE],
            id="a-clone-in-one-quoted-argument",
        ),
        pytest.param(
            ["scan", "fs", "--image", "app:1"],
            ["ash", "scan", "fs", *SANDBOX_OFF, "--image", "app:1"],
            id="an-image",
        ),
        pytest.param(
            ["scan", "fs", "--image=app:1"],
            ["ash", "scan", "fs", *SANDBOX_OFF, "--image=app:1"],
            id="an-image-with-its-value-attached",
        ),
        pytest.param(
            ["scan", "fs", "--image-archive", "image.tar"],
            ["ash", "scan", "fs", *SANDBOX_OFF, "--image-archive", "image.tar"],
            id="a-saved-image",
        ),
        pytest.param(
            ["scan", "fs", "--image-layout", "layout"],
            ["ash", "scan", "fs", *SANDBOX_OFF, "--image-layout", "layout"],
            id="an-image-layout",
        ),
        pytest.param(
            ["scan", "fs", "--cli-json-input", "scan.json"],
            ["ash", "scan", "fs", *SANDBOX_OFF, "--cli-json-input", "scan.json"],
            id="a-document-that-can-name-either",
        ),
    ],
)
def test_a_scan_that_names_another_source_keeps_the_variable_and_gets_no_path(
    runner, tmp_path, words, inner
):
    """The CLI inside refuses a PATH beside a clone, and it does not count the variable
    as the only name of the directory when a clone, an image or a document is named, so
    it prints no line about it. Such a scan is told its directory by the variable, as it
    was before the mount became a PATH argument: a clone replaces it, and `/src` is not
    among the scan's words."""
    result = _ash(runner, tmp_path, *words)
    run_argv = _run_argv(result)

    assert _inner_argv(run_argv) == inner
    assert "/src" not in _inner_argv(run_argv), run_argv
    assert "ASH_SOURCE_DIR=/src" in run_argv, run_argv
    assert "Deprecated" not in result.stderr, result.stderr


@pytest.mark.integration
def test_the_value_of_another_option_spelled_like_an_image_option_is_not_that_option(
    runner, tmp_path
):
    """The word after a value option is its value, whatever it spells: here ``--image``
    is the value of --output-formats, so the scan is still a scan of the directory and
    is given it as its PATH argument."""
    run_argv = _run_argv(
        _ash(runner, tmp_path, "scan", "fs", "--output-formats", "--image")
    )

    assert _inner_argv(run_argv) == [
        "ash",
        "scan",
        "fs",
        "/src",
        *SANDBOX_OFF,
        "--output-formats",
        "--image",
    ]
    assert "ASH_SOURCE_DIR=/src" not in run_argv, run_argv


@pytest.mark.integration
def test_source_dir_still_names_the_directory_and_warns_once(runner, tmp_path):
    source = tmp_path / "project"
    source.mkdir()

    result = _ash(runner, tmp_path, "scan", "fs", "--source-dir", str(source))
    run_argv = _run_argv(result)

    assert os.path.realpath(_mounted_source(run_argv)) == os.path.realpath(source)
    assert _inner_argv(run_argv) == ["ash", "scan", "fs", "/src", *SANDBOX_OFF]
    deprecated = [
        line for line in result.stderr.splitlines() if line.startswith("Deprecated:")
    ]
    assert len(deprecated) == 1, result.stderr
    assert "--source-dir is deprecated" in deprecated[0]
    assert "removed in ASH v4.0" in deprecated[0]
    assert "./ash scan fs <path>" in deprecated[0]


@pytest.mark.integration
@pytest.mark.parametrize("path_first", [True, False])
def test_naming_the_directory_twice_is_refused_with_the_usage_exit_code(
    runner, tmp_path, path_first
):
    source = tmp_path / "project"
    source.mkdir()
    words = (
        ["scan", "fs", str(source), "--source-dir", str(source)]
        if path_first
        else ["scan", "fs", "--source-dir", str(source), str(source)]
    )

    result = _ash(runner, tmp_path, *words)

    assert result.returncode == 5, result.stdout + result.stderr
    assert "Name the directory once" in result.stderr
    assert "FAKE-RUNNER-INVOKED-WITH" not in result.stdout


@pytest.mark.integration
def test_the_subject_less_form_still_forwards_its_words(runner, tmp_path):
    source = tmp_path / "project"
    source.mkdir()

    result = _ash(runner, tmp_path, "--source-dir", str(source), "scan")
    run_argv = _run_argv(result)

    assert _inner_argv(run_argv) == ["ash", "scan", *SANDBOX_OFF]
    assert "ASH_SOURCE_DIR=/src" in run_argv, (
        "the form with no subject is told its directory by the variable, and refuses "
        "a PATH argument"
    )
    assert "Deprecated" not in result.stderr, (
        "the scan inside prints the one line for a subject-less scan, and it names "
        "the same replacement, so the entrypoint adds none of its own"
    )


@pytest.mark.integration
def test_a_second_word_after_the_path_is_refused_not_forwarded(runner, tmp_path):
    source = tmp_path / "project"
    other = tmp_path / "other"
    source.mkdir()
    other.mkdir()

    result = _ash(runner, tmp_path, "scan", "fs", str(source), str(other))

    assert result.returncode == 5, result.stdout + result.stderr
    assert "Unexpected extra argument" in result.stderr
    assert "FAKE-RUNNER-INVOKED-WITH" not in result.stdout


@pytest.mark.integration
def test_a_workspace_value_is_not_read_as_a_second_directory(runner, tmp_path):
    source = tmp_path / "project"
    source.mkdir()

    result = _ash(
        runner,
        tmp_path,
        "scan",
        "fs",
        str(source),
        "--workspace",
        "team.code-workspace",
    )

    assert "Unexpected extra argument" not in result.stderr, result.stderr
    assert result.returncode == 3, result.stdout + result.stderr


#: What a refusal of a workspace scan says: its first words, and where it points.
WORKSPACE_REFUSAL = "./ash scans one directory and cannot run a workspace scan"
WORKSPACE_POINTER = "ash scan workspace <file> --mode container"


@pytest.mark.integration
@pytest.mark.parametrize(
    "words",
    [
        pytest.param(
            ["scan", "workspace", "team.code-workspace"], id="the-subject-and-its-file"
        ),
        pytest.param(["scan", "workspace"], id="the-subject-alone"),
        pytest.param(
            ["scan", "--scanners", "bandit", "workspace", "team.code-workspace"],
            id="an-option-before-the-subject",
        ),
        pytest.param(
            [
                "scan",
                "workspace",
                "team.code-workspace",
                "--workspace-config",
                "policy.yaml",
                "--allow-missing-projects",
            ],
            id="the-options-of-a-workspace-scan",
        ),
        pytest.param(
            ["scan", "workspace", "team.code-workspace", "extra"],
            id="a-word-after-the-file",
        ),
        pytest.param(
            ["scan", "workspace", "--source-dir", "elsewhere", "team.code-workspace"],
            id="a-source-dir-beside-the-file",
        ),
        # One quoted argument is split into words after the loop, and the subject is
        # found in them as well.
        pytest.param(["scan workspace team.code-workspace"], id="one-quoted-argument"),
        pytest.param(
            ["scan --scanners bandit workspace team.code-workspace"],
            id="one-quoted-argument-with-an-option-before-the-subject",
        ),
    ],
)
def test_a_workspace_scan_is_refused_with_a_pointer_and_nothing_runs(
    runner, tmp_path, words
):
    """The entrypoint mounts one directory, so a workspace file is not one it can
    scan: exit 3 before anything is built or run, naming the command that does, and
    no deprecation line for a --source-dir the refusal makes moot."""
    result = _ash(runner, tmp_path, *words)

    assert result.returncode == 3, result.stdout + result.stderr
    assert WORKSPACE_REFUSAL in result.stderr, result.stderr
    assert WORKSPACE_POINTER in result.stderr, result.stderr
    assert "Deprecated" not in result.stderr, result.stderr
    assert "FAKE-RUNNER-INVOKED-WITH" not in result.stdout, result.stdout


@pytest.mark.integration
@pytest.mark.parametrize("quoted", [False, True], ids=["words", "one-quoted-argument"])
def test_an_option_value_named_like_the_workspace_subject_is_not_the_subject(
    runner, tmp_path, quoted
):
    """The word after a value option is its value, whatever it spells, in the words as
    given and in the words of one quoted argument: here ``workspace`` is the value of
    --output-formats and the subject is ``fs``, so the scan runs."""
    source = tmp_path / "project"
    source.mkdir()
    words = ["scan", "--output-formats", "workspace", "fs", str(source)]

    result = _ash(runner, tmp_path, *([" ".join(words)] if quoted else words))

    assert result.returncode == 0, result.stdout + result.stderr
    assert WORKSPACE_REFUSAL not in result.stderr, result.stderr
    inner = _inner_argv(_run_argv(result))
    assert inner[:2] == ["ash", "scan"], inner
    assert "--output-formats" in inner, inner
    if not quoted:
        assert inner == [
            "ash",
            "scan",
            *SANDBOX_OFF,
            "--output-formats",
            "workspace",
            "fs",
            "/src",
        ]


@pytest.mark.integration
@pytest.mark.parametrize(
    "words",
    [
        pytest.param(["--workspace", "team.code-workspace"], id="workspace"),
        pytest.param(["--workspace=team.code-workspace"], id="workspace-attached"),
        pytest.param(["scan", "--workspace", "auto"], id="workspace-after-scan"),
        pytest.param(["--workspace-config", "policy.yaml"], id="workspace-config"),
        pytest.param(["scan", "--workspace-config=policy.yaml"], id="config-attached"),
    ],
)
def test_the_older_workspace_spellings_get_the_same_refusal_and_pointer(
    runner, tmp_path, words
):
    result = _ash(runner, tmp_path, *words)

    assert result.returncode == 3, result.stdout + result.stderr
    assert WORKSPACE_REFUSAL in result.stderr, result.stderr
    assert WORKSPACE_POINTER in result.stderr, result.stderr
    assert "--source-dir /src" not in result.stderr, (
        "the refusal no longer explains itself with the old inner call"
    )
    assert "FAKE-RUNNER-INVOKED-WITH" not in result.stdout, result.stdout


@pytest.mark.integration
@pytest.mark.parametrize(
    "words",
    [
        pytest.param(
            ["scan", "workspace", "team.code-workspace", "--sandbox", "bwrap"],
            id="separate",
        ),
        pytest.param(
            ["scan workspace team.code-workspace --sandbox bwrap"],
            id="one-quoted-argument",
        ),
    ],
)
def test_a_sandbox_beside_a_workspace_scan_is_still_the_usage_error(
    runner, tmp_path, words
):
    """The sandbox refusal is ASH's own usage error, 5, and runs first, as it does
    beside --workspace."""
    result = _ash(runner, tmp_path, *words)

    assert result.returncode == 5, result.stdout + result.stderr
    assert "--sandbox bwrap cannot be used" in result.stderr, result.stderr
    assert WORKSPACE_REFUSAL not in result.stderr, result.stderr


#: What a refusal of --archive says: its first words, and where it points.
ARCHIVE_REFUSAL = (
    "./ash runs without Python, so it cannot check or extract a source archive"
)
ARCHIVE_POINTER = "ash scan fs --archive <file>"


@pytest.mark.integration
@pytest.mark.parametrize(
    "words",
    [
        pytest.param(["scan", "fs", "--archive", "src.zip"], id="separate"),
        pytest.param(["scan", "fs", "--archive=src.zip"], id="attached"),
        pytest.param(
            ["scan", "fs", "--scanners", "bandit", "--archive", "src.zip"],
            id="after-another-option",
        ),
        pytest.param(["scan", "--archive", "src.zip", "fs"], id="before-the-subject"),
        pytest.param(["scan", "--archive", "src.zip"], id="with-no-subject"),
        pytest.param(["scan fs --archive src.zip"], id="one-quoted-argument"),
        pytest.param(["scan fs --archive=src.zip"], id="one-quoted-argument-attached"),
    ],
)
def test_a_source_archive_is_refused_with_a_pointer_and_nothing_runs(
    runner, tmp_path, words
):
    """The archive is checked and extracted by the Python CLI, which this script does
    not run: exit 3 before anything is built or run, naming the command that does."""
    result = _ash(runner, tmp_path, *words)

    assert result.returncode == 3, result.stdout + result.stderr
    assert ARCHIVE_REFUSAL in result.stderr, result.stderr
    assert ARCHIVE_POINTER in result.stderr, result.stderr
    assert "FAKE-RUNNER-INVOKED-WITH" not in result.stdout, result.stdout


@pytest.mark.integration
def test_the_value_of_another_option_spelled_like_archive_is_not_the_option(
    runner, tmp_path
):
    """The word after a value option is its value, whatever it spells: here
    ``--archive`` is the value of --output-formats, which the CLI inside refuses as a
    format, not an archive for this script to refuse."""
    source = tmp_path / "project"
    source.mkdir()

    result = _ash(
        runner, tmp_path, "scan", "fs", str(source), "--output-formats", "--archive"
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert ARCHIVE_REFUSAL not in result.stderr, result.stderr
    assert _inner_argv(_run_argv(result))[-2:] == ["--output-formats", "--archive"]


@pytest.mark.integration
def test_a_sandbox_beside_a_source_archive_is_still_the_usage_error(runner, tmp_path):
    result = _ash(
        runner, tmp_path, "scan", "fs", "--archive", "src.zip", "--sandbox", "bwrap"
    )

    assert result.returncode == 5, result.stdout + result.stderr
    assert ARCHIVE_REFUSAL not in result.stderr, result.stderr


@pytest.mark.unit
def test_the_entrypoint_runs_the_subjects_that_scan_a_directory_and_refuses_the_rest():
    """``fs`` takes the PATH argument ./ash mounts. Any other subject names something
    else, which ./ash cannot mount, so it is refused by name above; a subject the CLI
    gains fails here until the entrypoint decides which of the two it is."""
    import typer.main

    from automated_security_helper.cli.main import app

    subjects = typer.main.get_command(app).commands["scan"].commands
    scans_a_directory = {
        name
        for name, command in subjects.items()
        if any(
            param.param_type_name == "argument" and param.name == "path"
            for param in command.params
        )
    }

    assert scans_a_directory == {"fs"}
    assert set(subjects) - scans_a_directory == {"workspace"}


@pytest.mark.integration
def test_no_color_reaches_the_command_under_results(runner, tmp_path):
    run_argv = _run_argv(_ash(runner, tmp_path, "--no-color", "results", "report"))

    assert "--no-color" in _inner_argv(run_argv)
    assert _inner_argv(run_argv).index("results") < _inner_argv(run_argv).index(
        "report"
    )


@pytest.mark.integration
def test_an_option_value_after_the_path_is_not_a_second_path(runner, tmp_path):
    source = tmp_path / "project"
    source.mkdir()

    run_argv = _run_argv(
        _ash(runner, tmp_path, "scan", "fs", str(source), "--scanners", "bandit")
    )

    assert _inner_argv(run_argv)[-2:] == ["--scanners", "bandit"]


def _table(name):
    import re

    script = ASH_SCRIPT.read_text(encoding="utf-8")
    found = re.findall(rf'^{name}="([^"]*)"$', script, re.MULTILINE)
    assert len(found) == 1, (name, found)
    return set(found[0].split())


@pytest.mark.unit
def test_the_scan_tables_are_the_clis():
    """The subjects the entrypoint reads a PATH after, the value options that are not
    the root's, the options that name another source, and the options the completion
    offers, held to the real commands."""
    import typer.main

    from automated_security_helper.cli.main import app

    root = typer.main.get_command(app)
    subjects = root.commands["scan"].commands
    root_value = {
        spelling
        for param in root.params
        if param.param_type_name == "option" and not param.is_flag and not param.count
        for spelling in param.opts
    }
    subject_value = {
        spelling
        for subject in subjects.values()
        for param in subject.params
        if param.param_type_name == "option" and not param.is_flag and not param.count
        for spelling in param.opts
    } - root_value
    every_long_option = {
        spelling
        for param in [*root.params, *(p for s in subjects.values() for p in s.params)]
        if param.param_type_name == "option"
        for spelling in (*param.opts, *param.secondary_opts)
        if spelling.startswith("--")
    } - {"--install-completion"}  # the wrapper has no shell to install into

    # The options that name a source other than the directory, or a document that can:
    # written out here, and each held to being a real option of the CLI, so a rename
    # fails this and not only the table.
    other_source = {
        "--cli-json-input",
        "--image",
        "--image-archive",
        "--image-layout",
        "--source-git",
    }

    assert _table("ASH_SCAN_SUBJECTS") == set(subjects)
    assert _table("ASH_SCAN_VALUE_OPTIONS") == subject_value
    assert _table("ASH_SCAN_OTHER_SOURCE_OPTIONS") == other_source
    assert other_source <= every_long_option
    assert _table("ASH_ROOT_OPTIONS") == every_long_option


def _completions(tmp_path, words, cword):
    """What the printed function offers for COMP_WORDS=words at index cword."""
    script = tmp_path / "complete.bash"
    script.write_text(
        "set -u\n"
        f'source <(bash "{ASH_SCRIPT}" --show-completion)\n'
        "COMP_WORDS=(" + " ".join(f"'{word}'" for word in words) + ")\n"
        f"COMP_CWORD={cword}\n"
        "COMPREPLY=()\n"
        "_ash_completion\n"
        'printf "%s\\n" "${COMPREPLY[@]-}"\n'
    )
    result = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
        ["bash", str(script)],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return [line for line in result.stdout.splitlines() if line]


@pytest.mark.integration
def test_show_completion_prints_a_function_and_exits_without_a_runner(tmp_path):
    result = subprocess.run(  # nosec B603 B607 - fixed script path, list args
        ["bash", str(ASH_SCRIPT), "--show-completion"],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        env={k: v for k, v in os.environ.items() if k != "OCI_RUNNER"},
        timeout=60,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "_ash_completion()" in result.stdout
    assert "complete -o default -F _ash_completion ash ./ash" in result.stdout
    assert "mapfile" not in result.stdout, "bash 3.2, the macOS default, has no mapfile"


@pytest.mark.integration
def test_completion_offers_no_scan_option_after_another_subcommand(tmp_path):
    assert _completions(tmp_path, ["ash", "report", "--shard-"], 2) == []


@pytest.mark.integration
def test_completion_does_not_offer_the_install_completion_option(tmp_path):
    assert _completions(tmp_path, ["ash", "scan", "fs", "--install-"], 3) == []


@pytest.mark.integration
def test_completion_offers_the_subjects_after_scan(tmp_path):
    assert _completions(tmp_path, ["ash", "scan", ""], 2) == ["fs", "workspace"]


@pytest.mark.integration
def test_completion_finishes_a_partial_subject(tmp_path):
    assert _completions(tmp_path, ["ash", "scan", "w"], 2) == ["workspace"]
    assert _completions(tmp_path, ["ash", "scan", "f"], 2) == ["fs"]


@pytest.mark.integration
def test_completion_leaves_the_value_of_archive_to_the_shell(tmp_path):
    # --archive takes a file: the function offers nothing after it, so the shell's own
    # file completion (complete -o default) names the zip.
    assert _completions(tmp_path, ["ash", "scan", "fs", "--archive", ""], 4) == []


@pytest.mark.integration
def test_completion_offers_the_subcommands_with_none_named(tmp_path):
    offered = _completions(tmp_path, ["ash", "sc"], 1)

    assert offered == ["scan"]


@pytest.mark.integration
def test_completion_offers_the_options_after_a_dash(tmp_path):
    offered = _completions(tmp_path, ["ash", "scan", "fs", "--shard-"], 3)

    assert offered == ["--shard-count", "--shard-index"]


@pytest.mark.integration
def test_completion_leaves_a_value_alone(tmp_path):
    assert _completions(tmp_path, ["ash", "scan", "fs", "--mode", ""], 4) == []


@pytest.mark.integration
def test_completion_skips_an_option_value_when_finding_the_subject(tmp_path):
    # `--mode scan` names no subject: scan is the value, and the subjects are still
    # offered.
    offered = _completions(tmp_path, ["ash", "scan", "--mode", "local", ""], 4)

    assert offered == ["fs", "workspace"]
