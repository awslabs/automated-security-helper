# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Where `./ash` writes, what it prints where, and how it quotes the build.

The default output directory is `.ash/ash_output` inside the scanned directory, as
`ash scan` defaults it, so a `.ash` link a repository commits at its root is inside
the linked-output rule when --source-dir names a subdirectory. A link below the source
is found by place, not only by name: an output path spelled through a working
directory that is itself a link to the source is still refused. The wrapper's own
status lines and the build's output go to stderr, so `./ash report ... > file` holds
the container's stdout alone. The base-image options of the build are one argument
each, so an OCI layout directory with a space in its name reaches the build whole.

A fake OCI runner stands in for docker, as in
test_ash_bash_entrypoint_container_inputs.py, and records each call's argv
NUL-separated. Bash-wrapper tests are integration tier (tests/NAMING_CONVENTIONS.md).
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

import pytest

from tests.utils.host_ids import with_fixed_ids

REPO_ROOT = Path(__file__).resolve().parents[2]
ASH_SCRIPT = REPO_ROOT / "ash"

pytestmark = [
    pytest.mark.integration,
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

# Records each call's arguments, NUL-separated, in the next numbered file under
# $FAKE_RUNNER_LOG_DIR. A build prints $BUILD_STDOUT_LINE on stdout when it is set,
# as `docker build -q` prints the image ID, and fails when BUILD_FAILS is set, so a
# test that only needs the build's argv never reaches the run step.
RECORDING_RUNNER = """#!/bin/bash
count=$(find "$FAKE_RUNNER_LOG_DIR" -type f | wc -l)
printf '%s\\0' "$@" > "$FAKE_RUNNER_LOG_DIR/$(printf '%03d' "$count")"
if [ "$1" = build ]; then
  if [ -n "${BUILD_STDOUT_LINE:-}" ]; then
    echo "$BUILD_STDOUT_LINE"
  fi
  if [ -n "${BUILD_FAILS:-}" ]; then
    echo 'fake runner: refusing to build, argv recorded' >&2
    exit 1
  fi
fi
exit 0
"""

#: Environment that would change the wrapper's commands if the suite itself runs in
#: a CI job that exported it.
_SCRUBBED_ENV = (
    "CI",
    "ASH_IMAGE_NAME",
    "OCI_RUNNER",
    "OCI_RUNNER_WRAPPER",
    "ASH_BASE_OCI_LAYOUT",
    "ASH_BASE_IMAGE_OVERRIDE",
    "DOCKER_EXTRA_ARGS",
    "ASH_CONFIG",
    "CDPATH",
)


def _executable(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    return path


@pytest.fixture
def runner(tmp_path):
    """The recording runner and the directory its calls land in."""
    log_dir = tmp_path / "runner-calls"
    log_dir.mkdir()
    return _executable(tmp_path / "bin" / "fake-oci-runner", RECORDING_RUNNER), log_dir


def _calls(log_dir: Path) -> List[List[str]]:
    calls = []
    for record in sorted(log_dir.iterdir()):
        calls.append(record.read_bytes().decode("utf-8").split("\0")[:-1])
    return calls


def _run(
    runner,
    args: List[str],
    *,
    cwd: Path,
    env: Optional[Dict[str, str]] = None,
    program: Optional[Path] = None,
):
    """Run ./ash against the recording runner: (result, calls)."""
    default_program, log_dir = runner
    environment = with_fixed_ids(
        {k: v for k, v in os.environ.items() if k not in _SCRUBBED_ENV},
        log_dir.parent / "fixed-id-bin",
    )
    environment.update(
        {
            "OCI_RUNNER": str(program or default_program),
            "FAKE_RUNNER_LOG_DIR": str(log_dir),
        }
    )
    environment.update(env or {})
    result = subprocess.run(  # nosec B603 B607 - fixed script path, list args, no shell
        ["bash", str(ASH_SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=str(cwd),
        env=environment,
        stdin=subprocess.DEVNULL,
        timeout=180,
        check=False,
    )
    return result, _calls(log_dir)


def _only(calls: List[List[str]], verb: str, shown: str) -> List[str]:
    found = [call for call in calls if call[:1] == [verb]]
    assert len(found) == 1, f"expected one {verb} call, got {calls}\n{shown}"
    return found[0]


def _mounts(run: List[str]) -> Dict[str, Dict[str, str]]:
    """The run's --mount values, keyed by destination."""
    mounts = {}
    for at, word in enumerate(run):
        if word == "--mount":
            fields = dict(part.partition("=")[::2] for part in run[at + 1].split(","))
            mounts[fields["destination"]] = fields
    return mounts


@pytest.fixture
def elsewhere(tmp_path):
    """Where a committed `.ash` link points: a directory the scan must not write."""
    target = tmp_path / "elsewhere"
    target.mkdir()
    return target


def test_the_default_output_directory_is_inside_the_scanned_directory(
    runner, elsewhere, tmp_path
):
    """`./ash --source-dir sub` from a checkout root wrote `.ash/ash_output` beside
    the working directory at the base, through a `.ash` link committed at that root,
    which stands above the source and so outside the linked-output rule. The default
    is now the scanned directory's own `.ash/ash_output`, as `ash scan` defaults it."""
    checkout = tmp_path / "checkout"
    sub = checkout / "sub"
    sub.mkdir(parents=True)
    (checkout / ".ash").symlink_to(elsewhere, target_is_directory=True)

    result, calls = _run(runner, ["--no-build", "--source-dir", "sub"], cwd=checkout)

    shown = result.stdout + result.stderr
    assert result.returncode == 0, shown
    run = _only(calls, "run", shown)
    out = Path(_mounts(run)["/out"]["source"]).resolve()
    assert out == (sub / ".ash" / "ash_output").resolve(), run
    assert (sub / ".ash" / "ash_output").is_dir()
    assert list(elsewhere.iterdir()) == [], "nothing is written where the link points"


def test_a_link_below_the_source_is_refused_when_spelled_through_a_linked_cwd(
    runner, elsewhere, tmp_path
):
    """The source holds a committed `.ash -> elsewhere` link. The working directory
    is a link to the source, and the output path is spelled relative to it, so by
    name it is under a third spelling of the source; at the base the rule compared
    names only and followed the link. The directory holding `.ash` resolves to the
    source, so the link is below it and is refused before anything is created."""
    project = tmp_path / "real" / "project"
    project.mkdir(parents=True)
    (project / ".ash").symlink_to(elsewhere, target_is_directory=True)
    through = tmp_path / "through"
    through.symlink_to(project, target_is_directory=True)

    result, calls = _run(
        runner,
        ["--no-build", "--source-dir", str(project), "--output-dir", ".ash/ash_output"],
        cwd=through,
        # bash keeps a PWD that names the current directory, so the output path is
        # spelled through the link, as a shell at that prompt would spell it.
        env={"PWD": str(through)},
    )

    shown = result.stdout + result.stderr
    assert result.returncode == 3, shown
    assert "is a symlink" in result.stderr, result.stderr
    assert str(through / ".ash") in result.stderr, result.stderr
    # The operator chose this output directory, so nothing names --output-dir.
    assert "--output-dir to write elsewhere" not in result.stderr, result.stderr
    assert calls == []
    assert list(elsewhere.iterdir()) == [], "nothing is written where the link points"


def test_a_committed_link_under_the_default_output_names_the_option(
    runner, elsewhere, tmp_path
):
    """The repository commits `.ash -> elsewhere` and no --output-dir is given: the
    default `<source>/.ash/ash_output` runs through that link, so it is refused as
    any linked output is, with exit 3, and the refusal names --output-dir as the way
    to write elsewhere, as every refusal of the default does
    (tests/unit/test_ash_bash_entrypoint_refusals.py pins the usage refusals)."""
    source = tmp_path / "src"
    source.mkdir()
    (source / ".ash").symlink_to(elsewhere, target_is_directory=True)

    result, calls = _run(runner, ["--no-build", "--source-dir", "src"], cwd=tmp_path)

    shown = result.stdout + result.stderr
    assert result.returncode == 3, shown
    assert "/.ash' is a symlink" in result.stderr, result.stderr
    assert "pass --output-dir to write elsewhere" in result.stderr, result.stderr
    assert calls == []
    assert list(elsewhere.iterdir()) == [], "nothing is written where the link points"


def test_the_wrappers_status_lines_and_the_build_output_go_to_stderr(runner, tmp_path):
    """`./ash report --format json > file` has to hold the report alone. At the base
    the wrapper's status lines, and the image ID `build -q` prints, stood on stdout
    ahead of the container's output."""
    source = tmp_path / "src"
    source.mkdir()

    result, calls = _run(
        runner,
        ["--source-dir", str(source), "--output-dir", str(tmp_path / "out"), "report"],
        cwd=tmp_path,
        env={"BUILD_STDOUT_LINE": "FAKE-IMAGE-ID-ON-STDOUT"},
    )

    shown = result.stdout + result.stderr
    assert result.returncode == 0, shown
    assert [call[0] for call in calls] == ["build", "run"], calls
    assert result.stdout == "", result.stdout
    assert "Resolved OCI_RUNNER to:" in result.stderr, result.stderr
    assert "Building image" in result.stderr, result.stderr
    assert "Running ASH scan using built image" in result.stderr, result.stderr
    assert "FAKE-IMAGE-ID-ON-STDOUT" in result.stderr, result.stderr


def test_the_oci_layout_directory_reaches_the_build_as_one_argument(runner, tmp_path):
    """ASH_BASE_OCI_LAYOUT names a layout directory the action computed. Built into
    an unquoted string at the base, it was split on its spaces and globbed, so a
    directory with a space in its name reached the build as two words, and one with
    glob characters in it reached the build as whatever they matched. The name here
    holds both a space and glob characters, so both halves are exercised."""
    source = tmp_path / "src"
    source.mkdir()
    layout = tmp_path / "layout [1] * dir"
    layout.mkdir()
    # nerdctl and finch take the layout as a build context; the runtime is read from
    # the runner's name.
    nerdctl = _executable(tmp_path / "bin" / "nerdctl", RECORDING_RUNNER)

    result, calls = _run(
        runner,
        ["--source-dir", str(source), "--output-dir", str(tmp_path / "out")],
        cwd=tmp_path,
        env={
            "ASH_BASE_OCI_LAYOUT": f"{layout}@sha256:{'0' * 64}",
            "BUILD_FAILS": "1",
        },
        program=nerdctl,
    )

    shown = result.stdout + result.stderr
    build = _only(calls, "build", shown)
    context = build[build.index("--build-context") + 1]
    assert context == f"ash-base-image=oci-layout://{layout}", build
    assert "--pull=false" in build, build
    assert build.count("--build-context") == 1, build
